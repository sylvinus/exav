//! The minimum Windows a packer stub needs to believe it is running.
//!
//! A stub does three things before it reaches the original entry point: it
//! finds `kernel32`, it allocates memory, and it resolves the imports the
//! original program will need. This module supplies all three without a single
//! host syscall:
//!
//! * **Finding `kernel32`.** The two ways a stub does this are `fs:[0x30]` →
//!   PEB → loader module list, and calling `GetModuleHandleA`. Both are
//!   supported: the emulator builds a real PEB, a real `PEB_LDR_DATA` with the
//!   three module lists correctly cross-linked, and synthetic module images
//!   with genuine export directories.
//! * **Allocating memory.** `VirtualAlloc`/`HeapAlloc` hand out pages from a
//!   bump allocator inside the emulated address space, and the regions are
//!   remembered — a packer that unpacks into fresh memory rather than back over
//!   its own image leaves the payload there, so those regions are dump
//!   candidates.
//! * **Resolving imports.** Every export resolves to a unique address in a trap
//!   range. Executing one is what tells the driver an API was called; the call
//!   is then serviced here, in Rust. A stub that merely *writes* those addresses
//!   into an import table (the common case — the imports are for the original
//!   program, which never runs) works for the same reason.
//!
//! Everything an API "does" is confined to the emulated address space. There is
//! no file, registry, network or process API that touches the host: the ones
//! that would are present so a stub gets a plausible answer, and they fail the
//! way they would on a machine where the operation is not permitted.

use std::collections::HashMap;

use crate::cpu::{Cpu, Stop, EAX, ESP};
use crate::mem::{Mem, PAGE_SIZE};

/// How far below the initial stack the emulator will keep mapping pages on
/// demand. Windows reserves a megabyte and commits it page by page as the stack
/// grows; a stub that recurses or allocates a large frame walks off the bottom
/// of a fixed mapping and faults on an address that is perfectly ordinary.
pub const STACK_GUARD_FLOOR: u32 = 0x0001_0000;

/// Emulated thread stack.
pub const STACK_BASE: u32 = 0x0010_0000;
pub const STACK_SIZE: u32 = 0x0010_0000;
pub const STACK_TOP: u32 = STACK_BASE + STACK_SIZE;
/// Initial `esp`, left well below the top so that a stub which indexes above
/// the stack pointer (several do) stays inside mapped memory.
pub const INITIAL_ESP: u32 = STACK_TOP - 0x4000;

pub const TEB_BASE: u32 = 0x7ffd_e000;
pub const PEB_BASE: u32 = 0x7ffd_f000;
const LDR_BASE: u32 = 0x7ffd_c000;
/// `KUSER_SHARED_DATA`: the read-only page Windows maps at a fixed address in
/// every process. Stubs read the tick count and version fields from it directly
/// rather than calling an API, so an unmapped page here faults a stub that is
/// doing something entirely ordinary.
const SHARED_USER_DATA: u32 = 0x7ffe_0000;
/// Scratch page holding the strings APIs hand back (command line, module path).
const ENV_BASE: u32 = 0x0009_0000;

/// Bump allocator range serving `VirtualAlloc`, `HeapAlloc` and friends.
const HEAP_BASE: u32 = 0x0100_0000;
const HEAP_LIMIT: u32 = 0x6000_0000;

/// Address space each synthetic DLL occupies. The first 0x4000 bytes hold the
/// headers and export directory; the rest is the trap range its exports point
/// into.
const MODULE_SIZE: u32 = 0x0001_0000;
const TRAP_OFFSET: u32 = 0x4000;
const TRAP_STRIDE: u32 = 0x10;
/// Offset within `kernel32` that the emulator's two return sentinels sit at:
/// past the trap range, still inside the module image.
const RETURN_OFFSET: u32 = 0xc000;

/// Handle values with fixed meanings on Windows.
const INVALID_HANDLE: u32 = 0xffff_ffff;
/// First handle handed out for the program's own file, and the mapping handle
/// derived from one. Chosen to be distinguishable in a trace.
const FILE_HANDLE_BASE: u32 = 0x0000_0400;
const MAPPING_HANDLE_BASE: u32 = 0x0000_0800;
/// The path the emulator reports for the program, and the only one that opens.
const SAMPLE_PATH: &str = "C:\\sample.exe";
const PROCESS_HEAP: u32 = 0x0052_0000;

/// A synthetic loaded module.
pub struct Module {
    /// Lowercase file name, e.g. `kernel32.dll`.
    pub name: String,
    pub base: u32,
    pub size: u32,
    /// Next free trap address for an export resolved after load time.
    trap_next: u32,
}

/// What an emulated export does when it is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Api {
    LoadLibrary {
        wide: bool,
    },
    GetProcAddress,
    GetModuleHandle {
        wide: bool,
    },
    GetModuleFileName {
        wide: bool,
    },
    VirtualAlloc,
    VirtualFree,
    VirtualProtect,
    VirtualQuery,
    HeapCreate,
    HeapAlloc,
    HeapReAlloc,
    HeapFree,
    GetProcessHeap,
    LocalAlloc,
    GlobalAlloc,
    MemFree,
    ExitProcess,
    GetVersion,
    GetVersionEx,
    GetTickCount,
    QueryPerformanceCounter,
    IsDebuggerPresent,
    GetLastError,
    SetLastError,
    GetCurrentProcess,
    GetCurrentThread,
    GetCurrentProcessId,
    GetCommandLine {
        wide: bool,
    },
    GetStartupInfo,
    GetSystemInfo,
    GetSystemTimeAsFileTime,
    TlsAlloc,
    TlsSetValue,
    TlsGetValue,
    Sleep,
    CloseHandle,
    CreateFile {
        wide: bool,
    },
    ReadFile,
    WriteFile,
    SetFilePointer,
    GetFileSize,
    CreateFileMapping,
    MapViewOfFile,
    GetStdHandle,
    SetUnhandledExceptionFilter,
    InterlockedExchange,
    LstrLen {
        wide: bool,
    },
    LstrCpy {
        wide: bool,
    },
    LstrCat {
        wide: bool,
    },
    LstrCmpi {
        wide: bool,
    },
    Memcpy,
    Memset,
    RtlMoveMemory,
    RtlZeroMemory,
    NtProtect,
    NtAllocate,
    NtQueryInformationProcess,
    /// `malloc`/`calloc`: cdecl, size in the first argument.
    CrtMalloc,
    /// `strncpy(dst, src, n)`: cdecl.
    CrtStrncpy,
    /// `CharNext`: advance a string pointer by one character.
    CharNext,
    /// The CRT's `__p__*` accessors, which return a *pointer to* a variable the
    /// caller dereferences at once. Returning zero — the obvious stand-in for a
    /// function nobody implemented — is therefore a null dereference one
    /// instruction later, which is how every MinGW-built packed program died.
    CrtDataPointer,
    /// `GetLocaleInfo`: hand back a one-character answer. The callers are C and
    /// Delphi start-up code asking for a code page or a separator; what matters
    /// is that they get *something* and a non-zero length, because a zero
    /// return sends them down an error path that ends in a null dereference.
    GetLocaleInfo {
        wide: bool,
    },
    /// Returns a fixed value and cleans `argc` arguments off the stack.
    Const(u32),
}

struct ApiSpec {
    module: &'static str,
    name: &'static str,
    /// Stack arguments the callee removes (stdcall). Zero for cdecl exports,
    /// where the caller cleans up.
    argc: u8,
    api: Api,
}

/// The exports the emulator implements. A stub that asks for something outside
/// this table still gets a resolvable address; calling it stops the run with
/// the name recorded, which is how the table grows.
const APIS: &[ApiSpec] = &[
    k("LoadLibraryA", 1, Api::LoadLibrary { wide: false }),
    k("LoadLibraryW", 1, Api::LoadLibrary { wide: true }),
    k("LoadLibraryExA", 3, Api::LoadLibrary { wide: false }),
    k("LoadLibraryExW", 3, Api::LoadLibrary { wide: true }),
    k("FreeLibrary", 1, Api::Const(1)),
    k("GetProcAddress", 2, Api::GetProcAddress),
    k("GetModuleHandleA", 1, Api::GetModuleHandle { wide: false }),
    k("GetModuleHandleW", 1, Api::GetModuleHandle { wide: true }),
    k(
        "GetModuleFileNameA",
        3,
        Api::GetModuleFileName { wide: false },
    ),
    k(
        "GetModuleFileNameW",
        3,
        Api::GetModuleFileName { wide: true },
    ),
    k("VirtualAlloc", 4, Api::VirtualAlloc),
    k("VirtualAllocEx", 5, Api::VirtualAlloc),
    k("VirtualFree", 3, Api::VirtualFree),
    k("VirtualProtect", 4, Api::VirtualProtect),
    k("VirtualProtectEx", 5, Api::VirtualProtect),
    k("VirtualQuery", 3, Api::VirtualQuery),
    k("HeapCreate", 3, Api::HeapCreate),
    k("HeapDestroy", 1, Api::Const(1)),
    k("HeapAlloc", 3, Api::HeapAlloc),
    k("HeapReAlloc", 4, Api::HeapReAlloc),
    k("HeapFree", 3, Api::HeapFree),
    k("HeapSize", 3, Api::Const(0)),
    k("GetProcessHeap", 0, Api::GetProcessHeap),
    k("LocalAlloc", 2, Api::LocalAlloc),
    k("LocalFree", 1, Api::MemFree),
    k("GlobalAlloc", 2, Api::GlobalAlloc),
    k("GlobalFree", 1, Api::MemFree),
    k("ExitProcess", 1, Api::ExitProcess),
    k("TerminateProcess", 2, Api::ExitProcess),
    k("GetVersion", 0, Api::GetVersion),
    k("GetVersionExA", 1, Api::GetVersionEx),
    k("GetVersionExW", 1, Api::GetVersionEx),
    k("GetTickCount", 0, Api::GetTickCount),
    k("QueryPerformanceCounter", 1, Api::QueryPerformanceCounter),
    k("QueryPerformanceFrequency", 1, Api::QueryPerformanceCounter),
    k("IsDebuggerPresent", 0, Api::IsDebuggerPresent),
    k("CheckRemoteDebuggerPresent", 2, Api::Const(0)),
    k("GetLastError", 0, Api::GetLastError),
    k("SetLastError", 1, Api::SetLastError),
    k("GetCurrentProcess", 0, Api::GetCurrentProcess),
    k("GetCurrentThread", 0, Api::GetCurrentThread),
    k("GetCurrentProcessId", 0, Api::GetCurrentProcessId),
    k("GetCurrentThreadId", 0, Api::GetCurrentProcessId),
    k("GetCommandLineA", 0, Api::GetCommandLine { wide: false }),
    k("GetCommandLineW", 0, Api::GetCommandLine { wide: true }),
    k("GetStartupInfoA", 1, Api::GetStartupInfo),
    k("GetStartupInfoW", 1, Api::GetStartupInfo),
    k("GetSystemInfo", 1, Api::GetSystemInfo),
    k("GetSystemTimeAsFileTime", 1, Api::GetSystemTimeAsFileTime),
    k("TlsAlloc", 0, Api::TlsAlloc),
    k("TlsSetValue", 2, Api::TlsSetValue),
    k("TlsGetValue", 1, Api::TlsGetValue),
    k("TlsFree", 1, Api::Const(1)),
    k("Sleep", 1, Api::Sleep),
    k("CloseHandle", 1, Api::CloseHandle),
    k("CreateFileA", 7, Api::CreateFile { wide: false }),
    k("CreateFileW", 7, Api::CreateFile { wide: true }),
    k("ReadFile", 5, Api::ReadFile),
    k("WriteFile", 5, Api::WriteFile),
    k("GetStdHandle", 1, Api::GetStdHandle),
    k(
        "SetUnhandledExceptionFilter",
        1,
        Api::SetUnhandledExceptionFilter,
    ),
    k("InterlockedExchange", 2, Api::InterlockedExchange),
    k("lstrlenA", 1, Api::LstrLen { wide: false }),
    k("lstrlenW", 1, Api::LstrLen { wide: true }),
    k("lstrcpyA", 2, Api::LstrCpy { wide: false }),
    k("lstrcpyW", 2, Api::LstrCpy { wide: true }),
    k("lstrcatA", 2, Api::LstrCat { wide: false }),
    k("lstrcmpiA", 2, Api::LstrCmpi { wide: false }),
    k("lstrcmpiW", 2, Api::LstrCmpi { wide: true }),
    k("GetProcessAffinityMask", 3, Api::Const(1)),
    k("SetProcessAffinityMask", 2, Api::Const(1)),
    k("FlushInstructionCache", 3, Api::Const(1)),
    k("GetSystemDirectoryA", 2, Api::Const(0)),
    k("GetEnvironmentStringsW", 0, Api::Const(0)),
    k("GetACP", 0, Api::Const(1252)),
    k("SetErrorMode", 1, Api::Const(0)),
    k("CreateThread", 6, Api::Const(0)),
    k("WaitForSingleObject", 2, Api::Const(0)),
    k("CreateMutexA", 3, Api::Const(0x100)),
    k("OpenProcess", 3, Api::Const(0)),
    k("OutputDebugStringA", 1, Api::Const(0)),
    ApiSpec {
        module: "ntdll.dll",
        name: "NtProtectVirtualMemory",
        argc: 5,
        api: Api::NtProtect,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "ZwProtectVirtualMemory",
        argc: 5,
        api: Api::NtProtect,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "NtAllocateVirtualMemory",
        argc: 6,
        api: Api::NtAllocate,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "ZwAllocateVirtualMemory",
        argc: 6,
        api: Api::NtAllocate,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "NtQueryInformationProcess",
        argc: 5,
        api: Api::NtQueryInformationProcess,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "RtlMoveMemory",
        argc: 3,
        api: Api::RtlMoveMemory,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "RtlZeroMemory",
        argc: 2,
        api: Api::RtlZeroMemory,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "RtlAllocateHeap",
        argc: 3,
        api: Api::HeapAlloc,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "RtlFreeHeap",
        argc: 3,
        api: Api::HeapFree,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "NtSetInformationThread",
        argc: 4,
        api: Api::Const(0),
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "memcpy",
        argc: 0,
        api: Api::Memcpy,
    },
    ApiSpec {
        module: "ntdll.dll",
        name: "memset",
        argc: 0,
        api: Api::Memset,
    },
    ApiSpec {
        module: "msvcrt.dll",
        name: "memcpy",
        argc: 0,
        api: Api::Memcpy,
    },
    ApiSpec {
        module: "msvcrt.dll",
        name: "memset",
        argc: 0,
        api: Api::Memset,
    },
    // --- The C runtime start-up sequence -------------------------------
    //
    // These are not packer APIs: they are what the *original* program calls in
    // its first few hundred instructions. They matter because a stub often
    // hands control over and keeps running under emulation, and a run that
    // stops at `__set_app_type` has stopped after the interesting part but
    // before the emulator can see where it ended up. `msvcrt` exports are
    // cdecl, so the callee removes nothing.
    c("__set_app_type", Api::Const(0)),
    c("__setusermatherr", Api::Const(0)),
    c("__getmainargs", Api::Const(0)),
    c("__p__fmode", Api::CrtDataPointer),
    c("__p__commode", Api::CrtDataPointer),
    c("__p__acmdln", Api::CrtDataPointer),
    c("__p__wcmdln", Api::CrtDataPointer),
    c("__p__environ", Api::CrtDataPointer),
    c("__p__wenviron", Api::CrtDataPointer),
    c("__p__pgmptr", Api::CrtDataPointer),
    c("__p__wpgmptr", Api::CrtDataPointer),
    c("__p__osver", Api::CrtDataPointer),
    c("__p__winver", Api::CrtDataPointer),
    c("__p__winmajor", Api::CrtDataPointer),
    c("__p__winminor", Api::CrtDataPointer),
    c("__p___argc", Api::CrtDataPointer),
    c("__p___argv", Api::CrtDataPointer),
    c("__p___wargv", Api::CrtDataPointer),
    c("__p___initenv", Api::CrtDataPointer),
    c("__p__daylight", Api::CrtDataPointer),
    c("__p__timezone", Api::CrtDataPointer),
    c("__set_app_type", Api::Const(0)),
    c("_amsg_exit", Api::ExitProcess),
    c("__dllonexit", Api::Const(0)),
    c("_onexit", Api::Const(0)),
    c("_lock", Api::Const(0)),
    c("_unlock", Api::Const(0)),
    c("__setusermatherr", Api::Const(0)),
    c("_configthreadlocale", Api::Const(0)),
    c("__crtGetShowWindowMode", Api::Const(0)),
    c("_controlfp", Api::Const(0x9001f)),
    c("_initterm", Api::Const(0)),
    c("_except_handler3", Api::Const(1)),
    c("_XcptFilter", Api::Const(0)),
    c("exit", Api::ExitProcess),
    c("_exit", Api::ExitProcess),
    c("malloc", Api::CrtMalloc),
    c("calloc", Api::CrtMalloc),
    c("free", Api::Const(0)),
    c("strlen", Api::LstrLen { wide: false }),
    c("strncpy", Api::CrtStrncpy),
    c("strcmp", Api::LstrCmpi { wide: false }),
    c("memmove", Api::Memcpy),
    c("memcmp", Api::Const(0)),
    c("strcpy", Api::LstrCpy { wide: false }),
    c("strcat", Api::LstrCat { wide: false }),
    c("_stricmp", Api::LstrCmpi { wide: false }),
    // --- kernel32: the rest of what a program touches on the way up ----
    k("InitializeCriticalSection", 1, Api::Const(0)),
    k("InitializeCriticalSectionAndSpinCount", 2, Api::Const(1)),
    k("DeleteCriticalSection", 1, Api::Const(0)),
    k("EnterCriticalSection", 1, Api::Const(0)),
    k("LeaveCriticalSection", 1, Api::Const(0)),
    k("DisableThreadLibraryCalls", 1, Api::Const(1)),
    k("SetThreadLocale", 1, Api::Const(0x0409)),
    k("GetLongPathNameA", 3, Api::Const(0)),
    k("GetLongPathNameW", 3, Api::Const(0)),
    k("GetShortPathNameA", 3, Api::Const(0)),
    k("lstrcpynA", 3, Api::CrtStrncpy),
    k("lstrcpynW", 3, Api::Const(0)),
    k("GetThreadLocale", 0, Api::Const(0x0409)),
    k("GetUserDefaultLangID", 0, Api::Const(0x0409)),
    k("GetUserDefaultUILanguage", 0, Api::Const(0x0409)),
    k("GetSystemDefaultUILanguage", 0, Api::Const(0x0409)),
    k("IsValidLocale", 2, Api::Const(1)),
    k("IsValidCodePage", 1, Api::Const(1)),
    k("EnumSystemLocalesA", 2, Api::Const(1)),
    k("VerSetConditionMask", 4, Api::Const(0)),
    k("VerifyVersionInfoA", 3, Api::Const(1)),
    k("VerifyVersionInfoW", 3, Api::Const(1)),
    k("FindFirstFileA", 2, Api::Const(0xffff_ffff)),
    k("FindFirstFileW", 2, Api::Const(0xffff_ffff)),
    k("FindNextFileA", 2, Api::Const(0)),
    k("FindClose", 1, Api::Const(1)),
    k("CreateDirectoryA", 2, Api::Const(0)),
    k("CreateDirectoryW", 2, Api::Const(0)),
    k("GetFileAttributesA", 1, Api::Const(0xffff_ffff)),
    k("GetFileAttributesW", 1, Api::Const(0xffff_ffff)),
    k("SetFileAttributesA", 2, Api::Const(0)),
    k("CopyFileA", 3, Api::Const(0)),
    k("MoveFileA", 2, Api::Const(0)),
    k("GetDriveTypeA", 1, Api::Const(3)),
    k("GetLogicalDrives", 0, Api::Const(4)),
    k("GetComputerNameA", 2, Api::Const(0)),
    k("LoadLibraryExA", 3, Api::LoadLibrary { wide: false }),
    k("GetCPInfo", 2, Api::Const(1)),
    k("GetOEMCP", 0, Api::Const(437)),
    k("GetStringTypeA", 5, Api::Const(1)),
    k("GetStringTypeW", 4, Api::Const(1)),
    k("MultiByteToWideChar", 6, Api::Const(0)),
    k("WideCharToMultiByte", 8, Api::Const(0)),
    k("LCMapStringA", 6, Api::Const(0)),
    k("LCMapStringW", 6, Api::Const(0)),
    k("GetLocaleInfoA", 4, Api::GetLocaleInfo { wide: false }),
    k("GetLocaleInfoW", 4, Api::GetLocaleInfo { wide: true }),
    k("SetHandleCount", 1, Api::Const(1)),
    k("GetFileType", 1, Api::Const(1)),
    k("GetEnvironmentStrings", 0, Api::Const(0)),
    k("FreeEnvironmentStringsA", 1, Api::Const(1)),
    k("FreeEnvironmentStringsW", 1, Api::Const(1)),
    k("RtlUnwind", 4, Api::Const(0)),
    k("UnhandledExceptionFilter", 1, Api::Const(0)),
    k("SetConsoleCtrlHandler", 2, Api::Const(1)),
    k("GetSystemTime", 1, Api::Const(0)),
    k("GetLocalTime", 1, Api::Const(0)),
    k("GetSystemDirectoryW", 2, Api::Const(0)),
    k("GetWindowsDirectoryA", 2, Api::Const(0)),
    k("GetTempPathA", 2, Api::Const(0)),
    k("FindResourceA", 3, Api::Const(0)),
    k("LoadResource", 2, Api::Const(0)),
    k("LockResource", 1, Api::Const(0)),
    k("SizeofResource", 2, Api::Const(0)),
    k("CreateFileMappingA", 6, Api::CreateFileMapping),
    k("CreateFileMappingW", 6, Api::CreateFileMapping),
    k("MapViewOfFile", 5, Api::MapViewOfFile),
    k("MapViewOfFileEx", 6, Api::MapViewOfFile),
    k("UnmapViewOfFile", 1, Api::Const(1)),
    k("SetFilePointer", 4, Api::SetFilePointer),
    k("GetFileSize", 2, Api::GetFileSize),
    k("GetFileSizeEx", 2, Api::GetFileSize),
    k("DeleteFileA", 1, Api::Const(1)),
    k("IsBadReadPtr", 2, Api::Const(0)),
    k("IsBadWritePtr", 2, Api::Const(0)),
    k("GlobalMemoryStatus", 1, Api::Const(0)),
    k("ExitThread", 1, Api::ExitProcess),
    k("FreeConsole", 0, Api::Const(1)),
    k("Beep", 2, Api::Const(1)),
    k("WriteProcessMemory", 5, Api::Const(0)),
    k("ReadProcessMemory", 5, Api::Const(0)),
    k("CreateProcessA", 10, Api::Const(0)),
    k("CreateProcessW", 10, Api::Const(0)),
    k("GetThreadContext", 2, Api::Const(0)),
    k("SetThreadContext", 2, Api::Const(0)),
    k("ResumeThread", 1, Api::Const(0)),
    // --- user32 / advapi32 / the small system DLLs ---------------------
    u("MessageBoxA", 4, Api::Const(1)),
    u("MessageBoxW", 4, Api::Const(1)),
    u("GetSystemMetrics", 1, Api::Const(1024)),
    u("GetDesktopWindow", 0, Api::Const(0x0001_0010)),
    u("GetForegroundWindow", 0, Api::Const(0)),
    u("FindWindowA", 2, Api::Const(0)),
    u("ShowWindow", 2, Api::Const(1)),
    u("DefWindowProcA", 4, Api::Const(0)),
    u("PostQuitMessage", 1, Api::Const(0)),
    u("RegisterClassA", 1, Api::Const(1)),
    u("LoadIconA", 2, Api::Const(0)),
    u("LoadCursorA", 2, Api::Const(0)),
    u("SetTimer", 4, Api::Const(1)),
    u("KillTimer", 2, Api::Const(1)),
    u("CharUpperBuffA", 2, Api::Const(0)),
    u("CharNextA", 1, Api::CharNext),
    u("CharNextW", 1, Api::CharNext),
    u("wsprintfA", 0, Api::Const(0)),
    ApiSpec {
        module: "advapi32.dll",
        name: "RegOpenKeyExA",
        argc: 5,
        api: Api::Const(2), // ERROR_FILE_NOT_FOUND
    },
    ApiSpec {
        module: "advapi32.dll",
        name: "RegOpenKeyExW",
        argc: 5,
        api: Api::Const(2),
    },
    ApiSpec {
        module: "advapi32.dll",
        name: "RegQueryValueExW",
        argc: 6,
        api: Api::Const(2),
    },
    ApiSpec {
        module: "advapi32.dll",
        name: "RegQueryValueExA",
        argc: 6,
        api: Api::Const(2),
    },
    ApiSpec {
        module: "advapi32.dll",
        name: "RegCloseKey",
        argc: 1,
        api: Api::Const(0),
    },
    ApiSpec {
        module: "advapi32.dll",
        name: "GetUserNameA",
        argc: 2,
        api: Api::Const(0),
    },
    ApiSpec {
        module: "comctl32.dll",
        name: "InitCommonControls",
        argc: 0,
        api: Api::Const(0),
    },
    ApiSpec {
        module: "ole32.dll",
        name: "CoInitialize",
        argc: 1,
        api: Api::Const(0),
    },
    ApiSpec {
        module: "ole32.dll",
        name: "CoUninitialize",
        argc: 0,
        api: Api::Const(0),
    },
    ApiSpec {
        module: "ole32.dll",
        name: "CoCreateInstance",
        argc: 5,
        api: Api::Const(0x8000_4005), // E_FAIL
    },
    ApiSpec {
        module: "shell32.dll",
        name: "ShellExecuteA",
        argc: 6,
        api: Api::Const(42),
    },
    ApiSpec {
        module: "mscoree.dll",
        name: "_CorExeMain",
        argc: 0,
        // Handing control to the .NET runtime ends the part of the program an
        // x86 emulator can follow: everything past it is IL. Treated as a clean
        // end, so whatever the native stub rebuilt is dumped rather than thrown
        // away for stopping somewhere unexpected.
        api: Api::ExitProcess,
    },
    ApiSpec {
        module: "mscoree.dll",
        name: "_CorDllMain",
        argc: 0,
        api: Api::ExitProcess,
    },
];

/// Shorthand for a `kernel32` export (most of the table).
const fn k(name: &'static str, argc: u8, api: Api) -> ApiSpec {
    ApiSpec {
        module: "kernel32.dll",
        name,
        argc,
        api,
    }
}

/// Shorthand for a `user32` export.
const fn u(name: &'static str, argc: u8, api: Api) -> ApiSpec {
    ApiSpec {
        module: "user32.dll",
        name,
        argc,
        api,
    }
}

/// Shorthand for a C-runtime export: cdecl, so the callee removes nothing.
const fn c(name: &'static str, api: Api) -> ApiSpec {
    ApiSpec {
        module: "msvcrt.dll",
        name,
        argc: 0,
        api,
    }
}

/// Modules present from the start, in loader order. `ntdll` before `kernel32`
/// because that is the order the initialisation-order list has them in, and
/// stubs index that list positionally.
const PRELOADED: &[(&str, u32)] = &[
    ("ntdll.dll", 0x7c90_0000),
    ("kernel32.dll", 0x7c80_0000),
    ("user32.dll", 0x7e41_0000),
    ("advapi32.dll", 0x77dd_0000),
    ("msvcrt.dll", 0x7c34_0000),
];

/// A resolved export: the trap address, and what to do when it is reached.
struct Trap {
    api: Option<Api>,
    argc: u8,
    module: String,
    name: String,
}

/// What servicing an API call asked the driver to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiEffect {
    /// Execution continues at the return address.
    Continue,
    /// The stub called `ExitProcess`: it is done, and whatever it produced is
    /// all there will be.
    Exit,
    /// An export with no implementation was called. Execution continues from
    /// the return address with `eax = 0` and the arguments left in place, but
    /// the call is recorded: the stack is now wrong by whatever a `stdcall`
    /// callee would have removed, so anything the run produces afterwards is
    /// held to the stricter acceptance test.
    Unimplemented,
}

pub struct Env<'a> {
    pub modules: Vec<Module>,
    /// The bytes of the file being emulated.
    ///
    /// A stub is entitled to read the program it is part of, and many do:
    /// installers and self-extractors keep their payload as an overlay past the
    /// last section and reach it with `CreateFile`/`ReadFile` on their own path
    /// rather than through the loaded image. Refusing that (an invalid handle)
    /// makes those stubs report an error and exit, which is exactly what
    /// happened. Serving it from the buffer already in memory costs nothing and
    /// touches no host file: the only path that resolves is the program's own.
    file: &'a [u8],
    /// Open handles onto that file, with their read positions.
    open_files: HashMap<u32, u32>,
    next_handle: u32,
    /// Scratch cell handed back by the CRT's `__p__*` accessors.
    crt_cell: u32,
    traps: HashMap<u32, Trap>,
    /// Base address of the emulated program image (what `GetModuleHandle(NULL)`
    /// returns).
    pub image_base: u32,
    heap_next: u32,
    /// Live allocations, base to size. Regions handed out by `VirtualAlloc` are
    /// where a packer that does not unpack in place puts the payload, so the
    /// unpacker inspects them when looking for a dump.
    pub allocations: Vec<(u32, u32)>,
    last_error: u32,
    tick: u32,
    perf: u64,
    tls: HashMap<u32, u32>,
    tls_next: u32,
    /// Exports that were called but not implemented, for diagnostics.
    pub missing_apis: Vec<String>,
    /// Record every serviced call. Off on the scan path; the triage tool turns
    /// it on, because a stub that gives up usually did so because of an answer
    /// this environment gave it, and the call log is the only place that shows.
    pub trace: bool,
    pub api_log: Vec<String>,
    /// Bytes moved by block-copy APIs since the driver last collected them.
    ///
    /// The tick budget bounds how many instructions run, which is a fair proxy
    /// for work right up until one instruction moves 64 MiB. `memcpy` and its
    /// relatives do exactly that, so a stub can loop over them and spend the
    /// whole budget's worth of ticks while doing a budget's worth of copying per
    /// tick. Reporting the volume lets the driver charge for it, the same way
    /// `rep movsb` is charged per iteration rather than per instruction.
    bulk_bytes: u64,
}

impl<'a> Env<'a> {
    /// Build the environment: TEB, PEB, loader lists and the synthetic modules.
    pub fn new(
        mem: &mut Mem,
        image_base: u32,
        image_size: u32,
        file: &'a [u8],
    ) -> Result<Self, Stop> {
        let mut env = Env {
            modules: Vec::new(),
            file,
            open_files: HashMap::new(),
            next_handle: FILE_HANDLE_BASE,
            crt_cell: ENV_BASE + 0x100,
            traps: HashMap::new(),
            image_base,
            heap_next: HEAP_BASE,
            allocations: Vec::new(),
            last_error: 0,
            tick: 0x0001_0000,
            perf: 0x0010_0000,
            tls: HashMap::new(),
            tls_next: 1,
            missing_apis: Vec::new(),
            trace: false,
            api_log: Vec::new(),
            bulk_bytes: 0,
        };
        map(mem, STACK_BASE, STACK_SIZE)?;
        map(mem, ENV_BASE, PAGE_SIZE as u32)?;
        map(mem, LDR_BASE, 0x4000)?;
        env.build_shared_user_data(mem)?;

        for &(name, base) in PRELOADED {
            // The image is mapped before the environment is built, and it is
            // free to claim any base — including the address a real system DLL
            // lives at. Laying a synthetic module over it would corrupt the
            // program being unpacked and hide the emulator's own traps inside
            // it, so a colliding module is placed elsewhere instead.
            let mut at = base;
            for _ in 0..64 {
                if !mem.any_mapped(at, MODULE_SIZE) {
                    break;
                }
                at = at.saturating_sub(MODULE_SIZE);
            }
            env.create_module(mem, name, at)?;
        }
        env.build_teb_peb(mem, image_base, image_size)?;

        // Strings the string-returning APIs hand back.
        write_c_str(mem, ENV_BASE, "C:\\sample.exe")?;
        write_c_str(mem, ENV_BASE + 0x40, "\"C:\\sample.exe\"")?;
        Ok(env)
    }

    /// Address range the export traps live in, so the driver can recognise a
    /// call into one before it tries to decode an instruction there.
    pub fn is_trap(&self, addr: u32) -> bool {
        self.traps.contains_key(&addr)
    }

    /// The return address a thread starts with — inside `kernel32`, as on
    /// Windows, where a thread's first frame returns into
    /// `BaseProcessStart`.
    ///
    /// This is not cosmetic. A stub that wants `kernel32`'s base without
    /// touching the PEB reads the return address off the stack and walks
    /// *backwards* looking for the `MZ` header of the module it points into.
    /// Point the return address at a made-up sentinel and that walk runs off
    /// into unmapped memory; point it into the synthetic `kernel32` and the
    /// walk finds exactly what it is looking for.
    pub fn process_return(&self) -> u32 {
        self.kernel32_base() + RETURN_OFFSET
    }

    /// Return address handed to an SEH handler, in the same module for the same
    /// reason.
    pub fn seh_return(&self) -> u32 {
        self.kernel32_base() + RETURN_OFFSET + 0x10
    }

    fn kernel32_base(&self) -> u32 {
        self.find_module_by_name("kernel32.dll")
            .map(|m| m.base)
            .unwrap_or(0x7c80_0000)
    }

    fn find_module(&self, base: u32) -> Option<&Module> {
        self.modules.iter().find(|m| m.base == base)
    }

    fn find_module_by_name(&self, name: &str) -> Option<&Module> {
        let want = normalize_module(name);
        self.modules.iter().find(|m| m.name == want)
    }

    /// Create a synthetic DLL: PE headers, an export directory naming every API
    /// the emulator implements for it, and one trap address per export.
    fn create_module(&mut self, mem: &mut Mem, name: &str, base: u32) -> Result<(), Stop> {
        map(mem, base, MODULE_SIZE)?;
        let name = normalize_module(name);
        let exports: Vec<&ApiSpec> = {
            let mut v: Vec<&ApiSpec> = APIS.iter().filter(|s| s.module == name).collect();
            // Windows keeps the export name table sorted, and hand-written
            // resolvers binary-search it.
            v.sort_by_key(|s| s.name);
            v
        };

        let mut trap = base + TRAP_OFFSET;
        // Export directory at RVA 0x1000, arrays and strings after it.
        let ed_rva = 0x1000u32;
        let n = exports.len() as u32;
        let funcs_rva = ed_rva + 40;
        let names_rva = funcs_rva + n * 4;
        let ords_rva = names_rva + n * 4;
        let strings_rva = ords_rva + n * 2;

        let mut ed = Vec::with_capacity(40);
        ed.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
        ed.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        ed.extend_from_slice(&0u32.to_le_bytes()); // Major/Minor version
        ed.extend_from_slice(&strings_rva.to_le_bytes()); // Name (points at the
                                                          // first string, which
                                                          // is close enough for
                                                          // a resolver that
                                                          // only reads exports)
        ed.extend_from_slice(&1u32.to_le_bytes()); // Base ordinal
        ed.extend_from_slice(&n.to_le_bytes()); // NumberOfFunctions
        ed.extend_from_slice(&n.to_le_bytes()); // NumberOfNames
        ed.extend_from_slice(&funcs_rva.to_le_bytes());
        ed.extend_from_slice(&names_rva.to_le_bytes());
        ed.extend_from_slice(&ords_rva.to_le_bytes());
        mem.write_bytes(base + ed_rva, &ed).map_err(Stop::Fault)?;

        let mut str_rva = strings_rva;
        for (i, spec) in exports.iter().enumerate() {
            let i = i as u32;
            mem.write_u32(base + funcs_rva + i * 4, trap - base)
                .map_err(Stop::Fault)?;
            mem.write_u32(base + names_rva + i * 4, str_rva)
                .map_err(Stop::Fault)?;
            mem.write_u16(base + ords_rva + i * 2, i as u16)
                .map_err(Stop::Fault)?;
            write_c_str(mem, base + str_rva, spec.name)?;
            str_rva += spec.name.len() as u32 + 1;
            self.traps.insert(
                trap,
                Trap {
                    api: Some(spec.api),
                    argc: spec.argc,
                    module: name.clone(),
                    name: spec.name.to_string(),
                },
            );
            trap += TRAP_STRIDE;
        }

        write_module_headers(mem, base, MODULE_SIZE, ed_rva, str_rva - ed_rva)?;
        self.modules.push(Module {
            name,
            base,
            size: MODULE_SIZE,
            trap_next: trap,
        });
        Ok(())
    }

    /// Fill `KUSER_SHARED_DATA` with the handful of fields a stub reads: the
    /// interrupt/tick counters (used for timing checks) and the OS version.
    fn build_shared_user_data(&self, mem: &mut Mem) -> Result<(), Stop> {
        map(mem, SHARED_USER_DATA, PAGE_SIZE as u32)?;
        mem.write_u32(SHARED_USER_DATA, 0x0010_0000)
            .map_err(Stop::Fault)?; // TickCountLow
        mem.write_u32(SHARED_USER_DATA + 0x04, 0x000f_a000)
            .map_err(Stop::Fault)?; // TickCountMultiplier
        mem.write_u32(SHARED_USER_DATA + 0x08, 0x0010_0000)
            .map_err(Stop::Fault)?; // InterruptTime.LowPart
        mem.write_u32(SHARED_USER_DATA + 0x14, 0x1000_0000)
            .map_err(Stop::Fault)?; // SystemTime.LowPart
        write_utf16(mem, SHARED_USER_DATA + 0x30, "C:\\WINDOWS")?; // NtSystemRoot
        mem.write_u32(SHARED_USER_DATA + 0x26c, 5)
            .map_err(Stop::Fault)?; // NtMajorVersion
        mem.write_u32(SHARED_USER_DATA + 0x270, 1)
            .map_err(Stop::Fault)?; // NtMinorVersion
        Ok(())
    }

    /// Build the TEB, PEB and the three loader module lists.
    fn build_teb_peb(
        &mut self,
        mem: &mut Mem,
        image_base: u32,
        image_size: u32,
    ) -> Result<(), Stop> {
        map(mem, TEB_BASE, PAGE_SIZE as u32)?;
        map(mem, PEB_BASE, PAGE_SIZE as u32)?;

        // TEB.
        mem.write_u32(TEB_BASE, 0xffff_ffff).map_err(Stop::Fault)?; // ExceptionList: chain end
        mem.write_u32(TEB_BASE + 0x04, STACK_TOP)
            .map_err(Stop::Fault)?; // StackBase
        mem.write_u32(TEB_BASE + 0x08, STACK_BASE)
            .map_err(Stop::Fault)?; // StackLimit
        mem.write_u32(TEB_BASE + 0x18, TEB_BASE)
            .map_err(Stop::Fault)?; // Self
        mem.write_u32(TEB_BASE + 0x20, 0x0000_0abc)
            .map_err(Stop::Fault)?; // ProcessId
        mem.write_u32(TEB_BASE + 0x24, 0x0000_0def)
            .map_err(Stop::Fault)?; // ThreadId
        mem.write_u32(TEB_BASE + 0x30, PEB_BASE)
            .map_err(Stop::Fault)?; // PEB

        // PEB. `BeingDebugged` and `NtGlobalFlag` are the two fields anti-debug
        // stubs read directly, and both say "no debugger".
        mem.write_u32(PEB_BASE + 0x08, image_base)
            .map_err(Stop::Fault)?; // ImageBaseAddress
        mem.write_u32(PEB_BASE + 0x0c, LDR_BASE)
            .map_err(Stop::Fault)?; // Ldr
        mem.write_u32(PEB_BASE + 0x18, PROCESS_HEAP)
            .map_err(Stop::Fault)?; // ProcessHeap
        mem.write_u32(PEB_BASE + 0x64, 1).map_err(Stop::Fault)?; // NumberOfProcessors
        mem.write_u32(PEB_BASE + 0x68, 0).map_err(Stop::Fault)?; // NtGlobalFlag
        mem.write_u32(PEB_BASE + 0xa4, 5).map_err(Stop::Fault)?; // OSMajorVersion
        mem.write_u32(PEB_BASE + 0xa8, 1).map_err(Stop::Fault)?; // OSMinorVersion
        mem.write_u32(PEB_BASE + 0xac, 2600).map_err(Stop::Fault)?; // OSBuildNumber
        mem.write_u32(PEB_BASE + 0xb0, 2).map_err(Stop::Fault)?; // PlatformId

        // PEB_LDR_DATA followed by one LDR_DATA_TABLE_ENTRY per module. The
        // executable itself comes first in load and memory order, but not in
        // initialisation order — which is what a stub indexing
        // `Ldr->InInitializationOrderModuleList` to reach `kernel32` relies on.
        let ldr = LDR_BASE;
        let entry0 = LDR_BASE + 0x100;
        const ENTRY_SIZE: u32 = 0x60;

        struct L {
            base: u32,
            size: u32,
            name: String,
            in_init: bool,
        }
        let mut list = vec![L {
            base: image_base,
            size: image_size,
            name: "sample.exe".to_string(),
            in_init: false,
        }];
        for m in &self.modules {
            list.push(L {
                base: m.base,
                size: m.size,
                name: m.name.clone(),
                in_init: true,
            });
        }

        let addr_of = |i: usize| entry0 + i as u32 * ENTRY_SIZE;
        let load_head = ldr + 0x0c;
        let mem_head = ldr + 0x14;
        let init_head = ldr + 0x1c;

        mem.write_u32(ldr, 0x28).map_err(Stop::Fault)?; // Length
        mem.write_u32(ldr + 4, 1).map_err(Stop::Fault)?; // Initialized

        let init_idx: Vec<usize> = (0..list.len()).filter(|&i| list[i].in_init).collect();
        let all_idx: Vec<usize> = (0..list.len()).collect();

        // Cross-link one doubly-linked list. `off` is where in the entry the
        // links for this list live; the head is a LIST_ENTRY in PEB_LDR_DATA.
        let link = |mem: &mut Mem, head: u32, off: u32, order: &[usize]| -> Result<(), Stop> {
            let node = |i: usize| addr_of(i) + off;
            for (pos, &i) in order.iter().enumerate() {
                let next = if pos + 1 < order.len() {
                    node(order[pos + 1])
                } else {
                    head
                };
                let prev = if pos > 0 { node(order[pos - 1]) } else { head };
                mem.write_u32(node(i), next).map_err(Stop::Fault)?;
                mem.write_u32(node(i) + 4, prev).map_err(Stop::Fault)?;
            }
            let first = order.first().map(|&i| node(i)).unwrap_or(head);
            let last = order.last().map(|&i| node(i)).unwrap_or(head);
            mem.write_u32(head, first).map_err(Stop::Fault)?;
            mem.write_u32(head + 4, last).map_err(Stop::Fault)?;
            Ok(())
        };
        link(mem, load_head, 0x00, &all_idx)?;
        link(mem, mem_head, 0x08, &all_idx)?;
        link(mem, init_head, 0x10, &init_idx)?;

        for (i, l) in list.iter().enumerate() {
            let e = addr_of(i);
            mem.write_u32(e + 0x18, l.base).map_err(Stop::Fault)?; // DllBase
            mem.write_u32(e + 0x1c, l.base).map_err(Stop::Fault)?; // EntryPoint
            mem.write_u32(e + 0x20, l.size).map_err(Stop::Fault)?; // SizeOfImage
                                                                   // FullDllName / BaseDllName as UNICODE_STRINGs pointing into the
                                                                   // string area after the entries.
            let str_addr = entry0 + list.len() as u32 * ENTRY_SIZE + i as u32 * 0x80;
            let wide: Vec<u8> = l
                .name
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .chain([0, 0])
                .collect();
            mem.write_bytes(str_addr, &wide).map_err(Stop::Fault)?;
            let len = (l.name.len() * 2) as u16;
            for off in [0x24u32, 0x2c] {
                mem.write_u16(e + off, len).map_err(Stop::Fault)?;
                mem.write_u16(e + off + 2, len + 2).map_err(Stop::Fault)?;
                mem.write_u32(e + off + 4, str_addr).map_err(Stop::Fault)?;
            }
        }
        Ok(())
    }

    /// Allocate `size` bytes of emulated memory at `addr` (or wherever there is
    /// room when `addr` is 0). Returns 0 when the request cannot be served,
    /// which is what a stub sees as a failed `VirtualAlloc`.
    fn alloc(&mut self, mem: &mut Mem, addr: u32, size: u32) -> u32 {
        if size == 0 || size > 512 << 20 {
            return 0;
        }
        let rounded = (size + PAGE_SIZE as u32 - 1) & !(PAGE_SIZE as u32 - 1);
        let base = if addr != 0 {
            addr & !(PAGE_SIZE as u32 - 1)
        } else {
            let b = self.heap_next;
            if b.saturating_add(rounded) >= HEAP_LIMIT {
                return 0;
            }
            self.heap_next = b + rounded + PAGE_SIZE as u32; // guard page
            b
        };
        if mem.map(base, rounded).is_err() {
            return 0;
        }
        self.allocations.push((base, rounded));
        base
    }

    /// Bytes moved by block-copy APIs since the last call, and reset.
    ///
    /// The driver turns this into ticks so the budget bounds WORK rather than
    /// call count. Without it a stub reaches the same total copying in one
    /// `memcpy` per tick that a `rep movsb` would be charged the full price for.
    pub fn take_bulk_bytes(&mut self) -> u64 {
        std::mem::take(&mut self.bulk_bytes)
    }

    /// Service the call at a trap address. The instruction pointer is at the
    /// trap; on return it is at the caller's return address with the stack
    /// unwound per the export's calling convention.
    pub fn call(&mut self, cpu: &mut Cpu, mem: &mut Mem) -> Result<ApiEffect, Stop> {
        let addr = cpu.eip;
        let (api, argc, module, name) = match self.traps.get(&addr) {
            Some(t) => (t.api, t.argc, t.module.clone(), t.name.clone()),
            None => return Ok(ApiEffect::Unimplemented),
        };
        // Arguments as the callee sees them: [esp] is the return address.
        let ret = cpu.pop32(mem)?;

        let Some(api) = api else {
            // No implementation, but stopping here would throw away everything
            // the stub already rebuilt. Return to the caller with a failure
            // value and the arguments untouched — correct for a cdecl export,
            // and for a stdcall one it leaves the stack skewed, which is why
            // the call is recorded rather than passed over in silence.
            if self.missing_apis.len() < 64 {
                self.missing_apis.push(format!("{module}!{name}"));
            }
            cpu.regs[EAX] = 0;
            cpu.eip = ret;
            return Ok(ApiEffect::Unimplemented);
        };
        let arg = |cpu: &Cpu, mem: &mut Mem, i: u32| -> Result<u32, Stop> {
            mem.read_u32(cpu.regs[ESP].wrapping_add(i * 4))
                .map_err(Stop::Fault)
        };

        let mut effect = ApiEffect::Continue;
        let result: u32 = match api {
            Api::Const(v) => v,
            Api::LoadLibrary { wide } => {
                let p = arg(cpu, mem, 0)?;
                let name = read_str(mem, p, wide)?;
                match self.find_module_by_name(&name).map(|m| m.base) {
                    Some(b) => b,
                    None => {
                        let base = self.next_module_base();
                        match self.create_module(mem, &name, base) {
                            Ok(()) => base,
                            Err(_) => 0,
                        }
                    }
                }
            }
            Api::GetProcAddress => {
                let hmod = arg(cpu, mem, 0)?;
                let p = arg(cpu, mem, 1)?;
                self.resolve_export(mem, hmod, p)?
            }
            Api::GetModuleHandle { wide } => {
                let p = arg(cpu, mem, 0)?;
                if p == 0 {
                    self.image_base
                } else {
                    let name = read_str(mem, p, wide)?;
                    match self.find_module_by_name(&name).map(|m| m.base) {
                        Some(b) => b,
                        // A system DLL a real process has loaded (or would have
                        // loaded by now) reports as present, because a stub that
                        // asks for one and is told "not loaded" concludes it is
                        // running somewhere broken and gives up — `mscoree.dll`
                        // is how every packed .NET binary stopped. Anything
                        // *not* on this list still reports absent: naming an
                        // unknown DLL is how a stub probes for a sandbox, and
                        // the honest answer there is that it is not there.
                        None if is_system_dll(&name) => {
                            let base = self.next_module_base();
                            match self.create_module(mem, &name, base) {
                                Ok(()) => base,
                                Err(_) => 0,
                            }
                        }
                        None => 0,
                    }
                }
            }
            Api::GetModuleFileName { wide } => {
                let buf = arg(cpu, mem, 1)?;
                let cap = arg(cpu, mem, 2)?;
                let path = "C:\\sample.exe";
                write_str(mem, buf, path, wide, cap)?
            }
            Api::VirtualAlloc => {
                let addr = arg(cpu, mem, 0)?;
                let size = arg(cpu, mem, 1)?;
                self.alloc(mem, addr, size)
            }
            Api::VirtualFree => 1,
            Api::VirtualProtect => {
                // Report the previous protection as "everything", which is what
                // a stub that saves and restores it will put back.
                let old = arg(cpu, mem, 3)?;
                if old != 0 {
                    mem.write_u32(old, 0x40).map_err(Stop::Fault)?;
                }
                1
            }
            Api::VirtualQuery => {
                let addr = arg(cpu, mem, 0)?;
                let mbi = arg(cpu, mem, 1)?;
                let page = addr & !(PAGE_SIZE as u32 - 1);
                let committed = mem.is_mapped(page, 1);
                mem.write_u32(mbi, page).map_err(Stop::Fault)?; // BaseAddress
                mem.write_u32(mbi + 4, page).map_err(Stop::Fault)?; // AllocationBase
                mem.write_u32(mbi + 8, 0x40).map_err(Stop::Fault)?; // AllocationProtect
                mem.write_u32(mbi + 12, PAGE_SIZE as u32)
                    .map_err(Stop::Fault)?; // RegionSize
                mem.write_u32(mbi + 16, if committed { 0x1000 } else { 0x10000 })
                    .map_err(Stop::Fault)?; // State
                mem.write_u32(mbi + 20, 0x40).map_err(Stop::Fault)?; // Protect
                mem.write_u32(mbi + 24, 0x20000).map_err(Stop::Fault)?; // Type
                28
            }
            Api::HeapCreate => PROCESS_HEAP,
            Api::GetProcessHeap => PROCESS_HEAP,
            Api::HeapAlloc => {
                let size = arg(cpu, mem, 2)?;
                self.alloc(mem, 0, size)
            }
            Api::HeapReAlloc => {
                let old = arg(cpu, mem, 2)?;
                let size = arg(cpu, mem, 3)?;
                let new = self.alloc(mem, 0, size);
                if new != 0 && old != 0 {
                    let keep = self
                        .allocations
                        .iter()
                        .find(|&&(b, _)| b == old)
                        .map(|&(_, s)| s.min(size))
                        .unwrap_or(0);
                    if keep > 0 {
                        let bytes = mem.snapshot(old, keep as usize);
                        mem.write_bytes(new, &bytes).map_err(Stop::Fault)?;
                    }
                }
                new
            }
            Api::HeapFree => 1,
            Api::LocalAlloc | Api::GlobalAlloc => {
                let size = arg(cpu, mem, 1)?;
                self.alloc(mem, 0, size)
            }
            Api::CrtMalloc => {
                let size = arg(cpu, mem, 0)?;
                self.alloc(mem, 0, size)
            }
            Api::GetLocaleInfo { wide } => {
                let buf = arg(cpu, mem, 2)?;
                let cch = arg(cpu, mem, 3)?;
                if cch == 0 || buf == 0 {
                    2 // characters the caller would need to allocate
                } else {
                    write_str(mem, buf, "1", wide, cch)?;
                    2
                }
            }
            Api::CrtDataPointer => {
                // One cell per call site is unnecessary: the caller reads or
                // writes it and moves on, and nothing here depends on two
                // accessors returning different cells.
                let cell = self.crt_cell;
                if cell != 0 {
                    // Point it at the command line, the only one of these whose
                    // value a start-up path actually walks.
                    mem.write_u32(cell, ENV_BASE + 0x40).map_err(Stop::Fault)?;
                }
                cell
            }
            Api::CharNext => {
                let p = arg(cpu, mem, 0)?;
                // Past the terminator is still the terminator, which is what
                // the real one does at the end of a string.
                if mem.read_u8(p).map_err(Stop::Fault)? == 0 {
                    p
                } else {
                    p.wrapping_add(1)
                }
            }
            Api::CrtStrncpy => {
                let dst = arg(cpu, mem, 0)?;
                let src = arg(cpu, mem, 1)?;
                let n = arg(cpu, mem, 2)?.min(1 << 20);
                let bytes = mem.snapshot(src, n as usize);
                let cut = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                mem.write_bytes(dst, &bytes[..cut]).map_err(Stop::Fault)?;
                dst
            }
            Api::MemFree => 0,
            Api::ExitProcess => {
                effect = ApiEffect::Exit;
                0
            }
            Api::GetVersion => 0x0a28_0105, // Windows XP, as a stub expects
            Api::GetVersionEx => {
                let p = arg(cpu, mem, 0)?;
                mem.write_u32(p + 4, 5).map_err(Stop::Fault)?; // major
                mem.write_u32(p + 8, 1).map_err(Stop::Fault)?; // minor
                mem.write_u32(p + 12, 2600).map_err(Stop::Fault)?; // build
                mem.write_u32(p + 16, 2).map_err(Stop::Fault)?; // platform
                1
            }
            Api::GetTickCount => {
                self.tick = self.tick.wrapping_add(0x10);
                self.tick
            }
            Api::QueryPerformanceCounter => {
                let p = arg(cpu, mem, 0)?;
                self.perf = self.perf.wrapping_add(0x1000);
                mem.write_u32(p, self.perf as u32).map_err(Stop::Fault)?;
                mem.write_u32(p + 4, (self.perf >> 32) as u32)
                    .map_err(Stop::Fault)?;
                1
            }
            Api::IsDebuggerPresent => 0,
            Api::GetLastError => self.last_error,
            Api::SetLastError => {
                self.last_error = arg(cpu, mem, 0)?;
                0
            }
            Api::GetCurrentProcess => INVALID_HANDLE,
            Api::GetCurrentThread => 0xffff_fffe,
            Api::GetCurrentProcessId => 0x0abc,
            Api::GetCommandLine { wide } => {
                if wide {
                    let n = write_str(mem, ENV_BASE + 0x80, "\"C:\\sample.exe\"", true, 0x40)?;
                    let _ = n;
                    ENV_BASE + 0x80
                } else {
                    ENV_BASE + 0x40
                }
            }
            Api::GetStartupInfo => {
                let p = arg(cpu, mem, 0)?;
                let zero = [0u8; 68];
                mem.write_bytes(p, &zero).map_err(Stop::Fault)?;
                mem.write_u32(p, 68).map_err(Stop::Fault)?; // cb
                0
            }
            Api::GetSystemInfo => {
                let p = arg(cpu, mem, 0)?;
                let zero = [0u8; 36];
                mem.write_bytes(p, &zero).map_err(Stop::Fault)?;
                mem.write_u32(p + 4, PAGE_SIZE as u32)
                    .map_err(Stop::Fault)?; // dwPageSize
                mem.write_u32(p + 8, 0x0001_0000).map_err(Stop::Fault)?; // lpMinimumApplicationAddress
                mem.write_u32(p + 12, 0x7ffe_0000).map_err(Stop::Fault)?; // lpMaximumApplicationAddress
                mem.write_u32(p + 20, 1).map_err(Stop::Fault)?; // dwNumberOfProcessors
                mem.write_u32(p + 32, 0x1000).map_err(Stop::Fault)?; // dwAllocationGranularity
                0
            }
            Api::GetSystemTimeAsFileTime => {
                let p = arg(cpu, mem, 0)?;
                self.perf = self.perf.wrapping_add(0x1000);
                mem.write_u32(p, self.perf as u32).map_err(Stop::Fault)?;
                mem.write_u32(p + 4, 0x01c9_0000).map_err(Stop::Fault)?;
                0
            }
            Api::TlsAlloc => {
                let i = self.tls_next;
                self.tls_next += 1;
                i
            }
            Api::TlsSetValue => {
                let i = arg(cpu, mem, 0)?;
                let v = arg(cpu, mem, 1)?;
                self.tls.insert(i, v);
                1
            }
            Api::TlsGetValue => {
                let i = arg(cpu, mem, 0)?;
                self.tls.get(&i).copied().unwrap_or(0)
            }
            Api::Sleep => 0,
            Api::CloseHandle => 1,
            Api::CreateFile { wide } => {
                let p = arg(cpu, mem, 0)?;
                let path = read_str(mem, p, wide)?;
                if self.is_own_path(&path) {
                    let h = self.next_handle;
                    self.next_handle += 4;
                    self.open_files.insert(h, 0);
                    h
                } else {
                    // Every other path does not exist here at all: there is
                    // no host filesystem behind this environment.
                    self.last_error = 2; // ERROR_FILE_NOT_FOUND
                    INVALID_HANDLE
                }
            }
            Api::ReadFile => {
                let h = arg(cpu, mem, 0)?;
                let buf = arg(cpu, mem, 1)?;
                let want = arg(cpu, mem, 2)?;
                let read_ptr = arg(cpu, mem, 3)?;
                let pos = match self.open_files.get(&h) {
                    Some(&p) => p,
                    // Not a handle this environment handed out.
                    None => 0xffff_ffff,
                };
                if pos == 0xffff_ffff {
                    0
                } else {
                    let start = (pos as usize).min(self.file.len());
                    let end = start
                        .saturating_add(want.min(64 << 20) as usize)
                        .min(self.file.len());
                    let n = end - start;
                    if n > 0 {
                        self.bulk_bytes += n as u64;
                        let bytes = self.file[start..end].to_vec();
                        mem.write_bytes(buf, &bytes).map_err(Stop::Fault)?;
                    }
                    self.open_files.insert(h, pos.wrapping_add(n as u32));
                    if read_ptr != 0 {
                        mem.write_u32(read_ptr, n as u32).map_err(Stop::Fault)?;
                    }
                    1
                }
            }
            Api::WriteFile => {
                // Writes are accepted and discarded: nothing here is persistent,
                // and a stub that checks the return value should see success so
                // it keeps unpacking rather than erroring out.
                let want = arg(cpu, mem, 2)?;
                let written = arg(cpu, mem, 3)?;
                if written != 0 {
                    mem.write_u32(written, want).map_err(Stop::Fault)?;
                }
                1
            }
            Api::SetFilePointer => {
                let h = arg(cpu, mem, 0)?;
                let dist = arg(cpu, mem, 1)? as i32;
                let method = arg(cpu, mem, 3)?;
                let len = self.file.len() as i64;
                let cur = self.open_files.get(&h).copied().unwrap_or(0) as i64;
                let base = match method {
                    1 => cur, // FILE_CURRENT
                    2 => len, // FILE_END
                    _ => 0,   // FILE_BEGIN
                };
                let pos = (base + dist as i64).clamp(0, len) as u32;
                if self.open_files.contains_key(&h) {
                    self.open_files.insert(h, pos);
                }
                pos
            }
            Api::GetFileSize => {
                let high = arg(cpu, mem, 1)?;
                if high != 0 {
                    mem.write_u32(high, 0).map_err(Stop::Fault)?;
                }
                self.file.len() as u32
            }
            Api::CreateFileMapping => {
                let h = arg(cpu, mem, 0)?;
                if self.open_files.contains_key(&h) {
                    MAPPING_HANDLE_BASE
                } else {
                    0
                }
            }
            Api::MapViewOfFile => {
                let h = arg(cpu, mem, 0)?;
                if h != MAPPING_HANDLE_BASE {
                    0
                } else {
                    // Map the whole file, which is what a stub that maps itself
                    // wants; the size argument is a maximum, and 0 means "all".
                    let want = arg(cpu, mem, 4)?;
                    let len = if want == 0 {
                        self.file.len() as u32
                    } else {
                        (want as usize).min(self.file.len()) as u32
                    };
                    let base = self.alloc(mem, 0, len.max(1));
                    if base != 0 {
                        self.bulk_bytes += u64::from(len);
                        let bytes = self.file[..len as usize].to_vec();
                        mem.write_bytes(base, &bytes).map_err(Stop::Fault)?;
                    }
                    base
                }
            }
            Api::GetStdHandle => 0x0000_0007,
            Api::SetUnhandledExceptionFilter => 0,
            Api::InterlockedExchange => {
                let p = arg(cpu, mem, 0)?;
                let v = arg(cpu, mem, 1)?;
                let old = mem.read_u32(p).map_err(Stop::Fault)?;
                mem.write_u32(p, v).map_err(Stop::Fault)?;
                old
            }
            Api::LstrLen { wide } => {
                let p = arg(cpu, mem, 0)?;
                read_str(mem, p, wide)?.chars().count() as u32
            }
            Api::LstrCpy { wide } => {
                let dst = arg(cpu, mem, 0)?;
                let src = arg(cpu, mem, 1)?;
                let s = read_str(mem, src, wide)?;
                write_str(mem, dst, &s, wide, u32::MAX)?;
                dst
            }
            Api::LstrCat { wide } => {
                let dst = arg(cpu, mem, 0)?;
                let src = arg(cpu, mem, 1)?;
                let a = read_str(mem, dst, wide)?;
                let b = read_str(mem, src, wide)?;
                let joined = format!("{a}{b}");
                write_str(mem, dst, &joined, wide, u32::MAX)?;
                dst
            }
            Api::LstrCmpi { wide } => {
                let (pa, pb) = (arg(cpu, mem, 0)?, arg(cpu, mem, 1)?);
                let a = read_str(mem, pa, wide)?.to_ascii_lowercase();
                let b = read_str(mem, pb, wide)?.to_ascii_lowercase();
                match a.cmp(&b) {
                    std::cmp::Ordering::Less => (-1i32) as u32,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                }
            }
            Api::Memcpy | Api::RtlMoveMemory => {
                let dst = arg(cpu, mem, 0)?;
                let src = arg(cpu, mem, 1)?;
                let n = arg(cpu, mem, 2)?.min(64 << 20);
                self.bulk_bytes += u64::from(n);
                let bytes = mem.snapshot(src, n as usize);
                mem.write_bytes(dst, &bytes).map_err(Stop::Fault)?;
                dst
            }
            Api::Memset => {
                let dst = arg(cpu, mem, 0)?;
                let v = arg(cpu, mem, 1)? as u8;
                let n = arg(cpu, mem, 2)?.min(64 << 20);
                self.bulk_bytes += u64::from(n);
                let bytes = vec![v; n as usize];
                mem.write_bytes(dst, &bytes).map_err(Stop::Fault)?;
                dst
            }
            Api::RtlZeroMemory => {
                let dst = arg(cpu, mem, 0)?;
                let n = arg(cpu, mem, 1)?.min(64 << 20);
                self.bulk_bytes += u64::from(n);
                let bytes = vec![0u8; n as usize];
                mem.write_bytes(dst, &bytes).map_err(Stop::Fault)?;
                0
            }
            Api::NtProtect => 0, // STATUS_SUCCESS
            Api::NtAllocate => {
                // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits,
                // *RegionSize, AllocationType, Protect)
                let base_ptr = arg(cpu, mem, 1)?;
                let size_ptr = arg(cpu, mem, 3)?;
                let want = mem.read_u32(base_ptr).map_err(Stop::Fault)?;
                let size = mem.read_u32(size_ptr).map_err(Stop::Fault)?;
                let got = self.alloc(mem, want, size);
                if got == 0 {
                    0xc000_0017u32 // STATUS_NO_MEMORY
                } else {
                    mem.write_u32(base_ptr, got).map_err(Stop::Fault)?;
                    0
                }
            }
            Api::NtQueryInformationProcess => {
                // Anti-debug queries (ProcessDebugPort and friends): a zeroed
                // buffer is the "not being debugged" answer.
                let buf = arg(cpu, mem, 2)?;
                let len = arg(cpu, mem, 3)?.min(64);
                let zero = vec![0u8; len as usize];
                mem.write_bytes(buf, &zero).map_err(Stop::Fault)?;
                0
            }
        };

        if self.trace && self.api_log.len() < 4096 {
            // Log the *string* a name-taking export was given, not the pointer:
            // "GetProcAddress(kernel32, 0x1fbdb4)" says nothing, and which name
            // a stub asked for is usually the whole answer.
            let a: Vec<String> = (0..argc.min(6) as u32)
                .map(|i| match arg(cpu, mem, i) {
                    Ok(v) => match read_str(mem, v, false) {
                        Ok(s) if s.len() >= 3 && s.chars().all(|c| c.is_ascii_graphic()) => {
                            format!("\"{s}\"")
                        }
                        _ => format!("{v:#x}"),
                    },
                    Err(_) => "?".into(),
                })
                .collect();
            self.api_log
                .push(format!("{module}!{name}({}) -> {result:#x}", a.join(", ")));
        }
        cpu.regs[EAX] = result;
        cpu.regs[ESP] = cpu.regs[ESP].wrapping_add(argc as u32 * 4);
        cpu.eip = ret;
        Ok(effect)
    }

    /// Do what the Windows loader does before the entry point runs: walk the
    /// image's import directory and fill every IAT slot with the address of the
    /// imported function.
    ///
    /// This is not an optimisation. A packed image imports the handful of
    /// functions its stub needs — typically `LoadLibraryA` and
    /// `GetProcAddress` — and the stub *calls them through the IAT*, trusting
    /// the loader to have filled it in. Skip this and the very first thing the
    /// stub does is an indirect call through a slot still holding an on-disk
    /// RVA, which is a fault on an address that looks meaningless.
    ///
    /// Returns how many slots were bound. A malformed import directory binds
    /// what it can and stops: the file still runs on Windows up to the point
    /// where its imports are wrong, and so does the emulation.
    pub fn bind_imports(
        &mut self,
        mem: &mut Mem,
        base: u32,
        dir_rva: u32,
        dir_size: u32,
    ) -> Result<usize, Stop> {
        const DESCRIPTOR: u32 = 20;
        const MAX_DESCRIPTORS: u32 = 512;
        const MAX_THUNKS: u32 = 8192;
        if dir_rva == 0 || dir_size == 0 || !mem.is_mapped(base.wrapping_add(dir_rva), DESCRIPTOR) {
            return Ok(0);
        }
        let mut bound = 0usize;
        for i in 0..MAX_DESCRIPTORS.min(dir_size / DESCRIPTOR + 1) {
            let d = base.wrapping_add(dir_rva).wrapping_add(i * DESCRIPTOR);
            if !mem.is_mapped(d, DESCRIPTOR) {
                break;
            }
            let orig_thunk = mem.read_u32(d).map_err(Stop::Fault)?;
            let name_rva = mem.read_u32(d + 12).map_err(Stop::Fault)?;
            let first_thunk = mem.read_u32(d + 16).map_err(Stop::Fault)?;
            if name_rva == 0 && first_thunk == 0 {
                break; // the terminating all-zero descriptor
            }
            let dll = match read_str(mem, base.wrapping_add(name_rva), false) {
                Ok(n) if !n.is_empty() => n,
                _ => continue,
            };
            let module_base = match self.find_module_by_name(&dll).map(|m| m.base) {
                Some(b) => b,
                None => {
                    let b = self.next_module_base();
                    if self.create_module(mem, &dll, b).is_err() {
                        continue;
                    }
                    b
                }
            };
            // The name table is preferred, but a file whose `OriginalFirstThunk`
            // is zero (or which was bound) keeps the names in the IAT itself.
            let names_at = if orig_thunk != 0 {
                orig_thunk
            } else {
                first_thunk
            };
            if names_at == 0 || first_thunk == 0 {
                continue;
            }
            for t in 0..MAX_THUNKS {
                let name_slot = base.wrapping_add(names_at).wrapping_add(t * 4);
                let iat_slot = base.wrapping_add(first_thunk).wrapping_add(t * 4);
                if !mem.is_mapped(name_slot, 4) || !mem.is_mapped(iat_slot, 4) {
                    break;
                }
                let v = mem.read_u32(name_slot).map_err(Stop::Fault)?;
                if v == 0 {
                    break;
                }
                let name = if v & 0x8000_0000 != 0 {
                    format!("#{}", v & 0xffff)
                } else {
                    // IMAGE_IMPORT_BY_NAME: a hint word, then the name.
                    match read_str(mem, base.wrapping_add(v).wrapping_add(2), false) {
                        Ok(n) if !n.is_empty() => n,
                        _ => break,
                    }
                };
                let addr = self.export_addr(module_base, &name);
                mem.write_u32(iat_slot, addr).map_err(Stop::Fault)?;
                bound += 1;
            }
        }
        Ok(bound)
    }

    /// `GetProcAddress`: by name or by ordinal. A name the emulator does not
    /// implement still resolves — to a trap that reports itself when called —
    /// because a stub that cannot resolve an import usually aborts, and then we
    /// learn nothing at all.
    fn resolve_export(&mut self, mem: &mut Mem, hmod: u32, p: u32) -> Result<u32, Stop> {
        let name = if p < 0x1_0000 {
            format!("#{p}") // by ordinal
        } else {
            read_str(mem, p, false)?
        };
        Ok(self.export_addr(hmod, &name))
    }

    /// Address of `name` in the module loaded at `module_base`, allocating a
    /// fresh trap for an export the emulator has no implementation for.
    fn export_addr(&mut self, hmod: u32, name: &str) -> u32 {
        let Some(module_name) = self.find_module(hmod).map(|m| m.name.clone()) else {
            return 0;
        };
        // The lowest matching trap, not the first one iteration happens to
        // reach. More than one can match — a module created twice under two
        // spellings of its name, or an alias resolved after the export table
        // was built — and `traps` is a hash map, whose order varies from run to
        // run. Picking arbitrarily makes the *unpacked image* differ between
        // runs, because the address lands in the import table the stub
        // rebuilds; a scanner whose output is not reproducible cannot be
        // differentially tested, and its hash-based signatures do not match
        // twice. Lowest also means the module's own export table wins over a
        // trap allocated later for an unknown name.
        if let Some(addr) = self
            .traps
            .iter()
            .filter(|(_, t)| t.module == module_name && t.name == name)
            .map(|(&a, _)| a)
            .min()
        {
            return addr;
        }
        let Some(m) = self.modules.iter_mut().find(|m| m.base == hmod) else {
            return 0;
        };
        if m.trap_next >= m.base + m.size {
            return 0;
        }
        let addr = m.trap_next;
        m.trap_next += TRAP_STRIDE;
        // The export was not one this module advertises, but the *name* may
        // still be one the emulator implements: a forwarded export, a DLL
        // resolved under an alias, or an import whose module name did not
        // survive the packer's rewriting. Matching on the name keeps those
        // calls working instead of stopping the run on an export whose
        // behaviour is known.
        let spec = APIS.iter().find(|s| s.name == name);
        self.traps.insert(
            addr,
            Trap {
                api: spec.map(|s| s.api),
                argc: spec.map(|s| s.argc).unwrap_or(0),
                module: module_name,
                name: name.to_string(),
            },
        );
        addr
    }

    /// Map another page of stack, if `addr` is in the region the stack may grow
    /// into. Mirrors the guard page: on Windows the access succeeds and the
    /// stack commits, so an emulator that faults here diverges from the machine
    /// over something the program is entitled to do.
    pub fn grow_stack(&self, mem: &mut Mem, addr: u32) -> bool {
        if !(STACK_GUARD_FLOOR..STACK_BASE).contains(&addr) {
            return false;
        }
        let page = addr & !(PAGE_SIZE as u32 - 1);
        mem.map(page, PAGE_SIZE as u32).is_ok()
    }

    /// Whether a path names the program being emulated. Case-insensitive, and
    /// a bare file name counts: a stub that builds its own path from
    /// `GetModuleFileName` and one that hard-codes the base name both arrive
    /// here.
    fn is_own_path(&self, path: &str) -> bool {
        let p = path.to_ascii_lowercase();
        let base = p.rsplit(['\\', '/']).next().unwrap_or(&p);
        p == SAMPLE_PATH.to_ascii_lowercase() || base == "sample.exe"
    }

    fn next_module_base(&self) -> u32 {
        // Below the preloaded system DLLs, growing down, so a newly "loaded"
        // module never lands on one that is already mapped.
        self.modules
            .iter()
            .map(|m| m.base)
            .min()
            .unwrap_or(0x7000_0000)
            .saturating_sub(MODULE_SIZE)
    }
}

fn map(mem: &mut Mem, addr: u32, len: u32) -> Result<(), Stop> {
    mem.map(addr, len)
        .map_err(|_| Stop::Fault(crate::mem::Fault { addr, write: true }))
}

/// Whether a DLL name is one a Windows process plausibly has loaded. Used to
/// answer `GetModuleHandle` for modules the emulator did not preload, without
/// answering yes to the sandbox-detection probes that use the same call.
fn is_system_dll(name: &str) -> bool {
    const KNOWN: &[&str] = &[
        "kernel32.dll",
        "kernelbase.dll",
        "ntdll.dll",
        "user32.dll",
        "gdi32.dll",
        "advapi32.dll",
        "shell32.dll",
        "shlwapi.dll",
        "ole32.dll",
        "oleaut32.dll",
        "comctl32.dll",
        "comdlg32.dll",
        "msvcrt.dll",
        "mscoree.dll",
        "version.dll",
        "wininet.dll",
        "ws2_32.dll",
        "wsock32.dll",
        "crypt32.dll",
        "psapi.dll",
        "imm32.dll",
        "winmm.dll",
        "urlmon.dll",
        "netapi32.dll",
        "userenv.dll",
        "secur32.dll",
        "mpr.dll",
        "rpcrt4.dll",
        "setupapi.dll",
        "iphlpapi.dll",
        "dnsapi.dll",
        "wtsapi32.dll",
        "powrprof.dll",
        "cabinet.dll",
        "msi.dll",
        "gdiplus.dll",
        "uxtheme.dll",
        "dbghelp.dll",
        "winspool.drv",
    ];
    let n = normalize_module(name);
    KNOWN.contains(&n.as_str())
}

/// Lowercase base name with a `.dll` suffix, which is how module names are
/// compared here (Windows compares them case-insensitively too).
fn normalize_module(name: &str) -> String {
    let base = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    if base.contains('.') {
        base
    } else {
        format!("{base}.dll")
    }
}

fn write_utf16(mem: &mut Mem, addr: u32, s: &str) -> Result<(), Stop> {
    let b: Vec<u8> = s
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .chain([0, 0])
        .collect();
    mem.write_bytes(addr, &b).map_err(Stop::Fault)
}

fn write_c_str(mem: &mut Mem, addr: u32, s: &str) -> Result<(), Stop> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    mem.write_bytes(addr, &b).map_err(Stop::Fault)
}

/// Read a NUL-terminated string, ANSI or UTF-16. Bounded so a pointer into
/// uninitialised memory cannot produce an unbounded read.
fn read_str(mem: &mut Mem, addr: u32, wide: bool) -> Result<String, Stop> {
    const MAX: u32 = 1024;
    let mut out = String::new();
    let step = if wide { 2 } else { 1 };
    let mut a = addr;
    for _ in 0..MAX {
        let c = if wide {
            mem.read_u16(a).map_err(Stop::Fault)? as u32
        } else {
            mem.read_u8(a).map_err(Stop::Fault)? as u32
        };
        if c == 0 {
            break;
        }
        out.push(char::from_u32(c).unwrap_or('?'));
        a = a.wrapping_add(step);
    }
    Ok(out)
}

/// Write a string as ANSI or UTF-16, truncated to `cap` characters. Returns the
/// number of characters written, which is what the Windows APIs report.
fn write_str(mem: &mut Mem, addr: u32, s: &str, wide: bool, cap: u32) -> Result<u32, Stop> {
    let n = (s.len() as u32).min(cap.saturating_sub(1));
    let mut bytes = Vec::new();
    for ch in s.chars().take(n as usize) {
        if wide {
            bytes.extend_from_slice(&(ch as u16).to_le_bytes());
        } else {
            bytes.push(ch as u8);
        }
    }
    bytes.extend_from_slice(if wide { &[0, 0][..] } else { &[0][..] });
    mem.write_bytes(addr, &bytes).map_err(Stop::Fault)?;
    Ok(n)
}

/// Lay down PE headers for a synthetic DLL, with the export directory wired
/// into data directory 0 — the only part of the image a stub reads.
fn write_module_headers(
    mem: &mut Mem,
    base: u32,
    size: u32,
    export_rva: u32,
    export_size: u32,
) -> Result<(), Stop> {
    let mut h = vec![0u8; 0x200];
    h[0..2].copy_from_slice(b"MZ");
    h[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe = 0x80usize;
    h[pe..pe + 4].copy_from_slice(b"PE\0\0");
    h[pe + 4..pe + 6].copy_from_slice(&0x14cu16.to_le_bytes()); // i386
    h[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    h[pe + 20..pe + 22].copy_from_slice(&0xe0u16.to_le_bytes()); // SizeOfOptionalHeader
    h[pe + 22..pe + 24].copy_from_slice(&0x210eu16.to_le_bytes()); // Characteristics: DLL
    let opt = pe + 24;
    h[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32
    h[opt + 28..opt + 32].copy_from_slice(&base.to_le_bytes()); // ImageBase
    h[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    h[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    h[opt + 56..opt + 60].copy_from_slice(&size.to_le_bytes()); // SizeOfImage
    h[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
    h[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    let dd = opt + 96;
    h[dd..dd + 4].copy_from_slice(&export_rva.to_le_bytes());
    h[dd + 4..dd + 8].copy_from_slice(&export_size.to_le_bytes());
    // One section covering the whole image, so an RVA-to-offset walk over the
    // section table lands somewhere sensible.
    let sec = opt + 0xe0;
    h[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    h[sec + 8..sec + 12].copy_from_slice(&size.to_le_bytes()); // VirtualSize
    h[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    h[sec + 16..sec + 20].copy_from_slice(&size.to_le_bytes()); // SizeOfRawData
    h[sec + 20..sec + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // PointerToRawData
    mem.write_bytes(base, &h).map_err(Stop::Fault)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> (Mem, Env<'static>) {
        let mut mem = Mem::new(4096);
        mem.map(0x0040_0000, 0x1000).unwrap();
        // No file behind this environment: the tests here exercise the loader
        // structures and the export traps, not the self-read path.
        let env = Env::new(&mut mem, 0x0040_0000, 0x1_0000, b"").unwrap();
        (mem, env)
    }

    #[test]
    fn the_peb_chain_leads_to_kernel32() {
        // The walk a stub does: fs:[0x30] -> PEB -> Ldr ->
        // InInitializationOrderModuleList -> second entry -> DllBase.
        let (mut mem, env) = env();
        let peb = mem.read_u32(TEB_BASE + 0x30).unwrap();
        assert_eq!(peb, PEB_BASE);
        let ldr = mem.read_u32(peb + 0x0c).unwrap();
        let first = mem.read_u32(ldr + 0x1c).unwrap();
        let second = mem.read_u32(first).unwrap();
        // The list links point at InInitializationOrderLinks, which sits 0x10
        // into the entry, so DllBase (+0x18) is 8 bytes further on.
        let ntdll = mem.read_u32(first + 8).unwrap();
        let kernel32 = mem.read_u32(second + 8).unwrap();
        assert_eq!(ntdll, 0x7c90_0000, "ntdll initialises first");
        assert_eq!(kernel32, 0x7c80_0000, "kernel32 second");
        assert!(env.find_module(kernel32).is_some());
    }

    #[test]
    fn the_load_order_list_starts_with_the_program_itself() {
        let (mut mem, _env) = env();
        let ldr = mem.read_u32(PEB_BASE + 0x0c).unwrap();
        let first = mem.read_u32(ldr + 0x0c).unwrap();
        assert_eq!(mem.read_u32(first + 0x18).unwrap(), 0x0040_0000);
    }

    #[test]
    fn synthetic_kernel32_has_a_walkable_export_directory() {
        // Resolving GetProcAddress by hand: parse the export directory of the
        // synthetic kernel32 and find a name.
        let (mut mem, _env) = env();
        let base = 0x7c80_0000u32;
        let e_lfanew = mem.read_u32(base + 0x3c).unwrap();
        assert_eq!(mem.read_u32(base + e_lfanew).unwrap(), 0x0000_4550);
        let dd = base + e_lfanew + 24 + 96;
        let ed = base + mem.read_u32(dd).unwrap();
        let n_names = mem.read_u32(ed + 24).unwrap();
        let names = base + mem.read_u32(ed + 32).unwrap();
        let funcs = base + mem.read_u32(ed + 28).unwrap();
        let mut found = None;
        for i in 0..n_names {
            let p = base + mem.read_u32(names + i * 4).unwrap();
            let name = read_str(&mut mem, p, false).unwrap();
            if name == "VirtualAlloc" {
                found = Some(base + mem.read_u32(funcs + i * 4).unwrap());
            }
        }
        let addr = found.expect("VirtualAlloc is exported");
        assert!(
            _env.is_trap(addr),
            "the exported address is a trap the driver will service"
        );
    }

    /// A block copy reports the volume it moved, so the driver can charge for it.
    ///
    /// The tick budget bounds instructions executed, which stands in for work
    /// only while one instruction does a bounded amount of it. `memcpy` moves up
    /// to 64 MiB per call. Charged a flat tick, a stub looping over it spends
    /// the entire budget's worth of copying on every tick and the run never
    /// ends within any useful time — the budget counts calls while the machine
    /// does the work.
    #[test]
    fn a_block_copy_reports_the_bytes_it_moved() {
        let (mut mem, mut env) = env();
        let mut cpu = Cpu::new();
        cpu.regs[ESP] = INITIAL_ESP;

        assert_eq!(env.take_bulk_bytes(), 0, "nothing copied yet");

        // Somewhere to copy between.
        let src = 0x0050_0000u32;
        let dst = 0x0060_0000u32;
        mem.map(src, 0x2000).unwrap();
        mem.map(dst, 0x2000).unwrap();

        let n = 0x1800u32;
        let trap = trap_for(&env, "msvcrt.dll", "memcpy");
        cpu.push32(&mut mem, n).unwrap();
        cpu.push32(&mut mem, src).unwrap();
        cpu.push32(&mut mem, dst).unwrap();
        cpu.push32(&mut mem, 0xdead_0000).unwrap(); // return address
        cpu.eip = trap;
        assert_eq!(env.call(&mut cpu, &mut mem).unwrap(), ApiEffect::Continue);

        assert_eq!(
            env.take_bulk_bytes(),
            u64::from(n),
            "the copy must report every byte it moved, or the driver charges \
             one tick for work that took millions"
        );
        assert_eq!(
            env.take_bulk_bytes(),
            0,
            "and reset, so the next call is not charged for this one"
        );
    }

    #[test]
    fn virtualalloc_hands_out_usable_pages() {
        let (mut mem, mut env) = env();
        let mut cpu = Cpu::new();
        cpu.regs[ESP] = INITIAL_ESP;
        // Call VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_EXECUTE_READWRITE).
        let trap = trap_for(&env, "kernel32.dll", "VirtualAlloc");
        cpu.push32(&mut mem, 0x40).unwrap();
        cpu.push32(&mut mem, 0x1000).unwrap();
        cpu.push32(&mut mem, 0x2000).unwrap();
        cpu.push32(&mut mem, 0).unwrap();
        cpu.push32(&mut mem, 0xdead_0000).unwrap(); // return address
        cpu.eip = trap;
        assert_eq!(env.call(&mut cpu, &mut mem).unwrap(), ApiEffect::Continue);
        let p = cpu.regs[EAX];
        assert!(p != 0, "the allocation succeeded");
        assert!(mem.is_mapped(p, 0x2000), "and its pages are mapped");
        assert_eq!(cpu.eip, 0xdead_0000, "execution resumes at the caller");
        assert_eq!(
            cpu.regs[ESP], INITIAL_ESP,
            "a stdcall export cleans its own arguments"
        );
    }

    /// Resolving an export must not depend on hash-map iteration order.
    ///
    /// WHY THIS IS NOT A STYLE POINT: the address `GetProcAddress` returns is
    /// written into the import table the stub rebuilds, so it ends up *inside
    /// the unpacked image*. When the choice varied, the same input produced a
    /// different dump on different runs — 45 of 276 corpus samples — which
    /// makes the emulator impossible to differentially test and makes any
    /// hash-based signature over its output useless.
    ///
    /// Two traps are given the same module and name at different addresses, in
    /// both insertion orders. Whichever way the map happens to iterate, the
    /// answer must be the same, and it must be the lower address — the one the
    /// module's own export table allocated first.
    #[test]
    fn an_export_resolves_to_the_same_address_whatever_the_map_order() {
        let resolve = |ascending: bool| -> u32 {
            let (_mem, mut env) = env();
            let hmod = env
                .modules
                .iter()
                .find(|m| m.name == "kernel32.dll")
                .map(|m| m.base)
                .expect("kernel32 is preloaded");
            let dup = |env: &mut Env, addr: u32| {
                env.traps.insert(
                    addr,
                    Trap {
                        api: None,
                        argc: 0,
                        module: "kernel32.dll".to_string(),
                        name: "AmbiguousExport".to_string(),
                    },
                );
            };
            let (lo, hi) = (hmod + 0x9000, hmod + 0x9010);
            if ascending {
                dup(&mut env, lo);
                dup(&mut env, hi);
            } else {
                dup(&mut env, hi);
                dup(&mut env, lo);
            }
            let got = env.export_addr(hmod, "AmbiguousExport");
            assert_eq!(got, lo, "resolved to the higher of two equal candidates");
            got
        };
        assert_eq!(resolve(true), resolve(false));
    }

    #[test]
    fn getprocaddress_resolves_by_name_and_by_ordinal() {
        let (mut mem, mut env) = env();
        let mut cpu = Cpu::new();
        cpu.regs[ESP] = INITIAL_ESP;
        write_c_str(&mut mem, 0x0040_0100, "VirtualProtect").unwrap();
        let trap = trap_for(&env, "kernel32.dll", "GetProcAddress");
        cpu.push32(&mut mem, 0x0040_0100).unwrap();
        cpu.push32(&mut mem, 0x7c80_0000).unwrap();
        cpu.push32(&mut mem, 0xdead_0000).unwrap();
        cpu.eip = trap;
        env.call(&mut cpu, &mut mem).unwrap();
        assert_eq!(
            cpu.regs[EAX],
            trap_for(&env, "kernel32.dll", "VirtualProtect")
        );

        // An export the emulator does not implement still resolves, so a stub
        // that checks the return value keeps going.
        write_c_str(&mut mem, 0x0040_0200, "SomeUnknownExport").unwrap();
        cpu.regs[ESP] = INITIAL_ESP;
        cpu.push32(&mut mem, 0x0040_0200).unwrap();
        cpu.push32(&mut mem, 0x7c80_0000).unwrap();
        cpu.push32(&mut mem, 0xdead_0000).unwrap();
        cpu.eip = trap;
        env.call(&mut cpu, &mut mem).unwrap();
        assert!(cpu.regs[EAX] != 0);
        assert!(env.is_trap(cpu.regs[EAX]));
    }

    #[test]
    fn loadlibrary_of_an_unknown_dll_creates_a_module() {
        let (mut mem, mut env) = env();
        let mut cpu = Cpu::new();
        cpu.regs[ESP] = INITIAL_ESP;
        write_c_str(&mut mem, 0x0040_0100, "wininet.dll").unwrap();
        let trap = trap_for(&env, "kernel32.dll", "LoadLibraryA");
        cpu.push32(&mut mem, 0x0040_0100).unwrap();
        cpu.push32(&mut mem, 0xdead_0000).unwrap();
        cpu.eip = trap;
        env.call(&mut cpu, &mut mem).unwrap();
        let h = cpu.regs[EAX];
        assert!(h != 0);
        assert_eq!(
            env.find_module(h).map(|m| m.name.as_str()),
            Some("wininet.dll")
        );
    }

    fn trap_for(env: &Env, module: &str, name: &str) -> u32 {
        env.traps
            .iter()
            .filter(|(_, t)| t.module == module && t.name == name)
            .map(|(&a, _)| a)
            .min()
            .expect("export present")
    }
}
