import "pe"
import "elf"
import "math"
import "hash"
import "string"

private rule Fuzz_Marker { strings: $m = "MARKER" condition: $m }

global rule Fuzz_Size { condition: filesize < 10MB }

rule Fuzz_Text {
    meta: author = "exav fuzz"
    strings:
        $a = "hello" nocase wide ascii
        $b = { 48 65 ?? 6c [1-3] 6f }
        $c = /wor[a-z]{2,4}d/ nocase
        $d = "secret" xor(1-255) fullword
        $e = "payload" base64
        $f = { (4d 5a | 50 4b) 03 04 }
    condition:
        2 of ($a, $b, $c, $d, $e) or ($f at 0)
}

rule Fuzz_Loops {
    strings: $a = "ab" $b = "cd"
    condition:
        for any i in (1..#a) : (@a[i] < @b[1]) and
        for all of ($a, $b) : (# > 0) and
        #a in (0..1024) > 2 and $b in (filesize - 64..filesize)
}

rule Fuzz_Pe {
    condition:
        pe.is_pe and pe.number_of_sections > 1 and
        for any s in pe.sections : (s.name == ".text" and s.raw_data_size > 0) and
        (pe.imports("kernel32.dll", "LoadLibraryA") or pe.exports("Init") or pe.number_of_imports > 0 or pe.imphash() == "d41d8cd98f00b204e9800998ecf8427e")
}

rule Fuzz_Pe2 {
    condition:
        pe.machine == pe.MACHINE_I386 and pe.entry_point > 0 and
        uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x00004550 and
        pe.dll_characteristics > 0 or pe.timestamp > 0
}

rule Fuzz_Elf {
    condition:
        elf.type == elf.ET_EXEC and elf.number_of_sections > 0 and
        for any s in elf.sections : (s.type == elf.SHT_PROGBITS and s.size > 0) or
        for any seg in elf.segments : (seg.type == elf.PT_LOAD)
}

rule Fuzz_Math {
    condition:
        math.entropy(0, filesize) > 7.0 and
        math.mean(0, 256) < 100.0 and
        math.deviation(0, 256, math.MEAN_BYTES) > 1.0 and
        math.serial_correlation(0, 512) > 0.1 and
        math.monte_carlo_pi(0, 1024) < 4.0 and
        math.count(0x00, 0, 128) > 10 and
        math.percentage(0x41, 0, 64) > 0.1 and
        math.mode(0, 64) == 0x41
}

rule Fuzz_Hash {
    condition:
        hash.md5(0, 16) == "d41d8cd98f00b204e9800998ecf8427e" or
        hash.sha1(0, filesize) == "da39a3ee5e6b4b0d3255bfef95601890afd80709" or
        hash.sha256(0, 32) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" or
        hash.crc32(0, filesize) == 0 or hash.checksum32(0, 16) == 1
}

rule Fuzz_Str {
    strings: $s = "abc"
    condition:
        string.to_int("12") == 12 and string.length("x") == 1 and
        filename matches /\.(js|vbs)$/i and extension == ".js" and
        $s and "needle" contains "ee" and "NEEDLE" icontains "need" and
        "pre" startswith "pr" and "x.exe" endswith ".exe" and "A" iequals "a"
}

rule Fuzz_Ints {
    condition:
        int8(0) == 0x4d or uint8(1) > 0 or int16be(2) < 0 or uint32be(4) > 1 or
        int32(8) != 0 or uint16(filesize - 2) == 0xabcd or
        (filesize > 1KB and filesize < 1MB) or defined uint8(filesize + 10)
}

rule Fuzz_Wild {
    strings:
        $a = { 31 C0 [2-8] (E8 | E9) ?? ?? ?? ?? ~00 }
        $b = { 8B 45 ?? [0-4] 83 ?? ( 01 | 02 | 03 ) ?? }
        $c = "text" ascii wide private
        $d = /a.{0,32}b[^\x00-\x1f]{1,16}c\b/s
        $e = "needle" nocase fullword wide
    condition:
        any of them and $a in (0..100) and #b >= 1 and !c[1] > 0
}
