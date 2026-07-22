import "dotnet"
rule r_is_dotnet      { condition: dotnet.is_dotnet }
rule r_module_name    { condition: dotnet.module_name == "Newtonsoft.Json.dll" }
rule r_version        { condition: dotnet.version == "v4.0.30319" }
rule r_n_streams      { condition: dotnet.number_of_streams == 5 }
rule r_n_guids        { condition: dotnet.number_of_guids == 1 }
rule r_n_classes      { condition: dotnet.number_of_classes == 493 }
rule r_n_asmrefs      { condition: dotnet.number_of_assembly_refs == 22 }
rule r_n_modulerefs   { condition: dotnet.number_of_modulerefs == 0 }
rule r_n_userstrings  { condition: dotnet.number_of_user_strings == 783 }
rule r_n_constants    { condition: dotnet.number_of_constants == 95 }
rule r_n_fieldoffsets { condition: dotnet.number_of_field_offsets == 22 }
rule r_n_resources    { condition: dotnet.number_of_resources == 0 }
rule r_stream0        { condition: dotnet.streams[0].name == "#~" }
rule r_stream1_size   { condition: dotnet.streams[1].size == 0x1307c }
rule r_asm_name       { condition: dotnet.assembly.name == "Newtonsoft.Json" }
rule r_asm_major      { condition: dotnet.assembly.version.major == 13 }
rule r_asmref0        { condition: dotnet.assembly_refs[0].name == "System.Runtime" }
rule r_asmref0_major  { condition: dotnet.assembly_refs[0].version.major == 6 }
rule r_guid0          { condition: dotnet.guids[0] == "7e62198b-eab2-4380-bbac-29171862d1d8" }
