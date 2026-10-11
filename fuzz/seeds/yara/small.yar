import "pe"

rule Small {
    strings:
        $a = "hello" nocase
        $b = { 4d 5a ?? 00 }
        $c = /wor[a-z]d/
    condition:
        any of them or (uint16(0) == 0x5a4d and pe.is_pe)
}
