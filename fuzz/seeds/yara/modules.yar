import "elf"
import "math"
import "hash"

rule Modules {
    condition:
        (elf.type == elf.ET_EXEC and elf.number_of_segments > 0) or
        math.entropy(0, filesize) > 6.5 or
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"
}

rule Loops {
    strings: $a = "ab" $b = "cd"
    condition: for any i in (1..#a) : (@a[i] < @b[1]) and #a in (0..64) > 1
}
