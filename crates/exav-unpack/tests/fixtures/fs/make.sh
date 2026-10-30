#!/bin/bash
# Build the filesystem images of this directory.
#
#     bash make.sh [ext] [fat] [exfat] [squashfs] [cramfs] [romfs] [erofs]
#
# Each image holds the tree of tree.py (the suites compare a walk with it), and
# is kept gzipped, a filesystem being mostly empty space. The tools are
# e2fsprogs, mtools, exfatprogs, squashfs-tools, erofs-utils, genromfs and
# util-linux's mkfs.cramfs, and `sudo` for the images a kernel writes (a loop
# mount): those are marked.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
WORK="$(mktemp -d)"
trap 'sudo umount "$WORK/mnt" 2>/dev/null || true; rm -rf "$WORK"' EXIT

tree() { python3 "$DIR/tree.py" "$1" "${@:2}"; }
keep() { gzip -9 -n -c "$1" > "$2.img.gz"; }

# A volume a kernel wrote: pads written and every other one deleted, so the
# files that follow land in the holes, then the tree and extras.py's files.
# $1 name, $2 mkfs command (IMG stands for the image), $3 size in MiB, $4 mount
# options, $5 pad size.
kernel() {
    local img="$WORK/$1.img"
    truncate -s "$3M" "$img"
    eval "${2//IMG/$img}"
    mkdir -p "$WORK/mnt"
    sudo mount -o "loop,$4" "$img" "$WORK/mnt"
    sudo chown "$(id -u)" "$WORK/mnt" 2>/dev/null || true
    (
        cd "$WORK/mnt"
        mkdir pad
        for i in $(seq 0 99); do head -c "$5" /dev/zero | tr '\0' p > "pad/$i"; done
        for i in $(seq 0 2 99); do rm "pad/$i"; done
        tree .
        # A filesystem without holes or preallocation has no use for most of
        # these (plain), or only for the file longer than it was written (trunc).
        case "${6:-}" in
            plain) ;;
            trunc) python3 "$DIR/extras.py" --trunc-only ;;
            *) python3 "$DIR/extras.py" ;;
        esac
        rm -rf pad
    )
    sync
    sudo umount "$WORK/mnt"
    keep "$img" "$1"
}

# A volume made from a directory. $1 name, $2 mkfs command (IMG, TREE), $3 size.
from_tree() {
    local img="$WORK/$1.img"
    rm -rf "$WORK/tree"
    tree "$WORK/tree" --sparse
    truncate -s "$3M" "$img"
    eval "$(echo "$2" | sed "s|IMG|$img|; s|TREE|$WORK/tree|")"
    keep "$img" "$1"
}

ext() {
    local mk="mke2fs -q -F -E root_owner=0:0 -d TREE"
    from_tree ext4 "$mk -t ext4 -b 4096 IMG" 8
    from_tree ext2_blockmap "$mk -t ext2 -b 1024 IMG" 8
    from_tree ext3 "$mk -t ext3 -b 2048 IMG" 8
    from_tree ext4_inline "$mk -t ext4 -b 1024 -O inline_data,^has_journal IMG" 8
    from_tree ext4_metabg "$mk -t ext4 -b 1024 -g 1024 -i 65536 -O meta_bg,^resize_inode,64bit IMG" 24
    from_tree ext4_bigalloc "$mk -t ext4 -b 1024 -O bigalloc -C 8192 IMG" 8
    # Written by a kernel (sudo).
    kernel ext4_kernel "mkfs.ext4 -q -F -b 1024 IMG" 8 "" 8192
}

# A FAT volume made with mtools. $1 name, $2 mkfs.vfat options, $3 size in
# KiB. Pads are written and every other one deleted first, so the files that
# follow land in the holes: a fragmented file has more than one run.
mtools_fat() {
    local img="$WORK/$1.img"
    rm -rf "$WORK/tree"
    tree "$WORK/tree"
    truncate -s "${3}K" "$img"
    mkfs.vfat -n TESTVOL $2 "$img" > /dev/null
    mkdir "$WORK/pad"
    for i in $(seq 0 99); do head -c 3000 /dev/zero | tr '\0' p > "$WORK/pad/$i"; done
    mcopy -i "$img" "$WORK"/pad/* ::/
    for i in $(seq 0 2 99); do mdel -i "$img" "::/$i"; done
    mcopy -s -i "$img" "$WORK"/tree/* ::/
    for i in $(seq 1 2 99); do mdel -i "$img" "::/$i"; done
    rm -rf "$WORK/pad"
    keep "$img" "$1"
}

fat() {
    mtools_fat fat12 "-F 12" 1440
    mtools_fat fat16 "-F 16" 16384
    mtools_fat fat32 "-F 32 -s 2" 40960
    # Written by a kernel (sudo), which keeps the case of a short name in two
    # flags of its entry instead of a long name.
    kernel fat16_kernel "mkfs.vfat -F 16 IMG" 16 "shortname=winnt,uid=$(id -u)" 3000 plain
}

squashfs() {
    rm -rf "$WORK/tree"
    tree "$WORK/tree" --sparse
    # A link holds no file's bytes.
    ln -s tiny.txt "$WORK/tree/link"
    local c
    for c in gzip xz lzo lz4 zstd lzma; do
        mksquashfs "$WORK/tree" "$WORK/$c.sqsh" -comp "$c" -noappend -quiet > /dev/null
        keep "$WORK/$c.sqsh" "squashfs_$c"
    done
    mksquashfs "$WORK/tree" "$WORK/small.sqsh" -b 4096 -noappend -quiet > /dev/null
    keep "$WORK/small.sqsh" squashfs_small_blocks
    mksquashfs "$WORK/tree" "$WORK/plain.sqsh" -no-compression -no-fragments -noappend -quiet > /dev/null
    keep "$WORK/plain.sqsh" squashfs_uncompressed
}

# cramfs needs `mkcramfs` (MKCRAMFS names it: github.com/npitre/cramfs-tools,
# which Linux distributions do not package any more) and `cramfsswap`.
cramfs() {
    local mk="${MKCRAMFS:-mkcramfs}"
    rm -rf "$WORK/tree"
    tree "$WORK/tree"
    # Three blocks of nothing, which -z makes holes of, and a tail.
    { head -c 12288 /dev/zero; printf end; } > "$WORK/tree/zeros.bin"
    "$mk" "$WORK/tree" "$WORK/plain.cramfs" > /dev/null 2>&1
    keep "$WORK/plain.cramfs" cramfs
    "$mk" -p "$WORK/tree" "$WORK/padded.cramfs" > /dev/null 2>&1
    keep "$WORK/padded.cramfs" cramfs_padded
    "$mk" -z "$WORK/tree" "$WORK/holes.cramfs" > /dev/null 2>&1
    keep "$WORK/holes.cramfs" cramfs_holes
    "$mk" -x "$WORK/tree" "$WORK/ext.cramfs" > /dev/null 2>&1
    keep "$WORK/ext.cramfs" cramfs_extended
    cramfsswap "$WORK/plain.cramfs" "$WORK/be.cramfs" > /dev/null
    keep "$WORK/be.cramfs" cramfs_big_endian
}

romfs() {
    rm -rf "$WORK/tree"
    tree "$WORK/tree"
    # An executable, a hard link to it and a symbolic link, which holds no file.
    chmod +x "$WORK/tree/tiny.txt"
    ln "$WORK/tree/tiny.txt" "$WORK/tree/hard"
    ln -s tiny.txt "$WORK/tree/link"
    genromfs -f "$WORK/plain.romfs" -d "$WORK/tree" -V TEST > /dev/null
    keep "$WORK/plain.romfs" romfs
    genromfs -f "$WORK/aligned.romfs" -d "$WORK/tree" -a 512 > /dev/null
    keep "$WORK/aligned.romfs" romfs_aligned
}

erofs() {
    rm -rf "$WORK/tree"
    tree "$WORK/tree"
    # A link holds no file's bytes.
    ln -s tiny.txt "$WORK/tree/link"
    mkfs.erofs "$WORK/plain.erofs" "$WORK/tree" > /dev/null 2>&1
    keep "$WORK/plain.erofs" erofs
    mkfs.erofs -b 1024 "$WORK/small.erofs" "$WORK/tree" > /dev/null 2>&1
    keep "$WORK/small.erofs" erofs_small_blocks
    mkfs.erofs -E force-inode-compact "$WORK/compact.erofs" "$WORK/tree" > /dev/null 2>&1
    keep "$WORK/compact.erofs" erofs_compact_inodes
    # Compressed: the files are reported, the directories are read.
    mkfs.erofs -zlz4hc "$WORK/lz4.erofs" "$WORK/tree" > /dev/null 2>&1
    keep "$WORK/lz4.erofs" erofs_lz4
    # Files in chunks, with holes.
    tree "$WORK/tree" --sparse
    mkfs.erofs --chunksize 4096 "$WORK/chunks.erofs" "$WORK/tree" > /dev/null 2>&1
    keep "$WORK/chunks.erofs" erofs_chunks
}

exfat() {
    # Written by a kernel (sudo); the sparse file does not fit.
    kernel exfat "mkfs.exfat -c 4096 IMG" 16 "uid=$(id -u)" 30000 trunc
    kernel exfat_small_clusters "mkfs.exfat -c 512 IMG" 16 "uid=$(id -u)" 30000 trunc
}

[ $# -eq 0 ] && set -- ext fat exfat squashfs cramfs romfs erofs
for what in "$@"; do "$what"; done
ls -l "$DIR"/*.img.gz
