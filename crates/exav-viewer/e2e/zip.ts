// A zip of stored members (APPNOTE 4.3.7, 4.3.12, 4.3.16), for tests that
// hand the viewer an archive of their own.
const CRC = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of data) c = CRC[(c ^ b) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** `gap`: zero bytes after each member but the last, which no header claims. */
export function storedZip(files: [string, Uint8Array][], gap = 0): Buffer {
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [i, [name, data]] of files.entries()) {
    if (i > 0 && gap > 0) {
      parts.push(Buffer.alloc(gap));
      offset += gap;
    }
    const fname = Buffer.from(name);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(fname.length, 26);
    parts.push(local, fname, Buffer.from(data));
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(fname.length, 28);
    cd.writeUInt32LE(offset, 42);
    central.push(cd, fname);
    offset += 30 + fname.length + data.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, end]);
}

/** A Unix `ar` archive, GNU style (what a `.deb` is made of), for the same tests. */
export function ar(files: [string, Uint8Array][]): Buffer {
  const parts: Buffer[] = [Buffer.from("!<arch>\n")];
  for (const [name, data] of files) {
    const header = Buffer.alloc(60, " ");
    header.write(`${name}/`, 0, 16);
    header.write("0", 16);
    header.write("0", 28);
    header.write("0", 34);
    header.write("100644", 40);
    header.write(String(data.length), 48);
    header.write("`\n", 58);
    parts.push(header, Buffer.from(data), Buffer.alloc(data.length % 2, "\n"));
  }
  return Buffer.concat(parts);
}

/** A cpio archive in the "new ASCII" format (what an initramfs and an RPM payload are). */
export function cpio(files: [string, Uint8Array][]): Buffer {
  const parts: Buffer[] = [];
  const entry = (name: string, data: Uint8Array, mode: number) => {
    const fields = [1, mode, 0, 0, 1, 0, data.length, 0, 0, 0, 0, name.length + 1, 0];
    const header = Buffer.from(`070701${fields.map((f) => f.toString(16).padStart(8, "0")).join("")}${name}\0`);
    const pad = (n: number) => Buffer.alloc((4 - (n % 4)) % 4);
    parts.push(header, pad(header.length), Buffer.from(data), pad(data.length));
  };
  for (const [name, data] of files) entry(name, data, 0o100644);
  entry("TRAILER!!!", new Uint8Array(), 0);
  return Buffer.concat(parts);
}

/** A ustar archive of regular files (POSIX.1-1988), for the same tests. */
export function tar(files: [string, Uint8Array][]): Buffer {
  const blocks: Buffer[] = [];
  for (const [name, data] of files) {
    const header = Buffer.alloc(512);
    header.write(name, 0, 100);
    header.write("0000644\0", 100);
    header.write("0000000\0", 108);
    header.write("0000000\0", 116);
    header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124);
    header.write("00000000000\0", 136);
    header.write("        ", 148);
    header.write("0", 156);
    header.write("ustar\u000000", 257);
    const sum = header.reduce((a, b) => a + b, 0);
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
    blocks.push(header, Buffer.from(data), Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  return Buffer.concat([...blocks, Buffer.alloc(1024)]);
}
