"""Wrap a PS-X EXE in an ELF32 (MIPS, little endian) so Ghidra's ELF loader imports it with
the right language (MIPS:LE:32:default) and memory map.

Usage: python psx2elf.py <SLUS_xxx.xx> <out.elf>

Sections (the PlayStation's KSEG0 view of RAM, so every pointer the game forms resolves):
  .kernel   0x80000000..0x80010000  BIOS/kernel RAM (uninitialized)
  .text     t_addr..t_addr+t_size   the executable image (code and data)
  .bss      ..0x80200000            the rest of the 2 MiB of RAM (uninitialized)
  .scratch  0x1F800000 (1 KiB)      the data cache used as scratchpad RAM
  .io       0x1F801000 (8 KiB)      hardware registers
"""
import struct
import sys

RAM_END = 0x80200000


def build(exe):
    """ELF bytes for a PS-X EXE image (the whole image is one initialized .text section)."""
    assert exe[:8] == b'PS-X EXE', 'not a PS-X EXE'
    pc0, gp0, t_addr, t_size = struct.unpack_from('<4I', exe, 0x10)
    return build_segments(pc0, [('.text', t_addr, exe[0x800:0x800 + t_size])])


def build_segments(pc0, segments):
    """ELF bytes for initialized, executable `segments` [(name, addr, bytes)] in RAM; the rest of
    the 2 MiB stays uninitialized (.kernel below 0x80010000, .bss_N in the gaps)."""
    segments = sorted(segments, key=lambda s: s[1])
    secs = [('.kernel', 8, 3, 0x80000000, 0x10000, b'')]  # name, type, flags, addr, size, data
    cur = 0x80010000
    for i, (name, addr, data) in enumerate(segments):
        assert addr >= cur, f'{name} overlaps the previous section'
        if addr > cur:
            secs.append((f'.bss{i}', 8, 3, cur, addr - cur, b''))
        secs.append((name, 1, 7, addr, len(data), data))
        cur = addr + len(data)
    if cur < RAM_END:
        secs.append(('.bss', 8, 3, cur, RAM_END - cur, b''))
    secs += [('.scratch', 8, 3, 0x1F800000, 0x400, b''), ('.io', 8, 3, 0x1F801000, 0x2000, b'')]
    names = [s[0] for s in secs] + ['.shstrtab']
    shstr = bytes(1) + b''.join(n.encode() + bytes(1) for n in names)
    name_off, o = [], 1
    for n in names:
        name_off.append(o)
        o += len(n) + 1

    ehsize, phentsize, shentsize = 52, 32, 40
    phnum = len(secs)
    data_off = (ehsize + phnum * phentsize + 0xFFF) & ~0xFFF
    blob = bytearray()
    offs = []
    for s in secs:
        offs.append(data_off + len(blob))
        blob += s[5]
        while len(blob) % 16:
            blob += bytes(1)
    shstr_off = data_off + len(blob)
    blob += shstr
    while len(blob) % 4:
        blob += bytes(1)
    shoff = data_off + len(blob)
    shnum = len(secs) + 2  # null + sections + shstrtab

    out = bytearray()
    out += b'ELF' + bytes([1, 1, 1, 0]) + bytes(8)
    out += struct.pack('<HHIIIIIHHHHHH', 2, 8, 1, pc0, ehsize, shoff, 0x1000,
                       ehsize, phentsize, phnum, shentsize, shnum, shnum - 1)
    for s, off in zip(secs, offs):
        name, typ, flags, addr, size, data = s
        pflags = (4 if flags & 2 else 0) | (2 if flags & 1 else 0) | (1 if flags & 4 else 0)
        out += struct.pack('<8I', 1, off, addr, addr, len(data), size, pflags, 0x10)
    out += bytes(data_off - len(out))
    out += blob
    out += bytes(shentsize)
    for i, (s, off) in enumerate(zip(secs, offs)):
        name, typ, flags, addr, size, data = s
        out += struct.pack('<10I', name_off[i], typ, flags, addr, off, size, 0, 0, 16, 0)
    out += struct.pack('<10I', name_off[-1], 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(out)


def main():
    """Convert the PS-X EXE named on the command line into an ELF."""
    exe = open(sys.argv[1], 'rb').read()
    open(sys.argv[2], 'wb').write(build(exe))
    pc0, gp0, t_addr, t_size = struct.unpack_from('<4I', exe, 0x10)
    print(f'entry {pc0:#010x} gp {gp0:#010x} text {t_addr:#010x}+{t_size:#x} -> {sys.argv[2]}')


if __name__ == '__main__':
    main()
