"""Extract a PlayStation disc image (raw 2352-byte MODE2 .bin) into a folder.

Usage: python psx_extract.py <track1.bin> <out_dir>

Writes every ISO9660 file (form-1 user data; form-2 / XA streams
are only listed, the runtime reads them from the image) and
disc_files.csv (path, lba, size, flags, xa form).
"""
import os
import struct
import sys
import csv

SECTOR = 2352


def read_sector(f, lba):
    """Raw 2352-byte sector `lba` of the image."""
    f.seek(lba * SECTOR)
    return f.read(SECTOR)


def user_data(raw):
    # MODE2: 12 sync + 4 header + 8 subheader (2x4) + data
    """The 2048 user data bytes of a raw MODE2 form-1 sector."""
    return raw[24:24 + 2048]


def read_extent(f, lba, size):
    """`size` bytes of user data starting at sector `lba`."""
    out = bytearray()
    n = (size + 2047) // 2048
    for i in range(n):
        out += user_data(read_sector(f, lba + i))
    return bytes(out[:size])


def parse_dir(f, lba, size, prefix, files):
    """Walk an ISO9660 directory extent recursively, appending (path, lba, size, flags, xa) to files."""
    data = read_extent(f, lba, size)
    pos = 0
    while pos < len(data):
        ln = data[pos]
        if ln == 0:
            pos = (pos // 2048 + 1) * 2048
            continue
        rec = data[pos:pos + ln]
        ext_lba = struct.unpack_from('<I', rec, 2)[0]
        ext_size = struct.unpack_from('<I', rec, 10)[0]
        flags = rec[25]
        nlen = rec[32]
        name = rec[33:33 + nlen]
        # system use area: XA attributes
        su = rec[33 + nlen + ((nlen + 1) & 1):]
        xa_attr = 0
        if len(su) >= 14 and su[6:8] == b'XA':
            xa_attr = struct.unpack_from('>H', su, 4)[0]
        pos += ln
        if name in (b'\x00', b'\x01'):
            continue
        nm = name.decode('ascii', 'replace').split(';')[0]
        path = prefix + nm
        if flags & 2:
            parse_dir(f, ext_lba, ext_size, path + '/', files)
        else:
            files.append((path, ext_lba, ext_size, flags, xa_attr))


def main():
    """Extract every file of the disc image and write disc_files.csv."""
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    with open(src, 'rb') as f:
        pvd = user_data(read_sector(f, 16))
        assert pvd[1:6] == b'CD001', 'no ISO9660 PVD'
        root = pvd[156:156 + 34]
        rlba = struct.unpack_from('<I', root, 2)[0]
        rsize = struct.unpack_from('<I', root, 10)[0]
        files = []
        parse_dir(f, rlba, rsize, '', files)
        rows = []
        for path, lba, size, flags, xa in files:
            dst = os.path.join(out, 'files', path)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            form2 = bool(xa & 0x1000) or bool(xa & 0x4000)  # mode2 form2 / interleaved
            # check the first sector's submode for form 2
            raw0 = read_sector(f, lba)
            if len(raw0) < SECTOR:
                print('  beyond track 1:', path, lba, size)
                rows.append((path, lba, size, flags, 'outside'))
                continue
            if raw0[18] & 0x20:
                form2 = True
            if not form2:
                with open(dst, 'wb') as o:
                    o.write(read_extent(f, lba, size))
            rows.append((path, lba, size, flags, 'form2' if form2 else 'form1'))
            print(f'{lba:7d} {size:10d} {"F2" if form2 else "  "} {path}')
        with open(os.path.join(out, 'disc_files.csv'), 'w', newline='') as o:
            w = csv.writer(o)
            w.writerow(['path', 'lba', 'size', 'flags', 'form'])
            w.writerows(rows)
        total = os.path.getsize(src) // SECTOR
        print('sectors', total)


if __name__ == '__main__':
    main()
