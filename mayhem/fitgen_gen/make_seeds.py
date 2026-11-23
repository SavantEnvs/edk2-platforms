#!/usr/bin/env python3
"""Regenerate the fitgen_gen seed FDs: python3 mayhem/fitgen_gen/make_seeds.py <outdir>

Each seed is a 64 KiB flash image (mapped at 4 GiB - 64 KiB) holding one FFS2 firmware volume:
a BiosInfo FFS file (gBiosInfoGuid, Platform/Intel/BoardModulePkg/BoardModulePkg.dec) listing the
FIT entries, one RAW FFS file per blob those entries point at (microcode, ACM, BIOS module, ...),
a pad file, and the Volume Top File, as `FitGen -D <fd> <out> -I <BiosInfoGuid>` expects.
"""
import os
import struct
import sys
import uuid

FD_SIZE = 0x10000
TOP = 0x100000000
FFS2 = uuid.UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3")
VTF = uuid.UUID("1ba0062e-c779-4582-8566-336ae8f78f09")
BIOS_INFO = uuid.UUID("09d0d15c-e9f0-4dfc-9e0b-39331fca6685")
PAD = uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
RAW_GUIDS = [uuid.UUID(int=0x5EED0000 + i) for i in range(8)]


def flash(off):
    return TOP - FD_SIZE + off


def align8(n):
    return (n + 7) & ~7


def ffs(guid, ftype, body, size=None):
    size = 24 + len(body) if size is None else size
    hdr = bytearray(guid.bytes_le + struct.pack("<HBB", 0, ftype, 0) + size.to_bytes(3, "little") + b"\xf8")
    hdr[16] = (-sum(hdr[:16] + hdr[18:23])) & 0xFF  # header checksum
    hdr[17] = 0xAA                                   # FFS_FIXED_CHECKSUM: file data not summed
    return bytes(hdr) + body


def bios_info(entries):
    body = struct.pack("<8sII", b"$BIOSIF$", len(entries), 0)
    for t, attr, ver, size, addr in entries:
        body += struct.pack("<BBHIQ", t, attr, ver, size, addr)
    return body


def fv(blobs, entries):
    """entries: (type, attributes, version, size, blob index) -> BiosInfo entry at that blob's address."""
    hdr = bytearray(bytes(16) + FFS2.bytes_le
                    + struct.pack("<Q4sIHHHBB", FD_SIZE, b"_FVH", 0x0004FEFF, 0x48, 0, 0, 0, 2))
    hdr += struct.pack("<IIII", FD_SIZE // 0x1000, 0x1000, 0, 0)
    hdr[0x32:0x34] = struct.pack("<H", (-sum(struct.unpack("<36H", hdr))) & 0xFFFF)

    off = align8(0x48 + 24 + 16 + 16 * len(entries))
    addrs = []
    for b in blobs:
        addrs.append(flash(off + 24))
        off = align8(off + 24 + len(b))
    info = bios_info([(t, a, v, sz, addrs[i]) for t, a, v, sz, i in entries])
    files = [ffs(BIOS_INFO, 0x02, info)] + [ffs(RAW_GUIDS[i], 0x01, b) for i, b in enumerate(blobs)]
    vtf = ffs(VTF, 0x03, b"\xff" * 0x100)  # erased: the FIT pointer slot at FD end - 0x40 must be free

    img = bytearray(b"\xff" * FD_SIZE)
    img[: len(hdr)] = hdr
    off = 0x48
    for f in files:
        img[off: off + len(f)] = f
        off = align8(off + len(f))
    vtf_off = FD_SIZE - len(vtf)
    img[off: off + 24] = ffs(PAD, 0xF0, b"", size=vtf_off - off)  # free space, where the FIT goes
    img[vtf_off:] = vtf
    return bytes(img)


def microcode(rev):
    total = 0x800
    blob = bytearray(struct.pack("<IiIIiIIII12x", 1, rev, 0x07142022, 0x000906A3, 0, 1, 0x80, total - 48, total))
    blob += bytes(total - 48)
    s = sum(struct.unpack("<%dI" % (total // 4), blob)) & 0xFFFFFFFF
    blob[16:20] = struct.pack("<I", (-s) & 0xFFFFFFFF)
    return bytes(blob)


def startup_acm():
    """A chipset (startup) ACM: header v0, key 64 dwords, info table v4 with chipset + processor ID lists."""
    size = 0x1000
    acm = bytearray(size)
    struct.pack_into("<HHIIHHIIIHHIIIIII64xII", acm, 0, 2, 0, 0xE0 // 4, 0, 0xB00, 0, 0x8086, 0x20220714,
                     size // 4, 1, 1, 0, 0, 0, 0, 0, 0, 64, 2 * 64 + 15)
    info = 128 + 64 * 4 + 4 + 256 + (2 * 64 + 15) * 4  # CheckAcm(): past key, exponent, signature, scratch
    struct.pack_into("<IIIIBBHIIIIB3sI", acm, info, 0x7FC03AAA, 0x18DB46A7, 0x8F69AC2E, 0x5A7F418D, 0, 4, 0x2C,
                     0x600, 0, 0x200, 0, 0x10, b"\x01\x02\x03", 0x640)
    struct.pack_into("<IIHHH6x", acm, 0x600, 1, 1, 0x8086, 0xA700, 0)           # chipset ID list
    struct.pack_into("<IIIQQ", acm, 0x640, 1, 0x000906A0, 0x0FFF3FF0, 0, 0)     # processor ID list
    return bytes(acm)


def seeds():
    out = {}
    out["fd_microcode_bios"] = fv([microcode(0x10), microcode(0x11), bytes(0x2000)],
                                  [(1, 0, 0x100, 0x800, 0), (1, 0, 0x100, 0x800, 1), (7, 0, 0x100, 0x2000, 2)])
    out["fd_acm_manifests"] = fv([startup_acm(), microcode(0x20), bytes(0x1000), bytes(0x400), bytes(0x400)],
                                 [(2, 0, 0x200, 0x1000, 0), (1, 0x10, 0x100, 0x800, 1), (7, 0, 0x100, 0x1000, 2),
                                  (0xB, 0, 0x100, 0x400, 3), (0xC, 0, 0x100, 0x400, 4)])
    out["fd_empty_biosinfo"] = fv([], [])
    return out


if __name__ == "__main__":
    os.makedirs(sys.argv[1], exist_ok=True)
    for name, data in seeds().items():
        with open(os.path.join(sys.argv[1], name), "wb") as f:
            f.write(data)
