#!/usr/bin/env python3
"""Скан: кто из либ rootfs требует данный soname (для карты пакетов)."""
import os
import struct
import sys

ROOTFS = "/home/z/my-project/poler-os/cachyos-root/root"


def elf_dyn(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    shs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, typ, flags, addr, offset, size, link, info, align, entsize) = \
            struct.unpack_from("<IIQQQQIIQQ", data, off)
        shs.append(dict(name=name, typ=typ, offset=offset, size=size, link=link))
    sh = shs[e_shstrndx]
    shstr = data[sh["offset"]:sh["offset"] + sh["size"]]
    sname = lambda off: shstr[off:shstr.find(b"\0", off)].decode()
    sections = {sname(s["name"]): s for s in shs}
    dyn = sections.get(".dynamic")
    needed = []
    if dyn:
        off, end = dyn["offset"], dyn["offset"] + dyn["size"]
        while off < end:
            tag, val = struct.unpack_from("<QQ", data, off)
            off += 16
            if tag == 1:
                st = shs[dyn["link"]]
                strtab = data[st["offset"]:st["offset"] + st["size"]]
                needed.append(strtab[val:strtab.find(b"\0", val)].decode())
            elif tag == 0:
                break
    return needed


targets = sys.argv[1:]
for base, dirs, names in os.walk(os.path.join(ROOTFS, "usr")):
    for n in names:
        p = os.path.join(base, n)
        try:
            needed = elf_dyn(p)
        except Exception:
            needed = None
        if not needed:
            continue
        for t in targets:
            if t in needed:
                print(f"{t}  <--  {p}")
