#!/usr/bin/env python3
import os, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "e2e"))
from e2e_lib import build_cpio

# Read compiled binaries
with open(os.path.join(REPO, "userspace", "init"), "rb") as f:
    init_bin = f.read()

with open(os.path.join(REPO, "userspace", "sh"), "rb") as f:
    sh_bin = f.read()

with open(os.path.join(REPO, "userspace", "compositor"), "rb") as f:
    comp_bin = f.read()

os_release = b"""NAME="CachyOS / POLER-OS"
PRETTY_NAME="CachyOS Linux / POLER-OS Microkernel Substrate"
ID=cachyos
ID_LIKE=arch
BUILD_ID=rolling
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://cachyos.org/"
DOCUMENTATION_URL="https://wiki.cachyos.org/"
"""

issue = b"""
 \033[1;36mPOLER-OS / CachyOS Linux-ABI Substrate\033[0m (\l)
 Kernel \r on an \m

"""

readme = b"""POLER-OS v0.20.0-rc Root Filesystem (CachyOS Linux-ABI)
Architecture: x86_64 Long Mode (Ring 0 Microkernel + Ring 3 POSIX Userspace)
DRM/KMS: /dev/dri/card0 (1024x768 XRGB8888)
Input: /dev/input/event0, /dev/input/event1
"""

# Host glibc dynamic runtime binaries
with open("/usr/lib/ld-linux-x86-64.so.2", "rb") as f:
    ld_so = f.read()

with open("/usr/lib/libc.so.6", "rb") as f:
    libc_so = f.read()

uname_bin = b""
if os.path.isfile("/usr/bin/uname"):
    with open("/usr/bin/uname", "rb") as f:
        uname_bin = f.read()

echo_bin = b""
if os.path.isfile("/usr/bin/echo"):
    with open("/usr/bin/echo", "rb") as f:
        echo_bin = f.read()

files = {
    "sbin/init": init_bin,
    "bin/sh": sh_bin,
    "bin/init": init_bin,
    "bin/compositor": comp_bin,
    "lib64/ld-linux-x86-64.so.2": ld_so,
    "usr/lib/ld-linux-x86-64.so.2": ld_so,
    "usr/lib/libc.so.6": libc_so,
    "lib/libc.so.6": libc_so,
    "lib64/libc.so.6": libc_so,
    "bin/uname": uname_bin,
    "bin/echo": echo_bin,
    "etc/os-release": os_release,
    "etc/hostname": b"poler-cachyos\n",
    "etc/issue": issue,
    "README.txt": readme,
}

cpio_data = build_cpio(files)

# Write to build locations
build_dir = os.path.join(REPO, "build")
iso_boot_dir = os.path.join(REPO, "zig-kernel", "iso", "boot")
os.makedirs(build_dir, exist_ok=True)
os.makedirs(iso_boot_dir, exist_ok=True)

out1 = os.path.join(build_dir, "live-initrd.cpio")
out2 = os.path.join(iso_boot_dir, "live-initrd.cpio")

with open(out1, "wb") as f:
    f.write(cpio_data)

with open(out2, "wb") as f:
    f.write(cpio_data)

print(f"[OK] Packed {len(files)} files into {out1} and {out2} ({len(cpio_data)} bytes)")
