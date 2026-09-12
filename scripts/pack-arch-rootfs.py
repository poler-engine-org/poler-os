#!/usr/bin/env python3
import os, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "e2e"))
from e2e_lib import build_cpio

print("=== Packaging Authentic Arch Linux / CachyOS Live Environment ===")

files = {}

# 1. Read Arch/CachyOS busybox binary
bb_path = "/usr/lib/initcpio/busybox"
if not os.path.exists(bb_path):
    print(f"Error: {bb_path} not found")
    sys.exit(1)

with open(bb_path, "rb") as f:
    bb_data = f.read()

files["usr/bin/busybox"] = bb_data
files["bin/busybox"] = bb_data

# 2. Read glibc libraries from host CachyOS
libs = [
    ("/usr/lib/libc.so.6", "usr/lib/libc.so.6"),
    ("/usr/lib/libc.so.6", "lib64/libc.so.6"),
    ("/usr/lib/libc.so.6", "lib/libc.so.6"),
    ("/usr/lib/libcrypt.so.2", "usr/lib/libcrypt.so.2"),
    ("/usr/lib/libcrypt.so.2", "lib64/libcrypt.so.2"),
    ("/usr/lib/libcrypt.so.2", "lib/libcrypt.so.2"),
    ("/usr/lib/libm.so.6", "usr/lib/libm.so.6"),
    ("/usr/lib/libm.so.6", "lib64/libm.so.6"),
    ("/usr/lib/libm.so.6", "lib/libm.so.6"),
    ("/usr/lib/ld-linux-x86-64.so.2", "usr/lib/ld-linux-x86-64.so.2"),
    ("/usr/lib/ld-linux-x86-64.so.2", "lib64/ld-linux-x86-64.so.2"),
    ("/usr/lib/ld-linux-x86-64.so.2", "lib/ld-linux-x86-64.so.2"),
]

for src, dst in libs:
    if os.path.exists(src):
        real_src = os.path.realpath(src)
        with open(real_src, "rb") as f:
            files[dst] = f.read()
        print(f"  + Added library: {dst} ({len(files[dst])} bytes)")

# 3. Create all BusyBox applet entries as copies/shims
applets = [
    "sh", "bash", "ash", "ls", "cat", "echo", "clear", "pwd", "mkdir",
    "rm", "touch", "cp", "mv", "grep", "sed", "awk", "find", "which",
    "uname", "ps", "dmesg", "free", "df", "du", "kill", "killall",
    "head", "tail", "less", "more", "wc", "sort", "uniq", "tar",
    "gzip", "bzip2", "xz", "ping", "ifconfig", "ip", "route", "netstat",
    "vi", "env", "sleep", "date", "uptime", "sync", "stat", "chmod", "chown"
]

for app in applets:
    files[f"usr/bin/{app}"] = bb_data
    files[f"bin/{app}"] = bb_data

# 4. System configuration & release info
files["etc/os-release"] = b"""NAME="CachyOS"
PRETTY_NAME="CachyOS Linux (Arch-based) on POLER Microkernel"
ID=cachyos
ID_LIKE=arch
BUILD_ID=rolling
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://cachyos.org/"
DOCUMENTATION_URL="https://wiki.cachyos.org/"
"""

files["etc/hostname"] = b"cachyos-live\n"

files["etc/issue"] = b"""
 \033[1;36mCachyOS Live Installation Environment\033[0m
 Kernel 0.20.0-rc on an x86_64 POLER Microkernel Substrate

"""

files["etc/passwd"] = b"root:x:0:0:root:/root:/bin/sh\n"
files["etc/group"] = b"root:x:0:root\n"
files["etc/profile"] = b"""export PATH=/bin:/usr/bin:/sbin:/usr/sbin
export HOME=/root
export USER=root
export TERM=linux
export PS1='\\[\\033[1;36m\\][root@cachyos-live \\[\\033[1;33m\\]\\w\\[\\033[1;36m\\]]# \\[\\033[0m\\]'
alias l='ls -la'
alias ll='ls -l'
"""

# Read custom init and sh if compiled
sh_path = os.path.join(REPO, "userspace", "sh")
if os.path.exists(sh_path):
    with open(sh_path, "rb") as f:
        sh_data = f.read()
        files["bin/sh"] = sh_data
        files["usr/bin/sh"] = sh_data
        files["bin/bash"] = sh_data
        files["usr/bin/bash"] = sh_data
        print(f"  + Added standalone Ring 3 POSIX Shell: /bin/sh ({len(sh_data)} bytes)")

comp_path = os.path.join(REPO, "userspace", "compositor")
if os.path.exists(comp_path):
    with open(comp_path, "rb") as f:
        comp_data = f.read()
        files["bin/compositor"] = comp_data
        files["usr/bin/compositor"] = comp_data
        files["bin/startx"] = comp_data
        files["usr/bin/startx"] = comp_data
        files["bin/plasma"] = comp_data
        files["usr/bin/plasma"] = comp_data
        files["bin/gamescope"] = comp_data
        files["usr/bin/gamescope"] = comp_data
        print(f"  + Added Plasma 6 / Gamescope Compositor: /bin/compositor ({len(comp_data)} bytes)")

init_path = os.path.join(REPO, "userspace", "init")
if os.path.exists(init_path):
    with open(init_path, "rb") as f:
        files["sbin/init"] = f.read()
        files["init"] = f.read()

# Build CPIO
cpio_data = build_cpio(files)

# Output paths
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

print(f"[SUCCESS] Packaged {len(files)} files into {out1} ({len(cpio_data)} bytes / {len(cpio_data)/(1024*1024):.2f} MB)")
