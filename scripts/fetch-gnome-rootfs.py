#!/usr/bin/env python3
"""
fetch-gnome-rootfs.py — Download, extract, and package complete GNOME desktop
environment for POLER-OS Live ISO with multi-mirror resilience.
"""

import os
import sys
import subprocess
import urllib.request
import urllib.error
import zstandard
import tarfile
import shutil

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR = os.path.join(REPO, "build")
GNOME_CACHE = os.path.join(BUILD_DIR, "gnome-pkgcache")
GNOME_ROOT = os.path.join(BUILD_DIR, "gnome-root")
GNOME_SFS = os.path.join(BUILD_DIR, "gnome-rootfs.sfs")

os.makedirs(GNOME_CACHE, exist_ok=True)
os.makedirs(GNOME_ROOT, exist_ok=True)

FALLBACK_MIRRORS = [
    "https://mirror.cachyos.org/repo/x86_64_v3/cachyos-extra-v3/",
    "https://mirror.cachyos.org/repo/x86_64/cachyos-extra/",
    "https://mirror.cachyos.org/repo/x86_64/cachyos/",
    "https://mirror.cachyos.org/repo/x86_64_v3/cachyos-v3/",
    "https://geo.mirror.pkgbuild.com/extra/os/x86_64/",
    "https://geo.mirror.pkgbuild.com/core/os/x86_64/",
    "https://mirror.osbeck.com/archlinux/extra/os/x86_64/",
    "https://mirror.alpix.eu/archlinux/extra/os/x86_64/",
    "https://archlinux.cachyos.org/repo/extra/os/x86_64/",
    "https://archlinux.cachyos.org/repo/core/os/x86_64/",
]

def download_file(url, dest_path):
    fname = os.path.basename(url)
    urls_to_try = [url]
    for m in FALLBACK_MIRRORS:
        urls_to_try.append(m.rstrip("/") + "/" + fname)

    headers = {'User-Agent': 'POLER-OS-GNOME-Fetcher/1.0'}
    for candidate in urls_to_try:
        try:
            req = urllib.request.Request(candidate, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp, open(dest_path, "wb") as f_out:
                shutil.copyfileobj(resp, f_out)
            return True
        except Exception:
            continue
    return False

# 1. Obtain package URLs using pacman
targets = [
    "mutter",
    "gnome-shell",
    "gnome-session",
    "gnome-terminal",
    "nautilus",
    "adwaita-icon-theme",
    "cantarell-fonts",
    "gtk4",
    "libadwaita",
]

print(f"[*] Resolving dependency URLs for: {', '.join(targets)}")
raw_urls = subprocess.check_output(["pacman", "-Sp"] + targets).decode("utf-8").strip().split()
urls = sorted(list(set(raw_urls)))

print(f"[*] Total packages in closure: {len(urls)}")

# 2. Download packages to cache
for i, url in enumerate(urls, 1):
    fname = os.path.basename(url)
    dest_path = os.path.join(GNOME_CACHE, fname)
    if not os.path.exists(dest_path) or os.path.getsize(dest_path) == 0:
        print(f"[{i}/{len(urls)}] Downloading {fname}...")
        ok = download_file(url, dest_path)
        if not ok:
            print(f"  [WARN] Could not fetch {fname}, continuing...")
    else:
        print(f"[{i}/{len(urls)}] Cached: {fname}")

# 3. Extract packages into GNOME_ROOT
print(f"[*] Unpacking packages into {GNOME_ROOT}...")
for fname in sorted(os.listdir(GNOME_CACHE)):
    if not fname.endswith(".pkg.tar.zst"):
        continue
    pkg_path = os.path.join(GNOME_CACHE, fname)
    print(f"  -> Extracting {fname}...")
    try:
        with open(pkg_path, "rb") as f_in:
            dctx = zstandard.ZstdDecompressor()
            with dctx.stream_reader(f_in) as reader:
                with tarfile.open(fileobj=reader, mode="r|") as tar:
                    for member in tar:
                        if member.name.startswith("."):
                            continue
                        try:
                            tar.extract(member, path=GNOME_ROOT, filter=getattr(tarfile, 'data_filter', None))
                        except Exception:
                            try:
                                tar.extract(member, path=GNOME_ROOT)
                            except Exception:
                                pass
    except Exception as e:
        print(f"  [WARN] Failed to unpack {fname}: {e}")

# 4. Copy glibc and dynamic linker if missing
ld_path = "/usr/lib/ld-linux-x86-64.so.2"
libc_path = "/usr/lib/libc.so.6"
os.makedirs(os.path.join(GNOME_ROOT, "usr", "lib"), exist_ok=True)
os.makedirs(os.path.join(GNOME_ROOT, "lib64"), exist_ok=True)

if os.path.exists(ld_path):
    shutil.copy2(ld_path, os.path.join(GNOME_ROOT, "usr", "lib", "ld-linux-x86-64.so.2"))
if os.path.exists(libc_path):
    shutil.copy2(libc_path, os.path.join(GNOME_ROOT, "usr", "lib", "libc.so.6"))

# Symlinks for lib64
if not os.path.exists(os.path.join(GNOME_ROOT, "lib64", "ld-linux-x86-64.so.2")):
    try:
        os.symlink("../usr/lib/ld-linux-x86-64.so.2", os.path.join(GNOME_ROOT, "lib64", "ld-linux-x86-64.so.2"))
    except OSError:
        if os.path.exists(ld_path):
            shutil.copy2(ld_path, os.path.join(GNOME_ROOT, "lib64", "ld-linux-x86-64.so.2"))

# 5. Build SquashFS image
print(f"[*] Creating compact SquashFS: {GNOME_SFS}")
if os.path.exists(GNOME_SFS):
    os.remove(GNOME_SFS)

subprocess.check_call([
    "mksquashfs",
    GNOME_ROOT,
    GNOME_SFS,
    "-comp", "zstd",
    "-Xcompression-level", "15",
    "-noappend",
    "-wildcards",
    "-e", "usr/share/doc/*", "usr/share/man/*", "usr/include/*"
])

sfs_size = os.path.getsize(GNOME_SFS) / (1024 * 1024)
print(f"[OK] Complete GNOME Desktop Environment built: {GNOME_SFS} ({sfs_size:.2f} MB)")
