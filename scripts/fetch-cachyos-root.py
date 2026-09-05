#!/usr/bin/env python3
# ============================================================================
# fetch-cachyos-root.py — CDD #12 p1: CachyOS rootfs-кэш (gamescope + closure)
# ============================================================================
# Состав «боевого» rootfs CachyOS (CDD #12: корневой ФС-кэш = $CACHYOS_ROOT):
#   - gamescope (собственный пакет CachyOS, baseline) — бинарь композитора;
#   - glibc/gcc-libs (CachyOS v3: cachyos-v3) — НАСТОЯЩИЙ CachyOS glibc 2.44;
#   - wayland/libdrm/xorg-стек/libinput/… (CachyOS v3: extra-v3);
#   - systemd-libs/pipewire/libeis (Arch core/extra — CachyOS их тоже берёт
#     из Arch-реп: бинарно-совместимы, baseline);
# Пакеты качаются .pkg.tar.zst → распаковка в cachyos-root/root/usr/…
# Отчёт report.json: PT_INTERP, soname-замыкание, пути, размеры.
#
# v3-ноты: glibc/libstdc++ и пр. — x86-64-v3 (AVX2) → ядро включает
# OSXSAVE+XCR0 (CDD #12 p1), QEMU — -cpu max (TCG эмулирует AVX2).
#
# Кэш персистентен: повторный запуск докачивает только недостающее.
# ============================================================================
import io
import json
import os
import struct
import sys
import tarfile
import urllib.parse
import urllib.request

import zstandard

REPOES = [
    # (url, приоритет: первый — где ищем в первую очередь)
    "https://mirror.cachyos.org/repo/x86_64/cachyos",               # gamescope
    "https://mirror.cachyos.org/repo/x86_64_v3/cachyos-v3",         # glibc, gcc-libs
    "https://mirror.cachyos.org/repo/x86_64_v3/cachyos-extra-v3",   # wayland, libdrm, x11
    "https://mirror.cachyos.org/repo/x86_64_v3/cachyos-core-v3",    # libcap
    "https://mirror.cachyos.org/repo/x86_64_v3/cachyos-community-v3",
    "https://geo.mirror.pkgbuild.com/core/os/x86_64",               # systemd-libs
    "https://geo.mirror.pkgbuild.com/extra/os/x86_64",              # pipewire, libeis
]
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), "cachyos-root")
PKGCACHE = os.path.join(OUT, "pkgcache")
ROOTFS = os.path.join(OUT, "root")

# soname → имя пакета (когда авто-вывод из soname не совпадает)
SONAME_PKG = {
    "ld-linux-x86-64.so.2": "glibc",
    "libc.so.6": "glibc",
    "libm.so.6": "glibc",
    "librt.so.1": "glibc",
    "libpthread.so.0": "glibc",
    "libdl.so.2": "glibc",
    "libresolv.so.2": "glibc",
    "libutil.so.1": "glibc",
    "libanl.so.1": "glibc",
    "libnss_dns.so.2": "glibc",
    "libnss_files.so.2": "glibc",
    "libgcc_s.so.1": "gcc-libs",
    "libstdc++.so.6": "gcc-libs",
    "libwayland-client.so.0": "wayland",
    "libwayland-server.so.0": "wayland",
    "libwayland-cursor.so.0": "wayland",
    "libwayland-egl.so.1": "wayland",
    "libpipewire-0.3.so.0": "pipewire",
    "libudev.so.1": "systemd-libs",
    "libseat.so.1": "seatd",
    "libeis.so.1": "libeis",
    "libSDL2-2.0.so.0": "sdl2-compat",
    "libSDL3.so.0": "sdl3",
    "libluajit-5.1.so.2": "luajit",
    "libdecor-0.so.0": "libdecor",
    "libdisplay-info.so.1": "libdisplay-info",
    "libliftoff.so.0": "libliftoff",
    "libdrm.so.2": "libdrm",
    "libdrm_amdgpu.so.1": "libdrm",
    "libdrm_intel.so.1": "libdrm",
    "libdrm_nouveau.so.2": "libdrm",
    "libdrm_radeon.so.1": "libdrm",
    "libxkbcommon.so.0": "libxkbcommon",
    "libxkbcommon-x11.so.0": "libxkbcommon",
    "libX11.so.6": "libx11",
    "libX11-xcb.so.1": "libx11",
    "libxcb.so.1": "libxcb",
    "libxcb-dri3.so.0": "libxcb",
    "libXau.so.6": "libxau",
    "libXdmcp.so.6": "libxdmcp",
    "libXext.so.6": "libxext",
    "libXfixes.so.3": "libxfixes",
    "libXdamage.so.1": "libxdamage",
    "libXrender.so.1": "libxrender",
    "libXcomposite.so.1": "libxcomposite",
    "libXcursor.so.1": "libxcursor",
    "libXrandr.so.2": "libxrandr",
    "libXxf86vm.so.1": "libxxf86vm",
    "libXRes.so.1": "libxres",
    "libXtst.so.6": "libxtst",
    "libXi.so.6": "libxi",
    "libXmu.so.6": "libxmu",
    "libavif.so.16": "libavif",
    "libpng16.so.16": "libpng",
    "libjpeg.so.8": "libjpeg-turbo",
    "libpixman-1.so.0": "pixman",
    "libcap.so.2": "libcap",
    "libinput.so.10": "libinput",
    "libevdev.so.2": "libevdev",
    "libwacom.so.9": "libwacom",
    "mtdev.so.1": "mtdev",
    "libvulkan.so.1": "vulkan-icd-loader",
    "aom.so.3": "aom",
    "dav1d.so.7": "dav1d",
    "libsharpyuv.so.0": "libwebp",
    "libwebp.so.7": "libwebp",
    "libwebpdemux.so.2": "libwebp",
    "libyuv.so": "libyuv",
    "libwlroots.so.13": "wlroots",
    "libspa-0.2.so.0": "pipewire",
    "libxshmfence.so.1": "libxshmfence",
    "libpipewire-0.3.so.0": "libpipewire",
    "libgcc_s.so.1": "libgcc",
    "libstdc++.so.6": "libstdc++",
    "liblua5.4.so.5.4": "lua54",
    "libmtdev.so.1": "mtdev",
    "libXt.so.6": "libxt",
    "libdav1d.so.7": "dav1d",
    "librav1e.so.0.8": "rav1e",
    "libSvtAv1Enc.so.4": "svt-av1",
    "libaom.so.3": "aom",
    "libgudev-1.0.so.0": "libgudev",
    "libglib-2.0.so.0": "glib2",
    "libgobject-2.0.so.0": "glib2",
    "libgmodule-2.0.so.0": "glib2",
    "libgio-2.0.so.0": "glib2",
    "libgthread-2.0.so.0": "glib2",
    "libeis.so.1": "libei",
    "libmount.so.1": "util-linux-libs",
    "libblkid.so.1": "util-linux-libs",
    "libuuid.so.1": "util-linux-libs",
    "libpcre2-8.so.0": "pcre2",
    "libz.so.1": "zlib",
    "libSM.so.6": "libsm",
    "libICE.so.6": "libice",
    "libzstd.so.1": "zstd",
    "liblzma.so.5": "xz",
    "libbz2.so.1.0": "bzip2",
}


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "poler-cdd12/1.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read()


def repo_index(url):
    """HTML fancyindex → список имён пакетов."""
    html = http_get(url + "/").decode("utf-8", "replace")
    names = []
    for line in html.splitlines():
        if "href=" not in line:
            continue
        a = line.find('href="') + 6
        b = line.find('"', a)
        name = line[a:b]
        if ".pkg.tar." in name and not name.endswith(".sig"):
            names.append(name)
    return names


def pkg_split(name):
    """gamescope-3.16.25-1-x86_64.pkg.tar.zst → (pkgname, ver, rel, arch).
    pkgname — URL-РАСКОДИРОВАН (%2B → '+')."""
    stem = urllib.parse.unquote(name).rsplit(".pkg.tar", 1)[0]
    parts = stem.rsplit("-", 3)
    if len(parts) == 4:
        return parts[0], parts[1], parts[2], parts[3]
    return stem, "", "", ""


def ver_tuple(s):
    out = []
    cur = ""
    for ch in s:
        if ch.isdigit():
            cur += ch
        else:
            if cur:
                out.append(int(cur))
                cur = ""
            out.append(ch.lower())
    if cur:
        out.append(int(cur))
    return out


def cmp_ver(a, b):
    va, vb = ver_tuple(a), ver_tuple(b)
    for i in range(max(len(va), len(vb))):
        x = va[i] if i < len(va) else 0
        y = vb[i] if i < len(vb) else 0
        if x == y:
            continue
        return -1 if x < y else 1
    return 0


def best_pkg(idx, pkgname):
    cands = [n for n in idx if pkg_split(n)[0] == pkgname]
    if not cands:
        return None
    import functools
    return sorted(cands, key=functools.cmp_to_key(
        lambda a, b: cmp_ver(pkg_split(a)[1] + "." + pkg_split(a)[2],
                             pkg_split(b)[1] + "." + pkg_split(b)[2])))[-1]


# CDD №12 p4-фикс: сонам-резолв с префикс-фолбэками. Проблема: rolling-зеркало
# бампит версии сонамов (libLLVM.so.22.1 → .23) — точный ключ карты промахивается,
# а фолбэк «libLLVM» не является именем пакета. Префиксы маппим на стабильные
# имена пакетов (llvm-libs / icu / mesa / vulkan-icd-loader).
def pkg_for_soname(m):
    if m in SONAME_PKG:
        return SONAME_PKG[m]
    if m.startswith("libLLVM.so"):
        return "llvm-libs"
    # CDD №12 p4: хвост lvp-замыкания (эмпирика run3: 4 MISSING) — имена
    # пакетов ≠ сонам-префиксам (expat/spirv-tools/ncurses/libxcb-keysyms)
    if m == "libexpat.so.1":
        return "expat"
    if m == "libSPIRV-Tools.so" or m.startswith("libSPIRV-Tools"):
        return "spirv-tools"
    if m == "libncursesw.so.6" or m.startswith("libncurses"):
        return "ncurses"
    if m.startswith("libxcb-") or m == "libxcb.so.1":
        return "libxcb"
    if m.startswith("libicu"):
        return "icu"
    if m.startswith("libvulkan_lvp") or m.startswith("libglapi") or \
            m.startswith("libmesa_") or m.startswith("libgallium"):
        # CDD №12 p4-фикс: lavapipe (libvulkan_lvp.so + lvp_icd.json) живёт в
        # ОТДЕЛЬНОМ пакете vulkan-swrast (Arch/CachyOS split mesa 26.x);
        # пакет «mesa» содержит только GL/EGL/gallium-*.so
        return "vulkan-swrast"
    if m.startswith("libvulkan.so"):
        return "vulkan-icd-loader"
    if m.startswith("libSDL3"):
        return "sdl3"
    return m.split(".so")[0] if ".so" in m else m


def ensure_pkg(idx_map, pkgname):
    """Скачивает+распаковывает пакет (кэш). True если пакет есть."""
    if pkgname == "glibc":
        # «настоящий CachyOS glibc» — только v3-репо (в Arch другой)
        pass  # приоритет репо уже: cachyos-v3 раньше arch
    for url in REPOES:
        idx = idx_map.get(url)
        if idx is None:
            continue
        fname = best_pkg(idx, pkgname)
        if not fname:
            continue
        path = os.path.join(PKGCACHE, fname)
        if not os.path.exists(path):
            print(f"  download: {urllib.parse.unquote(fname)}  [{url.split('/repo/')[-1] if '/repo/' in url else url}]")
            data = http_get(url + "/" + fname)  # fname уже URL-encoded из href
            with open(path, "wb") as f:
                f.write(data)
        with open(path, "rb") as f:
            raw = f.read()
        if fname.endswith(".zst"):
            dctx = zstandard.ZstdDecompressor()
            raw = dctx.stream_reader(io.BytesIO(raw)).read()
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:tar")
        tf.extractall(ROOTFS, filter="data")
        return fname
    return None


# ─── ELF DT_NEEDED-ридер (ручной парс .dynamic + PT_INTERP) ─────────────────
def elf_dyn(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
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

    def sname(off):
        return shstr[off:shstr.find(b"\0", off)].decode()

    sections = {sname(s["name"]): s for s in shs}
    # PT_INTERP
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    interp = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type == 3:
            p_offset = struct.unpack_from("<Q", data, off + 0x08)[0]
            p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
            interp = data[p_offset:p_offset + p_filesz].rstrip(b"\0").decode()
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
    return interp, needed


def so_path(name):
    for d in ("usr/lib", "usr/lib64", "lib", "lib64"):
        p = os.path.join(ROOTFS, d, name)
        if os.path.exists(p):  # exists() следует симлинку — норм для резолва
            return p
    return None


def closure(binary):
    seen, missing, queue = set(), [], []
    interp, needed = elf_dyn(binary)
    queue.extend(needed)
    while queue:
        n = queue.pop(0)
        if n in seen:
            continue
        seen.add(n)
        p = so_path(n)
        if not p:
            missing.append(n)
            continue
        _, sub = elf_dyn(p) or (None, [])
        queue.extend(sub)
    return missing, sorted(seen), interp


def main():
    os.makedirs(PKGCACHE, exist_ok=True)
    os.makedirs(ROOTFS, exist_ok=True)
    print("=== CachyOS rootfs-fetch (CDD #12 p1) ===")
    print("[1/3] индексы репо...")
    idx_map = {}
    for url in REPOES:
        try:
            idx_map[url] = repo_index(url)
            print(f"  {url.split('//')[-1][:52]}: {len(idx_map[url])}")
        except Exception as e:
            print(f"  SKIP {url}: {e}")

    print("[2/3] gamescope + волна пакетов по DT_NEEDED-замыканию...")
    ensure_pkg(idx_map, "gamescope")
    binpath = os.path.join(ROOTFS, "usr/bin/gamescope")
    if not os.path.exists(binpath):
        print("FATAL: gamescope не встал")
        sys.exit(1)

    # CDD №12 p4-фикс: ХОЛОДНЫЙ СТАРТ dlopen-волны. Гейт os.path.exists()
    # на пустом кэше пропускал волну ЦЕЛИКОМ (SDL3/Vulkan/lavapipe нет в
    # DT_NEEDED-замыкании gamescope) → e2e: «Failed loading SDL3 library.» →
    # abort. Ставим пакеты-носители волн ДО гейта (идемпотентно: кэш-хит).
    for warm_pkg in ("sdl3", "vulkan-icd-loader", "vulkan-swrast", "mesa", "llvm-libs", "icu"):
        ensure_pkg(idx_map, warm_pkg)

    # dlopen-волна: gamescope dlopen'ит libSDL3.so.0 (sdl2-compat собран НА
    # SDL3) — DT_NEEDED-замыкание её НЕ видит; добавляем отдельной волной
    dlopen_extra = []
    for dlopen_target in ("usr/lib/libSDL3.so.0", "usr/lib/libvulkan.so.1",
                          "usr/lib/libvulkan_lvp.so"):
        p3 = os.path.join(ROOTFS, dlopen_target)
        if os.path.exists(p3):
            for round_no in range(8):
                missing2, libs2, _ = closure(p3)
                if not missing2:
                    break
                for m in missing2:
                    pkg = pkg_for_soname(m)
                    ensure_pkg(idx_map, pkg)
            missing2, libs2, _ = closure(p3)
            dlopen_extra.append(os.path.basename(p3))  # САМ файл (closure его не включает)
            dlopen_extra.extend(libs2)
            print(f"  dlopen-волна {dlopen_target}: {len(libs2)} либ, missing={missing2}")
        else:
            print(f"  dlopen-цель {dlopen_target} НЕ ВСТАЛА (пакет? зеркало?)")

    for round_no in range(16):
        missing, libs, interp = closure(binpath)
        if not missing:
            break
        print(f"  раунд {round_no}: {len(missing)} недостающих: {missing[:8]}{'…' if len(missing) > 8 else ''}")
        installed = []
        for m in missing:
            pkg = pkg_for_soname(m)
            fn = ensure_pkg(idx_map, pkg)
            if fn:
                installed.append(f"{m}→{fn}")
            elif pkg != m:
                fn = ensure_pkg(idx_map, m)
                if fn:
                    installed.append(f"{m}→{fn}")
        if not installed:
            print("  больше ставить нечего — стоп")
            break

    missing, libs, interp = closure(binpath)
    # union с dlopen-волной (SDL3 и её зависимости)
    for l in dlopen_extra:
        if l not in libs:
            libs.append(l)
    libs.sort()
    print()
    print(f"gamescope: {binpath} ({os.path.getsize(binpath)//1024} КБ)")
    print(f"  PT_INTERP: {interp}")
    print(f"  DT_NEEDED-замыкание: {len(libs)} либ")
    total = os.path.getsize(binpath)
    for l in libs:
        p = so_path(l)
        if p:
            print(f"    {l:28s} {os.path.getsize(p)//1024:5d} КБ")
            total += os.path.getsize(p)
        else:
            print(f"    {l:28s} MISSING")
    if missing:
        print(f"  !!! НЕ ЗАКРЫТО: {missing}")
    lds = os.path.join(ROOTFS, "usr/lib/ld-linux-x86-64.so.2")
    print(f"  ld.so: {'OK' if os.path.exists(lds) else 'ОТСУТСТВУЕТ'}")
    print(f"  суммарно: {total/1024/1024:.1f} МБ")

    # ICD-манифесты Vulkan (libvulkan ищет драйвер по /usr/share/vulkan/icd.d)
    extra_files = []
    icd_dir = os.path.join(ROOTFS, "usr", "share", "vulkan", "icd.d")
    if os.path.isdir(icd_dir):
        for n in os.listdir(icd_dir):
            extra_files.append(os.path.join(icd_dir, n))
    report = {"interp": interp, "libs": libs, "missing": missing,
              "binary": binpath, "total_bytes": total,
              "rootfs": ROOTFS, "extra_files": extra_files}
    with open(os.path.join(OUT, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(f"  отчёт: {os.path.join(OUT, 'report.json')}")
    print(f"  CACHYOS_ROOT={ROOTFS}")
    if missing:
        sys.exit(2)


if __name__ == "__main__":
    main()
