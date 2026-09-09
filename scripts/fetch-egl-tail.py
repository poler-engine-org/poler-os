#!/usr/bin/env python3
# ============================================================================
# fetch-egl-tail.py — CDD #15 p5: хвост EGL-волны Xwayland (glamor/epoxy)
# run9 показал: Xwayland abort от libepoxy — «Couldn't open libEGL.so.1».
# libgallium (DT_NEEDED libEGL_mesa) тянет libdrm_amdgpu/libdrm_intel,
# которым нужны libpciaccess / libelf / libsensors — их в rootfs НЕТ.
# Скрипт докачивает ровно эти 3 пакета, идемпотентен.
# ============================================================================
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "fcr", os.path.join(os.path.dirname(os.path.abspath(__file__)), "fetch-cachyos-root.py"))
fcr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fcr)

# индекс репо (кэшировать нельзя — индексы в памяти умирают с процессом)
idx_map = {}
for url in fcr.REPOES:
    try:
        idx_map[url] = fcr.repo_index(url)
        print(f"  {url.split('//')[-1][:52]}: {len(idx_map[url])}")
    except Exception as e:
        print(f"  WARN {url}: {e}")

for pkg in ("libpciaccess", "libelf", "lm_sensors"):
    fn = fcr.ensure_pkg(idx_map, pkg)
    print(f"  {pkg}: {'OK ' + fn if fn else 'НЕ НАЙДЕН'}")

# верификация хвоста
for soname in ("libpciaccess.so.0", "libelf.so.1", "libsensors.so.5"):
    p = os.path.join(fcr.ROOTFS, "usr/lib", soname)
    print(f"  {soname}: {'ЕСТЬ ' + str(os.path.getsize(os.path.realpath(p))//1024) + 'K' if os.path.exists(p) else 'НЕТ'}")
