#!/usr/bin/env python3
# ============================================================================
# p10-verify.py — CDD №12 p10: живой мониторинг инварианта отсутствия
# физ-алиасинга НА РАБОТАЮЩЕМ gamescope (компиляция шейдеров lvp/LLVM).
#
# Отличие от drm-gamescope-e2e.py: периодический ввод команды "physmap"
# (monitor sendkey → serial → ядро) на каждом этапе жизненного цикла:
#   1. physmap сразу после elfload (ранние mmap/brk/clone);
#   2. physmap каждые N сек (env VERIFY_PERIOD, дефолт 75с) пока идёт
#      компиляция шейдеров — здесь све­жий munmap/DONTNEED/brk-теарdown;
#   3. финальный physmap на краше/флипе.
# ИНВАРИАНТ: [PHYSMAP] RESULT: CLEAN + отсутствие [PMM] DOUBLE-FREE.
# ============================================================================
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal, QEMU_FULL, KERNEL

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CACHE = os.path.join(REPO, "cachyos-root", "drm-gamescope.initrd.cpio")
OUT = os.environ.get("VERIFY_OUT", "/tmp/p10-verify")

# cpio-кеш от drm-gamescope-e2e.py: читаем БЕЗ пересборки (64Б ключ + blob).
# p10-ФИКС OOM: копируем ПОТОКОМ (не держим blob в RAM — эмпирика verify2:
# python3 3.6ГБ RSS → OOM-килер убивал и python, и осиротевший QEMU).
# p10-ФИКС ПОРЯДКА: конструктор VM с initrd=b"" ТРАНКЕЙТИТ файл — копию
# делаем ПОСЛЕ конструктора (эмпирика verify3: пустой initrd → «No initrd
# modules loaded» → elfload «File not found»).
CACHE_COPY = "/tmp/p10-initrd-copy.cpio"
import shutil as _sh
with open(CACHE, "rb") as f:
    f.seek(64)
    with open(CACHE_COPY, "wb") as out:
        _sh.copyfileobj(f, out, 1024 * 1024)
print(f"[p10-verify] initrd из кеша: {os.path.getsize(CACHE_COPY)/1024/1024:.1f} МБ")

os.makedirs(OUT, exist_ok=True)

vm = VM("p10-verify", initrd=b"", mem=os.environ.get("E2E_MEM", "2G"),
        qemu=QEMU_FULL,
        extra_args=["-cpu", "max", "-vga", "none",
                    "-device", "virtio-gpu-pci,xres=1024,yres=768", "-vnc", ":0"])
# копия ПОСЛЕ конструктора: перезаписываем транкейтнутый файл кеша
with open(CACHE_COPY, "rb") as src, open(vm.initrd_path, "wb") as dst:
    _sh.copyfileobj(src, dst, 1024 * 1024)
os.unlink(CACHE_COPY)
try:
    # p10-ФИКС: serial.log append-режим — маркеры прошлых прогонов в text()
    # давали ЛОЖНЫЙ crash-детект («CPU EXCEPTION» от прошлой сессии).
    open(vm.ser_log_path, "wb").close()
    vm.start()
    # p10-ФИКС МАРКЕРА: ядро печатает «=== POLER-OS ... Interactive Shell»;
    # «Shell started» в drm-gamescope-e2e ловился только фолбэком [EVDEV].
    t = vm.wait_for("Interactive Shell", timeout=int(os.environ.get("E2E_BOOT_TIMEOUT", "300"))) or \
        vm.wait_for("[EVDEV]", timeout=15)
    if t is None:
        print("[p10-verify] FATAL: бут не завершён")
        sys.exit(1)
    print("[p10-verify] shell готов, старт gamescope")
    vm.type_cmd("ltrace")
    vm.type_cmd("elfload usr/bin/gamescope -W 1024 -H 768")

    period = int(os.environ.get("VERIFY_PERIOD", "75"))
    drill = int(os.environ.get("E2E_DRILL", "900"))
    physmap_count = 0
    scans_clean = 0
    scans_dirty = 0
    outcome = "timeout"
    deadline = time.time() + drill
    last_physmap = time.time()
    while time.time() < deadline:
        t = vm.text()
        if "CPU EXCEPTION" in t or "Fatal" in t:
            outcome = "crash"
            break
        if "page_flip" in t.lower() or "vblank" in t.lower():
            outcome = "flip"
            break
        if vm.proc and vm.proc.poll() is not None:
            outcome = "qemu-died"
            break
        if time.time() - last_physmap >= period:
            vm.type_cmd("physmap")
            physmap_count += 1
            last_physmap = time.time()
            # сразу классифицируем последний скан
            time.sleep(3.0)
            t = vm.text()
            res = re.findall(r"\[PHYSMAP\] RESULT: (.+)", t)
            if res:
                if "CLEAN" in res[-1]:
                    scans_clean += 1
                else:
                    scans_dirty += 1
                print(f"[p10-verify] physmap #{physmap_count}: {res[-1].strip()}")
            if "[PMM] DOUBLE-FREE" in t:
                print("[p10-verify] !!! PMM DOUBLE-FREE детектирован в живом прогоне")
        time.sleep(1.0)

    # финальный скан на месте события
    vm.type_cmd("physmap")
    physmap_count += 1
    time.sleep(5.0)
    text = vm.text()

    # краш-дамп должен допечататься
    if outcome == "crash":
        d = time.time() + 45
        while time.time() < d:
            t = vm.text()
            if "User process killed" in t or "Kernel fault" in t:
                break
            if vm.proc and vm.proc.poll() is not None:
                break
            time.sleep(2.0)

    text = vm.text()
    with open(os.path.join(OUT, "serial-full.log"), "w") as f:
        f.write(text)

    results = re.findall(r"\[PHYSMAP\] RESULT: (.+)", text)
    aliases = re.findall(r"\[PHYSMAP\] (ANON|MIXED)-ALIAS[^\n]*", text)
    dfs = re.findall(r"\[PMM\] DOUBLE-FREE[^\n]*", text)
    rips = re.findall(r"RIP=0x[0-9A-Fa-f]+ \(([^)]+)\)", text)
    exc = re.findall(r"!!! CPU EXCEPTION !!![\s\S]{0,400}", text)

    print(f"\n=== P10-VERIFY ИТОГ (outcome={outcome}) ===")
    print(f"physmap-сканов: {physmap_count} (clean={scans_clean} dirty={scans_dirty})")
    print(f"ALIAS-события: {len(aliases)}")
    for a in aliases[:10]:
        print("  " + a)
    print(f"DOUBLE-FREE события: {len(dfs)}")
    for a in dfs[:10]:
        print("  " + a)
    print(f"RIP-атрибyции: {rips[:6]}")
    print("Последний PHYSMAP-результат: " + (results[-1].strip() if results else "нет сканов"))
    if exc:
        print("--- фрагмент краша ---")
        print(exc[0][:400])
    ok = (len(aliases) == 0 and len(dfs) == 0 and
          results and "CLEAN" in results[-1])
    print("P10-VERIFY: " + ("PASS — инвариант держится" if ok else "FAIL — алиасинг жив"))
    sys.exit(0 if ok else 2)
finally:
    try:
        vm.stop()
    except Exception:
        pass
