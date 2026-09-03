#!/usr/bin/env python3
# ============================================================================
# input-smoke-e2e.py — smoke-прогон CDD №10 p2: evdev /dev/input/event0,1
# ============================================================================
# Проверяет: [EVDEV] регистрацию устройств, PS/2-мини (или safe-miss),
# ЖИВЫЕ клавиатурные события (набор команд через monitor sendkey прошёл
# через PS/2 → IRQ1 → evdev-очередь), inputtest ALL PASS, отсутствие паник.
# ============================================================================
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal

PASS = []
FAIL = []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)

vm = VM("input-smoke", initrd=build_cpio({"README.txt": b"poler input smoke"}), mem="256M")
try:
    vm.start()
    t = vm.wait_for("Shell started", timeout=90)
    if t is None:
        # fallback: ждём приглашение по маркеру загрузки
        t = vm.wait_for("[EVDEV] /dev/input/event0", timeout=60)
    if t is None:
        check("boot: EVDEV registration marker", False)
    else:
        check("boot: [EVDEV] devices registered", "[EVDEV] /dev/input/event0" in t)
        check("boot: PS2-mouse line present", "[PS2-MOUSE]" in t)
        check("boot: no fatal markers", not check_fatal(vm))

        vm.type_cmd("input")
        t2 = vm.wait_for("[INPUT] /dev/input/event1", timeout=30)
        check("input cmd: status dump", t2 is not None)

        vm.type_cmd("inputtest")
        t3 = vm.wait_for("[INPUTTEST] ALL PASS", timeout=60)
        check("inputtest: ALL PASS", t3 is not None)
        if t3:
            check("inputtest: live PS/2 keys captured", "live events (PS/2" in t3)
            check("inputtest: letters t/e validated", "letters 't'/'e' seen" in t3)
            check("inputtest: EAGAIN semantics", "-EAGAIN ok" in t3)
            check("inputtest: mouse roundtrip", "REL_X=7 REL_Y=-3" in t3)
            check("inputtest: no fatal markers", not check_fatal(vm))

        # клавиатура по-прежнему жива после inputtest (дренаж очереди
        # не сломал PS/2-путь): команда echo-подтверждение
        vm.type_cmd("drm")
        t4 = vm.wait_for("caps: VERSION", timeout=30)
        check("kbd alive after test (drm responds)", t4 is not None)
finally:
    vm.stop()

print("\n=== INPUT SMOKE: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
