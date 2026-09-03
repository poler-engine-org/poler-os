#!/usr/bin/env python3
# ============================================================================
# ldev-smoke-e2e.py — smoke-прогон CDD №10 p3: Linux POSIX графический слой
# ============================================================================
# Проверяет: [LDEVTEST] ALL PASS — полный цикл через fd-таблицу:
# write/openat/ioctl(DRM+evdev)/read/poll/epoll/futex/close,
# отсутствие CPU EXCEPTION / kernel-panic.
# ============================================================================
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal

PASS = []
FAIL = []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)

vm = VM("ldev-smoke", initrd=build_cpio({"README.txt": b"poler ldev smoke"}), mem="256M")
try:
    vm.start()
    t = vm.wait_for("Shell started", timeout=90) or vm.wait_for("[EVDEV]", timeout=60)
    if t is None:
        check("boot: shell ready", False)
    else:
        check("boot: no fatal markers", not check_fatal(vm))

        vm.type_cmd("ldevtest")
        t3 = vm.wait_for("[LDEVTEST] ALL PASS", timeout=90)
        check("ldevtest: ALL PASS", t3 is not None)
        if t3:
            check("ldevtest: openat card0 + event0", "openat /dev/dri/card0" in t3 and "openat /dev/input/event0" in t3)
            check("ldevtest: DRM ioctl cycle", "ADDFB + PAGE_FLIP ok" in t3)
            check("ldevtest: evdev EVIOCGVERSION", "EVIOCGVERSION ok" in t3)
            check("ldevtest: live input_event read", "live events" in t3)
            check("ldevtest: poll POLLOUT", "poll ok: card0 POLLOUT" in t3)
            check("ldevtest: epoll trio", "epoll create+ctl+wait ok" in t3)
            check("ldevtest: futex semantics", "futex WAIT/WAKE/EAGAIN" in t3)
            check("ldevtest: close lifecycle", "close lifecycle ok" in t3)
            check("ldevtest: no fatal markers", not check_fatal(vm))

        # клавиатура жива после самотеста
        vm.type_cmd("drm")
        t4 = vm.wait_for("caps: VERSION", timeout=30)
        check("kbd alive after test (drm responds)", t4 is not None)
finally:
    vm.stop()

print("\n=== LDEV SMOKE: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
