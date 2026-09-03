#!/usr/bin/env python3
# ============================================================================
# drm-smoke-e2e.py — smoke-прогон CDD №10 p1: бут + drmBootInit + drm/drmtest
# ============================================================================
# Проверяет: [DRM] PAT WC, [VIRTIO-GPU] probe (portable-QEMU без virtio-gpu
# → честное «no device»: probe-путь безопасен), регистрацию /dev/fb0 +
# /dev/dri/card0, полный [DRMTEST] ALL PASS, отсутствие CPU EXCEPTION /
# kernel-panic. Dumb-KMS НЕ требует GPU-железа — весь цикл верифицируем.
# ============================================================================
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal

PASS = []
FAIL = []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)

vm = VM("drm-smoke", initrd=build_cpio({"README.txt": b"poler drm smoke"}), mem="256M")
try:
    vm.start()
    t = vm.wait_for("[DRM] /dev/fb0 + /dev/dri/card0 registered", timeout=90)
    if t is None:
        check("boot: DRM registration marker", False)
    else:
        check("boot: [DRM] PAT programmed WC", "[DRM] PAT programmed" in t)
        check("boot: GPU probe line present", "[VIRTIO-GPU]" in t)
        # portable-QEMU собран без virtio-gpu-device: probe ОБЯЗАН безопасно
        # вернуть «нет устройства» (kernel жив) — верификация probe-пути
        check("boot: probe safe miss (no gpu in portable build)", "no device (expected" in t)
        check("boot: no fatal markers", not check_fatal(vm))

        vm.type_cmd("drm")
        t2 = vm.wait_for("caps: VERSION", timeout=30)
        check("drm cmd: status dump", t2 is not None and "no virtio-gpu" in vm.text())

        vm.type_cmd("drmtest")
        t3 = vm.wait_for("[DRMTEST] ALL PASS", timeout=60)
        check("drmtest: ALL PASS", t3 is not None)
        if t3:
            check("drmtest: pattern render+readback", "pattern ok" in t3)
            check("drmtest: no fatal markers", not check_fatal(vm))
finally:
    vm.stop()

print("\n=== DRM SMOKE: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
