#!/usr/bin/env python3
# ============================================================================
# live-boot-e2e.py — Live-USB загрузочный прогон CDD №10 p4
# ============================================================================
# Бутит ПОЛНЫЙ Live-стек (артефакты scripts/build-live-iso.sh):
#   ядро + live-initrd.cpio (структура /dev /proc /sys /usr /tmp + манифест)
#   + live-usb.img (FAT32 «USB-флешка» с POLEROS.KRN + LIVE.MAN).
# Проверяет: VFS Live-mode, FAT32-монтирование USB, ls RW-зоны,
# ldevtest ALL PASS (включая initrd-RO чтение + tmpfs-RAM запись),
# запись файла на USB (cmd write), отсутствие паник.
# ============================================================================
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, check_fatal

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BUILD = os.path.join(REPO, "build")

PASS = []
FAIL = []

def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)

# артефакты Live-USB (сборщик уже отработал)
with open(os.path.join(BUILD, "live-initrd.cpio"), "rb") as f:
    INITRD = f.read()
with open(os.path.join(BUILD, "live-usb.img"), "rb") as f:
    USB = f.read()

vm = VM("live-boot", initrd=INITRD, disk=USB, mem="512M")
try:
    vm.start()
    # ждём ПОЛНЫЙ бут (VFS/DRM/EVDEV печатаются ПОСЛЕ монтирования FAT32)
    t = vm.wait_for("Interactive Shell", timeout=90)
    if t is None:
        check("boot: shell ready", False)
    else:
        t = vm.text()
        check("boot: FAT32 USB mounted (live-usb.img)", "[FAT32] Filesystem mounted" in t)
        check("boot: [VFS] Live-mode marker", "[VFS] Live-mode VFS" in t)
        check("boot: [DRM] + [EVDEV] live stack", "[DRM] /dev/fb0" in t and "[EVDEV] /dev/input/event0" in t)
        check("boot: no fatal markers", not check_fatal(vm))

        # ls RW-зоны USB: ядро печатает 8.3-имена lowercase
        vm.type_cmd("ls")
        t2 = vm.wait_for("poleros", timeout=30)
        check("ls: USB-файлы видны (poleros.krn)", t2 is not None)
        if t2:
            check("ls: live.man виден", "live.man" in t2)

        # запись на USB (RW-зона — fat32.zig)
        vm.type_cmd("write live.txt POLER-LIVE-USB-RW")
        t3 = vm.wait_for("Wrote 17 bytes", timeout=30)
        check("write: файл на USB записан", t3 is not None)
        vm.type_cmd("cat live.txt")
        t4 = vm.wait_for("POLER-LIVE-USB-RW", timeout=30)
        check("cat: roundtrip с USB", t4 is not None)

        # полный Linux-слой самотест (включая initrd-RO + tmpfs-RAM)
        vm.type_cmd("ldevtest")
        t5 = vm.wait_for("[LDEVTEST] ALL PASS", timeout=90)
        check("ldevtest: ALL PASS", t5 is not None)
        if t5:
            check("ldevtest: initrd-RO (чтение с USB)", "initrd-RO" in t5)
            check("ldevtest: tmpfs-RAM roundtrip", "tmpfs-RAM" in t5)
            check("ldevtest: no fatal markers", not check_fatal(vm))
finally:
    vm.stop()

print("\n=== LIVE-BOOT: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
