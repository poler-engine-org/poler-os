#!/usr/bin/env python3
# ============================================================================
# gpu-scanout-e2e.py — E2E-прогон CDD №11 p2: VRING SCAN-OUT на дисплей
# ============================================================================
# Полный QEMU (qemu-full, virtio-gpu) + VNC-дисплей (скан-ауты включены):
#   1. Бут → [VIRTIO-GPU] vring INIT OK + GET_DISPLAY_INFO (геометрия от
#      устройства, не дефолт!)
#   2. gputest → [GPUTEST] ALL PASS (CREATE_2D/ATTACH/TRANSFER/SET_SCANOUT/
#      FLUSH через virtqueue)
#   3. QEMU-monitor screendump → PPM → ПИКСЕЛЬНАЯ верификация паттерна
#      (полосы 64px: R=0xC7/0x07 в зависимости от координат)
# ============================================================================
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal, QEMU_FULL, KERNEL

PASS = []
FAIL = []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)


def parse_ppm_pixels(path):
    """PPM P6 → (width, height, байты RGB). None при ошибке формата."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if data[:2] != b"P6":
        return None
    # заголовок: P6\n<w> <h>\n<max>\n<binary>
    parts = data.split(b"\n", 3)
    if len(parts) < 4:
        return None
    try:
        w, h = parts[1].split()
        w, h = int(w), int(h)
    except ValueError:
        return None
    return (w, h, parts[3])


if not os.path.exists(QEMU_FULL):
    print("FATAL: qemu-full отсутствует — запусти scripts/setup-qemu-full.sh")
    sys.exit(1)
if not os.path.exists(KERNEL):
    print("FATAL: ядро не собрано — zig build")
    sys.exit(1)

vm = VM(
    "gpu-scanout",
    initrd=build_cpio({"README.txt": b"poler gpu scanout"}),
    mem="256M",
    qemu=QEMU_FULL,
    display=None,  # -vnc :0 вместо -display (скан-ауты включены)
    # -vga none: virtio-gpu = ЕДИНСТВЕННЫЙ дисплей (screendump берёт его,
    # а не дефолтную VGA-консоль 720×400)
    extra_args=["-vga", "none", "-device", "virtio-gpu-pci,xres=1024,yres=768", "-vnc", ":0"],
)
try:
    vm.start()
    t = vm.wait_for("Shell started", timeout=90) or vm.wait_for("[EVDEV]", timeout=60)
    if t is None:
        check("boot: shell ready", False)
    else:
        check("boot: no fatal markers", not check_fatal(vm))

        # 1. vring-инициализация в буте
        t1 = vm.wait_for("vring INIT OK", timeout=30)
        check("vring: device init (DRIVER_OK, queue)", t1 is not None)
        if t1:
            check("vring: GET_DISPLAY_INFO roundtrip", "GET_DISPLAY_INFO: scanout" in t1)
            check("vring: scanout 1024x768 enabled", "scanout 1024x768 enabled" in t1)

        # 2. gputest — 2D-конвейер
        vm.type_cmd("gputest")
        t2 = vm.wait_for("[GPUTEST] ALL PASS", timeout=60)
        check("gputest: 2D pipeline (5 команд vring)", t2 is not None)
        if t2:
            check("gputest: pattern rendered", "pattern 1024x768" in t2)
            check("gputest: no fatal markers", not check_fatal(vm))

        # 3. screendump → пиксельная верификация
        dump_path = os.path.join(vm.workdir, "dump.ppm")
        if os.path.exists(dump_path):
            os.unlink(dump_path)  # старый дамп предыдущего прогона
        vm._mon.sendall(("screendump %s\n" % dump_path).encode())
        try:
            vm._mon.recv(4096)
        except Exception:
            pass
        # ждём НОВЫЙ файл
        deadline = time.time() + 15
        while time.time() < deadline and not os.path.exists(dump_path):
            time.sleep(0.3)
        if os.path.exists(dump_path):
            img = parse_ppm_pixels(dump_path)
            if img:
                w, h, rgb = img
                check("screendump: размер 1024x768", (w, h) == (1024, 768))
                # полосы 64px: (x/64 + y/64) % 2 → цвет A (R=0xC7,G=0x5B,B=0x12) / B (R=0x07,G=0x11,B=0x20)
                ok_a = ok_b = alt = True
                probes = [(100, 100, 0), (100 + 64, 100, 1), (512, 512, 0), (576, 512, 1)]
                for px, py, want_stripe in probes:
                    off = (py * w + px) * 3
                    r, g, b = rgb[off], rgb[off + 1], rgb[off + 2]
                    expect_a = ((px // 64) + (py // 64)) % 2 != 0
                    if want_stripe != (((px // 64) + (py // 64)) % 2):
                        pass
                    if expect_a:
                        if not (r == 0xC7 and g == 0x5B and b == 0x12):
                            ok_a = False
                    else:
                        if not (r == 0x07 and g == 0x11 and b == 0x20):
                            ok_b = False
                check("screendump: пиксели полос A (0xC75B12)", ok_a)
                check("screendump: пиксели полос B (0x12071120)", ok_b)
            else:
                check("screendump: PPM парсинг", False)
        else:
            check("screendump: файл создан", False)

        # клавиатура/шелл живы
        vm.type_cmd("drm")
        t4 = vm.wait_for("caps: VERSION", timeout=30)
        check("shell alive after gputest", t4 is not None)
finally:
    vm.stop()

print("\n=== GPU-SCANOUT: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
