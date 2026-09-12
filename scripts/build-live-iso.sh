#!/usr/bin/env bash
# ============================================================================
# build-live-iso.sh — POLER-OS Live-USB builder (v0.19.0, CDD №10 p4)
# ============================================================================
#
# НАЗНАЧЕНИЕ: сборка Live-USB образа POLER-OS (дуальный нативный дистрибутив):
# ядро на Zig грузит Live-сессию с USB-флешки — БЕЗ установки на жёсткий диск.
#
# СТРУКТУРА ОБРАЗА (артефакты build/):
#   live-initrd.cpio — CPIO-initrd: структура /dev /proc /sys /usr /tmp +
#                      LIVE-MANIFEST (что монтирует VFS Live-режима) +
#                      (опционально) юзерспейс-пакеты CachyOS;
#   live-usb.img     — FAT32-образ «USB-флешки»: ядро + манифест + RW-зона
#                      (ядро монтирует FAT32 через virtio-blk — fat32.zig
#                      v0.17: RW-файлы, ls/cat/write);
#   poler-os64.iso   — GRUB-ISO (если есть grub-mkrescue) — загрузка на
#                      реальном железе с USB/CD (multiboot2 + VBE-фреймбуфер
#                      → DRM linear-fb скан-аут).
#
# LIVE-МОДЕЛЬ ДАННЫХ (tmpfs overlay — «запись в RAM, чтение с USB»):
#   /dev/**   → devfs: fb0, dri/card0, input/event0,1 (fd-слой Linux);
#   /tmp/**   → tmpfs: RAM-записи (сессия, конфиги);
#   остальное → initrd-RO: пакеты/конфиги (чтение с «USB»).
#
# CACHYOS-ЮЗЕРСПЕЙС (топ-даун CDD): готовые бинарники экосистемы Arch
# x86-64-v3/v4 (Gamescope-микрокомпозитор, Wayland-сессия, KWin/Plasma,
# Mesa llvmpipe/virtio-gpu) кладутся в initrd/FAT32 из $CACHYOS_ROOT
# (распакованный squashfs или tarball rootfs). Запуск: ядро перехватывает
# краш-логи недостающих сисколлов/ioctl и реализует их по горячим следам
# (CDD №11+). SquashFS-ридер ядра — v0.20-бэклог; пока rootfs пакуется в
# CPIO/FAT32.
#
# ЗАПУСК (QEMU):
#   ./build-live-iso.sh --run          # графический дисплей (-vga std)
#   ./build-live-iso.sh --run-gpu      # virtio-gpu-pci (если QEMU собран с ним)
#   ./build-live-iso.sh --run-serial   # headless (serial-консоль, e2e-режим)
# ============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_DIR="$REPO/zig-kernel"
BUILD="$REPO/build"
KERNEL="$KERNEL_DIR/zig-out/bin/poler-os64"
QEMU="$REPO/qemu-portable/qemu-portable.sh"

echo "=== POLER-OS Live-USB builder (CDD #10 p4) ==="

# ─── 1. Ядро ────────────────────────────────────────────────────────────────
echo "[1/4] Building kernel (zig build)..."
( cd "$KERNEL_DIR" && zig build )
test -f "$KERNEL" || { echo "FATAL: kernel not built"; exit 1; }
echo "      kernel: $(du -h "$KERNEL" | cut -f1) — $KERNEL"

mkdir -p "$BUILD"

# python-хелперам нужны пути через окружение
export REPO BUILD KERNEL

# ─── 2. CPIO-initrd: структура Live-сессии + манифест ───────────────────────
echo "[2/4] Building live-initrd.cpio (Live-структура + манифест + userspace)..."
python3 "$REPO/scripts/pack-initrd.py"

# ─── 3. FAT32 «USB-флешка»: ядро + манифест + RW-зона ──────────────────────
echo "[3/4] Building live-usb.img (FAT32, RW-зона Live-сессии)..."
REPO="$REPO" BUILD="$BUILD" KERNEL="$KERNEL" python3 <<'PYEOF'
import os, struct, sys
REPO = os.environ["REPO"]
sys.path.insert(0, os.path.join(REPO, "scripts", "e2e"))
from e2e_lib import build_fat32

# базовый том: 32МБ FAT32 (валиден по fat32.zig validateBpb)
total_sectors = 65536  # 32МБ
img = bytearray(build_fat32(total_sectors=total_sectors, spc=8, reserved=32))
bps = 512
spc = 8
fat_size = 0
# пересчитаем геометрию как в build_fat32
num_fats = 2
fat_size = 64
for _ in range(8):
    data_sectors = total_sectors - 32 - num_fats * fat_size
    data_clusters = data_sectors // spc
    need_bytes = (data_clusters + 2) * 4
    fat_new = (need_bytes + bps - 1) // bps
    if fat_new == fat_size:
        break
    fat_size = fat_new
data_start = 32 + num_fats * fat_size
data_clusters = (total_sectors - data_start) // spc

def wr32(off, v): struct.pack_into("<I", img, off, v)

# FAT-цепь для кластера n длиной L (последовательные кластеры)
def fat_chain(first, length):
    for c in range(first, first + length - 1):
        wr32(32 * bps + c * 4, c + 1)
    wr32(32 * bps + (first + length - 1) * 4, 0x0FFFFFF8)

# 8.3-имя файла
def put_root_entry(idx, name11, first_clu, size):
    off = data_start * bps - 32 * 16 + idx * 32  # root dir = кластер 2
    off = (32 + num_fats * fat_size) * bps + (idx) * 32  # корень — перед data? нет:
    # root dir живёт В data-зоне (кластер 2); entry 0 = смещение кластера 2
    off = data_start * bps + idx * 32
    img[off:off + 11] = name11
    img[off + 11] = 0x20  # attrs: archive
    struct.pack_into("<H", img, off + 20, 0)      # high clu
    struct.pack_into("<H", img, off + 26, first_clu)
    struct.pack_into("<I", img, off + 28, size)

# файлы USB: ядро (копия) + манифест
files = []
kpath = os.environ["KERNEL"]
with open(kpath, "rb") as f:
    files.append(("POLEROS.KRN", f.read()))
manifest = b"POLER-OS LIVE-USB v0.19.0: FAT32 RW-zone (fat32.zig mount, write via kernel)\n"
files.append(("LIVE.MAN", manifest))

first_free = 3  # кластеры 0-2 — служебные/root
for i, (name, data) in enumerate(files):
    clus = (len(data) + spc * bps - 1) // (spc * bps)
    if clus == 0:
        clus = 1
    fat_chain(first_free, clus)
    off = data_start * bps + (first_free - 2) * spc * bps
    img[off:off + len(data)] = data
    put_root_entry(i, name.encode(), first_free, len(data))
    first_free += clus

out = os.path.join(os.environ["BUILD"], "live-usb.img")
with open(out, "wb") as f:
    f.write(bytes(img))
print(f"      usb-img: {os.path.getsize(out)} bytes, {len(files)} files (POLEROS.KRN, LIVE.MAN)")
PYEOF

# ─── 4. GRUB-ISO (если инструменты есть) ────────────────────────────────────
echo "[4/4] GRUB ISO (optional)..."
if command -v grub-mkrescue >/dev/null 2>&1 && command -v xorriso >/dev/null 2>&1; then
    rm -rf "$BUILD/iso"
    mkdir -p "$BUILD/iso/boot/grub"
    cp "$KERNEL" "$BUILD/iso/boot/poler-os64"
    cp "$BUILD/live-initrd.cpio" "$BUILD/iso/boot/live-initrd.cpio"
    cp "$KERNEL_DIR/iso/boot/grub/grub.cfg" "$BUILD/iso/boot/grub/grub.cfg"
    ( cd "$BUILD" && grub-mkrescue -o poler-os64.iso iso ) >/dev/null 2>&1 \
        && echo "      iso: $BUILD/poler-os64.iso ($(du -h "$BUILD/poler-os64.iso" | cut -f1))" \
        || echo "      iso: SKIP (grub-mkrescue failed)"
else
    echo "      iso: SKIP (нет grub-mkrescue/xorriso — QEMU-режимы работают через -kernel)"
fi

# ─── Готово: инструкции запуска ─────────────────────────────────────────────
echo ""
echo "=== Live-USB готов: $BUILD ==="
echo "  Артефакты: live-initrd.cpio, live-usb.img (+ iso, если собран)"
echo "  Запуск:"
echo "    $0 --run         # QEMU -vga std (графика через VBE/DRM linear-fb)"
echo "    $0 --run-gpu     # QEMU virtio-gpu-pci (probe 0x1050)"
echo "    $0 --run-serial  # headless serial (e2e)"
echo ""

case "${1:-}" in
    --run)
        exec "$QEMU" -kernel "$KERNEL" -m 512M \
            -initrd "$BUILD/live-initrd.cpio" \
            -drive "file=$BUILD/live-usb.img,if=virtio,format=raw" \
            -vga std -serial stdio -no-reboot
        ;;
    --run-gpu)
        exec "$QEMU" -kernel "$KERNEL" -m 512M \
            -initrd "$BUILD/live-initrd.cpio" \
            -drive "file=$BUILD/live-usb.img,if=virtio,format=raw" \
            -device virtio-gpu-pci -serial stdio -no-reboot
        ;;
    --run-serial)
        exec "$QEMU" -kernel "$KERNEL" -m 512M \
            -initrd "$BUILD/live-initrd.cpio" \
            -drive "file=$BUILD/live-usb.img,if=virtio,format=raw" \
            -nographic -no-reboot
        ;;
esac
