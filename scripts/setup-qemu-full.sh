#!/bin/bash
# ============================================================================
# setup-qemu-full.sh — полный QEMU для E2E (virtio-gpu) без root
# ============================================================================
# Portable-QEMU (qemu-portable/) собран БЕЗ virtio-gpu. Полный Debian QEMU
# ставится deb-распаковкой (без установки): qemu-system-x86 + data + common
# (модули hw-display-virtio-gpu*.so) + зависимости-libs.
# Результат: qemu-full/ (gitignored), запуск через qemu-full/qemu-full.sh.
# ============================================================================
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
OUT="$DIR/qemu-full"
mkdir -p "$OUT"
cd "$OUT"

if [ -x "$OUT/usr/bin/qemu-system-x86_64" ] && "$OUT/qemu-full.sh" -device virtio-gpu-pci,help >/dev/null 2>&1; then
    echo "qemu-full уже установлен: $(qemu-full.sh --version 2>/dev/null | head -1)"
    exit 0
fi

echo "[1/3] Загрузка deb-пакетов (без установки — только распаковка)…"
apt-get download \
    qemu-system-x86 qemu-system-data qemu-system-common \
    libpmem1 libvdeplug2t64 libaio1t64 libndctl6 libdaxctl1 \
    libcapstone5 libfdt1 libibverbs1 librdmacm1t64 libslirp0 \
    libfuse3-4 liburing2 libnl-3-200 libnl-route-3-200 \
    libkmod2 libzstd1 liblzma5 libpixman-1-0 2>/dev/null || true

echo "[2/3] Распаковка…"
for d in *.deb; do [ -f "$d" ] && dpkg -x "$d" "$OUT" 2>/dev/null || true; done

cat > "$OUT/qemu-full.sh" << 'WRAP'
#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
export QEMU_MODULE_DIR="$DIR/usr/lib/x86_64-linux-gnu/qemu"
export LD_LIBRARY_PATH="$DIR/usr/lib/x86_64-linux-gnu:$QEMU_MODULE_DIR"
exec "$DIR/usr/bin/qemu-system-x86_64" -L "$DIR/usr/share/qemu" "$@"
WRAP
chmod +x "$OUT/qemu-full.sh"

echo "[3/3] Проверка virtio-gpu…"
if "$OUT/qemu-full.sh" -device virtio-gpu-pci,help >/dev/null 2>&1; then
    echo "OK: $(qemu-full.sh --version 2>/dev/null | head -1) — virtio-gpu доступен"
else
    echo "FAIL: virtio-gpu недоступен — проверь распаковку"
    exit 1
fi
