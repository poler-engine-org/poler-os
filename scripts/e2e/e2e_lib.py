#!/usr/bin/env python3
# ============================================================================
# e2e_lib.py — E2E-инфраструктура POLER-OS (восстановлено для CDD №9, v0.18.0)
# ============================================================================
# Компоненты:
#   1. build_cpio()   — initrd newc-архив (ядро: cpio.zig, magic 070701/070702)
#   2. build_fat32()  — пустой FAT32-образ для VirtIO-Blk (fat32.zig: BPB 512/
#                       spc=2^k/Reserved>0/FatSize32>0/RootCluster>=2)
#   3. class VM       — QEMU-драйвер: serial через unix-socket (полный duplex),
#                       ввод команд через monitor sendkey (PS/2 → kbd_push →
#                       syscall #2), ожидание маркеров в serial-логе.
#
# Сеть: SLIRP user-mode (ядро статически 10.0.2.15, gw 10.0.2.2, DNS 10.0.2.3).
# ============================================================================

import os
import socket
import struct
import subprocess
import threading
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
KERNEL = os.environ.get("POLER_KERNEL") or os.path.join(
    REPO, "zig-kernel", "zig-out", "bin", "poler-os64")
QEMU = os.path.join(REPO, "qemu-portable", "qemu-portable.sh")
TESTDATA = os.path.join(REPO, "zig-kernel", "testdata")


# ─── 1. CPIO newc-билдер ────────────────────────────────────────────────────

def build_cpio(files):
    """files: dict[name(str) → bytes]. Возвращает newc-архив ( padded 512 )."""
    out = bytearray()

    def put_entry(name: bytes, data: bytes, mode: int):
        out.extend(b"070701")
        fields = [0, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0]
        for f in fields:
            out.extend(b"%08X" % f)
        out.extend(name + b"\0")
        while len(out) % 4:
            out.append(0)
        out.extend(data)
        while len(out) % 4:
            out.append(0)

    for name, data in files.items():
        put_entry(name.encode(), data, 0o100644)
    put_entry(b"TRAILER!!!", b"", 0)
    while len(out) % 512:
        out.append(0)
    return bytes(out)


# ─── 2. FAT32-билдер (пустой том) ───────────────────────────────────────────

def build_fat32(total_sectors=65536, spc=8, reserved=32):
    """Пустой FAT32-том: BPB + 2 FAT + пустой root-кластер (2).
    Валиден по validateBpb(): 512Б/сектор, spc=2^k, Reserved>0, FatSize32>0,
    RootCluster>=2."""
    bps = 512
    num_fats = 2
    # итеративно сходить к fat_size (entries = data_clusters + 2)
    fat_size = 64
    for _ in range(8):
        data_sectors = total_sectors - reserved - num_fats * fat_size
        data_clusters = data_sectors // spc
        need_bytes = (data_clusters + 2) * 4
        fat_size_new = (need_bytes + bps - 1) // bps
        if fat_size_new == fat_size:
            break
        fat_size = fat_size_new
    data_start = reserved + num_fats * fat_size
    data_clusters = (total_sectors - data_start) // spc

    img = bytearray(total_sectors * bps)

    def wr8(off, v): img[off] = v & 0xFF
    def wr16(off, v): struct.pack_into("<H", img, off, v)
    def wr32(off, v): struct.pack_into("<I", img, off, v)

    # BPB (offsets по спецификации FAT32)
    img[0:3] = b"\xEB\x58\x90"           # jmp
    img[3:11] = b"MSWIN4.1"              # OEM
    wr16(11, bps)                        # bytes/sector
    wr8(13, spc)                         # sectors/cluster
    wr16(14, reserved)                   # reserved sectors
    wr8(16, num_fats)                    # FAT count
    wr16(17, 0)                          # root entries (FAT12/16)
    wr16(19, 0)                          # total sectors 16
    wr8(21, 0xF8)                        # media
    wr16(22, 0)                          # FAT size 16
    wr16(24, 63)                         # sectors/track
    wr16(26, 255)                        # heads
    wr32(28, 0)                          # hidden
    wr32(32, total_sectors)              # total sectors 32
    wr32(36, fat_size)                   # FAT size 32
    wr16(40, 0)                          # ext flags
    wr16(42, 0)                          # fs version
    wr32(44, 2)                          # root cluster
    wr16(48, 1)                          # fsinfo sector
    wr16(50, 6)                          # backup boot sector
    wr8(64, 0x80)                        # drive number
    wr8(66, 0x29)                        # boot signature
    wr32(67, 0x504F4C45)                 # volume id ("POLE")
    img[71:82] = b"NO NAME    "          # label
    img[82:90] = b"FAT32   "             # fs type
    img[510:512] = b"\x55\xAA"

    # FAT[0] = 0x0FFFFFF8 (media), FAT[1] = 0x0FFFFFFF, FAT[2] = EOC (root)
    for fat_n in range(num_fats):
        fat_off = (reserved + fat_n * fat_size) * bps
        wr32(fat_off + 0, 0x0FFFFFF8)
        wr32(fat_off + 4, 0x0FFFFFFF)
        wr32(fat_off + 8, 0x0FFFFFFF)
    # кластер 2 (root dir) — уже нули (пустой каталог)
    _ = data_start
    _ = data_clusters
    return bytes(img)


# ─── 3. VM-драйвер (QEMU + serial unix-socket + monitor sendkey) ────────────

# QEMU key names для sendkey (символ → имя клавиши; uppercase → shift-X)
_KEYMAP = {
    " ": "spc", "-": "minus", ".": "dot", "/": "slash", ";": "semicolon",
    "'": "apostrophe", ",": "comma", "=": "equal", "[": "bracket_left",
    "]": "bracket_right", "\\": "backslash", "`": "grave_accent",
    "\t": "tab", "\n": "ret",
}
_SHIFT_KEYMAP = {
    ":": "semicolon", "?": "slash", "_": "minus", "+": "equal",
    "\"": "apostrophe", "<": "comma", ">": "dot", "~": "grave_accent",
    "{": "bracket_left", "}": "bracket_right", "|": "backslash",
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6",
    "&": "7", "*": "8", "(": "9", ")": "0",
}


class VM:
    def __init__(self, name, initrd, disk=None, mem="256M", timeout=180,
                 extra_args=None, workdir=None):
        self.name = name
        self.workdir = workdir or os.path.join("/tmp", "poler-e2e-" + name)
        os.makedirs(self.workdir, exist_ok=True)
        self.initrd_path = os.path.join(self.workdir, "initrd.cpio")
        with open(self.initrd_path, "wb") as f:
            f.write(initrd)
        self.disk_path = None
        if disk is not None:
            self.disk_path = os.path.join(self.workdir, "disk.img")
            with open(self.disk_path, "wb") as f:
                f.write(disk)
        self.ser_sock_path = os.path.join(self.workdir, "serial.sock")
        self.mon_sock_path = os.path.join(self.workdir, "monitor.sock")
        self.ser_log_path = os.path.join(self.workdir, "serial.log")
        self.proc = None
        self.timeout = timeout
        self.log = bytearray()
        self._lock = threading.Lock()
        self._ser = None
        self._mon = None
        self._extra = extra_args or []
        self.mem_size = mem

    def start(self):
        for p in (self.ser_sock_path, self.mon_sock_path):
            if os.path.exists(p):
                os.unlink(p)
        cmd = [
            QEMU,
            "-kernel", KERNEL,
            "-m", self.mem_size,
            "-initrd", self.initrd_path,
            "-display", "none",
            "-no-reboot",
            # wait=on: QEMU ждёт ПОДКЛЮЧЕНИЕ сокета ДО запуска ВМ — serial-лог
            # с первого байта (ранний бут: PMM/VMM/PCI/VBLK/FAT32 не теряется)
            "-chardev", "socket,id=ser0,path=%s,server=on,wait=on" % self.ser_sock_path,
            "-serial", "chardev:ser0",
            "-monitor", "unix:%s,server,nowait" % self.mon_sock_path,
            "-netdev", "user,id=n0",
            "-device", "virtio-net-pci,netdev=n0",
        ]
        if self.disk_path:
            cmd += ["-drive", "file=%s,if=virtio,format=raw" % self.disk_path]
        cmd += self._extra
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        # подключение к serial (повторные попытки — сокет создаётся асинхронно)
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.ser_sock_path)
                self._ser = s
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.05)
        if self._ser is None:
            raise RuntimeError("serial socket не подключился")
        self._ser.setblocking(False)
        threading.Thread(target=self._reader, daemon=True).start()
        # monitor
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                m = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                m.connect(self.mon_sock_path)
                self._mon = m
                break
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(0.2)
        if self._mon is None:
            raise RuntimeError("monitor socket не подключился")
        self._mon.settimeout(5.0)

    # чтобы argparse-подобная инициализация не путала: mem хранится тут
    mem_size = "256M"

    def _reader(self):
        while True:
            try:
                chunk = self._ser.recv(65536)
                if not chunk:
                    break
                with self._lock:
                    self.log.extend(chunk)
            except BlockingIOError:
                time.sleep(0.05)
            except OSError:
                break

    def text(self):
        with self._lock:
            return bytes(self.log).decode("utf-8", "replace")

    def sendkey(self, keyspec):
        self._mon.sendall(("sendkey %s\n" % keyspec).encode())
        try:
            self._mon.recv(4096)
        except socket.timeout:
            pass

    def type_cmd(self, line, delay=0.035):
        """Печатает строку посимвольно через monitor sendkey + Enter."""
        for ch in line:
            if ch.isupper():
                self.sendkey("shift-" + ch.lower())
            elif ch in _KEYMAP:
                self.sendkey(_KEYMAP[ch])
            elif ch in _SHIFT_KEYMAP:
                self.sendkey("shift-" + _SHIFT_KEYMAP[ch])
            elif ch.isalnum():
                self.sendkey(ch.lower())
            else:
                # неизвестный символ — пропускаем (e2e-строки ASCII-безопасны)
                pass
            time.sleep(delay)
        self.sendkey("ret")
        time.sleep(0.2)

    def wait_for(self, marker, timeout=None):
        """Ждёт появления маркера в serial-логе. Возвращает text() или None."""
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            t = self.text()
            if marker in t:
                return t
            if self.proc and self.proc.poll() is not None:
                break
            time.sleep(0.25)
        return None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self._mon.sendall(b"quit\n")
                time.sleep(1.0)
            except OSError:
                pass
            if self.proc.poll() is None:
                self.proc.kill()
        for s in (self._ser, self._mon):
            try:
                if s:
                    s.close()
            except OSError:
                pass
        with self._lock:
            with open(self.ser_log_path, "wb") as f:
                f.write(bytes(self.log))


# ─── 4. Общие assertion-хелперы прогонов ────────────────────────────────────

FATAL_MARKERS = [
    "CPU EXCEPTION",        # краш кадра/#GP/#PF в ядре
    "FRAME-GUARD",          # защита кадра сработала (v0.17 диагностика)
    "kernel-panic",         # прямой флаг паники
    "PANIC",
    "KERNEL PANIC",
]


def check_fatal(vm):
    """Возвращает список найденных фатальных маркеров (пустой = ОК)."""
    t = vm.text()
    return [m for m in FATAL_MARKERS if m in t]


def load_testfile(name):
    with open(os.path.join(TESTDATA, name), "rb") as f:
        return f.read()
