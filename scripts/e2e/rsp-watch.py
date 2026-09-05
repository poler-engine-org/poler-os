#!/usr/bin/env python3
# ============================================================================
# rsp-watch.py — минимальный GDB Remote Serial Protocol клиент для QEMU-stub.
# CDD №12 p4-final: WHO writes 0xAAAAAAAA into guest memory?
#   1. connect tcp:1234 (QEMU -s)
#   2. interrupt + wait stop
#   3. set WRITE watchpoint (Z2) on target addr (retry until page mapped)
#   4. continue → on trigger: dump RIP + all GPRs + stack scan (ret addrs)
# Usage: python3 rsp-watch.py <addr_hex> [len] [port]
# ============================================================================
import socket
import sys
import time


class Rsp:
    def __init__(self, port=1234, timeout=3.0):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""
        self._neg = False  # протокол QEMU стартует без ack

    def _send(self, raw: bytes):
        self.s.sendall(raw)

    def _recv(self) -> bytes:
        # накопительный разбор пакета $...#xx
        while True:
            if b"#" in self.buf and len(self.buf) >= self.buf.index(b"#") + 3:
                start = self.buf.index(b"$")
                end = self.buf.index(b"#") + 3
                pkt = self.buf[start:end]
                self.buf = self.buf[end:]
                return pkt[1:-3]  # без $ и #cs
            chunk = self.s.recv(4096)
            if not chunk:
                raise ConnectionError("gdb-stub closed")
            self.buf += chunk

    def cmd(self, data: str, wait_reply=True) -> bytes | None:
        payload = data.encode()
        cs = sum(payload) & 0xFF
        pkt = b"$" + payload + b"#%02x" % cs
        self._send(pkt)
        # ack
        self._send(b"+")
        if not wait_reply:
            return None
        # пропускаем ack'и
        while True:
            r = self._recv()
            if r == b"":  # пустой — это был ack-кадр (после '+' QEMU шлёт '+')
                continue
            return r

    def interrupt(self):
        self._send(b"\x03")
        # ждём T05/stop
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                r = self._recv()
            except socket.timeout:
                continue
            if r and (r[0:1] == b"T" or r[0:1] == b"S"):
                return r
        raise TimeoutError("no stop reply after interrupt")

    def read_mem(self, addr: int, length: int) -> bytes | None:
        r = self.cmd("m%x,%x" % (addr, length))
        if r.startswith(b"E"):
            return None
        return bytes.fromhex(r.decode())

    def read_regs(self) -> dict:
        r = self.cmd("g")
        raw = bytes.fromhex(r.decode())
        names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                 "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"]
        out = {}
        for i, n in enumerate(names):
            off = i * 8
            if off + 8 > len(raw):
                break
            out[n] = int.from_bytes(raw[off:off + 8], "little")
        return out

    def set_watch(self, addr: int, length: int) -> bool:
        r = self.cmd("Z2,%x,%x" % (addr, length))
        return r.startswith(b"OK")

    def cont(self):
        # continue; ответ придёт при остановке (watchpoint)
        return self._recv_stop()

    def _recv_stop(self, max_wait: float = 1200.0):
        deadline = time.time() + max_wait
        while time.time() < deadline:
            try:
                r = self._recv()
            except socket.timeout:
                continue
            if r and (r[0:1] == b"T" or r[0:1] == b"S" or r[0:1] == b"W"):
                return r
        return None


def main():
    addr = int(sys.argv[1], 16)
    length = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 1234

    r = Rsp(port)
    print("[rsp] connected (QEMU останавливает ВМ при коннекте)")
    # '?' — причина остановки (QEMU шлёт T05 сразу после connect)
    stop = r.cmd("?")
    print("[rsp] stop:", stop.decode(errors="replace"))

    # цикл установки watchpoint (страница может быть ещё не замаплена)
    ok = False
    for attempt in range(900):  # до 450с (бут ~2мин + загрузка либ)
        if r.set_watch(addr, length):
            ok = True
            print(f"[rsp] WATCH set on 0x{addr:x}+{length}")
            break
        # страница не существует — продолжаем и ждём (гостевой mmap)
        r.cmd("c", wait_reply=False)
        time.sleep(0.5)
        r.interrupt()
    if not ok:
        print("[rsp] FAILED to set watchpoint")
        return 1

    # проверим текущее содержимое
    cur = r.read_mem(addr, 8)
    if cur:
        print(f"[rsp] current mem = 0x{cur[::-1].hex()}")
        if cur == b"\xAA" * 8:
            print("[rsp] ⚠ 0xAAAA уже записан ДО watchpoint — поздно; перезапусти с более ранним attach")

    print("[rsp] continuing — waiting for 0xAAAAAAAAAAAAAAAA write (до 20 мин)...")
    rounds = 0
    while True:
        rounds += 1
        r.cmd("c", wait_reply=False)
        stop = r._recv_stop()
        if stop is None:
            print(f"[rsp] no trigger after {rounds} раундов (timeout)")
            return 2
        regs = r.read_regs()
        cur = r.read_mem(addr, 8)
        val = int.from_bytes(cur, "little") if cur else -1
        tag = stop.decode(errors="replace")
        print(f"[rsp] TRIGGER#{rounds}: {tag} rip=0x{regs.get('rip',0):x} "
              f"mem=0x{val:016x}")
        if val == 0xAAAAAAAAAAAAAAAA:
            print("[rsp] ★★ НАЙДЕНО — писатель 0xAAAA пойман ★★")
            for n in ["rip", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
                      "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
                      "r15"]:
                print(f"  {n} = 0x{regs.get(n, 0):016x}")
            # скан стека на ret-адреса
            rsp = regs.get("rsp", 0)
            if rsp:
                blob = r.read_mem(rsp, 8 * 48)
                if blob:
                    print("[rsp] STACK-RET scan:")
                    for i in range(48):
                        v = int.from_bytes(blob[i * 8:i * 8 + 8], "little")
                        if (0x400000000000 <= v < 0x400600000000) or (
                            0x100000000000 <= v < 0x100000400000):
                            print(f"  [rsp+0x{i*8:02x}] 0x{v:016x}")
            return 0
        # безобидная запись — продолжаем ждать


if __name__ == "__main__":
    sys.exit(main())
