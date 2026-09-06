#!/usr/bin/env python3
# ============================================================================
# watch-slot.py — CDD №12 p7: WHO WRITES 0xAAAAAAAAAAAAAAAA INTO THE POISON
# SLOT (task-5 kstack top-8 = 0x37C058)?
#
# who-ptr (TCG value-tracer) слеп к регистровым push/pop каскада isr64.S
# (эмпирика p7run7: 8.4M ядро-регион событий, НОЛЬ на слотах каскада) —
# у gdbstub Z2-watchpoint НЕТ этой слепоты: остановка НА инструкции записи.
#
# Механика: Z2 wp на слот → каждый хит: читаем [slot] — записанное значение
# уже в памяти (wp срабатывает ПОСЛЕ записи) → 0xAAAA... = ВИНОВНИК: дамп
# RIP+regs → это и есть запись, отравившая кадр задачи.
#
# Usage: python3 watch-slot.py [slot_hex] [port]
#   Слот: 0x37C058 (детерминирован 2 прогонами: R15-POISON slot=0x37C060).
# ============================================================================
import socket
import sys
import time


class Rsp:
    def __init__(self, port=1234, timeout=3.0):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""

    def _recv(self) -> bytes:
        while True:
            if b"#" in self.buf and len(self.buf) >= self.buf.index(b"#") + 3:
                start = self.buf.index(b"$")
                end = self.buf.index(b"#") + 3
                pkt = self.buf[start:end]
                self.buf = self.buf[end:]
                return pkt[1:-3]
            chunk = self.s.recv(4096)
            if not chunk:
                raise ConnectionError("gdb-stub closed")
            self.buf += chunk

    def cmd(self, data: str, wait_reply=True):
        payload = data.encode()
        cs = sum(payload) & 0xFF
        self.s.sendall(b"$" + payload + b"#%02x" % cs)
        self.s.sendall(b"+")
        if not wait_reply:
            return None
        while True:
            r = self._recv()
            if r == b"":
                continue
            return r

    def read_mem(self, addr: int, length: int):
        r = self.cmd("m%x,%x" % (addr, length))
        if r.startswith(b"E"):
            return None
        return bytes.fromhex(r.decode())

    def read_qword(self, addr: int):
        m = self.read_mem(addr, 8)
        if not m:
            return None
        return int.from_bytes(m, "little")

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

    def set_watch(self, addr: int, length: int = 8) -> bool:
        r = self.cmd("Z2,%x,%x" % (addr, length))
        return r.startswith(b"OK")

    def cont(self):
        self.cmd("c", wait_reply=False)

    def wait_stop(self, max_wait: float):
        deadline = time.time() + max_wait
        while time.time() < deadline:
            try:
                r = self._recv()
            except socket.timeout:
                continue
            if r and (r[0:1] in (b"T", b"S", b"W")):
                return r
        return None


def qword(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 8], "little")


def main():
    slot = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x37C058
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1234
    max_hits = int(sys.argv[3]) if len(sys.argv) > 3 else 20000
    max_wait = float(sys.argv[4]) if len(sys.argv) > 4 else 1500.0

    r = Rsp(port)
    print(f"[wp] connected; Z2 watchpoint @0x{slot:x} (8 bytes); "
          f"waiting for the 0xAAAA-writer", flush=True)
    print("[wp] stop:", r.cmd("?").decode(errors="replace")[:60], flush=True)

    if not r.set_watch(slot, 8):
        print("[wp] FAILED to set watchpoint", flush=True)
        return 1
    r.cont()

    hits = 0
    found = False
    t0 = time.time()
    while time.time() - t0 < max_wait and hits < max_hits:
        stop = r.wait_stop(10.0)
        if stop is None:
            continue
        hits += 1
        v = r.read_qword(slot)
        if v == 0xAAAAAAAAAAAAAAAA:
            found = True
            regs = r.read_regs()
            print(f"[wp] *** POISON WRITE after {hits} hits "
                  f"({time.time()-t0:.0f}s) ***", flush=True)
            print("--- REGS (writer) ---", flush=True)
            for n in ["rip", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                      "eflags", "cs"]:
                print(f"  {n:7s} = 0x{regs[n]:016x}", flush=True)
            # стек писателя (ret-цепь!)
            rsp = regs["rsp"]
            mem = r.read_mem(rsp, 96)
            if mem:
                print(f"--- WRITER STACK [rsp=0x{rsp:x}, 12 qwords] ---",
                      flush=True)
                for i in range(12):
                    print(f"  [rsp+0x{i*8:03x}] 0x{qword(mem, i*8):016x}",
                          flush=True)
            break
        if hits % 500 == 0:
            print(f"[wp] hits={hits} ({time.time()-t0:.0f}s) "
                  f"val=0x{v:016x}" if v else
                  f"[wp] hits={hits} ({time.time()-t0:.0f}s)", flush=True)
        r.cont()

    if not found:
        print(f"[wp] NO poison write in window: hits={hits}, "
              f"{time.time()-t0:.0f}s", flush=True)
        return 1
    print("[wp] done — VM остановлен на инструкции-писателе", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
