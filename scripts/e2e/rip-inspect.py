#!/usr/bin/env python3
# ============================================================================
# rip-inspect.py — CDD №12 p7: WHERE is the guest spinning?
# Прерываем VM (Ctrl-C RSP) в момент сталла → RIP/regs/stack → точка спина.
# Usage: python3 rip-inspect.py [port] [wait_seconds_before_interrupt]
# Запускать через e2e-daemon (детач-клиенты гибнут от reaper'а инструмента).
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

    def interrupt(self):
        self.s.sendall(b"\x03")
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                r = self._recv()
            except socket.timeout:
                continue
            if r and (r[0:1] in (b"T", b"S")):
                return r
        raise TimeoutError("no stop after interrupt")

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

    def read_mem(self, addr: int, length: int):
        r = self.cmd("m%x,%x" % (addr, length))
        if r.startswith(b"E"):
            return None
        return bytes.fromhex(r.decode())


def qword(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 8], "little")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1234
    wait_s = float(sys.argv[2]) if len(sys.argv) > 2 else 240.0

    r = Rsp(port)
    print(f"[ri] connected; watching serial [L]-count for stall", flush=True)
    print("[ri] initial stop:", r.cmd("?").decode(errors="replace")[:60],
          flush=True)
    r.cmd("c", wait_reply=False)  # продолжить (attach останавливает VM)

    # CDD №12 p7: ждать ЗАМЕРЗАНИЯ syscall-фронта (счётчик [L] в serial.log
    # не растёт 30с) — точный момент сталла (fixed-timer проигрывал гонку
    # с постсталл-резетом ядра).
    SER = "/tmp/poler-e2e-drm-gamescope/serial.log"
    def lcount():
        try:
            return sum(1 for line in open(SER, errors="ignore")
                       if "[L]" in line)
        except Exception:
            return 0
    t0 = time.time()
    last_n, last_change = -1, time.time()
    while time.time() - t0 < wait_s:
        time.sleep(4)
        n = lcount()
        if n != last_n:
            last_n, last_change = n, time.time()
        elif n > 400 and time.time() - last_change > 30:
            print(f"[ri] STALL: [L] frozen at {n} for "
                  f"{time.time()-last_change:.0f}s — interrupting NOW",
                  flush=True)
            break
    else:
        print(f"[ri] no stall in {wait_s:.0f}s — interrupting anyway",
              flush=True)

    # прерывание с ретраями (эмпирика: одиночный \x03 иногда теряется)
    stopped = False
    for attempt in range(3):
        try:
            r.interrupt()
            stopped = True
            break
        except TimeoutError:
            print(f"[ri] interrupt attempt {attempt+1} failed — retry",
                  flush=True)
            time.sleep(2)
    if not stopped:
        print("[ri] FAILED to interrupt", flush=True)
        return 1
    regs = r.read_regs()
    print("=== STALL STATE (interrupt) ===", flush=True)
    for n in ["rip", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
        print(f"  {n:4s} = 0x{regs[n]:016x}", flush=True)

    # код вокруг RIP
    code = r.read_mem(regs["rip"] - 16, 48)
    if code:
        print(f"--- CODE [rip-0x10, rip+0x20) ---", flush=True)
        print("  " + code.hex(), flush=True)

    # стек
    mem = r.read_mem(regs["rsp"], 96)
    if mem:
        print(f"--- STACK [rsp, +0x60) ---", flush=True)
        for i in range(12):
            print(f"  [rsp+0x{i*8:02x}] 0x{qword(mem, i*8):016x}", flush=True)

    # кадр rbp
    if 0x10000 < regs["rbp"] < 0x8000_0000_0000:
        m2 = r.read_mem(regs["rbp"] - 0x20, 0x40)
        if m2:
            print("--- FRAME [rbp-0x20, +0x20) ---", flush=True)
            for k in range(8):
                print(f"  [rbp-0x{0x20-k*8:02x}] 0x{qword(m2, k*8):016x}",
                      flush=True)
    print("[ri] done (VM остановлен)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
