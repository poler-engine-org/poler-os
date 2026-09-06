#!/usr/bin/env python3
# ============================================================================
# mon-inspect.py — CDD №12 p7: freeze the stalled guest via HMP monitor and
# dump the CPU state (RIP + regs + code) — WHERE is the spin?
#
# RSP-\x03 прерывание нестабильно (3 фейла подряд); HMP `stop` + `info
# registers` — прямой путь: e2e гейтит mon2.sock через E2E_MON2.
#
# Usage: python3 mon-inspect.py [sock] [stall_watch_s]
# Запускать через e2e-daemon (параллельно e2e с E2E_MON2=1).
# ============================================================================
import os
import socket
import sys
import time


class Mon:
    def __init__(self, path, timeout=3.0):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        self.s.connect(path)
        self.buf = b""
        time.sleep(0.3)
        try:
            self.s.recv(4096)  # баннер (qemu)
        except socket.timeout:
            pass

    def cmd(self, c: str, wait=1.5) -> str:
        self.s.sendall((c + "\n").encode())
        time.sleep(wait)
        out = b""
        try:
            while True:
                d = self.s.recv(65536)
                if not d:
                    break
                out += d
                if out.rstrip().endswith(b"(qemu)"):
                    break
        except socket.timeout:
            pass
        return out.decode("utf-8", "replace")


def main():
    sock = sys.argv[1] if len(sys.argv) > 1 else \
        "/tmp/poler-e2e-drm-gamescope/mon2.sock"
    watch = float(sys.argv[2]) if len(sys.argv) > 2 else 700.0

    # ждём замерзания [L]-фронта (сталл)
    SER = "/tmp/poler-e2e-drm-gamescope/serial.log"

    def lcount():
        try:
            return sum(1 for line in open(SER, errors="ignore")
                       if "[L]" in line)
        except Exception:
            return 0

    t0 = time.time()
    last_n, last_change = -1, time.time()
    stopped_by_stall = False
    while time.time() - t0 < watch:
        time.sleep(4)
        n = lcount()
        if n != last_n:
            last_n, last_change = n, time.time()
        elif n > 400 and time.time() - last_change > 30:
            print(f"[mi] STALL: [L] frozen at {n} — freezing VM via HMP",
                  flush=True)
            stopped_by_stall = True
            break
    if not stopped_by_stall:
        print(f"[mi] no stall detected in {watch:.0f}s — freezing anyway",
              flush=True)

    m = Mon(sock)
    print("=== HMP STOP ===", flush=True)
    print(m.cmd("stop"), flush=True)
    print("=== INFO REGISTERS ===", flush=True)
    regs = m.cmd("info registers", 2.0)
    print(regs, flush=True)

    # RIP из вывода (RIP=0x...)
    import re
    mm = re.search(r"RIP=([0-9a-fA-F]+)", regs)
    if mm:
        rip = int(mm.group(1), 16)
        print(f"=== CODE @RIP 0x{rip:x} ===", flush=True)
        print(m.cmd(f"x/24i 0x{rip-32:x}", 2.0), flush=True)
        # стек: RSP из вывода
        ms = re.search(r"RSP=([0-9a-fA-F]+)", regs)
        if ms:
            rsp = int(ms.group(1), 16)
            print(f"=== STACK @RSP 0x{rsp:x} ===", flush=True)
            print(m.cmd(f"x/24gx 0x{rsp:x}", 2.0), flush=True)
    print("[mi] done (VM заморожена)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
