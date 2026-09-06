#!/usr/bin/env python3
# ============================================================================
# bt-catch.py — CDD №12 p6: поймать момент ПЕРЕД крашем _Rb_tree_decrement.
# RSP-клиент (как rsp-watch.py): BREAKPOINT (Z0) на RIP fault-инструкции —
# остановка ДО #PF → полный дамп: все GPR, стек (qwords + классификация
# ret-адресов), узел дерева [x, x+0x40), структуры R13/R14.
# Usage: python3 bt-catch.py [rip_hex] [port]
# Запускать ПАРАЛЛЕЛЬНО e2e (E2E_GDB=1): e2e-daemon → sleep 15 → bt-catch.
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

    def cmd(self, data: str, wait_reply=True) -> bytes | None:
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

    def set_bp(self, addr: int) -> bool:
        r = self.cmd("Z0,%x,1" % addr)
        return r.startswith(b"OK")

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


def is_codeptr(v: int) -> bool:
    # мапы либ/JIT: 0x4000_0000_0000..0x4006_0000_0000; gamescope: 0x1000_...
    return (0x4000_0000_0000 <= v < 0x4006_0000_0000) or \
           (0x1000_0000_0000 <= v < 0x1000_0040_0000)


def dump_stack(r: Rsp, regs: dict, count: int = 96):
    rsp = regs["rsp"]
    print(f"--- STACK [rsp=0x{rsp:x}, {count} qwords] ---")
    mem = r.read_mem(rsp, count * 8)
    if not mem:
        print("(unmapped?)")
        return
    for i in range(count):
        v = qword(mem, i * 8)
        tag = ""
        if is_codeptr(v):
            tag = "  <-- CODE/RET"
        elif 0x400F_0000_0000 <= v < 0x4010_0000_0000:
            tag = "  <-- arena-ptr"
        elif 0x1000_0003_0000 <= v < 0x1000_0050_0000:
            tag = "  <-- brk-heap-ptr"
        print(f"  [rsp+0x{i*8:03x}] 0x{v:016x}{tag}")


def main():
    rip = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x400085EC2E
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1234
    node = 0x400F21C428  # вузол дерева (RDI на краші)

    r = Rsp(port)
    print(f"[bt] connected; target RIP=0x{rip:x}")
    print("[bt] stop:", r.cmd("?").decode(errors="replace"))

    if not r.set_bp(rip):
        print("[bt] FAILED to set breakpoint")
        return 1
    print("[bt] BP set; continuing...")

    r.cmd("c", wait_reply=False)
    stop = r.wait_stop(400)
    if stop is None:
        print("[bt] no stop in 400s")
        return 1
    print(f"[bt] STOPPED: {stop.decode(errors='replace')}")

    regs = r.read_regs()
    print("--- REGS ---")
    for n in ["rip", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
        print(f"  {n:4s} = 0x{regs[n]:016x}")

    if regs["rip"] != rip:
        print(f"[bt] ⚠ rip != target (0x{regs['rip']:x}) — возможно другой BP")

    dump_stack(r, regs)

    # вузол дерева: 0x40 байт (color/pad, parent, left, right + пользовательские)
    print(f"--- NODE [0x{node:x}, +0x40) ---")
    mem = r.read_mem(node, 0x40)
    if mem:
        print("  color/pad : 0x%s" % qword(mem, 0).to_bytes(8, "little").hex())
        print(f"  _M_parent : 0x{qword(mem, 8):x}")
        print(f"  _M_left   : 0x{qword(mem, 0x10):x}")
        print(f"  _M_right  : 0x{qword(mem, 0x18):x}")
        print(f"  [+0x20]   : 0x{qword(mem, 0x20):x}  (value/key?)")
        print(f"  [+0x28]   : 0x{qword(mem, 0x28):x}")
        print(f"  [+0x30]   : 0x{qword(mem, 0x30):x}")
        print(f"  [+0x38]   : 0x{qword(mem, 0x38):x}")
    else:
        print("  (unmapped)")

    # структуры R13/R14 (внутри PROT_NONE'd региона)
    for label, a in (("R13-стр", 0x400EF83960), ("R14-стр", 0x400EF838C0)):
        m2 = r.read_mem(a, 0x40)
        if m2:
            print(f"--- {label} [0x{a:x}] ---")
            for k in range(8):
                print(f"  [+0x{k*8:02x}] 0x{qword(m2, k*8):x}")
    # дамп кадра вокруг rbp
    m3 = r.read_mem(regs["rbp"] - 0x40, 0x80)
    if m3:
        print(f"--- FRAME [rbp-0x40, rbp+0x40) ---")
        for k in range(16):
            v = qword(m3, k * 8)
            print(f"  [rbp{'' if k < 8 else '+'}0x{(k-8)*8:+03x}] 0x{v:016x}"
                  f"{'  <-- CODE/RET' if is_codeptr(v) else ''}")
    print("[bt] done (VM остановлен; e2e продолжает своё)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
