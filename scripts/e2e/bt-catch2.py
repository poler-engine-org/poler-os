#!/usr/bin/env python3
# ============================================================================
# bt-catch2.py — CDD №12 p7: ЛОВЛЯ КРАШ-ИНСТАНЦИИ (loop-until-signature).
#
# bt-catch.py (p6) останавливался на ПЕРВОМ хите RIP — _Rb_tree_decrement
# ЗДОРОВО вызывается тысячи раз до краша. Здесь: bp на fault-инструкции
# (cmp rdi,[rax+8] @ libstdc+++0xE0C2E) → continue → на КАЖДОМ хите читаем
# ТОЛЬКО RAX (пакет 'p') → краш-сигнатура RAX==0 (здоровый декремент НИКОГДА
# не держит NULL в RAX на этой инструкции — иначе был бы #PF) → полный дамп:
# regs / стек-каскад / узел дерева / контейнеры R13-R14 / кадр RBP.
#
# Usage: python3 bt-catch2.py [rip_hex] [port] [max_hits] [max_wait_s]
# Запускать ПАРАЛЛЕЛЬНО e2e (E2E_GDB=1).
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
                if start < 0:
                    self.buf = b""
                    continue
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

    def read_reg(self, num: int):  # 'p' packet: один регистр
        r = self.cmd("p%x" % num)
        if r.startswith(b"E") or r == b"":
            return None
        raw = bytes.fromhex(r.decode())
        return int.from_bytes(raw.ljust(8, b"\0")[:8], "little")

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

    def set_bp(self, addr: int) -> bool:
        r = self.cmd("Z0,%x,1" % addr)
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


def is_codeptr(v: int) -> bool:
    # мапы либ/JIT: 0x4000_0000_0000..0x4020_0000_0000; gamescope: 0x1000_...
    return (0x4000_0000_0000 <= v < 0x4020_0000_0000) or \
           (0x1000_0000_0000 <= v < 0x1000_0080_0000)


def dump_stack(r: Rsp, regs: dict, count: int = 112):
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
        elif 0x400E_F000_0000 <= v < 0x4010_0000_0000:
            tag = "  <-- llvm-seg"
        elif 0x1000_0003_0000 <= v < 0x1000_0060_0000:
            tag = "  <-- brk-heap"
        print(f"  [rsp+0x{i*8:03x}] 0x{v:016x}{tag}")


def dump_region(r: Rsp, label: str, addr: int, size: int = 0x40):
    if addr == 0 or size == 0:
        return
    mem = r.read_mem(addr, size)
    if not mem:
        print(f"--- {label} [0x{addr:x}] --- (unmapped)")
        return
    print(f"--- {label} [0x{addr:x}, +0x{size:x}) ---")
    for k in range(size // 8):
        v = qword(mem, k * 8)
        tag = "  <-- CODE/RET" if is_codeptr(v) else ""
        print(f"  [+0x{k*8:02x}] 0x{v:016x}{tag}")


def main():
    rip = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x400085EC2E
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1234
    max_hits = int(sys.argv[3]) if len(sys.argv) > 3 else 100000
    max_wait = float(sys.argv[4]) if len(sys.argv) > 4 else 900.0

    r = Rsp(port)
    print(f"[bt2] connected; bp @ 0x{rip:x}; waiting for crash instance "
          f"(RAX==0), max {max_hits} hits / {max_wait:.0f}s")
    print("[bt2] stop:", r.cmd("?").decode(errors="replace")[:80])

    if not r.set_bp(rip):
        print("[bt2] FAILED to set breakpoint")
        return 1
    r.cont()

    hits = 0
    crash = None
    t0 = time.time()
    while time.time() - t0 < max_wait and hits < max_hits:
        stop = r.wait_stop(10.0)
        if stop is None:
            continue
        hits += 1
        # быстрый чек RAX (reg 0) без полного 'g'
        rax = r.read_reg(0)
        if rax == 0:
            crash = True
            break
        if hits % 2000 == 0:
            print(f"[bt2] hits={hits} ({time.time()-t0:.0f}s) — still healthy")
        r.cont()

    if crash is None:
        print(f"[bt2] NO crash instance in window: hits={hits}, "
              f"{time.time()-t0:.0f}s — layout мог сдвинуться?")
        return 1

    print(f"[bt2] *** CRASH INSTANCE after {hits} healthy hits "
          f"({time.time()-t0:.0f}s) ***")
    regs = r.read_regs()
    print("--- REGS ---")
    for n in ["rip", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
        print(f"  {n:4s} = 0x{regs[n]:016x}")

    dump_stack(r, regs)

    # узел дерева (RDI на краш-инструкции) + контейнерные структуры
    dump_region(r, "NODE(RDI)", regs["rdi"], 0x40)
    dump_region(r, "R12", regs["r12"], 0x40)
    dump_region(r, "R13-контейнер", regs["r13"], 0x40)
    dump_region(r, "R14-контейнер", regs["r14"], 0x40)
    # кадр вокруг rbp — локали + сохранённые reg + ret
    if 0x10000 < regs["rbp"] < 0x8000_0000_0000:
        m3 = r.read_mem(regs["rbp"] - 0x40, 0x80)
        if m3:
            print(f"--- FRAME [rbp-0x40, rbp+0x40) ---")
            for k in range(16):
                v = qword(m3, k * 8)
                print(f"  [rbp{'' if k < 8 else '+'}0x{(k-8)*8:+03x}] "
                      f"0x{v:016x}"
                      f"{'  <-- CODE/RET' if is_codeptr(v) else ''}")
    # КАК ВЫГЛЯДИТ ЗАГОЛОВОК: _Rb_tree_header = {color, parent(root), left, right}
    print("[bt2] done (VM остановлен на краш-инструкции — ДО #PF)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
