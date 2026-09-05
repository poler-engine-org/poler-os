#!/usr/bin/env python3
# ============================================================================
# crash-dump.py — монитор-наблюдатель CDD №12 p4-final.
# Задача: «кто кладёт 0xAAAAAAAA в память гостя».
#   1. Следит за serial-логом ВМ (файл) до "!!! CPU EXCEPTION !!!";
#   2. Через ВТОРОЙ QEMU-монитор: stop; info registers (CR3/RIP/R15);
#   3. Page-walk: VA 0x4002EED388 → PA (чтение PML4/PDP/PD/PT через xp);
#   4. xp /Ngx PA — физическое содержимое вокруг объекта (0x4002EED300..);
#   5. pmemsave окна физпамяти + поиск 0xAAAAAAAAAAAAAAAA;
#   6. Дамп «до/после»: страницы вокруг PA.
# Использование: python3 crash-dump.py <serial.log> <mon2.sock> [va_hex]
# ============================================================================
import os
import re
import socket
import sys
import time


def wait_crash(log_path: str, timeout_s: float = 1500.0) -> bool:
    """Ждём '!!! CPU EXCEPTION !!!' в serial-логе (поллинг размера файла)."""
    t0 = time.time()
    seen = 0
    while time.time() - t0 < timeout_s:
        try:
            with open(log_path, "rb") as f:
                data = f.read()
            n = data.count(b"!!! CPU EXCEPTION !!!")
            if n > seen:
                return True
        except FileNotFoundError:
            pass
        time.sleep(1.0)
    return False


class Mon:
    def __init__(self, sock_path: str, timeout=10.0):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(sock_path)
        self.s.settimeout(timeout)
        self._drain()

    def _drain(self):
        try:
            while True:
                d = self.s.recv(65536)
                if not d:
                    break
                if d.rstrip().endswith(b"(qemu)"):
                    break
        except socket.timeout:
            pass

    def cmd(self, c: str, wait=2.0) -> str:
        self.s.sendall(c.encode() + b"\n")
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
        return out.decode(errors="replace")


def read_qword(mon: Mon, pa: int) -> int | None:
    """xp /1gx PA → значение (0x-префикс, ANSI-чистка)."""
    out = mon.cmd("xp /1gx 0x%x" % pa, wait=1.2)
    clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out)
    for line in clean.splitlines():
        mm = re.match(r"^[0-9a-f]+:(.*)$", line.strip())
        if mm:
            h = re.search(r"0x([0-9a-f]{16})", mm.group(1))
            if h:
                return int(h.group(1), 16)
    return None


def read_page(mon: Mon, pa: int, n: int = 64) -> list[int]:
    """xp /Ngx PA → список qword (постранично, до n значений)."""
    out = mon.cmd("xp /%dgx 0x%x" % (n, pa), wait=3.0)
    clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out)
    vals: list[int] = []
    for line in clean.splitlines():
        mm = re.match(r"^[0-9a-f]+:(.*)$", line.strip())
        if mm:
            vals += [int(h, 16) for h in re.findall(r"0x([0-9a-f]{16})", mm.group(1))]
    return vals


def va_to_pa(mon: Mon, cr3: int, va: int) -> int | None:
    """4-уровневый page-walk через физчтение монитора."""
    pml4 = cr3 & 0x000FFFFFFFFFF000
    pml4e = read_qword(mon, pml4 + 8 * ((va >> 39) & 0x1FF))
    if pml4e is None or not (pml4e & 1):
        return None
    pdpt = pml4e & 0x000FFFFFFFFFF000
    pdpte = read_qword(mon, pdpt + 8 * ((va >> 30) & 0x1FF))
    if pdpte is None or not (pdpte & 1):
        return None
    if pdpte & (1 << 7):  # 1GB page
        return (pdpte & 0xFFC0000000000) + (va & 0x3FFFFFFF)
    pd = pdpte & 0x000FFFFFFFFFF000
    pde = read_qword(mon, pd + 8 * ((va >> 21) & 0x1FF))
    if pde is None or not (pde & 1):
        return None
    if pde & (1 << 7):  # 2MB page
        return (pde & 0xFFFFFFE00000) + (va & 0x1FFFFF)
    pt = pde & 0x000FFFFFFFFFF000
    pte = read_qword(mon, pt + 8 * ((va >> 12) & 0x1FF))
    if pte is None or not (pte & 1):
        return None
    return (pte & 0x000FFFFFFFFFF000) + (va & 0xFFF)


def mon_connect(mon_sock: str, tries: int = 30) -> Mon:
    """Монитор может появиться чуть позже (QEMU стартует) — ретраи."""
    for i in range(tries):
        try:
            return Mon(mon_sock)
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(1.0)
    raise RuntimeError(f"монитор {mon_sock} недоступен")


def main():
    log_path = sys.argv[1]
    mon_sock = sys.argv[2]
    target_va = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x4002EED388
    wait_s = float(sys.argv[4]) if len(sys.argv) > 4 else 1500.0

    print(f"[cd] ждём CPU EXCEPTION в {log_path} (до {wait_s/60:.0f} мин)...")
    if not wait_crash(log_path, wait_s):
        print("[cd] краш не наступил — выходим")
        return 1
    print("[cd] ★ краш пойман — останавливаем ВМ")

    # парсинг кадров краша из serial-лога (RIP/RSP/R15/PML4)
    crash = {}
    try:
        with open(log_path, "rb") as f:
            text = f.read().decode(errors="replace")
        idx = text.rfind("!!! CPU EXCEPTION !!!")
        block = text[idx: idx + 2500] if idx >= 0 else ""
        for key in ["RIP", "RSP", "R15", "R12", "RDI", "RAX"]:
            mm = re.search(rf"^{key}: 0x([0-9a-f]+)", block, re.M)
            if mm:
                crash[key] = int(mm.group(1), 16)
        mm = re.search(r"Created user PML4 at 0x([0-9a-f]+)", text)
        if mm:
            crash["PML4"] = int(mm.group(1), 16)
    except Exception as e:
        print("[cd] парсинг краша:", e)
    print("[cd] crash regs:", {k: hex(v) for k, v in crash.items()})

    mon = mon_connect(mon_sock)
    mon.cmd("stop", wait=0.5)
    regs = mon.cmd("info registers", wait=1.0)
    print("[cd] --- info registers (хвост) ---")
    print("\n".join(regs.splitlines()[-8:]))

    m = re.search(r"CR3=\S*([0-9a-f]+)", regs)
    cr3 = int(m.group(1), 16) if m else 0
    # если CPU уже вернулся в kernel-контекст — идём по PML4 из лога
    pml4 = crash.get("PML4", 0) or cr3
    print(f"[cd] CR3 = 0x{cr3:x}; PML4 краша = 0x{pml4:x}")

    # 1) страница объекта (R12-регион)
    pa = va_to_pa(mon, pml4, target_va)
    print(f"[cd] VA 0x{target_va:x} → PA {hex(pa) if pa else 'НЕ МАППИТСЯ'}")
    if pa:
        page = pa & ~0xFFF
        vals = read_page(mon, page, 96)
        print("[cd] --- физстраница объекта 0x%x (+0x2c0..+0x4c0) ---" % page)
        for i, v in enumerate(vals):
            if 0x2C0 <= i * 8 < 0x4C0:
                print("  +0x%03x  0x%016x" % (i * 8, v))

    # 2) СТЕК-страница краша (RSP) — паттерн-инициализация локалей
    if "RSP" in crash:
        spa = va_to_pa(mon, pml4, crash["RSP"] & ~0xFFF)
        if spa:
            print(f"[cd] --- СТЕК RSP=0x{crash['RSP']:x} (PA 0x{spa:x}, -0x100..+0x80) ---")
            svals = read_page(mon, spa - 0x180, 96)
            for i, v in enumerate(svals):
                off = -0x180 + i * 8
                print(f"  rsp{off:+#05x}  0x{v:016x}")
        else:
            print("[cd] стек-страница не маппится")

    # pmemsave нижних 512МБ (ядро+куча+стеки; initrd выше 1.8ГБ) для
    # офлайн-поиска 0xAAAA. ⚠ QEMU 10: путь — В КАВЫЧКАХ (иначе парсер
    # выражений даст "invalid char 't'").
    dump_path = "/tmp/crash-phys.bin"
    print("[cd] pmemsave 0x0 0x20000000 →", dump_path)
    out = mon.cmd('pmemsave 0x0 0x20000000 "%s"' % dump_path, wait=12.0)
    print("[cd] pmemsave-ответ:", out[-120:].replace("\n", " "))
    if os.path.exists(dump_path):
        sz = os.path.getsize(dump_path)
        print(f"[cd] дамп {sz/1024/1024:.0f} МБ — ищем 0xAAAAAAAAAAAAAAAA")
        hits = 0
        sample = []
        with open(dump_path, "rb") as f:
            off = 0
            needle = b"\xAA" * 8
            while True:
                blob = f.read(16 * 1024 * 1024)
                if not blob:
                    break
                i = 0
                while True:
                    i = blob.find(needle, i)
                    if i < 0:
                        break
                    pa_hit = off + i
                    if pa_hit % 8 == 0:  # выровненные
                        hits += 1
                        if len(sample) < 40:
                            sample.append(pa_hit)
                    i += 1
                off += len(blob)
        print(f"[cd] 0xAAAAAAAAAAAAAAAA выровненных вхождений: {hits}")
        print("[cd] первые PA:", [hex(x) for x in sample])
    mon.cmd("cont", wait=0.5)
    # освободить HOLD (ВМ жива до этого флага)
    release = "/tmp/e2e-hold-release"
    if os.path.exists(release):
        os.unlink(release)
    with open(release, "w") as f:
        f.write("released\n")
    print("[cd] HOLD освобождён")
    return 0


if __name__ == "__main__":
    sys.exit(main())
