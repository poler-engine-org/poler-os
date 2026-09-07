#!/usr/bin/env python3
# ============================================================================
# p11-watch.py — WHO пишет в JIT-страницу? (CDD №12 p11)
# ============================================================================
# Write-watchpoint (Z2) на детерминированный адрес JIT-страницы краша
# (эмпирика: mmap-аллокатор ядра детерминирован → 0x401569D000 стабильно).
# На каждый триггер: RIP (писатель!) + 16Б контента + регистры. Ловим:
#   (а) исходную запись машинного кода LLVM (memcpy-подобный store)
#   (б) ТАИНСТВЕННЫЙ занулятор первых 6 байт
#   (в) попытку исполнения (не триггерит — Z2 = write-only)
# Атрибуция: lvp base=0x40002FD000, libLLVM base=0x4009D4F000 (VM-run),
# libc=0x40000A0000 (текст RX=0x40000C4000).
# Usage: python3 p11-watch.py [addr_hex] [len] [max_triggers] [port]
# ============================================================================
import sys
import time

sys.path.insert(0, "/tmp/my-project/poler-os/scripts/e2e")
from importlib.util import spec_from_file_location, module_from_spec
_spec = spec_from_file_location("rspw", "/tmp/my-project/poler-os/scripts/e2e/rsp-watch.py")
_rspw = module_from_spec(_spec)
_spec.loader.exec_module(_rspw)
Rsp = _rspw.Rsp


def attr(va: int) -> str:
    """VM-run атрибуция (детерминированные базы p11-прогонов)."""
    mods = [
        (0x40002FD000, 0x4E6000, "libvulkan_lvp.so"),
        (0x4009D4F000, 0x22E000, "libLLVM.so.22.1"),
        (0x40000C4000, 0x1B0000, "libc.so.6(text)"),
        (0x4000002000, 0x9B000, "libvulkan.so.1"),
        (0x4015568000, 0x4A000, "arena-anon"),
        (0x400D568000, 0x8000000, "thread4-stack"),
        (0x100000000000, 0x5000, "sysharness"),
        (0x4000000000, 0x43000, "ld.so"),
        (0x7FFF8000000, 0x8000000, "[stack]"),
        (0x4001131000, 0x2C000, "lvp-bss-anon"),
        (0x40010D3000, 0x5E000, "lvp-data"),
    ]
    for base, size, name in mods:
        if base <= va < base + size:
            return f"{name}+0x{va-base:x}"
    if 0x4000000000 <= va < 0x7FFF8000000:
        return f"mmap-region(0x{va:x})"
    return f"0x{va:x}"


def main():
    addr = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x401569D000
    length = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    max_trig = int(sys.argv[3]) if len(sys.argv) > 3 else 24
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 1234

    r = None
    for attempt in range(60):  # до 300с: QEMU поднимает :1234 асинхронно
        try:
            r = Rsp(port)
            break
        except (ConnectionRefusedError, OSError):
            print(f"[p11] connect retry {attempt}...", flush=True)
            time.sleep(5.0)
    if r is None:
        print("[p11] FAILED to connect to gdbstub", flush=True)
        return 1
    print(f"[p11] connected; target 0x{addr:x}+{length}")
    r.cmd("?")

    ok = False
    for attempt in range(600):  # до 300с
        if r.set_watch(addr, length):
            ok = True
            print(f"[p11] WATCH set on 0x{addr:x}+{length} (attempt {attempt})")
            break
        r.cmd("c", wait_reply=False)
        time.sleep(0.5)
        r.interrupt()
    if not ok:
        print("[p11] FAILED to set watchpoint")
        return 1

    cur = r.read_mem(addr, 16)
    if cur:
        print(f"[p11] initial mem[16] = {cur.hex()}")

    print("[p11] continuing — ловим писателей...", flush=True)
    import socket as _socket
    trig = 0
    while trig < max_trig:
        r.cmd("c", wait_reply=False)
        # heartbeat-ожидание стоп-пакета (постоянный вывод держит
        # bash-вызов живым — песочница режет тихие пайпы!)
        stop = None
        deadline = time.time() + 900.0
        hb = 0
        while time.time() < deadline:
            try:
                pkt = r._recv()
            except _socket.timeout:
                hb += 1
                if hb % 3 == 0:
                    print(f"[hb] alive, trig={trig}, t={int(time.time() % 100000)}", flush=True)
                continue
            except Exception as e:
                print(f"[p11] recv-error: {e!r}", flush=True)
                break
            if pkt and pkt[0:1] in (b"T", b"S", b"W"):
                stop = pkt
                break
        if stop is None:
            print(f"[p11] no more triggers ({trig} поймано, таймаут 900с)", flush=True)
            break
        trig += 1
        regs = r.read_regs()
        mem = r.read_mem(addr, 16)
        rip = regs.get("rip", 0)
        print(f"\n[p11] TRIGGER#{trig}: {stop.decode(errors='replace')}")
        print(f"  writer-rip = 0x{rip:x}  ({attr(rip)})")
        print(f"  mem[16]    = {mem.hex() if mem else '???'}")
        brief = {k: regs[k] for k in
                 ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r10", "r12") if k in regs}
        print(f"  regs       = { {k: hex(v) for k, v in brief.items()} }")
        # знак судьбы: нули в первых байтах
        if mem and mem[:6] == b"\x00" * 6:
            print("  *** ПЕРВЫЕ 6 БАЙТ = НУЛИ — вот он, момент порчи! ***")
    print(f"\n[p11] done: {trig} триггеров")
    # снятие watchpoint и финальное продолжение (пусть дамп допечатается)
    r.cmd("z2,%x,%x" % (addr, length))
    r.cmd("c", wait_reply=False)
    time.sleep(3.0)
    return 0


if __name__ == "__main__":
    try:
        rc = main()
        print("[p11] watcher exiting rc=%d" % rc, flush=True)
        sys.exit(rc)
    except BaseException as e:
        import traceback
        traceback.print_exc()
        print("[p11] watcher CRASHED: %r" % e, flush=True)
        sys.exit(3)
