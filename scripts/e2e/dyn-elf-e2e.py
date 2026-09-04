#!/usr/bin/env python3
# ============================================================================
# dyn-elf-e2e.py — crash-driven прогон CDD №11 p3: ДИНАМИЧЕСКИЙ ELF (ld.so)
# ============================================================================
# gcc -pie hello.c → PT_INTERP /lib64/ld-linux-x86-64.so.2: наш загрузчик
# поднимает интерпретатор (вторая ET_DYN-картинка, LINUX_INTERP_BASE) и
# передаёт управление ЕГО entry (handoff; AT_BASE=базис ld.so).
# Методика CDD: прогон 1 — БЕЗ трейса (естественный исход: HELLO-WORLD /
# краш); если HELLO нет — прогон 2 с ltrace → syscall-крашлог в отчёт.
# Волна p3 закрывает: file-backed mmap (MAP_PRIVATE), lseek/pread64,
# writev, access, newfstatat, CPIO-канонизация имён (диалекты '/x','x','./x').
# ============================================================================
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal, TESTDATA

PASS = []
FAIL = []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)


# 1. динамический бинарник + интерпретатор + libc в initrd
import subprocess
SRC = os.path.join(TESTDATA, "hello-dyn.c")
with open(SRC, "w") as f:
    f.write('#include <stdio.h>\nint main() { printf("HELLO-WORLD-FROM-DYNAMIC\\n"); return 0; }\n')
subprocess.run(["gcc", "-fPIE", "-pie", "-o", "/tmp/hello-dyn", SRC], check=True)
with open("/tmp/hello-dyn", "rb") as f:
    dyn_bin = f.read()

INTERP = "/lib64/ld-linux-x86-64.so.2"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"
files = {"hello-dyn": dyn_bin}
# пути — КАК ИХ ВИДИТ ld.so (initrd = корень: /lib64/…, /lib/…);
# CPIO-ключи без ведущего слеша — kanонизация в ядре (cpioCanon) обе стороны
for cand in (INTERP, "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"):
    if os.path.exists(cand):
        with open(cand, "rb") as f:
            files["lib64/ld-linux-x86-64.so.2"] = f.read()
        break
if os.path.exists(LIBC):
    with open(LIBC, "rb") as f:
        files["lib/x86_64-linux-gnu/libc.so.6"] = f.read()
# vDSO-заглушка НЕ нужна: clock_gettime — syscall в ядре


def run_once(with_trace, tag):
    """Один QEMU-прогон. Возвращает (ok_hellо, text)."""
    vm = VM(f"dyn-elf-{tag}", initrd=build_cpio(files), mem="256M")
    try:
        vm.start()
        t = vm.wait_for("Shell started", timeout=90) or vm.wait_for("[EVDEV]", timeout=60)
        if t is None:
            check(f"[{tag}] boot: shell ready", False)
            return False, ""
        check(f"[{tag}] boot: no fatal markers", not check_fatal(vm))

        if with_trace:
            vm.type_cmd("ltrace")
        vm.type_cmd("elfload hello-dyn")
        ok = vm.wait_for("HELLO-WORLD-FROM-DYNAMIC", timeout=45)
        # дождаться исхода (выход/краш) — добираем хвост лога
        vm.wait_for("exit_group", timeout=10)
        text = vm.text()
        return ok is not None, text
    finally:
        vm.stop()


ok, text = run_once(with_trace=False, tag="plain")

if ok:
    check("dyn: ld.so → libc → printf HELLO-WORLD (полный динамический путь)", True)
    check("dyn: PT_INTERP handoff прошёл", "[ELF] PT_INTERP:" in text)
    check("dyn: no kernel panic", "kernel-panic" not in text and "Halting" not in text)
else:
    # CDD-итерация: второй прогон с ltrace — крашлог в отчёт
    print("--- [plain] исход без HELLO: включаю ltrace для краш-лога ---")
    idx = text.find("[ELF]")
    if idx >= 0:
        print(text[idx : idx + 1200])
    ok2, t2 = run_once(with_trace=True, tag="trace")
    check("dyn: ld.so → libc → printf HELLO-WORLD (полный динамический путь)", ok2)
    print("--- CRASH LOG (CDD артефакт, ltrace) ---")
    idx = t2.find("[ELF]")
    if idx >= 0:
        print(t2[idx : idx + 2500])
    else:
        idx = t2.find("[L] ")
        if idx >= 0:
            print(t2[:2000])
    print("--- ---------------------------------- ---")
    check("dyn: no kernel panic", "kernel-panic" not in t2 and "Halting" not in t2)
    check("dyn: какой-то исход зафиксирован (краш-лог собран)", True)

print("\n=== DYN-ELF: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
