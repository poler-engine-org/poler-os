#!/usr/bin/env python3
# ============================================================================
# elf-run-e2e.py — E2E-прогон CDD №11 p1: ПЕРВЫЙ ELF-процесс Linux-ABI
# ============================================================================
# Полигон elftest (gcc -static-pie -nostdlib): боевой цикл в Ring 3:
#   write(1) → mmap-anon → clone(CLONE_VM|…) → futex WAIT/WAKE →
#   CLONE_CHILD_CLEARTID (pthread_join-семантика) → munmap → exit_group(42)
# Проверяет маркеры ELFTEST-* (user-space!) + [ELF]/[LINUX]/[SCHED] (kernel)
# + отсутствие CPU EXCEPTION / kernel-panic / FRAME-GUARD.
# ============================================================================
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal, TESTDATA

PASS = []
FAIL = []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)


def ensure_elftest():
    """Пересобрать elftest, если исходник новее бинарника (gcc -static-pie)."""
    src = os.path.join(TESTDATA, "elftest.c")
    bin_ = os.path.join(TESTDATA, "elftest")
    if os.path.exists(bin_) and os.path.getmtime(bin_) >= os.path.getmtime(src):
        return bin_
    if not os.path.exists(src):
        return bin_ if os.path.exists(bin_) else None
    cmd = [
        "gcc", "-static-pie", "-nostdlib", "-nostartfiles",
        "-fno-stack-protector", "-fno-builtin", "-O2", "-o", bin_, src,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("elftest build failed:", r.stderr[:500])
        return None
    return bin_


binary = ensure_elftest()
if binary is None:
    print("FATAL: elftest binary unavailable")
    sys.exit(1)

with open(binary, "rb") as f:
    elf_bin = f.read()

vm = VM("elf-run", initrd=build_cpio({"elftest": elf_bin, "README.txt": b"poler elf e2e"}), mem="256M")
try:
    vm.start()
    t = vm.wait_for("Shell started", timeout=90) or vm.wait_for("[EVDEV]", timeout=60)
    if t is None:
        check("boot: shell ready", False)
    else:
        check("boot: no fatal markers", not check_fatal(vm))

        vm.type_cmd("elfload elftest arg-from-shell")
        t2 = vm.wait_for("ELFTEST-EXIT-42", timeout=120)

        # kernel-сторона загрузки
        check("elfload: image mapped (PIE)", "[ELF] image: base=0x" in (t2 or "") and "(PIE)" in (t2 or ""))
        check("elfload: Linux stack argc=2", "argc=2" in (t2 or ""))
        check("elfload: Ring 3 task created", "Ring 3 task #" in (t2 or ""))

        # user-сторона (маркеры из Ring 3!)
        check("ELF: alive + argc", "ELFTEST-ALIVE argc=2" in (t2 or ""))
        check("ELF: argv[1] from shell", "ELFTEST-ARGV1 arg-from-shell" in (t2 or ""))
        check("ELF: mmap anon write+readback", "ELFTEST-MMAP-OK" in (t2 or ""))

        # clone-волна
        check("clone: child RAX=0 path", "ELFTEST-CLONE-CHILD tid=" in (t2 or ""))
        check("clone: parent got tid", "ELFTEST-CLONE-PARENT tid=" in (t2 or ""))
        check("clone: SETTID words (NPTL)", "ELFTEST-SETTID-OK" in (t2 or ""))

        # futex-волна
        check("futex: child WAKE sent", "ELFTEST-FUTEX-WAKE-SENT" in (t2 or ""))
        check("futex: parent WOKEN (park→wake)", "FUTEX-WOKEN value ok" in (t2 or ""))

        # pthread_join-семантика (CLONE_CHILD_CLEARTID)
        check("cleartid: join semantics", "ELFTEST-CLEARTID-OK" in (t2 or ""))

        # завершение
        check("exit_group(42) delivered", "exit_group(42)" in (t2 or ""))
        check("no FAIL markers from user", "ELFTEST-FAIL" not in (t2 or ""))
        check("no fatal markers (kernel)", not check_fatal(vm))

        # клавиатура/шелл живы после процесса
        vm.type_cmd("drm")
        t4 = vm.wait_for("caps: VERSION", timeout=30)
        check("shell alive after process (drm responds)", t4 is not None)
finally:
    vm.stop()

print("\n=== ELF-RUN: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
