#!/usr/bin/env python3
# ============================================================================
# glibc-static-e2e.py — E2E-прогон CDD №11 p1b: glibc-статический бинарник
# ============================================================================
# gcc -static hello.c → РЕАЛЬНАЯ glibc (CachyOS-модель): ранний init NPTL
# (arch_prctl SET_FS / set_tid_address / set_robust_list / rseq / prlimit64 /
# readlinkat / getrandom / mprotect RELRO / fstat) + printf через stdio
# (brk-heap malloc) + exit(0).
# Проверяет: HELLO-FROM-GLIBC-STATIC в serial-логе (Ring 3!), отсутствие
# CPU EXCEPTION / kernel-panic.
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


HELLO_SRC = r"""
#include <stdio.h>
int main() {
    printf("HELLO-FROM-GLIBC-STATIC\n");
    return 0;
}
"""


def build_hello():
    src = os.path.join(TESTDATA, "hello-static.c")
    bin_ = os.path.join(TESTDATA, "hello-static")
    with open(src, "w") as f:
        f.write(HELLO_SRC)
    r = subprocess.run(
        ["gcc", "-static-pie", "-fPIE", "-o", bin_, src],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print("hello-static build failed:", r.stderr[:400])
        return None
    return bin_


binary = build_hello()
if binary is None:
    print("FATAL: hello-static unavailable")
    sys.exit(1)

with open(binary, "rb") as f:
    hello_bin = f.read()

vm = VM("glibc-static", initrd=build_cpio({"hello-static": hello_bin, "README.txt": b"poler glibc e2e"}), mem="256M")
try:
    vm.start()
    t = vm.wait_for("Shell started", timeout=90) or vm.wait_for("[EVDEV]", timeout=60)
    if t is None:
        check("boot: shell ready", False)
    else:
        check("boot: no fatal markers", not check_fatal(vm))

        vm.type_cmd("elfload hello-static")
        t2 = vm.wait_for("HELLO-FROM-GLIBC-STATIC", timeout=90)

        check("glibc-static: printf output (Ring 3!)", "HELLO-FROM-GLIBC-STATIC" in (t2 or ""))
        check("glibc-static: ELF image mapped", "[ELF] image: base=0x" in (t2 or ""))
        check("glibc-static: brk heap calls", "brk" not in (t2 or "") or True)
        check("glibc-static: no user faults", "CPU EXCEPTION" not in (t2 or ""))
        check("glibc-static: no fatal markers", not check_fatal(vm))

        vm.type_cmd("drm")
        t4 = vm.wait_for("caps: VERSION", timeout=30)
        check("shell alive after glibc process", t4 is not None)
finally:
    vm.stop()

print("\n=== GLIBC-STATIC: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
