#!/usr/bin/env python3
# dyn-elf-debug.py — полный краш-лог прогон (временный CDD-инструмент)
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, TESTDATA
import subprocess

SRC = os.path.join(TESTDATA, "hello-dyn.c")
subprocess.run(["gcc", "-fPIE", "-pie", "-o", "/tmp/hello-dyn", SRC], check=True)
with open("/tmp/hello-dyn", "rb") as f:
    dyn_bin = f.read()

files = {"hello-dyn": dyn_bin}
with open("/lib64/ld-linux-x86-64.so.2", "rb") as f:
    files["lib64/ld-linux-x86-64.so.2"] = f.read()
with open("/lib/x86_64-linux-gnu/libc.so.6", "rb") as f:
    files["lib/x86_64-linux-gnu/libc.so.6"] = f.read()

vm = VM("dyn-elf-dbg", initrd=build_cpio(files), mem="256M")
try:
    vm.start()
    vm.wait_for("Shell started", timeout=90)
    vm.type_cmd("ltrace")
    vm.type_cmd("elfload hello-dyn")
    vm.wait_for("HELLO-WORLD-FROM-DYNAMIC", timeout=120)
    import time
    time.sleep(3)
    text = vm.text()
    with open("/tmp/dyn-full.log", "w") as f:
        f.write(text)
    print(f"FULL LOG: {len(text)} chars → /tmp/dyn-full.log")
    # вырезка: всё между "[ELF] image" и первыми tick-спамами
    lines = text.splitlines()
    keep = []
    spam = 0
    for l in lines:
        if l.startswith("[SCHED] tick"):
            spam += 1
            if spam > 5:
                continue
        else:
            spam = 0
        keep.append(l)
    print("=== SERIALIZED EVENTS (без tick-спама) ===")
    print("\n".join(keep))
finally:
    vm.stop()
