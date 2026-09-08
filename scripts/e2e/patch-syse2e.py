#!/usr/bin/env python3
# patch-syse2e.py — CDD №12 p11: env-ручки для sysharness-e2e.py
#   1. E2E_QEMU=full → VM под qemu-full (Debian 10.0.11, TCG-плагины)
#   2. E2E_PLUGIN="LO,HI" → -plugin file=.../jit-writer.so,LO,HI
#      (паттерн drm-gamescope-e2e.py: позиционные куски, плагин склеивает)
#   3. импорт QEMU, QEMU_FULL из e2e_lib
import io, sys

P = "/tmp/my-project/poler-os/scripts/e2e/sysharness-e2e.py"
src = open(P, encoding="utf-8").read()

# 1. импорт констант QEMU
old_imp = "from e2e_lib import VM, build_cpio, check_fatal, KERNEL"
new_imp = "from e2e_lib import VM, build_cpio, check_fatal, KERNEL, QEMU_FULL"
assert old_imp in src, "import line not found"
src = src.replace(old_imp, new_imp)

# 2. VM(...): qemu-ручка + plugin-аргументы
old_vm = '''vm = VM("sysharness", initrd=INITRD, mem=os.environ.get("E2E_MEM", "2G"),
        extra_args=["-cpu", "max",
                    # CDD №12 p11: gdb-stub для p11-watch.py (write-watchpoint
                    # на детерминированную JIT-страницу — «кто пишет нули»)
                    *(["-s"] if os.environ.get("E2E_GDB") else [])])'''
new_vm = '''vm = VM("sysharness", initrd=INITRD, mem=os.environ.get("E2E_MEM", "2G"),
        qemu=(QEMU_FULL if os.environ.get("E2E_QEMU") == "full" else None),
        extra_args=["-cpu", "max",
                    # CDD №12 p11: gdb-stub для p11-watch.py (write-watchpoint
                    # на детерминированную JIT-страницу — «кто пишет нули»)
                    *(["-s"] if os.environ.get("E2E_GDB") else []),
                    # CDD №12 p11: НАТИВНЫЙ TCG-плагин jit-writer.so — история
                    # записей в JIT-диапазон с vpc писателя (gdbstub хрупок:
                    # run2 заморозил бут на APIC-timer). Позиционные LO,HI.
                    *(["-plugin",
                       "file=%s/scripts/e2e/%s,%s" % (
                           os.path.abspath(os.path.join(
                               os.path.dirname(os.path.abspath(__file__)),
                               "..", "..")),
                           os.environ.get("E2E_WHO", "jit-writer.so"),
                           os.environ["E2E_PLUGIN"])]
                      if os.environ.get("E2E_PLUGIN") else [])])'''
assert old_vm in src, "VM block not found"
src = src.replace(old_vm, new_vm)

open(P, "w", encoding="utf-8").write(src)
print("patched OK:", P)
