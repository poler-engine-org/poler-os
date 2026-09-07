#!/usr/bin/env python3
# p11-launch-gdb.py — daemonized sysharness-e2e с E2E_GDB=1 (gdbstub :1234)
import os
import sys

REPO = "/tmp/my-project/poler-os"
LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p11-harness-gdb.log"

pid = os.fork()
if pid == 0:
    os.setsid()
    if os.fork() == 0:
        env = dict(os.environ)
        env.update({"E2E_MEM": "2G", "E2E_BOOT_TIMEOUT": "180",
                    "E2E_DRILL": "1500", "E2E_GDB": "1"})
        with open(LOG, "w") as lf:
            os.dup2(lf.fileno(), 1)
            os.dup2(lf.fileno(), 2)
            os.chdir(REPO)
            os.execve("/usr/bin/python3",
                      ["python3", "scripts/e2e/sysharness-e2e.py"], env)
        os._exit(1)
    os._exit(0)
os.waitpid(pid, 0)
print(f"daemonized (gdbstub on :1234) -> {LOG}")
