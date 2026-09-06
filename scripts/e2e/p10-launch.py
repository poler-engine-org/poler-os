#!/usr/bin/env python3
# ============================================================================
# p10-launch.py — daemonized запуск e2e (переживает границы bash-вызовов:
# песочница репает дерево процессов вызова; double-fork → сирота под init).
# ============================================================================
import os
import sys

REPO = "/tmp/my-project/poler-os"
LOG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p10-run.log"
ENV = {
    "E2E_PTR": "PAT",                       # who-ptr2 PATTERN-режим (0xAA-семья)
    "E2E_WHO": "who-ptr2.so",
    "E2E_BOOT_TIMEOUT": "300",           # бут под плагином ~4 мин (замер)
    "E2E_DRILL": "3600",
    "WHOAAAA_LOG": "/tmp/who-ptr.log",
    "E2E_MEM": "2G",
}

pid = os.fork()
if pid == 0:
    os.setsid()
    if os.fork() == 0:
        env = dict(os.environ)
        env.update(ENV)
        with open(LOG, "w") as lf:
            os.dup2(lf.fileno(), 1)
            os.dup2(lf.fileno(), 2)
            os.chdir(REPO)
            os.execve("/usr/bin/python3",
                      ["python3", "scripts/e2e/drm-gamescope-e2e.py"], env)
        os._exit(1)
    os._exit(0)
os.waitpid(pid, 0)
print(f"daemonized e2e → {LOG} (who-ptr → /tmp/who-ptr.log)")
