#!/usr/bin/env python3
# ============================================================================
# pe-run4-e2e.py — POLER-OS CDD №9 (v0.18.0): базовый HTTP-путь Ring 3
# ============================================================================
# peload curl.exe http://example.com через SLIRP:
#   ОЖИДАЕТ: DNS-резолв → TCP-хендшейк → HTTP GET → тело «Example Domain»
#            → чистый ExitProcess(0)
#   ЗАПРЕЩЕНО: CPU EXCEPTION / FRAME-GUARD / kernel-panic (инвариант CDD №9)
# ============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, load_testfile, check_fatal


def main():
    initrd = build_cpio({
        "curl.exe": load_testfile("curl.exe"),
    })
    vm = VM("pe-run4", initrd, timeout=240)
    vm.start()
    try:
        # 1. Дождаться приглашения оболочки (бут: enrollment+PUF+VNET)
        t = vm.wait_for("Interactive Shell", timeout=90)
        if t is None:
            print("FAIL: shell не загрузился (90с)")
            return 1

        # 2. Запустить curl в Ring 3
        vm.type_cmd("dbg1")
        vm.type_cmd("peload curl.exe http://example.com")

        # 3. Ключевые маркеры полного цикла
        got_dns = vm.wait_for("Resolved", timeout=60)
        got_body = vm.wait_for("Example Domain", timeout=120)
        got_exit = vm.wait_for("ExitProcess(0", timeout=120)

        fatal = check_fatal(vm)

        print("=" * 60)
        print("pe-run4 (HTTP loopback):")
        print("  DNS resolve:      %s" % ("OK" if got_dns else "MISS"))
        print("  HTTP body:        %s" % ("OK" if got_body else "MISS"))
        print("  ExitProcess(0):   %s" % ("OK" if got_exit else "MISS"))
        print("  fatal markers:    %s" % (fatal if fatal else "none"))
        print("=" * 60)

        ok = got_body is not None and got_exit is not None and not fatal
        print("RESULT: %s" % ("PASS" if ok else "FAIL"))
        return 0 if ok else 1
    finally:
        vm.stop()


if __name__ == "__main__":
    sys.exit(main())
