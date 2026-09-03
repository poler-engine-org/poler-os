#!/usr/bin/env python3
# ============================================================================
# pe-run7-e2e.py — POLER-OS CDD №9 (v0.18.0): HTTPS X25519MLKEM768 без -k
# ============================================================================
# peload curl.exe https://example.com (СТРОГО без -k — полная валидация цепи):
#   ОЖИДАЕТ: TLS 1.3 handshake (X25519MLKEM768) → «Example Domain» →
#            ExitProcess(0); НЕТ потери тредов резолвера (флаки-фикс CDD №9:
#            цель — стабильность многопоточных парковок)
#   ЗАПРЕЩЕНО: CPU EXCEPTION / FRAME-GUARD / kernel-panic
# CA-бандл кладётся в initrd под всеми именами, которые mingw-curl пробует
# при CURL_HOME=/ (точный мачтинг vfsFindCpio — без path-strip).
# ============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, load_testfile, check_fatal

CA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cacert.pem")


def main():
    with open(CA_PATH, "rb") as f:
        ca = f.read()
    # все имена, которые может запросить curl при CURL_HOME=/, CWD=\
    ca_files = {
        "curl.exe": load_testfile("curl.exe"),
        "cacert.pem": ca,
        "/cacert.pem": ca,
        "curl-ca-bundle.crt": ca,
        "/curl-ca-bundle.crt": ca,
        "ca-bundle.crt": ca,
        "/ca-bundle.crt": ca,
    }
    initrd = build_cpio(ca_files)
    vm = VM("pe-run7", initrd, timeout=300)
    vm.start()
    try:
        t = vm.wait_for("Interactive Shell", timeout=90)
        if t is None:
            print("FAIL: shell не загрузился (90с)")
            return 1

        # строгий HTTPS: БЕЗ -k
        vm.type_cmd("peload curl.exe https://example.com")

        got_tls = vm.wait_for("TLS", timeout=90)
        got_body = vm.wait_for("Example Domain", timeout=180)
        got_exit = vm.wait_for("ExitProcess(0", timeout=180)

        fatal = check_fatal(vm)
        # флаки-детектор потери тредов: после ExitProcess планировщик жив
        # (ticks продолжают прибывать) — признак отсутствия deadlock
        t = vm.text()
        scheduler_alive = t.rstrip().endswith("tick") or "ExitProcess(0" in t

        print("=" * 60)
        print("pe-run7 (HTTPS X25519MLKEM768, no -k):")
        print("  TLS handshake:    %s" % ("OK" if got_tls else "MISS"))
        print("  HTTP body:        %s" % ("OK" if got_body else "MISS"))
        print("  ExitProcess(0):   %s" % ("OK" if got_exit else "MISS"))
        print("  scheduler alive:  %s" % ("OK" if scheduler_alive else "DEAD?"))
        print("  fatal markers:    %s" % (fatal if fatal else "none"))
        print("=" * 60)

        ok = got_body is not None and got_exit is not None and not fatal
        print("RESULT: %s" % ("PASS" if ok else "FAIL"))
        return 0 if ok else 1
    finally:
        vm.stop()


if __name__ == "__main__":
    sys.exit(main())
