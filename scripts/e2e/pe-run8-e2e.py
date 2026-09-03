#!/usr/bin/env python3
# ============================================================================
# pe-run8-e2e.py — POLER-OS CDD №9 (v0.18.0): 7-Zip LZMA + curl→FAT32 RW
# ============================================================================
# Матрица (МОМЕНТ ИСТИНЫ №8 + FAT32 RW, диск VirtIO-Blk):
#   1. peload 7za.exe b -mmt1   → LZMA-бенчмарк в Ring 3 → ExitProcess(0)
#   2. peload curl.exe -o index.html http://example.com → [VFS] write: FAT32
#   3. cat index.html → «Example Domain» (данные с ДИСКА, не из кеша curl)
#   ЗАПРЕЩЕНО: CPU EXCEPTION / FRAME-GUARD / kernel-panic
# ============================================================================

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, build_fat32, load_testfile, check_fatal


def main():
    initrd = build_cpio({
        "7za.exe": load_testfile("7za.exe"),
        "curl.exe": load_testfile("curl.exe"),
    })
    disk = build_fat32(total_sectors=65536)  # 32MB
    vm = VM("pe-run8", initrd, disk=disk, timeout=420)
    vm.start()
    try:
        t = vm.wait_for("Interactive Shell", timeout=90)
        if t is None:
            print("FAIL: shell не загрузился (90с)")
            return 1
        t = vm.wait_for("FAT32] Mounted", timeout=30)
        if t is None:
            print("FAIL: FAT32 не смонтировалась (нет virtio-blk?)")
            return 1

        # ── 1. 7-Zip LZMA benchmark (mmt1) ──
        vm.type_cmd("peload 7za.exe b -mmt1")
        got_bench = vm.wait_for("Bench", timeout=180)
        got_7z_exit = vm.wait_for("ExitProcess(0", timeout=240)

        # ── 2. curl -o на FAT32 ──
        vm.type_cmd("peload curl.exe -o index.html http://example.com")
        got_write = vm.wait_for("[VFS] write: FAT32", timeout=180)
        got_curl_exit = vm.wait_for("ExitProcess(0", timeout=120)

        # ── 3. чтение с диска ──
        vm.type_cmd("cat index.html")
        got_read = vm.wait_for("Example Domain", timeout=60)

        # ls должен показать index.html
        vm.type_cmd("ls")
        got_ls = vm.wait_for("index.html", timeout=30)

        fatal = check_fatal(vm)

        print("=" * 60)
        print("pe-run8 (7za + curl -o + FAT32 RW):")
        print("  7za bench:        %s" % ("OK" if got_bench else "MISS"))
        print("  7za Exit(0):      %s" % ("OK" if got_7z_exit else "MISS"))
        print("  curl FAT32 write: %s" % ("OK" if got_write else "MISS"))
        print("  curl Exit(0):     %s" % ("OK" if got_curl_exit else "MISS"))
        print("  cat from disk:    %s" % ("OK" if got_read else "MISS"))
        print("  ls shows file:    %s" % ("OK" if got_ls else "MISS"))
        print("  fatal markers:    %s" % (fatal if fatal else "none"))
        print("=" * 60)

        ok = (got_7z_exit is not None and got_write is not None
              and got_read is not None and not fatal)
        print("RESULT: %s" % ("PASS" if ok else "FAIL"))
        return 0 if ok else 1
    finally:
        vm.stop()


if __name__ == "__main__":
    sys.exit(main())
