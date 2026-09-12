#!/usr/bin/env python3
# ============================================================================
# pacman-e2e.py — CDD #17: ПОЛНОЦЕННЫЙ сетевой pacman в POLER-OS
# ============================================================================
# Что доказывает (реальная сеть через SLIRP + реальное зеркало Arch):
#   1. pacman -Sy     — HTTP GET core.db (130КБ) → gzip → ALPM-парсер
#   2. pacman -S pkg  — резолв → HTTP GET .pkg.tar.zst → zstd → tar → VFS
#   3. cat /etc/...   — файлы УСТАНОВЛЕНЫ в RAM-overlay (чтение через VFS)
#   4. Ring 3 (sh)    — pacman -Q через syscall-gate 1000 (kernel transaction)
#
# Маркеры (serial, БЕЗ ANSI):
#   [PAC] sync OK: N packages (core)
#   [PAC] PACMAN-OK / [PAC] PACMAN-FAIL: <причина>
#
# Пакет: pacman-mirrorlist (6.6КБ, БЕЗ зависимостей — идеален для RAM-модели).
# Запуск: python3 scripts/e2e/pacman-e2e.py
# ============================================================================

import os, sys, subprocess, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, KERNEL

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PKG = "pacman-mirrorlist"  # 6.6КБ, 0 зависимостей


def rebuild_sh():
    """Пересобрать userspace/sh (static-pie), если исходник новее."""
    src = os.path.join(REPO, "userspace", "sh.c")
    bin_ = os.path.join(REPO, "userspace", "sh")
    if os.path.exists(bin_) and os.path.getmtime(bin_) >= os.path.getmtime(src):
        return bin_
    subprocess.check_call([
        "gcc", "-O2", "-nostdlib", "-fPIE", "-Wl,-pie,--no-dynamic-linker",
        "-fno-stack-protector", "-o", bin_, src,
    ])
    return bin_


def main():
    failures = []

    sh_bin = rebuild_sh()
    with open(sh_bin, "rb") as f:
        sh_data = f.read()

    # initrd: bin/sh (Ring 3-полигон) + минимальная структура
    initrd = build_cpio(
        files={"bin/sh": sh_data},
        dirs=["bin", "dev", "tmp", "usr", "usr/bin", "etc"],
    )

    print("[e2e] boot POLER-OS (virtio-net SLIRP → реальный HTTP)...")
    vm = VM("pacman-e2e", initrd=initrd, mem="2G", timeout=90)
    vm.start()

    try:
        # ── 0. boot → Ring 3 /bin/sh (авто-спавн) ──
        t = vm.wait_for("Ring 3 POSIX", timeout=60)
        if t is None:
            failures.append("boot: баннер Ring 3 sh не найден")
            return finish(vm, failures)
        print("[e2e] boot OK (Ring 3 /bin/sh)")
        time.sleep(1)  # промпт готов

        # ── 1. pacman -Sy (реальный HTTP: DNS + TCP + 130КБ core.db) ──
        print("[e2e] pacman -Sy (реальный core.db с зеркала)...")
        vm.type_cmd("pacman -Sy")
        t = vm.wait_for("[PAC] sync OK", timeout=150)
        if t is None:
            failures.append("-Sy: маркер sync OK не найден (DNS/TCP/HTTP?)")
            return finish(vm, failures)
        print("[e2e] -Sy OK (БД синхронизирована)")

        # ── 2. pacman -S pacman-mirrorlist (скачать+распаковать+VFS) ──
        print(f"[e2e] pacman -S {PKG} (реальный .pkg.tar.zst)...")
        vm.type_cmd(f"pacman -S {PKG}")
        # ВАЖНО: маркер ищем ПОСЛЕ последнего gate: -S (PACMAN-OK уже маячит
        # от -Sy — эмпирика probe-сессии: wait_for матчил СТАРЫЙ маркер)
        t = vm.wait_for("[PAC] install OK", timeout=180)
        if t is None:
            t2 = vm.text() or ""
            failures.append("-S: PACMAN-OK не найден; хвост: %r" % t2[-600:])
            return finish(vm, failures)
        print(f"[e2e] -S OK ({PKG} установлен в RAM-overlay)")

        # ── 3. cat файла пакета: содержимое через VFS ──
        print("[e2e] cat /etc/pacman.d/mirrorlist (файл из пакета)...")
        vm.type_cmd("cat /etc/pacman.d/mirrorlist")
        t = vm.wait_for("Server", timeout=20)
        if t is None:
            failures.append("cat: файл пакета не читается (VFS overlay?)")
        else:
            print("[e2e] cat OK — файлы пакета в VFS")

        # ── 4. pacman -Q (тот же Ring 3 gate — список установленного) ──
        print("[e2e] pacman -Q (список установленных)...")
        vm.type_cmd("pacman -Q")
        t = vm.wait_for(PKG, timeout=60)
        if t is None:
            failures.append("-Q: пакет не виден (gate/state?)")
        else:
            print("[e2e] pacman -Q OK")
    finally:
        finish(vm, failures)


def finish(vm, failures):
    t = vm.text()
    print("\n===== serial tail =====")
    print(t[-1200:] if t else "<нет лога>")
    print("=======================\n")
    vm.stop()
    if failures:
        for f in failures:
            print("FAIL:", f)
        sys.exit(1)
    print("PASS: pacman-e2e — полноценный сетевой установщик (CDD #17)")
    sys.exit(0)


if __name__ == "__main__":
    main()
