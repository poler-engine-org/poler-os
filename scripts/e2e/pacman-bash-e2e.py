#!/usr/bin/env python3
# ============================================================================
# pacman-bash-e2e.py — ШАГ 1+2 Linux-слоя: мульти-пакетная установка bash
# зависимостей + ЗАПУСК установленного динамического бинарника в Ring 3.
# ============================================================================
# Что доказывает (реальная сеть через SLIRP + реальное зеркало Arch):
#   1. pacman -Sy         — HTTP GET core.db (130КБ) → gzip → ALPM
#   2. pacman -S bash     — мульти-пакетная транзакция: resolveDeps →
#                           вся цепочка (glibc, ncurses, readline, bash…)
#                           скачивается/распаковывается/ставится в overlay
#   3. /usr/bin/bash      — execve в Ring 3: PT_INTERP ld-linux + libc.so.6
#                           из tmpfs-overlay (CDD #17-путь)
#   4. echo V-$BASH_VERSION / echo R-$((6*7)) — живой bash исполняет
#                           арифметику и выводит результат
#
# Маркеры (serial, БЕЗ ANSI):
#   [PAC] PACMAN-OK                 — транзакция завершена
#   [LINUX] execve: /usr/bin/bash   — handoff на установленный бинарник
#   V-5.                            — bash напечатал свою версию
#   R-42                            — bash посчитал 6*7
#
# Запуск: python3 scripts/e2e/pacman-bash-e2e.py
# ============================================================================

import os, sys, subprocess, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, KERNEL

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TARGET = os.environ.get("PAC_TARGET", "bash")


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

    initrd = build_cpio(
        files={"bin/sh": sh_data},
        dirs=["bin", "dev", "tmp", "usr", "usr/bin", "etc"],
    )

    print(f"[e2e] boot POLER-OS → мульти-пакетный {TARGET} + Ring 3 запуск...")
    # CDD #18-форензика: pcap всего SLIRP-юзернета (filter-dump на netdev n0)
    vm = VM(
        "pacman-bash-e2e", initrd=initrd, mem="1536M", timeout=180,
        extra_args=[
            "-object",
            "filter-dump,id=fdump,netdev=n0,file=/tmp/poler-e2e-pacman-bash-e2e/net.pcap",
        ],
    )
    vm.start()

    # локальный «метод» VM: свежая часть лога
    vm.wait_for_after = lambda marker, base, timeout=None: _wait_for_after(
        vm, marker, base, timeout)

    try:
        # ── 0. boot → Ring 3 /bin/sh ──
        t = vm.wait_for("Ring 3 POSIX", timeout=60)
        if t is None:
            failures.append("boot: баннер Ring 3 sh не найден")
            return finish(vm, failures)
        print("[e2e] boot OK (Ring 3 /bin/sh)")
        time.sleep(1)

        # ── 1. pacman -Sy (реальный HTTP: DNS + TCP + 130КБ core.db) ──
        print("[e2e] pacman -Sy (реальный core.db с зеркала)...")
        vm.type_cmd("pacman -Sy")
        t = vm.wait_for("[PAC] sync OK", timeout=150)
        if t is None:
            failures.append("-Sy: маркер sync OK не найден (DNS/TCP/HTTP?)")
            return finish(vm, failures)
        print("[e2e] -Sy OK (БД синхронизирована)")
        time.sleep(1)

        # ── 2. pacman -S bash — мульти-пакетная транзакция ──
        # glibc ~11МБ + ncurses + readline + bash ≈ 17МБ по HTTP. Таймаут
        # щедрый: медленный WAN + TCG-декомпрессия zstd.
        # ПАУЗА: хвост первой сессии (RST/retx-шторм SLIRP) утихает
        time.sleep(8)
        for attempt in range(3):
            print(f"[e2e] pacman -S {TARGET} (попытка {attempt+1}/3, вся цепочка)...")
            base = len(vm.text())  # маркеры ищем ТОЛЬКО после подачи команды
            vm.type_cmd(f"pacman -S {TARGET}")
            t = vm.wait_for_after("PACMAN-OK", base, timeout=700)
            if t is not None and "install OK: " + TARGET in t[base:]:
                break
            # не вышло: ждём отравленных хвостов перед повтором
            time.sleep(10)
        if t is None:
            failures.append(f"-S {TARGET}: PACMAN-OK не найден (download/zstd/VFS?)")
            return finish(vm, failures)
        if f"install OK: {TARGET}" not in t[base:]:
            failures.append(f"-S {TARGET}: install OK: {TARGET} не найден")
            return finish(vm, failures)
        # ПАКЕТОВ в плане: "Packages (N)" — цепочка должна быть >= 3
        import re
        m = re.search(r"Packages \((\d+)\)", t)
        npkgs = int(m.group(1)) if m else -1
        if npkgs < 3:
            failures.append(f"-S {TARGET}: цепочка подозрительно короткая: {npkgs}")
        else:
            print(f"[e2e] -S OK: {npkgs} пакетов в транзакции")
        time.sleep(2)

        # ── 3. execve /usr/bin/bash в Ring 3 ──
        print(f"[e2e] execve /usr/bin/{TARGET} (PT_INTERP из overlay)...")
        base = len(vm.text())
        vm.type_cmd(f"/usr/bin/{TARGET}")
        t = vm.wait_for_after(f"[LINUX] execve: /usr/bin/{TARGET}", base, timeout=60)
        if t is None:
            failures.append(f"execve: маркер запуска /usr/bin/{TARGET} не найден")
            return finish(vm, failures)
        print("[e2e] execve OK — ядро передало управление bash (ld.so handoff)")
        # glibc-инициализация под TCG небыстрая: дать bash'у подняться
        time.sleep(8)

        # ── 4. живой bash: версия ──
        print("[e2e] echo V-$BASH_VERSION в живом bash...")
        vm.type_cmd("echo V-$BASH_VERSION")
        t = vm.wait_for("V-5.", timeout=240)
        if t is None:
            failures.append("bash: версия не напечатана (ld.so/libc упали?)")
        else:
            print("[e2e] bash жив: BASH_VERSION напечатан")

        # ── 5. живой bash: арифметика ──
        print("[e2e] echo R-$((6*7)) в живом bash...")
        vm.type_cmd("echo R-$((6*7))")
        t = vm.wait_for("R-42", timeout=120)
        if t is None:
            failures.append("bash: арифметика $((6*7)) не дала R-42")
        else:
            print("[e2e] bash считает: R-42")

        return finish(vm, failures)
    finally:
        vm.stop()


def _wait_for_after(vm, marker, base, timeout=None):
    """Маркер в СВЕЖЕЙ части лога (после позиции base) — анти-матчинг
    старых маркеров от предыдущих команд (эмпирика: -Sy тоже печатает
    PACMAN-OK в конце — wait_for матчил ЕГО и скрипт ехал раньше времени)."""
    deadline = time.time() + (timeout or vm.timeout)
    while time.time() < deadline:
        t = vm.text()
        if marker in t[base:]:
            return t
        if vm.proc and vm.proc.poll() is not None:
            break
        time.sleep(0.25)
    return None


def finish(vm, failures):
    t = vm.text()
    print("\n===== RESULT: %s =====" % ("PASS" if not failures else "FAIL"))
    for f in failures:
        print("  FAIL: %s" % f)
    # хвост serial для отладки
    tail = t[-3000:]
    print("\n===== serial tail =====\n%s\n=======================" % tail)
    return len(failures) == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
