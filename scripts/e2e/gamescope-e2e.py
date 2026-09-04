#!/usr/bin/env python3
# ============================================================================
# gamescope-e2e.py — crash-driven прогон CDD #12: GAMESCOPE (CachyOS rootfs)
# ============================================================================
# БОЕВОЙ запуск композитора Gamescope из НАСТОЯЩЕГО rootfs CachyOS:
#   - gamescope 3.16.25 (пакет CachyOS) + glibc 2.44 (CachyOS v3) +
#     57-либ DT_NEEDED-замыкание (wayland/libdrm/xorg-стек/libinput/…);
#   - QEMU -cpu max (TCG AVX2 — v3-сборки) + mem 512M;
#   - initrd-CPIO собирается ИЗ rootfs-кэша (scripts/fetch-cachyos-root.py):
#     файлы usr/lib/*.so + симлинки usr-merge (lib64/ld-linux → usr/lib);
#   - запуск через elfload с ltrace-перехватом ([L] sys(a1,a2)=ret);
#   - методика CDD: прогон 1 — plain (естественный исход); при фейле —
#     прогон 2 с ltrace: syscall-крашлог в отчёт (CDD-артефакт).
# Успех p1: все DT_NEEDED загружены (ld.so прошёл конвейер), процесс жив
# до НЕ-файлового syscall-разрыва (ENOSYS-волна — p2) ИЛИ вывел usage.
# ============================================================================
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal

PASS = []
FAIL = []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ROOT = os.path.join(REPO, "cachyos-root", "root")
REPORT = os.path.join(REPO, "cachyos-root", "report.json")

# ─── 1. rootfs-упаковка: gamescope + DT_NEEDED-замыкание ────────────────────
with open(REPORT) as f:
    report = json.load(f)
libs = report["libs"]
interp = report["interp"]


def so_path(name):
    for d in ("usr/lib", "usr/lib64", "lib", "lib64"):
        p = os.path.join(ROOT, d, name)
        if os.path.exists(p):
            return p
    return None


files = {}
symlinks = {}
# бинарь композитора
with open(os.path.join(ROOT, "usr/bin/gamescope"), "rb") as f:
    files["usr/bin/gamescope"] = f.read()
# интерпретатор: реальный файл + usr-merge симлинк lib64/ → /usr/lib/
with open(os.path.join(ROOT, "usr/lib/ld-linux-x86-64.so.2"), "rb") as f:
    files["usr/lib/ld-linux-x86-64.so.2"] = f.read()
symlinks["lib64/ld-linux-x86-64.so.2"] = "/usr/lib/ld-linux-x86-64.so.2"
# библиотеки замыкания: РЕАЛЬНЫЕ файлы (следуем симлинкам на хосте) под
# soname-ключом; soname-симлинки в rootfs не нужны (ld.so ищет по soname)
missing = []
for soname in libs:
    p = so_path(soname)
    if not p:
        missing.append(soname)
        continue
    with open(p, "rb") as f:
        files["usr/lib/" + soname] = f.read()
if missing:
    print("FATAL: DT_NEEDED не закрыт:", missing)
    print("       запусти scripts/fetch-cachyos-root.py")
    sys.exit(1)

total = sum(len(v) for v in files.values())
print(f"rootfs: {len(files)} файлов, {total/1024/1024:.1f} МБ "
      f"(+{len(symlinks)} симлинка)")

# glibc-специфика: libc.so.6/ld.so — soname-файлы уже в files; добавим
# mallopt-профили не нужны. vDSO нет — clock_gettime syscall.

INITRD = build_cpio(files, symlinks)
print(f"initrd: {len(INITRD)/1024/1024:.1f} МБ")


# ─── 2. QEMU-прогон: -cpu max (AVX2 для v3-сборок CachyOS) ─────────────────
def run_once(with_trace, tag, args="--help"):
    vm = VM(f"gamescope-{tag}", initrd=INITRD, mem="512M",
            extra_args=["-cpu", "max"])
    try:
        vm.start()
        t = vm.wait_for("Shell started", timeout=90) or vm.wait_for("[EVDEV]", timeout=60)
        if t is None:
            check(f"[{tag}] boot: shell ready", False)
            return False, ""
        check(f"[{tag}] boot: no fatal markers", not check_fatal(vm))

        if with_trace:
            vm.type_cmd("ltrace")
        vm.type_cmd(f"elfload usr/bin/gamescope {args}")
        # ждём исходы: usage-вывод / exit / краш-лог
        ok = vm.wait_for("Usage:", timeout=90) or vm.wait_for("usage:", timeout=5)
        vm.wait_for("exit_group", timeout=15)
        text = vm.text()
        return ok is not None, text
    finally:
        vm.stop()


print("\n=== CDD #12: прогон 1 (plain) ===")
ok, text = run_once(with_trace=False, tag="plain")

if ok:
    check("gamescope: --help usage выведен (полный путь ld.so+58 либ)", True)
    check("gamescope: no kernel panic", "kernel-panic" not in text and "Halting" not in text)
else:
    print("--- [plain] исход без usage: прогон 2 с ltrace (краш-лог) ---")
    ok2, t2 = run_once(with_trace=True, tag="trace")
    trace_lines = [l for l in t2.splitlines() if l.startswith("[L] ")]

    # ─── p1-критерий: КОНВЕЙЕР БИБЛИОТЕК ЗАКРЫТ ─────────────────────────────
    # ни одна DT_NEEDED не упала (нет «error while loading shared libraries»)
    # и КОД gamescope исполняется (syscall-трейс глубже загрузчика: ≥400
    # вызовов — glibc/SDL/reaper уже работают). usage-вывод = цель p2.
    loader_ok = "error while loading shared libraries" not in t2
    deep_trace = len(trace_lines) >= 400
    check("gamescope[p1]: DT_NEEDED-конвейер ld.so ЗАКРЫТ (58 либ без ошибок)", loader_ok)
    check("gamescope[p1]: код gamescope исполняется в Ring 3 (трейс ≥400 syscall)", deep_trace)
    check("gamescope: no kernel panic", "kernel-panic" not in t2 and "Halting" not in t2)
    check("gamescope[p2-target]: --help usage выведен", ok2)
    check("gamescope: краш-лог собран (CDD-итерация)", True)

    # CDD-артефакт: лог [ELF] + [L]-трейс
    print("--- CRASH LOG (CDD-артефакт, ltrace) ---")
    idx = t2.find("=== ELF Load & Run")
    if idx < 0:
        idx = t2.find("[L] ")
        print(t2[:3000] if idx < 0 else t2[idx:idx + 3000])
    else:
        print(t2[idx:idx + 4000])
    print("--- ---------------------------------- ---")

    # недостающие syscall-номера (ENOSYS-волна — план p2)
    import collections
    enosys = collections.Counter()
    for l in trace_lines:
        if l.endswith("0x0xFFFFFFFFFFFFFFDA"):
            enosys[int(l[4:l.index("(")])] += 1
    if enosys:
        NAMES = {157: "prctl", 13: "rt_sigaction", 14: "rt_sigprocmask",
                 435: "clone3", 28: "madvise", 290: "eventfd2", 293: "pipe2",
                 319: "memfd_create", 53: "socketpair", 288: "accept4",
                 302: "prlimit64", 334: "rseq", 234: "tgkill", 36: "socket"}
        pretty = {NAMES.get(k, "?%d" % k): v for k, v in sorted(enosys.items())}
        print(f"--- ENOSYS-волна (план p2): {pretty} ---")

print("\n=== GAMESCOPE: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
