#!/usr/bin/env python3
# ============================================================================
# sysharness-e2e.py — CDD №12 p11: SYSCALL-DIFF VM-прогон Vulkan-харнесса.
# ============================================================================
# Тот же бинарник (scripts/e2e/sysharness.c), что идёт на host Linux под
# strace (эталон): vkCreateInstance → lvp → vkCreateDevice →
# vkCreateComputePipelines (LLVM-JIT компиляция шейдера — фаза краша
# libLLVM DenseMap-tombstone в gamescope-прогоне) → dispatch → teardown.
# Здесь: ltrace ON → elfload usr/bin/sysharness → [L]-фронт syscall'ов —
# вход дифференциального движка scripts/e2e/syscall-diff.py.
# ============================================================================
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal, KERNEL, QEMU_FULL

PASS = []
FAIL = []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ROOT = os.path.join(REPO, "cachyos-root", "root")
REPORT = os.path.join(REPO, "cachyos-root", "report.json")
HARNESS = os.path.join(REPO, "scripts", "e2e", "sysharness")

if not os.path.exists(HARNESS):
    print("FATAL: sysharness не собран — gcc scripts/e2e/sysharness.c (см. sysharness.c)")
    sys.exit(1)
if not os.path.exists(KERNEL):
    print("FATAL: ядро не собрано — zig build")
    sys.exit(1)

import json

with open(REPORT) as f:
    report = json.load(f)
libs = report["libs"]

# ─── 1. rootfs: харнесс + ld.so + либы + ICD (абс. путь) + /proc + /sys ─────
files = {}
symlinks = {}
with open(HARNESS, "rb") as f:
    files["usr/bin/sysharness"] = f.read()
with open(os.path.join(ROOT, "usr/lib/ld-linux-x86-64.so.2"), "rb") as f:
    files["usr/lib/ld-linux-x86-64.so.2"] = f.read()
symlinks["lib64/ld-linux-x86-64.so.2"] = "/usr/lib/ld-linux-x86-64.so.2"
for soname in libs:
    p = os.path.join(ROOT, "usr/lib", soname)
    if os.path.exists(p):
        with open(p, "rb") as f:
            files["usr/lib/" + soname] = f.read()

# ICD-манифест: library_path → АБСОЛЮТНЫЙ (лоадер резолвит относительный
# от манифеста; в initrd манифест лежит не рядом с либой)
for _pth in report.get("extra_files", []):
    pth = _pth
    if not os.path.exists(pth):
        _idx = _pth.find("cachyos-root/")
        if _idx >= 0:
            pth = os.path.join(REPO, "cachyos-root", _pth[_idx + len("cachyos-root/"):])
    if os.path.exists(pth):
        with open(pth, "rb") as f:
            j = f.read().decode("utf-8")
        for soname in ("libvulkan_lvp.so", "libvulkan_lavapipe.so"):
            if '"library_path": "%s"' % soname in j:
                j = j.replace('"library_path": "%s"' % soname,
                              '"library_path": "/usr/lib/%s"' % soname)
        files["usr/share/vulkan/icd.d/" + os.path.basename(pth)] = j.encode()
        break

# /proc + /sys-псевдодерево (как в drm-gamescope: llvmpipe/LLVM читают
# топологию CPU; glibc sysconf-фолбэки)
SYS_DIRS = [
    "sys", "sys/dev", "sys/dev/char",
    "sys/devices", "sys/devices/system", "sys/devices/system/cpu",
    "sys/devices/system/cpu/cpu0",
    "sys/devices/system/cpu/cpu0/cpufreq",
]
for d in SYS_DIRS:
    files.pop(d, None)
files["sys/devices/system/cpu/online"] = b"0\n"
files["sys/devices/system/cpu/offline"] = b"\n"
files["sys/devices/system/cpu/possible"] = b"0\n"
files["sys/devices/system/cpu/present"] = b"0\n"
files["sys/devices/system/cpu/kernel_max"] = b"255\n"
files["sys/devices/system/cpu/cpu0/online"] = b"1\n"
files["sys/devices/system/cpu/cpu0/topology/core_id"] = b"0\n"
files["sys/devices/system/cpu/cpu0/topology/physical_package_id"] = b"0\n"
files["sys/devices/system/cpu/cpu0/topology/thread_siblings"] = b"00000001\n"
files["proc/cpuinfo"] = (
    b"processor\t: 0\nvendor_id\t: GenuineIntel\n"
    b"cpu family\t: 6\nmodel\t\t: 126\nmodel name\t: POLER-OS Virtual CPU (QEMU max)\n"
    b"stepping\t: 3\nmicrocode\t: 0x1\ncpu MHz\t\t: 2400.000\n"
    b"cache size\t: 4096 KB\nphysical id\t: 0\nsiblings\t: 1\n"
    b"core id\t\t: 0\ncpu cores\t: 1\napicid\t\t: 0\n"
    b"initial apicid\t: 0\nfpu\t\t: yes\n"
    b"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca "
    b"cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb "
    b"rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology "
    b"cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 "
    b"sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor "
    b"lahf_lm abm 3dnowprefetch cpuid_fault invpcd_single ibrs_enh "
    b"avx2 avx512f avx512dq rdseed adx smap clflushopt clwb sha_ni "
    b"xsaveopt xsavec xgetbv1 xs umip pku ospke gfni vaes vpclmulqdq "
    b"cmp_legacy ds fsqm\n"
    b"bugs\t\t:\nbogomips\t: 4800.00\n"
    b"clflush size\t: 64\ncache_alignment\t: 64\n"
    b"address sizes\t: 40 bits physical, 48 bits virtual\n"
    b"power management:\n\n"
)
print(f"rootfs: {len(files)} файлов, {sum(len(v) for v in files.values())/1024/1024:.1f} МБ")

# ─── CPIO-кеш (сборка 246МБ ≈ минуты; ключ — mtimes харнесса+либ) ──────────
import hashlib as _hl

_cache_path = os.path.join(REPO, "cachyos-root", "sysharness.initrd.cpio")
_h = _hl.sha256()
_h.update(open(HARNESS, "rb").read())
for _p in [os.path.join(ROOT, "usr/lib/ld-linux-x86-64.so.2"), REPORT]:
    if os.path.exists(_p):
        _h.update(str(os.path.getmtime(_p)).encode())
        _h.update(str(os.path.getsize(_p)).encode())
for _soname in libs:
    _p = os.path.join(ROOT, "usr/lib", _soname)
    if os.path.exists(_p):
        _h.update(str(os.path.getmtime(_p)).encode())
        _h.update(str(os.path.getsize(_p)).encode())
_cache_key = _h.hexdigest()

if os.path.exists(_cache_path) and os.path.getsize(_cache_path) > 10_000_000:
    with open(_cache_path, "rb") as _f:
        _blob = _f.read()
    if _blob[: 64].decode("ascii", "ignore").strip() == _cache_key:
        INITRD = _blob[64:]
        print(f"cpio-cache: HIT ({len(INITRD)/1024/1024:.1f} МБ)")
    else:
        _blob = None
else:
    _blob = None
if _blob is None:
    INITRD = build_cpio(files, symlinks, dirs=SYS_DIRS)
    with open(_cache_path, "wb") as _f:
        _f.write(_cache_key.encode("ascii"))
        _f.write(INITRD)
    print(f"cpio-cache: MISS — собран и записан ({len(INITRD)/1024/1024:.1f} МБ)")
del files, symlinks

# ─── 2. QEMU + ltrace + запуск ──────────────────────────────────────────────
vm = VM("sysharness", initrd=INITRD, mem=os.environ.get("E2E_MEM", "2G"),
        qemu=(QEMU_FULL if os.environ.get("E2E_QEMU") == "full" else None),
        extra_args=["-cpu", "max",
                    # CDD №12 p11: gdb-stub для p11-watch.py (write-watchpoint
                    # на детерминированную JIT-страницу — «кто пишет нули»)
                    *(["-s"] if os.environ.get("E2E_GDB") else []),
                    *(["-d", "int,cpu_reset", "-D", "/tmp/qint.log"] if os.environ.get("E2E_QINT") else []),
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
                      if os.environ.get("E2E_PLUGIN") else [])])
del INITRD
try:
    vm.start()
    # Маркер бута: строка-баннер интерактивного шелла (НЕ "Shell started" —
    # этого маркера в serial-выводе нет; gamescope-e2e спасается [EVDEV]-фолбэком)
    t = vm.wait_for("Interactive Shell", timeout=int(os.environ.get("E2E_BOOT_TIMEOUT", "120")))
    if t is None:
        t = vm.wait_for("poler>", timeout=10)
    if t is None:
        check("boot: shell ready", False)
        print(vm.text()[-3000:])
        sys.exit(1)
    check("boot: shell ready", True)
    check("boot: no fatal markers", not check_fatal(vm))

    vm.type_cmd("ltrace")
    vm.type_cmd("elfload usr/bin/sysharness")

    # ждём: маркеры харнесса / краш / таймаут (LLVM под TCG = минуты)
    deadline = time.time() + int(os.environ.get("E2E_DRILL", "1500"))
    deadline_hit = None
    seen_markers = []
    while time.time() < deadline:
        t = vm.text()
        for m in re.findall(r"HARNESS-[A-Z0-9-]+(?:\s+\S+)?", t):
            if m not in seen_markers:
                seen_markers.append(m)
                print(f"MARK: {m}")
        if "HARNESS-DONE" in t:
            deadline_hit = "done"
            break
        if "HARNESS-FAIL" in t:
            deadline_hit = "fail"
            break
        if "CPU EXCEPTION" in t or "Fatal" in t:
            deadline_hit = "crash"
            break
        if vm.proc and vm.proc.poll() is not None:
            deadline_hit = "qemu-died"
            break
        time.sleep(1.0)

    # краш-дамп должен допечататься (модель drm-gamescope-e2e)
    if deadline_hit == "crash":
        dump_deadline = time.time() + 45
        while time.time() < dump_deadline:
            t = vm.text()
            if "User process killed" in t or "Kernel fault" in t:
                print("DUMP: краш-отчёт допечатан")
                break
            if vm.proc and vm.proc.poll() is not None:
                break
            time.sleep(2.0)

    text = vm.text()
    print(f"--- исход: {deadline_hit} ---")

    # краш-контекст (CDD-артефакт): RIP + первые строки дампa
    idx = text.find("=== ELF Load & Run")
    if idx >= 0:
        print("--- RUN LOG (первые 2500 симв.) ---")
        print(text[idx:idx + 2500])
        print("--- -------------------------- ---")
    cidx = text.find("!!! CPU EXCEPTION !!!")
    if cidx >= 0:
        print("--- CRASH HEADER ---")
        print(text[cidx:cidx + 1800])
        print("--- -------------- ---")

    # ─── 3. [L]-гистограмма (вход syscall-diff) ─────────────────────────────
    ltrace_lines = re.findall(r"\[L\] (\d+)\(", text)
    hist = {}
    for n in ltrace_lines:
        hist[int(n)] = hist.get(int(n), 0) + 1
    print(f"--- [L]-гистограмма ({len(ltrace_lines)} вызовов): "
          f"{dict(sorted(hist.items(), key=lambda kv: -kv[1]))} ---")

    check("sysharness: ltrace-фронт снят (>100 syscall)", len(ltrace_lines) > 100)
    check("sysharness: INSTANCE создан", "HARNESS-INSTANCE" in text)
    if deadline_hit == "done":
        check("sysharness: полный прогон DONE (LLVM-JIT прошёл)", True)
    elif deadline_hit == "crash":
        check("sysharness: краш-лог собран (CDD-итерация)", True)
        check("sysharness: PIPELINE достигнут (LLVM-JIT фаза)", "HARNESS-PIPELINE" in text)
    elif deadline_hit == "fail":
        print(f"FAIL-маркер: {re.findall(r'HARNESS-FAIL[^\n]*', text)}")
        check("sysharness: FAIL-маркер (см. выше)", False)
    else:
        check("sysharness: полный прогон DONE", False)

    check("sysharness: no kernel panic", "kernel-panic" not in text and "Halting" not in text)
finally:
    vm.stop()

print("\n=== SYSHARNESS: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
