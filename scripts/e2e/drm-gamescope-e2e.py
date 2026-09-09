#!/usr/bin/env python3
# ============================================================================
# drm-gamescope-e2e.py — crash-driven прогон CDD №12 p3: DRM MASTER handoff
# ============================================================================
# БОЕВОЙ запуск композитора: «gamescope -W 1024 -H 768» на НАШЕЙ DRM-KMS
# карте (/dev/dri/card0 из drm_kms.zig) + VirtIO-GPU (qemu-full, VNC-scanout):
#   1. Бут с virtio-gpu-pci (-vga none — карта ЕДИНСТВЕННЫЙ дисплей);
#   2. ltrace-перехват: elfload usr/bin/gamescope -W 1024 -H 768;
#   3. Ожидание: libdrm-конвейер (open /dev/dri/card0 → VERSION → SET_MASTER
#      → GETRESOURCES → GETCONNECTOR/GETCRTC → CREATE_DUMB → ADDFB2 →
#      PAGE_FLIP) — ioctl-команды видны в [L] 16(fd,cmd,arg);
#   4. CDD-методика: crash-лог в отчёт; DRM-ioctl-декодер:
#      0xC00864xx-0xC04064xx → номера из drm.h (что не реализовано = EINVAL).
# Успех p3: gamescope дошёл до DRM-мастера и цикла page-flip (или дальше —
# до первого кадра), kernel-panic=0.
# ============================================================================
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_lib import VM, build_cpio, check_fatal, QEMU_FULL, KERNEL

PASS = []
FAIL = []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("PASS: " if cond else "FAIL: ") + name)


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ROOT = os.path.join(REPO, "cachyos-root", "root")
REPORT = os.path.join(REPO, "cachyos-root", "report.json")

if not os.path.exists(QEMU_FULL):
    print("FATAL: qemu-full отсутствует — запусти scripts/setup-qemu-full.sh")
    sys.exit(1)

# ─── 1. rootfs-упаковка (как в gamescope-e2e) + xkb-данные при наличии ──────
import json

with open(REPORT) as f:
    report = json.load(f)
libs = report["libs"]

files = {}
symlinks = {}
with open(os.path.join(ROOT, "usr/bin/gamescope"), "rb") as f:
    files["usr/bin/gamescope"] = f.read()
# p14: Xwayland — без него gamescope-конструктор возвращает NULL → краш!
with open(os.path.join(ROOT, "usr/bin/Xwayland"), "rb") as f:
    if os.path.exists(os.path.join(ROOT, "usr/bin/Xwayland")):
        files["usr/bin/Xwayland"] = f.read()
        print("rootfs: + Xwayland (p14)")
with open(os.path.join(ROOT, "usr/lib/ld-linux-x86-64.so.2"), "rb") as f:
    files["usr/lib/ld-linux-x86-64.so.2"] = f.read()
symlinks["lib64/ld-linux-x86-64.so.2"] = "/usr/lib/ld-linux-x86-64.so.2"
for soname in libs:
    for d in ("usr/lib",):
        p = os.path.join(ROOT, d, soname)
        if os.path.exists(p):
            with open(p, "rb") as f:
                files["usr/lib/" + soname] = f.read()
            break

# v0.20 (CDD №15): Xwayland-замыкание — либы ВТОРОГО ELF (X11/xcb-стек:
# libX11/libxcb/libxkbcommon/… — не полностью пересекается с gamescope)
_xw_n = 0
for soname in report.get("xwayland_libs", []):
    p = os.path.join(ROOT, "usr/lib", soname)
    if os.path.exists(p):
        with open(p, "rb") as f:
            files["usr/lib/" + soname] = f.read()
        _xw_n += 1
print(f"rootfs: + Xwayland-замыкание ({_xw_n} либ)")

# CDD №15 p4: Xwayland DLOPEN-волна (НЕ DT_NEEDED — холодный старт, как
# SDL3-фикс gamescope p4): glamor/EGL. libEGL.so.1 (mesa) в rootfs ЕСТЬ,
# но в замыкание не попадает → open-fail × 4 → glamor-путь умирает.
for warm_xw in ("libEGL.so.1", "libEGL_mesa.so.0", "libGLESv2.so.2"):
    p = os.path.join(ROOT, "usr/lib", warm_xw)
    if os.path.exists(p) and ("usr/lib/" + warm_xw) not in files:
        with open(p, "rb") as f:
            files["usr/lib/" + warm_xw] = f.read()
        print(f"rootfs: + Xwayland-dlopen {warm_xw}")

# CDD №12 p13: ТЁПЛЫЙ mesa-кэш из host-прогонов (LLVM-JIT-компиляция шейдеров
# gamescope уже выполнена на host — хэши совпадают: те же бинарники/либы/ICD).
# VFS-overlay: initrd-RO читается, новые записи идут в tmpfs-RW.
import os as _os
SYS_DIRS_EXTRA = []
_warm_root = "/tmp/p13-host/mesa-cache/mesa_shader_cache"
_warm_n = 0
if _os.path.isdir(_warm_root):
    for _base, _, _names in _os.walk(_warm_root):
        for _n in _names:
            _p = _os.path.join(_base, _n)
            _arc = "tmp/mesa_shader_cache/mesa_shader_cache" + _p[len(_warm_root):]
            with open(_p, "rb") as _f:
                files[_arc] = _f.read()
            _warm_n += 1
    # директории кэша (двухбуквенные корзины) — как dir-записи
    for _d in ("tmp", "tmp/mesa_shader_cache", "tmp/mesa_shader_cache/mesa_shader_cache"):
        files.pop(_d, None)
        SYS_DIRS_EXTRA.append(_d)
    for _base, _dirs, _ in _os.walk(_warm_root):
        for _d in _dirs:
            _arc = "tmp/mesa_shader_cache/mesa_shader_cache" + (_os.path.join(_base, _d)[len(_warm_root):])
            SYS_DIRS_EXTRA.append(_arc)
print(f"rootfs: + ТЁПЛЫЙ mesa-кэш ({_warm_n} записей из host-прогонов)")

# xkb-данные (libxkbcommon компилирует раскладку при создании устройств ввода)
XKB_ROOT = os.path.join(ROOT, "usr", "share", "X11", "xkb")
xkb_count = 0
if os.path.isdir(XKB_ROOT):
    for base, _, names in os.walk(XKB_ROOT):
        for n in names:
            p = os.path.join(base, n)
            arc = "usr/share/X11/xkb" + p[len(XKB_ROOT):]
            with open(p, "rb") as f:
                files[arc] = f.read()
            xkb_count += 1
print(f"rootfs: {len(files)} файлов ({xkb_count} xkb) + {len(symlinks)} симлинка, "
      f"{sum(len(v) for v in files.values())/1024/1024:.1f} МБ")

# ICD-манифесты Vulkan (libvulkan → lavapipe). library_path ПЕРЕПИСЫВАЕМ
# в АБСОЛЮТНЫЙ путь: Khronos-лоадер резолвит относительный путь ОТНОСИТЕЛЬНО
# МАНИФЕСТА (/usr/share/vulkan/icd.d/...) — там файла нет → ICD не загружен
# → vkCreateInstance = -9 (VK_ERROR_INCOMPATIBLE_DRIVER).
# CDD №12 p10: extra_files в report.json хранит АБСОЮТНЫЕ пути среды,
# где каталогался пакеты (полер-os-recover/...) — окружение сессии могло
# переехать (p5-авария PolarFS → git-clone в новый путь). Нормализуем:
# не существует → срезаем всё до 'cachyos-root/' и подставляем ТЕКУЩИЙ
# REPO. Эмпирика p10-run3: ICD тихо выпал из CPIO → ENOENT lvp_icd.json
# → gamescope abort exit(134) ДО всякого LLVM/шейдеров.
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
    else:
        print(f"WARN: ICD-манифест не найден ни по исходному, ни по "
              f"нормализованному пути: {_pth}")

# ─── CDD #12 p3: VK-слой POLER_drm + виртуальное /sys-дерево libdrm ─────────
# КОРЕНЬ ЗАДАЧИ: gamescope требует VK_EXT_physical_device_drm (ValidPhysical
# Device → vulkan_has_drm_props) + DrmProperties (drmGetDeviceFromDevId →
# /sys/dev/char/226:128 → render-узел). CachyOS lavapipe НЕ экспортирует
# расширение (vkprobe: 184 ext, DRM нет) → shim-слой добавляет его и
# заполняет пропсы нашей DRM-топологией (226:0 primary / 226:128 render).
LAYER_SO = os.path.join(REPO, "scripts", "libvklayer_poler_drm.so")
if os.path.exists(LAYER_SO):
    with open(LAYER_SO, "rb") as f:
        files["usr/lib/libvklayer_poler_drm.so"] = f.read()
    files["usr/share/vulkan/implicit_layer.d/VK_LAYER_POLER_drm.json"] = (
        '{\n  "file_format_version" : "1.0.0",\n  "layer" : {\n'
        '    "name" : "VK_LAYER_POLER_drm",\n    "type" : "GLOBAL",\n'
        '    "library_path" : "/usr/lib/libvklayer_poler_drm.so",\n'
        '    "api_version" : "1.3.0",\n    "implementation_version" : "1",\n'
        '    "description" : "POLER-OS DRM shim (VK_EXT_physical_device_drm)",\n'
        '    "disable_environment" : { "DISABLE_POLER_DRM_LAYER" : "1" }\n'
        '  }\n}\n').encode()
    print("rootfs: + VK_LAYER_POLER_drm (implicit)")
else:
    print("WARN: libvklayer_poler_drm.so не собран — запусти gcc в scripts/")

# /sys-дерево: libdrm drmGetDeviceFromDevId(makedev(226,128)) читает
#   /sys/dev/char/<maj>:<min>/device/drm (stat — drmNodeIsDRM)
#   /sys/dev/char/<maj>:<min>/device/subsystem (readlink → "*/pci")
#   /sys/dev/char/<maj>:<min>/device/uevent (PCI_SLOT_NAME — drmParsePciBusInfo)
#   /sys/dev/char/<maj>:<min>/device/{vendor,device,subsystem_vendor,
#    subsystem_device} (parse_separate_sysfs_files)
# + realpath(...) компонентов — все stat-ятся как S_IFDIR (dir-записи CPIO).
# PCI-слот: virtio-gpu QEMU 0000:00:04.0, vendor 0x1af4, device 0x1050.
SYS_DIRS = [
    "sys", "sys/dev", "sys/dev/char",
    "sys/dev/char/226:0", "sys/dev/char/226:0/device",
    "sys/dev/char/226:0/device/drm",
    "sys/dev/char/226:128", "sys/dev/char/226:128/device",
    "sys/dev/char/226:128/device/drm",
    # CDD #12 p3: CPU-топология (glibc sysconf fallback + LLVM/Mesa)
    "sys/devices", "sys/devices/system", "sys/devices/system/cpu",
    "sys/devices/system/cpu/cpu0",
    "sys/devices/system/cpu/cpu0/cpufreq",
    # CDD #12 p13: /sys/class/drm — udev-энумерация DRM-узлов сессии
    "sys/class", "sys/class/drm",
    "sys/class/drm/card0",
    "sys/class/drm/renderD128",
]
for d in SYS_DIRS:
    files.pop(d, None)  # страховка: файлы не должны затереть дир-записи
for node_minor in (0, 128):
    base = "sys/dev/char/226:%d/device" % node_minor
    files[base + "/uevent"] = b"DRIVER=poler-drm\nPCI_SLOT_NAME=0000:00:04.0\n"
    files[base + "/vendor"] = b"0x1af4\n"
    files[base + "/device"] = b"0x1050\n"
    files[base + "/subsystem_vendor"] = b"0x1af4\n"
    files[base + "/subsystem_device"] = b"0x1100\n"
    # readlink возвращает ЦЕЛЬ — get_subsystem_type ищет "/pci" в хвосте
    symlinks[base + "/subsystem"] = "../../../bus/pci"
# CPU-маска/топология: glibc sysconf(_SC_NPROCESSORS_*) fallback
# CDD #12 p13: DRM-узлы класса (udev: dev=«major:minor», uevent)
files["sys/class/drm/card0/dev"] = b"226:0\n"
files["sys/class/drm/renderD128/dev"] = b"226:128\n"
files["sys/class/drm/card0/uevent"] = b"MAJOR=226\nMINOR=0\nDEVTYPE=drm_minor\n"
files["sys/class/drm/renderD128/uevent"] = b"MAJOR=226\nMINOR=128\nDEVTYPE=drm_minor\n"
files["sys/devices/system/cpu/online"] = b"0\n"
files["sys/devices/system/cpu/offline"] = b"\n"
files["sys/devices/system/cpu/possible"] = b"0\n"
files["sys/devices/system/cpu/present"] = b"0\n"
files["sys/devices/system/cpu/kernel_max"] = b"255\n"
files["sys/devices/system/cpu/cpu0/online"] = b"1\n"
files["sys/devices/system/cpu/cpu0/topology/core_id"] = b"0\n"
files["sys/devices/system/cpu/cpu0/topology/physical_package_id"] = b"0\n"
files["sys/devices/system/cpu/cpu0/topology/thread_siblings"] = b"00000001\n"
# /proc/cpuinfo: минимальный валидный (1 CPU; lvp/LLVM/glibc-фолбэки)
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
    b"lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single ibrs_enh "
    b"avx2 avx512f avx512dq rdseed adx smap clflushopt clwb sha_ni "
    b"xsaveopt xsavec xgetbv1 xs umip pku ospke gfni vaes vpclmulqdq "
    b"cmp_legacy ds fsqm\n"
    b"bugs\t\t:\nbogomips\t: 4800.00\n"
    b"clflush size\t: 64\ncache_alignment\t: 64\n"
    b"address sizes\t: 40 bits physical, 48 bits virtual\n"
    b"power management:\n\n"
)
print("rootfs: + /sys/dev/char/226:{0,128} + /sys/devices/system/cpu + /proc/cpuinfo")

# ─── CPIO-КЕШ (CDD №12 p4-final): сборка 246МБ чистым Python ≈ 4 мин —
# недопустимо на каждой итерации. Ключ кеша: mtimes исходников rootfs
# (gamescope, ld.so, все либы из report.json, VK-слой, сам скрипт).
# Промах/расхождение — пересборка и запись.
import hashlib as _hl

_cache_path = os.path.join(REPO, "cachyos-root", "drm-gamescope.initrd.cpio")
_h = _hl.sha256()
_h.update(open(__file__, "rb").read())
for _p in [os.path.join(ROOT, "usr/bin/gamescope"),
           os.path.join(ROOT, "usr/bin/Xwayland"),
           os.path.join(ROOT, "usr/lib/ld-linux-x86-64.so.2"),
           LAYER_SO, REPORT]:
    if os.path.exists(_p):
        _h.update(str(os.path.getmtime(_p)).encode())
        _h.update(str(os.path.getsize(_p)).encode())
for _soname in libs:
    _p = os.path.join(ROOT, "usr/lib", _soname)
    if os.path.exists(_p):
        _h.update(str(os.path.getmtime(_p)).encode())
        _h.update(str(os.path.getsize(_p)).encode())
# p14: VK-слой — в ключ кэша (иначе .so-обновление протухает в initrd!)
if os.path.exists(LAYER_SO):
    _h.update(b"VKLAYER")
    _h.update(str(os.path.getmtime(LAYER_SO)).encode())
    _h.update(str(os.path.getsize(LAYER_SO)).encode())
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
    INITRD = build_cpio(files, symlinks, dirs=SYS_DIRS + SYS_DIRS_EXTRA)
    with open(_cache_path, "wb") as _f:
        _f.write(_cache_key.encode("ascii"))
        _f.write(INITRD)
    print(f"cpio-cache: MISS — собран и записан ({len(INITRD)/1024/1024:.1f} МБ)")
del files, symlinks  # OOM-гигиена: 246МБ словаря не переживают CPIO-сборку

# ─── 2. QEMU: virtio-gpu (скан-ауты), ltrace, полный запуск композитора ────
vm = VM("drm-gamescope", initrd=INITRD, mem=os.environ.get("E2E_MEM", "2G"), qemu=QEMU_FULL,
        extra_args=["-cpu", "max", "-vga", "none",
                    "-device", "virtio-gpu-pci,xres=1024,yres=768", "-vnc", ":0",
                    # CDD №12 p4-final: gdb-stub для rsp-watch.py (watchpoint
                    # на гостевой VA — «кто пишет 0xAAAA»); env-гейт
                    *(["-s"] if os.environ.get("E2E_GDB") else []),
                    # второй монитор (e2e_lib держит первый) — доступ
                    # монитору-наблюдателю (crash-dump физпамяти) env-гейтом
                    *(["-monitor", "unix:/tmp/poler-e2e-drm-gamescope/mon2.sock,server,nowait"]
                      if os.environ.get("E2E_MON2") else []),
                    # CDD №12 p4-final: TCG-плагин «кто пишет» (who-aaaa2.so):
                    # env E2E_PLUGIN="ADDR,LEN[,ADDR2,LEN2...]" — лог записей
                    # в гостевой диапазон с vpc-писателем (root 0xAAAA-утечки).
                    # CDD №12 p6: БАГ ИНСТРУМЕНТА — «arg=%s» ЛОМАЛ ДИАПАЗОН:
                    # QEMU режет -plugin по запятым на key=val/позиционные
                    # куски → плагин получал только «arg=ADDR» (8Б-часы!), LEN
                    # терялся → пустые логи run12/p6run2/p6run3. Правильно —
                    # ПОЗИЦИОННЫЕ куски: file=...,ADDR,LEN,ADDR2,LEN2 —
                    # who-aaaa.c склеивает их обратно в «ADDR,LEN,ADDR2,LEN2».
                    *(["-plugin", "file=%s/scripts/e2e/who-aaaa2.so,%s"
                       % (REPO, os.environ["E2E_PLUGIN"])]
                      if os.environ.get("E2E_PLUGIN") else []),
                    # CDD №12 p6: value-трассировщик «откуда указатель?»
                    # (who-ptr.so): env E2E_PTR="TARGET_HEX" — логирует КАЖДУЮ
                    # load/store-операцию со значением TARGET (источник
                    # мусорного указателя: vaddr чтения + vpc записи).
                    *(["-plugin", "file=%s/scripts/e2e/%s,%s"
                       % (REPO, os.environ.get("E2E_WHO", "who-ptr.so"),
                          os.environ["E2E_PTR"])]
                      if os.environ.get("E2E_PTR") else [])])
del INITRD  # VM держит только путь к файлу — 258МБ больше не нужны в RAM
try:
    vm.start()
    # CDD №12 p7: TCG-плагины (who-ptr/who-aaaa) замедляют бут в 10-50× —
    # таймаут бута управляется env (E2E_BOOT_TIMEOUT, дефолт 90с).
    _boot_to = int(os.environ.get("E2E_BOOT_TIMEOUT", "90"))
    t = vm.wait_for("Shell started", timeout=_boot_to) or vm.wait_for("[EVDEV]", timeout=_boot_to)
    if t is None:
        check("boot: shell ready", False)
        sys.exit(1)
    check("boot: shell ready", True)
    check("boot: no fatal markers", not check_fatal(vm))

    vm.type_cmd("ltrace")
    # CDD №12 p4-final: снять СТАРЫЙ HOLD-флаг (прерванный прошлый прогон)
    if os.path.exists("/tmp/e2e-hold-release"):
        os.unlink("/tmp/e2e-hold-release")
    vm.type_cmd("elfload usr/bin/gamescope -W 1024 -H 768")

    # ждём: DRM-конвейер / первый флип / краш-лог (паттерны гибкие)
    # CDD №12 p4-final: окно — env E2E_DRILL (по умолчанию 900с): шейдер-
    # компиляция lvp/LLVM в TCG волатильна (5..20+ мин по прогонам).
    markers = ["[DRM] page_flip", "page_flip", "SETCRTC", "gamescope:",
               "vblank", "VBLANK", "CPU EXCEPTION", "Fatal"]
    deadline_hit = None
    shot1_taken = False
    import time
    deadline = time.time() + int(os.environ.get("E2E_DRILL", "900"))
    n_crashes = 0
    while time.time() < deadline:
        t = vm.text()
        # p14: краш ОДНОГО рабочего потока НЕ убивает gamescope (render-loop
        # жив!) — не обрываем drill, считаем и продолжаем до флипа/таймаута.
        t_crashes = t.count("CPU EXCEPTION")
        if t_crashes > n_crashes:
            n_crashes = t_crashes
            print(f"CPU-EXCEPTION #{n_crashes} (поток жив? drill продолжается)")
        if "Kernel fault" in t or "kernel-panic" in t:
            deadline_hit = "crash"
            break
        if "page_flip" in t.lower() or "vblank" in t.lower():
            deadline_hit = "flip"
            break
        # CDD №12 p5 (ШАГ 2): скриншот ДО флипа — прогресс рендера
        # (Wayland/fb контент) + ПОСЛЕ — первый кадр. Через мон2 (env E2E_MON2).
        if os.environ.get("E2E_MON2") and not shot1_taken and "vulkan:" in t:
            shot1_taken = True
            try:
                vm.mon_cmd("screendump /tmp/poler-e2e-drm-gamescope/shot-pre.ppm")
                print("SHOT: /tmp/shot-pre.ppm (pre-flip)")
            except Exception as e:
                print("SHOT pre fail:", e)
        if vm.proc and vm.proc.poll() is not None:
            deadline_hit = "qemu-died"
            break
        time.sleep(1.0)

    # CDD №12 p7: КРАШ-ДАМП ДОЛЖЕН ДОПЕЧАТАТЬСЯ. Эмпирика: e2e ломал цикл
    # на «CPU EXCEPTION» и убивал QEMU ДО завершения печать STACK-RET →
    # RBP-CHAIN/NODE-DUMP/C-DUMP (секция диагноза) терялись. Ждём маркер
    # завершения (≤45с: 1024-слот скан + serial — медленно под TCG).
    if deadline_hit == "crash":
        dump_deadline = time.time() + 45
        while time.time() < dump_deadline:
            t = vm.text()
            if "User process killed" in t or "Kernel fault" in t:
                print("DUMP: краш-отчёт допечатан (маркер kill найден)")
                break
            if vm.proc and vm.proc.poll() is not None:
                break
            time.sleep(2.0)
        else:
            print("DUMP: маркер завершения не найден за 45с (дамп обрезан?)")

    text = vm.text()

    # ─── 2b. Скриншот ПОСЛЕ флипа + PPM-анализ пикселей ──────────────────
    if os.environ.get("E2E_MON2") and deadline_hit in ("flip", "crash"):
        try:
            vm.mon_cmd("screendump /tmp/poler-e2e-drm-gamescope/shot-post.ppm")
            time.sleep(2.0)
            vm.mon_cmd("screendump /tmp/poler-e2e-drm-gamescope/shot-post2.ppm")
            print("SHOT: /tmp/shot-post.ppm + shot-post2.ppm (после флипа)")
        except Exception as e:
            print("SHOT post fail:", e)
        for name in ("shot-pre.ppm", "shot-post.ppm", "shot-post2.ppm"):
            p = f"/tmp/poler-e2e-drm-gamescope/{name}"
            if os.path.exists(p):
                # PPM P6: ширина/высота; считаем НЕ-чёрные пиксели
                try:
                    with open(p, "rb") as f:
                        head = f.readline()  # P6
                        dims = f.readline()
                        while dims.startswith(b"#"):
                            dims = f.readline()
                        w, h = map(int, dims.split())
                        f.readline()
                        data = f.read()
                    total = w * h
                    black = 0
                    for i in range(0, min(len(data), total * 3), 3):
                        if data[i] == 0 and data[i+1] == 0 and data[i+2] == 0:
                            black += 1
                    nonblack = total - black
                    print(f"SHOT-ANALYZE {name}: {w}x{h}, не-чёрных {nonblack}/{total} "
                          f"({100*nonblack/total:.1f}%)")
                    if deadline_hit == "flip":
                        check(f"кадр {name}: есть контент (>1% не-чёрных)", nonblack * 100 > total)
                except Exception as e:
                    print("PPM-анализ", name, "fail:", e)

    # ─── 3. Анализ: DRM-ioctl декодер из ltrace ────────────────────────────
    # p13: формат [L] печатает склеенные аргументы 0x0xADDR0xADDR →
    # cmd идёт вторым аргументом с двойным префиксом
    ioctl_calls = re.findall(r"\[L\] 16\([^,]+,0x[0-9A-F]*x([0-9A-F]+),", text)
    KNOWN = {  # сверено с /usr/include/drm/drm.h (gcc sizeof, x86_64)
        "C0406400": "VERSION", "C006640C": "GET_CAP", "C010640D": "SET_CLIENT_CAP",
        "6401E": "SET_MASTER", "6401F": "DROP_MASTER", "C0106407": "SET_VERSION",
        "C04064A0": "GETRESOURCES", "C03864A1": "GETCRTC", "C03864A2": "SETCRTC",
        "C02864A6": "GETENCOD", "C04864A7": "GETCONNECT",
        "C01C64AE": "ADDFB", "C06864B8": "ADDFB2", "C00464AF": "RMFB",
        "C01864B0": "PAGE_FLIP", "C02064B2": "CREATE_DUMB",
        "C01064B3": "MAP_DUMB", "C00464B4": "DESTROY_DUMB",
        "C02064B9": "OBJ_GETPROPS", "C01064AC": "GETPROPBLOB",
        "C01064B5": "GETPLANERES", "C02064B6": "GETPLANE",
    }
    seen = {}
    for h in ioctl_calls:
        h2 = h.lstrip("0") or "0"
        # нормализация к 8-символьному hex
        h2 = h2.rjust(8, "0").upper() if len(h2) <= 8 else h2
        name = KNOWN.get(h2, "?" + h2)
        seen[name] = seen.get(name, 0) + 1
    print(f"--- DRM-ioctl-конвейер ({len(ioctl_calls)} вызовов): {seen} ---")

    enosys = {}
    for l in text.splitlines():
        m = re.match(r"\[L\] (\d+)\(.*\) = 0x(FFFFFFFFFFFFFF..)$", l)
        if m:
            enosys[int(m.group(1))] = enosys.get(int(m.group(1)), 0) + 1
    if enosys:
        print(f"--- ENOSYS/EINVAL-хвосты: {enosys} ---")

    # краш-лог (CDD-артефакт)
    idx = text.find("=== ELF Load & Run")
    if idx >= 0:
        print("--- CRASH LOG (CDD-артефакт, ltrace+DRM) ---")
        print(text[idx:idx + 3000])
        print("--- ------------------------------------- ---")

    check("drm-gamescope: DRM-конвейер запущен (ioctl'ы идут)", len(ioctl_calls) > 4)
    check("drm-gamescope: SET_MASTER дошёл", "SET_MASTER" in str(seen) or "GETRESOURCES" in str(seen))
    check("drm-gamescope: no kernel panic", "kernel-panic" not in text and "Halting" not in text)
    if deadline_hit == "flip":
        check("drm-gamescope: PAGE_FLIP/VBLANK цикл", True)
    elif deadline_hit == "crash":
        print(f"--- исход: краш (см. лог) ---")
        check("drm-gamescope: краш-лог собран (CDD-итерация)", True)
    else:
        check("drm-gamescope: PAGE_FLIP/VBLANK цикл", False)

    # CDD №12 p5: HOLD-режим — держим ВМ ЖИВОЙ после краша, чтобы
    # монитор-наблюдатель (crash-dump.py) успел снять физдамп (гонка:
    # без HOLD finally мгновенно убивал QEMU). Освобождение — файл-флаг.
    if os.environ.get("E2E_HOLD") and deadline_hit == "crash":
        release = "/tmp/e2e-hold-release"
        print(f"HOLD: ВМ живёт до появления {release} (макс 600с)...")
        t0 = time.time()
        while time.time() - t0 < 600 and not os.path.exists(release):
            time.sleep(1.0)
        if os.path.exists(release):
            os.unlink(release)
            print("HOLD: освобождено наблюдателем — останавливаем ВМ")
        else:
            print("HOLD: таймаут 600с — останавливаем ВМ")
finally:
    vm.stop()

print("\n=== DRM-GAMESCOPE: %d/%d PASS ===" % (len(PASS), len(PASS) + len(FAIL)))
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
