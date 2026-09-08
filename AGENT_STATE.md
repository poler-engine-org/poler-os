updated_utc: 2026-09-08T19:30:00Z
repo: poler-os
branch: main
commit: 757bf82 feat(cdd12-p14): БЛОКИРУЮЩИЙ poll (слайс-парк 20мс) — TCG-спин мёртв; EXPORT-FABRIC + DRM-конвейер (ADDFB2×4=0); 434/434
tag: v0.19.0 (следующий релиз — v0.20.0-rc: после первого PAGE_FLIP)
pushed: origin/main
tests: zig build OK; 434/434 юнит-тестов (12 модулей); E2E: gamescope-конвейер жив (VK/lavapipe/ADDFB2/vblank-DISARM), elf-run 17/17; детекторы ЧИСТЫЕ
current_task: CDD №12 p14 ЗАВЕРШЁН. ФРОНТ v0.20.0-rc = fork+execve (в системе один ELF gamescope; Xwayland не процесс — execve в ядре отсутствует; см. секцию «ТЕКУЩИЙ ФРОНТ» внизу файла). Дисциплина p7: тег — только после первого PAGE_FLIP + shot-final.png 1024×768.
blocked_on: —
tmux_sessions: нет (QEMU через qemu-portable/qemu-portable.sh; e2e scripts/e2e/ + drm-gamescope-e2e.py; vkprobe2 host-прогон: ld-linux --library-path root/usr/lib + VK_ICD_FILENAMES)
credentials: токен передаётся вне репозитория (НЕ хранить в репо)

## Последние сессии

| Дата (UTC) | Задача | Результат |
| 2026-09-08 | **CDD №12 p14 ФИНАЛ + ЧИСТКА РЕПО (commits e9c97841, 757bf82, + chore)** | EXPORT-FABRIC (4×FABRIC-FD), DRM-конвейер: ADDFB2×4=0, Wayland-сокет, Vulkan/lavapipe шейдеры, vkQueueSubmit×3; vblank ARM→EXPIRE→OnPollIn→DISARM; БЛОКИРУЮЩИЙ poll (слайс-парк 20мс) — TCG-спин мёртв (лог 1.28М→400К); fake-fork фильтр CLONE_VM; 434/434. РЕПО: удалены logs-p11 (191МБ), upload (89МБ), registry-analysis, linux-arch-experiment, mini-services, bin, .env, grub-local, дубликаты («docs-с-кавычкой, poler-os/); доки в docs/; README → v0.19.x; старые релизы ISO v0.6–v0.9.3 удалены (новый ISO — с v0.20.0-rc). |
| 2026-09-07 | **CDD №12 p13: SYSCALL-DIFF host-Linux → ATOMIC-LITE + SEATD + PRIME (commit feat(cdd12-p13))** | Host-диф: socket/getsockname/statx/dup/fallocate=ENOSYS + GetConnector-ABI-скрамбл + MAX_TASKS — ВСЁ закрыто. Встроенный seatd (SCM_RIGHTS-устройства!), atomic-lite (плоскости/пропы/blob'ы/MODE_ATOMIC-транслятор), PRIME fd→memfd→скан-аут, VFS-overlay no-shadow + COW-фолбэк. gamescope: полный KMS-пайплайн (режим 1024x768 выбран!), живой render-loop, PRIME×3. Фронт: lvp-dmabuf-экспорт (userspace). sysharness 6/6; юнит-тесты зелёные. |
| 2026-09-07 | **CDD №12 p12: R15-POISON/FPU-ФЛАКИ-КИЛЛЕР (commit fix(cdd12-p12))** | Полный FPU-контекст пер-таск (xsave/xrstor 0x7: x87+MXCSR+XMM+YMM) в трёх путях: syscall-строки .bss [8][832] (парк-безопасность), exception-строки [8][2][832] (глубина-2, вложенный #PF), IRQ вход-сейв/хвост-реставр (Task.fpu). ДВА клоуна найдены дизассемблом: memset перед xsave = SSE-бродкаст XMM0 (нули на JIT-странице) и Zig-Debug 0xAA-филл undefined-локали (SSE). Фиксы: rep stosq GPR-only + .bss-строки + тонкая геометрия + GPR-GUARD. sysharness DONE ×4 (1037 syscall), elf-run 17/17, детекторы 0. |
| 2026-09-06 | **CDD №12 p10: TEARDOWN-ИНВАРИАНТЫ + PHYS-MAP-СКАНЕР (commit 48b77392, push pending)** | Алиасинг физстраниц ЗАКРЫТ и ОПРОВЕРГНУТ как источник яда: INVLPG в unmapPageInPML4 (активный CR3; треды CLONE_VM не сбрасывали TLB), порядок unmap→free, PMM double-free детектор, physmap-сканер (живой VERIFY: CLEAN 0/0). Форензика who-ptr2 PAT 27М событий: все каналы доставки чисты; 0xAA = LLVM pattern-fill (memset ×1152) + DenseMap tombstone; краш = деструктор списка следует в tombstone → #GP. Фронт p11: syscall-diff vs host-Linux. 573/573; elf 17/17; dyn 4/4; glibc 7/7. |
| 2026-09-06 | **CDD №12 p8: ВЫХОДНОЙ КАДР = СТРОКА ВЛАДЕЛЬЦА (commit 5cf153f5, local)** | ЭПИК: кросс-таск hijack syscall-выхода НАЙДЕН+ЗАКРЫТ — глобал syscall_exit_frame_ptr в парк-окнах пере-указывается дитятей → родитель после clone sysretq в КОНТЕКСТ ДИТЯ (glue/ThreadFunc epoll_wait) → gamescope main-поток вечно в ThreadFunc-парке (фронт 1158/1171 — «epoll без wake»). Фикс: пере-указка на строку ВЛАДЕЛЬЦА перед возвратом в asm. РЕЗУЛЬТАТ: фронт 1865, /dev/dri/card0 newfstatat ✓, opendir+getdents64 ✓ (libdrm-скан!). ИНСТРУМЕНТЫ: tasks (РЕЕСТР ПАРКОВОК: задачи/wake/fd/epoll-watches/каналы/futex), peek (page-walk чтение user-VA: имена тредов 'gamescope-eis', vtable→gamescope base 0x100000000000), [EPW]/[FXW] входной трейс паркующих syscall'ов, who-ptr range-first + WHO-PTR-STACK, p8-parkdump.py. НОВЫЙ ФРОНТ p9: 0xAAAA в brk-хипе (memset 0xAA fill из libc-loop, вызывающий неизвестен) → #GP LLVM при спискоходе полу-инициализированной структуры. 573/573. |
|---|---|---|
| 2026-09-06 | **CDD №12 p5: DEMAND-ZERO ПЕЙДЖИНГ (commit 3d86e54)** | АВАРИЯ PolarFS FUSE (хостил репо) mid-сессии → полное восстановление окружения с нуля: git-clone org (250МБ), Zig 0.14.1 16-потоковым чанкером (49МБ/195с), qemu-full (git-скрипт был ОБРЕЗАН mid-heredoc — qemu-full.sh написан заново, -L-прошивки), rootfs из выжившего /tmp/cdd12/archroot + ICD/отчёт-пути. ГЛАВНОЕ: demand-zero пейджинг — mmap-anon/brk = VA-резервация, #PF(P=0) → нулевая страница с r.pte региона; validate МАТЕРИАЛИЗУЕТ lazy (madvise-EFAULT ломал glibc/lua → 0xAAAA→#GP); MMAP_BUDGET 1ГБ→48ГБ (LLVM 10.7ГБ-JIT-арены); PVH-лимит initrd 256→512МБ (cpio 280МБ молча отбрасывался!); RIP-bytes: точный опкод fault-инструкции (16 байт от RIP; старый код печатал 1 байт по RIP-8). Прогоны: run8 llvmpipe выбран; run12 прошёл старый 578-syscall фронт → 867 syscall (LLVM W^X-арены) → libstdc++ _Rb_tree_decrement NULL (многопоточные гонки — следующий фронт). 573/573. |
| 2026-09-05 | **CDD №12 p4 (промежуток): МОДУЛЬНАЯ АТРИБУЦИЯ + tgkill + F_DUPFD + реестр-2048 — vkCreateDevice ✓✓, фронт в компиляции шейдеров** | 10 коммитов (91f447ba..): attribution mmap-регионов ([RIP]/[CR2]→библиотека, STACK-HIST, mmapinfo), tgkill(234) с wait-семантикой 128+sig, F_DUPFD/F_DUPFD_CLOEXEC (КОРЕНЬ wl_display_create=NULL), mmap-реестр 512→2048 (КОРЕНЬ lvp NULL+0x38 — «registry full» ×159), fetch cold-start+vulkan-swrast+xcb-util-keysyms (замыкание 79 либ восстановлено), ltrace-PATH-декодер, [VFS] open-fail, SeaBIOS-фикс qemu-full, PAGE_FLIP/SETCRTC→vring скан-аут-канал (готов к первому кадру). 573/573. ФРОНТ: tgsi-0xAAAA+stack-smash в шейдерах; host vkprobe2 с реальными шейдерами gamescope — БЕЗ краша → корень в ядро-среде. |
| 2026-09-05 | **CDD №12 p3: VULCAN→GAMESCOPE ДРАЙВ + DRM-слой (commit 3b4bf347)** | Shared-mem (ftruncate+MAP_SHARED PMM), getdents64/DirStream, st_rdev (226:0/226:128), DRM: ADDFB2/RMFB/SET_VERSION/OBJ_GETPROPS/flip-complete-события+CLIENT_CAP-гейт, БЛОКИРУЮЩИЙ epoll_wait (анти-СПИН 2526 вызовов), futex BITSET/REALTIME, sched_getaffinity/sysinfo/mkdir, ГОНКА createUserTaskAbi (abi до Ready — «Unknown syscall: 262»), стек 128МБ, VK-слой POLER_drm (VK_EXT_physical_device_drm на lavapipe — host+kernel верифицирован), /sys-дерево libdrm. E2E-CDD: gamescope доходит до vkCreateDevice→lvp/LLVM-init (фронт: userspace-краш в lvp). Матрица 563/563 + elf-run 17/17 + dyn-elf 4/4 + glibc-static 7/7 + gpu-scanout 11/11 + pe-run4/8 PASS + gamescope 3/3. |
| 2026-09-05 | **CDD №12 p1: GAMESCOPE (CachyOS rootfs) — конвейер либ в Ring 3** | fetch-cachyos-root.py: gamescope 3.16.25 (пакет CachyOS) + НАСТОЯЩИЙ glibc 2.44 CachyOS-v3 + 57-либ DT_NEEDED-замыкание + SDL3-dlopen-волна = 58 либ 49МБ initrd. Ядро: OSXSAVE+XCR0 (AVX2 для v3), PMM CMOS RAM-детект (512МБ), VFS usr-merge+симлинки+readlink, close→release_file (EMFILE-течь), исправлены якоря syscall (readlink 89, readlinkat 267, rseq 334 — 293=pipe2 коллизия!). ИТОГ p1: ld.so грузит ВСЕ либы без ошибок, код gamescope исполняется (≥400 syscall: SDL, потоки, epoll) — падение только на ENOSYS-волне (p2). 522/522 тестов; gamescope e2e 6/7; регресс dyn-elf 5/5, glibc-static 7/7. |
| 2026-09-04 | **CDD №11 p3: МОМЕНТ ИСТИНЫ №9 — ДИНАМИЧЕСКИЙ ELF в Ring 3 (ld.so + glibc)** | 4 crash-driven раунда: PT_INTERP+handoff → file-mmap/lseek/pread64/writev/access/newfstatat → CPIO-канонизация → fstat (st_dev,st_ino)-КОЛЛИЗИЯ «already loaded» (dl-load.c:959) → АНОНИМНЫЙ MAP_FIXED bss (dl-map-segments.h:163). ИТОГ: «HELLO-WORLD-FROM-DYNAMIC» → exit_group(0) — 30 syscall, printf через write(25Б), mprotect RELRO, getrandom, brk-malloc. 505/505; dyn-elf 4/4 + регресс: glibc-static 7/7, elf-run 17/17, ldev 12/12, input 11/11, drm 8/8. |
| 2026-09-04 | **v0.19.0 FINAL: CDD-цикл №10 закрыт — графический стек + Live-USB + Linux POSIX волна** | P1: drm_kms.zig (UAPI dumb-KMS: 15 ioctl якорям libdrm, fbdev-фасад, PAT→WC) + virtio_gpu.zig (probe 0x1050 + caps + 2D-команды); P2: evdev.zig (input_event-поток, PS/2 клав+мышь, IRQ12→v44; 8042-гонка ЗАКРЫТА cli+flush+waitIbf — Set2-сырец излечен); P3: linux_syscalls графическая волна (fd-таблица, ioctl/futex/poll/epoll/mmap-dev/munmap/clone/exit_group/fcntl, 17 runtime-мостов, ldevtest); P4: vfs.zig (devfs+initrd-RO+tmpfs-RAM overlay) + build-live-iso.sh (Live-USB: CPIO+структура+FAT32 с файлами+QEMU-режимы) + файловые fd. 457/457; E2E: drm 8/8, input 11/11 (живые клавиши), ldev 12/12, live-boot 12/12 (FAT32 RW + VFS overlay), pe-run4 + pe-run8 PASS; kernel-panic=0. ТЕГ v0.19.0. |
| 2026-09-04 | v0.18.0 FINAL: CDD-цикл №9 — residual + 3 корневых бага + ПОЛНАЯ матрица | (A) КОРЕНЬ cks-гонки найден: DEBUG-кадр win32_crt.dispatch 57КБ > 32КБ kstack → 25КБ-переполнение в kstack СОСЕДА («DNS-спрей» v0.14-v0.18) → kstack 128КБ. (B) #GP returnError: NULL-ctx читал BIOS IVT (физ.0) → зануление первой страницы. (C) Многопроцессный re-map: утечка маппингов мёртвого процесса в общей цепочке PML4[0] → AlreadyMapped ×352 → remap-толерантность loader+CRT ops → ВТОРОЙ peload работает (7za→curl в одном буте — МНОГОПРОЦЕССНОСТЬ). (D) sched_resume.zig: пер-таск .bss резюм-кадры (align16!) + FRAME-GUARD «50 подряд». 335/335; pe-run4+7+8 ALL PASS; kernel-panic=0. ТЕГ v0.18.0. |
| 2026-09-03 | v0.18.0-RC: CDD-цикл №9 — Per-Task Syscall State + security-харденинг + Linux POSIX-фундамент | Архитектурное закрытие cks-гонки ~90%: asm-вход syscall по ВЛАДЕЛЬЦУ user-RSP (скан kstack/ustack-таблиц), ur-владельцы, create_thread 5-арг, SAVE-контент-фильтр, FRAME-GUARD-паллиатив. Харденинг: RX-bounds, validateRange (overflow+ceiling), PMM-rollback. Linux POSIX: linux_syscalls.zig (6 syscall, errno-ABI) + Task.abi + RAX-маршрутизация. 329/329. |
| 2026-09-02 | v0.17.0: CDD-цикл №8 — FAT32 RW + .reloc DIR64 + 7-Zip МОМЕНТ ИСТИНЫ №8 | 7-Zip LZMA в Ring 3 ПОЛНОСТЬЮ; FAT32 RW round-trip; .reloc DIR64 (2258 fixups); Wait fast-path. 311/311. |
| 2026-09-02 | v0.16.0: CDD-цикл №7 — PUF-энтропия + VFS/FILE-API + IRQ-сетворкер | ВЕРИФИЦИРОВАННЫЙ ПОСТКВАНТОВЫЙ HTTPS БЕЗ -k (X25519MLKEM768); CA-бандл из initrd-VFS; CMOS-RTC. 301/301. |
| 2026-09-02 | v0.15.0: CDD-цикл №6 — HTTPS-замыкание + TCP-hardening | TLS 1.3 handshake + расшифрованный HTML в консоли ОС; кооперативная парковка сна. 296/296. |
| 2026-09-02 | v0.14.0: CDD-цикл №5 — VirtIO-Net + реальный сетевой стек | РЕАЛЬНЫЙ интернет в Ring 3 — ARP/DNS/TCP/HTML «Example Domain». 288/288. |
| 2026-09-01 | v0.13.0–v0.12.0: CDD-циклы №4-3 — SocketState/select + МОСТ КОЛБЭКА + Win64-треды | ПОЛНЫЙ HTTP-ОБМЕН; connect() через Win64-треды; InitOnce-мост. |
| 2026-09-01 | v0.11.0–v0.10.0: CDD-циклы №2-1 — Ring-3 запуск curl.exe | pe_loader/win32_stubs/win32_api; МОМЕНТ ИСТИНЫ №1: curl дошёл до main(). |
| 2026-09-01 | v0.9.0: PE/COFF-лоадер + CDD-стабы | addRunArtifact-инвариант (тесты ЗАПУСКАЮТСЯ). E2E 16/16. |
| 2026-08-31 — 2026-09-01 | v0.7.x — v0.8.0 | entropy-hub, PVH, PUF, перенос в оргу. |

---
## CDD №12 p11 — ИТОГ: XMM-КОРЕНЬ 0xAAAA-ШТОРМА НАЙДЕН И ЗАКРЫТ

**ГЛАВНЫЙ ПРОРЫВ ВСЕЙ CDD #12:** корень «0xAAAA-шторма»/JIT-крашей — **порча XMM0-15
гостевого состояния через exception/syscall-пути ядра**. ISR-стаб (isr64.S) и
syscall_entry сохраняли ТОЛЬКО GPR; Zig-хендлеры свободно юзали SSE (мемсеты
demand-zero — 16Б-сторы!) → фолтящий SSE-стор libc-memmove ретраился с затёртым
XMM0 → 11 нулевых байт вместо [endbr64+imul×2]-пролога в JIT-странице LLVM →
call мусора → #PF(0). Forensic-цепочка: jit-writer.c (TCG-плагин v1-v13) —
staging-буфер, PREFIX-QW, LOAD-watch, read_memory_vaddr; host-дифференциал
shim-mprotect.c (LD_PRELOAD). Все логи: logs-p11/.

**Фиксы (hal.zig):**
1. `isrSaveXmm/isrRestoreXmm` (movups×16 → .bss) в isr_common_handler, vector<32.
2. `sysSaveXmm/sysRestoreXmm` — обёртка zig_syscall_handler (Linux-инвариант
   kernel_fpu_begin: syscall обязан вернуть XMM нетронутыми; gamescope падал
   в llvm::SelectionDAG: call → 0x40 после mprotect-шторма).

**Результаты:**
- sysharness (Vulkan compute) = **6/6 PASS, ПОЛНЫЙ ПРОГОН DONE** — LLVM-JIT
  шейдера + dispatch + waitIdle работают на POLER-OS.
- elf-run = **17/17 PASS** (×2), юнит-тесты = **зелёные** (прlimit64-тест
  поправлен: old_va=NULL → 0 по man, не EFAULT).
- gamescope: дальше всех прошлых прогонов — выбор vulkan-устройства
  «llvmpipe (LLVM 22.1.8, 256 bits)», mesa_shader_cache, 25-мин drill жив.
- p11-syscall-фиксы (prlimit64-таблица 0..15, sched_setscheduler/setpriority,
  madvise-валидация) — подтверждены host-дифом и тестами.

**Фронт p12 (стратегия):**
1. **R15-POISON (флаки-киллер gamescope):** «[R15-POISON] кадр kstack испорчен
   (0xAAAA…) slot=…» — детектор ядра ловит; кадры на kstack-топе портятся
   невидимыми для TCG-плагинов путями (p7-гипотеза: interrupt-entry push-и).
   Нужен per-task XMM+GPR exit-слоты и аудит вложенных входов.
2. Пер-таск XMM при futex-парковках (сейчас общий .bss-буфер).
3. После R15-фикса: gamescope → SET_MASTER → CREATE_DUMB → ADDFB2 → SETCRTC →
   **PAGE_FLIP** → screendump 1024×768 → tag **v0.20.0-rc**.

Тулчейн: /tmp/my-project/tools/zig-0.14.0/zig (сеть в песочнице недоступна).

---

## CDD №12 p12 — ИТОГ: R15-POISON/FPU-ФЛАКИ-КИЛЛЕР — ПОЛНЫЙ FPU-КОНТЕКСТ PER-TASK

**Двойной корень p12-регрессии (дизассембл-доказанный):**
1. `@memset(slot,0)` перед `xsave` в fpuSave — Zig компилирует в SSE-бродкаст
   (`movd %edi,%xmm0; pshufd $0; movdqu`) — **memset затирал гостевой XMM0 ДО
   сохранения**: каждый fpuSave писал нулевой XMM0 ⇒ xrstor доставлял юзеру
   XMM0=0 ⇒ рестарт-стор #PF (demand-zero first-touch) писал 11 нулей на
   JIT-страницу LLVM вместо endbr64+imul×2 ⇒ mprotect(RX) ⇒ прыжок ⇒ #PF
   (краш @989 syscall — p11-база 1038/DONE). Host-репро xsave-test это
   упустил (проверял BV/#GP-семантику, не сохранность XMM0 через memset).
2. Zig-Debug 0xAA-филл undefined-стек-локали exception-пути
   (`memset $0xAA,$0x340` в isr_common_handler — SSE!) — та же порча XMM0
   (паттерн 0xAA) + 0xAA-спрей в kstack-зоны.

**Геометрический корень (фикс-3):** 832Б стек-локал обёртки растягивал кадр —
спиллы/филлы писали в GPR-слоты STALE-кадра таймер-преэмпции
[top-176,top-128) → диспетчеризация иреткой (CS/RIP «валидны» — перезаписаны
живым каскадом) доставляла юзеру R15=0xAAAA → #GP в libstdc++ (триплата:
живой frame.r15=0xAAAA, cs=0x23; EXIT/ENTRY-POISON молчали).

**Архитектура (инвариант kernel_fpu_begin/end, AVX XCR0=0x207, v3-YMM):**
- syscall: `syscall_fpu_frame[8][832]` .bss-строки, владелец по user_rsp
  (парк-безопасность по конструкции), fallback для вне-таблиц;
- exception: `exc_fpu_frame[8][2][832]` .bss-строки глубина-2 (вложенный
  #PF-в-#PF; владелец по kstack-адресу; утечка глубины безвредна — слоты
  симметричные пары save/restore);
- IRQ: вход-сейв `tasks[o].fpu` (первое заявление — до SSE-структурных
  копий), хвост-реставр адресата иретки (свич → current_task_id — FIX2;
  не-свич → identity);
- `fpuSave`: `cld; rep stosq` (104 qword — ТОЛЬКО GPR!) + `xsave` маска 0x7;
  comptime-страховка $104 ↔ FPU_AREA_SIZE=832.

**GPR-GUARD (sched_resume.zig):** frameContentValid + проверка 0xAAAA в
r15..r12 (frame+0/8/16/24) — отравленный кадр НЕ диспетчеризуется.

**Трипвайр (форензика-инструмент, спит):** poll слота [top-176] на каждом
IRQ-входе; авто-арм снят (хардкод task 3 — охота закрыта); армит ручная
запись p12_watch_addr+магика.

**Результаты:** sysharness DONE ×4 (1037 syscall = база p11), elf-run 17/17,
юнит-тесты зелёные; R15-POISON=0, EXIT/ENTRY-POISON=0, трипвайр=0.
**ТЕГ НЕ СТАВИТСЯ** (первого PAGE_FLIP нет — дисциплина p7).

**Фронт p13:** gamescope → SET_MASTER → CREATE_DUMB → ADDFB2 → SETCRTC →
**PAGE_FLIP** → screendump 1024×768 → тег **v0.20.0-rc**.

Патч-скрипты (полная история охоты): /home/z/my-project/scripts/p12-*.py;
логи: /tmp/p12/; тулчейн: /tmp/my-project/tools/zig-0.14.0/zig.

## CDD №12 p13 — ИТОГ: SYSCALL-DIFF host-Linux → SEATD + ATOMIC-LITE + PRIME + VFS

Дифференциальное тестирование syscall-поведения POLER-OS против настоящего host-Linux
(один и тот же gamescope на обоих): расхождения закрыты пакетом p13 — SEATD (сессии
девайсов /dev/dri/card0), ATOMIC-LITE (DRM_MODE_ATOMIC минимальный сет), PRIME
(dmabuf-fd мосты), VFS-достройка. gamescope проходит seatd-handshake и открывает
карту.

## CDD №12 p14 — ИТОГ: EXPORT-FABRIC + полный DRM-конвейер; 434/434

- **EXPORT-FABRIC**: Vulkan implicit-layer `libvklayer_poler_drm.so`
  (vkCreateInstance/B2B FD) — экспорт буферов в DRM (4×FABRIC-FD в логе).
- **DRM-конвейер gamescope**: ADDFB2×4=0, wlserver поднял Wayland-сокет, Vulkan
  заходит в lavapipe/LLVM, компиляция реальных шейдеров gamescope, vkQueueSubmit×3.
- **timerfd vblank**: ARM → EXPIRE → OnPollIn → DISARM (DISARM — норма re-arm).
- **БЛОКИРУЮЩИЙ poll**: sysPoll слайс-парк 20мс (зеркало epoll_wait) — TCG-спин
  мёртв, лог 1.28М→400К, потоки реально паркуются.
- **Тесты: 434/434** (12 модулей); fake-fork отфильтрован от CLONE_VM-тредов.

## ТЕКУЩИЙ ФРОНТ: v0.20.0-rc — ПОСЛЕДНИЙ КИЛОМЕТР = fork+execve

ФОНАД РАСКРЫТ: в системе ровно ОДИН ELF — gamescope. Xwayland НИКОГДА не запускался
(«/tmp/.X11-unix» в логе — это wlserver сам создаёт каталог). execve в ядре
отсутствует полностью; fork — fake (pid из реестра, wait4 из zombie-реестра).
Без клиента damage нет → hasRepaint не взводится → PAGE_FLIP/SETCRTC/ATOMIC = 0.

**План v0.20:**
1. MAX_LINUX_PROCS 2→8 (gamescope + Xwayland + клиенты);
2. настоящий fork: адрес-пространво копировать через createUserPML4/mapPageInPML4/
   userLeafRaw (механика VMM уже есть);
3. execve (номер 59): ELF-загрузчик уже умеет static+dynamic;
4. Xwayland как реальный процесс → damage → hasRepaint → PAGE_FLIP →
   screendump 1024×768 (shot-final.png) → тег v0.20.0-rc.

Известные несгоревшие хвосты: lvp worker crash (STL list-splice, libvulkan_lvp.so
+0x301A4C, LLVMPipe worker) — эксперимент LP_NUM_THREADS=0 в envp e2e уже вписан,
не проверен; wlserver «shm file for format table» (wlr_linux_dmabuf_v1) —
предварительно не блокирует.

Примечание по окружению: полигон разработки (bash-сессии, /tmp e2e-артефакты)
переживает сбросы контекста — рабочая копия репо теперь клонируется по
необходимости; ключевые артефакты фиксируются в GitHub немедленно.
