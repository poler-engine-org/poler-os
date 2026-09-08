# POLER-OS

**Универсальная операционная система нового поколения. x86_64, монолитное ядро, Zig 0.14.0. Двойной ABI-сабстрат в Ring 3: Windows PE64 + Linux ELF (glibc / CachyOS).**

POLER-OS — это не дистрибутив Linux и не надстройка над ним. Это независимая операционная система, спроектированная с нуля для решения фундаментальной проблемы: insecurity by design. Linux уязвим архитектурно — ядро открыто для модификации после загрузки, root-процесс является богом системы, а защита строится как надстройка поверх ОС. POLER-OS меняет парадигму: безопасность не добавляется — она является архитектурным свойством ядра.

---

## Архитектурные принципы

### Ядро закрывается после загрузки

После инициализации и верификации целостности ядро криптографически блокирует возможность модификации самого себя. Руткит физически не может внедриться в ядро — механизм внедрения отсутствует как таковой. В Linux `insmod` может загрузить любой модуль, `/dev/mem` даёт доступ к памяти ядра, а eBPF — одновременно инструмент мониторинга и вектор атаки. В POLER-OS ядро неизменяемо после загрузки: XorDDoS, Plague и подавляющее большинство Linux-руткитов работают через модификацию ядра, а если ядро неизменяемо — 90% атак на ядро отпадают.

### Программа — гость, а не хозяин

Даже процесс с максимальными привилегиями в userspace не может модифицировать ядро. Это отличает POLER-OS от Linux, где root = неограниченный доступ. Root в POLER-OS может всё в userspace, но ядро — неприкосновенно. Компрометация userspace-процесса не означает компрометацию системы.

### Прямая Windows-совместимость

Подход Wine/Proton — обратная совместимость: Windows-программа → прослойка-переводчик → Linux kernel. Всегда что-то теряется: не все API реализованы, DRM и античиты не работают, производительность проседает. POLER-OS реализует прямую совместимость: ядро нативно понимает форматы PE/COFF и обрабатывает Win32/Win64 системные вызовы напрямую, без промежуточного слоя-переводчика. Windows-программа говорит на своём языке, и ядро её понимает нативно. Цель — 100% запуск Windows-софта без прослоек.

### Нативная поддержка Linux-софта

Linux-программы работают нативно — POLER-OS реализует подмножество Linux system call interface, позволяя запускать скомпилированный под Linux софт без перекомпиляции. Долгосрочная цель — нативная поддержка KDE Plasma и других десктопных сред через реализацию достаточного подмножества Linux syscalls для работы Wayland и Qt.

---

## Механизмы защиты

Защита в POLER-OS — не надстройка (как ClamAV поверх Linux), а архитектурное свойство:

| Механизм | Реализация | Уровень |
|---|---|---|
| Криптографическая неизменяемость ядра | Ядро верифицирует свою целостность и блокирует модификацию после загрузки | Ядро |
| Сигнатурный анализ | База сигнатур известных угроз, userspace-сканер с kernel-хуками | Ядро + userspace |
| Эвристический анализ | Мониторинг подозрительных паттернов syscall'ов на уровне ядра | Ядро |
| Поведенческий мониторинг | Детект аномалий: массовое шифрование файлов, нетипичные системные вызовы | Ядро |
| Контроль целостности (FIM) | Хеши критических файлов хранятся в ядре, верификация при каждом доступе | Ядро |
| Обнаружение руткитов | Неизменяемое ядро исключает kernel-level руткиты; userspace-руткиты детектятся через FIM | Ядро + userspace |
| Верификация пакетов | Ядро проверяет цифровую подпись перед установкой; неподписанные пакеты блокируются | Ядро (привратник) |

Пакетный менеджер работает в userspace — ядро не должно содержать логику скачивания и распаковки. Но ядро выступает привратником: userspace-PM ставит, ядро верифицирует подпись и разрешает или блокирует установку.

---

## Текущая версия: v0.19.x (CDD-цикл №12 — графический стек)

**Готовим релиз v0.20.0-rc — ПЕРВЫЙ КАДР (DRM PAGE_FLIP 1024×768).**

| Подсистема | Статус | Описание |
|---|---|---|
| Boot / HAL / ACPI | Готово | Multiboot2 + PVH, 32→64, GDT/IDT/PIC/APIC/IO-APIC/HPET, TSS IST |
| Memory | Готово | PMM (bitmap), VMM 4-level paging + demand-zero (Linux-семантика анонимной памяти), physmap-сканер, kernel heap (SipHash-2-4) |
| Scheduler | Готово | Round-robin preempt + кооперативная парковка сна, полный FPU/AVX-контекст per-task (xsave/xrstor, XCR0=0x207, фреймы 832Б), GPR-GUARD диспетчеризации |
| Ring 3 — Win64 (PE32+) | Готово | PE/COFF парсер + загрузчик, IAT-стабы, .reloc DIR64 (DYNAMIC_BASE), Win64-треды, SocketState-движок, select; curl.exe — HTTPS TLS 1.3; 7-Zip LZMA-бенчмарк (МОМЕНТЫ ИСТИНЫ №4–№8) |
| Ring 3 — Linux (ELF) | Готово | ELF64 loader (static + dynamic: ld.so + glibc PT_INTERP handoff), Linux syscall layer (clone/futex/epoll/poll/mmap/timerfd/wait4/exit_group…), CachyOS rootfs — конвейер из 79 либ в Ring 3 |
| Криптография | Готово | PND v8, RSA-OAEP, POLER-CTR AEAD, PUF-энтропия (анти-клон), верифицированный HTTPS (CA-бандл, без -k) |
| Сеть | Готово | VirtIO-Net, ARP/IPv4/TCP (окно/ретрансмиты/keepalive)/ICMP/DNS, TLS 1.3 (X25519 / ML-KEM-768) |
| Драйверы | Готово | VirtIO-BLK/NET/GPU (vring scan-out), PCI, FAT32 RW, CPIO, evdev (/dev/input), PS/2, serial, CMOS-RTC |
| **DRM-KMS / графконвейер** | **98% — CDD №12 p1–p14** | **gamescope в Ring 3**: Vulkan в ядре (lavapipe/LLVM компилирует реальные шейдеры gamescope), ADDFB2×4=0, libliftoff (GETPROPERTY ×64), timerfd vblank ARM→EXPIRE→OnPollIn→DISARM, Wayland-сокет, EXPORT-FABRIC (4×FABRIC-FD), блокирующий poll (слайс-парк 20мс — TCG-спин мёртв, лог 1.28М→400К) |
| **Первый кадр (PAGE_FLIP)** | **финишная прямая** | Осталось: fork+execve (Xwayland как реальный процесс) → damage → PAGE_FLIP → скриншот 1024×768 → тег v0.20.0-rc |
| SMP | Планируется | Многоядерность |
| VFS / верификатор пакетов | Планируется | Единая виртуальная ФС, крипто-верификация пакетов |

---

## Тесты

- **434/434 юнит-тестов** (12 модулей) — Linux syscall-семантика (poll/epoll/timerfd/fork-ABI), FPU-контекст, VFS, DRM-слой
- E2E-харнессы в `scripts/e2e/`: drm-gamescope-e2e.py (полный конвейер gamescope + Vulkan + DRM + vblank), dyn-elf-e2e.py (ld.so/glibc), pe-run-серия (Win64-регрессии)

## Сборка

### Зависимости

- **Zig 0.14.0** — компилятор
- **QEMU** — для тестирования
- **GRUB** (`grub-pc-bin`, `grub-mkrescue`) — загрузчик
- **xorriso** — создание ISO

Установка зависимостей (Debian/Ubuntu):

```bash
# Минимум для BIOS-загрузки
sudo apt install grub-pc-bin xorriso

# Для UEFI + BIOS dual-boot
sudo apt install grub-pc-bin grub-efi-amd64-bin xorriso mtools
```

### Команды

```bash
# Сборка ядра (32-bit + 64-bit)
zig build

# Сборка загрузочного ISO (BIOS + UEFI если доступны модули)
zig build iso

# Запуск 64-bit ядра в QEMU (serial console, без графического окна)
zig build run64

# Запуск 64-bit ядра в QEMU (VGA окно + serial)
zig build run64-gfx

# Запуск 32-bit ядра в QEMU (legacy)
zig build run32

# Тесты POLER Core + RSA-OAEP
zig build test
```

### Ручная сборка ISO

```bash
cd zig-kernel
zig build
bash build-iso.sh
```

### Запуск ISO в QEMU

```bash
qemu-system-x86_64 -cdrom poler-os64.iso -m 256M -serial stdio -no-reboot
```

---

## Структура проекта

```
zig-kernel/                  # Ядро POLER-OS (Zig 0.14.0)
├── src64/                   # 64-bit ядро
│   ├── main64.zig           # Точка входа, boot sequence, shell, таймеры
│   ├── hal.zig              # GDT/IDT/PIC/APIC/IOAPIC/keyboard/serial
│   ├── acpi.zig / pmm64.zig / vmm64.zig / heap64.zig
│   ├── scheduler.zig        # Планировщик + FPU/AVX-контекст per-task
│   ├── sched_resume.zig     # GPR-GUARD диспетчеризации кадров задач
│   ├── elf_loader.zig       # ELF64 (static + dynamic ld.so/glibc)
│   ├── pe.zig / pe_loader.zig          # PE/COFF PE32+ парсер и загрузчик
│   ├── win32_api.zig / win32_crt.zig / win32_stubs.zig   # Win32 ABI-слой
│   ├── linux_syscalls.zig   # Linux syscall layer (clone/futex/epoll/poll/
│   │                        #  mmap/timerfd/wait4/exit_group…)
│   ├── drm_kms.zig          # DRM-KMS: ADDFB2, ATOMIC, seatd, libliftoff
│   ├── virtio_gpu.zig       # VirtIO-GPU VRING scan-out
│   ├── virtio_blk.zig / virtio_net.zig / pci.zig / evdev.zig
│   ├── vfs.zig / fat32.zig / cpio.zig
│   ├── puf.zig / rsa_oaep.zig / poler_core.zig    # Криптография
│   ├── enroll_gate.zig / framebuffer.zig / smp.zig / multiboot2.zig
│   └── boot64.S / isr64.S / boot_smp.S / linker64.ld
├── src/                     # Legacy 32-bit ядро
└── build.zig / build-iso.sh

scripts/                     # E2E-стенд и тулинг
├── e2e/                     # e2e-харнессы (drm-gamescope-e2e.py,
│   │                        #  dyn-elf-e2e.py, e2e_lib.py, …)
├── build-live-iso.sh        # Live-USB/ISO сборка
├── fetch-cachyos-root.py    # Пакеты CachyOS → rootfs (79 либ, mesa, gamescope)
├── setup-qemu-full.sh       # Развёртывание боевого QEMU-стенда
├── vklayer_poler_drm.c      # Vulkan EXPORT-FABRIC слой (FABRIC-FD)
└── vkprobe2.c / gs_shaders.h / extract-gs-shaders.py / …

cachyos-root/                # CachyOS rootfs: glibc, Mesa (lavapipe),
│                            #  gamescope, wayland-либы — сабстрат Ring 3
qemu-portable/               # Портативный QEMU — тесты без системных зависимостей
docs/                        # Архитектурная документация и анализ
│                            #  (DRM-KMS-Wayland syscall analysis, ARCHITECTURE,
│                            #   math-sources, pe-reference, …)
iso/                         # GRUB-шаблон загрузочного ISO (BIOS/UEFI)
```

## Дорожная карта

### Этап 1 — Ядро — ✅ ЗАКРЫТ
- [x] Загрузка в 64-bit long mode через Multiboot2/GRUB и Xen/QEMU PVH (`.note.gnu.pvh`)
- [x] HAL: GDT, IDT, PIC, APIC, IO-APIC, TSS
- [x] PMM + VMM (demand-zero) + kernel heap + physmap-сканер
- [x] Preemptive multitasking + кооперативная парковка сна
- [x] Полный FPU/AVX-контекст per-task (xsave/xrstor — фиксы 0xAAAA-шторма и R15-POISON)
- [x] Framebuffer, PS/2, serial, CMOS-RTC
- [x] Мульти-пуловый хаб аппаратной энтропии: PUF/TSC + Bus + IRQ + Bio
- [ ] SMP — многоядерность (backlog)

### Этап 2 — Файловая система и драйверы — ✅ ЗАКРЫТ
- [x] VirtIO-BLK (split virtqueues, DMA identity-map)
- [x] FAT32 (чтение/запись/создание/удаление)
- [x] CPIO Initrd-парсер
- [x] VirtIO-Net + мини-стек ARP/IPv4/TCP/ICMP/DNS
- [x] VirtIO-GPU VRING scan-out (пиксельная верификация кадра)
- [ ] VFS-унификация поверх FAT32/cpio/CachyOS-rootfs (частично в vfs.zig)

### Этап 3 — Безопасность — ✅ ЗАКРЫТ (v0.16–v0.18)
- [x] Аппаратная привязка энтропии кремния (PUF Anti-Clone)
- [x] Верифицированный HTTPS без `-k` (CA-бандл через VFS/FILE-API)
- [x] Постквантовые группы X25519 / ML-KEM-768 в TLS 1.3
- [x] Per-Task Syscall State + хардинг-волна (heap IF-фикс, SCAN-SAVE, FRAME-HEAL)
- [ ] Криптоблокировка ядра после загрузки / FIM / сигнатурный сканер (backlog)

### Этап 4 — Совместимость (Win64 PE32+ & Linux ELF) — ✅ ЗАКРЫТ (CDD №1–№12)
- [x] **Windows**: PE32+ загрузка, IAT-стабы, Win64-треды, select, SocketState;
       curl.exe: HTTP → HTTPS TLS 1.3 (МОМЕНТ ИСТИНЫ №4–№6); 7-Zip LZMA (№8)
- [x] **Linux**: ELF static + dynamic (ld.so + glibc PT_INTERP), clone/futex/epoll,
       VMA-семантика Linux, demand-zero, tgkill/abort-путь glibc
- [x] **CachyOS-сабстрат**: 79 либ rootfs в Ring 3 (usr-merge VFS + симлинки)

### Этап 5 — Графическая среда — 🔥 ТЕКУЩИЙ (98%)
- [x] DRM-KMS в ядре (ADDFB2, SETCRTC, ATOMIC, libliftoff: резолв по именам проперти)
- [x] Vulkan в ядре — lavapipe/LLVM компилирует реальные шейдеры gamescope
- [x] gamescope композитор жив в Ring 3 (баннер, VK-инициализация, llvmpipe, wlserver)
- [x] timerfd vblank: ARM → EXPIRE → OnPollIn → DISARM (полный цикл)
- [x] EXPORT-FABRIC: Vulkan-слой libvklayer_poler_drm (4×FABRIC-FD)
- [x] Блокирующий poll (слайс-парк 20мс) — TCG-спин мёртв, лог 1.28М→400К
- [ ] **fork+execve** — Xwayland как реальный процесс (последний километр v0.20)
- [ ] Первый damage → PAGE_FLIP → скриншот 1024×768 → тег **v0.20.0-rc**

### Этап 6 — KDE Plasma 6 — СЛЕДУЮЩИЙ (CDD №13)
- [ ] Qt6 / KWin / Dolphin из CachyOS-пакетов поверх gamescope/Wayland
- [ ] Полноценная сессия рабочего стола в QEMU

## История версий

### v0.19.x — CDD-циклы №11–№12: Linux-сабстрат и gamescope в Ring 3 (текущая ветка)
- **CDD №11 — ДИНАМИЧЕСКИЙ ELF**: Linux-ABI ELF loader (clone-треды, futex park/wake, pthread_join), РЕАЛЬНАЯ glibc static → dynamic (ld.so, PT_INTERP handoff, file-backed сегменты), VirtIO-GPU VRING scan-out с пиксельной верификацией кадра.
- **CDD №12 (p1–p14) — gamescope из CachyOS rootfs в Ring 3**:
  - p1–p2: конвейер либ ld.so (usr-merge VFS + симлинки, AVX/XCR0), syscall-волна, корень isr64 R8-clobber;
  - p3–p4: **Vulkan в ядре** — vkCreateDevice входит в lavapipe/LLVM; mmap-реестр 512→2048; F_DUPFD (корень wl_display_create=NULL); tgkill; vkprobe2 — host ground-truth;
  - p5–p7: demand-zero paging, VMA-семантика Linux, CFS-wakeup-yield, .bss-выходной кадр + clone-TLS/SETTID;
  - p8–p10: кросс-таск hijack закрыт (выходной кадр = строка владельца), 0xAA-шторм (mesa-cache→tmpfs), teardown-инварианты + physmap-сканер (CLEAN);
  - p11–p12: **XMM-КОРЕНЬ 0xAAAA-ШТОРМА** + **R15-POISON/ФЛАКИ-КИЛЛЕР** — полный FPU/AVX-контекст per-task (xsave/xrstor 832Б, syscall/exception/IRQ-фреймы, GPR-GUARD);
  - p13: **SYSCALL-DIFF host-Linux** — дифференциация поведения против настоящего Linux: SEATD, ATOMIC-LITE, PRIME, VFS;
  - p14: **EXPORT-FABRIC + полный DRM-конвейер** — Vulkan-слой (4×FABRIC-FD), ADDFB2×4=0, Wayland-сокет, fake-fork (только fork-подобных clone), timerfd vblank-диагностика (DISARM = норма), **блокирующий poll** (слайс-парк 20мс — TCG-спин мёртв). Тесты: **434/434** (12 модулей).
- **Фронт v0.20.0-rc (финальный столп):** в системе сейчас один ELF (gamescope) — Xwayland ещё не является процессом, ядро не реализует execve. Последний километр — **fork+execve** → Xwayland → damage → **PAGE_FLIP** → первый кадр 1024×768.

### v0.19.0 — CDD-цикл №10: графический фундамент + Live-USB
- Framebuffer & DRM-KMS kernel foundation, evdev + /dev/input, Linux POSIX graphics syscalls (ioctl/futex/epoll/mmap), Live-USB boot infrastructure, CachyOS userspace init.

### v0.18.0 — CDD-цикл №9: Per-Task Syscall State + хардинг
- asm-вход syscall по владельцу user-RSP (kstack/ustack-таблицы), Linux POSIX-фундамент, e2e-харнессы — 329/329, все E2E PASS.

### v0.17.0 — CDD-цикл №8: МОМЕНТ ИСТИНЫ №8 — 7-Zip LZMA в Ring 3
- .reloc DIR64-движок (DYNAMIC_BASE), Win32 RW-слой, msvcrt-нативы, cks-хардинг (heap IF-фикс, SCAN-SAVE, FRAME-HEAL) — 311/311.

### v0.16.0 — CDD-цикл №7: МОМЕНТ ИСТИНЫ №7 — ВЕРИФИЦИРОВАННЫЙ постквант HTTPS
- PUF-энтропия, VFS/FILE-API (CA-бандл — HTTPS без `-k`), IRQ-сетворкер, CMOS-RTC: curl.exe по https с верификацией сертификатов.

### v0.15.0 — CDD-цикл №6: МОМЕНТ ИСТИНЫ №6 — ПОЛНОЕ ЗАМЫКАНИЕ HTTPS (TLS 1.3 в Ring 3)
- **МОМЕНТ ИСТИНЫ №6 — ЗАШИФРОВАННЫЙ ИНТЕРНЕТ В RING 3**: `peload curl.exe -k --curves X25519 https://example.com` в QEMU SLIRP: DNS (104.20.23.154) → TCP-рукопожатие → **настоящий TLS 1.3 handshake** (ClientHello 311Б → ServerHello+Certificate flight 4846Б/16 сегментов → CCS+client Finished 6+58Б) → **зашифрованный HTTP GET (123Б)** через наш virtio-net → **расшифрованный curl-OpenSSL HTML «Example Domain» (585Б тело) напечатан в консоли ОС** → TLS close_notify (31/48/24Б) → graceful FIN → **штатный ExitProcess(0x0)**. Бэклог трапов ПУСТ. TLS-крипто (X25519 + AES-256-GCM + SHA-384, шифр 0x1303) считался самим curl — мы доставили поток бит-в-бит.
- **РОТ-КОЗЁЛ HTTPS-провала v0.14.0 НАЙДЕН И УСТРАНЁН — гонка слайсов**: разведка (pcap + serial) показала: серверный FIN приходил через ~10с TLS-таймаута, потому что клиентский Finished опаздывал на ~40с — **воркер-треды curl крутились в SleepConditionVariableCS(10мс) с мгновенным возвратом** (255K вызовов за прогон!), in_win32_syscall≈всегда поднят → schedule() не тикает → крипто-треду достаются крохи CPU. После фикса: крипто = **1 секунда** (было 40с), CV-вызовы = 43 (было 255K).
- **Кооперативная парковка сна задач** (`scheduler.zig` + `win32_api.zig`): Task.wake_tick (планировщик пропускает спящую до будильника); Sleep/SleepEx/SleepConditionVariableCS → ops.sleep_task → kSleepTask: внутри syscall-транзакции АТОМАРНО (cli) опускаем in_win32_syscall, уходим в hlt-цикл до дедлайна (тики переключают задачи, CPU спит), перед возвратом восстанавливаем СВОЙ user_rsp (мог быть затёрт syscall'ами задач, исполнявшихся в парковке) и флаг транзакции под cli — asm-exit делает sysretq на НАШ стек. Гонка v0.13.0 не вскрылась обратно (регрессии pe-run4/pe-run5 — ALL PASS).
- **TCP Stack Hardening** (`virtio_net.zig`): скользящее окно приёма (реклама РЕАЛЬНОГО места RX-ринга ≤64К, drop+re-ACK при исчерпании, window-update после дренажа — 16-сегментные TLS-flights проходят без потерь); ретрансмиты данных с экспоненциальным бэкоффом (RTX-буфер 32КБ [snd_una..snd_nxt), RTO 200мс→×2→потолок 3с, ≤8 попыток, +FIN в хвосте чанка); keep-alive (1с тишины → проба seq=snd_nxt-1, ≤5 без ответа → abort); честный FIN-кланг: established → fin_wait_1 (наш FIN) → fin_wait_2 (FIN ACKed) → time_wait (финальный ACK) → closed; ACK-машина snd_una-продвижения (сброс RTO/KA-таймеров, seq-обёртки u32).
- **ICMP + сетевая диагностика шелла**: билдеры/парсер Echo Request/Reply (RFC 1071 чексуммы), ответ на входящие ping (SLIRP probe), icmpPing с TSC-RTT-калибровкой; команды `ping <ip|host>` (DNS-резолв цели, пофробные [PING]-логи, сводка), `ifconfig` (eth0: IP/MAC/gw/DNS/link/счётчики RX-TX/ретрансмиты/KА-пробы/DNS-кэш), `netstat` (таблица TCP: пир/состояние/ринг/inflight/FIN/ABORT).
- **strerror_s/_wcserror_s** (C11 Annex K, api-ms-win-crt-runtime): усечение с NUL без выхода за буфер, errno_t-возвраты (0/EINVAL 22), UTF-16LE для wide — TLS-ошибки curl печатаются честным текстом («bad decrypt»-диагностика стала возможна). curl импортирует strerror_s (274 fn / 22 DLL).
- **Диагностика MLKEM (бэклог №7)**: дефолтный пост-квантовый гибрид X25519MLKEM768 (группа 0x11EC, key_share 1124Б) у этой сборки curl/OpenSSL даёт CRYPTO_internal:bad decrypt на декапсуляции (поток бит-в-бит чист — проверено pcap↔ring); чистый X25519 работает идеально — форсируем --curves X25519.
- Тесты: 296/296 (+8 к v0.14: ICMP roundtrip/отбрасывания/echo-reply, sliding-window инварианты, RTX seq-математика обёрток u32, бэкофф-потолок, strerror_s/_wcserror_s). E2E: **pe-run6 ALL PASS** (момент №6: ICMP 4×4 + ifconfig/netstat + HTTPS HTML + exit(0), pcap 9319Б с TLS-record 0x16 0x03) + pe-run5 ALL PASS (HTTP-регрессия) + pe-run4 ALL PASS (loopback-регрессия).

### v0.14.0 — CDD-цикл №5: МОМЕНТ ИСТИНЫ №5 — РЕАЛЬНЫЙ сетевой обмен (VirtIO-Net + SLIRP)
- **МОМЕНТ ИСТИНЫ №5 — НАСТОЯЩИЙ ИНТЕРНЕТ В RING 3**: `curl.exe http://example.com` в QEMU (`-netdev user` + `-device virtio-net-pci`): наш ARP-резолвинг шлюза SLIRP (10.0.2.2) → наш DNS-резолвер (UDP → 10.0.2.3, A-запись example.com → 172.66.147.243) → наше TCP-рукопожатие (SYN → SYN-ACK → ACK) → GET / HTTP/1.1 (75Б) через наш virtio-net TX → **РЕАЛЬНЫЙ HTML-ответ (870Б) «Example Domain» через наш RX** → напечатан curl.exe в консоли ОС (MB2WC → WriteConsoleW) → **штатный ExitProcess(0x0)**. Бэклог трапов ПУСТ. Без единой строки Windows — вся сеть наша.
- **Драйвер VirtIO-Net** (`virtio_net.zig`, 840+ строк): PCI-скан (0x1AF4:0x1000, subsystem 1 — фикс чтения на 0x2E вместо 0x2C), очереди RX (queue 0, posted WRITE-буферы) и TX (queue 1, поллинг used-ring как virtio-blk), MAC из device-config, legacy-контракт **10Б виртуального заголовка перед каждым кадром** (диагноз: pcap-дамп показывал обрезанные 32Б-фреймы вместо 42Б ARP — девайс съедал первые 10Б как заголовок).
- **Мини-стек ядра**: ARP (запрос/ответ, кэш шлюза, ответы на probe SLIRP), IPv4 (RFC 1071 чексуммы, обрезка по total_len — фикс «фантомных данных» из Ethernet-паддинга), TCP (тройное рукопожатие с ретрансмитами SYN, PSH-данные с нарезкой по MSS, RX-кольцо 64КБ на соединение, отложенные ACKи need_ack — фикс анти-реентерабельности: sendTcpAck из pollRx перезаписывал TX-дескриптор в спине sendFrame), DNS (A-записи, сжатие имён).
- **Интеграция сокетов** (плавный fallback по спеке): `net_ready/net_dns_resolve/net_tcp_*` в Ops-инъекции; getaddrinfo при активном драйвере делает НАСТОЯЩИЙ резолв (иначе синтез TEST-NET), connect — настоящее TCP-соединение (иначе loopback-шим), send/recv — данные через virtio (лог `[NET-SEND]`/`[NET-RECV]`), select — активный RX-поллинг. Регрессия pe-run4 (loopback-путь) — ALL PASS.
- **SSPI/SChannel TLS Engine (SYNTHETIC-TLS)**: полная таблица SecurityFunctionTable + QuerySecurityPackageInfo/AcquireCredentialsHandle/InitializeSecurityContext (генерация НАСТОЯЩЕГО TLS ClientHello: record 0x16, random, cipher-suites, SNI/ALPN; парсинг ServerHello)/EncryptMessage/DecryptMessage (XOR-поток по сессионному ключу, STREAM_HEADER/TRAILER по контрактам SChannel)/QueryContextAttributes(STREAM_SIZES)/Delete/Free; сокет-машина https (порт 443 → синтетический сервер). Разведка: curl.exe 8.21 MSYS2 содержит ВСТРОЕННЫЙ OpenSSL (сертификат: настоящий ClientHello 1539Б из Ring 3 отправлен и server-flight принят+расшифрован) — полный SChannel-путь не активируется этой сборкой; HTTPS-финализация — цикл №6.
- **Wave-A + ctype + byteswap**: CreateMutexA (пул 0x400+, WaitFor→WAIT_OBJECT_0), bcrypt!BCryptGenRandom (xorshift-энтропия), ReleaseMutex, strnlen, inet_pton, isalnum/isdigit/isalpha/isupper/islower/isxdigit/ispunct (punycode-резолвер: isalnum-trap → livelock), _byteswap_ulong/ushort/uint64 (OpenSSL TLS-потоки).
- **Native qsort (175Б, GNU as)**: insertion-sort с вызовом КОМПАРАТОРА приложения из Ring 3 (прецедент native-bsearch v0.12); OpenSSL сортирует cipher-списки — trap → livelock. kStackArg расширен до arg10 (InitializeSecurityContext — 10 аргументов).
- Тесты: 288/288 (+17 к v0.13: 10 virtio_net-билдеры/чексуммы/DNS-парсеры, 5 SSPI/TLS-движка, Wave-A, qsort). E2E: **pe-run5 ALL PASS** (момент №5: реальный HTML + exit(0), pcap-дамп 2399Б) + pe-run4 ALL PASS (loopback-регрессия).

### v0.13.0 — CDD-цикл №4: МОМЕНТ ИСТИНЫ №4 — первый HTTP-обмен в POLER-OS
- **МОМЕНТ ИСТИНЫ №4 — ПОЛНЫЙ ЗАМКНУТЫЙ ЦИКЛ**: `curl.exe http://example.com` в Ring 3: … → connect(192.0.2.1:80) → select (WRITABLE) → **send(«GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.21.0…», 75Б)** → recv(«HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello POLER!\n», 52Б) → MultiByteToWideChar → WriteConsoleW → **«Hello POLER!» напечатан curl.exe в консоли ОС** → **штатный ExitProcess(0x0)**. Бэклог трапов ПУСТ — цепочка дошла до конца без новых падений.
- **SocketState-движок** (`win32_crt.zig`): таблица состояний сокетов (fd=0x100+индекс): опции (TCP_NODELAY/SO_KEEPALIVE/SO_RCVBUF/SO_SNDBUF), nonblocking, connected, peer/local адреса, события FD_* (pending/mask/авто-сброс). setsockopt/getsockopt (SO_ERROR=0 — статус неблокирующего connect), getsockname/getpeername (заполнение sockaddr_in, эфемерный порт), shutdown.
- **Мультиплексор select с НАСТОЯЩЕЙ семантикой**: fd_set перезаписывается (остаются только готовые дескрипторы — curl проверяет через __WSAFDIsSet), подключённый сокет WRITABLE, после send — READABLE; exceptfds очищается.
- **Event-машина WS2**: WSAEventSelect/EnumNetworkEvents с ОТЧЁТОМ FD_CONNECT (iErrorCode[FD_CONNECT_BIT]=0 — curl узнаёт о завершении неблокирующего connect — КЛЮЧ волны: до этого вечный поллинг), авто-сброс записей, производная сигнальность WSAWaitForMultipleEvents.
- **Loopback-HTTP**: send — валидация буфера + лог первого payload `[HTTP-SEND]` + возврат len; recv — синтет-ответ «HTTP/1.1 200 OK…Hello POLER!\n» (Content-Length честен — curl завершает передачу по телу), по исчерпании 0=EOF+FD_CLOSE.
- **КРИТИЧЕСКИЙ фикс планировщика — гонка user_rsp (латентная с v0.12, взорвалась на 3 Ring-3 задачах)**: глобальный user_rsp в isr64.S перезаписывался чужим тредом, когда таймерный тик прерывал syscall-обработчик и переключал задачу — sysretq выбрасывал задачу на ЧУЖОЙ стек. Лечение: флаг in_win32_syscall (isr64.S ставит/снимает при IF=0; schedule не переключает задачу внутри syscall-транзакции; сброс в exit-пути — иначе deadlock hlt).
- **Прочие фиксы планировщика**: атомарность переключения (cli вокруг schedule в handleIRQ — вложенные тики меняли состояние среди кадра), структурная валидация кадров (rsp обязан лежать в собственном kstack задачи; мусор → задача пропускается), kernel_stack 8→32КБ (переполнение cmd_peload затирало header нижележащей tasks[] — kernel-panic каскад), канарейки внизу каждого kstack (детектор переполнения), guard @ptrFromInt(0) в таймерном пути (паники «cast causes pointer to be null»/«incorrect alignment»).
- **Финал-волна печати**: SleepEx, _get_osfhandle (fd → stdio-псевдохэндлы), MultiByteToWideChar (ASCII→UTF-16LE, двухфазный вызов UCRT), WriteConsoleW (UTF-16LE → UTF-8 → консоль ОС) — без них curl печатал «(23) ERROR on write».
- Тесты: 271/271 (+5 к v0.12: send/recv-loopback, sockopt, sockname, events, MB2WC). E2E: **pe-run4 ALL PASS** (момент №4 + Hello POLER! + exit(0); цикло №1-совместимые pe-run v1 + kbd 9/9 + pe-e2e PASS — все регрессии зелёные).

### v0.12.0 — CDD-цикл №3: нативная версия/SSPI/окружение, МОСТ КОЛБЭКА, Win64-треды, connect()
- **МОМЕНТ ИСТИНЫ №3c**: `curl.exe` (реальный PE32+, 3.8МБ) в Ring 3 проходит ПОЛНЫЙ путь сетевой инициализации: CRT-init → main() → парсинг URL (`--url` через native-bsearch) → конфиг/CA-поиск → WSAStartup → InitSecurityInterfaceA (SSPI-таблица 25/25) → **два Dns-треда** (Happy Eyeballs) → getaddrinfo (синтез TEST-NET) → socket(AF_INET) → ioctlsocket(FIONBIO) → **connect(192.0.2.1:80) — ЦЕЛЬ ЦИКЛА ДОСТИГНУТА**.
- **НАСТОЯЩИЕ Win64-треды**: `CreateThread` → задача планировщика на ТОЙ ЖЕ PML4 (общее адресное пространство, как процесс Windows): RCX=param, [rsp]=exit-трамплин (динамическая extra-запись `ExitThread`), стек 64КБ из vheap; возврат из ThreadProc = syscall #6 → kill задачи. WaitFor-семья видит мёртвый тред-хэндл (WAIT_OBJECT_0) — резолвер будит цикл curl.
- **Мост Win64-колбэка** (`InitOnceExecuteOnce`): вызов user-кода из syscall-обработчика без разрушения ядра — sysretq → launcher (Ring 3) → callback → trampoline → syscall #7 (cb_done) → восстановление сохранённого syscall-кадра; вложенность (глубина 2), стек транзакций.
- **Enrollment-Gate** (спека §4): `enroll_gate.zig` — TSC-кремниевый отпечаток (CPUID-детерминизм, sponge-фолдинг), bindEnrolled() при буте — сверка с запечённым эталоном; `[ENROLL] PASSED`.
- **Нативная версия/окружение** (не эмуляция — контракт): VerSetConditionMask (покомпонентные маски), VerifyVersionInfoW с ТЮПЛЬ-семантикой (major/minor) — «да, эта машина Win10-совместима»; GetEnvironmentVariableA/W с LastError-контрактом (ERROR_ENVVAR_NOT_FOUND); FormatMessageA/W со стек-аргументами; строки: strcmp/strncmp — native Ring-3-код (машинные байты сверены с GNU-as), _strdup/strchr/strrchr/strstr/memcmp/strcspn/_stricmp/atoi/strtol/…; strerror/setlocale/mbstowcs_s/_time64.
- **WSA-event-каркас**: WSACreateEvent (пул 0x200+; ранее trap-NULL → «curl: (27) Out of memory»), WSAEventSelect/EnumNetworkEvents/WaitForMultipleEvents, __WSAFDIsSet с РЕАЛЬНОЙ семантикой fd_set (массив с смещения 8!), WSAIoctl, CreateEventA, WaitFor-семья, CS/CV-функции.
- **Native-bsearch**: 142Б Ring-3-кода (3 слота) — вызывает КОМПАРАТОР ПРИЛОЖЕНИЯ (не наш код!) из Ring 3; собран через GNU `as` (после двух ошибок ручного кодирования — volаtile-регистр RDX убил p-указатель; регрессионный тест с RDX-затирающим компаратором).
- Исправления на пути: ucl_pending не сбрасывался после редиректа (бесконечный цикл моста — isr64.S), размер OSVERSIONINFOW = 284 (szCSDVersion = 128 WCHAR!), стек-аргументы Win64: arg5 = [rsp+0x28] у callee (32Б shadow).
- Тесты: 266/266 (+52 к v0.11: мост, SSPI, ws2, версия, окружение, строки, события, треды). E2E: pe-run3 ALL PASS (моменты №3a/№3b/№3c) + pe-run v1 (цикло-агностичен) + kbd 9/9 + pe-e2e PASS.

### v0.11.0 — CDD-цикл №2: вторая волна Win32/CRT API + углубление в main()
- **МОМЕНТ ИСТИНЫ №2**: curl.exe печатает свой текст (`curl: error initializing curl library`) через наш fputs/fputc в консоль ОС — приложение дошло до WSAStartup → realloc → GetConsoleScreenBufferInfo → вывод → штатный exit(2).
- Модуль `src64/win32_crt.zig` (новый, ~1300 строк): ЧИСТАЯ семантика Win32/CRT с Ops-инъекцией (прецедент LoaderOps) — нативно тестируется вся семантика: block-heap, GetProcAddress, QPF/QPC, консольные структуры, ленивые argc/argv/iob.
- **Native-стабы** (`win32_stubs.zig`): memset/memcpy/memmove/strlen — чистый Ring-3 машинный код (rep stosb/movsb, 20/20/41/14 байт) без syscall-оверхеда; тесты РЕАЛЬНО исполняют сгенерированный код с Win64-раскладкой регистров.
- **Block-heap с заголовками** (16Б: magic+size): malloc/calloc/realloc/free — realloc читает СТАРЫЙ размер из заголовка (то, чего не хватало v0.10); heap-регион разделён на vheap (VirtualAlloc) и bheap (CRT).
- **GetProcAddress**: динамический резолв по реестру стабов — возврат user-VA трамплина; чужое имя → NULL + CDD-лог (видимость динамических запросов).
- **QPF/QPC**: калибровка TSC по тикам APIC-таймера (PIT-калиброванного, 100 Гц) при peload; QPC — hal.readMsr(0x10).
- Ленивые CRT-структуры (syscall-контекст): стабильный iob-массив 3×80Б, argc/argv с токенизацией cmdline НА МЕСТЕ, РАЗДЕЛЬНЫЕ `__p__fmode`/`__p__commode`/`_errno` (v0.10-баг: каждая пара получала один блок).
- **Валидация user-указателей из ядра** (vmm.userLeafFlags): walk PML4 процесса через identity — мусорный аргумент → отказ, а не #PF-паника ядра; kernel-VA (без USER-бита) → отказ (security).
- **Латентный баг v0.10.0 пойман и исправлен** (GCC-эталон + исполнение): байты `4C 89 C2` в syscall-трамплине были `mov rdx, r8` вместо `mov r10, r8` — все impl-функции с ≥2 аргументами получали перепутанные аргументы (1-аргументные — потому и работали).
- Два собственных бага native-стабов пойманы исполнением: `rep stosb` пишет AL (не DL), `rep movsb` с DF=1 идёт вниз от ТЕКУЩИХ rsi/rdi (нужна lea-предустановка на конец региона).
- Вейв-2 по логу цепочки v0.10.0: 16 трамплинов + 4 native = 20 функций (GetProcAddress, QPF/QPC, GetConsoleMode/ScreenBufferInfo, SRWLock, GetCurrentThreadId, SetUnhandledExceptionFilter, setvbuf, fputs/fputc/fflush, realloc, WSAStartup/WSACleanup…).
- Тесты: 196/196 (27 win32_crt-тестов; STUB_CODE_SIZE 31→48). E2E: pe-run2 13/13 PASS + pe-run (v1) + kbd 9/9 + peinfo/pestubs — все зелёные.

### v0.10.0 — Ring-3 PE64 Execution & CDD Cycle #1
- Модуль `src64/pe_loader.zig`: посекционный маппинг PE64 в виртуальную память (ImageBase `0x140000000`), инициализация структуры процесса, командной строки, TEB/PEB и выделение стека Ring 3.
- Модуль `src64/win32_api.zig`: диспетчер системных вызовов (syscall #6) с поддержкой базовых CRT и Win32 функций (`GetStdHandle`, `VirtualAlloc` с реальным PMM+VMM, `malloc`, `exit`).
- Поддержка команды `peload <file>` в шелле ядра: загрузка, IAT-патчинг стабами и запуск `curl.exe` в Ring 3 с передачей управления на `AddressOfEntryPoint`.
- Исправление критических ошибок архитектуры:
  - Коррекция GDT-селекторов под инструкцию `SYSRET` (устранен `#GP(0x20)`).
  - Сохранение callee-saved регистров `RSI`/`RDI` в syscall-трамплинах Win64 ABI.
  - Удален флаг `USER` с листовых страниц ядра 0–4 ГБ в `boot64.S` (аппаратная изоляция Ring 3).
- Добавлен `.gitattributes` (`linguist-vendored` для `upload/` и `docs/`) — статистика GitHub показывает честные 95%+ Zig.
- Тесты: 167/167 нативных юнит-тестов, 16/16 E2E тестов в QEMU.

### v0.9.0 — PE/COFF (PE32+) Loader & Win32 Stub Dispatcher
- Модуль `src64/pe.zig`: полноценный парсер исполняемых файлов Win64 (PE32+). Поддержка DOS Header, COFF Header, Optional Header 64, Section Table, Data Directories, Data Directory IAT (Import Address Table).
- Харденинг выравнивания `align(1)`: безопасный разбор невыровненных бинарных образов из CPIO Initrd без паник `@alignCast`.
- Модуль `src64/win32_stubs.zig`: динамический генератор Win64-стабов (31 байт на функцию с выравниванием стека `sub/add rsp, 8` для предотвращения `#GP`).
- Режимы работы стабов: `.int3` (контролируемый брейкпоинт в ядре) и `.record` (лог вызовов для нативных тестов).
- Интерактивные команды ядра: `peinfo <file>` и `pestubs <file>`.
- Тестовая верификация: 152/152 нативных юнит-тестов (запуск через `addRunArtifact`), успешный парсинг `curl.exe` (22 DLL, 274 функции).

### v0.8.0 — PVH Boot Protocol & Direct QEMU 11 Support
- Встроена секция `.note.gnu.pvh` в `boot64.S` для прямой загрузки ядра через `qemu-system-x86_64 -kernel` в современных версиях QEMU (≥11).
- Поддержка структур `hvm_start_info` и `HvmModListEntry` для обнаружения Initrd модулей при PVH-старте.
- Устранена уязвимость зацикливания парсера Multiboot2 при невалидном `multiboot_info`.

### v0.7.3 — Input Pipeline & Scheduler Hardening
- Исправлена критическая ошибка захвата сканкодов в Bio-пуле (устранено чтение порта 0x60 до обработчика клавиатуры).
- Корректная таблица PS/2 Scancode Set 1, маскирование PIC IRQ1 для устранения дублирования прерываний.
- Подключение `timerTickCallback` в планировщике, выравнивание стека задач по SysV ABI.

### v0.7.2 — Multi-Pool Hardware Entropy Hub
- Полная реализация всех 4 пулов физической энтропии по спецификации `POLER_OS_POST_QUANTUM_HARDWARE_ENTROPY_SPEC.md`:
  1. **Phase Pool** (`DOMAIN_POOL_PHASE`): кремниевый PUF-джиттер и TSC флуктуации
  2. **Bus Pool** (`DOMAIN_POOL_BUS`): задержки транзакций шины PCIe / VirtIO DMA I/O
  3. **IRQ Pool** (`DOMAIN_POOL_IRQ`): интервалы аппаратных прерываний (APIC Timer / IO-APIC)
  4. **Bio Pool** (`DOMAIN_POOL_BIO`): биодинамика пользователя (тайминги нажатия клавиш клавиатуры)
- Модуль `UnifiedEntropyHub` в `src64/puf.zig` — синхронное аккумулирование и свертка всех пулов через SipHash-диффузию
- Инструментирование HAL и VirtIO: `hal.irq_entropy_sink`, `hal.bio_entropy_sink`, `virtio_blk.bus_entropy_sink`
- Автоматическая регенерация PRNG ядра каждые 64 аппаратных прерывания
- Команда интерактивного шелла `entropy` для мониторинга в реальном времени

### v0.7.1 — PUF Hardware Entropy Binding
- Модуль `src64/puf.zig`: экстрактор аппаратной энтропии (SipHash-губка
  с доменным разделением: сид / identity / live-пул)
- Boot-привязка: сбор TSC-джиттера (128 замеров IA32_TSC) → сид PRNG
  ядра + печать 256-бит device identity (спека
  `docs/POLER_OS_POST_QUANTUM_HARDWARE_ENTROPY_SPEC.md`)
- Анти-клон: `enroll()`/`bindEnrolled()` — мажоритарный консенсус +
  стабильная маска; чужой кремний/VM → `NotThisDevice`
- Health-check (sparse-aware) + LivePool для подмешивания живой
  энтропии в рантайме
- 11 юнит-тестов PUF (нативно, `zig build test`)
- Docs: версия тулчейна выровнена с реальностью — Zig 0.14
  (миграция Allocator `std.mem.Alignment` — коммит cd6e7b37)

### v0.7.0 — Ring 3 User Mode
- ELF64 loader, per-process CR3, TSS IST1
- User code/data segments (CS=0x1B, SS=0x23)
- syscall/sysretq privilege switch
- IRETQ для возврата в user mode

### v0.6.1 — Bug Fixes
- CTR brace mismatch в hybridEncrypt()
- Q glyph рендеринг
- Circular import hal↔scheduler → callback

### v0.6.0 — Preemptive Multitasking
- Round-robin scheduler с APIC timer
- 8 одновременных задач
- Context switch через stack-based состояния

### v0.5.0 — 64-bit Long Mode
- Multiboot2 boot, 32→64 переход
- HAL: GDT, IDT, PIC, APIC
- PMM + VMM + kernel heap

---

## Лицензия

GNU General Public License v3.0 or later (GPLv3+). См. [LICENSE](LICENSE).
