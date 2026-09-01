# POLER-OS

**Универсальная операционная система нового поколения. x86_64, монолитное ядро, Zig 0.14.0.**

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

## Текущая версия: v0.13.0

| Подсистема | Статус | Описание |
|---|---|---|
| Boot | Готово | Multiboot2 → 32→64 transition → identity paging (4GB, 2MB pages) |
| HAL | Готово | GDT, IDT, PIC remap, Local APIC timer (vector 48), IO-APIC, TSS IST1 |
| ACPI | Готово | RSDP/RSDT/MADT/HPET parsing |
| Memory | Готово | PMM (bitmap), VMM (4-level paging + OOM rollback), kernel heap (free-list + SipHash-2-4) |
| Scheduler | Готово | Round-robin с APIC timer preemption (8 задач, 32КБ kernel-стеки, атомарное переключение, структурная валидация кадров) |
| Ring 3 | Готово | User mode: ELF64 loader, per-process CR3, syscall/sysretq, TSS IST, транзакции syscall (in_win32_syscall — многотредовая безопасность) |
| Framebuffer | Готово | Linear framebuffer (1024x768x32bpp) + bitmap font |
| Keyboard | Готово | PS/2 Set 2 → Set 1 translation через i8042 controller (bit 6) |
| Serial | Готово | COM1 (115200 baud, 8N1) |
| Crypto | Готово | PND v8 (Parametric Nonlinear Diffusion), RSA-OAEP + POLER-CTR AEAD |
| PUF | Готово | Привязка аппаратной энтропии: TSC-джиттер → сид PRNG ядра + identity; анти-клон enrollment (спека POST_QUANTUM_HARDWARE_ENTROPY) |
| Syscalls | Готово | syscall/sysretq: print, read_key, clear_screen, win32_call (#6), cb_done (#7) |
| **Win32 PE Runtime** | **CDD-циклы 1–4** | **curl.exe в Ring 3 — ПОЛНЫЙ HTTP-ОБМЕН**: CRT-init → main() → 2 Win64-треда (Happy Eyeballs) → getaddrinfo → socket() → connect() → select → **send(«GET / HTTP/1.1…», 75Б)** → recv(HTTP/1.1 200 OK, 52Б) → **«Hello POLER!» в консоли ОС** → штатный exit(0). 128 имплементаций + 6 native-стабов, SocketState-движок (опции/события FD_*/loopback-I/O), мультиплексор select с перезаписью fd_set, мост колбэка InitOnce, Enrollment-Gate |
| SMP | Планируется | Многоядерность |
| Networking | Планируется | virtio-net (реальный стек вместо loopback-штора) |
| VFS | Планируется | Виртуальная файловая система |
| Package verifier | Планируется | Криптографическая верификация пакетов на уровне ядра |

---

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
zig-kernel/
├── src64/                    # 64-bit ядро (POLER-OS v0.7.0)
│   ├── boot64.S              # Multiboot2 header, 32→64 переход, page tables
│   ├── isr64.S               # ISR/IRQ stubs + syscall entry
│   ├── main64.zig            # Точка входа, boot sequence, shell
│   ├── hal.zig               # HAL: GDT/IDT/PIC/APIC/IOAPIC/keyboard/serial
│   ├── acpi.zig              # RSDP/RSDT/MADT/HPET парсинг
│   ├── pmm64.zig             # Physical Memory Manager (bitmap)
│   ├── vmm64.zig             # Virtual Memory Manager (4-level paging)
│   ├── heap64.zig            # Kernel heap (free-list + SipHash-2-4)
│   ├── scheduler.zig         # Round-robin scheduler (APIC preempt)
│   ├── elf_loader.zig        # ELF64 loader (Ring 3 user mode)
│   ├── framebuffer.zig       # Linear framebuffer + bitmap font
│   ├── multiboot2.zig        # Multiboot2 info parser
│   ├── cpio.zig              # CPIO initrd parser
│   ├── poler_core.zig        # PND v8 tensor algebra
│   ├── rsa_oaep.zig          # RSA-OAEP + POLER-CTR AEAD
│   └── linker64.ld           # Linker script
├── src/                      # Legacy 32-bit ядро
│   ├── boot32.S              # 16-bit real → 32-bit protected mode
│   ├── isr32.S               # 32-bit ISR stubs
│   ├── main32.zig            # 32-bit kernel entry
│   └── ...
├── drivers/                  # Общие драйверы
├── arch/                     # Архитектурно-зависимый код
├── boot/                     # Boot logic
├── mm/                       # Memory management helpers
├── iso/                      # GRUB ISO структура (BIOS boot)
├── iso-efi/                  # GRUB ISO структура (UEFI boot)
├── iso-minimal/              # Минимальная ISO структура
├── build.zig                 # Конфигурация сборки Zig
├── build-iso.sh              # Скрипт сборки ISO (auto-detect BIOS/UEFI)
├── build-minimal-iso.sh      # Минимальная ISO сборка
├── run-qemu.sh               # Скрипт запуска QEMU
└── run-qemu-iso.sh           # Скрипт запуска QEMU с ISO
```

---

## Дорожная карта

### Этап 1 — Ядро (текущий)
- [x] Загрузка в 64-bit long mode через Multiboot2/GRUB и Xen/QEMU PVH (`.note.gnu.pvh`)
- [x] HAL: GDT, IDT, PIC, APIC, IO-APIC, TSS
- [x] Управление памятью: PMM + VMM + kernel heap
- [x] Preemptive multitasking: round-robin scheduler
- [x] Ring 3: user mode, ELF64 loader, per-process CR3
- [x] Криптография: PND v8, RSA-OAEP, POLER-CTR AEAD
- [x] Framebuffer, PS/2 клавиатура, serial console
- [x] Мульти-пуловый хаб аппаратной энтропии: PUF/TSC + Bus + IRQ + Bio
- [ ] SMP — многоядерность

### Этап 2 — Файловая система и драйверы
- [x] VirtIO-BLK драйвер диска (split virtqueues, DMA identity-map)
- [x] FAT32 файловая система (чтение, запись, создание, удаление файлов и папок)
- [x] CPIO Initrd парсер для загрузки образов и утилит
- [ ] VFS (виртуальная файловая система)
- [ ] Драйвер AHCI/SATA
- [ ] Драйвер сети (virtio-net / e1000)
- [ ] USB stack

### Этап 3 — Безопасность
- [x] Аппаратная привязка энтропии кремния (PUF Anti-Clone)
- [ ] Криптографическая блокировка ядра после загрузки
- [ ] Верификация целостности системных файлов (FIM)
- [ ] Сигнатурный сканер (userspace + kernel hooks)
- [ ] Поведенческий мониторинг на уровне ядра
- [ ] Верификатор пакетов (kernel gatekeeper)

### Этап 4 — Совместимость (Win64 / PE32+ & Linux)
- [x] PE/COFF (PE32+) парсер заголовков (DOS, File, Optional64, Sections, DataDirectories)
- [x] Парсинг Import Directory Table (IAT / OriginalFirstThunk / FirstThunk)
- [x] Генератор динамических Win32-заглушек (Stub Dispatcher) с int3 контролируемым остановом (Crash-Driven Development)
- [x] Интерактивные команды шелла `peinfo`, `pestubs` и `peload` (загрузка + запуск)
- [x] VMM-маппинг секций PE64 в Ring 3 по ImageBase с посекционными правами (RW/NX/USER)
- [x] Запуск EntryPoint реального приложения (curl.exe): CRT-init → main() → аргументы → крипто/SSPI-init → Dns-треды → socket() → connect() → select → send() → recv() → печать тела → exit(0) (v0.10–v0.13, CDD-циклы 1–4)
- [x] Реализация базовых API kernel32/UCRT/WS2_32 «по мере запросов» (CDD): 128 syscall-трамплинов + 6 native-стабов (memset/memcpy/memmove/strlen/strcmp/strncmp + native-bsearch), block-heap, GetProcAddress, QPF/QPC (TSC), НАСТОЯЩИЕ Win64-треды, Enrollment-Gate, SocketState-движок с событиями FD_* и loopback-HTTP
- [ ] Следующие CDD-циклы: TLS-стек (SChannel: InitializeSecurityContext/AcquireCredentials через SSPI-таблицу — https://), DNS-резолвер реальный (сейчас — синтез TEST-NET), .reloc для DYNAMIC_BASE, сетевой стек virtio-net (замена loopback-шиму) — по логу цепочки v0.13.0
- [ ] Подмножество Linux system call interface
- [ ] POSIX compatibility layer

### Этап 5 — Графическая среда
- [ ] GPU driver (минимальный)
- [ ] Wayland / собственный display server
- [ ] Qt портирование / нативная поддержка
- [ ] KDE Plasma или собственная DE

---

## История версий

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
