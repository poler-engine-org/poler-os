# AGENT STATE — машиночитаемое состояние агента (poler-os)

> Обновляется в конце каждой сессии и после значимых коммитов.
> Истинный HEAD — `git log -1 --oneline`. Формат — строгий `key: value`.

updated_utc: 2026-09-01T16:45:00Z
repo: poler-os
branch: main
commit: (см. git log -1 — v0.10.0)
tag: v0.10.0
pushed: true
tests: zig build 5/5; zig build test 167/167 (addRunArtifact — реальный прогон); E2E QEMU 11.0.2 (PVH+TCG, -m 256M): kbd 9/9 PASS, peinfo/pestubs PASS, **pe-run-e2e ALL PASS** (CDD-цикл №1: peload curl.exe → Ring 3 → 17 missing + 20 impl calls → штатный exit → шелл жив)
current_task: CDD-цикл №1 — VMM-маппинг PE64 в Ring 3 + IAT-патч стабами + запуск EntryPoint — ВЫПОЛНЕН
current_task_note: v0.10.0 — pe_loader.zig (посекционный маппинг по ImageBase 0x140000000, права по секциям P/RW/NX, BSS-обнуление, TEB/PEB/params+cmdline UTF-16, user-стек; LoaderOps-инъекция — весь лоадер покрыт нативными тестами на реальном curl.exe), win32_stubs.zig v2 (три варианта стабов: trap=xor/int3/ret, impl=syscall-трамплин #6 с push/pop RSI/RDI — фикс callee-saved-бага Win64 ABI, record=нативные тесты; logical_base для user-VA), win32_api.zig (GetStdHandle, GetCommandLineA/W, VirtualAlloc=реальный PMM+VMM bump-аллокатор, ExitProcess, GetModuleHandleA/W, Sleep, __acrt_iob_func, __p__fmode/__p__commode/__p___argc/__p___argv/__p__environ, _errno, malloc/calloc/free, exit/_exit/abort, initterm-семья); hal.zig (int3Callback для CDD-трапов, syscall #6 win32_call с 6-м аргументом r9, CR2+регистры в #PF-дампе); БАГФИКСЫ: GDT раскладка для SYSRET (0x18=UserData/0x20=UserCode — до фикса sysret грузил CS=0x23=DATA→#GP(0x20) на первом iretq из int3), boot64.S identity 0-4ГБ без USER-бита (изоляция Ring3: до фикса user-маппинг открывал ВСЁ ядро), pmm.reserveRange+allocContiguousZeroed (initrd защищён); команда шелла peload/run
next_task: CDD-цикл №2 — по логу цепочки v0.10.0: api-ms-win-crt-string!memset (реальная имплементация с записью в user-память), KERNEL32!GetProcAddress (динамический резолв через наш реестр стабов), QueryPerformanceFrequency/Counter (TSC), GetCurrentThreadId, SRWLock (no-op), realloc; далее — п.2 плана: Enrollment-Gate (bindEnrolled) в бут-пайплайне (PUF-энтропия уже в puf.zig); .reloc-обработка для образов с DYNAMIC_BASE вне предпочтительного базиса
blocked_on: —
tmux_sessions: нет (tmux отсутствует в песочнице — QEMU 11.0.2 фоном: serial→file + monitor→unix-sock; харнессы /home/z/my-project/scripts/{kbd-test,pe-e2e-test,pe-run-e2e}.py)
credentials: ВАЛИДЕН — файл-хранилище upload/«гитхаб токен .txt»; подача через /home/z/my-project/scripts/gh-cred-helper.sh
notes: канон протокола — POLER-Quantum-RS v0.3.8 (AGENT.md); upload/ содержит токены и чувствительные файлы — в git не коммитить; .gitattributes (v0.10.0) — linguist-vendored для upload/grub-local/qemu-portable, linguist-documentation для docs/pe-reference; удалённый origin = https://github.com/poler-engine-org/poler-os.git; осиротевшая июльская цепочка v1.2.0 (228f9fdc) содержит готовые решения (timer callback, kernel shell, FAT32) — сверяться перед реврайтом

## Последние сессии

| Дата (UTC) | Задача | Результат |
|---|---|---|
| 2026-09-01 | v0.10.0: CDD-цикл №1 — Ring-3 запуск curl.exe | pe_loader.zig (ops-инъекция, посекционные права, TEB/PEB, 15 нативных тестов), win32_stubs v2 (trap/impl/record), win32_api.zig (34 имплементации), syscall #6. МОМЕНТ ИСТИНЫ состоялся: 17 недостающих функций в цепочке (setvbuf, GetProcAddress, WSAStartup, memset…), 20 реализованных вызовов, curl дошёл до main(), штатный exit. Два критических багфикса на пути: GDT/SYSRET-раскладка (CS=0x23/SS=0x1B) и callee-saved RSI/RDI в syscall-трамплине; boot64.S identity без USER-бита (изоляция). E2E: 16 проверок ALL PASS + регрессии kbd 9/9, peinfo PASS |
| 2026-09-01 | v0.9.0: PE/COFF-лоадер + CDD-стабы (п.1 плана) | pe.zig: парсер PE32+ (без аллокаций, @alignOf==1 на всех структурах — фикс @alignCast-паники на непроверенном входе); win32_stubs.zig: стабы 31Б с выравниванием стека (фикс #GP: movaps на rsp%16==0) и указателем-синглтоном (фикс потери счётчиков). РАЗОБЛАЧЕНО: «zig build test» раньше только КОМПИЛИРОВАЛ бинарники (Step.Compile) — падения/паники не ловились; теперь addRunArtifact → 152/152 реально выполняются. Фикстура: curl.exe (PE32+, 22 DLL/274 fn). E2E QEMU PVH+initrd: 16/16 (peinfo/pestubs) |
| 2026-09-01 | v0.7.3 + v0.8.0: аудит коммитов «antigravity» и фикс | Ревизия v0.7.2: энтропия-хаб оставлен, но найден критический баг (bio-пул читал порт 0x60 ДО handleKeyboard → клавиатура мертва в рантайме). v0.7.3: sink на TSC, Set1-таблица переписана (сдвиг на 1), OBF-гард + маскирование PIC (двойная доставка IRQ1), атомики kbd-буфера, timerTickCallback подключён, шелл на kernel-direct вызовах, стек -8 (SysV ABI), virtio-dump восстановлен, cmd_entropy рефактор. v0.8.0: PVH ELF-note из ассемблера (lld не умеет .long в скриптах!), защита Parser.init(0)/findTag, PMM PVH-fallback. E2E 9/9 |
| 2026-08-31 | v0.7.2 Multi-Pool Entropy Hub | Все 4 пула по спеке (Phase, Bus, IRQ, Bio) + UnifiedEntropyHub + авто-регенерация PRNG + команда entropy; 34/34 тестов |
| 2026-08-31 | v0.7.1 + перенос в оргу | poler-os → poler-engine-org (3-й репо консолидации, private); 94a29e0: puf.zig + boot-привязка TSC-энтропии + 11 тестов; тег v0.7.1; Zig 0.14.0 |
| 2026-08-28 | agent-протокол | AGENT.md-стаб + AGENT_STATE.md (канон: POLER-Quantum-RS v0.3.8) |
| 2026-08-27 | VGA/framebuffer | 594305d: fb_ptr32, CR/LF, Zig 0.14 |
