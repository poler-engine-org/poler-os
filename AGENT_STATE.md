# AGENT STATE — машиночитаемое состояние агента (poler-os)

> Обновляется в конце каждой сессии и после значимых коммитов.
> Истинный HEAD — `git log -1 --oneline`. Формат — строгий `key: value`.

updated_utc: 2026-09-01T14:30:00Z
repo: poler-os
branch: main
commit: 729d2607
tag: v0.9.0
pushed: true
tests: zig build 5/5; zig build test 152/152 (РЕАЛЬНЫЙ запуск: addRunArtifact — компиляция ≠ прогон, урок v0.9.0); E2E QEMU 11.0.2 (PVH+TCG): boot→shell→peinfo/pestubs — 16/16 PASS
current_task: PE/COFF-loader + генератор Win32-заглушек (Crash-Driven Development, п.1 плана владельца) — ВЫПОЛНЕН
current_task_note: v0.9.0 (729d2607) — pe.zig (парсер PE32+/AMD64 без аллокаций; харденинг: все структуры формата @alignOf==1, вход из cpio по произвольному смещению), win32_stubs.zig (стабы 31Б: sub/add rsp,8 — фикс #GP; синглтон-указатель), build.zig (addRunArtifact: 152/152 реально запускаются), main64.zig (PVH start_info→initrd, cpio, команды peinfo/pestubs); фикстура curl.exe: 22 DLL/274 импорта (KERNEL32=80), негативный кейс 7zr.exe (i386); референсы в docs/pe-reference/
next_task: запуск PE-образа в ядре (CDD-цикл №1): VMM-маппинг SizeOfImage по ImageBase с релокацией .reloc, копия секций по RVA, патч IAT стабами, переход на AddressOfEntryPoint в Ring-3-задаче → первый int3-лог «kernel32.dll!CreateFileA — не реализовано» → реализация топ-функций (WriteFile/GetStdHandle/CreateFileA/HeapAlloc…); параллельно Enrollment-Gate (bindEnrolled, п.2 плана) в бут-пайплайне
blocked_on: —
tmux_sessions: нет (tmux отсутствует в песочнице — отклонение от §3 AGENT.md; QEMU 11.0.2 запускается фоном с serial→file и монитором на unix-сокете: /home/z/my-project/scripts/kbd-test.py)
credentials: ВАЛИДЕН — файл-хранилище upload/«гитхаб токен .txt»; подача через /home/z/my-project/scripts/gh-cred-helper.sh
notes: канон протокола — POLER-Quantum-RS v0.3.8 (AGENT.md); upload/ содержит токены и чувствительные файлы — в git не коммитить; удалённый origin = https://github.com/poler-engine-org/poler-os.git; референсы PE/COFF (winnt.h, PEB/TEB ReactOS, стабы Wine/ntdll) — /home/z/my-project/upload/poler-os-knowledge.tar.gz; осиротевшая июльская цепочка v1.2.0 (228f9fdc) содержит готовые решения (timer callback, kernel shell, FAT32) — сверяться перед реврайтом

## Последние сессии

| Дата (UTC) | Задача | Результат |
|---|---|---|
| 2026-09-01 | v0.9.0: PE/COFF-лоадер + CDD-стабы (п.1 плана) | pe.zig: парсер PE32+ (без аллокаций, @alignOf==1 на всех структурах — фикс @alignCast-паники на непроверенном входе); win32_stubs.zig: стабы 31Б с выравниванием стека (фикс #GP: movaps на rsp%16==0) и указателем-синглтоном (фикс потери счётчиков). РАЗОБЛАЧЕНО: «zig build test» раньше только КОМПИЛИРОВАЛ бинарники (Step.Compile) — падения/паники не ловились; теперь addRunArtifact → 152/152 реально выполняются. Фикстура: curl.exe (PE32+, 22 DLL/274 fn). E2E QEMU PVH+initrd: 16/16 (peinfo/pestubs) |
| 2026-09-01 | v0.7.3 + v0.8.0: аудит коммитов «antigravity» и фикс | Ревизия v0.7.2: энтропия-хаб оставлен, но найден критический баг (bio-пул читал порт 0x60 ДО handleKeyboard → клавиатура мертва в рантайме). v0.7.3: sink на TSC, Set1-таблица переписана (сдвиг на 1), OBF-гард + маскирование PIC (двойная доставка IRQ1), атомики kbd-буфера, timerTickCallback подключён, шелл на kernel-direct вызовах, стек -8 (SysV ABI), virtio-dump восстановлен, cmd_entropy рефактор. v0.8.0: PVH ELF-note из ассемблера (lld не умеет .long в скриптах!), защита Parser.init(0)/findTag, PMM PVH-fallback. E2E 9/9 |
| 2026-08-31 | v0.7.2 Multi-Pool Entropy Hub | Все 4 пула по спеке (Phase, Bus, IRQ, Bio) + UnifiedEntropyHub + авто-регенерация PRNG + команда entropy; 34/34 тестов |
| 2026-08-31 | v0.7.1 + перенос в оргу | poler-os → poler-engine-org (3-й репо консолидации, private); 94a29e0: puf.zig + boot-привязка TSC-энтропии + 11 тестов; тег v0.7.1; Zig 0.14.0 |
| 2026-08-28 | agent-протокол | AGENT.md-стаб + AGENT_STATE.md (канон: POLER-Quantum-RS v0.3.8) |
| 2026-08-27 | VGA/framebuffer | 594305d: fb_ptr32, CR/LF, Zig 0.14 |
