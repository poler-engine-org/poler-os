# AGENT STATE — машиночитаемое состояние агента (poler-os)

> Обновляется в конце каждой сессии и после значимых коммитов.
> Истинный HEAD — `git log -1 --oneline`. Формат — строгий `key: value`.

updated_utc: 2026-09-01T12:00:00Z
repo: poler-os
branch: main
commit: e897f148
tag: v0.8.0
pushed: true
tests: zig build 5/5, zig build test — зелёные; runtime E2E в QEMU 11.0.2 (PVH, TCG): boot→shell→клавиатура→команда help — 9/9 PASS
current_task: PE/COFF-loader + генератор Win32-заглушек (Crash-Driven Development, п.1 плана владельца)
current_task_note: v0.7.3 (67e227f1) — починены регрессии v0.7.2 (кража сканкодов bio-пулом, сдвинутая Set1-таблица, двойная доставка IRQ1 PIC+IO-APIC, невозврат virtio-dump) + латентные баги перезапуска v0.7.0 (timerTickCallback не подключён → задачи никогда не планировались; Ring0-шелл через SYSCALL → #PF; выравнивание стека задач); v0.8.0 (e897f148) — PVH ELF-note: QEMU 11 грузит ядро напрямую -kernel, попутно защищён mb2-парсер от мусорного MBI (вечный цикл в findTag)
next_task: PE/COFF-загрузчик (парсер PE32+ DOS/NT/Section-заголовков + разбор IAT ntdll/kernel32/user32), диспетчер заглушек с логом имени функции и контролируемым int3-остановом, тесты на реальном PE64-бинарнике; затем Enrollment-Gate (bindEnrolled) в бут-пайплайне
blocked_on: —
tmux_sessions: нет (tmux отсутствует в песочнице — отклонение от §3 AGENT.md; QEMU 11.0.2 запускается фоном с serial→file и монитором на unix-сокете: /home/z/my-project/scripts/kbd-test.py)
credentials: ВАЛИДЕН — файл-хранилище upload/«гитхаб токен .txt»; подача через /home/z/my-project/scripts/gh-cred-helper.sh
notes: канон протокола — POLER-Quantum-RS v0.3.8 (AGENT.md); upload/ содержит токены и чувствительные файлы — в git не коммитить; удалённый origin = https://github.com/poler-engine-org/poler-os.git; референсы PE/COFF (winnt.h, PEB/TEB ReactOS, стабы Wine/ntdll) — /home/z/my-project/upload/poler-os-knowledge.tar.gz; осиротевшая июльская цепочка v1.2.0 (228f9fdc) содержит готовые решения (timer callback, kernel shell, FAT32) — сверяться перед реврайтом

## Последние сессии

| Дата (UTC) | Задача | Результат |
|---|---|---|
| 2026-09-01 | v0.7.3 + v0.8.0: аудит коммитов «antigravity» и фикс | Ревизия v0.7.2: энтропия-хаб оставлен, но найден критический баг (bio-пул читал порт 0x60 ДО handleKeyboard → клавиатура мертва в рантайме). v0.7.3: sink на TSC, Set1-таблица переписана (сдвиг на 1), OBF-гард + маскирование PIC (двойная доставка IRQ1), атомики kbd-буфера, timerTickCallback подключён, шелл на kernel-direct вызовах, стек -8 (SysV ABI), virtio-dump восстановлен, cmd_entropy рефактор. v0.8.0: PVH ELF-note из ассемблера (lld не умеет .long в скриптах!), защита Parser.init(0)/findTag, PMM PVH-fallback. E2E 9/9 |
| 2026-08-31 | v0.7.2 Multi-Pool Entropy Hub | Все 4 пула по спеке (Phase, Bus, IRQ, Bio) + UnifiedEntropyHub + авто-регенерация PRNG + команда entropy; 34/34 тестов |
| 2026-08-31 | v0.7.1 + перенос в оргу | poler-os → poler-engine-org (3-й репо консолидации, private); 94a29e0: puf.zig + boot-привязка TSC-энтропии + 11 тестов; тег v0.7.1; Zig 0.14.0 |
| 2026-08-28 | agent-протокол | AGENT.md-стаб + AGENT_STATE.md (канон: POLER-Quantum-RS v0.3.8) |
| 2026-08-27 | VGA/framebuffer | 594305d: fb_ptr32, CR/LF, Zig 0.14 |
