# AGENT.md — протокол агента этого репозитория

Канонический протокол **Context-Free Resilience** живёт в
POLER-Quantum-RS v0.3.8: [`../poler-quantum-rs/AGENT.md`](https://github.com/Kotokvit/POLER-Quantum-RS/blob/main/AGENT.md).
Этот файл — обязательный минимум для агентов, работающих с poler-os:

1. **Первым делом** прочитать `AGENT_STATE.md` в корне этого репозитория —
   вектор движения (current_task → next_task, blocked_on).
2. **Fetch-before-work**: `git fetch origin --tags` до начала любой работы;
   расхождения local/remote разрешать по §5 канона (слепой merge запрещён,
   force-push — только с разрешения пользователя).
3. Длительные задачи (сборка ISO, QEMU-прогоны, xorriso) — только в
   именованной tmux-сессии `poler-os-<задача>`; опрос:
   `tmux capture-pane -p -t <имя> -S -100`. Сборочные артефакты (iso/, grub-local/,
   upload/xorriso-1.4.6/) в git не коммитить.
4. Значимые изменения — **немедленный коммит**; push после проверки;
   в конце сессии `git log origin/main..HEAD` пуст.
5. Токены — только через credential-helper; никогда в remote-URL, коммитах,
   логах и ответах (маска `ghp_****`).
6. Контекстное окно чата — не источник фактов; истина — git, ФС, процессы.
