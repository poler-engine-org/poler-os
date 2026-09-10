updated_utc: 2026-09-10T04:50:00Z
repo: poler-os
branch: main
commit: ba8ad4c feat(cdd15-p5): 🎲 ВСТРЯХИВАТЕЛЬ КОСТЕЙ — TSC-сдвиг физ-раскладки на каждом буте
tag: v0.19.0 (следующий — v0.20.0-rc: ЖДАТЬ ПЕРВЫЙ PAGE_FLIP + shot-final.png)
pushed: origin/main
tests: zig build OK; 585 юнит-тестов зелёные
current_task: CDD №15 p5 — СЕССИЯ НАШЛА И ИЗЛЕЧИЛА ТРЁХ HANDSHAKE-УБИЙЦ. Конвейер теперь:
  gamescope render-loop ✓ → vkQueueSubmit ✓ (несколько) → vkWaitSemaphores(-1)=0 ✓ →
  wlserver «Starting Xwayland on :0» ✓ → execve Xwayland = РЕАЛЬНЫЙ процесс (t12, 41-либ
  замыкание 282 mmap) ✓ → WAYLAND_SOCKET(45) ✓ → sendmsg(45, 24Б) = wl_display_get_registry
  ОТПРАВЛЕН (первый wl-запрос в истории!) ✓.
  ТРИ КОРНЯ, ИЗЛЕЧЕННЫХ СЕССИЕЙ (все запушены):
  1) 952dfc8: SYS_ppoll OFF-BY-ONE — было 270 (=pselect6!), канон x86_64: 270=pselect6,
     271=ppoll → настоящий ppoll(271) падал в ENOSYS → «could not connect to wayland
     server». Оба номера → sysPpoll + честный таймаут (NULL=блок).
  2) a1b8849 (+правка a162540): sysSendmsg/sysRecvmsg(socket) писали ТОЛЬКО первый iov —
     libwayland-flush пишет кольцевой буфер 2-3 iov → обрезка сообщений → фиксы: все iov,
     честные partial write/read, POLLOUT по месту.
  3) c54e60b: 💥 ЭХО-СОКЕТПАРА — sysSocketpair клал ОБА конца на ОДИН канал → писец видел
     СВОЮ запись в POLLIN → читал СВОЙ запрос обратно → «message too short, object (1)» →
     «could not connect». ФИКС: НАПРАВЛЕННАЯ пара (write(fdA)→буфер B; read(fdA)→свой A),
     peer/peer_closed, EPIPE/EAGAIN, EPOLLHUP; оба места создания (sysSocketpair +
     connect/accept wayland-0 эмуляция); моки и тесты под новую семантику.
blocked_on: t8-краш (lvp/LLVM JIT-воркер) — ТАЙМИНГОВАЯ ЛОТЕРЕЯ: в ~15% прогонов t8
  переживает submit-фазу → Xwayland спавнится (runs 19/21/29); в остальных умирает
  раньше (NULL-deref семейство: lvp+0x1767E6 bump=0 / lvp+0x1483A81 CR2=0x20 /
  lvp+0x1484E77 RAX=0x40 — жертвы меняются, писец всегда t8). Форензик-сеть v6 развёрнута:
  [PW]-v4 (born/dead/сэмплы), [B-DUMP] контент-таймлайн, [DZ-FAULT]/[DZ-MAT],
  [PTE-DIAG] MAP/UNMAP/HIDE/PROT/RESTORE, [PM-FREE]/[PM-REISSUE] физ-ловушка,
  4×DR-watchpoint ([DB-WRITE] task/rip/val + invlpg-выстрел), [FREE-LIVE] refcount-аудит.
  ИСКЛЮЧЕНО эмпирически: PMM-перевыдача (ловушка чиста), munmap/DONTNEED-яд ([FREE-LIVE]=0),
  double-free (=0), kernel-identity-записи (phys-слоты DR молчали), кросс-тредовая гонка
  на A-struct (пишец только t8), mid-#PF преемпция (таймер не зовёт schedule), stale-TLB
  на PTE-путях (ядерный CR3-reload на всех мутациях НЕ спас). Гипотеза-лидер: тонкая
  TLB/кэш-несогласованность или семантическая дыра в syscall-границе — не локализована.
next_steps:
  1) RETRY-ЦИКЛ до выжившего прогона: python3 scripts/gs-daemon-launch.py /tmp/gs-live/launch-runN.log
     → sleep 400 → gs-type.py "usr/bin/gamescope -W 1024 -H 768" → поллить ~10 мин:
     маркеры «Starting Xwayland» / «execve: /usr/bin/Xwayland» / отсутствие «(EE)».
     [DICE]-встряхиватель (rdtsc&0xF страниц на буте) даёт свежую раскладку каждому прогону.
  2) В выжившем прогоне: handshake теперь НЕ блокирован (эхо+ppoll+iov излечены) →
     wl_registry/bind → damage → DRM atomic commit → PAGE_FLIP →
     python3 scripts/gs-monitor.py --shot final → /tmp/gs-live/shot-final.png →
     git tag v0.20.0-rc + push --tags.
  3) Если t8-смерть до спавна: продолжать цикл (вероятность ~15%/ран, ~19 мин/ран).
  4) (опционально, следующая сессия) — корень t8: DR-нож на Другие подозреваемые поля,
     сопоставление RIP крашей с LLVM-символами, аудит futex-парка на lost-wakeup.
tmux_sessions: нет; QEMU-прогоны автономны (gs-daemon-launch.py: double-fork+setsid);
  сериал-логи: tools/gs-run{1..35}-serial.log; initrd /tmp/poler-e2e-drm-gamescope/initrd.cpio (310МБ, полный EGL-хвост)
