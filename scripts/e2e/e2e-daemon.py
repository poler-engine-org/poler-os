#!/usr/bin/env python3
# ============================================================================
# e2e-daemon.py — запуск долгих e2e-прогонов ДЕМОНОМ (двойной fork, reparent
# в init, setsid) — переживает завершение Bash-вызова/сессии. CDD №12 p4:
# QEMU-прогоны >10 мин (gamescope/Plasma) не влезают в таймаут инструмента.
#
# Usage: python3 e2e-daemon.py <script.py> <tag> [timeout_s]
#   Лог:  /tmp/e2e-<tag>.log
#   Стоп: /tmp/e2e-<tag>.pid (kill $(cat ...) — убивает дерево QEMU+python)
# ============================================================================
import os
import sys
import signal
import subprocess


def daemonize():
    # fork #1: родитель немедленно выходит — ребёнок репарентится в init
    if os.fork() > 0:
        sys.exit(0)
    # новая сессия: отвязка от controlling terminal и process-group убийства
    os.setsid()
    # fork #2: гарантия — демон никогда не.acquire() управляющий терминал
    if os.fork() > 0:
        sys.exit(0)
    # перенаправить stdio в лог (файл, НЕ pipe родителю)
    log_path = os.environ["E2E_DAEMON_LOG"]
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(fd)
    fd0 = os.open(os.devnull, os.O_RDONLY)
    os.dup2(fd0, 0)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


def kill_tree(pid: int):
    """Убить процесс + всех потомков (QEMU под python)."""
    try:
        # убить process-group демона (setsid → он же лидер группы)
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except ProcessLookupError:
        pass


def main():
    script, tag = sys.argv[1], sys.argv[2]
    timeout_s = sys.argv[3] if len(sys.argv) > 3 else "1500"
    log_path = f"/tmp/e2e-{tag}.log"
    pid_path = f"/tmp/e2e-{tag}.pid"
    done_path = f"/tmp/e2e-{tag}.done"

    # повторный запуск с тем же tag: прибить старое дерево
    if os.path.exists(pid_path):
        try:
            with open(pid_path) as f:
                old = int(f.read().strip())
            kill_tree(old)
        except (ValueError, FileNotFoundError):
            pass
        for p in (pid_path, done_path):
            if os.path.exists(p):
                os.unlink(p)

    os.environ["E2E_DAEMON_LOG"] = log_path
    pid = os.fork()
    if pid > 0:
        # родитель: записать pid ребёнка и выйти (ребёнок переживёт вызов)
        with open(pid_path, "w") as f:
            f.write(str(pid))
        print(f"DAEMON_PID={pid} LOG={log_path} PIDFILE={pid_path}")
        return
    # ─── демон-ребёнок ───
    daemonize()  # внутри: fork#1+setsid+fork#2 → pid в pidfile СТАРЕЕТ!

    # ⚠ После daemonize() наш pid УЖЕ не тот, что в pidfile (второй fork).
    # Перепишем pidfile изнутри демона (атомарно, родитель уже вышел).
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))
    open(done_path, "w").close()

    env = dict(os.environ)
    env.pop("E2E_DAEMON_LOG", None)
    ret = subprocess.call(
        [sys.executable, "-u", script, *sys.argv[4:]],
        env=env,
        timeout=None,
    )
    with open(done_path, "w") as f:
        f.write(f"rc={ret}\n")
    os._exit(ret if ret < 250 else 1)


if __name__ == "__main__":
    main()
