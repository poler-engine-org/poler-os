#!/usr/bin/env python3
# ============================================================================
# p8-parkdump.py — CDD #12 p8: при замерзании [L]-фронта напечатать в гостя
# команду `tasks` (РЕЕСТР ПАРКОВОК из нового ядра) через monitor sendkey
# (PS/2 → evdev → shell) и снять дамп из serial.log.
#
# Usage: python3 p8-parkdump.py [tag] [stall_s]
#   sock:  /tmp/poler-e2e-<script>/monitor.sock (VM #1 — sendkey)
#   serial: /tmp/poler-e2e-<script>/serial.log
# ============================================================================
import os
import socket
import sys
import time

TAG = sys.argv[1] if len(sys.argv) > 1 else "drm-gamescope"
DIR = f"/tmp/poler-e2e-{TAG}"
SER = os.path.join(DIR, "serial.log")
MON_SOCK = os.environ.get("PARK_MON") or os.path.join(DIR, "mon2.sock")
STALL_S = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0

# символы, которых нет в простом sendkey-алфавите — только строчные буквы
KEYMAP = {
    " ": "spc", "\t": "tab", "-": "minus", "=": "equal", "[": "bracket_left",
    "]": "bracket_right", ";": "semicolon", "'": "apostrophe", "`": "grave_accent",
    "\\": "backslash", ",": "comma", ".": "dot", "/": "slash",
}


class Mon:
    def __init__(self, path, timeout=3.0):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(timeout)
        self.s.connect(path)
        time.sleep(0.3)
        try:
            self.s.recv(4096)
        except socket.timeout:
            pass

    def sendkey(self, k):
        self.s.sendall(("sendkey %s\n" % k).encode())
        try:
            self.s.recv(4096)
        except socket.timeout:
            pass

    def type_line(self, line, delay=0.03):
        for ch in line:
            if ch.isupper():
                self.sendkey("shift-" + ch.lower())
            elif ch in KEYMAP:
                self.sendkey(KEYMAP[ch])
            elif ch.isalnum():
                self.sendkey(ch.lower())
        self.sendkey("ret")
        time.sleep(0.3)


def lcount():
    try:
        return sum(1 for line in open(SER, errors="ignore") if "[L]" in line)
    except Exception:
        return 0


def main() -> int:
    # ждём, что фронт [L] живёт и потом замерзает
    t0 = time.time()
    last_n, last_change = -1, time.time()
    frozen = False
    while time.time() - t0 < 900:
        time.sleep(5)
        n = lcount()
        if n != last_n:
            last_n, last_change = n, time.time()
        elif n > 400 and time.time() - last_change > STALL_S:
            frozen = True
            break
    if not frozen:
        print(f"i] stall не детектирован за 900с ([L]={last_n}) — дамп всё равно")
    print(f"i] [L] frozen at {last_n}; typing `tasks`", flush=True)

    m = Mon(MON_SOCK)
    m.type_line("tasks")
    time.sleep(30)  # дамп печатается медленно (serial busy-wait)

    # вытащить блок [TASKS] из serial.log
    out = []
    grab = False
    for line in open(SER, errors="ignore"):
        if "[TASKS] tick=" in line:
            grab = True
        if grab:
            out.append(line.rstrip())
            if "[TASKS] end" in line:
                grab = False
    if out:
        print("\n".join(out))
    else:
        print("i] блок [TASKS] не найден в serial.log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
