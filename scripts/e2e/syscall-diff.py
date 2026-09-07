#!/usr/bin/env python3
# ============================================================================
# syscall-diff.py — CDD №12 p11: ДИФФЕРЕНЦИАЛЬНЫЙ ДВИЖОК host-Linux vs POLER.
# ============================================================================
# Входы:
#   --host <strace-file>  : strace -f -tt -yy вывод ХАРОНЕССА на host Linux
#                           (тот же бинарник, те же rootfs-либы, тот же ICD)
#   --vm <serial.log>     : [L]-фронт того же харнесса в POLER-OS (ltrace)
# Сравнение:
#   1. Гистограммы (syscall → count) обеих сторон + недостающие вызовы.
#   2. Классы возвратов: success-0 / положительный / -errno(N) по каждому
#      syscall'у — расхождение errno-множеств = дивергенция.
#   3. Контекст дивергенций: первые K вызовов с обеих сторон.
# Особые отчёты (фронт p11): rseq, clone3, madvise-advice, prlimit-res,
#   sched_*, membarrier, futex-op/ret, getrandom, epoll, неизвестные.
# ============================================================================
import argparse
import re
import sys
from collections import Counter, defaultdict

# ─── x86_64 syscall number → name (ядро: linux_syscalls.zig; host: strace) ──
NAMES = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect",
    11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
    15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64",
    19: "readv", 20: "writev", 21: "access", 22: "pipe", 23: "select",
    24: "sched_yield", 25: "mremap", 26: "msync", 27: "mincore",
    28: "madvise", 29: "shmget", 30: "shmat", 31: "shmctl",
    32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep",
    39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto",
    45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 48: "shutdown",
    49: "bind", 50: "listen", 54: "setsockopt", 55: "getsockopt",
    57: "fork", 58: "vfork", 59: "execve", 60: "exit", 61: "wait4",
    62: "kill", 63: "uname", 64: "semget", 72: "fcntl", 73: "flock",
    78: "getdents", 79: "getcwd", 80: "chdir", 83: "mkdir", 84: "rmdir",
    85: "unlink", 87: "readlink", 88: "chmod", 89: "readlinkat",
    90: "fchmod", 91: "chown", 96: "gettimeofday", 97: "getuid",
    98: "getgid", 99: "setuid", 100: "setgid", 101: "geteuid",
    102: "getegid", 104: "setitimer", 105: "getitimer",
    107: "geteuid", 108: "getegid",
    109: "setpgid", 110: "getppid", 113: "setrlimit", 114: "getrlimit",
    116: "sysinfo", 117: "times", 118: "getrusage",
    124: "personality", 125: "prof", 128: "init_module",
    129: "delete_module", 131: "sigaltstack", 132: "mlock", 133: "munlock",
    137: "statfs", 138: "fstatfs", 139: "ioperm", 141: "setpriority",
    142: "getpriority", 143: "sched_setparam", 144: "sched_getparam",
    145: "sched_setscheduler", 146: "sched_getscheduler",
    147: "sched_get_priority_max", 148: "sched_get_priority_min",
    150: "mlockall", 152: "prctl", 153: "poll-old?", 156: "gettid",
    157: "readahead", 158: "setxattr", 161: "listxattr",
    163: "removexattr", 165: "getcwd", 167: "swapon",
    186: "getrlimit?", 187: "mremap?",
    191: "ugetrlimit?", 197: "fremovexattr",
    201: "time", 202: "futex", 203: "sched_setaffinity",
    204: "sched_getaffinity", 205: "set_thread_area",
    206: "io_setup", 210: "lookup_dcookie", 212: "set_tid_address",
    213: "restart_syscall", 217: "getdents64", 218: "set_tid_address2?",
    219: "restart_syscall?", 231: "exit_group", 232: "epoll_wait",
    233: "epoll_ctl", 234: "tgkill", 235: "waitid",
    248: "timerfd_create?", 252: "timerfd_settime?", 257: "openat",
    262: "newfstatat", 267: "readlinkat", 270: "futimesat",
    271: "newfstatat?", 288: "accept4", 289: "eventfd",
    290: "eventfd2", 291: "epoll_create1", 292: "epoll_ctl_old",
    293: "pipe2", 294: "inotify_init1", 300: "fallocate",
    302: "prlimit64", 303: "name_to_handle_at", 306: "setns",
    307: "getcpu", 308: "process_vm_readv", 312: "kcmp",
    313: "finit_module", 315: "sched_setattr", 316: "sched_getattr",
    317: "renameat2", 318: "getrandom", 319: "memfd_create",
    320: "kexec_file_load", 322: "execveat", 323: "userfaultfd",
    324: "membarrier", 325: "mlock2", 327: "pwritev2",
    329: "pkey_mprotect", 330: "pkey_alloc", 331: "pkey_free",
    332: "statx", 334: "rseq", 335: "pidfd_send_signal",
    424: "pidfd_open", 435: "clone3", 462: "futex_waitv",
    436: "close_range", 439: "faccessat2", 441: "epoll_pwait2",
    437: "openat2",
}
# Дубли/легаси вычищаем ручным сето не-string
NAMES = {k: v for k, v in NAMES.items() if "?" not in v}

ERRNOS = {
    1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO",
    6: "ENXIO", 7: "E2BIG", 8: "ENOEXEC", 9: "EBADF", 11: "EAGAIN",
    12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 16: "EBUSY",
    17: "EEXIST", 18: "EXDEV", 19: "ENODEV", 20: "ENOTDIR",
    21: "EISDIR", 22: "EINVAL", 24: "EMFILE", 27: "EFBIG",
    28: "ENOSPC", 29: "ESPIPE", 30: "EROFS", 31: "EMLINK",
    32: "EPIPE", 36: "ENAMETOOLONG", 38: "ENOSYS", 40: "ELOOP",
    61: "ENODATA", 62: "ETIME", 75: "EOVERFLOW", 84: "EILSEQ",
    90: "EMSGSIZE", 95: "EOPNOTSUPP", 98: "EADDRINUSE",
    104: "ECONNRESET", 110: "ETIMEDOUT", 111: "ECONNREFUSED",
}


def errno_name(v):
    if v >= 4096:  # errno-ABI ядра: u64 = -errno как 0xFFFF...
        e = (2**64 - v)
        return ERRNOS.get(e, "E%d" % e)
    return None


# ─── Host: strace парсер ────────────────────────────────────────────────────
HOST_LINE = re.compile(
    r"^(?:\d+\s+\d+:\d+:\d+\.\d+\s+)?"          # pid [time]
    r"(?:<\.\.\.\s+)?"                            # resumed
    r"([a-zA-Z0-9_]+)\((.*?)\)\s*=\s*(.+)$")


def parse_host(path):
    calls = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("strace:"):
            continue
        m = HOST_LINE.match(line)
        if not m:
            # resumed без аргументов: "<... futex resumed>) = 0"
            m2 = re.match(r"^(?:\d+\s+\d+:\d+:\d+\.\d+\s+)?<\.\.\.\s+(\w+)\s+resumed>\)?\s*=\s*(.+)$", line)
            if m2:
                name, res = m2.group(1), m2.group(2).strip()
            else:
                continue
        else:
            name, res = m.group(1), m.group(3).strip()
        if name in ("resumed",):
            continue
        if res.startswith("{") or res.startswith("NULL"):
            val = None  # struct / NULL — не число
        else:
            mm = re.match(r"(-?\d+|0x[0-9a-f]+)", res)
            val = int(mm.group(1), 0) if mm else None
        calls.append((name, val))
    return calls


# ─── VM: [L]-парсер (формат [L] NUM(0xA1,0xA2,...) = 0xRET) ────────────────
VM_LINE = re.compile(
    r"\[L\] (\d+)\((.*?)\)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+)")


def parse_vm(path):
    calls = []
    text = open(path, encoding="utf-8", errors="replace").read()
    for line in text.splitlines():
        m = VM_LINE.search(line)
        if not m:
            continue
        num = int(m.group(1))
        ret = int(m.group(3), 16 if m.group(3).startswith("0x") else 10)
        name = NAMES.get(num, "sys_%d" % num)
        calls.append((name, ret))
    return calls


def ret_class(v):
    if v is None:
        return "struct"
    if v == 0:
        return "0"
    if v > 0:
        return "val>0"
    return "neg"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--vm", required=True)
    ap.add_argument("--context", type=int, default=6)
    args = ap.parse_args()

    host = parse_host(args.host)
    vm = parse_vm(args.vm)
    print(f"host: {len(host)} syscall-событий; vm: {len(vm)} [L]-событий")

    h_hist = Counter(n for n, _ in host)
    v_hist = Counter(n for n, _ in vm)

    print("\n=== 1. ГИСТОГРАММЫ (syscall: host-count / vm-count) ===")
    allnames = sorted(set(h_hist) | set(v_hist),
                      key=lambda n: -(h_hist.get(n, 0) + v_hist.get(n, 0)))
    for n in allnames:
        h, v = h_hist.get(n, 0), v_hist.get(n, 0)
        flag = ""
        if v == 0 and h > 0:
            flag = "  ← НЕТ В VM (ENOSYS? не вызван?)"
        elif h == 0 and v > 0:
            flag = "  ← НЕТ НА HOST"
        elif v > 0 and h > 0 and max(h, v) / min(h, v) > 3:
            flag = "  ← СИЛЬНЫЙ ПЕРЕКОС"
        print(f"  {n:24s} {h:6d} / {v:6d}{flag}")

    print("\n=== 2. КЛАССЫ ВОЗВРАТОВ по syscall (host → vm) ===")
    h_retc = defaultdict(Counter)
    v_retc = defaultdict(Counter)
    h_errn = defaultdict(Counter)
    v_errn = defaultdict(Counter)
    for n, val in host:
        h_retc[n][ret_class(val)] += 1
        if val is not None and (val < 0 or val > 4096):
            en = ERRNOS.get(-val if val < 0 else 2**64 - val)
            if en:
                h_errn[n][en] += 1
    for n, val in vm:
        v_retc[n][ret_class(val)] += 1
        en = errno_name(val)
        if en:
            v_errn[n][en] += 1

    for n in allnames:
        hc, vc = h_retc.get(n), v_retc.get(n)
        if not hc or not vc:
            continue
        hset, vset = set(hc), set(vc)
        # расхождение = errno есть только с одной стороны
        honly = hset - vset
        vonly = vset - hset
        if honly or vonly:
            print(f"  {n:24s} host={dict(hc)} vm={dict(vc)}"
                  f"  ← РАСХОЖДЕНИЕ {sorted(honly)} vs {sorted(vonly)}")
        if h_errn.get(n) or v_errn.get(n):
            he, ve = h_errn.get(n, Counter()), v_errn.get(n, Counter())
            if set(he) != set(ve):
                print(f"  {n:24s} errno: host={dict(he)} vm={dict(ve)}")

    print("\n=== 3. ЦЕЛЕВЫЕ SYSCALL'Ы p11 ===")
    for target in ("rseq", "clone3", "madvise", "prlimit64", "sched_yield",
                   "membarrier", "futex", "getrandom", "setpriority",
                   "sched_setscheduler", "sched_setaffinity", "sysinfo",
                   "memfd_create", "getuid", "geteuid", "uname"):
        h = h_hist.get(target, 0)
        v = v_hist.get(target, 0)
        hc = dict(h_retc.get(target, {}))
        vc = dict(v_retc.get(target, {}))
        he = dict(h_errn.get(target, {}))
        ve = dict(v_errn.get(target, {}))
        if h or v:
            print(f"  {target:22s} host: {h:3d} {hc} {he} | vm: {v:3d} {vc} {ve}")

    print("\n=== 4. КОНТЕКСТ РАСХОЖДЕНИЙ (первые различия потока) ===")
    # выравнивание по общим syscall'ам: идём параллельно, на первом
    # расхождении errno-класса печатаем окно обеих сторон
    i = j = 0
    shown = 0
    while i < len(host) and j < len(vm) and shown < args.context:
        hn, hv = host[i]
        vn, vv = vm[j]
        if hn == vn:
            hc, vc = ret_class(hv), ret_class(vv)
            he = errno_name(vv) if vv is not None else None
            hh = ERRNOS.get(-hv, None) if hv is not None and hv < 0 else None
            if hc != vc and not (hc in ("0", "val>0") and vc in ("0", "val>0")):
                print(f"  #{i}/{j} {hn}: host={hv}({hc}) vs vm={vv}({vc})")
                print(f"    host окно: {[x[0] for x in host[max(0,i-4):i+4]]}")
                print(f"    vm окно:   {[x[0] for x in vm[max(0,j-4):j+4]]}")
                shown += 1
            i += 1
            j += 1
        elif hn in v_hist and v_hist[hn] > 0:
            # host-вызов, которого нет на vm-позиции: host опережает
            i += 1
        elif vn in h_hist and h_hist[vn] > 0:
            j += 1
        else:
            i += 1
            j += 1
    if shown == 0:
        print("  (в общих позициях errno-классы совпали)")

    print("\n=== 5. СПЕЦ-РАЗБОР: madvise advice / prlimit / futex ops ===")
    # madvise advice из host-трейса
    madv_h = re.findall(r"madvise\([^,]+, \d+, ([A-Z_0-9]+|\d+)\)",
                        open(args.host, encoding="utf-8", errors="replace").read())
    print(f"  host madvise advice: {Counter(madv_h)}")
    # VM: [L] 28(a1,a2,a3): advice = a3
    madv_v = []
    for line in open(args.vm, encoding="utf-8", errors="replace"):
        m = re.search(r"\[L\] 28\(0x[0-9A-Fa-f]+0x[0-9A-Fa-f]+,0x([0-9A-Fa-f]+),0x([0-9A-Fa-f]+)", line)
        if m:
            madv_v.append("a2=0x%s,advice=0x%s" % (m.group(1), m.group(2)))
    print(f"  vm madvise (len,advice): {Counter(madv_v)}")
    # prlimit: host resources
    prl_h = re.findall(r"prlimit64\(\d+, (\w+),", open(args.host, encoding="utf-8", errors="replace").read())
    print(f"  host prlimit64 resources: {Counter(prl_h)}")
    # futex: host ops
    ftx_h = re.findall(r"futex\([^,]+, ([A-Z_0-9|]+)(?:,|\s)", open(args.host, encoding="utf-8", errors="replace").read())
    print(f"  host futex ops: {Counter(ftx_h)}")
    ftx_v = []
    for line in open(args.vm, encoding="utf-8", errors="replace"):
        m = re.search(r"\[L\] 202\(0x[0-9A-Fa-f]+0x[0-9A-Fa-f]+,0x([0-9A-Fa-f]+)", line)
        if m:
            op = int(m.group(1), 16)
            ftx_v.append("op=%d%s" % (op & 0x7F, "P" if op & 128 else ""))
    print(f"  vm futex ops: {Counter(ftx_v)}")

    print("\n=== 6. ПЕРВЫЕ 40 / ПОСЛЕДНИЕ 20 VM-событий (для навигации) ===")
    for n, v in vm[:40]:
        print(f"   vm0 {n} = {v}")
    print("   ...")
    for n, v in vm[-20:]:
        print(f"   vmN {n} = {v}")


if __name__ == "__main__":
    sys.exit(main())
