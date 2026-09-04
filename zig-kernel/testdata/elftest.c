// ============================================================================
// elftest.c — CDD №11 p1: ПЕРВЫЙ ELF-процесс POLER-OS (Linux-ABI полигон)
// ============================================================================
// Статический freestanding-бинарник (gcc -static -nostdlib): полный боевой
// цикл syscall-фундамента v0.20:
//   1. write(1, …)            — консоль через fd-таблицу процесса
//   2. mmap(MAP_ANONYMOUS)    — anon-страницы + запись/чтение (реестр)
//   3. clone(CLONE_VM|…)      — НАСТОЯЩИЙ тред: RAX=0 у ребёнка, общий CR3
//   4. futex WAIT/WAKE        — парковка/пробуждение между тредами
//   5. CLONE_CHILD_CLEARTID   — tid-слово обнуляется на exit + WAKE (join!)
//   6. exit_group(42)         — завершение процесса
// Маркеры ELFTEST-* ловит scripts/e2e/elf-run-e2e.py в serial-логе.
// ============================================================================

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

// ─── Linux x86-64 syscall-обёртка (RAX=номер, RDI/RSI/RDX/R10/R8/R9) ───────
static inline i64 sys6(u64 n, u64 a, u64 b, u64 c, u64 d, u64 e, u64 f) {
    i64 ret;
    register u64 r10 asm("r10") = d;
    register u64 r8 asm("r8") = e;
    register u64 r9 asm("r9") = f;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return ret;
}

#define SYS_write 1
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_clone 56
#define SYS_futex 202
#define SYS_exit 60
#define SYS_exit_group 231
#define SYS_gettid 186
#define SYS_getpid 39

#define CLONE_VM 0x100
#define CLONE_FS 0x200
#define CLONE_FILES 0x400
#define CLONE_SIGHAND 0x800
#define CLONE_THREAD 0x10000
#define CLONE_PARENT_SETTID 0x100000
#define CLONE_CHILD_CLEARTID 0x200000
#define CLONE_CHILD_SETTID 0x10000000

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

#define FUTEX_WAIT 0
#define FUTEX_WAIT_PRIVATE 128
#define FUTEX_WAKE 1
#define FUTEX_WAKE_PRIVATE 129

static u64 slen(const char *s) {
    u64 n = 0;
    while (s[n]) n++;
    return n;
}

static void emit(const char *s) {
    (void)sys6(SYS_write, 1, (u64)s, slen(s), 0, 0, 0);
}

static void emit_u64(const char *prefix, u64 v, const char *suffix) {
    char buf[32];
    buf[0] = 0;
    char tmp[20];
    int n = 0;
    if (v == 0) { tmp[n++] = '0'; }
    while (v > 0 && n < 19) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    for (int i = n - 1; i >= 0; i--) buf[slen(buf)] = tmp[i];
    // prefix + число + suffix
    char out[96];
    int k = 0;
    for (int i = 0; prefix[i] && k < 90; i++) out[k++] = prefix[i];
    for (int i = 0; buf[i] && k < 90; i++) out[k++] = buf[i];
    for (int i = 0; suffix[i] && k < 90; i++) out[k++] = suffix[i];
    out[k] = 0;
    emit(out);
}

// ─── Общая память тредов (mmap-страница, CLONE_VM) ──────────────────────────
static volatile u32 *shared_word;   // слово futex-обмена
static volatile u32 *child_tid_word; // CLONE_CHILD_SETTID/CLEARTID-слово

// ─── ПУТЬ РЕБЁНКА (noinline!) ───────────────────────────────────────────────
// После clone() ребёнок продолжает ИЗНУТРИ sys6-кадра родителя с НОВЫМ RSP:
// все локали РОДИТЕЛЯ ([rsp+X] его кадра) для ребёнка НЕДОСТУПНЫ. Поэтому
// путь ребёнка — отдельная noinline-функция: её пролог кладёт локали на
// НОВЫЙ стек (ниже RSP — внутри mmap-региона), как glibc-трамплин __clone.
__attribute__((noinline, noreturn))
static void child_entry(void) {
    i64 mytid = sys6(SYS_gettid, 0, 0, 0, 0, 0, 0);
    emit_u64("ELFTEST-CLONE-CHILD tid=", (u64)mytid, " (RAX=0 path)\n");

    // ЗАДЕРЖКА: родитель обязан успеть запарковаться (futex WAIT) ДО
    // нашего WAKE — тогда WAKE найдёт реестровую запись (woken=1):
    // честный park→wake roundtrip через hlt-механику планировщика
    for (volatile i64 i = 0; i < 40000000; i++) {
        asm volatile("pause");
    }

    // кладём маркер в общую память и будим родителя
    *shared_word = 0xC0FE;
    i64 woken = sys6(SYS_futex, (u64)shared_word, FUTEX_WAKE, 1, 0, 0, 0);
    emit_u64("ELFTEST-FUTEX-WAKE-SENT woken=", (u64)woken, "\n");

    // exit(0): sys_exit — CLONE_CHILD_CLEARTID обнулит child_tid_word
    // + FUTEX_WAKE (родитель ждёт на этом слове — pthread_join!)
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
    for (;;) asm volatile("pause");
}

// ─── main: боевой цикл ──────────────────────────────────────────────────────
int main_c(long argc, char **argv) {
    emit_u64("ELFTEST-ALIVE argc=", (u64)argc, "\n");
    if (argc > 1) {
        emit("ELFTEST-ARGV1 ");
        emit(argv[1]);
        emit("\n");
    }

    // 1. mmap анонимный: 2 страницы → запись/чтение
    i64 pg = sys6(SYS_mmap, 0, 8192, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, (u64)-1, 0);
    if (pg < 0) {
        emit("ELFTEST-FAIL mmap errno\n");
        return 1;
    }
    volatile u32 *page = (volatile u32 *)(u64)pg;
    page[0] = 0xABCDEF01;
    page[2047] = 0x11223344; // вторая страница
    if (page[0] != 0xABCDEF01 || page[2047] != 0x11223344) {
        emit("ELFTEST-FAIL mmap readback\n");
        return 1;
    }
    emit("ELFTEST-MMAP-OK anon write+readback\n");
    shared_word = &page[512];
    child_tid_word = &page[513];
    *shared_word = 0;

    // 2. Стек треда: mmap 64КБ (clone-аргумент = верх)
    i64 stk = sys6(SYS_mmap, 0, 65536, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, (u64)-1, 0);
    if (stk < 0) {
        emit("ELFTEST-FAIL thread-stack mmap\n");
        return 1;
    }
    u64 stack_top = (u64)stk + 65536; // 16-выровнен (страницы)

    // 3. clone: НАСТОЯЩИЙ Linux-тред
    u32 ptid = 0, ctid = 0;
    u64 clone_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                      CLONE_THREAD |
                      CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    i64 tid = sys6(SYS_clone, clone_flags, stack_top,
                   (u64)&ptid, (u64)child_tid_word, 0, 0);
    if (tid < 0) {
        emit_u64("ELFTEST-FAIL clone errno=", (u64)(-tid), "\n");
        return 1;
    }

    if (tid == 0) {
        // РЕБЁНОК: noinline-путь — локали на НОВОМ стеке (glibc-трамплин)
        child_entry();
    }

    // ═══ РОДИТЕЛЬ ═══
    emit_u64("ELFTEST-CLONE-PARENT tid=", (u64)tid, "\n");
    emit_u64("ELFTEST-SETTID ptid=", ptid, " ctid=");
    // (объединяем в один маркер ниже — emit_u64 по одному слову)
    {
        // проверка SETTID: оба слова == tid
        if (ptid == (u32)tid && *child_tid_word == (u32)tid) {
            emit("ELFTEST-SETTID-OK parent+child words\n");
        } else {
            emit("ELFTEST-FAIL settid words\n");
        }
    }

    // 4. futex-WAIT: парковка до WAKE ребёнка (слово 0 → 0xC0FE)
    i64 fr = sys6(SYS_futex, (u64)shared_word, FUTEX_WAIT, 0, 0, 0, 0);
    if (fr == 0 || *shared_word == 0xC0FE) {
        emit("ELFTEST-FUTEX-WOKEN value ok\n");
    } else if (fr == -11) { // EAGAIN: слово уже изменилось ДО парка
        emit("ELFTEST-FUTEX-EAGAIN value ok\n");
    } else {
        emit_u64("ELFTEST-FAIL futex ret=", (u64)fr, "\n");
        return 1;
    }

    // 5. pthread_join-семантика: ждать обнуления child_tid_word
    //    (CLONE_CHILD_CLEARTID на exit ребёнка → 0 + WAKE)
    {
        int joined = 0;
        for (int spin = 0; spin < 2000; spin++) {
            if (*child_tid_word == 0) { joined = 1; break; }
            // futex-парковка на слове (значение ещё = tid)
            (void)sys6(SYS_futex, (u64)child_tid_word, FUTEX_WAIT,
                       *child_tid_word, 0, 0, 0);
        }
        if (joined) {
            emit("ELFTEST-CLEARTID-OK join semantics (tid word zeroed)\n");
        } else {
            emit("ELFTEST-FAIL cleartid join\n");
            return 1;
        }
    }

    // 6. munmap тред-стека (реестр → физблок освобождается)
    (void)sys6(SYS_munmap, (u64)stk, 65536, 0, 0, 0, 0);

    // 7. exit_group(42) — маркер завершения процесса
    emit("ELFTEST-EXIT-42 all subsystems green\n");
    sys6(SYS_exit_group, 42, 0, 0, 0, 0, 0);
    for (;;) asm volatile("pause");
}

// ─── _start: первичный вход (Linux-ABI стек: [rsp]=argc) ────────────────────
void _start(void) {
    asm volatile(
        "movq (%%rsp), %%rdi\n"      // argc
        "leaq 8(%%rsp), %%rsi\n"     // argv
        "andq $-16, %%rsp\n"         // SysV: выравнивание стека под call
        "call main_c\n"
        "movl %%eax, %%edi\n"
        "movl $231, %%eax\n"         // exit_group(ret)
        "syscall\n"
        "hlt\n"
        ::: "rdi", "rsi", "memory");
    __builtin_unreachable();
}
