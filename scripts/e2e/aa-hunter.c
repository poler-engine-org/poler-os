// ============================================================================
// aa-hunter.c — CDD №12 p9: ЛОВЕЦ ЗАПИСИ 0xAAAA В USER-ПАМЯТЬ (дефинитив).
// Эмпирика: value-capture для STORE работает (run3: реальные значения),
// register-API НЕработает (rsp/rbp=0 всегда + host-segv) — вырезан.
// Ловим:
//   1. STORE 0xAA-семьи (u8/u16/u32/u64/u128) в user-VA → [AA-STORE]
//      vpc = ТОЧНАЯ инструкция-писатель яда!
//   2. Кольцо 512 TB + дамп на входе #GP(13)/#PF(14) стабиль = контекст.
// Компиляция: gcc -O2 -fPIC -shared -I. -o aa-hunter.so aa-hunter.c
// Env: AAHUNT_LOG, AAHUNT_LO/HI (hex), CRASHBT_ISR13/14
// ============================================================================
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

extern void qemu_plugin_register_vcpu_tb_exec_cb(
    struct qemu_plugin_tb *tb, void (*cb)(unsigned int, void *),
    enum qemu_plugin_cb_flags flags, void *udata);
extern uint64_t qemu_plugin_tb_vaddr(const struct qemu_plugin_tb *tb);
extern void qemu_plugin_register_atexit_cb(
    qemu_plugin_id_t id, void (*cb)(void *), void *udata);

// ─── кольцо TB (как crash-bt) ──────────────────────────────────────────────
#define RING_N 512
static uint64_t g_ring[RING_N];
static volatile uint32_t g_ring_pos = 0;
static uint64_t g_isr13 = 0x10d101;
static uint64_t g_isr14 = 0x10d108;
static uint64_t g_memset_va = 0x4000D9B800;  // libc+0x1B2800 = memset-вход (avx)
static int g_ms_dumps = 0;

static uint64_t g_lo = 0x4000000000;       // user VA низ (либы)
static uint64_t g_hi = 0x800000000000;     // user VA верх
static FILE *g_out = NULL;
static int g_stores = 0;

// дедуп vpc (каждый уникальный call-site пишем раз)
#define MAX_D 96
static uint64_t g_dumped[MAX_D];
static int g_dumped_n = 0;

static int vpc_dumped(uint64_t vpc) {
    for (int i = 0; i < g_dumped_n; i++)
        if (g_dumped[i] == vpc) return 1;
    return 0;
}

static int is_aa_bytes(uint64_t v, unsigned nb) {
    for (unsigned b = 0; b < nb; b++)
        if (((v >> (b * 8)) & 0xFF) != 0xAA) return 0;
    return 1;
}

typedef struct { uint64_t vpc; } UserData;

static void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                   uint64_t vaddr, void *udata)
{
    qemu_plugin_mem_value mv = qemu_plugin_mem_get_value(info);
    if (!qemu_plugin_mem_is_store(info)) return;   // только STORE-сторона
    if (vaddr < g_lo || vaddr >= g_hi) return;     // user-VA фильтр

    uint64_t val = 0;
    unsigned width = 0;
    int match = 0;
    switch (mv.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:
        val = mv.data.u8; width = 1; match = (val == 0xAA); break;
    case QEMU_PLUGIN_MEM_VALUE_U16:
        val = mv.data.u16; width = 2; match = (val == 0xAAAA); break;
    case QEMU_PLUGIN_MEM_VALUE_U32:
        val = mv.data.u32; width = 4; match = (val == 0xAAAAAAAAULL); break;
    case QEMU_PLUGIN_MEM_VALUE_U64:
        val = mv.data.u64; width = 8; match = is_aa_bytes(val, 8); break;
    case QEMU_PLUGIN_MEM_VALUE_U128:
        val = mv.data.u128.low; width = 16;
        match = (is_aa_bytes(mv.data.u128.low, 8) &&
                 is_aa_bytes(mv.data.u128.high, 8));
        break;
    default:
        return;
    }
    if (!match) return;

    g_stores++;
    uint64_t vpc = ((UserData *)udata)->vpc;
    fprintf(g_out, "[AA-STORE] #%d vpc=0x%" PRIx64 " vaddr=0x%" PRIx64
                   " w=%u val=0x%016" PRIx64 "\n",
            g_stores, vpc, vaddr, width, val);
    fflush(g_out);
    if (!vpc_dumped(vpc) && g_dumped_n < MAX_D) {
        g_dumped[g_dumped_n++] = vpc;
        // v2: ДАМП КОЛЬЦА на первом матче vpc — кольцо = ТБ-контекст:
        // memset-луп + его вызыватель (call-site ТБ ниже кольца)
        uint32_t pos = g_ring_pos;
        fprintf(g_out, "[AA-BT] vpc=0x%" PRIx64 " ring (newest first):\n", vpc);
        for (int i = 0; i < 64; i++) {
            uint64_t va = g_ring[(pos - 1 - i) & (RING_N - 1)];
            if (!va) break;
            fprintf(g_out, "  bt[%2d] 0x%016" PRIx64 "\n", i, va);
        }
        fflush(g_out);
    }
}

// ─── кольцо + дамп на входе исключения ─────────────────────────────────────
static void ring_cb(unsigned int vcpu, void *udata) {
    (void)vcpu;
    uint32_t p = g_ring_pos;
    g_ring[p & (RING_N - 1)] = (uint64_t)udata;
    g_ring_pos = p + 1;
}

static void exc_cb(unsigned int vcpu, void *udata) {
    (void)udata;
    fprintf(g_out, "EXC-ENTRY vcpu=%u ring_pos=%u (total aa-stores=%d)\n",
            vcpu, g_ring_pos, g_stores);
    uint32_t pos = g_ring_pos;
    for (int i = 0; i < 96; i++) {
        uint64_t va = g_ring[(pos - 1 - i) & (RING_N - 1)];
        if (!va) break;
        fprintf(g_out, "  [%2d] 0x%016" PRIx64 "%s\n", i, va,
                (i == 0) ? " <- faulting TB" : "");
    }
    fflush(g_out);
    memset(g_ring, 0, sizeof(g_ring));
}

// ─── вход в memset: кольцо = [memset-entry] ← [CALL-SITE вызывателя] ← …
// Дамп при НОВОМ вызывателе (ring[1]) — функция-источник заполнения!
static uint64_t g_ms_callers[64];
static int g_ms_callers_n = 0;

static void memset_entry_cb(unsigned int vcpu, void *udata) {
    (void)udata;
    uint32_t pos = g_ring_pos;
    if (pos < 2) return;
    uint64_t self_tb = g_ring[(pos - 1) & (RING_N - 1)];
    uint64_t caller_tb = g_ring[(pos - 2) & (RING_N - 1)];
    for (int i = 0; i < g_ms_callers_n; i++)
        if (g_ms_callers[i] == caller_tb) return;  // дедуп по вызывателю
    if (g_ms_callers_n >= 64) return;
    g_ms_callers[g_ms_callers_n++] = caller_tb;
    g_ms_dumps++;
    fprintf(g_out, "[MS-ENTRY] #%d caller_tb=0x%016" PRIx64
                   " self=0x%" PRIx64 "\n",
            g_ms_dumps, caller_tb, self_tb);
    for (int i = 2; i < 16; i++) {
        uint64_t va = g_ring[(pos - 1 - i) & (RING_N - 1)];
        if (!va) break;
        fprintf(g_out, "  ms-bt[%2d] 0x%016" PRIx64 "\n", i, va);
    }
    fflush(g_out);
}

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    (void)id;
    uint64_t va = qemu_plugin_tb_vaddr(tb);
    if (va == g_isr14 || va == g_isr13) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, exc_cb,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)va);
    } else if (va == g_memset_va) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, memset_entry_cb,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)va);
    }
    // mem-callback на КАЖДУЮ инструкцию (store-сторона; LOAD-фильтр в cb)
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        UserData *ud = malloc(sizeof(UserData));
        ud->vpc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_mem_cb(insn, mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                                          QEMU_PLUGIN_MEM_W, ud);
    }
    // кольцо: регистрируем exec-cb на сам TB
    qemu_plugin_register_vcpu_tb_exec_cb(tb, ring_cb,
                                         QEMU_PLUGIN_CB_NO_REGS, (void *)va);
}

static void atexit_cb(void *udata) {
    (void)udata;
    if (!g_out) return;
    fprintf(g_out, "\nATEXIT: aa-stores total=%d\n", g_stores);
    fflush(g_out);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv) {
    (void)info; (void)argc; (void)argv;
    const char *lo = getenv("AAHUNT_LO");
    const char *hi = getenv("AAHUNT_HI");
    if (lo) g_lo = strtoull(lo, NULL, 16);
    if (hi) g_hi = strtoull(hi, NULL, 16);
    const char *isr13 = getenv("CRASHBT_ISR13");
    const char *isr14 = getenv("CRASHBT_ISR14");
    if (isr13) g_isr13 = strtoull(isr13, NULL, 16);
    if (isr14) g_isr14 = strtoull(isr14, NULL, 16);
    const char *msva = getenv("AAHUNT_MEMSET");
    if (msva) g_memset_va = strtoull(msva, NULL, 16);
    const char *logpath = getenv("AAHUNT_LOG");
    g_out = fopen(logpath ? logpath : "/tmp/aa-hunter.log", "w");
    if (!g_out) g_out = stderr;
    fprintf(g_out, "[aaHUNTER] lo=0x%" PRIx64 " hi=0x%" PRIx64
                   " isr13=0x%" PRIx64 " isr14=0x%" PRIx64 "\n",
            g_lo, g_hi, g_isr13, g_isr14);
    fflush(g_out);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, atexit_cb, NULL);
    return 0;
}
