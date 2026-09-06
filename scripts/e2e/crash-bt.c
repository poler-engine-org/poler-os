// ============================================================================
// crash-bt.c v2 — CDD №12 p9: ОХОТНИК ЗА NULL-VTABLE КРАШЕМ (RIP=0x40).
// УРОК v1: qemu_plugin_get_registers / read_register / read_memory в этом
// QEMU-билде НЕРАБОТОСПОСОБНЫ (run3: rsp=0/rbp=0 всегда; v1: host-сегфолт
// в walk дескрипторов). v2 = ТОЛЬКО ring-buffer TB-адресов (NO_REGS, без
// обращений к памяти гостя):
//   1. каждый TB пишет свой vaddr в кольцо (дёшево: 1 store);
//   2. exec TB по адресу isr_stub_14 (0x10d108 = вход IDT #PF) → дамп
//      кольца (32 записи). ПОСЛЕДНЯЯ запись = faulting TB = call-сайт!
//   3. корреляция: kernel-краш-репорт в serial.log даёт RSP/RBP/регистры;
//      PF-ENTRY #N в логе плагина = N-я #PF — финальный перед «CPU
//      EXCEPTION» в serial = искомый.
//   4. atexit — финальное кольцо.
// Env: CRASHBT_LOG, CRASHBT_ISR (hex, default 0x10d108).
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

#define RING_N 512
static uint64_t g_ring[RING_N];
static volatile uint32_t g_ring_pos = 0;
static uint64_t g_isr13 = 0x10d101;   // #GP stub (isr_stub_13)
static uint64_t g_isr14 = 0x10d108;   // #PF stub (isr_stub_14)
static FILE *g_out = NULL;
static int g_dumps = 0;

static void ring_cb(unsigned int vcpu, void *udata) {
    (void)vcpu;
    uint32_t p = g_ring_pos;
    g_ring[p & (RING_N - 1)] = (uint64_t)udata;
    g_ring_pos = p + 1;
}

static void pf_cb(unsigned int vcpu, void *udata) {
    (void)udata;
    g_dumps++;
    fprintf(g_out, "PF-ENTRY #%d vcpu=%u ring_pos=%u\n", g_dumps, vcpu,
            g_ring_pos);
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

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    (void)id;
    uint64_t va = qemu_plugin_tb_vaddr(tb);
    if (va == g_isr14 || va == g_isr13) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, pf_cb,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)va);
    } else {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, ring_cb,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)va);
    }
}

static void atexit_cb(void *udata) {
    (void)udata;
    if (!g_out) return;
    fprintf(g_out, "\nATEXIT: финальное кольцо (последний TB):\n");
    uint32_t pos = g_ring_pos;
    for (int i = 0; i < 96; i++) {
        uint64_t va = g_ring[(pos - 1 - i) & (RING_N - 1)];
        if (!va) break;
        fprintf(g_out, "  [%2d] 0x%016" PRIx64 "\n", i, va);
    }
    fflush(g_out);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv) {
    (void)info;
    (void)argc;
    (void)argv;
    const char *isr = getenv("CRASHBT_ISR");
    if (isr) g_isr14 = strtoull(isr, NULL, 16);
    const char *logpath = getenv("CRASHBT_LOG");
    g_out = fopen(logpath ? logpath : "/tmp/crash-bt.log", "w");
    if (!g_out) g_out = stderr;
    fprintf(g_out, "[crashBT-v3] isr13=0x%" PRIx64 " isr14=0x%" PRIx64 "\n",
            g_isr13, g_isr14);
    fflush(g_out);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, atexit_cb, NULL);
    return 0;
}
