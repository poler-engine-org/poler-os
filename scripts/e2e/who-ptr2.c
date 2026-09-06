// ============================================================================
// who-ptr2.c — CDD №12 p9: WHO-PTR-2 — бэктрейс-трассировщик 0xAA-семьи.
// Закрывает 2 бага p8-инструмента (run8: «poison БЕЗ store-событий»):
//   1. ШИРИНА ЗНАЧЕНИЯ: p8-к cmp был ТОЛЬКО по точному target (u32
//      0xAAAAAAAA). AVX/SSE-заполнение идёт u128-сторами (обе половины
//      0xAAAAAAAAAAAAAAAA — НЕ равны 0xAAAAAAAA) → memset-хвост ловился,
//      основное тело — НЕТ. Теперь: PATTERN-режим (arg=PAT) — ловим ВСЕ
//      ширины, у которых КАЖДЫЙ байт = 0xAA: u8 0xAA, u16 0xAAAA,
//      u32 0xAAAAAAAA, u64 0xAAAA…, u128 (обе половины).
//   2. LOAD-СТОРОНА: run8-стиль (грязная страница от ядра — 0xAA УЖЕ в
//      памяти, userspace только ЧИТАЕТ) — p8-к tracer load-молчал.
//      Теперь load-hit тоже логируется + бэктрейс (рид-сайд яда).
// На КАЖДЫЙ хит (store И load): vpc + vaddr + ширина + бэктрейс:
//   [rsp+0..15] сырой ret-цеп (memset leaf → caller = [rsp]) +
//   RBP-регистр (если валидный user-VA → [rbp], [rbp+8] = frame-ret).
// Дедуп по vpc: каждый уникальный call-site дамбит стек ОДИН раз
// (макс 48 дампов), счётчик повторов в конце.
// Загрузка: -plugin file=who-ptr2.so,PAT          (0xAA-семья)
//                file=who-ptr2.so,DEADBEEF        (точный 64-бит target)
// Фильтр VA: env WHOAAAA_LO / WHOAAAA_HI (hex); лог: WHOAAAA_LOG.
// ============================================================================
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t g_target = 0;
static int g_pattern = 0;      // 1 = 0xAA-семья любой ширины
static uint64_t g_lo = 0, g_hi = 0;
static FILE *g_out = NULL;

// ─── регистры гостя (API v4) ───────────────────────────────────────────
struct qemu_plugin_register;
typedef struct qemu_plugin_register qemu_plugin_reg;
typedef struct {
    const char *name;
    qemu_plugin_reg *handle;
} qemu_plugin_reg_descriptor;
extern int qemu_plugin_get_registers(qemu_plugin_reg_descriptor **out);
extern int qemu_plugin_read_register(qemu_plugin_reg *reg, GByteArray *buf);
static qemu_plugin_reg *g_rsp = NULL;
static qemu_plugin_reg *g_rbp = NULL;

#define MAX_DUMPS 48
static uint64_t g_dumped_vpc[MAX_DUMPS];
static int g_dump_count = 0;
static uint64_t g_total_hits = 0;

static int vpc_already_dumped(uint64_t vpc) {
    for (int i = 0; i < g_dump_count; i++)
        if (g_dumped_vpc[i] == vpc) return 1;
    return 0;
}

static uint64_t read_reg64(qemu_plugin_reg *reg) {
    if (!reg) return 0;
    GByteArray *ba = g_byte_array_sized_new(8);
    uint64_t v = 0;
    if (qemu_plugin_read_register(reg, ba) && ba->len >= 8)
        memcpy(&v, ba->data, 8);
    g_byte_array_free(ba, TRUE);
    return v;
}

static void ensure_regs(void) {
    static int tried = 0;
    if (tried) return;
    tried = 1;
    qemu_plugin_reg_descriptor *descs = NULL;
    int n = qemu_plugin_get_registers(&descs);
    if (n <= 0) return;
    for (int i = 0; i < n; i++) {
        if (!descs[i].name) continue;
        if (strcmp(descs[i].name, "rsp") == 0) g_rsp = descs[i].handle;
        else if (strcmp(descs[i].name, "rbp") == 0) g_rbp = descs[i].handle;
    }
}

static void read_qword(uint64_t va, uint64_t *out) {
    *out = 0;
    GByteArray *ba = g_byte_array_sized_new(8);
    if (qemu_plugin_read_memory_vaddr(va, ba, 8) && ba->len >= 8)
        memcpy(out, ba->data, 8);
    g_byte_array_free(ba, TRUE);
}

// бэктрейс: сырой rsp-цеп + rbp-кадр
static void dump_backtrace(uint64_t vpc, const char *kind, unsigned width) {
    ensure_regs();
    uint64_t rsp = read_reg64(g_rsp);
    uint64_t rbp = read_reg64(g_rbp);
    fprintf(g_out, "[HIT] %s vpc=0x%" PRIx64 " w=%u rsp=0x%" PRIx64
                   " rbp=0x%" PRIx64 "\n", kind, vpc, width, rsp, rbp);
    for (int i = 0; i < 16; i++) {
        uint64_t v = 0;
        read_qword(rsp + i * 8, &v);
        fprintf(g_out, "  [rsp+%#03x] 0x%016" PRIx64 "\n", i * 8, v);
    }
    if (rbp > 0x10000 && rbp < 0x800000000000) {
        uint64_t sv = 0, rt = 0;
        read_qword(rbp, &sv);
        read_qword(rbp + 8, &rt);
        fprintf(g_out, "  [rbp+0]  =0x%016" PRIx64 " [rbp+8] =0x%016" PRIx64
                       "\n", sv, rt);
    }
    fflush(g_out);
}

// паттерн: все байты значения = 0xAA (g_pattern-режим)
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
    int is_store = qemu_plugin_mem_is_store(info) ? 1 : 0;
    uint64_t val = 0;
    unsigned width = 0;
    int match = 0;

    switch (mv.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:
        val = mv.data.u8; width = 1;
        match = g_pattern ? (val == 0xAA) : (val == g_target);
        break;
    case QEMU_PLUGIN_MEM_VALUE_U16:
        val = mv.data.u16; width = 2;
        match = g_pattern ? (val == 0xAAAA) : (val == g_target);
        break;
    case QEMU_PLUGIN_MEM_VALUE_U32:
        val = mv.data.u32; width = 4;
        match = g_pattern ? (val == 0xAAAAAAAAULL) : (val == g_target);
        break;
    case QEMU_PLUGIN_MEM_VALUE_U64:
        val = mv.data.u64; width = 8;
        match = g_pattern ? is_aa_bytes(val, 8) : (val == g_target);
        break;
    case QEMU_PLUGIN_MEM_VALUE_U128:
        match = g_pattern
            ? (is_aa_bytes(mv.data.u128.low, 8) &&
               is_aa_bytes(mv.data.u128.high, 8))
            : (mv.data.u128.low == g_target || mv.data.u128.high == g_target);
        width = 16;
        break;
    default:
        return;
    }

    // VA-фильтр ПЕРВЫМ (kernel-VA 0x100000 отсекается мгновенно)
    if (g_lo | g_hi) {
        if (vaddr < g_lo || vaddr >= g_hi) return;
    }

    // LOAD: value не заполняется — читаем память ДО операции (pre-load
    // чтение = значение, которое загрузится). Ширина: не знаем из mv
    // (value-тип у LOAD пуст) — но для 0xAA-семьи достаточно проверить
    // БАЙТ по vaddr + нулевое расширение: 1/2/4/8-байтный 0xAA-паттерн
    // детектируется чтением qword и проверкой младших байтов.
    if (!is_store) {
        unsigned nb = (width > 8) ? 8 : width;
        if (nb == 0) nb = 8;
        uint64_t tmp = 0;
        read_qword(vaddr, &tmp);
        match = g_pattern ? is_aa_bytes(tmp, nb) : (tmp == g_target);
    }

    if (!match) return;

    g_total_hits++;
    uint64_t vpc = ((UserData *)udata)->vpc;
    fprintf(g_out, "[EV] vcpu=%u %s vaddr=0x%" PRIx64 " w=%u vpc=0x%" PRIx64
                   " val=0x%016" PRIx64 "\n",
            vcpu_index, is_store ? "STORE" : "LOAD", vaddr, width, vpc, val);
    fflush(g_out);

    if (!vpc_already_dumped(vpc) && g_dump_count < MAX_DUMPS) {
        g_dumped_vpc[g_dump_count++] = vpc;
        dump_backtrace(vpc, is_store ? "STORE-BT" : "LOAD-BT", width);
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        UserData *ud = malloc(sizeof(UserData));
        ud->vpc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_mem_cb(insn, mem_cb, QEMU_PLUGIN_CB_R_REGS,
                                         QEMU_PLUGIN_MEM_RW, ud);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    char argbuf[64];
    argbuf[0] = 0;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "arg=", 4) == 0) {
            snprintf(argbuf, sizeof(argbuf), "%s", argv[i] + 4);
            break;
        }
    }
    if (!argbuf[0]) {
        for (int i = 0; i < argc; i++) {
            if (strncmp(argv[i], "file=", 5) == 0) continue;
            snprintf(argbuf, sizeof(argbuf), "%s", argv[i]);
            break;
        }
    }
    if (!argbuf[0]) {
        fprintf(stderr, "[whoPTR2] требуется PAT или TARGET_HEX\n");
        return -1;
    }
    if (strcasecmp(argbuf, "PAT") == 0 || strcasecmp(argbuf, "PATTERN") == 0 ||
        strncasecmp(argbuf, "PAT=", 4) == 0 ||
        strncasecmp(argbuf, "PATTERN=", 8) == 0) {
        // QEMU 10: bare «PAT» превращает в «PAT=on» (short-form boolean)
        g_pattern = 1;
        g_target = 0xAAAAAAAAAAAAAAAAULL;
    } else {
        g_pattern = 0;
        g_target = strtoull(argbuf, NULL, 16);
    }

    const char *lo = getenv("WHOAAAA_LO");
    const char *hi = getenv("WHOAAAA_HI");
    if (lo) g_lo = strtoull(lo, NULL, 16);
    if (hi) g_hi = strtoull(hi, NULL, 16);

    const char *logpath = getenv("WHOAAAA_LOG");
    g_out = fopen(logpath ? logpath : "/tmp/who-ptr2.log", "w");
    if (!g_out) g_out = stderr;
    fprintf(g_out, "[whoPTR2] mode=%s target=0x%" PRIx64 " lo=0x%" PRIx64
                   " hi=0x%" PRIx64 "\n", g_pattern ? "PATTERN" : "VALUE",
            g_target, g_lo, g_hi);
    fflush(g_out);

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
