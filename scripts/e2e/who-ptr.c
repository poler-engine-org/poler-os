// ============================================================================
// who-ptr.c — CDD №12 p6: TCG-плагин «ОТКУДА ВЗЯЛСЯ УКАЗАТЕЛЬ?»
// Логирует КАЖДУЮ операцию (load или store), чей ЗНАЧЕНЬЕ (qemu_plugin_mem_
// get_value) равно TARGET — находим источник мусорного/нулевого указателя:
//   • load  c TARGET  = память, ИЗ которой приложение прочитало указатель
//   • store c TARGET  = память, В которую указатель был записан (источник — vpc)
// Загрузка: -plugin file=who-ptr.so,TARGET_HEX   (позиционные куски — QEMU
// режет по запятым и передаёт их плагину; arg=префикс тоже поддержан).
// Лог: env WHOAAAA_LOG (default /tmp/who-ptr.log).
// API v4 (QEMU ≥10): qemu_plugin_mem_get_value работает в mem_cb без regs.
// ============================================================================
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t g_target = 0;
static uint64_t g_lo = 0;       // CDD №12 p7: фильтр диапазона (kernel-region)
static uint64_t g_hi = 0;       // 0/0 = без фильтра (все VA)
static FILE *g_out = NULL;


// ─── CDD #12 p8 (WHO-PTR-STACK): API v4 регистров гостя ───────────────
struct qemu_plugin_register;
typedef struct qemu_plugin_register qemu_plugin_reg;
typedef struct {
    const char *name;
    qemu_plugin_reg *handle;
} qemu_plugin_reg_descriptor;
extern int qemu_plugin_get_registers(qemu_plugin_reg_descriptor **out);
extern int qemu_plugin_read_register(qemu_plugin_reg *reg, GByteArray *buf);
static qemu_plugin_reg *g_rsp = NULL;   // дескриптор RSP (инициализация лениво)
static int g_stack_dumps = 0;           // анти-спам: максимум 8 дампов

static void dump_guest_stack(void)
{
    if (g_stack_dumps >= 8) return;
    if (!g_rsp) {
        qemu_plugin_reg_descriptor *descs = NULL;
        int n = qemu_plugin_get_registers(&descs);
        if (n <= 0) { g_rsp = (qemu_plugin_reg *)1; return; } // нет API — выкл
        for (int i = 0; i < n; i++) {
            if (descs[i].name && strcmp(descs[i].name, "rsp") == 0) {
                g_rsp = descs[i].handle;
                break;
            }
        }
    }
    if (!g_rsp || g_rsp == (qemu_plugin_reg *)1) return;
    GByteArray *rspbuf = g_byte_array_sized_new(8);
    if (qemu_plugin_read_register(g_rsp, rspbuf) && rspbuf->len >= 8) {
        uint64_t rsp = 0;
        memcpy(&rsp, rspbuf->data, 8);
        g_byte_array_free(rspbuf, TRUE);
        fprintf(g_out, "[whoPTR-STACK] rsp=0x%" PRIx64 " ret-chain:\n", rsp);
        for (int i = 0; i < 12; i++) {
            uint64_t va = rsp + i * 8;
            GByteArray *ba = g_byte_array_sized_new(8);
            if (qemu_plugin_read_memory_vaddr(va, ba, 8) && ba->len >= 8) {
                uint64_t v = 0;
                memcpy(&v, ba->data, 8);
                fprintf(g_out, "  [rsp+%#04x] 0x%016" PRIx64 "\n", i * 8, v);
            }
            g_byte_array_free(ba, TRUE);
        }
        fflush(g_out);
        g_stack_dumps++;
    } else {
        g_byte_array_free(rspbuf, TRUE);
    }
}

typedef struct {
    uint64_t vpc;
} UserData;

static void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                   uint64_t vaddr, void *udata)
{
    qemu_plugin_mem_value mv = qemu_plugin_mem_get_value(info);
    uint64_t val = 0;
    int is_store = qemu_plugin_mem_is_store(info) ? 1 : 0;
    switch (mv.type) {
        case QEMU_PLUGIN_MEM_VALUE_U8:  val = mv.data.u8;  break;
        case QEMU_PLUGIN_MEM_VALUE_U16: val = mv.data.u16; break;
        case QEMU_PLUGIN_MEM_VALUE_U32: val = mv.data.u32; break;
        case QEMU_PLUGIN_MEM_VALUE_U64: val = mv.data.u64; break;
        case QEMU_PLUGIN_MEM_VALUE_U128:
            if (mv.data.u128.low == g_target || mv.data.u128.high == g_target) {
                fprintf(g_out, "[whoPTR] vcpu=%u %s vaddr=0x%" PRIx64
                               " vpc=0x%" PRIx64 " val.lo=0x%016" PRIx64
                               " val.hi=0x%016" PRIx64 "\n",
                        vcpu_index, is_store ? "STORE" : "LOAD", vaddr,
                        ((UserData *)udata)->vpc,
                        mv.data.u128.low, mv.data.u128.high);
                fflush(g_out);
            }
            return;
        default: val = 0; break;
    }
    // CDD #12 p8: ФИЛЬТР ДИАПАЗОНА ПЕРВЫМ (до дорогого read_memory):
    // kernel-VA (бут/CPIO) выходит мгновенно; readback — только guest-VA.
    // (env WHOAAAA_LO/HI hex — guest-диапазон: 0x100000000000..0x800000000000)
    if (g_lo | g_hi) {
        if (vaddr < g_lo || vaddr >= g_hi) return;
    }
    // CDD №12 p6: get_value для LOAD в QEMU 10 не заполняется (тип U-64
    // только у store) — читаем память ДО загрузки (callback срабатывает
    // ПЕРЕД операцией: pre-load чтение = значение, которое загрузится).
    if (!is_store) {
        GByteArray *ba = g_byte_array_sized_new(8);
        if (qemu_plugin_read_memory_vaddr(vaddr, ba, 8) && ba->len >= 8) {
            memcpy(&val, ba->data, 8);
        }
        g_byte_array_free(ba, TRUE);
    }
    if (val != g_target) return;
    fprintf(g_out, "[whoPTR] vcpu=%u %s vaddr=0x%" PRIx64 " vpc=0x%" PRIx64 " val=0x%016" PRIx64 "\n",
            vcpu_index, is_store ? "STORE" : "LOAD", vaddr,
            ((UserData *)udata)->vpc, val);
    fflush(g_out);
    if (is_store) dump_guest_stack(); // CDD #12 p8: вызывающая цепочка memset
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
    char argbuf[128];
    argbuf[0] = 0;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "arg=", 4) == 0) {
            snprintf(argbuf, sizeof(argbuf), "%s", argv[i] + 4);
            break;
        }
    }
    if (!argbuf[0] && argc >= 1) {
        // позиционные куски: первый — TARGET (QEMU 10 передаёт без префикса;
        // file= кусок QEMU потребляет сам — до плагина он НЕ доходит)
        for (int i = 0; i < argc; i++) {
            if (strncmp(argv[i], "file=", 5) == 0) continue;
            snprintf(argbuf, sizeof(argbuf), "%s", argv[i]);
            break;
        }
    }
    if (!argbuf[0]) {
        fprintf(stderr, "[whoPTR] требуется TARGET_HEX (позиционно или arg=)\n");
        return -1;
    }
    g_target = strtoull(argbuf, NULL, 16);

    const char *lo = getenv("WHOAAAA_LO");
    const char *hi = getenv("WHOAAAA_HI");
    if (lo) g_lo = strtoull(lo, NULL, 16);
    if (hi) g_hi = strtoull(hi, NULL, 16);

    const char *logpath = getenv("WHOAAAA_LOG");
    g_out = fopen(logpath ? logpath : "/tmp/who-ptr.log", "w");
    if (!g_out) g_out = stderr;
    fprintf(g_out, "[whoPTR] target=0x%" PRIx64 " log=%s\n", g_target,
            logpath ? logpath : "/tmp/who-ptr.log");
    fflush(g_out);

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
