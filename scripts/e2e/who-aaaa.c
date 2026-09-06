// ============================================================================
// who-aaaa.c — CDD №12 p4-final: TCG-плагин «КТО ПИШЕТ 0xAAAAAAAA?»
// Логирует каждую ЗАПИСЬ в заданный гостевой адрес (или диапазон) с
// vpc (адресом инструкции-писателя) и значением QWORD после записи.
// QEMU ≥10, plugin API v4. Загрузка: -plugin file=who-aaaa.so,arg=ADDR[,LEN]
// Лог: QEMU stderr (моно-поллинг не нужен — фильтр на месте).
// ============================================================================
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t g_lo[4] = {0,0,0,0}, g_hi[4] = {0,0,0,0};
static int g_nr = 0;
static FILE *g_out = NULL;
static GMutex g_mut;

typedef struct {
    uint64_t vpc;
} UserData;

// чтение гостевой памяти после записи (vaddr) — через plugin API v4:
// qemu_plugin_read_memory_vaddr(vaddr, buf, len) → bool


static void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                   uint64_t vaddr, void *udata)
{
    if (!(qemu_plugin_mem_is_store(info))) return;
    int hit = 0;
    for (int k = 0; k < g_nr; k++)
        if (vaddr >= g_lo[k] && vaddr < g_hi[k]) { hit = 1; break; }
    if (!hit) return;

    UserData *ud = (UserData *)udata;
    uint64_t val = 0;
    GByteArray *ba = g_byte_array_sized_new(8);
    if (qemu_plugin_read_memory_vaddr(vaddr, ba, 8) && ba->len >= 8) {
        memcpy(&val, ba->data, 8);
    }
    g_byte_array_free(ba, TRUE);

    g_mutex_lock(&g_mut);
    fprintf(g_out, "[whoAAAA] vcpu=%u store vaddr=0x%" PRIx64
                   " vpc=0x%" PRIx64 " new=0x%016" PRIx64 "\n",
            vcpu_index, vaddr, ud->vpc, val);
    fflush(g_out);
    g_mutex_unlock(&g_mut);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        // подписываем КАЖДУЮ инструкцию на mem-cb (CB сам фильтрует store+addr)
        UserData *ud = g_new0(UserData, 1);
        ud->vpc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_mem_cb(insn, mem_cb, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, ud);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    // QEMU 10 передаёт аргументы БЕЗ 'arg='-префикса: "40e380" "8";
    // старый формат "arg=ADDR[,LEN]" — тоже поддерживаем.
    char argbuf[128];
    argbuf[0] = 0;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "arg=", 4) == 0) {
            snprintf(argbuf, sizeof(argbuf), "%s", argv[i] + 4);
            break;
        }
    }
    if (!argbuf[0]) {
        // CDD №12 p6: QEMU передаёт диапазоны ПОЗИЦИОННЫМИ кусками (по
        // запятым -plugin); старый код склеивал только argv[0]+argv[1] —
        // второй диапазон (ADDR2,LEN2) ТЕРЯЛСЯ (пустые логи half-watch!).
        // Склеиваем ВСЕ куски (кроме file=, который QEMU потребляет сам).
        int first = 1;
        for (int i = 0; i < argc; i++) {
            if (strncmp(argv[i], "file=", 5) == 0) continue;
            if (!first) {
                size_t l = strlen(argbuf);
                if (l + 1 < sizeof(argbuf)) {
                    argbuf[l] = ',';
                    argbuf[l + 1] = 0;
                }
            }
            strncat(argbuf, argv[i], sizeof(argbuf) - strlen(argbuf) - 1);
            first = 0;
        }
    }
    const char *argstr = argbuf[0] ? argbuf : NULL;
    if (!argstr) {
        fprintf(stderr, "[whoAAAA] требуется arg=HEXADDR[,LEN]\n");
        return -1;
    }
    // формат: "ADDR,LEN[,ADDR2,LEN2...]" (до 4 диапазонов)
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", argstr);
    char *save = NULL;
    for (char *tok = strtok_r(tmp, ",;", &save); tok && g_nr < 4; ) {
        uint64_t a = strtoull(tok, NULL, 16);
        char *tok2 = strtok_r(NULL, ",;", &save);
        uint64_t l = tok2 ? strtoull(tok2, NULL, 16) : 8;
        g_lo[g_nr] = a; g_hi[g_nr] = a + l; g_nr++;
        tok = strtok_r(NULL, ",;", &save);
    }

    const char *logpath = getenv("WHOAAAA_LOG");
    g_out = fopen(logpath ? logpath : "/tmp/who-aaaa.log", "w");
    if (!g_out) g_out = stderr;

    for (int k = 0; k < g_nr; k++)
        fprintf(stderr, "[whoAAAA] watch#%d [0x%" PRIx64 ", 0x%" PRIx64 ")\n",
                k, g_lo[k], g_hi[k]);
    fprintf(stderr, "[whoAAAA] log→%s\n", logpath ? logpath : "/tmp/who-aaaa.log");

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
