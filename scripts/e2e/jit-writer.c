// ============================================================================
// jit-writer.c v2 — CDD №12 p11: КТО пишет в JIT-страницу + ГДЕ ОСЕДАЕТ
// УКАЗАТЕЛЬ на JIT-функцию? (нативный TCG-плагин; gdbstub-путь хрупок)
// ============================================================================
// Эмпирика run3: memmove (libc+0x18DE9D) копирует object-код: 11 НУЛЕЙ на
// P1+0, функция — на P1+0x0B (89 D0 83 E0 07...), релокация (libLLVM) — в
// P2. Крах: call *0x30(%r10) входит на P1+0 — на 11 байт ниже входа.
// v2 добавляет:
//   1. Мульти-диапазоны (до 4): argv = LO,HI,LO2,HI2,... (позиционные)
//   2. VALUE-WATCH: любая user-запись (w>=8) со значением в
//      [JITW_VLO, JITW_VHI) (дефолт = диапазон-1) → [JW-V]: ГДЕ хранится
//      указатель на JIT-функцию и ЧЕМ он был записан (P1+0 vs P1+0xB!)
//   3. EXC-дамп кольца ТОЛЬКО когда уже были JIT-записи (stores>0) —
//      ранний demand-#PF ld.so не съедает one-shot (баг run3).
// Ядро-ТБ не инструментируем (бут без 10-50× штрафа; эмпирика p6).
// Env: JITW_LOG, JITW_VLO/JITW_VHI, JITW_ISR13/14, JITW_USER_LO.
// Компиляция: gcc -O2 -fPIC -shared -I. -o jit-writer.so jit-writer.c
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
static uint64_t g_isr13 = 0x10d101;
static uint64_t g_isr14 = 0x10d108;
// v3: JITW_USER_LO по умолчанию 0 — инструментируем И KERNEL-ТБ (ловим
// kernel copy_out в user-память); boot-стоимость приемлема (фильтр в C).
static uint64_t g_user_lo = 0;

#define MAX_R 4
static uint64_t g_rlo[MAX_R] = {0x401569D000, 0, 0, 0};
static uint64_t g_rhi[MAX_R] = {0x40156A0000, 0, 0, 0};
static int g_nr = 1;

// value-watch: любое user-хранилище со значением в этом окне
static uint64_t g_vlo = 0x401569D000;
static uint64_t g_vhi = 0x40156A0000;

static FILE *g_out = NULL;
static long g_stores = 0;
static long g_vstores = 0;
static int g_exc_n = 0;
static long g_loads = 0;

typedef struct { uint64_t vpc; } UserData;

// v7: ловим эмиcсию endbr64 (0xfa1e0ff3) в ЛЮБОЙ ширине/половине
// (эмиттер может флашить u64/u128-чанками!) + первый qword ТЕЛА шейдера
// (0x07c28307e083d089 = байты 89 d0 83 e0 07 83 c2 07) — адрес его записи
// = адрес staging-буфера → следующий прогон: range-watch занулителя.
static uint64_t g_endbr_hits = 0;
static uint64_t g_body_hits = 0;
static uint64_t g_prefix_hits = 0;

static void dump_mem(const char *tag, uint64_t va, size_t len);
static void scan_sources(void);

static void watch_markers(uint64_t vpc, uint64_t vaddr, unsigned width,
                          uint64_t val, qemu_plugin_mem_value mv) {
    int endbr = 0, body = 0;
    uint32_t lo4 = (uint32_t)(val & 0xFFFFFFFFULL);
    uint32_t hi4 = (width >= 8) ? (uint32_t)(val >> 32) : 0;
    if (lo4 == 0xfa1e0ff3UL || hi4 == 0xfa1e0ff3UL) endbr = 1;
    if (width == 16 && mv.type == QEMU_PLUGIN_MEM_VALUE_U128) {
        if ((uint32_t)(mv.data.u128.high & 0xFFFFFFFFULL) == 0xfa1e0ff3UL ||
            (uint32_t)(mv.data.u128.high >> 32) == 0xfa1e0ff3UL)
            endbr = 1;
        if (mv.data.u128.high == 0x07c28307e083d089ULL) body = 1;
    }
    if (width >= 8 && val == 0x07c28307e083d089ULL) body = 1;

    if (endbr && g_endbr_hits < 32) {
        g_endbr_hits++;
        fprintf(g_out, "[ENDBR] #%lu vpc=0x%" PRIx64 " vaddr=0x%" PRIx64
                       " w=%u val=0x%016" PRIx64 "\n",
                g_endbr_hits, vpc, vaddr, width, val);
        fflush(g_out);
    }
    if (body && g_body_hits < 32) {
        g_body_hits++;
        fprintf(g_out, "[BODY-QW] #%lu vpc=0x%" PRIx64 " vaddr=0x%" PRIx64
                       " w=%u val=0x%016" PRIx64 "  <<== STAGING!\n",
                g_body_hits, vpc, vaddr, width, val);
        // v9: в момент P1-копии — СКАН источников: ищем СЛОМАННЫЙ буфер
        // ([qword=0][…][body@+0x0B]) и ПРАВИЛЬНЫЕ ([prefix][body@+0x0B]).
        if (vaddr == 0x401569d00bULL)
            scan_sources();
        // v8: если это P1-копия — дамп STAGING в ЭТОТ момент: префикс
        // (endbr64+imul×2 = 0x41d1af0ffa1e0ff3) на месте? Если ДА — а P1
        // получает нули → подмена кадра/stale-TLB = ядро, 100%.
        if (vaddr == 0x401569d00bULL)
            dump_mem("STAGING-AT-P1COPY", 0x400d563ee0, 0x50);
        if (vaddr == 0x400d563eebULL)
            dump_mem("STAGING-AFTER-COPYIN", 0x400d563ee0, 0x50);
        fflush(g_out);
    }
    // v8: ловим запись ПРЕФИКСА (endbr64+imul×2 = qword 0x41d1af0ffa1e0ff3)
    if (width >= 8 && val == 0x41d1af0ffa1e0ff3ULL && g_prefix_hits < 16) {
        g_prefix_hits++;
        fprintf(g_out, "[PREFIX-QW] #%lu vpc=0x%" PRIx64 " vaddr=0x%" PRIx64
                       " w=%u — ПРЕФИКС ЗАПИСАН!\n",
                g_prefix_hits, vpc, vaddr, width);
        dump_mem("STAGING-AT-PREFIXWRITE", 0x400d563ee0, 0x50);
        fflush(g_out);
    }
}

// v4: дамп гостевой памяти через API плагина (glib-символы экспортированы
// из QEMU-процесса; хедер сам декларирует g_byte_array_*).
static void dump_mem(const char *tag, uint64_t va, size_t len) {
    GByteArray *ba = g_byte_array_sized_new((guint)len);
    if (!ba || !qemu_plugin_read_memory_vaddr(va, ba, len)) {
        fprintf(g_out, "%s @0x%" PRIx64 ": READ FAIL\n", tag, va);
        if (ba) g_byte_array_free(ba, TRUE);
        return;
    }
    fprintf(g_out, "%s @0x%" PRIx64 " len=%u:", tag, va, ba->len);
    for (guint i = 0; i + 8 <= ba->len; i += 8) {
        uint64_t q = 0;
        memcpy(&q, ba->data + i, 8);
        fprintf(g_out, " %016" PRIx64, q);
        if ((i & 31) == 24) fprintf(g_out, "\n    ");
    }
    fprintf(g_out, "\n");
    fflush(g_out);
    g_byte_array_free(ba, TRUE);
}

// v9: скан источников P1-копии: буферы с телом шейдера (негабаритный
// memmem 8Б) и проверкой 11-байтного префикса: ПРАВИЛЬНЫЙ (endbr64+imul)
// vs СЛОМАННЫЙ (нули). Вызывается в момент P1-копии ([BODY-QW]@P1+0x0B).
static void scan_sources(void) {
    static const unsigned char body[8] =
        {0x89,0xd0,0x83,0xe0,0x07,0x83,0xc2,0x07};
    static const unsigned char pfx[8] =
        {0xf3,0x0f,0x1e,0xfa,0x0f,0xaf,0xd1,0x41};
    uint64_t ranges[][2] = {
        {0x100000000000ULL, 0x100000220000ULL},
        {0x4010000000ULL,   0x4015700000ULL},
        {0x400D0000000ULL,  0x400D7000000ULL},
    };
    const char *names[] = {"brk", "arenas", "thstacks"};
    int good = 0, broken = 0;
    for (int r = 0; r < 3; r++) {
        for (uint64_t pg = ranges[r][0]; pg < ranges[r][1]; pg += 0x1000) {
            GByteArray *ba = g_byte_array_sized_new(0x1000);
            if (!qemu_plugin_read_memory_vaddr(pg, ba, 0x1000)) {
                g_byte_array_free(ba, TRUE);
                continue;
            }
            const guint8 *d = ba->data;
            guint n = ba->len;
            for (guint i = 0; i + 8 + 0x0B <= n; i++) {
                if (memcmp(d + i, body, 8) != 0) continue;
                uint64_t at = pg + i; // адрес тела
                if (i < 0x0B) continue;
                if (memcmp(d + i - 0x0B, pfx, 8) == 0) {
                    if (good++ < 10) {
                        fprintf(g_out, "[SRC-GOOD] %s body@0x%" PRIx64
                                       " (префикс ЕСТЬ)\n", names[r], at);
                        dump_mem("SRC-GOOD-CTX", at - 0x30, 0x60);
                    }
                } else {
                    uint64_t q = 0;
                    memcpy(&q, d + i - 0x0B, 8);
                    if (q == 0) {
                        if (broken++ < 10) {
                            fprintf(g_out, "[SRC-BROKEN] %s body@0x%" PRIx64
                                           " (ПРЕФИКС = НУЛИ!)\n",
                                    names[r], at);
                            dump_mem("SRC-BROKEN-CTX", at - 0x30, 0x60);
                        }
                    }
                }
            }
            g_byte_array_free(ba, TRUE);
            if (broken >= 10) break;
        }
        if (broken >= 10) break;
    }
    fprintf(g_out, "[SCAN-SRC] итог: good=%d broken=%d\n", good, broken);
    fflush(g_out);
}

static void mem_cb(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                   uint64_t vaddr, void *udata)
{
    (void)vcpu_index;
    // v11: LOAD-хиты из staging-диапазона (значение = прочитанное!)
    if (!qemu_plugin_mem_is_store(info)) {
        qemu_plugin_mem_value mv = qemu_plugin_mem_get_value(info);
        uint64_t val = 0; unsigned width = 0;
        switch (mv.type) {
        case QEMU_PLUGIN_MEM_VALUE_U8:  val = mv.data.u8;  width = 1; break;
        case QEMU_PLUGIN_MEM_VALUE_U16: val = mv.data.u16; width = 2; break;
        case QEMU_PLUGIN_MEM_VALUE_U32: val = mv.data.u32; width = 4; break;
        case QEMU_PLUGIN_MEM_VALUE_U64: val = mv.data.u64; width = 8; break;
        default: return;
        }
        // v13: ЛЮБЫЕ загрузки с vpc в области memmove-libc — источник+значение
        // каждого копирования (найдём источник P1-копии без угадывания зон!)
        uint64_t ld_vpc = ((UserData *)udata)->vpc;
        if (ld_vpc >= 0x4000251e00ULL && ld_vpc < 0x4000252000ULL
            && g_prefix_hits > 0) {
            g_loads++;
            if (g_loads < 400)
                fprintf(g_out, "[LD-MM] #%ld vpc=0x%" PRIx64 " vaddr=0x%"
                               PRIx64 " w=%u val=0x%016" PRIx64 "%s\n",
                        g_loads, ld_vpc, vaddr, width, val,
                        (val == 0) ? "  <<== НОЛЬ!" : "");
            fflush(g_out);
            return;
        }
        // v12: загрузки из staging + арена-буфера 0x4010163c60 (источник P1?)
        int ld_zone = (vaddr >= 0x400d563ee0ULL && vaddr < 0x400d563f30ULL)
                      ? 1
                      : (vaddr >= 0x4010163c40ULL && vaddr < 0x4010163d00ULL)
                            ? 2
                            : 0;
        if (ld_zone != 0 && g_prefix_hits > 0) {
            g_loads++;
            if (g_loads < 200)
                fprintf(g_out, "[JW-LD] #%ld vpc=0x%" PRIx64 " vaddr=0x%" PRIx64
                               " w=%u val=0x%016" PRIx64 "%s\n",
                        g_loads, ((UserData *)udata)->vpc, vaddr, width, val,
                        (val == 0) ? "  <<== ЗАГРУЗКА НУЛЯ!" : "");
            else if (g_loads == 200)
                fprintf(g_out, "[JW-LD] ...дальше обрезано (200)\n");
            fflush(g_out);
        }
        return;
    }
    if (!qemu_plugin_mem_is_store(info)) return;   // только STORE дальше

    qemu_plugin_mem_value mv = qemu_plugin_mem_get_value(info);
    uint64_t val = 0;
    unsigned width = 0;
    switch (mv.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:  val = mv.data.u8;  width = 1; break;
    case QEMU_PLUGIN_MEM_VALUE_U16: val = mv.data.u16; width = 2; break;
    case QEMU_PLUGIN_MEM_VALUE_U32: val = mv.data.u32; width = 4; break;
    case QEMU_PLUGIN_MEM_VALUE_U64: val = mv.data.u64; width = 8; break;
    case QEMU_PLUGIN_MEM_VALUE_U128: val = mv.data.u128.low; width = 16; break;
    default: return;
    }

    // 3) v7: маркеры эмиcсии (endbr64/тело шейдера) на ЛЮБОМ VA
    watch_markers(((UserData *)udata)->vpc, vaddr, width, val, mv);

    // 1) диапазон-хиты: полная история записи JIT-страниц
    int r = -1;
    for (int i = 0; i < g_nr; i++) {
        if (vaddr >= g_rlo[i] && vaddr < g_rhi[i]) { r = i; break; }
    }
// 2) value-хиты: где оседает указатель на JIT-функцию.
//    v4: ТОЛЬКО u64/u128 (низ+верх) на ЛЮБОМ VA — включая kernel/physmap!
//    (LO32-ветка v3 вырезана: флуд = собственный [L]-принтер ядра
//    форматирует адрес в hex-буфер — 600 ложных срабатываний.)
    if (g_vstores < 200 && width >= 8) {
        const char *half = "";
        int vh = 0;
        if (val >= g_vlo && val < g_vhi) {
            vh = 1;
        } else if (width == 16 && mv.type == QEMU_PLUGIN_MEM_VALUE_U128 &&
                   mv.data.u128.high >= g_vlo && mv.data.u128.high < g_vhi) {
            vh = 1;
            half = " HI";
        }
        if (vh) {
            g_vstores++;
            fprintf(g_out, "[JW-V%s] #%ld vpc=0x%" PRIx64 " vaddr=0x%" PRIx64
                           " w=%u val=0x%016" PRIx64 "\n",
                    half, g_vstores, ((UserData *)udata)->vpc, vaddr,
                    width, val);
            fflush(g_out);
        }
    }
    if (r < 0) return;

    g_stores++;
    fprintf(g_out, "[JW-R%d] #%ld vpc=0x%" PRIx64 " vaddr=0x%" PRIx64
                   " w=%u val=0x%016" PRIx64,
            r, g_stores, ((UserData *)udata)->vpc, vaddr, width, val);
    if (width == 16)
        fprintf(g_out, "%016" PRIx64, mv.data.u128.high);
    fprintf(g_out, "\n");
    fflush(g_out);
}

static void ring_cb(unsigned int vcpu, void *udata) {
    (void)vcpu;
    uint32_t p = g_ring_pos;
    g_ring[p & (RING_N - 1)] = (uint64_t)udata;
    g_ring_pos = p + 1;
}

static void exc_cb(unsigned int vcpu, void *udata);
static void scan_for_pattern(uint64_t pat);

static void exc_cb(unsigned int vcpu, void *udata) {
    (void)udata;
    if (g_stores == 0) return;          // ранние demand-#PF — мимо
    if (g_exc_n >= 3) return;
    g_exc_n++;
    fprintf(g_out, "=== EXC-ENTRY#%d vcpu=%u stores=%ld vstores=%ld "
                   "ring (newest first) ===\n",
            g_exc_n, vcpu, g_stores, g_vstores);
    uint32_t pos = g_ring_pos;
    for (int i = 0; i < 48; i++) {
        uint64_t va = g_ring[(pos - 1 - i) & (RING_N - 1)];
        if (!va) break;
        fprintf(g_out, "  [%2d] 0x%016" PRIx64 "%s\n", i, va,
                (i == 0) ? " <- last user TB before exc" : "");
    }
    // v4: ДАМП ПАМЯТИ В МОМЕНТ КРАША (через адресное пространство текущего
    // vcpu — CR3=faulting-задача!): csobj ± , обе JIT-страницы.
    dump_mem("MEM-CSOBJ", 0x4010000B00, 0x100);
    dump_mem("MEM-CSOBJ+30", 0x4010000B70, 0x80);
    dump_mem("MEM-JIT-P1", 0x401569D000, 0x40);
    dump_mem("MEM-JIT-P2", 0x401569E000, 0x40);
    fflush(g_out);
    // v5: СКАН STAGING-БУФЕРА (источник memmove): ищем сигнатуру тела
    // шейдера (байты c283 07c1 ea03 31c9 — qword 0xc93103eac107c283,
    // ложится в [JW-R0]#2 на P1+0x10) в brk-куче и аренах. Найдя — дамп
    // окрестностей ±0x40: префикс [endbr64+imul×2] жив или занулён?
    // + анализ пересечения границы страницы.
    scan_for_pattern(0xc93103eac107c283ULL);
}

// v5: скан диапазонов на 8-байтовую сигнатуру (страницами, через
// read_memory_vaddr; read-фейлы = незамапленные страницы — пропускаем).
static void scan_for_pattern(uint64_t pat) {
    struct { uint64_t lo, hi; const char *name; } ranges[] = {
        {0x100000000000ULL, 0x10000220000ULL + 0x100000000000ULL - 0x100000000000ULL, "brk-heap"},
    };
    // фиксированные диапазоны прогона (детерминизм): brk-куча sysharness
    // [0x100000000000, ~+0x220000) и mmap-арены [0x4010000000, +0x100000)
    // и [0x4015568000, +0x4A000)
    uint64_t scan_list[][2] = {
        {0x100000000000ULL, 0x100000220000ULL},
        {0x4010000000ULL,   0x4015700000ULL},
        {0x400D0000000ULL,  0x400D7000000ULL},
    };
    const char *names[] = {"brk", "arenas", "thstacks"};
    (void)ranges;
    int hits = 0;
    for (int r = 0; r < 3 && hits < 12; r++) {
        for (uint64_t pg = scan_list[r][0]; pg < scan_list[r][1] && hits < 12;
             pg += 0x1000) {
            GByteArray *ba = g_byte_array_sized_new(0x1000);
            if (!qemu_plugin_read_memory_vaddr(pg, ba, 0x1000)) {
                g_byte_array_free(ba, TRUE);
                continue;
            }
            const guint8 *d = ba->data;
            guint n = ba->len;
            for (guint i = 0; i + 8 <= n; i += 8) {
                uint64_t q = 0;
                memcpy(&q, d + i, 8);
                if (q == pat) {
                    uint64_t at = pg + i;
                    hits++;
                    fprintf(g_out, "[SCAN] HIT %s @0x%" PRIx64
                                   " (page+0x%x, page-cross=%s)\n",
                            names[r], at, (unsigned)(at & 0xFFF),
                            ((at & 0xFFF) > 0xFF0 || (at & 0xFFF) < 0x10)
                                ? "near-edge" : "mid-page");
                    dump_mem("SCAN-CTX", at - 0x40, 0x80);
                }
            }
            g_byte_array_free(ba, TRUE);
        }
    }
    if (!hits)
        fprintf(g_out, "[SCAN] паттерн не найден (staging уже освобождён?)\n");
    fflush(g_out);
}

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    (void)id;
    uint64_t va = qemu_plugin_tb_vaddr(tb);
    if (va == g_isr14 || va == g_isr13) {          // вход исключения ядра
        qemu_plugin_register_vcpu_tb_exec_cb(tb, exc_cb,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)va);
        return;
    }
    if (va < g_user_lo) return;                    // kernel-ТБ — мимо

    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        UserData *ud = malloc(sizeof(UserData));
        ud->vpc = qemu_plugin_insn_vaddr(insn);
        // v11: LOAD-сторож: регистрируем и чтения (MEM_RW) — value-capture
    // работает и на загрузках → увидим ЧТО вернул mov rax,[rsi] в момент,
    // когда страница содержит префикс (доказательство подмены кадра/TLB).
    qemu_plugin_register_vcpu_mem_cb(insn, mem_cb,
                                          QEMU_PLUGIN_CB_NO_REGS,
                                          QEMU_PLUGIN_MEM_RW, ud);
    }
    qemu_plugin_register_vcpu_tb_exec_cb(tb, ring_cb,
                                         QEMU_PLUGIN_CB_NO_REGS, (void *)va);
}

static void atexit_cb(void *udata) {
    (void)udata;
    if (!g_out) return;
    fprintf(g_out, "\nATEXIT: range-stores=%ld value-stores=%ld exc=%d\n",
            g_stores, g_vstores, g_exc_n);
    fflush(g_out);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv) {
    (void)info; (void)id;
    // QEMU режет "-plugin file=x,LO,HI,LO2,HI2..." по запятым; позиционные
    // куски приходят как argv[0..N-1] (эмпирика run3: индексация с нуля)
    g_nr = 0;
    for (int i = 0; i + 1 < argc && g_nr < MAX_R; i += 2) {
        g_rlo[g_nr] = strtoull(argv[i], NULL, 16);
        g_rhi[g_nr] = strtoull(argv[i + 1], NULL, 16);
        g_nr++;
    }
    if (g_nr == 0) {  // дефолт: JIT-страница из run1/run3
        g_rlo[0] = 0x401569D000;
        g_rhi[0] = 0x40156A0000;
        g_nr = 1;
    }
    const char *vlo = getenv("JITW_VLO");
    const char *vhi = getenv("JITW_VHI");
    g_vlo = vlo ? strtoull(vlo, NULL, 16) : g_rlo[0];
    g_vhi = vhi ? strtoull(vhi, NULL, 16) : g_rhi[0];
    const char *usrlo = getenv("JITW_USER_LO");
    if (usrlo) g_user_lo = strtoull(usrlo, NULL, 16);
    const char *isr13 = getenv("JITW_ISR13");
    const char *isr14 = getenv("JITW_ISR14");
    if (isr13) g_isr13 = strtoull(isr13, NULL, 16);
    if (isr14) g_isr14 = strtoull(isr14, NULL, 16);
    const char *logpath = getenv("JITW_LOG");
    g_out = fopen(logpath ? logpath : "/tmp/jit-writer.log", "w");
    if (!g_out) g_out = stderr;
    fprintf(g_out, "[jit-writer v2] ranges:");
    for (int i = 0; i < g_nr; i++)
        fprintf(g_out, " [0x%" PRIx64 ",0x%" PRIx64 ")", g_rlo[i], g_rhi[i]);
    fprintf(g_out, " value=[0x%" PRIx64 ",0x%" PRIx64
                   ") user_lo=0x%" PRIx64 "\n",
            g_vlo, g_vhi, g_user_lo);
    fflush(g_out);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, atexit_cb, NULL);
    return 0;
}
