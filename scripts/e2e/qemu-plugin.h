/* ============================================================================
 * qemu-plugin.h — минимальный API-v4 заголовок (QEMU 10.x, CDD №12 p7).
 * Восстановлен по ABI скомпилированного who-aaaa.so (версия=4, MEM_RW=3,
 * CB_NO_REGS=0) — полный дистрибутивный заголовок в deb-пакетах Debian 13
 * отсутствует. Достаточен для who-aaaa.c / who-ptr.c.
 * ==========================================================================*/
#ifndef QEMU_PLUGIN_API_H
#define QEMU_PLUGIN_API_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* glib-типы (резолвятся из процесса QEMU при dlopen плагина) */
typedef uint8_t guint8;
typedef unsigned int guint;
typedef struct GByteArray {
    guint8 *data;
    guint len;
} GByteArray;

/* glib-хелперы (символы резолвятся из процесса QEMU) */
typedef int gboolean;
#define TRUE 1
#define FALSE 0
extern GByteArray *g_byte_array_sized_new(guint reserved_size);
extern GByteArray *g_byte_array_append(GByteArray *array,
                                        const guint8 *data, guint len);
extern GByteArray *g_byte_array_free(GByteArray *array, gboolean free_segment);

#define QEMU_PLUGIN_VERSION 4
#define QEMU_PLUGIN_EXPORT extern

typedef uint64_t qemu_plugin_id_t;
typedef int qemu_plugin_meminfo_t;

typedef struct qemu_plugin_insn qemu_plugin_insn;
typedef struct qemu_plugin_tb qemu_plugin_tb;
typedef struct qemu_info_t qemu_info_t;

enum qemu_plugin_cb_flags {
    QEMU_PLUGIN_CB_NO_REGS,   /* 0 */
    QEMU_PLUGIN_CB_R_REGS,
    QEMU_PLUGIN_CB_W_REGS,
    QEMU_PLUGIN_CB_RW_REGS,
};

enum qemu_plugin_mem_rw {
    QEMU_PLUGIN_MEM_R = 1,
    QEMU_PLUGIN_MEM_W = 2,
    QEMU_PLUGIN_MEM_RW = 3,
};

typedef enum qemu_plugin_mem_value_type {
    QEMU_PLUGIN_MEM_VALUE_INVALID, /* 0 */
    QEMU_PLUGIN_MEM_VALUE_U8,
    QEMU_PLUGIN_MEM_VALUE_U16,
    QEMU_PLUGIN_MEM_VALUE_U32,
    QEMU_PLUGIN_MEM_VALUE_U64,
    QEMU_PLUGIN_MEM_VALUE_U128,
} qemu_plugin_mem_value_type;

typedef struct qemu_plugin_mem_value {
    qemu_plugin_mem_value_type type;
    union {
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
        struct {
            uint64_t low;
            uint64_t high;
        } u128;
    } data;
} qemu_plugin_mem_value;

void qemu_plugin_register_vcpu_tb_trans_cb(
    qemu_plugin_id_t id,
    void (*cb)(qemu_plugin_id_t id, struct qemu_plugin_tb *tb));

void qemu_plugin_register_vcpu_mem_cb(
    struct qemu_plugin_insn *insn,
    void (*cb)(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
               uint64_t vaddr, void *udata),
    enum qemu_plugin_cb_flags flags,
    enum qemu_plugin_mem_rw rw,
    void *udata);

size_t qemu_plugin_tb_n_insns(struct qemu_plugin_tb *tb);
struct qemu_plugin_insn *qemu_plugin_tb_get_insn(struct qemu_plugin_tb *tb,
                                                  size_t idx);
uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn);

qemu_plugin_mem_value qemu_plugin_mem_get_value(qemu_plugin_meminfo_t info);
bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info);
bool qemu_plugin_read_memory_vaddr(uint64_t vaddr, GByteArray *buf, size_t len);

#endif /* QEMU_PLUGIN_API_H */
