// ============================================================================
// shim-mprotect.c — CDD №12 p11: HOST-ДИФФЕРЕНЦИАЛ JIT-СТРАНИЦЫ.
// ============================================================================
// LD_PRELOAD-шима: перехват mprotect; при (prot & PROT_EXEC) дампим первые
// 64 байта страницы ДО смены прав (в VM у первых 11 байт — нули, дальше код
// шейдера; вопрос: эмитит ли LLVM их же на host, или host видит код с +0).
// Также логируем mmap-возвраты (адреса JIT-страниц host-эталона).
// ============================================================================
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static int (*real_mprotect)(void *, size_t, int) = NULL;
static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
static int g_mp = 0, g_mm = 0;

int mprotect(void *addr, size_t len, int prot) {
    if (!real_mprotect) real_mprotect = dlsym(RTLD_NEXT, "mprotect");
    if (prot & PROT_EXEC) {
        g_mp++;
        unsigned char *p = (unsigned char *)addr;
        char buf[160];
        int o = 0;
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++)
            o += snprintf(buf + o, sizeof(buf) - o, "%02x", p[i]);
        buf[o] = 0;
        fprintf(stderr, "[SHIM-MP] #%d addr=%p len=%zu prot=%d pre64: %s\n",
                g_mp, addr, len, prot, buf);
        fflush(stderr);
        int rc = real_mprotect(addr, len, prot);
        fprintf(stderr, "[SHIM-MP] #%d rc=%d post64: %s\n", g_mp, rc,
                buf); // pre-кадр остаётся в buf; пост-чтение ниже
        fflush(stderr);
        return rc;
    }
    return real_mprotect(addr, len, prot);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    if (!real_mmap) real_mmap = dlsym(RTLD_NEXT, "mmap");
    void *rc = real_mmap(addr, len, prot, flags, fd, off);
    if (rc != MAP_FAILED && len == 4096) {
        g_mm++;
        fprintf(stderr, "[SHIM-MM] #%d hint=%p len=%zu prot=%d flags=%x fd=%d "
                        "off=%lld => %p\n",
                g_mm, addr, len, prot, flags, fd, (long long)off, rc);
        fflush(stderr);
    }
    return rc;
}
