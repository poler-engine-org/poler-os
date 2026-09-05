// libvklayer_poler_drm.c — POLER-OS Vulkan implicit layer (CDD #12 p3)
// ============================================================================
// ЗАЧЕМ: gamescope 3.16 DRM-бэкенд требует у физического устройства
// расширение VK_EXT_physical_device_drm (vulkan_has_drm_props →
// CDRMBackend::ValidPhysicalDevice) + DrmProperties (renderMajor/Minor →
// drmGetDeviceFromDevId → open("/dev/dri/renderD128")). CachyOS lavapipe
// (llvmpipe) расширение НЕ экспортирует (проверено vkprobe: 184 ext, DRM
// нет) → gamescope: "not a valid physical device" → "Failed to initialize
// Vulkan" → exit(1).
//
// ЧТО ДЕЛАЕТ СЛОЙ (классический implicit-layer протокол Khronos):
//   vkCreateInstance(ci, al, out, nextGIPA) — сцепка с загрузчиком;
//   vkGetInstanceProcAddr — возвращает обёртки:
//     * vkEnumerateDeviceExtensionProperties: + VK_EXT_physical_device_drm
//       v1 (если запрошен список без layerName);
//     * vkGetPhysicalDeviceProperties2[KHR]: заполняет
//       VkPhysicalDeviceDrmPropertiesEXT в pNext-цепочке:
//       hasPrimary=1 (226:0 = /dev/dri/card0), hasRender=1 (226:128 =
//       /dev/dri/renderD128) — виртуальная DRM-топология POLER-OS
//       (ядро: encodeDev(226,128), /sys/dev/char/226:{0,128}).
// ============================================================================
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define DBG(s) write(2, "[POLER-LAYER] " s "\n", sizeof("[POLER-LAYER] " s "\n") - 1)

// ─── минимальные Vulkan-типы (без заголовков) ───────────────────────────────
typedef uint32_t VkResult;
typedef uint32_t VkBool32;
typedef uint64_t VkInstance;   // opaque handle
typedef uint64_t VkPhysicalDevice;
typedef void* (*PFN_vkVoidFunction_ptr)(void);

typedef struct VkBaseOut {
    uint32_t sType;
    void* pNext;
} VkBaseOut;

typedef struct {
    char extensionName[256];
    uint32_t specVersion;
} VkExtensionProperties;

typedef struct {
    uint32_t sType;          // @0
    void* pNext;             // @8
    uint32_t hasPrimary;     // @16  (VkBool32)
    uint32_t hasRender;      // @20  (VkBool32 — СРАЗУ за hasPrimary!)
    int64_t primaryMajor;    // @24
    int64_t primaryMinor;    // @32
    int64_t renderMajor;     // @40
    int64_t renderMinor;     // @48
} VkPhysicalDeviceDrmPropertiesEXT; // 56Б (vulkan_core.h — точная раскладка)

typedef struct {
    uint32_t sType;          // VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1
    void* pNext;
    uint32_t flags;
    void* pApplicationInfo;
    uint32_t enabledLayerCount;
    const char* const* ppEnabledLayerNames;
    uint32_t enabledExtensionCount;
    const char* const* ppEnabledExtensionNames;
} VkInstanceCreateInfo;

// VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRM_PROPERTIES_EXT (vulkan_core.h)
#define STYPE_DRM_PROPS 1000353000
// VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFO (vulkan_core.h, internal)
#define STYPE_LOADER_INSTANCE_CREATE_INFO 47
#define VK_LAYER_LINK_INFO 0
#define VK_SUCCESS 0
#define VK_INCOMPLETE 5
#define POLER_DRM_MAJOR 226
#define POLER_RENDER_MINOR 128
#define POLER_PRIMARY_MINOR 0

typedef VkResult (*PFN_vkCreateInstance_t)(const VkInstanceCreateInfo*,
                                           const void*, VkInstance*);
typedef void* (*PFN_vkGetInstanceProcAddr_t)(VkInstance, const char*);
typedef VkResult (*PFN_vkEnumDevExt_t)(VkPhysicalDevice, const char*,
                                        uint32_t*, VkExtensionProperties*);
typedef void (*PFN_vkGetPhysDevProps2_t)(VkPhysicalDevice, void*);

// vk_layer.h: VkLayerInstanceLink { pNext, pfnNextGetInstanceProcAddr, … }
typedef struct VkLayerInstanceLink {
    struct VkLayerInstanceLink* pNext;
    void* pfnNextGetInstanceProcAddr;
    void* pfnNextGetPhysicalDeviceProcAddr;
} VkLayerInstanceLink;

// vk_layer.h: VkLayerInstanceCreateInfo (sType=47, function=LINK_INFO)
typedef struct {
    uint32_t sType;
    void* pNext;
    uint32_t function;
    union {
        VkLayerInstanceLink* pLayerInfo;
        void* pfnSetInstanceLoaderData;
    } u;
} VkLayerInstanceCreateInfo;

static PFN_vkGetInstanceProcAddr_t g_next_gipa;
static VkInstance g_instance;

static VkResult vkEnumerateInstanceExtensionProperties_shim(
    const char* pLayerName, uint32_t* pCount, void* pProperties);
__attribute__((visibility("default")))
void* vkEnumerateInstanceLayerProperties(uint32_t* pCount, void* pProps);

// ─── обёртки ────────────────────────────────────────────────────────────────

static void* getdown(const char* name) {
    if (!g_next_gipa) return 0;
    return g_next_gipa(g_instance, name);
}

static VkResult wrap_vkEnumerateDeviceExtensionProperties(
    VkPhysicalDevice pd, const char* pLayerName, uint32_t* pPropertyCount,
    VkExtensionProperties* pProperties)
{
    DBG("wrap_ede");
    PFN_vkEnumDevExt_t next =
        (PFN_vkEnumDevExt_t)getdown("vkEnumerateDeviceExtensionProperties");
    if (!next) { DBG("ede:NONEXT"); return -3; }

    if (pLayerName) return next(pd, pLayerName, pPropertyCount, pProperties);

    if (!pProperties) {
        // запрос СЧЁТА: честный + 1 (наше расширение)
        VkResult r = next(pd, 0, pPropertyCount, 0);
        if (r == VK_SUCCESS) (*pPropertyCount)++;
        return r;
    }
    // запрос МАССИВА: после ICD-записей добавляем свою
    uint32_t n = *pPropertyCount;
    VkResult r = next(pd, 0, &n, pProperties);
    if (r == VK_SUCCESS) {
        if (n < *pPropertyCount) {
            memset(&pProperties[n], 0, sizeof(VkExtensionProperties));
            memcpy(pProperties[n].extensionName,
                   "VK_EXT_physical_device_drm", sizeof("VK_EXT_physical_device_drm"));
            pProperties[n].specVersion = 1;
            *pPropertyCount = n + 1;
        } else {
            return VK_INCOMPLETE; // приложение выделило без +1 — перезапрос
        }
    }
    return r;
}

static void fill_drm_props(VkPhysicalDeviceDrmPropertiesEXT* d) {
    d->hasPrimary = 1;
    d->primaryMajor = POLER_DRM_MAJOR;
    d->primaryMinor = POLER_PRIMARY_MINOR;
    d->hasRender = 1;
    d->renderMajor = POLER_DRM_MAJOR;
    d->renderMinor = POLER_RENDER_MINOR;
}

static void wrap_vkGetPhysicalDeviceProperties2(VkPhysicalDevice pd, void* pProps) {
    DBG("wrap_gpdp2");
    PFN_vkGetPhysDevProps2_t next =
        (PFN_vkGetPhysDevProps2_t)getdown("vkGetPhysicalDeviceProperties2");
    if (!next) { DBG("gpdp2:NONEXT"); return; }
    next(pd, pProps);
    // pNext-цепочка: VkPhysicalDeviceProperties2 { sType, pNext, props… }
    VkBaseOut* base = (VkBaseOut*)pProps;
    for (void* p = base->pNext; p; p = ((VkBaseOut*)p)->pNext) {
        if (((VkBaseOut*)p)->sType == STYPE_DRM_PROPS)
            fill_drm_props((VkPhysicalDeviceDrmPropertiesEXT*)p);
    }
    DBG("gpdp2:FILLED");
}

// ─── протокол слоя (классический implicit-layer интерфейс) ─────────────────

__attribute__((visibility("default")))
VkResult vkCreateInstance(const VkInstanceCreateInfo* pCreateInfo,
                          const void* pAllocator, VkInstance* pInstance,
                          PFN_vkGetInstanceProcAddr_t pfnGPA)
{
    (void)pAllocator;
    // ЛИНК-ЦЕПЬ (vk_layer.h): loader вставляет VkLayerInstanceCreateInfo
    // (sType=47, function=VK_LAYER_LINK_INFO) в pCreateInfo->pNext; линк
    // несёт pfnNextGetInstanceProcAddr — GIPA СЛЕДУЮЩЕГО компонента цепи
    // (для последнего слоя — терминатор загрузчика → ICD). 4-й арг (loader-
    // трамплин) не пригоден для запроса vkCreateInstance (эмпирика: NULL-
    // deref/рекурсия) — берём GIPA строго из линка.
    VkLayerInstanceCreateInfo* chain = (VkLayerInstanceCreateInfo*)pCreateInfo->pNext;
    while (chain && !(chain->sType == STYPE_LOADER_INSTANCE_CREATE_INFO &&
                      chain->function == VK_LAYER_LINK_INFO))
        chain = (VkLayerInstanceCreateInfo*)chain->pNext;
    if (!chain || !chain->u.pLayerInfo) {
        g_next_gipa = pfnGPA; // фолбэк: старый интерфейс без линка
    } else {
        g_next_gipa = (PFN_vkGetInstanceProcAddr_t)chain->u.pLayerInfo->pfnNextGetInstanceProcAddr;
    }
    if (!g_next_gipa) { DBG("create:NOLINK"); return -3; }
    PFN_vkCreateInstance_t next =
        (PFN_vkCreateInstance_t)g_next_gipa(0, "vkCreateInstance");
    if (!next) { DBG("create:NOCREATE"); return -3; }
    VkResult r = next(pCreateInfo, pAllocator, pInstance);
    if (r == VK_SUCCESS) g_instance = *pInstance;
    DBG("create:OK");
    return r;
}

__attribute__((visibility("default")))
void* vkGetInstanceProcAddr(VkInstance instance, const char* pName)
{
    // глобальные команды уровня слоя (loader зовёт с instance=NULL ДО
    // создания инстанса — эмпирика: без этого «Failed to find
    // 'vkCreateInstance'» → loader_create_instance_chain отказ)
    if (strcmp(pName, "vkCreateInstance") == 0)
        return (void*)vkCreateInstance;
    if (strcmp(pName, "vkGetInstanceProcAddr") == 0)
        return (void*)vkGetInstanceProcAddr;
    if (strcmp(pName, "vkEnumerateInstanceLayerProperties") == 0)
        return (void*)vkEnumerateInstanceLayerProperties;
    if (strcmp(pName, "vkEnumerateInstanceExtensionProperties") == 0)
        return (void*)vkEnumerateInstanceExtensionProperties_shim;
    if (strcmp(pName, "vkEnumerateDeviceExtensionProperties") == 0)
        return (void*)wrap_vkEnumerateDeviceExtensionProperties;
    if (strcmp(pName, "vkGetPhysicalDeviceProperties2") == 0 ||
        strcmp(pName, "vkGetPhysicalDeviceProperties2KHR") == 0)
        return (void*)wrap_vkGetPhysicalDeviceProperties2;
    return g_next_gipa ? g_next_gipa(instance, pName) : 0;
}

/// глобальный vkEnumerateInstanceExtensionProperties (слой своих
/// instance-расширений не добавляет — чистый проброс через next-GIPA)
static VkResult vkEnumerateInstanceExtensionProperties_shim(
    const char* pLayerName, uint32_t* pCount, void* pProperties)
{
    if (!g_next_gipa) return -3;
    VkResult (*next)(const char*, uint32_t*, void*) =
        (VkResult (*)(const char*, uint32_t*, void*))g_next_gipa(0,
            "vkEnumerateInstanceExtensionProperties");
    if (!next) return -3;
    return next(pLayerName, pCount, pProperties);
}

__attribute__((visibility("default")))
void* vkEnumerateInstanceLayerProperties(uint32_t* pCount, void* pProps)
{
    (void)pProps;
    if (pCount) *pCount = 0;
    return (void*)0;
}

// vkGetDeviceProcAddr: НЕ ЭКСПОРТИРУЕМ (v0.20.0-фикс host-эмпирики):
// экспорт втягивает слой в DEVICE-цепь загрузчика, а мы не перехватываем
// девайс-функции — возвращать было нечего, кроме instance-уровневых
// указателей (→ диспетч-каша → SEGV в vkCreateDevice). Без экспорта
// loader завершает слой на instance-уровне — протокол корректен.
