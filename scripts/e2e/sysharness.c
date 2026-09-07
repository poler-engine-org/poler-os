// sysharness.c — CDD №12 p11: SYSCALL-DIFF эталонный Vulkan-прогон.
// ============================================================================
// Минимальный Lavapipe-конвейер до LLVM-JIT (компиляция compute-шейдера):
//   vkCreateInstance → EnumeratePhysicalDevices → vkCreateDevice →
//   vkCreateShaderModule → vkCreatePipelineLayout → vkCreateComputePipelines →
//   CommandBuffer+Dispatch → QueueSubmit → QueueWaitIdle → teardown.
// Маркеры HARNESS-* на stdout (fd 1) — фазовые точки для diff-движка:
// один и тот же бинарник идёт (а) под host-Linux strace (эталон),
// (б) в POLER-OS elfload под ltrace ([L]-фронт) — диф возвратов = корень.
// Специфика: никаких DRM/Wayland — фаза ДО DRM-init (где живёт краш
// libLLVM DenseMap-tombstone), чистая LLVM-ветка.
// ============================================================================
#include <vulkan/vulkan.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Минимальный валидный SPIR-V: GLCompute "void main(){}" LocalSize(1,1,1).
// Инструкция = (wordcount<<16 | opcode), операнды после. bound=5 (id 1..4):
//   %1=void, %2=func-type, %3=main, %4=label-entry.
static const uint32_t spirv[] = {
    0x07230203, 0x00010300, 0x00000000, 5, 0x00000000,
    0x00020011, 1,                      // OpCapability Shader
    0x0003000E, 0, 1,                   // OpMemoryModel Logical GLSL450
    0x0005000F, 5, 3, 0x6e69616d, 0,    // OpEntryPoint GLCompute %3 "main"
    0x00060010, 3, 17, 1, 1, 1,         // OpExecutionMode %3 LocalSize 1 1 1
    0x00020013, 1,                      // OpTypeVoid %1
    0x00030021, 2, 1,                   // OpTypeFunction %2 → %1 ()
    0x00050036, 1, 3, 0, 2,             // %3 = OpFunction: type %1, result %3, None, %2
    0x000200F8, 4,                      // %4 = OpLabel
    0x000100FD,                         // OpReturn
    0x00010038,                         // OpFunctionEnd
};

#define MARK(tag) do { printf("HARNESS-%s\n", tag); fflush(stdout); } while (0)
#define VCHECK(call, tag) do { \
    VkResult _r = (call); \
    if (_r != VK_SUCCESS) { \
        printf("HARNESS-FAIL-%s vkresult=%d\n", tag, (int)_r); \
        fflush(stdout); \
        return 1; \
    } \
    MARK(tag); \
} while (0)

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    MARK("INIT");

    VkApplicationInfo app = {0};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "sysharness";
    app.applicationVersion = 1;
    app.pEngineName = "sysharness";
    app.engineVersion = 1;
    app.apiVersion = VK_API_VERSION_1_3;

    VkInstanceCreateInfo ci = {0};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;

    VkInstance inst;
    VCHECK(vkCreateInstance(&ci, NULL, &inst), "INSTANCE");

    uint32_t npd = 0;
    VCHECK(vkEnumeratePhysicalDevices(inst, &npd, NULL), "PDEV-COUNT");
    printf("HARNESS-PDEVICES %u\n", npd);
    if (npd == 0) {
        printf("HARNESS-FAIL-NO-PDEV\n");
        return 1;
    }
    VkPhysicalDevice pdev;
    VCHECK(vkEnumeratePhysicalDevices(inst, &npd, &pdev), "PDEV-ENUM");

    uint32_t nq = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(pdev, &nq, NULL);
    if (nq > 16) nq = 16;
    VkQueueFamilyProperties qfp[16];
    vkGetPhysicalDeviceQueueFamilyProperties(pdev, &nq, qfp);
    uint32_t qf = 0xFFFFFFFF;
    for (uint32_t i = 0; i < nq; i++) {
        if (qfp[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { qf = i; break; }
    }
    printf("HARNESS-QFAMILY %u of %u\n", qf, nq);
    if (qf == 0xFFFFFFFF) {
        printf("HARNESS-FAIL-NO-COMPUTE-Q\n");
        return 1;
    }

    float prio = 1.0f;
    VkDeviceQueueCreateInfo dq = {0};
    dq.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    dq.queueFamilyIndex = qf;
    dq.queueCount = 1;
    dq.pQueuePriorities = &prio;

    VkDeviceCreateInfo dc = {0};
    dc.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dc.queueCreateInfoCount = 1;
    dc.pQueueCreateInfos = &dq;

    VkDevice dev;
    VCHECK(vkCreateDevice(pdev, &dc, NULL, &dev), "DEVICE");

    VkQueue queue;
    vkGetDeviceQueue(dev, qf, 0, &queue);

    VkShaderModuleCreateInfo sm = {0};
    sm.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm.codeSize = sizeof(spirv);
    sm.pCode = spirv;
    VkShaderModule mod;
    VCHECK(vkCreateShaderModule(dev, &sm, NULL, &mod), "SHADER-MODULE");

    VkPipelineLayoutCreateInfo pl = {0};
    pl.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    VkPipelineLayout layout;
    VCHECK(vkCreatePipelineLayout(dev, &pl, NULL, &layout), "PIPELINE-LAYOUT");

    VkComputePipelineCreateInfo cp = {0};
    cp.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    cp.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    cp.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    cp.stage.module = mod;
    cp.stage.pName = "main";
    cp.layout = layout;

    VkPipeline pipe;
    // llvmpipe компилирует compute-шейдер ВОТ ЗДЕСЬ (gallivm/LLVM-JIT) —
    // фаза, на которой POLER-прогон gamescope ловит DenseMap-tombstone #GP.
    VCHECK(vkCreateComputePipelines(dev, NULL, 1, &cp, NULL, &pipe), "PIPELINE");

    VkCommandPoolCreateInfo pool_ci = {0};
    pool_ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    pool_ci.queueFamilyIndex = qf;
    VkCommandPool pool;
    VCHECK(vkCreateCommandPool(dev, &pool_ci, NULL, &pool), "CMD-POOL");

    VkCommandBufferAllocateInfo cbi = {0};
    cbi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cbi.commandPool = pool;
    cbi.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cbi.commandBufferCount = 1;
    VkCommandBuffer cmb;
    VCHECK(vkAllocateCommandBuffers(dev, &cbi, &cmb), "CMD-BUF");

    VkCommandBufferBeginInfo beg = {0};
    beg.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    VCHECK(vkBeginCommandBuffer(cmb, &beg), "CMD-BEGIN");
    vkCmdBindPipeline(cmb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    vkCmdDispatch(cmb, 1, 1, 1);
    VCHECK(vkEndCommandBuffer(cmb), "CMD-END");

    VkSubmitInfo si = {0};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmb;
    VCHECK(vkQueueSubmit(queue, 1, &si, VK_NULL_HANDLE), "SUBMIT");
    VCHECK(vkQueueWaitIdle(queue), "WAIT-IDLE");
    MARK("DISPATCH");

    vkDestroyCommandPool(dev, pool, NULL);
    vkDestroyPipeline(dev, pipe, NULL);
    vkDestroyPipelineLayout(dev, layout, NULL);
    vkDestroyShaderModule(dev, mod, NULL);
    vkDestroyDevice(dev, NULL);
    vkDestroyInstance(inst, NULL);
    MARK("DONE");
    return 0;
}
