// vkprobe2.c — pipeline stress: llvmpipe device + GRAPHICS PIPELINE + SPIR-V
// compile (gamescope-style). CDD #12 p4: ядро падало после vkCreateDevice в
// tgsi_to_nir (0xAAAA-poison) + stack smashing — проверяем те же либы на хосте.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define VK_NO_PROTOTYPES 1
#define VK_USE_PLATFORM_XLIB_KHR 0
#include "vulkan_core.h"
#include <dlfcn.h>

#include <execinfo.h>
#include <unistd.h>
#include <signal.h>
static void segv_handler(int sig) {
    void* bt[32];
    int n = backtrace(bt, 32);
    fprintf(stderr, "\n=== SIGSEGV backtrace (%d frames) ===\n", n);
    backtrace_symbols_fd(bt, n, 2);
    _exit(139);
}


int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGSEGV, segv_handler);
    const char* loader = "/tmp/my-project/poler-os/cachyos-root/root/usr/lib/libvulkan.so.1";
    if (argc > 1) loader = argv[1];
    void* h = dlopen(loader, RTLD_NOW);
    if (!h) { printf("dlopen: %s\n", dlerror()); return 1; }

   PFN_vkCreateInstance vkCreateInstance = dlsym(h, "vkCreateInstance");
    if (!vkCreateInstance) { printf("no vkCreateInstance\n"); return 1; }

    VkApplicationInfo app = {0};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.apiVersion = VK_API_VERSION_1_0;
    VkInstanceCreateInfo ci = {0};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;
    VkInstance inst = NULL;
    int r = vkCreateInstance(&ci, NULL, &inst);
    printf("vkCreateInstance = %d\n", r);
    if (r) return 1;

    u_int32_t n = 0;
    PFN_vkEnumeratePhysicalDevices vkEnumeratePhysicalDevices = (void*)dlsym(h, "vkEnumeratePhysicalDevices");
    vkEnumeratePhysicalDevices(inst, &n, NULL);
    VkPhysicalDevice pds[4] = {0};
    vkEnumeratePhysicalDevices(inst, &n, pds);
    printf("physical devices = %u\n", n);
    VkPhysicalDevice pd = pds[0];

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qci = {0};
    qci.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qci.queueFamilyIndex = 0; qci.queueCount = 1; qci.pQueuePriorities = &prio;
    VkDeviceCreateInfo dci = {0};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1; dci.pQueueCreateInfos = &qci;
    VkDevice dev = NULL;
    PFN_vkCreateDevice vkCreateDevice = (void*)dlsym(h, "vkCreateDevice");
    r = vkCreateDevice(pd, &dci, 0, &dev);
    printf("vkCreateDevice = %d\n", r);
    if (r) return 1;

    void* (*gipa)(void*, const char*) = dlsym(h, "vkGetInstanceProcAddr");
    PFN_vkCreateRenderPass vkCreateRenderPass = (PFN_vkCreateRenderPass)(void*)gipa(inst, "vkCreateRenderPass");
    PFN_vkCreateShaderModule vkCreateShaderModule = (PFN_vkCreateShaderModule)(void*)gipa(inst, "vkCreateShaderModule");
    PFN_vkCreatePipelineLayout vkCreatePipelineLayout = (PFN_vkCreatePipelineLayout)(void*)gipa(inst, "vkCreatePipelineLayout");
    PFN_vkCreateGraphicsPipelines vkCreateGraphicsPipelines = (PFN_vkCreateGraphicsPipelines)(void*)gipa(inst, "vkCreateGraphicsPipelines");

    // render pass: B8G8R8A8, 1 subpass
    VkAttachmentDescription att = {0};
    att.format = VK_FORMAT_B8G8R8A8_UNORM;
    att.samples = VK_SAMPLE_COUNT_1_BIT;
    att.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    att.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    att.initialLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    att.finalLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    VkAttachmentReference aref = {0};
    aref.attachment = 0;
    aref.layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    VkSubpassDescription sp = {0};
    sp.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    sp.colorAttachmentCount = 1;
    sp.pColorAttachments = &aref;
    VkRenderPassCreateInfo rpci = {0};
    rpci.sType = VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO;
    rpci.attachmentCount = 1; rpci.pAttachments = &att;
    rpci.subpassCount = 1; rpci.pSubpasses = &sp;
    VkRenderPass rp = NULL;
    r = vkCreateRenderPass(dev, &rpci, 0, &rp);
    printf("vkCreateRenderPass = %d\n", r);
    if (r) return 1;

    // gamescope's OWN embedded shaders (реальные glslang-модули из бинарника)
    #include "gs_shaders.h"

    static const uint32_t vs[] = {
        0x07230203,0x00010000,0x0008000a,0x00000000,0x00000011,0x00000001,0x00060001,0x00000005,
        0x0000002d,0x0000000e,0x00030003,0x00000002,0x000a0004,0x675f6f6c,0x74736f6d,0x00000000,
        0x00060005,0x00000006,0x6f6c6f6d,0x00000000,0x00000000,0x00030005,0x00000004,0x6e69616d,
        0x00030005,0x00000008,0x74736e69,0x00040047,0x00000004,0x0000001b,0x00000000,0x00050047,
        0x00000006,0x00000004,0x00000004,0x6e695600,0x00030047,0x00000008,0x00000003,0x00020013,
        0x00000002,0x00030021,0x00000003,0x00000002,0x00030016,0x00000006,0x00000020,0x00040017,
        0x00000007,0x00000006,0x00000004,0x00040015,0x00000008,0x00000002,0x00000002,0x0004002b,
        0x00000008,0x00000000,0x00000000,0x00040020,0x00000009,0x00000007,0x00000002,0x0004003b,
        0x00000009,0x00000007,0x00000000,0x00050036,0x00000002,0x00000004,0x00000000,0x00000003,
        0x000200f8,0x00000005,0x00050041,0x00000000,0x00000001,0x00000007,0x00000000,0x000300f7,
        0x00000000,0x00000000,0x0004003d,0x00000006,0x00000006,0x00000007,0x000500f4,0x00000005,
        0x00000006,0x00000006,0x00000000,0x000100fd,0x00010038,
    };
    static const uint32_t fs[] = {
        0x07230203,0x00010000,0x0008000a,0x00000000,0x00000011,0x00000002,0x00060001,0x00000004,
        0x0000002d,0x0000000e,0x00030003,0x00000002,0x000a0004,0x675f6f6c,0x74736f6d,0x00000000,
        0x00030005,0x00000004,0x6f6c6f6d,0x00000000,0x00030005,0x00000008,0x74736e69,0x00040047,
        0x00000008,0x00000003,0x00040047,0x00000004,0x0000001e,0x00000000,0x00020013,0x00000002,
        0x00030021,0x00000003,0x00000002,0x00030016,0x00000004,0x00000020,0x0004002b,0x00000004,
        0x00000000,0x00000003,0x00040017,0x00000009,0x00000004,0x00000002,0x00040020,0x0000000a,
        0x00000009,0x00000003,0x0004003b,0x0000000a,0x00000009,0x00000000,0x00050036,0x00000003,
        0x00000008,0x00000000,0x00000005,0x000600f7,0x00000005,0x00000000,0x00000000,0x00000000,
        0x0000000a,0x00050041,0x00000000,0x00000001,0x00000009,0x00000000,0x000300f7,0x00000002,
        0x00000000,0x0003003e,0x00000009,0x00000009,0x000100fd,0x00010038,
    };
    VkShaderModuleCreateInfo vsci = {0};
    vsci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    vsci.codeSize = sizeof(GS_VS); vsci.pCode = GS_VS;
    VkShaderModule vsmod = NULL;
    r = vkCreateShaderModule(dev, &vsci, 0, &vsmod);
    printf("vkCreateShaderModule(vs) = %d\n", r);
    VkShaderModuleCreateInfo fsci = {0};
    fsci.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    fsci.codeSize = sizeof(GS_FS); fsci.pCode = GS_FS;
    VkShaderModule fsmod = NULL;
    r = vkCreateShaderModule(dev, &fsci, 0, &fsmod);
    printf("vkCreateShaderModule(fs) = %d\n", r);
    if (r) return 1;

    VkPipelineLayoutCreateInfo plci = {0};
    plci.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    VkPipelineLayout layout = NULL;
    r = vkCreatePipelineLayout(dev, &plci, 0, &layout);
    printf("vkCreatePipelineLayout = %d\n", r);
    if (r) return 1;

    VkPipelineShaderStageCreateInfo stages[2] = {0};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = vsmod;
    stages[0].pName = "main";
    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = fsmod;
    stages[1].pName = "main";

    VkPipelineVertexInputStateCreateInfo vi = {0};
    vi.sType = VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO;
    VkPipelineInputAssemblyStateCreateInfo ia = {0};
    ia.sType = VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO;
    ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    VkPipelineViewportStateCreateInfo vp = {0};
    vp.sType = VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO;
    vp.viewportCount = 1; vp.scissorCount = 1;
    VkPipelineRasterizationStateCreateInfo rs = {0};
    rs.sType = VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO;
    rs.polygonMode = VK_POLYGON_MODE_FILL;
    rs.lineWidth = 1.0f;
    rs.cullMode = VK_CULL_MODE_NONE;
    VkPipelineMultisampleStateCreateInfo ms = {0};
    ms.sType = VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO;
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
    VkPipelineColorBlendAttachmentState cba = {0};
    cba.colorWriteMask = 0xF;
    VkPipelineColorBlendStateCreateInfo cb = {0};
    cb.sType = VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO;
    cb.attachmentCount = 1;
    cb.pAttachments = &cba;

    VkGraphicsPipelineCreateInfo gpci = {0};
    gpci.sType = VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO;
    gpci.stageCount = 2;
    gpci.pStages = stages;
    gpci.pVertexInputState = &vi;
    gpci.pInputAssemblyState = &ia;
    gpci.pViewportState = &vp;
    gpci.pRasterizationState = &rs;
    gpci.pMultisampleState = &ms;
    gpci.pColorBlendState = &cb;
    gpci.layout = layout;
    gpci.renderPass = rp;
    gpci.subpass = 0;
    VkPipeline pipe = NULL;
    r = vkCreateGraphicsPipelines(dev, NULL, 1, &gpci, 0, &pipe);
    printf("vkCreateGraphicsPipelines = %d (%s)\n", r, r == 0 ? "PIPELINE OK — lvp компилировал SPIR-V" : "FAIL");
    return r != 0;
}
