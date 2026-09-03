// ============================================================================
// POLER-OS drm_kms.zig — DRM/KMS + fbdev ядро (v0.19.0, CDD №10, шаг 1)
// ============================================================================
//
// МОДЕЛЬ (Starnix-прецедент linux_syscalls.zig): семантическое ядро DRM —
// ЧИСТОЕ (нативные тесты через DrmOps-инъекцию), платформенный доступ
// (валидация user-VA, копирование, PMM-страницы dumb-буферов) — за ops.
//
// ФИЛОСОФИЯ «Всё есть файл» (UNIX): экран = /dev/fb0 и /dev/dri/card0.
// Вывод = mmap видеопамяти + запись пикселей; режим = sys_ioctl; события
// ввода = /dev/input/event0/1 (evdev.zig, шаг 2). Mesa/Gamescope/Wayland —
// ГОТОВЫЙ юзерспейс CachyOS, поднимающийся поверх этих файлов.
//
// UAPI-СОВМЕСТИМОСТЬ: все структуры = дословные раскладки include/uapi/drm/*
// и include/uapi/linux/fb.h (x86_64). ioctl-номера кодируются _IO/_IOR/_IOW/
// _IOWR с базой 'd' (0x64) — тесты сверяют с реальными значениями Linux
// (libdrm/strace), чтобы libdrm из CachyOS говорила с ядром без пересборки.
//
// WC (Write-Combining): линейный фреймбуфер мапится PWT-битом PTE (0x08)
// ПОСЛЕ перепрограммирования IA32_PAT (MSR 0x277) в Linux-раскладку
// 0x0007010600070106, где PAT[1]/PAT[5] = WC — максимальный FPS записи
// пикселей без cacheline-writeback-трафика на VRAM.
//
// Инвариант CDD №10: НИКАКОЙ враждебный ввод (мусорные VA/cmd/handle/размеры)
// не должен приводить к kernel-panic — только к -errno.
// ============================================================================

const std = @import("std");
const testing = std.testing;
const linux = @import("linux_syscalls.zig");

// ─── IOC-кодирование ioctl (asm-generic/ioctl.h) ──────────────────────────

pub const IOC_NONE: u32 = 0;
pub const IOC_WRITE: u32 = 1; // user → kernel
pub const IOC_READ: u32 = 2; // kernel → user

/// _IOC(dir, type, nr, size): dir<<30 | size<<16 | type<<8 | nr
pub inline fn ioc(dir: u32, typ: u32, nr: u32, size: u32) u32 {
    return (dir << 30) | (size << 16) | (typ << 8) | nr;
}

pub inline fn io(typ: u32, nr: u32) u32 {
    return ioc(IOC_NONE, typ, nr, 0);
}

pub inline fn ior(comptime T: type, typ: u32, nr: u32) u32 {
    return ioc(IOC_READ, typ, nr, @sizeOf(T));
}

pub inline fn iow(comptime T: type, typ: u32, nr: u32) u32 {
    return ioc(IOC_WRITE, typ, nr, @sizeOf(T));
}

pub inline fn iowr(comptime T: type, typ: u32, nr: u32) u32 {
    return ioc(IOC_READ | IOC_WRITE, typ, nr, @sizeOf(T));
}

// ─── UAPI-структуры DRM (include/uapi/drm/drm.h + drm_mode.h, x86_64) ──────

/// struct drm_version (64Б): name/date/desc — ПРИЁМНИКИ в user, длины in/out.
pub const DrmVersion = extern struct {
    major: i32 = 0,
    minor: i32 = 0,
    patch: i32 = 0,
    // неявное выравнивание 4Б до u64 (компилятор — как в C)
    name_len: u64 = 0,
    name_ptr: u64 = 0,
    date_len: u64 = 0,
    date_ptr: u64 = 0,
    desc_len: u64 = 0,
    desc_ptr: u64 = 0,
};

/// struct drm_get_cap (16Б)
pub const DrmGetCap = extern struct {
    capability: u64 = 0,
    value: u64 = 0,
};

/// struct drm_set_client_cap (16Б)
pub const DrmSetClientCap = extern struct {
    capability: u64 = 0,
    value: u64 = 0,
};

/// struct drm_mode_modeinfo (68Б)
pub const Modeinfo = extern struct {
    clock: u32 = 0,
    hdisplay: u16 = 0,
    hsync_start: u16 = 0,
    hsync_end: u16 = 0,
    htotal: u16 = 0,
    hskew: u16 = 0,
    vdisplay: u16 = 0,
    vsync_start: u16 = 0,
    vsync_end: u16 = 0,
    vtotal: u16 = 0,
    vscan: u16 = 0,
    vrefresh: u32 = 0,
    flags: u32 = 0,
    mtype: u32 = 0, // DRM_MODE_TYPE_*
    name: [32]u8 = .{0} ** 32,
};

/// struct drm_mode_card_res (64Б)
pub const CardRes = extern struct {
    fb_id_ptr: u64 = 0,
    crtc_id_ptr: u64 = 0,
    connector_id_ptr: u64 = 0,
    encoder_id_ptr: u64 = 0,
    count_fbs: u32 = 0,
    count_crtcs: u32 = 0,
    count_connectors: u32 = 0,
    count_encoders: u32 = 0,
    max_width: u32 = 0,
    max_height: u32 = 0,
    min_width: u32 = 0,
    min_height: u32 = 0,
};

/// struct drm_mode_crtc (104Б): fb_id — только для SETCRTC (GETCRTC игнорирует)
pub const ModeCrtc = extern struct {
    set_connectors_ptr: u64 = 0,
    count_connectors: u32 = 0,
    crtc_id: u32 = 0,
    fb_id: u32 = 0,
    x: u32 = 0,
    y: u32 = 0,
    gamma_size: u32 = 0,
    mode_valid: u32 = 0,
    mode: Modeinfo = .{},
};

/// struct drm_mode_get_encoder (20Б)
pub const GetEncoder = extern struct {
    encoder_id: u32 = 0,
    encoder_type: u32 = 0,
    crtc_id: u32 = 0,
    possible_crtcs: u32 = 0,
    possible_clones: u32 = 0,
};

/// struct drm_mode_get_connector (80Б)
pub const GetConnector = extern struct {
    encoders_ptr: u64 = 0,
    modes_ptr: u64 = 0,
    count_encoders: u32 = 0,
    count_modes: u32 = 0,
    count_props: u32 = 0,
    pad: u32 = 0,
    props_ptr: u64 = 0,
    prop_values_ptr: u64 = 0,
    encoder_id: u32 = 0,
    connector_id: u32 = 0,
    connector_type: u32 = 0,
    connector_type_id: u32 = 0,
    mm_width: u32 = 0,
    mm_height: u32 = 0,
    subpixel: u32 = 0,
    pad2: u32 = 0,
};

/// struct drm_mode_fb_cmd (28Б) — ADDFB/GETFB (legacy, без модификаторов)
pub const FbCmd = extern struct {
    fb_id: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    pitch: u32 = 0,
    bpp: u32 = 0,
    depth: u32 = 0,
    handle: u32 = 0,
};

/// struct drm_mode_create_dumb (32Б)
pub const CreateDumb = extern struct {
    height: u32 = 0,
    width: u32 = 0,
    bpp: u32 = 0,
    flags: u32 = 0,
    handle: u32 = 0,
    pitch: u32 = 0,
    size: u64 = 0,
};

/// struct drm_mode_map_dumb (16Б)
pub const MapDumb = extern struct {
    handle: u32 = 0,
    pad: u32 = 0,
    offset: u64 = 0,
};

/// struct drm_mode_destroy_dumb (4Б)
pub const DestroyDumb = extern struct {
    handle: u32 = 0,
};

/// struct drm_mode_crtc_page_flip (24Б)
pub const PageFlip = extern struct {
    crtc_id: u32 = 0,
    fb_id: u32 = 0,
    flags: u32 = 0,
    sequence: u32 = 0,
    user_data: u64 = 0,
};

// ─── UAPI-структуры fbdev (include/uapi/linux/fb.h, x86_64) ────────────────

/// struct fb_bitfield (12Б)
pub const FbBitfield = extern struct {
    offset: u32 = 0,
    length: u32 = 0,
    msb_right: u32 = 0,
};

/// struct fb_var_screeninfo (160Б) — VSCREENINFO
pub const FbVarScreenInfo = extern struct {
    xres: u32 = 0,
    yres: u32 = 0,
    xres_virtual: u32 = 0,
    yres_virtual: u32 = 0,
    xoffset: u32 = 0,
    yoffset: u32 = 0,
    bits_per_pixel: u32 = 0,
    grayscale: u32 = 0,
    red: FbBitfield = .{},
    green: FbBitfield = .{},
    blue: FbBitfield = .{},
    transp: FbBitfield = .{},
    nonstd: u32 = 0,
    activate: u32 = 0,
    height: u32 = 0, // мм (ЭЛТ-эпоха) — 0 = неизвестно
    width: u32 = 0,
    accel_flags: u32 = 0,
    pixclock: u32 = 0, // пикосекунды на пиксель
    left_margin: u32 = 0,
    right_margin: u32 = 0,
    upper_margin: u32 = 0,
    lower_margin: u32 = 0,
    hsync_len: u32 = 0,
    vsync_len: u32 = 0,
    sync: u32 = 0,
    vmode: u32 = 0,
    rotate: u32 = 0,
    colorspace: u32 = 0,
    reserved: [4]u32 = .{0} ** 4,
};

/// struct fb_fix_screeninfo (80Б) — FSCREENINFO
pub const FbFixScreenInfo = extern struct {
    id: [16]u8 = .{0} ** 16,
    smem_start: u64 = 0, // физ. адрес VRAM (информативно для юзерспейса)
    smem_len: u32 = 0,
    ftype: u32 = 0, // FB_TYPE_*
    type_aux: u32 = 0,
    visual: u32 = 0, // FB_VISUAL_*
    xpanstep: u16 = 0,
    ypanstep: u16 = 0,
    ywrapstep: u16 = 0,
    line_length: u32 = 0, // pitch
    // неявное выравнивание 4Б до u64 (компилятор — как в C)
    mmio_start: u64 = 0,
    mmio_len: u32 = 0,
    accel: u32 = 0, // FB_ACCEL_NONE
    capabilities: u16 = 0,
    reserved: u16 = 0,
};

// ─── DRM ioctl-номера (nr из include/uapi/drm/drm.h) ───────────────────────

pub const DRM_IOCTL_BASE: u32 = 0x64; // 'd'

pub const DRM_IOCTL_VERSION: u32 = ior(DrmVersion, DRM_IOCTL_BASE, 0x00);
pub const DRM_IOCTL_GET_MAGIC: u32 = ioc(IOC_READ, DRM_IOCTL_BASE, 0x02, 4);
pub const DRM_IOCTL_GET_CAP: u32 = iowr(DrmGetCap, DRM_IOCTL_BASE, 0x0C);
pub const DRM_IOCTL_SET_CLIENT_CAP: u32 = iow(DrmSetClientCap, DRM_IOCTL_BASE, 0x0D);
pub const DRM_IOCTL_SET_MASTER: u32 = io(DRM_IOCTL_BASE, 0x1E);
pub const DRM_IOCTL_DROP_MASTER: u32 = io(DRM_IOCTL_BASE, 0x1F);

pub const DRM_IOCTL_MODE_GETRESOURCES: u32 = iowr(CardRes, DRM_IOCTL_BASE, 0xA0);
pub const DRM_IOCTL_MODE_GETCRTC: u32 = iowr(ModeCrtc, DRM_IOCTL_BASE, 0xA1);
pub const DRM_IOCTL_MODE_SETCRTC: u32 = iowr(ModeCrtc, DRM_IOCTL_BASE, 0xA2);
pub const DRM_IOCTL_MODE_GETENCODER: u32 = iowr(GetEncoder, DRM_IOCTL_BASE, 0xA6);
pub const DRM_IOCTL_MODE_GETCONNECTOR: u32 = iowr(GetConnector, DRM_IOCTL_BASE, 0xA7);
pub const DRM_IOCTL_MODE_ADDFB: u32 = iow(FbCmd, DRM_IOCTL_BASE, 0xAE);
pub const DRM_IOCTL_MODE_PAGE_FLIP: u32 = iow(PageFlip, DRM_IOCTL_BASE, 0xB0);
pub const DRM_IOCTL_MODE_CREATE_DUMB: u32 = iowr(CreateDumb, DRM_IOCTL_BASE, 0xB2);
pub const DRM_IOCTL_MODE_MAP_DUMB: u32 = iowr(MapDumb, DRM_IOCTL_BASE, 0xB3);
pub const DRM_IOCTL_MODE_DESTROY_DUMB: u32 = iowr(DestroyDumb, DRM_IOCTL_BASE, 0xB4);

// ─── fbdev ioctl-номера (legacy-плоские, include/uapi/linux/fb.h) ──────────

pub const FBIOGET_VSCREENINFO: u32 = 0x4600;
pub const FBIOPUT_VSCREENINFO: u32 = 0x4601;
pub const FBIOGET_FSCREENINFO: u32 = 0x4602;
pub const FBIOPUT_FSCREENINFO: u32 = 0x4603;

// ─── DRM-константы-значения ────────────────────────────────────────────────

pub const DRM_CAP_DUMB_BUFFER: u64 = 0x1;
pub const DRM_CAP_DUMB_PREFERRED_DEPTH: u64 = 0x3;
pub const DRM_CAP_TIMESTAMP_MONOTONIC: u64 = 0x6;
pub const DRM_CAP_CURSOR_WIDTH: u64 = 0x9;
pub const DRM_CAP_CURSOR_HEIGHT: u64 = 0xA;

pub const DRM_MODE_ENCODER_VIRTUAL: u32 = 5;
pub const DRM_MODE_CONNECTOR_VIRTUAL: u32 = 15;
pub const DRM_MODE_SUBPIXEL_NONE: u32 = 1;
/// connector_status: connected = 1 (enum drm_connector_status)
pub const DRM_MODE_CONNECTED: u32 = 1;
pub const DRM_MODE_TYPE_DRIVER: u32 = 3; // DRIVER|PREFERRED
pub const DRM_MODE_FLAG_NHSYNC: u32 = 0x2;
pub const DRM_MODE_FLAG_NVSYNC: u32 = 0x4;

pub const FB_TYPE_PACKED_PIXELS: u32 = 0;
pub const FB_VISUAL_TRUECOLOR: u32 = 2;
pub const FB_VMODE_NONINTERLACED: u32 = 0;
pub const FB_ACCEL_NONE: u32 = 0;

/// Максимальный dumb-буфер: 8192×8192×4 = 256МБ виртуально допустимо,
/// но бюджет PMM ограничивает разумным 16МБ на буфер (16×1МБ-страниц …).
pub const MAX_DUMB_BYTES: u64 = 16 * 1024 * 1024;
/// Лимит измерений dumb (дрм-санити): XRGB8888 → 8192×8192.
pub const MAX_DUMB_DIM: u32 = 8192;

// ─── PAT/WC (write-combing видеопамяти) ────────────────────────────────────

/// PTE-бит PWT (0x08) ПОСЛЕ PAT-репрограммирования выбирает PAT[1]=WC.
/// Маппинг фреймбуфера: PRESENT|WRITABLE|USER|PWT (+NX) — быстрые burst-записи.
pub const PTE_WC: u64 = 0x08;

/// Linux-раскладка IA32_PAT (MSR 0x277): PA0/PA4=WB, PA1/PA5=WC,
/// PA2/PA6=UC-, PA3/PA7=UC. Запись ядра на буте → PWT-бит = WC.
pub const PAT_LINUX_WC: u64 = 0x0007_0106_0007_0106;

// ─── Файловый фасад UNIX: пути устройств ───────────────────────────────────

pub const DevKind = enum {
    fb0,
    dri_card0,
    dri_render,
};

/// Резолв путей devfs: «Всё есть файл» — экран это файл.
pub fn resolveDevPath(path: []const u8) ?DevKind {
    if (std.mem.eql(u8, path, "/dev/fb0")) return .fb0;
    if (std.mem.eql(u8, path, "/dev/dri/card0")) return .dri_card0;
    if (std.mem.eql(u8, path, "/dev/dri/renderD128")) return .dri_render;
    return null;
}

// ─── Операции окружения (инъекция: ядро ↔ нативные тесты) ──────────────────

pub const DrmOps = struct {
    /// Проверить user-диапазон [va, va+len) (want_write) — контракт
    /// linuxValidate (постраничный walk PML4, canonical-потолок).
    validate: *const fn (va: u64, len: u64, want_write: bool) bool,
    /// User → ядро: копия байтов (ioctl-аргументы in). false = EFAULT.
    copy_in: *const fn (dst: []u8, src_va: u64) bool,
    /// Ядро → user: копия байтов (ioctl-аргументы out). false = EFAULT.
    copy_out: *const fn (dst_va: u64, src: []const u8) bool,
    /// Выделить N физ. страниц (нулевых) — backing dumb-буфера. null = ENOMEM.
    alloc_pages: *const fn (pages: u64) ?u64,
    /// Освободить N физ. страниц (DESTROY_DUMB).
    free_pages: *const fn (phys: u64, pages: u64) void,
};

// ─── Состояние DRM (dumb-KMS: 1 CRTC + 1 энкодер + 1 коннектор) ────────────

pub const FbGeom = struct {
    phys: u64 = 0,
    width: u32 = 0,
    height: u32 = 0,
    pitch: u32 = 0,
    bpp: u8 = 0,
};

pub const DumbMode = enum {
    inactive,
    linear_fb, // скан-аут = линейный фреймбуфер бут-лоадера (VBE/PVH)
    virtio_gpu, // скан-аут через VirtIO-GPU 2D (probe шага 1)
};

pub const DumbBuf = struct {
    used: bool = false,
    handle: u32 = 0,
    phys: u64 = 0, // физ. база backing-страниц
    size: u64 = 0,
    pages: u64 = 0,
    width: u32 = 0,
    height: u32 = 0,
    pitch: u32 = 0,
    bpp: u32 = 0,
};

pub const FbReg = struct {
    used: bool = false,
    fb_id: u32 = 0,
    handle: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    pitch: u32 = 0,
    bpp: u32 = 0,
    depth: u32 = 0,
};

pub const MAX_DUMB: usize = 8;
pub const MAX_FBS: usize = 8;

/// Служебные object-id (libdrm ожидает ненулевые уникальные).
const CRTC_ID: u32 = 33;
const ENCODER_ID: u32 = 34;
const CONNECTOR_ID: u32 = 35;

/// Фейковая GPU-апертура для MAP_DUMB-offset'ов: mmap(fd=card0, offset=X)
/// ядра (шаг 3) резолвит X → dumb-буфер → физ. страницы. Слот на буфер —
/// 256МБ (дешёвый div-lookup, достаточно для 8 буферов).
pub const DUMB_APERTURE_BASE: u64 = 0x1000_0000_0000;
pub const DUMB_SLOT_SIZE: u64 = 0x1000_0000;

pub const DrmState = struct {
    mode: DumbMode = .inactive,
    geom: FbGeom = .{},
    dumb: [MAX_DUMB]DumbBuf = [_]DumbBuf{.{}} ** MAX_DUMB,
    fbs: [MAX_FBS]FbReg = [_]FbReg{.{}} ** MAX_FBS,
    next_handle: u32 = 1, // 0 = невалидный handle (GEM-конвенция)
    next_fb_id: u32 = 1,
    crtc_fb_id: u32 = 0, // fb на скан-ауте (PAGE_FLIP/SETCRTC)
    flips: u32 = 0, // счётчик page-flip'ов (E2E-наблюдаемо)
    width_mm: u32 = 300,
    height_mm: u32 = 200,
};

/// Активировать DRM в режиме линейного фреймбуфера (скан-аут задан
/// бут-лоадером: VBE через GRUB-multiboot2 или консольный linear fb).
pub fn initLinearFb(st: *DrmState, geom: FbGeom) void {
    st.mode = .linear_fb;
    st.geom = geom;
}

/// Активировать DRM в режиме VirtIO-GPU (probe успешно, скан-аут через
/// 2D-команды — виртуальный дисплей QEMU).
pub fn initVirtioGpu(st: *DrmState, geom: FbGeom) void {
    st.mode = .virtio_gpu;
    st.geom = geom;
}

/// Идентификаторы объектов KMS (для логов/тестов): CRTC/энкодер/коннектор.
pub fn kmsIds() [3]u32 {
    return .{ CRTC_ID, ENCODER_ID, CONNECTOR_ID };
}

// ─── Внутренние хелперы ────────────────────────────────────────────────────

fn findDumb(st: *DrmState, handle: u32) ?*DumbBuf {
    if (handle == 0) return null;
    for (&st.dumb) |*b| {
        if (b.used and b.handle == handle) return b;
    }
    return null;
}

fn findFb(st: *DrmState, fb_id: u32) ?*FbReg {
    if (fb_id == 0) return null;
    for (&st.fbs) |*f| {
        if (f.used and f.fb_id == fb_id) return f;
    }
    return null;
}

fn activeFbCount(st: *DrmState) u32 {
    var n: u32 = 0;
    for (&st.fbs) |*f| {
        if (f.used) n += 1;
    }
    return n;
}

/// Modeinfo из геометрии скан-аута: 60Гц, vrefresh, имя-разрешение.
/// Часовая частота: приближение CVT (tot ≈ 1.25× visible) — семантика,
/// не VESA-точность: libdrm сопоставляет режим по hdisplay/vdisplay.
pub fn geomModeinfo(geom: FbGeom) Modeinfo {
    var m = Modeinfo{};
    m.hdisplay = @intCast(@min(geom.width, 65535));
    m.vdisplay = @intCast(@min(geom.height, 65535));
    m.hsync_start = m.hdisplay + 40;
    m.hsync_end = m.hsync_start + 40;
    m.htotal = m.hdisplay + 160;
    m.vsync_start = m.vdisplay + 10;
    m.vsync_end = m.vsync_start + 10;
    m.vtotal = m.vdisplay + 40;
    m.vrefresh = 60;
    m.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC;
    m.mtype = DRM_MODE_TYPE_DRIVER;
    const label = std.fmt.bufPrint(&m.name, "{d}x{d}", .{ m.hdisplay, m.vdisplay }) catch "poler";
    _ = label;
    // pixclock-аналог (кГц-масштаб): 60Гц × тотал-пиксели
    const total: u64 = @as(u64, m.htotal) * @as(u64, m.vtotal);
    m.clock = @intCast(@min(total * 60 / 1000, std.math.maxInt(u32)));
    return m;
}

// ─── DRM ioctl: диспетчер /dev/dri/card0 ───────────────────────────────────

/// Главная точка ioctl-слоя DRM. Возвращает 0 или -errno (Linux-ABI).
pub fn drmIoctl(st: *DrmState, ops: DrmOps, cmd: u32, arg: u64) i64 {
    switch (cmd) {
        DRM_IOCTL_VERSION => return ioVersion(ops, arg),
        DRM_IOCTL_GET_MAGIC => {
            // struct drm_auth { magic: u32 } — ядро-мастер: любой валиден
            if (!ops.validate(arg, 4, true)) return -linux.EFAULT;
            var magic: u32 = 42;
            if (!ops.copy_out(arg, std.mem.asBytes(&magic))) return -linux.EFAULT;
            return 0;
        },
        DRM_IOCTL_GET_CAP => return ioGetCap(ops, arg),
        DRM_IOCTL_SET_CLIENT_CAP => return ioSetClientCap(ops, arg),
        DRM_IOCTL_SET_MASTER, DRM_IOCTL_DROP_MASTER => return 0,
        DRM_IOCTL_MODE_GETRESOURCES => return ioGetResources(st, ops, arg),
        DRM_IOCTL_MODE_GETCRTC => return ioGetCrtc(st, ops, arg),
        DRM_IOCTL_MODE_SETCRTC => return ioSetCrtc(st, ops, arg),
        DRM_IOCTL_MODE_GETENCODER => return ioGetEncoder(st, ops, arg),
        DRM_IOCTL_MODE_GETCONNECTOR => return ioGetConnector(st, ops, arg),
        DRM_IOCTL_MODE_ADDFB => return ioAddFb(st, ops, arg),
        DRM_IOCTL_MODE_PAGE_FLIP => return ioPageFlip(st, ops, arg),
        DRM_IOCTL_MODE_CREATE_DUMB => return ioCreateDumb(st, ops, arg),
        DRM_IOCTL_MODE_MAP_DUMB => return ioMapDumb(st, ops, arg),
        DRM_IOCTL_MODE_DESTROY_DUMB => return ioDestroyDumb(st, ops, arg),
        else => return -linux.EINVAL, // DRM-ядро: unknown ioctl → EINVAL
    }
}

/// DRM_IOCTL_VERSION: libdrm зовёт ДВАЖДЫ (null-указатели → длины; буферы →
/// строки). Драйвер: «poler-drm» 1.19.0.
fn ioVersion(ops: DrmOps, arg: u64) i64 {
    var v: DrmVersion = undefined;
    if (!ops.copy_in(std.mem.asBytes(&v), arg)) return -linux.EFAULT;

    const name = "poler-drm";
    const date = "2026";
    const desc = "POLER-OS dumb-KMS (CDD #10)";

    // строки — только если user дал буфер, вмещающий строку
    if (v.name_ptr != 0 and v.name_len >= name.len) {
        if (!ops.copy_out(v.name_ptr, name)) return -linux.EFAULT;
    }
    if (v.date_ptr != 0 and v.date_len >= date.len) {
        if (!ops.copy_out(v.date_ptr, date)) return -linux.EFAULT;
    }
    if (v.desc_ptr != 0 and v.desc_len >= desc.len) {
        if (!ops.copy_out(v.desc_ptr, desc)) return -linux.EFAULT;
    }

    v.major = 1;
    v.minor = 19;
    v.patch = 0;
    v.name_len = name.len;
    v.date_len = date.len;
    v.desc_len = desc.len;
    if (!ops.copy_out(arg, std.mem.asBytes(&v))) return -linux.EFAULT;
    return 0;
}

fn ioGetCap(ops: DrmOps, arg: u64) i64 {
    var c: DrmGetCap = undefined;
    if (!ops.copy_in(std.mem.asBytes(&c), arg)) return -linux.EFAULT;
    const val: u64 = switch (c.capability) {
        DRM_CAP_DUMB_BUFFER => 1,
        DRM_CAP_DUMB_PREFERRED_DEPTH => 32, // XRGB8888
        DRM_CAP_TIMESTAMP_MONOTONIC => 1,
        DRM_CAP_CURSOR_WIDTH => 64,
        DRM_CAP_CURSOR_HEIGHT => 64,
        else => return -linux.EINVAL, // Linux: unknown capability → EINVAL
    };
    c.value = val;
    if (!ops.copy_out(arg, std.mem.asBytes(&c))) return -linux.EFAULT;
    return 0;
}

fn ioSetClientCap(ops: DrmOps, arg: u64) i64 {
    var c: DrmSetClientCap = undefined;
    if (!ops.copy_in(std.mem.asBytes(&c), arg)) return -linux.EFAULT;
    // клиентские капсы не влияют на dumb-KMS: принимаем (atomic? нет —
    // Universal planes? нет) — честная заглушка «принято, не активно».
    return 0;
}

fn ioGetResources(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    // Headless (inactive) = render-node-семантика: KMS-объекты существуют
    // (виртуальная топология 1+1+1), список режимов пуст (GETCONNECTOR).
    // Dumb-буферы НЕ требуют скан-аута — lifecycle верифицируем headless.
    var r: CardRes = undefined;
    if (!ops.copy_in(std.mem.asBytes(&r), arg)) return -linux.EFAULT;

    const n_fbs = activeFbCount(st);
    // Семантика Linux drm_mode_getresources: ядро ЗАПИСЫВАЕТ фактические
    // счётчики; если пользовательский буфер вмещает — пишет и id-массивы.
    if (r.crtc_id_ptr != 0 and r.count_crtcs >= 1) {
        if (!writeU32(ops, r.crtc_id_ptr, CRTC_ID)) return -linux.EFAULT;
    }
    if (r.encoder_id_ptr != 0 and r.count_encoders >= 1) {
        if (!writeU32(ops, r.encoder_id_ptr, ENCODER_ID)) return -linux.EFAULT;
    }
    if (r.connector_id_ptr != 0 and r.count_connectors >= 1) {
        if (!writeU32(ops, r.connector_id_ptr, CONNECTOR_ID)) return -linux.EFAULT;
    }
    if (r.fb_id_ptr != 0 and r.count_fbs >= n_fbs and n_fbs > 0) {
        var off: u64 = 0;
        for (&st.fbs) |*f| {
            if (!f.used) continue;
            if (!writeU32(ops, r.fb_id_ptr + off, f.fb_id)) return -linux.EFAULT;
            off += 4;
        }
    }

    r.count_fbs = n_fbs;
    r.count_crtcs = 1;
    r.count_encoders = 1;
    r.count_connectors = 1;
    r.max_width = MAX_DUMB_DIM;
    r.max_height = MAX_DUMB_DIM;
    r.min_width = 1;
    r.min_height = 1;
    if (!ops.copy_out(arg, std.mem.asBytes(&r))) return -linux.EFAULT;
    return 0;
}

fn ioGetCrtc(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    var c: ModeCrtc = undefined;
    if (!ops.copy_in(std.mem.asBytes(&c), arg)) return -linux.EFAULT;
    if (c.crtc_id != 0 and c.crtc_id != CRTC_ID) return -linux.EINVAL;
    c.crtc_id = CRTC_ID;
    c.gamma_size = 256;
    if (st.mode != .inactive and st.geom.width > 0) {
        c.mode_valid = 1;
        c.mode = geomModeinfo(st.geom);
    } else {
        c.mode_valid = 0;
    }
    if (!ops.copy_out(arg, std.mem.asBytes(&c))) return -linux.EFAULT;
    return 0;
}

fn ioSetCrtc(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    var c: ModeCrtc = undefined;
    if (!ops.copy_in(std.mem.asBytes(&c), arg)) return -linux.EFAULT;
    if (c.crtc_id != CRTC_ID) return -linux.EINVAL;
    // fb_id=0 → disable CRTC (dpms off) — принимаем
    if (c.fb_id != 0) {
        if (findFb(st, c.fb_id) == null) return -linux.ENOENT;
        st.crtc_fb_id = c.fb_id;
    } else {
        st.crtc_fb_id = 0;
    }
    return 0;
}

fn ioGetEncoder(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    _ = st; // энкодер не зависит от геометрии скан-аута
    var e: GetEncoder = undefined;
    if (!ops.copy_in(std.mem.asBytes(&e), arg)) return -linux.EFAULT;
    if (e.encoder_id != 0 and e.encoder_id != ENCODER_ID) return -linux.EINVAL;
    e.encoder_id = ENCODER_ID;
    e.encoder_type = DRM_MODE_ENCODER_VIRTUAL;
    e.crtc_id = CRTC_ID;
    e.possible_crtcs = 1; // битмаска: только CRTC-0
    e.possible_clones = 0;
    if (!ops.copy_out(arg, std.mem.asBytes(&e))) return -linux.EFAULT;
    return 0;
}

fn ioGetConnector(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    var c: GetConnector = undefined;
    if (!ops.copy_in(std.mem.asBytes(&c), arg)) return -linux.EFAULT;
    if (c.connector_id != 0 and c.connector_id != CONNECTOR_ID) return -linux.EINVAL;

    const has_mode = st.mode != .inactive and st.geom.width > 0;
    const n_modes: u32 = if (has_mode) 1 else 0;

    // список режимов — в user-массив modeinfo (если вмещает)
    if (c.modes_ptr != 0 and c.count_modes >= n_modes and n_modes > 0) {
        const mode = geomModeinfo(st.geom);
        if (!ops.copy_out(c.modes_ptr, std.mem.asBytes(&mode))) return -linux.EFAULT;
    }
    // список энкодеров — id-массив u32
    if (c.encoders_ptr != 0 and c.count_encoders >= 1) {
        if (!writeU32(ops, c.encoders_ptr, ENCODER_ID)) return -linux.EFAULT;
    }

    c.connector_id = CONNECTOR_ID;
    c.encoder_id = if (has_mode) ENCODER_ID else 0;
    c.connector_type = DRM_MODE_CONNECTOR_VIRTUAL;
    c.connector_type_id = 1;
    c.mm_width = st.width_mm;
    c.mm_height = st.height_mm;
    c.subpixel = DRM_MODE_SUBPIXEL_NONE;
    c.count_encoders = 1;
    c.count_modes = n_modes;
    c.count_props = 0;
    if (!ops.copy_out(arg, std.mem.asBytes(&c))) return -linux.EFAULT;
    return 0;
}

fn ioAddFb(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    var f: FbCmd = undefined;
    if (!ops.copy_in(std.mem.asBytes(&f), arg)) return -linux.EFAULT;
    const b = findDumb(st, f.handle) orelse return -linux.EINVAL; // GEM-handle нет
    if (f.width != b.width or f.height != b.height or f.pitch != b.pitch or f.bpp != b.bpp)
        return -linux.EINVAL; // рассинхрон метрик с буфером

    // переиспользование слота? ADDFB с существующим fb_id=0 → новый id
    var slot: ?*FbReg = null;
    for (&st.fbs) |*r| {
        if (!r.used) {
            slot = r;
            break;
        }
    }
    if (slot == null) return -linux.ENOMEM;

    slot.?.used = true;
    slot.?.fb_id = st.next_fb_id;
    st.next_fb_id +%= 1;
    slot.?.handle = b.handle;
    slot.?.width = b.width;
    slot.?.height = b.height;
    slot.?.pitch = b.pitch;
    slot.?.bpp = b.bpp;
    slot.?.depth = 24; // XRGB8888 → 24bpp полезных

    f.fb_id = slot.?.fb_id;
    f.depth = 24;
    if (!ops.copy_out(arg, std.mem.asBytes(&f))) return -linux.EFAULT;
    return 0;
}

fn ioPageFlip(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    var p: PageFlip = undefined;
    if (!ops.copy_in(std.mem.asBytes(&p), arg)) return -linux.EFAULT;
    // Linux drm_mode_page_flip: crtc-lookup неудача → -ENOENT
    if (p.crtc_id != CRTC_ID) return -linux.ENOENT;
    if (findFb(st, p.fb_id) == null) return -linux.ENOENT;
    // Асинхронные флипы (DRM_MODE_PAGE_FLIP_ASYNC) и vblank-event'ы
    // (DRM_EVENT_PAGE_FLIP в drmHandleEvent) — вне фундамента v0.19:
    // флип применяется немедленно, счётчик для E2E.
    st.crtc_fb_id = p.fb_id;
    st.flips += 1;
    return 0;
}

fn ioCreateDumb(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    var d: CreateDumb = undefined;
    if (!ops.copy_in(std.mem.asBytes(&d), arg)) return -linux.EFAULT;

    // Санити: только XRGB8888, разумные размеры (враждебный ввод → EINVAL)
    if (d.bpp != 32) return -linux.EINVAL;
    if (d.width == 0 or d.height == 0) return -linux.EINVAL;
    if (d.width > MAX_DUMB_DIM or d.height > MAX_DUMB_DIM) return -linux.EINVAL;

    const pm = @mulWithOverflow(d.width, @as(u32, 4)); // pitch = w*4, XRGB8888
    if (pm[1] != 0) return -linux.EINVAL;
    const pitch: u32 = pm[0];
    const size: u64 = @as(u64, pitch) * @as(u64, d.height);
    if (size == 0 or size > MAX_DUMB_BYTES) return -linux.ENOMEM;
    const pages = (size + 4095) / 4096;

    var slot: ?*DumbBuf = null;
    for (&st.dumb) |*b| {
        if (!b.used) {
            slot = b;
            break;
        }
    }
    if (slot == null) return -linux.ENOMEM;

    const phys = ops.alloc_pages(pages) orelse return -linux.ENOMEM;

    slot.?.used = true;
    slot.?.handle = st.next_handle;
    st.next_handle +%= 1;
    slot.?.phys = phys;
    slot.?.size = size;
    slot.?.pages = pages;
    slot.?.width = d.width;
    slot.?.height = d.height;
    slot.?.pitch = pitch;
    slot.?.bpp = 32;

    d.handle = slot.?.handle;
    d.pitch = pitch;
    d.size = size;
    if (!ops.copy_out(arg, std.mem.asBytes(&d))) return -linux.EFAULT;
    return 0;
}

fn ioMapDumb(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    var m: MapDumb = undefined;
    if (!ops.copy_in(std.mem.asBytes(&m), arg)) return -linux.EFAULT;
    const b = findDumb(st, m.handle) orelse return -linux.ENOENT;
    // offset в фейковой апертуре — mmap-слой (шаг 3) резолвит её в страницы
    m.offset = apertureOffset(b.handle);
    if (!ops.copy_out(arg, std.mem.asBytes(&m))) return -linux.EFAULT;
    return 0;
}

fn ioDestroyDumb(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    var d: DestroyDumb = undefined;
    if (!ops.copy_in(std.mem.asBytes(&d), arg)) return -linux.EFAULT;
    const b = findDumb(st, d.handle) orelse return -linux.EINVAL;
    ops.free_pages(b.phys, b.pages);
    b.* = .{};
    return 0;
}

// ─── fbdev ioctl: диспетчер /dev/fb0 ───────────────────────────────────────

/// ioctl на /dev/fb0 (legacy-номера, без IOC-кодирования). /dev/fb0 открывают
/// прямые фреймбуфер-клиенты ДО поднятия DRM (initrd-лог, Plymouth-подобные).
pub fn fbIoctl(st: *DrmState, ops: DrmOps, cmd: u32, arg: u64) i64 {
    switch (cmd) {
        FBIOGET_VSCREENINFO => return fbGetVar(st, ops, arg),
        FBIOPUT_VSCREENINFO => return fbPutVar(st, ops, arg),
        FBIOGET_FSCREENINFO => return fbGetFix(st, ops, arg),
        FBIOPUT_FSCREENINFO => return -linux.EPERM, // fix-поля RO для user
        else => return -linux.EINVAL,
    }
}

fn fbGetVar(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    if (st.mode == .inactive) return -linux.ENODEV;
    var v: FbVarScreenInfo = .{};
    v.xres = st.geom.width;
    v.yres = st.geom.height;
    v.xres_virtual = st.geom.width;
    v.yres_virtual = st.geom.height;
    v.bits_per_pixel = st.geom.bpp;
    v.grayscale = 0;
    // XRGB8888 little-endian: blue 0:8, green 8:8, red 16:8, transp 24:0
    v.blue = .{ .offset = 0, .length = 8, .msb_right = 0 };
    v.green = .{ .offset = 8, .length = 8, .msb_right = 0 };
    v.red = .{ .offset = 16, .length = 8, .msb_right = 0 };
    v.transp = .{ .offset = 24, .length = 0, .msb_right = 0 };
    v.activate = 0; // FB_ACTIVATE_NOW
    v.pixclock = 1000000000 / 60; // ~60Гц (пикосекунды/пиксель — приближение)
    v.vmode = FB_VMODE_NONINTERLACED;
    if (!ops.copy_out(arg, std.mem.asBytes(&v))) return -linux.EFAULT;
    return 0;
}

fn fbPutVar(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    if (st.mode == .inactive) return -linux.ENODEV;
    var v: FbVarScreenInfo = undefined;
    if (!ops.copy_in(std.mem.asBytes(&v), arg)) return -linux.EFAULT;
    // Линейный fb бут-лоадера не переключается fbdev-ом (нет собственного
    // CRTC): принимаем ТОЛЬКО идентичную геометрию — иначе EINVAL (честный
    // отказ вместо молчаливой лжи).
    if (v.xres != st.geom.width or v.yres != st.geom.height or
        v.bits_per_pixel != st.geom.bpp) return -linux.EINVAL;
    return 0;
}

fn fbGetFix(st: *DrmState, ops: DrmOps, arg: u64) i64 {
    if (st.mode == .inactive) return -linux.ENODEV;
    var f: FbFixScreenInfo = .{};
    const id = "poler-fb0"; // ≤15 символов + нуль
    @memcpy(f.id[0..id.len], id);
    f.smem_start = st.geom.phys;
    f.smem_len = @intCast(@as(u64, st.geom.pitch) * @as(u64, st.geom.height));
    f.ftype = FB_TYPE_PACKED_PIXELS;
    f.visual = FB_VISUAL_TRUECOLOR;
    f.line_length = st.geom.pitch;
    f.accel = FB_ACCEL_NONE;
    if (!ops.copy_out(arg, std.mem.asBytes(&f))) return -linux.EFAULT;
    return 0;
}

// ─── Апертура dumb-буферов (мост mmap fd=card0 → страницы) ─────────────────

/// Offset-слот буфера в фейковой GPU-апертуре (MAP_DUMB возвращает её).
pub fn apertureOffset(handle: u32) u64 {
    return DUMB_APERTURE_BASE + @as(u64, handle) * DUMB_SLOT_SIZE;
}

/// Резолв mmap-offset → dumb-буфер (mmap-слой шага 3). Ошибка = null.
pub fn lookupAperture(st: *DrmState, off: u64) ?*DumbBuf {
    if (off < DUMB_APERTURE_BASE) return null;
    const rel = off - DUMB_APERTURE_BASE;
    if (rel % DUMB_SLOT_SIZE != 0) return null;
    const handle: u32 = std.math.cast(u32, rel / DUMB_SLOT_SIZE) orelse return null;
    return findDumb(st, handle);
}

// ─── Хелперы копирования u32-массивов ──────────────────────────────────────

fn writeU32(ops: DrmOps, va: u64, value: u32) bool {
    return ops.copy_out(va, std.mem.asBytes(&value));
}

// ============================================================================
//  Нативные тесты (linux x86_64 gnu — Zig test runner)
// ============================================================================

/// Фейковое user-пространство (прецедент linux_syscalls.FakeEnv):
/// буфер 32КБ по VA 0x20000_0000, fake-аллокатор физических страниц.
const FakeEnv = struct {
    const USER_BASE: u64 = 0x20000_0000;
    const USER_LEN: u64 = 32 * 1024;

    mem: []u8,
    mmap_cursor: u64 = USER_BASE + USER_LEN,
    allocs: usize = 0, // счётчик alloc_pages
    frees: usize = 0, // счётчик free_pages
    last_free_pages: u64 = 0,

    fn init() !FakeEnv {
        return .{ .mem = try testing.allocator.alloc(u8, @intCast(USER_LEN)) };
    }
    fn deinit(self: *FakeEnv) void {
        testing.allocator.free(self.mem);
    }
    fn vaOk(va: u64, len: u64) bool {
        if (len == 0) return true;
        const sum = @addWithOverflow(va, len);
        if (sum[1] != 0) return false;
        if (sum[0] > linux.USER_VA_CEILING) return false;
        return va >= USER_BASE and sum[0] <= USER_BASE + USER_LEN;
    }
    fn vaPtr(self: *FakeEnv, va: u64) ?[*]u8 {
        if (va < USER_BASE or va >= USER_BASE + USER_LEN) return null;
        return self.mem.ptr + @as(usize, @intCast(va - USER_BASE));
    }
};

var g_env: ?*FakeEnv = null;

fn fakeValidate(va: u64, len: u64, want_write: bool) bool {
    _ = want_write;
    return FakeEnv.vaOk(va, len);
}
fn fakeCopyIn(dst: []u8, src_va: u64) bool {
    const e = g_env.?;
    if (!FakeEnv.vaOk(src_va, dst.len)) return false;
    const p = e.vaPtr(src_va) orelse return false;
    @memcpy(dst, p[0..dst.len]);
    return true;
}
fn fakeCopyOut(dst_va: u64, src: []const u8) bool {
    const e = g_env.?;
    if (!FakeEnv.vaOk(dst_va, src.len)) return false;
    const p = e.vaPtr(dst_va) orelse return false;
    @memcpy(p[0..src.len], src);
    return true;
}
fn fakeAllocPages(pages: u64) ?u64 {
    g_env.?.allocs += 1;
    const pa: u64 = 0x5000_0000 + g_env.?.mmap_cursor; // «физика» fake
    _ = pages;
    return pa;
}
fn fakeFreePages(phys: u64, pages: u64) void {
    _ = phys;
    const e = g_env.?;
    e.frees += 1;
    e.last_free_pages = pages;
}

fn fakeOps() DrmOps {
    return .{
        .validate = fakeValidate,
        .copy_in = fakeCopyIn,
        .copy_out = fakeCopyOut,
        .alloc_pages = fakeAllocPages,
        .free_pages = fakeFreePages,
    };
}

fn envSetup() !*FakeEnv {
    const e = try testing.allocator.create(FakeEnv);
    e.* = try FakeEnv.init();
    @memset(e.mem, 0);
    g_env = e;
    return e;
}
fn envTeardown(e: *FakeEnv) void {
    g_env = null;
    e.deinit();
    testing.allocator.destroy(e);
}

fn geom640() FbGeom {
    return .{ .phys = 0xFD00_0000, .width = 640, .height = 480, .pitch = 2560, .bpp = 32 };
}

// ─── Тесты: UAPI-совместимость номеров/раскладок (якоря libdrm/strace) ─────

test "drm: IOC-кодирование — формула _IOC(dir,type,nr,size)" {
    // _IO('d', 0x1E) = 0x0000641E (SET_MASTER)
    try testing.expectEqual(@as(u32, 0x0000_641E), DRM_IOCTL_SET_MASTER);
    // _IOR('d', 0x00, drm_version 64Б) = 0x80406400 (VERSION — якорь strace:
    // размер 0x40 сидит в битах 29..16, НЕ «0804» как у 4Б-структур!)
    try testing.expectEqual(@as(u32, 0x8040_6400), DRM_IOCTL_VERSION);
    // _IOWR('d', 0x0C, drm_get_cap 16Б) = 0xC010640C (GET_CAP)
    try testing.expectEqual(@as(u32, 0xC010_640C), DRM_IOCTL_GET_CAP);
    // _IOW('d', 0x0D, drm_set_client_cap 16Б) = 0x4010640D
    try testing.expectEqual(@as(u32, 0x4010_640D), DRM_IOCTL_SET_CLIENT_CAP);
}

test "drm: DRM_MODE-* ioctl-номера = реальные значения Linux uapi" {
    try testing.expectEqual(@as(u32, 0xC040_64A0), DRM_IOCTL_MODE_GETRESOURCES);
    try testing.expectEqual(@as(u32, 0xC068_64A1), DRM_IOCTL_MODE_GETCRTC);
    try testing.expectEqual(@as(u32, 0xC068_64A2), DRM_IOCTL_MODE_SETCRTC);
    try testing.expectEqual(@as(u32, 0xC014_64A6), DRM_IOCTL_MODE_GETENCODER);
    try testing.expectEqual(@as(u32, 0xC050_64A7), DRM_IOCTL_MODE_GETCONNECTOR);
    try testing.expectEqual(@as(u32, 0x401C_64AE), DRM_IOCTL_MODE_ADDFB);
    try testing.expectEqual(@as(u32, 0x4018_64B0), DRM_IOCTL_MODE_PAGE_FLIP);
    try testing.expectEqual(@as(u32, 0xC020_64B2), DRM_IOCTL_MODE_CREATE_DUMB);
    try testing.expectEqual(@as(u32, 0xC010_64B3), DRM_IOCTL_MODE_MAP_DUMB);
    try testing.expectEqual(@as(u32, 0xC004_64B4), DRM_IOCTL_MODE_DESTROY_DUMB);
}

test "drm: UAPI-раскладки структур (x86_64 sizeof-якоря)" {
    try testing.expectEqual(@as(usize, 64), @sizeOf(DrmVersion));
    try testing.expectEqual(@as(usize, 16), @sizeOf(DrmGetCap));
    try testing.expectEqual(@as(usize, 68), @sizeOf(Modeinfo));
    try testing.expectEqual(@as(usize, 64), @sizeOf(CardRes));
    try testing.expectEqual(@as(usize, 104), @sizeOf(ModeCrtc));
    try testing.expectEqual(@as(usize, 20), @sizeOf(GetEncoder));
    try testing.expectEqual(@as(usize, 80), @sizeOf(GetConnector));
    try testing.expectEqual(@as(usize, 28), @sizeOf(FbCmd));
    try testing.expectEqual(@as(usize, 32), @sizeOf(CreateDumb));
    try testing.expectEqual(@as(usize, 16), @sizeOf(MapDumb));
    try testing.expectEqual(@as(usize, 4), @sizeOf(DestroyDumb));
    try testing.expectEqual(@as(usize, 24), @sizeOf(PageFlip));
    // выравнивание u64 после трёх i32 в drm_version: name_len @16
    try testing.expectEqual(@as(usize, 16), @offsetOf(DrmVersion, "name_len"));
}

test "drm: fbdev-структуры — sizeof 160/80 (glibc fb.h)" {
    try testing.expectEqual(@as(usize, 160), @sizeOf(FbVarScreenInfo));
    try testing.expectEqual(@as(usize, 80), @sizeOf(FbFixScreenInfo));
    // неявные паддинги: mmio_start @56 (после line_length @48 + pad)
    try testing.expectEqual(@as(usize, 56), @offsetOf(FbFixScreenInfo, "mmio_start"));
}

// ─── Тесты: VERSION / CAP ──────────────────────────────────────────────────

test "drm: VERSION — двухфазный протокол libdrm (длины → строки)" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());

    // Фаза 1: null-указатели → ядро возвращает только длины
    var v: DrmVersion = .{};
    const va = FakeEnv.USER_BASE;
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, fakeOps(), DRM_IOCTL_VERSION, va));
    const p = e.vaPtr(va).?;
    const got: *const DrmVersion = @ptrCast(@alignCast(p));
    try testing.expectEqual(@as(i32, 1), got.major);
    try testing.expectEqual(@as(i64, 9), @as(i64, @intCast(got.name_len))); // "poler-drm"
    try testing.expectEqual(@as(i64, 4), @as(i64, @intCast(got.date_len))); // "2026"

    // Фаза 2: буферы → строки записаны в user
    v.name_len = 64;
    v.name_ptr = va + 0x100;
    v.date_len = 64;
    v.date_ptr = va + 0x140;
    v.desc_len = 128;
    v.desc_ptr = va + 0x180;
    @memcpy(e.vaPtr(va).?[0..@sizeOf(DrmVersion)], std.mem.asBytes(&v));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, fakeOps(), DRM_IOCTL_VERSION, va));
    const name = e.vaPtr(va + 0x100).?[0..9];
    try testing.expectEqualStrings("poler-drm", name);
    const date = e.vaPtr(va + 0x140).?[0..4];
    try testing.expectEqualStrings("2026", date);
}

test "drm: GET_CAP — поддержанные капсы; неизвестная → -EINVAL" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const va = FakeEnv.USER_BASE;

    var c: DrmGetCap = .{ .capability = DRM_CAP_DUMB_BUFFER };
    @memcpy(e.vaPtr(va).?[0..16], std.mem.asBytes(&c));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, fakeOps(), DRM_IOCTL_GET_CAP, va));
    const got: *const DrmGetCap = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqual(@as(u64, 1), got.value);

    c.capability = DRM_CAP_DUMB_PREFERRED_DEPTH;
    @memcpy(e.vaPtr(va).?[0..16], std.mem.asBytes(&c));
    _ = drmIoctl(&st, fakeOps(), DRM_IOCTL_GET_CAP, va);
    try testing.expectEqual(@as(u64, 32), got.value);

    c.capability = 0x999;
    @memcpy(e.vaPtr(va).?[0..16], std.mem.asBytes(&c));
    try testing.expectEqual(-linux.EINVAL, drmIoctl(&st, fakeOps(), DRM_IOCTL_GET_CAP, va));

    // SET_MASTER — безаргументный успех
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, fakeOps(), DRM_IOCTL_SET_MASTER, 0));
    // неизвестный ioctl → -EINVAL (ядро DRM Linux)
    try testing.expectEqual(-linux.EINVAL, drmIoctl(&st, fakeOps(), 0xC0DE_6499, va));
}

// ─── Тесты: GETRESOURCES / GETCRTC / GETENCODER / GETCONNECTOR ─────────────

test "drm: GETRESOURCES — 1 CRTC/энкодер/коннектор, id-массивы в user" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const va = FakeEnv.USER_BASE;
    const ids_va = FakeEnv.USER_BASE + 0x200;

    var r: CardRes = .{};
    // входные counts = ёмкость буферов юзера (Linux-семантика: ядро пишет
    // id-массивы ТОЛЬКО если ёмкость вмещает; счётчики обновляет всегда)
    r.count_crtcs = 1;
    r.count_encoders = 1;
    r.count_connectors = 1;
    r.crtc_id_ptr = ids_va;
    r.encoder_id_ptr = ids_va + 4;
    r.connector_id_ptr = ids_va + 8;
    @memcpy(e.vaPtr(va).?[0..64], std.mem.asBytes(&r));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, fakeOps(), DRM_IOCTL_MODE_GETRESOURCES, va));

    const got: *const CardRes = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqual(@as(u32, 1), got.count_crtcs);
    try testing.expectEqual(@as(u32, 1), got.count_encoders);
    try testing.expectEqual(@as(u32, 1), got.count_connectors);
    try testing.expectEqual(@as(u32, 0), got.count_fbs); // ADDFB ещё не было
    const ids = e.vaPtr(ids_va).?;
    try testing.expectEqual(kmsIds()[0], std.mem.readInt(u32, ids[0..4], .little));
    try testing.expectEqual(kmsIds()[1], std.mem.readInt(u32, ids[4..8], .little));
    try testing.expectEqual(kmsIds()[2], std.mem.readInt(u32, ids[8..12], .little));

    // карта неактивна (headless) → render-node: объекты есть, ошибок нет
    var st2 = DrmState{};
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st2, fakeOps(), DRM_IOCTL_MODE_GETRESOURCES, va));
    const r2: *const CardRes = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqual(@as(u32, 1), r2.count_crtcs);
}

test "drm: GETCRTC — mode_valid + modeinfo из геометрии" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const va = FakeEnv.USER_BASE;

    var c: ModeCrtc = .{};
    @memcpy(e.vaPtr(va).?[0..@sizeOf(ModeCrtc)], std.mem.asBytes(&c));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, fakeOps(), DRM_IOCTL_MODE_GETCRTC, va));
    const got: *const ModeCrtc = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqual(@as(u32, 1), got.mode_valid);
    try testing.expectEqual(@as(u32, 640), got.mode.hdisplay);
    try testing.expectEqual(@as(u32, 480), got.mode.vdisplay);
    try testing.expectEqual(@as(u32, 60), got.mode.vrefresh);
    try testing.expectEqual(@as(u32, 256), got.gamma_size);

    // чужой crtc_id → -EINVAL
    c.crtc_id = 99;
    @memcpy(e.vaPtr(va).?[0..@sizeOf(ModeCrtc)], std.mem.asBytes(&c));
    try testing.expectEqual(-linux.EINVAL, drmIoctl(&st, fakeOps(), DRM_IOCTL_MODE_GETCRTC, va));
}

test "drm: GETENCODER + GETCONNECTOR — статусы dumb-KMS" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const va = FakeEnv.USER_BASE;
    const modes_va = FakeEnv.USER_BASE + 0x300;

    var enc: GetEncoder = .{};
    @memcpy(e.vaPtr(va).?[0..20], std.mem.asBytes(&enc));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, fakeOps(), DRM_IOCTL_MODE_GETENCODER, va));
    const ge: *const GetEncoder = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqual(@as(u32, 5), ge.encoder_type); // VIRTUAL
    try testing.expectEqual(@as(u32, 1), ge.possible_crtcs);

    var con: GetConnector = .{};
    con.modes_ptr = modes_va;
    con.count_modes = 1;
    @memcpy(e.vaPtr(va).?[0..80], std.mem.asBytes(&con));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, fakeOps(), DRM_IOCTL_MODE_GETCONNECTOR, va));
    const gc: *const GetConnector = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqual(@as(u32, 15), gc.connector_type); // VIRTUAL
    try testing.expectEqual(@as(u32, 1), gc.count_modes);
    try testing.expectEqual(kmsIds()[1], gc.encoder_id); // привязан к энкодеру
    // modeinfo записан в user-массив (hdisplay — смещение 4, после clock)
    const md = e.vaPtr(modes_va).?;
    try testing.expectEqual(@as(u16, 640), std.mem.readInt(u16, md[4..6], .little));
}

// ─── Тесты: жизненный цикл dumb-буфера ─────────────────────────────────────

test "drm: CREATE→MAP→ADDFB→FLIP→DESTROY — полный жизненный цикл" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const ops = fakeOps();
    const va = FakeEnv.USER_BASE;

    // CREATE_DUMB 320×240×32 → pitch=1280, size=307200 (75 страниц +1).
    // Значения снимаем в ЛОКАЛЫ сразу после ioctl: va перезаписывается
    // следующими структурами (урок CSE: *const-указатель в user-памяти
    // перечитывает СВЕЖИЕ байты).
    var d: CreateDumb = .{ .width = 320, .height = 240, .bpp = 32 };
    @memcpy(e.vaPtr(va).?[0..32], std.mem.asBytes(&d));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, ops, DRM_IOCTL_MODE_CREATE_DUMB, va));
    const gd: *const CreateDumb = @ptrCast(@alignCast(e.vaPtr(va).?));
    const dumb_handle = gd.handle;
    const dumb_pitch = gd.pitch;
    const dumb_size = gd.size;
    try testing.expect(dumb_handle != 0);
    try testing.expectEqual(@as(u32, 1280), dumb_pitch);
    try testing.expectEqual(@as(u64, 307200), dumb_size);
    try testing.expectEqual(@as(usize, 1), e.allocs);

    // MAP_DUMB → апертурный offset, резолвится обратно в буфер
    var m: MapDumb = .{ .handle = dumb_handle };
    @memcpy(e.vaPtr(va).?[0..16], std.mem.asBytes(&m));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, ops, DRM_IOCTL_MODE_MAP_DUMB, va));
    const gm: *const MapDumb = @ptrCast(@alignCast(e.vaPtr(va).?));
    const dumb_offset = gm.offset;
    try testing.expectEqual(apertureOffset(dumb_handle), dumb_offset);
    const buf = lookupAperture(&st, dumb_offset).?;
    try testing.expectEqual(@as(u32, 320), buf.width);
    // lookup с чужим offset → null
    try testing.expect(lookupAperture(&st, dumb_offset + 0x1000) == null);
    try testing.expect(lookupAperture(&st, 0x1000) == null);

    // ADDFB из handle
    var f: FbCmd = .{ .handle = dumb_handle, .width = 320, .height = 240, .pitch = dumb_pitch, .bpp = 32 };
    @memcpy(e.vaPtr(va).?[0..28], std.mem.asBytes(&f));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, ops, DRM_IOCTL_MODE_ADDFB, va));
    const gf: *const FbCmd = @ptrCast(@alignCast(e.vaPtr(va).?));
    const fb_id = gf.fb_id;
    const fb_depth = gf.depth;
    try testing.expect(fb_id != 0);
    try testing.expectEqual(@as(u32, 24), fb_depth);

    // PAGE_FLIP ×2 → flips=2, scanout=fb (crtc_id обязателен, как drmModePageFlip)
    var p: PageFlip = .{ .crtc_id = kmsIds()[0], .fb_id = fb_id };
    @memcpy(e.vaPtr(va).?[0..24], std.mem.asBytes(&p));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, ops, DRM_IOCTL_MODE_PAGE_FLIP, va));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, ops, DRM_IOCTL_MODE_PAGE_FLIP, va));
    try testing.expectEqual(@as(u32, 2), st.flips);
    try testing.expectEqual(fb_id, st.crtc_fb_id);

    // GETRESOURCES теперь видит 1 fb (count_fbs) — читаем копиюбэк из user
    var r: CardRes = .{};
    @memcpy(e.vaPtr(va).?[0..64], std.mem.asBytes(&r));
    _ = drmIoctl(&st, ops, DRM_IOCTL_MODE_GETRESOURCES, va);
    const rback: *const CardRes = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqual(@as(u32, 1), rback.count_fbs);

    // SETCRTC с валидным fb
    var cr: ModeCrtc = .{ .crtc_id = kmsIds()[0], .fb_id = fb_id };
    @memcpy(e.vaPtr(va).?[0..@sizeOf(ModeCrtc)], std.mem.asBytes(&cr));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, ops, DRM_IOCTL_MODE_SETCRTC, va));

    // DESTROY → free_pages вызван
    var dd: DestroyDumb = .{ .handle = dumb_handle };
    @memcpy(e.vaPtr(va).?[0..4], std.mem.asBytes(&dd));
    try testing.expectEqual(@as(i64, 0), drmIoctl(&st, ops, DRM_IOCTL_MODE_DESTROY_DUMB, va));
    try testing.expectEqual(@as(usize, 1), e.frees);
    try testing.expectEqual(@as(u64, 75), e.last_free_pages); // 307200 = ровно 75 страниц
    // повторный destroy → -EINVAL (слот пуст)
    try testing.expectEqual(-linux.EINVAL, drmIoctl(&st, ops, DRM_IOCTL_MODE_DESTROY_DUMB, va));
}

test "drm: CREATE_DUMB — враждебные параметры → -EINVAL/-ENOMEM" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const ops = fakeOps();
    const va = FakeEnv.USER_BASE;

    // bpp != 32
    var d: CreateDumb = .{ .width = 64, .height = 64, .bpp = 16 };
    @memcpy(e.vaPtr(va).?[0..32], std.mem.asBytes(&d));
    try testing.expectEqual(-linux.EINVAL, drmIoctl(&st, ops, DRM_IOCTL_MODE_CREATE_DUMB, va));
    // нулевые размеры
    d = .{ .width = 0, .height = 64, .bpp = 32 };
    @memcpy(e.vaPtr(va).?[0..32], std.mem.asBytes(&d));
    try testing.expectEqual(-linux.EINVAL, drmIoctl(&st, ops, DRM_IOCTL_MODE_CREATE_DUMB, va));
    // гигантский буфер > MAX_DUMB_BYTES → -ENOMEM
    d = .{ .width = 8192, .height = 8192, .bpp = 32 };
    @memcpy(e.vaPtr(va).?[0..32], std.mem.asBytes(&d));
    try testing.expectEqual(-linux.ENOMEM, drmIoctl(&st, ops, DRM_IOCTL_MODE_CREATE_DUMB, va));
    // измерение за лимитом → -EINVAL
    d = .{ .width = 9000, .height = 64, .bpp = 32 };
    @memcpy(e.vaPtr(va).?[0..32], std.mem.asBytes(&d));
    try testing.expectEqual(-linux.EINVAL, drmIoctl(&st, ops, DRM_IOCTL_MODE_CREATE_DUMB, va));
    try testing.expectEqual(@as(usize, 0), e.allocs); // аллокатор не дёргали
}

test "drm: ADDFB/FLIP с мусорными handle/fb → -EINVAL/-ENOENT" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const ops = fakeOps();
    const va = FakeEnv.USER_BASE;

    // ADDFB несуществующий handle → -EINVAL
    var f: FbCmd = .{ .handle = 777, .width = 8, .height = 8, .pitch = 32, .bpp = 32 };
    @memcpy(e.vaPtr(va).?[0..28], std.mem.asBytes(&f));
    try testing.expectEqual(-linux.EINVAL, drmIoctl(&st, ops, DRM_IOCTL_MODE_ADDFB, va));

    // PAGE_FLIP несуществующий fb (crtc корректен) → -ENOENT
    var p: PageFlip = .{ .crtc_id = kmsIds()[0], .fb_id = 555 };
    @memcpy(e.vaPtr(va).?[0..24], std.mem.asBytes(&p));
    try testing.expectEqual(-linux.ENOENT, drmIoctl(&st, ops, DRM_IOCTL_MODE_PAGE_FLIP, va));

    // MAP_DUMB handle=0 → -ENOENT
    var m: MapDumb = .{ .handle = 0 };
    @memcpy(e.vaPtr(va).?[0..16], std.mem.asBytes(&m));
    try testing.expectEqual(-linux.ENOENT, drmIoctl(&st, ops, DRM_IOCTL_MODE_MAP_DUMB, va));
}

// ─── Тесты: враждебные указатели (инвариант нуля паник) ────────────────────

test "drm: мусорный arg-VA → -EFAULT на всех ioctl (ноль паник)" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const ops = fakeOps();

    const cmds = [_]u32{
        DRM_IOCTL_VERSION,
        DRM_IOCTL_GET_CAP,
        DRM_IOCTL_MODE_GETRESOURCES,
        DRM_IOCTL_MODE_GETCRTC,
        DRM_IOCTL_MODE_GETENCODER,
        DRM_IOCTL_MODE_GETCONNECTOR,
        DRM_IOCTL_MODE_CREATE_DUMB,
        DRM_IOCTL_MODE_MAP_DUMB,
        DRM_IOCTL_MODE_DESTROY_DUMB,
        DRM_IOCTL_MODE_ADDFB,
        DRM_IOCTL_MODE_PAGE_FLIP,
    };
    // «край» региона: любая структура ≥2Б пересекает границу
    const bad_vas = [_]u64{ 0, 0xFFFF_8000_0000_0000, 0x30000_0000, FakeEnv.USER_BASE + FakeEnv.USER_LEN - 1 };
    for (cmds) |cmd| {
        for (bad_vas) |va| {
            const r = drmIoctl(&st, ops, cmd, va);
            try testing.expectEqual(-linux.EFAULT, r);
        }
    }
    // частичный заход за границу fake-региона (64Б-структура на краю)
    try testing.expectEqual(-linux.EFAULT, drmIoctl(&st, ops, DRM_IOCTL_VERSION, FakeEnv.USER_BASE + FakeEnv.USER_LEN - 8));
}

// ─── Тесты: fbdev /dev/fb0 ─────────────────────────────────────────────────

test "drm: fb0 — VSCREENINFO/FSCREENINFO из геометрии; PUT идентичной = 0" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{};
    initLinearFb(&st, geom640());
    const ops = fakeOps();
    const va = FakeEnv.USER_BASE;

    // GET var
    try testing.expectEqual(@as(i64, 0), fbIoctl(&st, ops, FBIOGET_VSCREENINFO, va));
    const v: *const FbVarScreenInfo = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqual(@as(u32, 640), v.xres);
    try testing.expectEqual(@as(u32, 480), v.yres);
    try testing.expectEqual(@as(u32, 32), v.bits_per_pixel);
    try testing.expectEqual(@as(u32, 16), v.red.offset);
    try testing.expectEqual(@as(u32, 8), v.red.length);
    try testing.expectEqual(@as(u32, 0), v.blue.offset);

    // PUT той же геометрии → 0
    var put: FbVarScreenInfo = v.*;
    @memcpy(e.vaPtr(va).?[0..160], std.mem.asBytes(&put));
    try testing.expectEqual(@as(i64, 0), fbIoctl(&st, ops, FBIOPUT_VSCREENINFO, va));

    // PUT чужой геометрии → -EINVAL (режим не переключается fbdev-ом)
    put.xres = 1920;
    @memcpy(e.vaPtr(va).?[0..160], std.mem.asBytes(&put));
    try testing.expectEqual(-linux.EINVAL, fbIoctl(&st, ops, FBIOPUT_VSCREENINFO, va));

    // GET fix
    @memset(e.mem, 0);
    try testing.expectEqual(@as(i64, 0), fbIoctl(&st, ops, FBIOGET_FSCREENINFO, va));
    const fix: *const FbFixScreenInfo = @ptrCast(@alignCast(e.vaPtr(va).?));
    try testing.expectEqualStrings("poler-fb0", fix.id[0..9]);
    try testing.expectEqual(@as(u64, 0xFD00_0000), fix.smem_start);
    try testing.expectEqual(@as(u32, 2560), fix.line_length);
    try testing.expectEqual(@as(u32, 2), fix.visual); // TRUECOLOR
    // PUT fix → -EPERM (RO)
    try testing.expectEqual(-linux.EPERM, fbIoctl(&st, ops, FBIOPUT_FSCREENINFO, va));
    // неизвестный fb-ioctl → -EINVAL
    try testing.expectEqual(-linux.EINVAL, fbIoctl(&st, ops, 0x4699, va));
}

test "drm: fb0 без карты → -ENODEV; devfs-резолв путей" {
    const e = try envSetup();
    defer envTeardown(e);
    var st = DrmState{}; // inactive
    try testing.expectEqual(-linux.ENODEV, fbIoctl(&st, fakeOps(), FBIOGET_VSCREENINFO, FakeEnv.USER_BASE));

    // файловый фасад: «Всё есть файл»
    try testing.expectEqual(DevKind.fb0, resolveDevPath("/dev/fb0"));
    try testing.expectEqual(DevKind.dri_card0, resolveDevPath("/dev/dri/card0"));
    try testing.expectEqual(DevKind.dri_render, resolveDevPath("/dev/dri/renderD128"));
    try testing.expect(resolveDevPath("/dev/fb1") == null);
    try testing.expect(resolveDevPath("/dev/dri/card1") == null);
    try testing.expect(resolveDevPath("/etc/passwd") == null);
}

// ─── Тесты: WC/PAT-семантика ───────────────────────────────────────────────

test "drm: PAT Linux-раскладка — PWT-бит выбирает WC-страницу" {
    // значение MSR 0x277 (байты PA0..PA7):
    //   PA0=WB PA1=WC PA2=UC- PA3=UC PA4=WB PA5=WC PA6=UC- PA7=UC
    const pat: [8]u64 = blk: {
        var b: [8]u64 = undefined;
        var msr = PAT_LINUX_WC;
        for (0..8) |i| {
            b[i] = msr & 0xFF; // младший байт MSR = PA0 (LSB-первый)
            msr >>= 8;
        }
        break :blk b;
    };
    // PA1 (PWT=1,PCD=0,PAT=0) = 0x01 = WC — память типа Write-Combining
    try testing.expectEqual(@as(u64, 0x01), pat[1]);
    try testing.expectEqual(@as(u64, 0x06), pat[0]); // PA0 = WB
    try testing.expectEqual(@as(u64, 0x00), pat[3]); // PA3 = UC
    // PTE_WC = PWT-бит — после PAT-записи страницы фреймбуфера с ним = WC
    try testing.expectEqual(@as(u64, 0x08), PTE_WC);
}

test "drm: geomModeinfo — vrefresh/флаги/имя-разрешение" {
    const m = geomModeinfo(geom640());
    try testing.expectEqual(@as(u16, 640), m.hdisplay);
    try testing.expectEqual(@as(u16, 480), m.vdisplay);
    try testing.expectEqual(@as(u16, 800), m.htotal); // 640+160
    try testing.expectEqual(@as(u16, 520), m.vtotal); // 480+40
    try testing.expectEqual(@as(u32, 60), m.vrefresh);
    try testing.expectEqual(DRM_MODE_TYPE_DRIVER, m.mtype);
    const name = m.name[0..(std.mem.indexOfScalar(u8, &m.name, 0) orelse 32)];
    try testing.expectEqualStrings("640x480", name);
}
