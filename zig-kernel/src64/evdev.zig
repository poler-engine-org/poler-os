// ============================================================================
// POLER-OS evdev.zig — подсистема ввода Evdev (v0.19.0, CDD №10, шаг 2)
// ============================================================================
//
// «Всё есть файл»: мышь и клавиатура = /dev/input/event0 и /dev/input/event1.
// Чтение ввода = sys_read потока struct input_event (24Б: timeval + type +
// code + value). Мультиплексирование = poll/epoll (шаг 3), неблокирующее
// чтение = O_NONBLOCK → -EAGAIN.
//
// UAPI-СОВМЕСТИМОСТЬ (include/uapi/linux/input.h + input-event-codes.h):
//   struct input_event = 24Б на x86_64 (timeval 16Б: sec/usec i64);
//   EVIOCGVERSION/EVIOCGID/EVIOCGNAME/EVIOCGBIT — кодируются с базой 'E'
//   (0x45) — тесты сверяют с реальными значениями Linux (libevdev/strace).
//
// МОДЕЛЬ (Starnix-прецедент): очереди/парсеры/таблицы — ЧИСТЫЕ (нативные
// тесты), интеграция с IRQ (PS/2 клавиатура вектор 33, PS/2 мышь вектор 44)
// — в hal.zig, устройства-синглтоны — hal-глобалы (push из IRQ-контекста,
// атомарность гарантирует cli/sti вызывающего).
//
// Инвариант CDD №10: враждебный ввод (мусорный count, битые пакеты мыши)
// → errno/дроп, НЕ паника ядра.
// ============================================================================

const std = @import("std");
const testing = std.testing;
const linux = @import("linux_syscalls.zig");

// ─── IOC-кодирование (база 'E' = 0x45) ─────────────────────────────────────

pub const EV_IOC_BASE: u32 = 0x45; // 'E'
pub const IOC_READ: u32 = 2;

pub inline fn evIoc(nr: u32, size: u32) u32 {
    return (IOC_READ << 30) | (size << 16) | (EV_IOC_BASE << 8) | nr;
}

/// EVIOCGVERSION — _IOR('E', 0x01, int)
pub const EVIOCGVERSION: u32 = evIoc(0x01, 4);
/// EVIOCGID — _IOR('E', 0x02, struct input_id)
pub const EVIOCGID: u32 = evIoc(0x02, 8);
/// EVIOCGNAME(len) — _IOC(_IOC_READ, 'E', 0x06, len): ВАРИАБЕЛЬНАЯ длина
pub inline fn EVIOCGNAME(len: u32) u32 {
    return evIoc(0x06, len);
}
/// EVIOCGBIT(ev, len) — _IOC(_IOC_READ, 'E', 0x20 + ev, len)
pub inline fn EVIOCGBIT(ev: u2, len: u32) u32 {
    return evIoc(0x20 + @as(u32, ev), len);
}

/// EV_VERSION из linux/input.h: 1.0.1
pub const EV_VERSION: i32 = 0x010001;

// ─── UAPI-структуры (input.h, x86_64) ──────────────────────────────────────

/// struct input_id (8Б)
pub const InputId = extern struct {
    bustype: u16 = 0,
    vendor: u16 = 0,
    product: u16 = 0,
    version: u16 = 0,
};

/// struct timeval glibc x86_64 (16Б: __time_t i64 + __suseconds_t i64)
pub const Timeval = extern struct {
    sec: i64 = 0,
    usec: i64 = 0,
};

/// struct input_event (24Б на x86_64)
pub const InputEvent = extern struct {
    time: Timeval = .{},
    type_: u16 = 0,
    code: u16 = 0,
    value: i32 = 0,
};

// ─── Коды событий (input-event-codes.h) ────────────────────────────────────

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;

pub const SYN_REPORT: u16 = 0;

pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_WHEEL: u16 = 0x08;

pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x112;
pub const BTN_MIDDLE: u16 = 0x111;

// Клавиатура (подмножество, PS/2 Set1-диапазон 0x01..0x39 = 1..57)
pub const KEY_ESC: u16 = 1;
pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_LEFTALT: u16 = 56;
pub const KEY_SPACE: u16 = 57;
// E0-расширенные
pub const KEY_UP: u16 = 103;
pub const KEY_DOWN: u16 = 108;
pub const KEY_LEFT: u16 = 105;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_RIGHTCTRL: u16 = 97;
pub const KEY_RIGHTSHIFT: u16 = 54;

/// BUS_VIRTUAL (input.h) — виртуальная шина POLER-OS
pub const BUS_VIRTUAL: u16 = 0x06;

// ─── Устройство evdev: кольцевая очередь событий ───────────────────────────

pub const QUEUE_LEN: usize = 128;
/// sizeof(input_event) — гранулярность чтения
pub const EVENT_SIZE: usize = @sizeOf(InputEvent);

/// PS/2 мышиный пакет → дельты/кнопки (после разбора 3 байтов).
pub const MouseDelta = struct {
    dx: i32 = 0,
    dy: i32 = 0,
    left: bool = false,
    right: bool = false,
    middle: bool = false,
    /// Пакет невалиден (овфлоу X/Y) — дроп, НЕ паника.
    valid: bool = true,
};

pub const Evdev = struct {
    id: InputId = .{},
    name_buf: [32]u8 = .{0} ** 32,
    name_len: usize = 0,
    /// Битовая маска поддержанных ТИПОВ событий (EV_SYN/EV_KEY/EV_REL)
    ev_bits: u32 = 0,
    /// Битовая маска REL-кодов (REL_X=0, REL_Y=1, REL_WHEEL=8)
    rel_bits: u32 = 0,
    /// Битовая маска KEY/BTN-кодов: 12 слов = 384 бита (до кода 0x17F —
    /// покрывает BTN_MOUSE 0x110-0x112 и всю клавиатуру)
    key_bits: [12]u32 = .{0} ** 12,
    // Очередь: SPSC (producer — IRQ hal, consumer — sys_read)
    q: [QUEUE_LEN]InputEvent = [_]InputEvent{.{}} ** QUEUE_LEN,
    head: u16 = 0, // чтение
    tail: u16 = 0, // запись
    /// Счётчик дропов при переполнении (E2E-наблюдаемо)
    dropped: u32 = 0,
    /// Счётчик отданных событий
    delivered: u32 = 0,

    /// Очистить (реинициализация устройства).
    pub fn reset(self: *Evdev) void {
        self.head = 0;
        self.tail = 0;
        self.dropped = 0;
        self.delivered = 0;
    }

    /// Событий в очереди (консистентный срез: считаем от снапшотов).
    pub fn pending(self: *const Evdev) usize {
        const t: u32 = self.tail;
        const h: u32 = self.head;
        if (t >= h) return t - h;
        return QUEUE_LEN - (h - t);
    }

    /// Записать событие в очередь (из IRQ — вызывающий гарантирует
    /// атомарность cli/sti). Переполнение → дроп (счётчик), НЕ паника.
    pub fn push(self: *Evdev, ev: InputEvent) void {
        const next: u16 = @intCast((@as(u32, self.tail) + 1) % QUEUE_LEN);
        if (next == self.head) {
            // Полная: дроп (классика — теряем СТАРОЕ, читатель догоняет)
            self.dropped += 1;
            return;
        }
        self.q[self.tail] = ev;
        self.tail = next;
    }

    /// EV_KEY-событие (value: 1 нажатие / 0 отпускание / 2 автоповтор).
    pub fn pushKey(self: *Evdev, code: u16, value: i32) void {
        self.push(.{ .type_ = EV_KEY, .code = code, .value = value });
    }

    /// EV_REL-событие (относительная дельта оси).
    pub fn pushRel(self: *Evdev, code: u16, value: i32) void {
        self.push(.{ .type_ = EV_REL, .code = code, .value = value });
    }

    /// SYN_REPORT — терминатор пакета (после пачки мыши/клавиши).
    pub fn pushSyn(self: *Evdev) void {
        self.push(.{ .type_ = EV_SYN, .code = SYN_REPORT, .value = 0 });
    }

    /// Прочитать до out.len событий (FIFO). Возвращает число скопированных.
    pub fn drain(self: *Evdev, out: []InputEvent) usize {
        var n: usize = 0;
        while (n < out.len and self.head != self.tail) {
            out[n] = self.q[self.head];
            self.head = @intCast((@as(u32, self.head) + 1) % QUEUE_LEN);
            n += 1;
            self.delivered += 1;
        }
        return n;
    }

    /// Семантика read(2) на /dev/input/eventN: буфер кратен 24Б → возвращает
    /// ЧИСЛО БАЙТОВ (полные события), пусто + nonblock → -EAGAIN,
    /// count < 24 → -EINVAL (ядро Linux читает только целые события).
    pub fn readBytes(self: *Evdev, out: []u8, nonblock: bool) i64 {
        if (out.len < EVENT_SIZE) return -linux.EINVAL;
        if (self.head == self.tail) {
            return if (nonblock) -linux.EAGAIN else 0;
        }
        // floor до целых событий
        const n_events_max = out.len / EVENT_SIZE;
        var tmp: [QUEUE_LEN]InputEvent = undefined;
        const n = self.drain(tmp[0..n_events_max]);
        if (n == 0) return if (nonblock) -linux.EAGAIN else 0;
        const p: [*]u8 = out.ptr;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            @memcpy(p[i * EVENT_SIZE ..][0..EVENT_SIZE], std.mem.asBytes(&tmp[i]));
        }
        return @intCast(n * EVENT_SIZE);
    }
};

// ─── Инициализация устройств-прототипов ────────────────────────────────────

/// Клавиатура /dev/input/event0: PS/2, Set1.
pub fn initKeyboard(dev: *Evdev) void {
    dev.* = .{};
    dev.id = .{ .bustype = BUS_VIRTUAL, .vendor = 0x1A4F, .product = 0x0001, .version = 0x0100 };
    const name = "POLER-PS/2-Keyboard";
    @memcpy(dev.name_buf[0..name.len], name);
    dev.name_len = name.len;
    dev.ev_bits = (@as(u32, 1) << EV_SYN) | (@as(u32, 1) << EV_KEY);
    // Поддержанные клавиши: весь Set1-диапазон 0x01..0x39 + E0-стрелки
    var code: u16 = 1;
    while (code <= 57) : (code += 1) {
        dev.key_bits[code / 32] |= @as(u32, 1) << @intCast(code % 32);
    }
    for ([_]u16{ KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT, KEY_RIGHTCTRL, KEY_RIGHTSHIFT }) |kc| {
        dev.key_bits[kc / 32] |= @as(u32, 1) << @intCast(kc % 32);
    }
}

/// Мышь /dev/input/event1: PS/2, 3-байтный относительный протокол.
pub fn initMouse(dev: *Evdev) void {
    dev.* = .{};
    dev.id = .{ .bustype = BUS_VIRTUAL, .vendor = 0x1A4F, .product = 0x0002, .version = 0x0100 };
    const name = "POLER-PS/2-Mouse";
    @memcpy(dev.name_buf[0..name.len], name);
    dev.name_len = name.len;
    dev.ev_bits = (@as(u32, 1) << EV_SYN) | (@as(u32, 1) << EV_KEY) | (@as(u32, 1) << EV_REL);
    dev.rel_bits = (@as(u32, 1) << @intCast(REL_X)) | (@as(u32, 1) << @intCast(REL_Y)) | (@as(u32, 1) << @intCast(REL_WHEEL));
    for ([_]u16{ BTN_LEFT, BTN_MIDDLE, BTN_RIGHT }) |bc| {
        dev.key_bits[bc / 32] |= @as(u32, 1) << @intCast(bc % 32);
    }
}

// ─── PS/2 Set1 → Linux KEY-* (таблица — история XT-кодов почти 1:1) ────────

/// Сканкод Set1 (без E0-префикса, бит7 = отпускание снят вызывающим) →
/// Linux KEY_*. 0 = не-клавиша (PAUSE-разрывы и пр.). Базовый блок 0x01-0x39
/// исторически СОВПАДАЕТ с Linux-кодами (XT-наследие); E0-кнопки — расширенные.
pub fn set1ToKeyCode(scan: u8) u16 {
    if (scan >= 1 and scan <= 57) return scan; // XT-блок 1:1
    if (scan == 0x5B) return 0; // PAUSE-разрыв — обслуживает E0-путь
    return 0;
}

/// E0-расширенный сканкод → Linux KEY_* (стрелки, RCtrl/RShift-ряд).
pub fn set1ExtToKeyCode(scan: u8) u16 {
    return switch (scan) {
        0x48 => KEY_UP,
        0x50 => KEY_DOWN,
        0x4B => KEY_LEFT,
        0x4D => KEY_RIGHT,
        0x1D => KEY_RIGHTCTRL,
        0x36 => KEY_RIGHTSHIFT,
        else => 0,
    };
}

// ─── PS/2 мышиный пакет (3 байта) → дельты ─────────────────────────────────

/// Классический 3-байтный протокол PS/2 мыши:
///   byte0: Yovf Xovf Ysign Xsign 1 middle right left
///   byte1: X-дельта (доплнение до 2 при Xsign)
///   byte2: Y-дельта (оси Y инвертирована Экраном: отрицательное = вверх)
pub fn parseMousePacket(b0: u8, b1: u8, b2: u8) MouseDelta {
    const ovf = (b0 & 0xC0) != 0;
    const x_sign = (b0 & 0x10) != 0;
    const y_sign = (b0 & 0x20) != 0;
    var dx: i32 = @as(i32, b1);
    var dy: i32 = @as(i32, b2);
    if (x_sign) dx -= 256;
    if (y_sign) dy -= 256;
    // Экранная ось Y растёт ВНИЗ, мышиная — ВВЕРХ: инверсия (Linux evdev
    // отдаёт СЫРЫЕ дельты протокола; libinput инвертирует) — храним raw.
    return .{
        .dx = dx,
        .dy = dy,
        .left = (b0 & 0x01) != 0,
        .right = (b0 & 0x02) != 0,
        .middle = (b0 & 0x04) != 0,
        .valid = !ovf,
    };
}

/// Кнопки MouseDelta → битмаска u3 (left=1, right=2, middle=4) — для
/// отслеживания состояния вызывающим (hal IRQ-путь).
pub fn buttonsOf(md: MouseDelta) u3 {
    return @intCast(@as(u32, @intFromBool(md.left)) | (@as(u32, @intFromBool(md.right)) << 1) | (@as(u32, @intFromBool(md.middle)) << 2));
}

/// Загнать мышиный пакет в evdev-очередь (REL + BTN + SYN_REPORT).
/// Некорректный пакет (овфлоу) → дроп.
pub fn mousePacketToEvents(dev: *Evdev, md: MouseDelta, buttons_prev: u3) void {
    if (!md.valid) {
        dev.dropped += 1;
        return;
    }
    if (md.dx != 0) dev.pushRel(REL_X, md.dx);
    if (md.dy != 0) dev.pushRel(REL_Y, md.dy);
    // Кнопки: только ИЗМЕНЕНИЯ (классика evdev — value = 1/0 при переходе)
    const cur: u3 = @intCast(@as(u32, @intFromBool(md.left)) | (@as(u32, @intFromBool(md.right)) << 1) | (@as(u32, @intFromBool(md.middle)) << 2));
    if ((cur & 1) != (buttons_prev & 1)) dev.pushKey(BTN_LEFT, @intFromBool(md.left));
    if ((cur & 2) != (buttons_prev & 2)) dev.pushKey(BTN_RIGHT, @intFromBool(md.right));
    if ((cur & 4) != (buttons_prev & 4)) dev.pushKey(BTN_MIDDLE, @intFromBool(md.middle));
    dev.pushSyn();
}

// ─── Файловый фасад: пути /dev/input ───────────────────────────────────────

pub const DevKind = enum {
    event0_kbd,
    event1_mouse,
};

pub fn resolveDevPath(path: []const u8) ?DevKind {
    if (std.mem.eql(u8, path, "/dev/input/event0")) return .event0_kbd;
    if (std.mem.eql(u8, path, "/dev/input/event1")) return .event1_mouse;
    return null;
}

// ─── evdev ioctl: чистые обработчики (буферы вызывающего) ──────────────────

/// Обработчик ioctl на /dev/input/eventN. out — буфер вызывающего (fd-слой
/// шага 3 копирует в user). Возвращает 0/-errno.
pub fn ioctlEvdev(dev: *const Evdev, cmd: u32, out: []u8) i64 {
    switch (cmd) {
        EVIOCGVERSION => {
            if (out.len < 4) return -linux.EINVAL;
            std.mem.writeInt(i32, out[0..4], EV_VERSION, .little);
            return 0;
        },
        EVIOCGID => {
            if (out.len < @sizeOf(InputId)) return -linux.EINVAL;
            std.mem.writeInt(u16, out[0..2], dev.id.bustype, .little);
            std.mem.writeInt(u16, out[2..4], dev.id.vendor, .little);
            std.mem.writeInt(u16, out[4..6], dev.id.product, .little);
            std.mem.writeInt(u16, out[6..8], dev.id.version, .little);
            return 0;
        },
        else => {
            // ВАРИАБЕЛЬНО-длинные: EVIOCGNAME(len)/EVIOCGBIT(ev, len) —
            // размер сидит в бите 29..16 команды
            const size = (cmd >> 16) & 0x3FFF;
            const nr = cmd & 0xFF;
            const dir = (cmd >> 30) & 3;
            if (dir != IOC_READ or cmd & 0xFF00 != EV_IOC_BASE << 8) return -linux.ENOTTY;
            if (out.len < size) return -linux.EINVAL;
            if (nr == 0x06) { // EVIOCGNAME
                const n = @min(@as(usize, @intCast(size)), dev.name_len + 1); // +1 нуль
                @memcpy(out[0..n], dev.name_buf[0..n]);
                if (size > 0) out[@min(n, @as(usize, @intCast(size)) - 1)] = 0;
                return @intCast(n);
            }
            if (nr >= 0x20 and nr <= 0x23) { // EVIOCGBIT(ev, len): ev = nr-0x20
                const ev: u16 = @intCast(nr - 0x20);
                var filled: usize = 0;
                switch (ev) {
                    0 => { // битмап ТИПОВ
                        if (size >= 4) {
                            std.mem.writeInt(u32, out[0..4], dev.ev_bits, .little);
                            filled = 4;
                        }
                    },
                    EV_REL => {
                        if (size >= 4) {
                            std.mem.writeInt(u32, out[0..4], dev.rel_bits, .little);
                            filled = 4;
                        }
                    },
                    EV_KEY => {
                        // битмап клавиш: min(size, 48Б) из key_bits
                        const n = @min(@as(usize, @intCast(size)), @sizeOf(@TypeOf(dev.key_bits)));
                        var off: usize = 0;
                        while (off < n) : (off += 4) {
                            std.mem.writeInt(u32, out[off..][0..4], dev.key_bits[off / 4], .little);
                        }
                        filled = n;
                    },
                    else => {},
                }
                return @intCast(filled);
            }
            return -linux.ENOTTY;
        },
    }
}

// ============================================================================
//  Нативные тесты
// ============================================================================

test "evdev: UAPI-якоря — sizeof input_event 24Б, input_id 8Б, timeval 16Б" {
    try testing.expectEqual(@as(usize, 24), @sizeOf(InputEvent));
    try testing.expectEqual(@as(usize, 8), @sizeOf(InputId));
    try testing.expectEqual(@as(usize, 16), @sizeOf(Timeval));
    // раскладка input_event: type @16, code @18, value @20
    try testing.expectEqual(@as(usize, 16), @offsetOf(InputEvent, "type_"));
    try testing.expectEqual(@as(usize, 18), @offsetOf(InputEvent, "code"));
    try testing.expectEqual(@as(usize, 20), @offsetOf(InputEvent, "value"));
}

test "evdev: ioctl-номера = реальные значения Linux (libevdev/strace)" {
    try testing.expectEqual(@as(u32, 0x8004_4501), EVIOCGVERSION); // _IOR('E',1,int)
    try testing.expectEqual(@as(u32, 0x8008_4502), EVIOCGID); // _IOR('E',2,input_id)
    try testing.expectEqual(@as(u32, 0x8020_4506), EVIOCGNAME(32)); // имя 32Б
    try testing.expectEqual(@as(u32, 0x8130_4506), EVIOCGNAME(304)); // libevdev full
    try testing.expectEqual(@as(u32, 0x8130_4521), EVIOCGBIT(1, 304)); // key-битмап libevdev
    try testing.expectEqual(@as(u32, 0x8004_4520), EVIOCGBIT(0, 4)); // ev-типы
    try testing.expectEqual(@as(u32, 0x8008_4521), EVIOCGBIT(1, 8)); // key-биты
    try testing.expectEqual(@as(u32, 0x8008_4522), EVIOCGBIT(2, 8)); // rel-биты
}

test "evdev: очередь — FIFO, pending/drain, pushKey/pushSyn" {
    var dev = Evdev{};
    initKeyboard(&dev);

    try testing.expectEqual(@as(usize, 0), dev.pending());
    dev.pushKey(KEY_A_KC, 1);
    dev.pushSyn();
    dev.pushKey(KEY_A_KC, 0);
    dev.pushSyn();
    try testing.expectEqual(@as(usize, 4), dev.pending());

    var out: [4]InputEvent = undefined;
    const n = dev.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqual(@as(usize, 0), dev.pending());
    // FIFO: первое — нажатие
    try testing.expectEqual(EV_KEY, out[0].type_);
    try testing.expectEqual(KEY_A_KC, out[0].code);
    try testing.expectEqual(@as(i32, 1), out[0].value);
    // второе — SYN_REPORT
    try testing.expectEqual(EV_SYN, out[1].type_);
    // третье — отпускание
    try testing.expectEqual(@as(i32, 0), out[2].value);
    try testing.expectEqual(@as(u32, 4), dev.delivered);
}

const KEY_A_KC: u16 = 30; // KEY_A

test "evdev: readBytes — кратность 24, -EAGAIN, -EINVAL, частичный буфер" {
    var dev = Evdev{};
    initKeyboard(&dev);

    // пусто + O_NONBLOCK → -EAGAIN
    var buf: [EVENT_SIZE * 3]u8 = undefined;
    try testing.expectEqual(-linux.EAGAIN, dev.readBytes(&buf, true));
    // пусто + блокирующий → 0
    try testing.expectEqual(@as(i64, 0), dev.readBytes(&buf, false));
    // буфер < 24 → -EINVAL (даже с событиями)
    var small: [16]u8 = undefined;
    try testing.expectEqual(-linux.EINVAL, dev.readBytes(&small, true));

    // 3 события в очереди, буфер на 2.5 события (60Б) → 2 события = 48Б
    dev.pushKey(KEY_A_KC, 1);
    dev.pushSyn();
    dev.pushKey(KEY_A_KC, 0);
    dev.pushSyn(); // 4 события
    var partial: [EVENT_SIZE * 2 + 12]u8 = undefined;
    const r = dev.readBytes(&partial, false);
    try testing.expectEqual(@as(i64, 48), r); // floor(60/24)=2 события
    // байты 0..24 = первое событие (EV_KEY/KEY_A/1)
    try testing.expectEqual(EV_KEY, std.mem.readInt(u16, partial[16..18], .little));
    try testing.expectEqual(@as(i32, 1), @as(i32, @bitCast(std.mem.readInt(u32, partial[20..24], .little))));
    // осталось 2 события
    try testing.expectEqual(@as(usize, 2), dev.pending());
}

test "evdev: переполнение очереди → дроп-счётчик, НЕ паника" {
    var dev = Evdev{};
    initMouse(&dev);
    // QUEUE_LEN-1 влезает (одно место тратится на различие head/tail)
    var i: usize = 0;
    while (i < QUEUE_LEN + 50) : (i += 1) {
        dev.pushRel(REL_X, 1);
    }
    try testing.expectEqual(@as(usize, 51), dev.dropped);
    try testing.expectEqual(@as(usize, QUEUE_LEN - 1), dev.pending());
    // очередь по-прежнему читается
    var out: [QUEUE_LEN]InputEvent = undefined;
    const n = dev.drain(&out);
    try testing.expectEqual(@as(usize, QUEUE_LEN - 1), n);
}

test "evdev: set1ToKeyCode — XT-блок 1:1; расширенные E0-коды" {
    // Базовый блок исторически совпадает с Linux KEY_*
    try testing.expectEqual(@as(u16, 1), set1ToKeyCode(0x01)); // ESC → KEY_ESC
    try testing.expectEqual(@as(u16, 28), set1ToKeyCode(0x1C)); // Enter
    try testing.expectEqual(@as(u16, 42), set1ToKeyCode(0x2A)); // LShift
    try testing.expectEqual(@as(u16, 57), set1ToKeyCode(0x39)); // Space
    try testing.expectEqual(@as(u16, 0), set1ToKeyCode(0x00));
    try testing.expectEqual(@as(u16, 0), set1ToKeyCode(0x58)); // вне таблицы
    // E0-расширенные
    try testing.expectEqual(KEY_UP, set1ExtToKeyCode(0x48));
    try testing.expectEqual(KEY_DOWN, set1ExtToKeyCode(0x50));
    try testing.expectEqual(KEY_LEFT, set1ExtToKeyCode(0x4B));
    try testing.expectEqual(KEY_RIGHT, set1ExtToKeyCode(0x4D));
    try testing.expectEqual(KEY_RIGHTCTRL, set1ExtToKeyCode(0x1D));
    try testing.expectEqual(@as(u16, 0), set1ExtToKeyCode(0x1F));
}

test "evdev: parseMousePacket — знаковые дельты, кнопки, овфлоу-дроп" {
    // dx=+2, dy=-5 (Ysign), left+middle
    const md = parseMousePacket(0x05 | 0x20, 0x02, 0xFB);
    try testing.expectEqual(@as(i32, 2), md.dx);
    try testing.expectEqual(@as(i32, -5), md.dy);
    try testing.expect(md.left);
    try testing.expect(md.middle);
    try testing.expect(!md.right);
    try testing.expect(md.valid);

    // без знаков: сырые беззнаковые дельты (dx=255, dy=251)
    const md2 = parseMousePacket(0x09, 0xFF, 0xFB);
    try testing.expectEqual(@as(i32, 255), md2.dx);
    try testing.expectEqual(@as(i32, 251), md2.dy);

    // овфлоу-биты (0x40/0x80) → invalid
    const md3 = parseMousePacket(0x09 | 0x40, 0x02, 0x02);
    try testing.expect(!md3.valid);
    // right-only
    const md4 = parseMousePacket(0x0A, 0, 0);
    try testing.expect(md4.right);
    try testing.expect(!md4.left);
}

test "evdev: mousePacketToEvents — REL + только ИЗМЕНЁННЫЕ кнопки + SYN" {
    var dev = Evdev{};
    initMouse(&dev);

    // первый пакет: dx=3, dy=-2, left нажата
    const md1 = parseMousePacket(0x08 | 0x20 | 0x01, 0x03, 0xFE);
    mousePacketToEvents(&dev, md1, 0);
    // REL_X, REL_Y, BTN_LEFT(1), SYN = 4 события
    try testing.expectEqual(@as(usize, 4), dev.pending());

    // второй пакет: та же кнопка зажата (без изменений) → только REL+SYN
    const md2 = parseMousePacket(0x08 | 0x20 | 0x01, 0x01, 0x01);
    mousePacketToEvents(&dev, md2, 1);
    try testing.expectEqual(@as(usize, 7), dev.pending()); // +3 (REL_Y? нет: dy=1 → +REL_Y+SYN... )
    // пересчёт: dx=1 dy=1 → REL_X+REL_Y+SYN = 3

    // третий: отпустили left (b0 без знаков — dx=dy=0) → BTN_LEFT(0)+SYN
    const md3 = parseMousePacket(0x08, 0, 0);
    mousePacketToEvents(&dev, md3, 1);
    // dx=dy=0 → только BTN_LEFT(0)+SYN = 2
    try testing.expectEqual(@as(usize, 9), dev.pending());

    // некорректный (овфлоу) → дроп
    const md4 = parseMousePacket(0x40, 0, 0);
    mousePacketToEvents(&dev, md4, 0);
    try testing.expectEqual(@as(usize, 9), dev.pending());
    try testing.expectEqual(@as(u32, 1), dev.dropped);
}

test "evdev: ioctlEvdev — VERSION/ID/NAME/BIT; чужая команда → -ENOTTY" {
    var dev = Evdev{};
    initKeyboard(&dev);

    var buf: [64]u8 = .{0} ** 64;
    try testing.expectEqual(@as(i64, 0), ioctlEvdev(&dev, EVIOCGVERSION, buf[0..4]));
    try testing.expectEqual(EV_VERSION, std.mem.readInt(i32, buf[0..4], .little));

    try testing.expectEqual(@as(i64, 0), ioctlEvdev(&dev, EVIOCGID, buf[0..8]));
    try testing.expectEqual(BUS_VIRTUAL, std.mem.readInt(u16, buf[0..2], .little));

    // имя: EVIOCGNAME(32) → возвращает длину с нулём, буфер заполнен
    const r = ioctlEvdev(&dev, EVIOCGNAME(32), buf[0..32]);
    try testing.expectEqual(@as(i64, 20), r); // "POLER-PS/2-Keyboard" 19 + 1
    try testing.expectEqualStrings("POLER-PS/2-Keyboard", buf[0..19]);
    try testing.expectEqual(@as(u8, 0), buf[19]);

    // EVIOCGBIT(0, 4): типы SYN|KEY
    try testing.expectEqual(@as(i64, 4), ioctlEvdev(&dev, EVIOCGBIT(0, 4), buf[0..4]));
    const evbits = std.mem.readInt(u32, buf[0..4], .little);
    try testing.expect(evbits & (@as(u32, 1) << EV_SYN) != 0);
    try testing.expect(evbits & (@as(u32, 1) << EV_KEY) != 0);
    try testing.expect(evbits & (@as(u32, 1) << EV_REL) == 0); // клавиатура без REL

    // EVIOCGBIT(1, 48) для МЫШИ: BTN_LEFT бит установлен (код 0x110)
    var mouse = Evdev{};
    initMouse(&mouse);
    var kbuf: [48]u8 = .{0} ** 48;
    _ = ioctlEvdev(&mouse, EVIOCGBIT(1, 48), kbuf[0..48]);
    const word8 = std.mem.readInt(u32, kbuf[32..36], .little); // слово 8: коды 256..287
    try testing.expect(word8 & (@as(u32, 1) << (BTN_LEFT % 32)) != 0);
    try testing.expect(word8 & (@as(u32, 1) << (BTN_RIGHT % 32)) != 0);

    // EVIOCGBIT(2, 4) мыши: REL_X|REL_Y|REL_WHEEL
    var rbuf: [4]u8 = .{0} ** 4;
    _ = ioctlEvdev(&mouse, EVIOCGBIT(2, 4), rbuf[0..4]);
    const relbits = std.mem.readInt(u32, rbuf[0..4], .little);
    try testing.expect(relbits & (@as(u32, 1) << @intCast(REL_X)) != 0);
    try testing.expect(relbits & (@as(u32, 1) << @intCast(REL_WHEEL)) != 0);

    // чужая команда → -ENOTTY (Linux: не-evdev ioctl)
    try testing.expectEqual(-linux.ENOTTY, ioctlEvdev(&dev, 0xDEAD_BEEF, buf[0..8]));
    // чужой буфер (меньше размера в cmd) → -EINVAL
    try testing.expectEqual(-linux.EINVAL, ioctlEvdev(&dev, EVIOCGNAME(64), buf[0..16]));
}

test "evdev: devfs-резолв /dev/input/event0,1" {
    try testing.expectEqual(DevKind.event0_kbd, resolveDevPath("/dev/input/event0"));
    try testing.expectEqual(DevKind.event1_mouse, resolveDevPath("/dev/input/event1"));
    try testing.expect(resolveDevPath("/dev/input/event2") == null);
    try testing.expect(resolveDevPath("/dev/fb0") == null);
}
