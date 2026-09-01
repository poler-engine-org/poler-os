// ============================================================================
// POLER-OS — PUF: привязка аппаратной энтропии (Hardware Entropy Binding)
// ============================================================================
//
// Реализация спецификации:
//   docs/POLER_OS_POST_QUANTUM_HARDWARE_ENTROPY_SPEC.md (v1.0)
//
// Задача (спека §1–2): физический отпечаток кремния (PUF) превращается в
// неотъемлемую часть криптографического состояния ядра:
//
//   сырой отпечаток (разреженные фазовые события / TSC-джиттер)
//        │
//        ▼
//   healthCheck ── reject ──► Degenerate (клон/нулевой буфер)
//        │ pass
//        ▼
//   SipHash-губка (firewallPRF, доменное разделение)
//        ├── DOMAIN_SEED     → 256-бит сид → PolerPrng / PolerCipher
//        └── DOMAIN_IDENTITY → 256-бит identity (аттестация устройства)
//        │
//        ▼
//   LivePool: подмешивание живого джиттера в рантайме (спека §2.1)
//   Enrollment: стабильная маска + консенсус → анти-клон (спека §4)
//
// Формат сырых данных:
//   • «фазовый отпечаток» — N×u64, почти все слова нулевые, ~десяток
//     одиночных битов в пространстве 8192 бит (позиции фазовых событий);
//   • «живой джиттер» — плотные u64 (TSC-дельты, IRQ-интервалы).
//   Оба формата — []const u8; экстрактор одинаков.
//
// ЧЕСТНЫЕ ГРАНИЦЫ (см. док-культуру репо):
//   1. Экстрактор НЕ создаёт энтропию — он только перемешивает:
//      энтропия выхода ограничена мин-энтропией входа.
//   2. healthCheck НЕ детектирует гипервизор надёжно (QEMU/KVM дают
//      «правдоподобный» буфер). Анти-клонинг по спеке §4 — это
//      bindEnrolled(): VM/чужой кремний даёт ДРУГОЙ отпечаток и
//      свертка с записанным identity не сходится.
//   3. Fuzzy-match = repetition-код по стабильной маске (без ECC и
//      helper-data). Защита от деградации шума — v0.8+ (см. ROADMAP).
//   4. Идентичность НЕ зависит от nonce (воспроизводима на том же
//      кремнии); сид — зависит (каждая загрузка даёт новый ключевой
//      материал, подмешивая TSC-базу).
//
// Зависимости: только poler_core.zig (firewallPRF = SipHash-2-4,
// PolerPrng). Модуль ЧИСТЫЙ: без hal/allocation — одинаковый код в
// ядре (freestanding) и в нативных тестах (build.zig: test).
// ============================================================================

const std = @import("std");
const poler = @import("poler_core.zig");

// ── Константы ─────────────────────────────────────────────────────────────

pub const MIN_RAW_LEN: usize = 64; // ≥ 8 слов u64
pub const MAX_RAW_LEN: usize = 4096; // ≤ 512 слов u64 (Enrollment-массивы)
pub const MAX_WORDS: usize = MAX_RAW_LEN / 8;
pub const SEED_WORDS: usize = 8; // 256 бит
pub const IDENTITY_LEN: usize = 32; // 256 бит
pub const DEFAULT_TOL_BITS: u32 = 16; // допуск расстояния до консенсуса

// Доменное разделение (domain separation): разные «русла» губки.
// Значения — ASCII-магия, чтобы не пересекаться со служебными ключами
// фаервола (poler_core: firewallPRF).
const DOMAIN_SEED: u64 = 0x5055_4653_4545_4421; // "PUFSEED!"
const DOMAIN_ID: u64 = 0x5055_4645_4E54_2121; // "PUFENT!!"
const DOMAIN_LIVE: u64 = 0x5055_4649_4C49_5645; // "PUFILIVE"

// ── Ошибки ────────────────────────────────────────────────────────────────

pub const PufError = error{
    TooShort, // < MIN_RAW_LEN
    TooLong, // > MAX_RAW_LEN
    Degenerate, // нулевой/константный/вырожденный буфер
    LengthMismatch, // захваты разной длины при enroll
    TooFewCaptures, // enroll требует ≥ 2 захвата
    NotThisDevice, // свертка не совпала (клон / VM / чужой кремний)
};

// ── Health-check (sparse-aware) ───────────────────────────────────────────

/// К качество источника. `weak` принимается, но помечается (ядро честно
/// сообщает об этом при загрузке); `rejected` → PufError.Degenerate.
pub const Quality = enum { strong, weak };

pub const HealthReport = struct {
    quality: Quality,
    /// Всего установленных бит (для разреженного отпечатка = число событий).
    events: u32,
    /// Число ненулевых слов u64.
    distinct_words: u32,
};

/// Оценка здоровья источника. Честная граница: это гигиеническая проверка
/// (нули/константа/слишком мало событий), а НЕ детектор VM — детектор
/// по спеке §4 это bindEnrolled().
pub fn healthCheck(raw: []const u8) PufError!HealthReport {
    if (raw.len < MIN_RAW_LEN) return error.TooShort;
    if (raw.len > MAX_RAW_LEN) return error.TooLong;

    var events: u32 = 0;
    var distinct_words: u32 = 0;

    const n = raw.len / 8;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const w = readWord(raw, i * 8);
        events +%= @as(u32, @popCount(w));
        if (w != 0) {
            // подсчётDistinct без аллокаций: O(n²) по словам (n ≤ 512)
            var seen = false;
            var j: usize = 0;
            while (j < i) : (j += 1) {
                if (readWord(raw, j * 8) == w) {
                    seen = true;
                    break;
                }
            }
            if (!seen) distinct_words += 1;
        }
    }
    // хвост < 8 байт учитываем в events, чтобы нулевой хвост не обесценил буфер
    if (raw.len % 8 != 0) {
        var tail: u64 = 0;
        var t: usize = 0;
        while (n * 8 + t < raw.len) : (t += 1) {
            tail |= @as(u64, raw[n * 8 + t]) << @intCast(t * 8);
        }
        events +%= @as(u32, @popCount(tail));
    }

    // Вырожденные случаи: константный буфер / всё нули / мало событий.
    if (events < 8 or distinct_words < 3) return error.Degenerate;

    const quality: Quality = if (events >= 10 and distinct_words >= 5) .strong else .weak;
    return .{ .quality = quality, .events = events, .distinct_words = distinct_words };
}

// ── SipHash-губка (экстрактор) ────────────────────────────────────────────

/// Губка поверх firewallPRF (SipHash-2-4, 128-бит ключ → 32-бит блок).
/// Состояние — два слова k0/k1; каждое поглощённое слово u64 переводит
/// состояние через два PRF-вызова (прямое и инверсное сообщение), чтобы
/// простое инвертирование входа не давало коллизий состояний.
const Sponge = struct {
    k0: u64,
    k1: u64,
    ctr: u32,

    fn init(domain: u64, nonce: u64) Sponge {
        return .{
            .k0 = domain ^ 0xA5A5_5A5A_5A5A_A5A5 ^ nonce,
            .k1 = ~domain ^ 0x0F0F_F0F0_F0F0_0F0F ^ (nonce << 17) ^ (nonce >> 41),
            .ctr = 0,
        };
    }

    fn absorbWord(self: *Sponge, m: u64) void {
        self.ctr +%= 1;
        const r0 = poler.firewallPRF(m ^ self.ctr, self.k0, self.k1);
        const r1 = poler.firewallPRF(~m ^ self.ctr, self.k1, self.k0);
        self.k0 ^= (@as(u64, r1) << 32) | r0;
        self.k1 ^= (@as(u64, r0) << 32) | r1;
    }

    fn absorb(self: *Sponge, bytes: []const u8) void {
        const n = bytes.len / 8;
        var i: usize = 0;
        while (i < n) : (i += 1) self.absorbWord(readWord(bytes, i * 8));
        // Хвост с паддингом 0x80 + длина (последний байт) — устойчиво к
        // буферам разной длины с одинаковым словесным префиксом.
        if (bytes.len % 8 != 0) {
            var tail: [8]u8 = .{0} ** 8;
            var t: usize = 0;
            while (n * 8 + t < bytes.len) : (t += 1) tail[t] = bytes[n * 8 + t];
            tail[7] = 0x80;
            tail[6] = @truncate(bytes.len);
            self.absorbWord(std.mem.readInt(u64, &tail, .little));
        } else {
            // маркируем «ровный» буфер отдельным домен-словом
            self.absorbWord(0x80);
        }
    }

    /// Отжим 256 бит в 8 слов u32 (counter-mode поверх состояния).
    fn squeeze(self: *const Sponge) [SEED_WORDS]u32 {
        var out: [SEED_WORDS]u32 = undefined;
        for (&out, 0..) |*w, idx| {
            const msg = self.k0 ^ ((@as(u64, @intCast(idx)) + 1) << 32) ^ @as(u64, self.ctr);
            w.* = poler.firewallPRF(msg, self.k1 ^ @as(u64, @intCast(idx)), ~self.k0);
        }
        return out;
    }
};

// ── Binding: сид + идентичность ───────────────────────────────────────────

/// Результат привязки: ключевой материал (сид) и аттестация устройства.
pub const Binding = struct {
    /// 256-бит сид → prngFrom() / PolerCipher.init(). ЗАВИСИТ от nonce
    /// (каждая загрузка — новый материал при живом источнике).
    seed: [SEED_WORDS]u32,
    /// 256-бит identity. НЕ зависит от nonce — воспроизводим на том же
    /// кремнии, различается на клоне/VM (спека §4).
    identity: [IDENTITY_LEN]u8,
    quality: Quality,
    health: HealthReport,

    pub fn prng(self: *const Binding) poler.PolerPrng {
        return prngFromSeed(self.seed);
    }
};

/// Прямая привязка сырого буфера (без регистрации).
/// nonce — переменный ключевой материал загрузки (например, TSC-база).
pub fn bindRaw(raw: []const u8, nonce: u64) PufError!Binding {
    const health = try healthCheck(raw);

    var id_sponge = Sponge.init(DOMAIN_ID, 0); // identity: nonce фикс. = 0
    id_sponge.absorb(raw);
    const id_words = id_sponge.squeeze();
    var identity: [IDENTITY_LEN]u8 = undefined;
    for (id_words, 0..) |w, i| {
        std.mem.writeInt(u32, identity[i * 4 ..][0..4], w, .little);
    }

    var seed_sponge = Sponge.init(DOMAIN_SEED, nonce);
    seed_sponge.absorb(raw);
    const seed = seed_sponge.squeeze();

    return .{ .seed = seed, .identity = identity, .quality = health.quality, .health = health };
}

/// PRNG ядра из сида: три независимых канала сида → (state, epsilon, key).
pub fn prngFromSeed(seed: [SEED_WORDS]u32) poler.PolerPrng {
    const state = seed[0] ^ seed[4] ^ (seed[2] << 1);
    const epsilon = seed[1] ^ seed[5];
    const key = seed[3] ^ seed[6] ^ (seed[7] << 3);
    return poler.PolerPrng.init(state, epsilon, key);
}

// ── Доменное разделение для всех пулов энтропии (Спека §1-2) ───────────────
pub const DOMAIN_POOL_PHASE: u64 = 0x5055_4650_4841_5345; // "PUFPHASE" - Кремниевый шум & TSC
pub const DOMAIN_POOL_BUS: u64   = 0x5055_4642_5553_2121; // "PUFBUS!!" - Латентность шины PCIe & VirtIO
pub const DOMAIN_POOL_IRQ: u64   = 0x5055_4649_5251_2121; // "PUFIRQ!!" - APIC/HPET тайминги прерываний
pub const DOMAIN_POOL_BIO: u64   = 0x5055_4642_494F_2121; // "PUFBIO!!" - Биодинамика оператора (клавиатура)

// ── LivePool: подмешивание живой энтропии в рантайме ──────────────────────

/// Пул живой энтропии (спека §2.1: TSC-джиттер, IRQ-микроинтервалы).
/// foldInto() вплетает накопленное в готовый сид — при расхождении
/// физики (VM после миграции) сид естественно «уплывает».
pub const LivePool = struct {
    sponge: Sponge,
    events: u32,
    domain: u64,

    pub fn init(domain: u64, nonce: u64) LivePool {
        return .{ .sponge = Sponge.init(domain, nonce), .events = 0, .domain = domain };
    }

    /// Смешать одно событие (дельту TSC, интервал IRQ и т.п.).
    pub fn mix(self: *LivePool, event: u64) void {
        self.sponge.absorbWord(event);
        self.events +%= 1;
    }

    /// Вплести пул в сид: XOR-свёртка + финальная диффузия SipHash,
    /// чтобы прямое XOR двух PRF-русл не оставалось линейным.
    pub fn foldInto(self: *const LivePool, seed: *[SEED_WORDS]u32) void {
        const live = self.sponge.squeeze();
        for (seed, 0..) |*w, i| {
            const mixed = w.* ^ live[i];
            const fin = poler.firewallPRF(
                (@as(u64, mixed) << 32) | @as(u64, live[(i + 1) % SEED_WORDS]),
                self.sponge.k0 ^ @as(u64, i),
                self.sponge.k1,
            );
            w.* = mixed ^ fin;
        }
    }
};

// ── Multi-Pool Architecture (Спека §1: Все 4 физических пула) ──────────────

/// Объединённый энтропийный хаб (Entropy Hub) ядра POLER-OS.
/// Аккумулирует 4 независимых потока физической энтропии:
///   1. PhasePool: кремниевый фазовый джиттер и TSC флуктуации
///   2. BusPool: задержки транзакций шины PCIe / DMA / VirtIO
///   3. IrqPool: интервалы аппаратных прерываний (APIC Timer, IRQ)
///   4. BioPool: биодинамика оператора (интервалы нажатия клавиш)
pub const UnifiedEntropyHub = struct {
    phase_pool: LivePool,
    bus_pool: LivePool,
    irq_pool: LivePool,
    bio_pool: LivePool,
    total_samples: u64,

    pub fn init(nonce: u64) UnifiedEntropyHub {
        return .{
            .phase_pool = LivePool.init(DOMAIN_POOL_PHASE, nonce ^ 0x01),
            .bus_pool   = LivePool.init(DOMAIN_POOL_BUS,   nonce ^ 0x02),
            .irq_pool   = LivePool.init(DOMAIN_POOL_IRQ,   nonce ^ 0x03),
            .bio_pool   = LivePool.init(DOMAIN_POOL_BIO,   nonce ^ 0x04),
            .total_samples = 0,
        };
    }

    /// 1. Кремниевый шум & фазовые задержки (PUF/TSC)
    pub fn feedPhase(self: *UnifiedEntropyHub, sample: u64) void {
        self.phase_pool.mix(sample);
        self.total_samples +%= 1;
    }

    /// 2. Задержки шины и накопителя (PCIe / VirtIO I/O latency)
    pub fn feedBus(self: *UnifiedEntropyHub, sample: u64) void {
        self.bus_pool.mix(sample);
        self.total_samples +%= 1;
    }

    /// 3. Тайминги аппаратных прерываний (APIC timer / IRQ)
    pub fn feedIrq(self: *UnifiedEntropyHub, sample: u64) void {
        self.irq_pool.mix(sample);
        self.total_samples +%= 1;
    }

    /// 4. Биодинамика пользователя (клавиатурные интервалы)
    pub fn feedBio(self: *UnifiedEntropyHub, sample: u64) void {
        self.bio_pool.mix(sample);
        self.total_samples +%= 1;
    }

    /// Вплетает все 4 пула в единый криптографический сид ядра
    pub fn foldAll(self: *const UnifiedEntropyHub, seed: *[SEED_WORDS]u32) void {
        self.phase_pool.foldInto(seed);
        self.bus_pool.foldInto(seed);
        self.irq_pool.foldInto(seed);
        self.bio_pool.foldInto(seed);
    }
};

// ── Расстояния и постоянное время ─────────────────────────────────────────

/// Хэммингво расстояние между двумя сырыми буферами (в битах,
/// пословно, хвост игнорируется при несовпадении длины слов).
pub fn rawDistance(a: []const u8, b: []const u8) u32 {
    const n = @min(a.len, b.len) / 8;
    var dist: u32 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const wa = readWord(a, i * 8);
        const wb = readWord(b, i * 8);
        dist +%= @as(u32, @popCount(wa ^ wb));
    }
    return dist;
}

/// Сравнение identity в постоянном времени (без раннего выхода).
pub fn ctEqual(a: *const [IDENTITY_LEN]u8, b: *const [IDENTITY_LEN]u8) bool {
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

// ── Enrollment: регистрация устройства (анти-клон, спека §4) ─────────────

/// Регистрация устройства по нескольким захватам отпечатка.
/// • consensus — мажоритарные биты (устойчивые «1»);
/// • stable_mask — биты, одинаковые ВО ВСЕХ захватах (только они
///   участвуют в выводе ключа — шум не меняет proj);
/// • identity = экстрактор(proj консенсуса).
/// Fuzzy-свойство: захват с шумом в НЕстабильных битах даёт тот же
/// identity; чужой кремний (даже без шума) — другой.
pub const Enrollment = struct {
    word_count: usize,
    tol_bits: u32,
    consensus: [MAX_WORDS]u64,
    stable_mask: [MAX_WORDS]u64,
    identity: [IDENTITY_LEN]u8,
    /// Доля стабильных бит (0–100): гигиена источника при регистрации.
    stability_pct: u8,

    /// Проекция захвата на стабильные биты (сырой путь к ключу).
    pub fn project(self: *const Enrollment, raw: []const u8) [MAX_WORDS]u64 {
        var proj: [MAX_WORDS]u64 = .{0} ** MAX_WORDS;
        const n = @min(@min(raw.len / 8, self.word_count), MAX_WORDS);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            proj[i] = readWord(raw, i * 8) & self.stable_mask[i];
        }
        return proj;
    }

    /// Быстрая проверка (грубое расстояние до консенсуса ≤ tol).
    /// Итоговое решение — только по identity (см. bindEnrolled).
    pub fn nearEnough(self: *const Enrollment, raw: []const u8) bool {
        const n = @min(raw.len / 8, self.word_count);
        var dist: u32 = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const w = readWord(raw, i * 8);
            dist +%= @as(u32, @popCount((w ^ self.consensus[i]) & self.stable_mask[i]));
        }
        return dist <= self.tol_bits;
    }
};

/// Регистрация: ≥ 2 захвата одного и того же кремния.
/// Возвращает консенсус + стабильную маску + identity.
pub fn enroll(captures: []const []const u8) PufError!Enrollment {
    if (captures.len < 2) return error.TooFewCaptures;
    const len = captures[0].len;
    if (len < MIN_RAW_LEN or len > MAX_RAW_LEN) return error.TooShort;
    for (captures) |c| {
        if (c.len != len) return error.LengthMismatch;
    }
    // Гигиена: хотя бы один захват должен проходить health-check.
    var any_healthy = false;
    for (captures) |c| {
        if (healthCheck(c)) |_| {
            any_healthy = true;
            break;
        } else |_| {}
    }
    if (!any_healthy) return error.Degenerate;

    const n = len / 8;
    var consensus: [MAX_WORDS]u64 = .{0} ** MAX_WORDS;
    var stable_mask: [MAX_WORDS]u64 = .{0} ** MAX_WORDS;

    // Мажоритарный консенсус и маска стабильности.
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var ones_count: [64]u32 = .{0} ** 64; // голоса «1» по битам слова
        for (captures) |c| {
            const w = readWord(c, i * 8);
            var b: usize = 0;
            while (b < 64) : (b += 1) {
                if ((w >> @intCast(b)) & 1 == 1) ones_count[b] += 1;
            }
        }
        var maj: u64 = 0;
        var stable: u64 = 0;
        var b: usize = 0;
        while (b < 64) : (b += 1) {
            const c1 = ones_count[b];
            const c0: u32 = @intCast(captures.len - @as(usize, c1));
            if (c1 > c0) maj |= @as(u64, 1) << @intCast(b);
            if (c1 == 0 or c0 == 0) stable |= @as(u64, 1) << @intCast(b);
        }
        consensus[i] = maj;
        stable_mask[i] = stable;
    }

    // Identity: экстрактор проекции консенсуса (nonce фикс. = 0).
    var proj: [MAX_WORDS]u64 = undefined;
    proj = consensus;
    var pi: usize = 0;
    while (pi < n) : (pi += 1) proj[pi] &= stable_mask[pi];

    var id_sponge = Sponge.init(DOMAIN_ID, 0);
    var wi: usize = 0;
    while (wi < n) : (wi += 1) id_sponge.absorbWord(proj[wi]);
    const id_words = id_sponge.squeeze();
    var identity: [IDENTITY_LEN]u8 = undefined;
    for (id_words, 0..) |w, k| {
        std.mem.writeInt(u32, identity[k * 4 ..][0..4], w, .little);
    }

    var total_bits: u64 = 0;
    var stable_bits: u64 = 0;
    var si: usize = 0;
    while (si < n) : (si += 1) {
        total_bits += 64;
        stable_bits += @popCount(stable_mask[si]);
    }
    const pct: u64 = if (total_bits == 0) 0 else (stable_bits * 100) / total_bits;

    return .{
        .word_count = n,
        .tol_bits = DEFAULT_TOL_BITS,
        .consensus = consensus,
        .stable_mask = stable_mask,
        .identity = identity,
        .stability_pct = @intCast(@min(pct, 100)),
    };
}

/// Привязка с верификацией (анти-клон): чужой кремний/VM → NotThisDevice.
/// Ключ выводится ТОЛЬКО из стабильных бит — шум захвата не меняет сид.
pub fn bindEnrolled(raw: []const u8, enr: *const Enrollment) PufError!Binding {
    const health = try healthCheck(raw);
    if (!enr.nearEnough(raw)) return error.NotThisDevice;

    // proj = raw & stable_mask; сравнение identity с записанным.
    var id_sponge = Sponge.init(DOMAIN_ID, 0);
    const n = @min(raw.len / 8, enr.word_count);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const proj_word = readWord(raw, i * 8) & enr.stable_mask[i];
        id_sponge.absorbWord(proj_word);
    }
    const id_words = id_sponge.squeeze();
    var identity: [IDENTITY_LEN]u8 = undefined;
    for (id_words, 0..) |w, k| {
        std.mem.writeInt(u32, identity[k * 4 ..][0..4], w, .little);
    }
    if (!ctEqual(&identity, &enr.identity)) return error.NotThisDevice;

    // Ключ: сид-губка по той же проекции + живой nonce вызывающего.
    // (nonce=0: сид воспроизводим; подмешивание живой энтропии — LivePool.)
    var seed_sponge = Sponge.init(DOMAIN_SEED, 0);
    var j: usize = 0;
    while (j < n) : (j += 1) {
        seed_sponge.absorbWord(readWord(raw, j * 8) & enr.stable_mask[j]);
    }
    const seed = seed_sponge.squeeze();

    return .{ .seed = seed, .identity = identity, .quality = health.quality, .health = health };
}

/// v0.12.0 (Enrollment-Gate, CDD №3): экстрактор identity из ПЕРВЫХ
/// stable_words слов сырого материала (хвост — живой свидетель, в identity
/// НЕ входит). Отдельный domain отделяет gate-identity от PUF-identity
/// (русла seed/identity не пересекаются — та же дисциплина, что в bindRaw).
/// Это «свертка кремниевого отпечатка» для проверки при старте ядра.
pub fn extractIdentity(raw: []const u8, stable_words: usize, domain: u64) [IDENTITY_LEN]u8 {
    var sponge = Sponge.init(domain, 0);
    const n = @min(stable_words, raw.len / 8);
    var i: usize = 0;
    while (i < n) : (i += 1) sponge.absorbWord(readWord(raw, i * 8));
    const words = sponge.squeeze();
    var identity: [IDENTITY_LEN]u8 = undefined;
    for (words, 0..) |w, k| {
        std.mem.writeInt(u32, identity[k * 4 ..][0..4], w, .little);
    }
    return identity;
}

// ── Вспомогательное ───────────────────────────────────────────────────────

/// Чтение слова u64 по смещению off (LE, за пределами буфера — нули).
fn readWord(bytes: []const u8, off: usize) u64 {
    if (off >= bytes.len) return 0;
    var b: [8]u8 = .{0} ** 8;
    const n = @min(8, bytes.len - off);
    @memcpy(b[0..n], bytes[off..][0..n]);
    return std.mem.readInt(u64, &b, .little);
}

// ============================================================================
// ТЕСТЫ (нативно; build.zig → step "test")
// ============================================================================

const testing = std.testing;

/// Детерминированный генератор тестовых буферов на PolerPrng
/// (самодостаточность: не тянем std.Random в ядерный путь).
fn fillPseudo(buf: []u8, seed: u32) void {
    var pr = poler.PolerPrng.init(seed, 1, 0x1234_5678);
    var i: usize = 0;
    while (i < buf.len) : (i += 4) {
        const v = pr.next();
        var k: usize = 0;
        while (k < 4 and i + k < buf.len) : (k += 1) {
            buf[i + k] = @truncate(v >> @intCast(k * 8));
        }
    }
}

fn sparseFingerprint(buf: []u8, seed: u32) void {
    // Разреженный «фазовый» формат: 12 одиночных битов в 8192-бит поле.
    // Позиции детерминированы (слово/бит не повторяются), seed задаёт фазу.
    _ = seed;
    @memset(buf, 0);
    const events = [12][2]usize{
        .{ 1, 9 },   .{ 7, 31 },  .{ 15, 3 },  .{ 23, 47 },
        .{ 31, 17 }, .{ 45, 62 }, .{ 59, 8 },  .{ 73, 21 },
        .{ 87, 55 }, .{ 101, 2 }, .{ 115, 40 }, .{ 127, 12 },
    };
    for (events) |ev| {
        const w = readWord(buf, ev[0] * 8) | (@as(u64, 1) << @intCast(ev[1]));
        std.mem.writeInt(u64, buf[ev[0] * 8 ..][0..8], w, .little);
    }
}

test "health: вырожденные входы отбраковываются" {
    var buf: [1024]u8 = undefined;
    @memset(&buf, 0);
    try testing.expectError(error.Degenerate, healthCheck(&buf)); // всё нули
    @memset(&buf, 0xAA);
    try testing.expectError(error.Degenerate, healthCheck(&buf)); // 1 значение
    var short: [32]u8 = undefined;
    try testing.expectError(error.TooShort, healthCheck(&short));
    // разреженный, но событий слишком мало (2 бита, 2 значения)
    var sparse: [1024]u8 = undefined;
    @memset(&sparse, 0);
    std.mem.writeInt(u64, sparse[0..8], 0x100, .little);
    std.mem.writeInt(u64, sparse[8..16], 0x200, .little);
    try testing.expectError(error.Degenerate, healthCheck(&sparse));
}

test "health: разреженный отпечаток проходит" {
    var buf: [1024]u8 = undefined;
    sparseFingerprint(&buf, 42);
    const h = try healthCheck(&buf);
    try testing.expect(h.events >= 10);
    try testing.expect(h.distinct_words >= 5);
}

test "bindRaw: детерминизм и независимость от nonce у identity" {
    var raw: [1024]u8 = undefined;
    fillPseudo(&raw, 100);
    const b1 = try bindRaw(&raw, 0);
    const b2 = try bindRaw(&raw, 0);
    const b3 = try bindRaw(&raw, 0xDEAD_BEEF);
    try testing.expectEqualSlices(u8, &b1.identity, &b2.identity);
    // identity не зависит от nonce; сид — зависит
    try testing.expect(!std.mem.eql(u32, &b1.seed, &b3.seed));
    // доменное разделение: сид и identity — разные русла
    var seed_bytes: [32]u8 = undefined;
    for (b1.seed, 0..) |w, i| std.mem.writeInt(u32, seed_bytes[i * 4 ..][0..4], w, .little);
    try testing.expect(!std.mem.eql(u8, &seed_bytes, &b1.identity));
}

test "bindRaw: лавинный эффект (flip одного бита входа)" {
    var raw: [1024]u8 = undefined;
    fillPseudo(&raw, 55);
    const base = try bindRaw(&raw, 0);
    var total_diff: u64 = 0;
    const flips = 32;
    var f: usize = 0;
    while (f < flips) : (f += 1) {
        const byte_i = (f * 31) % raw.len;
        const bit_i: u3 = @intCast((f * 5) % 8);
        raw[byte_i] ^= @as(u8, 1) << bit_i;
        const flipped = try bindRaw(&raw, 0);
        var diff: u32 = 0;
        for (base.identity, flipped.identity) |x, y| diff += @popCount(x ^ y);
        try testing.expect(diff >= 80); // каждая инверсия существенна
        total_diff += diff;
        raw[byte_i] ^= @as(u8, 1) << bit_i; // откат
    }
    const avg = total_diff / flips;
    try testing.expect(avg >= 104 and avg <= 152); // ~128 ± 3σ
}

test "enroll/bindEnrolled: тот же кремний — тот же identity, клон — отказ" {
    var base: [256]u8 = undefined;
    fillPseudo(&base, 900);

    // Три захвата с шумом в РАЗНЫХ нестабильных позициях.
    var cap1: [256]u8 = undefined;
    var cap2: [256]u8 = undefined;
    var cap3: [256]u8 = undefined;
    @memcpy(&cap1, &base);
    @memcpy(&cap2, &base);
    @memcpy(&cap3, &base);
    cap1[1] ^= 0x10; // бит 4 байта 1
    cap2[3] ^= 0x01; // бит 0 байта 3
    cap2[5] ^= 0x80; // бит 7 байта 5
    cap3[9] ^= 0x04; // бит 2 байта 9
    cap3[10] ^= 0x20; // бит 5 байта 10

    const enr = try enroll(&.{ &cap1, &cap2, &cap3 });
    try testing.expect(enr.stability_pct < 100); // шум зафиксирован маской

    // Новый захват с шумом ТОЛЬКО в нестабильных битах → тот же identity.
    var cap4: [256]u8 = undefined;
    @memcpy(&cap4, &base);
    cap4[1] ^= 0x10; // та же нестабильная позиция
    cap4[9] ^= 0x04;
    const ok = try bindEnrolled(&cap4, &enr);
    try testing.expect(ctEqual(&ok.identity, &enr.identity));

    // Чистый захват оригинала — тоже сходится.
    const clean = try bindEnrolled(&base, &enr);
    try testing.expect(ctEqual(&clean.identity, &enr.identity));

    // Клон: другой кремний → NotThisDevice.
    var alien: [256]u8 = undefined;
    fillPseudo(&alien, 901);
    try testing.expectError(error.NotThisDevice, bindEnrolled(&alien, &enr));

    // Подмена стабильного бита (позиция, где все захваты равны) → отказ.
    // Шум был только в байтах 1,3,5,9,10 → байт 2 стабилен во всех захватах.
    var tampered: [256]u8 = undefined;
    @memcpy(&tampered, &base);
    tampered[2] ^= 0x01;
    try testing.expectError(error.NotThisDevice, bindEnrolled(&tampered, &enr));
}

test "enroll: захваты разной длины и один захват отклоняются" {
    var a: [256]u8 = undefined;
    var b: [128]u8 = undefined;
    fillPseudo(&a, 1);
    fillPseudo(&b, 2);
    try testing.expectError(error.LengthMismatch, enroll(&.{ &a, &b }));
    try testing.expectError(error.TooFewCaptures, enroll(&.{&a}));
}

test "LivePool: подмешивание меняет сид и детерминировано" {
    var raw: [1024]u8 = undefined;
    fillPseudo(&raw, 300);
    const b = try bindRaw(&raw, 0);

    var seed_a = b.seed;
    var pool = LivePool.init(DOMAIN_POOL_PHASE, 0);
    pool.mix(0x1111_2222_3333_4444);
    pool.mix(0x5555_6666_7777_8888);
    pool.foldInto(&seed_a);
    try testing.expect(!std.mem.eql(u32, &seed_a, &b.seed));

    // Детерминизм: тот же поток событий → то же вплетение.
    var seed_b = b.seed;
    var pool2 = LivePool.init(DOMAIN_POOL_PHASE, 0);
    pool2.mix(0x1111_2222_3333_4444);
    pool2.mix(0x5555_6666_7777_8888);
    pool2.foldInto(&seed_b);
    try testing.expectEqualSlices(u32, &seed_a, &seed_b);
}

test "UnifiedEntropyHub: все 4 пула вплетаются и изменяют состояние сида" {
    var raw: [1024]u8 = undefined;
    fillPseudo(&raw, 400);
    const b = try bindRaw(&raw, 0);

    var hub = UnifiedEntropyHub.init(12345);
    hub.feedPhase(0xAAAA_BBBB_CCCC_DDDD);
    hub.feedBus(0x1234_5678_9ABC_DEF0);
    hub.feedIrq(0xFEED_FACE_CAFE_BEEF);
    hub.feedBio(0x0102_0304_0506_0708);

    try testing.expectEqual(@as(u64, 4), hub.total_samples);
    try testing.expectEqual(@as(u32, 1), hub.phase_pool.events);
    try testing.expectEqual(@as(u32, 1), hub.bus_pool.events);
    try testing.expectEqual(@as(u32, 1), hub.irq_pool.events);
    try testing.expectEqual(@as(u32, 1), hub.bio_pool.events);

    var seed_mixed = b.seed;
    hub.foldAll(&seed_mixed);
    try testing.expect(!std.mem.eql(u32, &seed_mixed, &b.seed));
}

test "rawDistance/ctEqual: базовые свойства" {
    var a: [128]u8 = undefined;
    var b: [128]u8 = undefined;
    fillPseudo(&a, 10);
    @memcpy(&b, &a);
    try testing.expectEqual(@as(u32, 0), rawDistance(&a, &b));
    b[0] ^= 0x03; // 2 бита
    try testing.expectEqual(@as(u32, 2), rawDistance(&a, &b));
    var c: [32]u8 = undefined;
    var d: [32]u8 = undefined;
    fillPseudo(&c, 11);
    try testing.expect(ctEqual(&c, &c));
    fillPseudo(&d, 12);
    try testing.expect(!ctEqual(&c, &d));
}

test "prngFromSeed: сид даёт живой, различаемый поток" {
    var raw1: [1024]u8 = undefined;
    var raw2: [1024]u8 = undefined;
    fillPseudo(&raw1, 601);
    fillPseudo(&raw2, 602);
    const b1 = try bindRaw(&raw1, 0);
    const b2 = try bindRaw(&raw2, 0);
    var p1 = b1.prng();
    var p2 = b2.prng();
    var same: u32 = 0;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        if (p1.next() == p2.next()) same += 1;
    }
    // разных источников → почти нет совпадений (допуск 4 из 256)
    try testing.expect(same <= 4);
    // поток не вырожден: не константа
    var p3 = b1.prng();
    const first = p3.next();
    var constant = true;
    i = 0;
    while (i < 16) : (i += 1) {
        if (p3.next() != first) constant = false;
    }
    try testing.expect(!constant);
}

test "bindEnrolled: сид воспроизводим на том же кремнии (нестабильный шум)" {
    var base: [256]u8 = undefined;
    fillPseudo(&base, 700);
    var cap1: [256]u8 = undefined;
    var cap2: [256]u8 = undefined;
    @memcpy(&cap1, &base);
    @memcpy(&cap2, &base);
    cap1[20] ^= 0x40; // шум
    cap2[40] ^= 0x02; // другой шум
    const enr = try enroll(&.{ &cap1, &cap2 });

    var noisy: [256]u8 = undefined;
    @memcpy(&noisy, &base);
    noisy[20] ^= 0x40; // тот же нестабильный бит
    noisy[40] ^= 0x02;
    const s1 = try bindEnrolled(&noisy, &enr);
    const s2 = try bindEnrolled(&base, &enr);
    // ключ выведен из стабильной проекции → совпадает
    try testing.expectEqualSlices(u32, &s1.seed, &s2.seed);
}

// ─── v0.12.0: extractIdentity (Enrollment-Gate) ────────────────────────────

test "extractIdentity: детерминизм, граница стабильных слов, домены" {
    // 128 слов: 24 «стабильных» (CPUID-подобных) + 104 «свидетеля»
    var raw: [1024]u8 = undefined;
    var w: usize = 0;
    while (w < 128) : (w += 1) {
        const val: u64 = if (w < 24) 0x1000_0000 + w * 0x0101 else w * 0xDEAD_BEEF;
        std.mem.writeInt(u64, raw[w * 8 ..][0..8], val, .little);
    }
    const DOM_A: u64 = 0x4547_4154_4531_2132;

    // детерминизм
    try testing.expectEqualSlices(u8, &extractIdentity(&raw, 24, DOM_A), &extractIdentity(&raw, 24, DOM_A));

    // свидетель (слова ≥ 24) НЕ входит в identity: мутации хвоста невидимы
    var raw2 = raw;
    std.mem.writeInt(u64, raw2[100 * 8 ..][0..8], 0x4242_4242_4242_4242, .little);
    try testing.expectEqualSlices(u8, &extractIdentity(&raw, 24, DOM_A), &extractIdentity(&raw2, 24, DOM_A));

    // мутация СТАБИЛЬНОГО слова меняет identity
    var raw3 = raw;
    std.mem.writeInt(u64, raw3[5 * 8 ..][0..8], 0x9999_9999_9999_9999, .little);
    try testing.expect(!std.mem.eql(u8, &extractIdentity(&raw, 24, DOM_A), &extractIdentity(&raw3, 24, DOM_A)));

    // домен разделяет русла
    const DOM_B: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    try testing.expect(!std.mem.eql(u8, &extractIdentity(&raw, 24, DOM_A), &extractIdentity(&raw, 24, DOM_B)));

    // усечение: 24 стабильных ≠ 12 стабильных
    try testing.expect(!std.mem.eql(u8, &extractIdentity(&raw, 24, DOM_A), &extractIdentity(&raw, 12, DOM_A)));

    // пустой буфер — валидный (нулевой) identity, не паника
    _ = extractIdentity(&[_]u8{}, 24, DOM_A);
}
