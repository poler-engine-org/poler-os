// ============================================================================
// POLER-OS Hardware Enrollment-Gate — v0.12.0 (CDD-цикл №3)
// ============================================================================
//
// Спецификация: docs/POLER_OS_POST_QUANTUM_HARDWARE_ENTROPY_SPEC.md §4
// (Anti-Cloning & Cloud Immunity): клон образа ОС на чужой процессор или
// в неавторизованную VM обязан ОТЛИЧАТЬСЯ от эталона (ε_vm ≠ ε_silicon),
// ядро печатает предупреждение и требует аттестацию.
//
// Кремниевый отпечаток (RAW_LEN = 1024Б = 128 слов u64):
//   • слова 0..23 — СТАБИЛЬНЫЙ CPUID-блок (вендор/сигнатура/фичи/бренд/
//     гипервизор-листы): одинаков на том же кремнии/VM-конфиге на каждой
//     загрузке, различается у чужого CPU/гипервизора ("TCGTCGTCGTCG" против
//     "KVMKVMKVM" против нулей на голом железе) — это и есть §4-различитель
//     «VM против кремния»;
//   • слова 24..127 — живое TSC-свидетельство (rdtsc-джиттер): НЕ входит в
//     identity (несёт «живое железо прямо сейчас», уходит в отчёт).
//
// Identity = puf.extractIdentity(raw, STABLE_WORDS, DOMAIN_GATE) — сверка
// (bindEnrolled) с эталонным профилем, сравнение — puf.ctEqual (постоянное
// время). Эталон: скомпилированная константа main64.enroll_reference
// (null → режим FIRST BOOT: регистрируем профиль этой загрузки и ПЕЧАТАЕМ
// его для бейка; cmd 'enroll' выводит live-identity).
//
// Честные границы v0.12.0: identity различает КЛАСС кремния (guest-CPU
// модель + гипервизор-вендор), а не экземпляр; поперечное сравнение
// идентичных экземпляров (две одинаковые VM-конфигурации) — будущее
// (персистентный fuzzy-профиль puf.Enrollment на FAT32 + TSC-микротайминг
// ε как в §4). Мисматч → диагностическое ПРЕДУПРЕЖДЕНИЕ (не halt) —
// крипто-русьла ядра помечаются unenrolled (см. main64).
//
// Нативная тестируемость: CPUID/RDTSC — inline asm, работает и в ядре
// (freestanding), и в linux-тестах на том же физическом CPU: capture в
// одном процессе детерминирован (свидетель в identity не входит).
// ============================================================================

const std = @import("std");
const puf = @import("puf.zig");

/// Размер сырого отпечатка (совпадает с puf.MAX_RAW_LEN-контрактом).
pub const RAW_LEN: usize = 1024;
/// Стабильных слов (CPUID-блок: вендор+сигнатура+фичи+бренд+гипервизор
/// + адресные биты = 18 слов); [18..128) — TSC-свидетельство.
pub const STABLE_WORDS: usize = 18;
/// Домен gate-identity (≠ PUF-домены: русла не пересекаются).
pub const DOMAIN_GATE: u64 = 0x4547_4154_4531_2132; // "EGATE1!2"

pub const Identity = [puf.IDENTITY_LEN]u8;

pub const Verdict = enum {
    /// Эталона нет: FIRST BOOT — профиль зарегистрирован этой загрузкой.
    first_boot,
    /// Свёртка совпала с эталоном: тот же кремний/VM-конфиг.
    verified,
    /// ЧУЖОЙ процессор / неавторизованная VM — требуется аттестация (§4).
    mismatch,
};

// ─── CPUID (inline asm: ядро + нативные тесты — один код) ───────────────────

inline fn cpuid4(leaf: u32, subleaf: u32) [4]u32 {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [sub] "{ecx}" (subleaf),
    );
    return .{ eax, ebx, ecx, edx };
}

inline fn readTsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

/// Собрать слово u64 из пары регистров (lo, hi).
inline fn pair(lo: u32, hi: u32) u64 {
    return (@as(u64, hi) << 32) | lo;
}

/// Собрать кремниевый отпечаток:
///   [0..24)  — CPUID-блок (СТАБИЛЕН: identity строится только из него);
///   [24..128) — TSC-свидетельство (rdtsc-джиттер, в identity НЕ входит).
pub fn captureFingerprint(out: *[RAW_LEN]u8) void {
    @memset(out, 0);

    const l0 = cpuid4(0, 0); // max_leaf + vendor "GenuineIntel"/"AuthenticAMD"
    const l1 = cpuid4(1, 0); // сигнатура + EBX-мisc + фичи ECX/EDX
    const l7 = cpuid4(7, 0); // расширенные фичи (контекст: subleaf=0)
    const l81 = cpuid4(0x8000_0001, 0); // ext-фичи (NX, 1G-страницы…)
    const l82 = cpuid4(0x8000_0002, 0); // brand string, часть 1/3
    const l83 = cpuid4(0x8000_0003, 0); // часть 2/3
    const l84 = cpuid4(0x8000_0004, 0); // часть 3/3 («QEMU Virtual CPU…»)
    const lh0 = cpuid4(0x4000_0000, 0); // гипервизор: max-leaf + сигнатура
    const lh1 = cpuid4(0x4000_0001, 0); // KVM-фичи / TCG: нули
    const l88 = cpuid4(0x8000_0008, 0); // физ/вирт адресные биты

    var w: usize = 0;
    const put = struct {
        fn f(buf: *[RAW_LEN]u8, idx: *usize, v: u64) void {
            if (idx.* < RAW_LEN / 8) {
                std.mem.writeInt(u64, buf[idx.* * 8 ..][0..8], v, .little);
                idx.* += 1;
            }
        }
    }.f;

    put(out, &w, pair(l0[0], l0[1])); // 0: max_leaf | vendor[0:4]
    put(out, &w, pair(l0[3], l0[2])); // 1: vendor[8:12] | vendor[4:8]
    put(out, &w, pair(l1[0], l1[1])); // 2: сигнатура | misc(EBX)
    put(out, &w, pair(l1[2], l1[3])); // 3: фичи ECX | EDX
    put(out, &w, pair(l7[0], l7[1])); // 4
    put(out, &w, pair(l7[2], l7[3])); // 5
    put(out, &w, pair(l81[0], l81[1])); // 6
    put(out, &w, pair(l81[2], l81[3])); // 7
    for ([_][4]u32{ l82, l83, l84 }) |l| { // 8..19: brand string
        put(out, &w, pair(l[0], l[1]));
        put(out, &w, pair(l[2], l[3]));
    }
    put(out, &w, pair(lh0[0], lh0[1])); // 20: гипервизор max | сигнатура[0:4]
    put(out, &w, pair(lh0[2], lh0[3])); // 21: сигнатура[8:12] | [4:8]
    put(out, &w, pair(lh1[0], lh1[1])); // 22: гипервизор-фичи
    put(out, &w, pair(l88[0], l88[1])); // 23: адресные биты
    // v0.12-dev: assert снят для QEMU-диагностики (w считается детерминированно)

    // TSC-свидетельство (24..127): живой джиттер
    var i: usize = w;
    while (i < RAW_LEN / 8) : (i += 1) {
        const t = readTsc();
        const mixed = t ^ (t >> 31) ^ (@as(u64, i) << 56);
        std.mem.writeInt(u64, out[i * 8 ..][0..8], mixed, .little);
    }
}

/// Свёртка отпечатка в identity (только стабильный CPUID-блок).
pub fn identityOf(raw: *const [RAW_LEN]u8) Identity {
    return puf.extractIdentity(raw, STABLE_WORDS, DOMAIN_GATE);
}

/// Проверка Enrollment-Gate (спека §4): свёртка живого отпечатка против
/// эталонного профиля. null-эталон → first_boot (профиль этой загрузки
/// становится рабочим). Сравнение — постоянное время (puf.ctEqual).
pub fn bindEnrolled(raw: *const [RAW_LEN]u8, reference: ?Identity) Verdict {
    const id = identityOf(raw);
    const ref = reference orelse return .first_boot;
    return if (puf.ctEqual(&id, &ref)) .verified else .mismatch;
}

// ============================================================================
// Тесты (нативно): CPUID/RDTSC исполняются на хосте — те же инструкции,
// что в ядре QEMU. Identity детерминирован (свидетель исключён).
// ============================================================================

const testing = std.testing;

test "gate: fingerprint — детерминизм identity (свидетель вне свёртки)" {
    var raw1: [RAW_LEN]u8 = undefined;
    var raw2: [RAW_LEN]u8 = undefined;
    captureFingerprint(&raw1);
    captureFingerprint(&raw2);

    // CPUID-блок совпадает (та же машина, тот же процесс)
    try testing.expectEqualSlices(u8, raw1[0 .. STABLE_WORDS * 8], raw2[0 .. STABLE_WORDS * 8]);
    // TSC-свидетельство живое — почти наверняка различается
    // (НЕ проверяем жёстко: rdtsc на гипервизоре может совпасть)

    const id1 = identityOf(&raw1);
    const id2 = identityOf(&raw2);
    try testing.expectEqualSlices(u8, &id1, &id2); // identity стабилен

    // Подделка свидетеля не меняет identity (ε-шум вне русла)
    var raw3 = raw1;
    for (raw3[STABLE_WORDS * 8 ..]) |*b| b.* ^= 0xFF;
    try testing.expectEqualSlices(u8, &id1, &identityOf(&raw3));
}

test "gate: bindEnrolled — вердикты first_boot / verified / mismatch" {
    var raw: [RAW_LEN]u8 = undefined;
    captureFingerprint(&raw);

    // эталона нет → FIRST BOOT
    try testing.expectEqual(Verdict.first_boot, bindEnrolled(&raw, null));

    // эталон = своя identity → VERIFIED (та же VM/кремний)
    const ref = identityOf(&raw);
    try testing.expectEqual(Verdict.verified, bindEnrolled(&raw, ref));

    // клон диска на «чужом кремнии»: стабилизированный блок другой → MISMATCH
    var forged = raw;
    std.mem.writeInt(u64, forged[2 * 8 ..][0..8], 0, .little); // сигнатура CPU затёрта
    try testing.expectEqual(Verdict.mismatch, bindEnrolled(&forged, ref));

    // почти-совпадение (один бит в 8-м слове) — постоянное время всё равно ловит
    var one_bit = raw;
    one_bit[8 * 8] ^= 0x01;
    try testing.expectEqual(Verdict.mismatch, bindEnrolled(&one_bit, ref));
}
