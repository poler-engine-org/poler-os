// ============================================================================
// POLER-OS Win32 Stub Dispatcher — x86_64 (v0.10.0, CDD-цикл №1)
// ============================================================================
//
// Диспетчер заглушек для PE-импортов, вызываемых из Ring 3. Каждая функция
// получает свой машинный код; ТРИ варианта (StubKind):
//
//  1) trap (kernel .int3):             xor rax,rax; int3; ret
//     App вызывает импорт → int3 (#BP, DPL=3) → ядро по RIP находит entry
//     (findByRip: RIP-1 внутри [stub_addr, stub_addr+SIZE)), логирует
//     «[WIN32] ВЫЗОВ DLL!Func — не реализовано», продвигает RIP на 1
//     (skip int3) → stub делает ret с rax=0 (xor уже исполнен) → приложение
//     ЖИВЁТ и идёт дальше — так собирается ЦЕПОЧКА недостающих функций
//     (Crash-Driven Development: падение → лог → реализуй следующую).
//
//  2) impl (реализовано):              mov rsi,rcx; mov r10,r8;
//                                      movabs rdi,id; mov rax,6; syscall; ret
//     Win64-аргументы RCX/RDX/R8/R9 перекладываются в syscall-конвенцию
//     (rdi=id, rsi=arg1, rdx=arg2, r10=arg3, r9=arg4) → syscall #6
//     (win32_call) → ядро диспетчеризует по id на реальную реализацию
//     (win32_api.zig). Касаем только volatile-регистров Win64 — конвенция
//     не нарушена. Реализовано в v0.10.0: GetStdHandle, GetCommandLineA/W,
//     VirtualAlloc, ExitProcess.
//
//  3) record (нативные тесты):         sub rsp,8; movabs rdi,id;
//                                      movabs rax,stubCommon; call rax;
//                                      add rsp,8; ret
//     Тот же адресный контекст (Linux-тест) — вызов Zig-обработчика напрямую.
//     sub/add rsp,8 — выравнивание под call (movaps-#GP, урок v0.9.0).
//
// ЛОГИЧЕСКИЙ АДРЕС: в ядре стабы лежат в физ. страницах (kernel-identity
// запись) и маппятся в user-VA. Код пишется через identity-указатель
// (Dispatcher.code), а IAT и findByRip работают с USER-адресами:
// logical_base = user-VA буфера стабов; stub_addr = logical_base + off.
//
// ВАЖНО (v0.10.0): стабы Ring 3 НЕ могут вызывать ядро напрямую (call на
// kernel-адрес из Ring 3 = #PF — kernel-страницы supervisor-only), поэтому
// дизайн v0.9.0 «call stubCommon» заменён на int3-трап и syscall-трамплин.
// ============================================================================

const std = @import("std");
const pe = @import("pe.zig");

pub const Pe = pe.Pe;

// ─── Реестр заглушек ────────────────────────────────────────────────────────

pub const MAX_STUB_ENTRIES: usize = 1024;
// v0.11.0: 31 → 48 — memmove-стаб вырос до 41Б (lea-предустановка указателей
// на конец региона для обратного копирования: rep movsb с DF=1 идёт ВНИЗ от
// ТЕКУЩИХ rsi/rdi, а не от конца региона — урок, пойманный исполнением).
pub const STUB_CODE_SIZE: usize = 48;

/// Номер syscall'а «win32_call» (hal.zig: case 6).
pub const WIN32_SYSCALL: u64 = 6;

pub const StubKind = enum {
    trap, // не реализовано: xor rax,rax; int3; ret (kernel)
    impl, // реализовано: syscall-трамплин (kernel)
    record, // нативный тест: call stubCommon
    native, // v0.11.0: чистый Ring-3 код (memset/memcpy/memmove/strlen)
};

/// Вид native-стаба — какие Win64-аргументы обрабатывает сгенерированный код.
pub const NativeKind = enum {
    /// memset(dst=RCX, val=EDX, count=R8) → rep stosb, ретурн dst
    memset,
    /// memcpy(dst=RCX, src=RDX, count=R8) → rep movsb, ретурн dst
    memcpy,
    /// memmove(dst=RCX, src=RDX, count=R8) → направление по cmp dst/src
    memmove,
    /// strlen(s=RCX) → скан до NUL, ретурн длина
    strlen,
};

pub const StubEntry = struct {
    dll: []const u8,
    func: pe.ImportFn,
    kind: StubKind = .trap,
    stub_addr: u64, // ЛОГИЧЕСКИЙ адрес кода (user-VA в ядре; физ — в тестах)
    iat_rva: u32, // RVA IAT-слота (FirstThunk + index*8)
    slot_index: usize,
    code_off: usize, // смещение кода внутри Dispatcher.code
    /// Сколько раз стаб сработал (CDD-статистика; лог — только 1-й вызов)
    hits: usize = 0,
};

pub const TrapMode = enum {
    int3, // ядро: генерировать trap-стабы (#BP → CDD-лог)
    record, // тесты: генерировать record-стабы (фиксация вызова)
};

pub const Dispatcher = struct {
    entries: []StubEntry = &[_]StubEntry{},
    count: usize = 0,
    mode: TrapMode = .int3,

    /// Логический (user-VA) базовый адрес кода стабов. null → использовать
    /// физический адрес code.ptr (нативные тесты, один адресный контекст).
    logical_base: ?u64 = null,

    /// Лог-хук: ядро подключает Serial.puts; тесты — свой сборщик.
    log_fn: ?*const fn (ctx: ?*anyopaque, msg: []const u8) void = null,
    log_ctx: ?*anyopaque = null,

    /// Буфер для режима .record (нативные тесты).
    last_called: usize = std.math.maxInt(usize),
    call_count: usize = 0,

    /// Сгенерированный код (identity-указатель для записи; RX для Ring 3).
    code: ?[]u8 = null,

    pub fn init(entries_buf: []StubEntry, code_buf: []u8, mode: TrapMode) Dispatcher {
        return .{
            .entries = entries_buf,
            .code = code_buf,
            .mode = mode,
        };
    }

    fn stubAddr(self: *const Dispatcher, code_off: usize) u64 {
        if (self.logical_base) |base| return base + code_off;
        return @intFromPtr(self.code.?.ptr + code_off);
    }

    // ─── Генерация машинного кода вариантов ───

    fn writeTrapStub(out: []u8) void {
        @memset(out, 0);
        // 48 31 C0   xor rax, rax     — дефолтный возврат 0 (NULL/ошибка)
        out[0] = 0x48;
        out[1] = 0x31;
        out[2] = 0xC0;
        // CC         int3             — CDD-трап: #BP → ядро логирует имя
        out[3] = 0xCC;
        // C3         ret              — возврат в PE-код с rax=0
        out[4] = 0xC3;
    }

    fn writeRecordStub(out: []u8, entry_id: usize, common_addr: u64) void {
        @memset(out, 0);
        // 48 83 EC 08   sub rsp, 8
        out[0] = 0x48;
        out[1] = 0x83;
        out[2] = 0xEC;
        out[3] = 0x08;
        // 48 BF <id>    movabs rdi, entry_id
        out[4] = 0x48;
        out[5] = 0xBF;
        std.mem.writeInt(u64, out[6..14], entry_id, .little);
        // 48 B8 <fn>    movabs rax, stubCommon
        out[14] = 0x48;
        out[15] = 0xB8;
        std.mem.writeInt(u64, out[16..24], common_addr, .little);
        // FF D0         call rax
        out[24] = 0xFF;
        out[25] = 0xD0;
        // 48 83 C4 08   add rsp, 8
        out[26] = 0x48;
        out[27] = 0x83;
        out[28] = 0xC4;
        out[29] = 0x08;
        // C3            ret
        out[30] = 0xC3;
    }

    /// Syscall-трамплин для РЕАЛИЗОВАННОЙ функции.
    /// Win64-конвенция: RCX/RDX/R8/R9 = аргументы; RSI/RDI/RBX/RBP/R12+ —
    /// НЕВОЛАТИЛЬНЫЕ (callee-saved) — ОБЯЗАНЫ сохраняться!
    /// SysV/syscall-конвенция: rdi=arg1(id), rsi=arg2, rdx=arg3, r10=arg4,
    /// rax=sysnum; r9 читается обработчиком напрямую (Win64 arg4).
    /// ⚠ v0.10.0-dev-баг: mov rsi,rcx без push/pop затирал callee-saved RSI
    /// → вызывающая CRT-функция падала на мусорном указателе (#PF).
    fn writeImplStub(out: []u8, entry_id: usize) void {
        @memset(out, 0);
        // 56            push rsi         — callee-saved (Win64)
        out[0] = 0x56;
        // 57            push rdi         — callee-saved (Win64)
        out[1] = 0x57;
        // 48 89 CE      mov rsi, rcx   — Win64 arg1 → syscall arg2
        out[2] = 0x48;
        out[3] = 0x89;
        out[4] = 0xCE;
        // 4D 89 C2      mov r10, r8    — Win64 arg3 → syscall arg4
        // ⚠ v0.10.0-ЛАТЕНТНЫЙ БАГ (пойман GCC-эталоном в v0.11): байты были
        // 4C 89 C2 = mov rdx, r8 — ЗАТИРАЛ Win64-arg2 (RDX) третьим аргументом
        // и оставлял r10 мусором → все impl-функции с ≥2 аргументами получали
        // перепутанные аргументы (calloc/VirtualAlloc). 1-аргументные
        // (GetStdHandle/malloc) не страдали — потому E2E-цикл №1 это не поймал.
        out[5] = 0x4D;
        out[6] = 0x89;
        out[7] = 0xC2;
        // 48 BF <id>    movabs rdi, entry_id — syscall arg1
        out[8] = 0x48;
        out[9] = 0xBF;
        std.mem.writeInt(u64, out[10..18], entry_id, .little);
        // 48 C7 C0 06 00 00 00   mov rax, WIN32_SYSCALL
        out[18] = 0x48;
        out[19] = 0xC7;
        out[20] = 0xC0;
        out[21] = 0x06; // WIN32_SYSCALL (6) — младший байт imm32
        out[22] = 0x00;
        out[23] = 0x00;
        out[24] = 0x00;
        // 0F 05        syscall
        out[25] = 0x0F;
        out[26] = 0x05;
        // 5F            pop rdi
        out[27] = 0x5F;
        // 5E            pop rsi
        out[28] = 0x5E;
        // C3           ret (rax = результат из ядра)
        out[29] = 0xC3;
        // r9 (Win64 arg4) не трогаем — syscall-обработчик читает его сам;
        // rcx/r11 затирает сама инструкция syscall — они volatile в Win64 ✓
    }

    // ─── v0.11.0: native-стабы (чистый Ring-3 код, без syscall) ───

    /// memset/memcpy/memmove/strlen исполняются НАПРЯМУЮ в Ring 3 — CRT зовёт
    /// их на каждом шагу, syscall-оверхед недопустим. Код соблюдает Win64 ABI:
    /// трогаются только volatile-регистры (+ callee-saved push/pop), DF=0
    /// на выходе, ретурн-значение в RAX.
    ///
    /// ⚠ memset: 20Б / memcpy: 20Б / strlen: 14Б / memmove: 41Б — паддинг нулями;
    ///   слот STUB_CODE_SIZE=48Б (максимум — memmove с lea-хвостами).
    fn writeNativeStub(out: []u8, kind: NativeKind) void {
        @memset(out, 0);
        switch (kind) {
            // memset(dst=RCX, val=EDX, count=R8):
            //   push rdi; mov r9,rcx; mov rdi,rcx; movzx eax,dl;
            //   mov rcx,r8; rep stosb; mov rax,r9; pop rdi; ret
            // ⚠ rep stosb хранит AL (не DL!) — val обязан попасть в AL;
            //   dst для ретурна сохраняется в r9 (volatile 4-й слот — memset
            //   принимает только 3 аргумента, r9 свободен).
            .memset => {
                out[0] = 0x57; // push rdi (callee-saved)
                out[1] = 0x49; // mov r9, rcx — спрятать dst для ретурна
                out[2] = 0x89;
                out[3] = 0xC9;
                out[4] = 0x48; // mov rdi, rcx — rdi = dst
                out[5] = 0x89;
                out[6] = 0xCF;
                out[7] = 0x0F; // movzx eax, dl — val (мл. байт int) → AL
                out[8] = 0xB6;
                out[9] = 0xC2;
                out[10] = 0x4C; // mov rcx, r8 — счётчик
                out[11] = 0x89;
                out[12] = 0xC1;
                out[13] = 0xF3; // rep stosb — заполняет байтом из AL
                out[14] = 0xAA;
                out[15] = 0x4C; // mov rax, r9 — ретурн dst
                out[16] = 0x89;
                out[17] = 0xC8;
                out[18] = 0x5F; // pop rdi
                out[19] = 0xC3; // ret
            },
            // memcpy(dst=RCX, src=RDX, count=R8):
            //   push rsi; push rdi; mov rax,rcx; mov rdi,rcx; mov rsi,rdx;
            //   mov rcx,r8; cld; rep movsb; pop rdi; pop rsi; ret
            .memcpy => {
                out[0] = 0x56; // push rsi
                out[1] = 0x57; // push rdi
                out[2] = 0x48; // mov rax, rcx — return value = dst
                out[3] = 0x89;
                out[4] = 0xC8;
                out[5] = 0x48; // mov rdi, rcx
                out[6] = 0x89;
                out[7] = 0xCF;
                out[8] = 0x48; // mov rsi, rdx
                out[9] = 0x89;
                out[10] = 0xD6;
                out[11] = 0x4C; // mov rcx, r8
                out[12] = 0x89;
                out[13] = 0xC1;
                out[14] = 0xFC; // cld (DF=0 — ABI-гард)
                out[15] = 0xF3; // rep movsb
                out[16] = 0xA4;
                out[17] = 0x5F; // pop rdi
                out[18] = 0x5E; // pop rsi
                out[19] = 0xC3; // ret
            },
            // memmove(dst=RCX, src=RDX, count=R8) — overlap-safe:
            //   dst <= src → forward (cld + rep movsb);
            //   dst >  src → backward: lea ставит rsi/rdi на КОНЕЦ региона
            //   (src/dst + count - 1), std, rep movsb идёт вниз, cld.
            // ⚠ v0.11-урок: rep movsb с DF=1 копирует от ТЕКУЩИХ rsi/rdi ВНИЗ —
            //   без lea-подстройки читает ПАМЯТЬ НИЖЕ буферов (мусор/стек).
            //   push rsi; push rdi; mov rax,rcx; mov rdi,rcx; mov rsi,rdx;
            //   mov rcx,r8; cmp rdi,rsi; jbe .fwd;
            //   lea rsi,[rsi+rcx-1]; lea rdi,[rdi+rcx-1]; std; rep movsb; cld;
            //   jmp .done; .fwd: cld; rep movsb;
            //   .done: pop rdi; pop rsi; ret
            .memmove => {
                out[0] = 0x56; // push rsi
                out[1] = 0x57; // push rdi
                out[2] = 0x48; // mov rax, rcx — return value = dst
                out[3] = 0x89;
                out[4] = 0xC8;
                out[5] = 0x48; // mov rdi, rcx — dst
                out[6] = 0x89;
                out[7] = 0xCF;
                out[8] = 0x48; // mov rsi, rdx — src
                out[9] = 0x89;
                out[10] = 0xD6;
                out[11] = 0x4C; // mov rcx, r8 — count
                out[12] = 0x89;
                out[13] = 0xC1;
                out[14] = 0x48; // cmp rdi, rsi
                out[15] = 0x39;
                out[16] = 0xF7;
                out[17] = 0x76; // jbe .fwd (+16 → 35)
                out[18] = 0x10;
                out[19] = 0x48; // lea rsi, [rsi + rcx - 1] — хвост src
                out[20] = 0x8D;
                out[21] = 0x74;
                out[22] = 0x0E;
                out[23] = 0xFF;
                out[24] = 0x48; // lea rdi, [rdi + rcx - 1] — хвост dst
                out[25] = 0x8D;
                out[26] = 0x7C;
                out[27] = 0x0F;
                out[28] = 0xFF;
                out[29] = 0xFD; // std — обратное копирование
                out[30] = 0xF3; // rep movsb (вниз от хвостов)
                out[31] = 0xA4;
                out[32] = 0xFC; // cld — восстановить DF=0
                out[33] = 0xEB; // jmp .done (+3 → 38)
                out[34] = 0x03;
                out[35] = 0xFC; // .fwd: cld (гард против нарушенного ABI)
                out[36] = 0xF3; // rep movsb — прямое копирование
                out[37] = 0xA4;
                out[38] = 0x5F; // .done: pop rdi
                out[39] = 0x5E; // pop rsi
                out[40] = 0xC3; // ret — 41Б (слот 48Б)
            },
            // strlen(s=RCX) → RAX:
            //   xor eax,eax; .loop: cmp byte [rcx+rax],0; je .done;
            //   inc rax; jmp .loop; .done: ret
            .strlen => {
                out[0] = 0x31; // xor eax, eax
                out[1] = 0xC0;
                out[2] = 0x80; // cmp byte [rcx + rax], 0
                out[3] = 0x3C;
                out[4] = 0x01;
                out[5] = 0x00;
                out[6] = 0x74; // je .done (+5 → 13)
                out[7] = 0x05;
                out[8] = 0x48; // inc rax
                out[9] = 0xFF;
                out[10] = 0xC0;
                out[11] = 0xEB; // jmp .loop (-11 → 2)
                out[12] = 0xF5;
                out[13] = 0xC3; // .done: ret
            },
        }
    }

    // ─── Генерация стабов под все импорты образа ───

    /// Генерирует стаб для КАЖДОЙ функции из таблицы импортов PE.
    /// Не патчит IAT — это делает applyToImage (после копии образа по RVA).
    pub fn generateFor(self: *Dispatcher, image: *const Pe) !usize {
        if (self.code == null) return error.NoCodeBuffer;
        const code_buf = self.code.?;

        var dlls = try image.importDlls();
        var idx: usize = 0;
        while (dlls.next()) |dll| {
            var slot: usize = 0;
            var fns = dll.functions;
            while (fns.next()) |f| {
                if (idx >= self.entries.len) return error.TooManyStubs;
                const code_off = idx * STUB_CODE_SIZE;
                if (code_off + STUB_CODE_SIZE > code_buf.len) return error.CodeBufferTooSmall;

                const out = code_buf[code_off..][0..STUB_CODE_SIZE];
                const kind: StubKind = switch (self.mode) {
                    .int3 => .trap,
                    .record => .record,
                };
                switch (kind) {
                    .trap => writeTrapStub(out),
                    .record => writeRecordStub(out, idx, @intFromPtr(&stubCommon)),
                    .impl => unreachable,
                    .native => unreachable, // только через implementNative
                }

                self.entries[idx] = .{
                    .dll = dll.name,
                    .func = f,
                    .kind = kind,
                    .stub_addr = self.stubAddr(code_off),
                    .iat_rva = dll.iat_rva,
                    .slot_index = slot,
                    .code_off = code_off,
                };
                idx += 1;
                slot += 1;
            }
        }
        self.count = idx;
        return idx;
    }

    /// Пометить импорт dll!func как РЕАЛИЗОВАННЫЙ: перегенерировать его стаб
    /// в syscall-трамплин. Возврат — нашли ли запись (имена case-insensitive).
    pub fn implementBy(self: *Dispatcher, dll_needle: []const u8, func_needle: []const u8) bool {
        if (self.code == null) return false;
        const code_buf = self.code.?;
        for (self.entries[0..self.count]) |*e| {
            if (!std.ascii.eqlIgnoreCase(e.dll, dll_needle)) continue;
            switch (e.func) {
                .by_name => |n| if (std.mem.eql(u8, n, func_needle)) {
                    const off = e.code_off;
                    if (off + STUB_CODE_SIZE > code_buf.len) return false;
                    writeImplStub(code_buf[off..][0..STUB_CODE_SIZE], @intCast(e.code_off / STUB_CODE_SIZE));
                    e.kind = .impl;
                    return true;
                },
                .by_ordinal => {},
            }
        }
        return false;
    }

    /// v0.11.0: перегенерировать стаб dll!func в NATIVE Ring-3 код (без
    /// syscall-оверхеда — CRT зовёт memset/memcpy постоянно). Возврат —
    /// нашли ли запись.
    pub fn implementNative(self: *Dispatcher, dll_needle: []const u8, func_needle: []const u8, kind: NativeKind) bool {
        if (self.code == null) return false;
        const code_buf = self.code.?;
        for (self.entries[0..self.count]) |*e| {
            if (!std.ascii.eqlIgnoreCase(e.dll, dll_needle)) continue;
            switch (e.func) {
                .by_name => |n| if (std.mem.eql(u8, n, func_needle)) {
                    const off = e.code_off;
                    if (off + STUB_CODE_SIZE > code_buf.len) return false;
                    writeNativeStub(code_buf[off..][0..STUB_CODE_SIZE], kind);
                    e.kind = .native;
                    return true;
                },
                .by_ordinal => {},
            }
        }
        return false;
    }

    /// v0.11.0 (GetProcAddress): поиск записи ПО ИМЕНИ по ВСЕМ DLL реестра
    /// (case-insensitive). Первое совпадение — dynaresolv вернёт его stub_addr.
    pub fn findByNameAnyDll(self: *Dispatcher, func_needle: []const u8) ?*StubEntry {
        for (self.entries[0..self.count]) |*e| {
            switch (e.func) {
                .by_name => |n| if (std.ascii.eqlIgnoreCase(n, func_needle)) return e,
                .by_ordinal => {},
            }
        }
        return null;
    }

    /// Патчит IAT скопированного образа: каждый слот получает адрес стаба.
    /// image_mem — identity-указатель ЗАГРУЖЕННОГО образа (запись из CPL=0);
    /// записываемое значение — ЛОГИЧЕСКИЙ (user-VA) адрес стаба.
    pub fn applyToImage(self: *Dispatcher, image_mem: [*]u8) void {
        for (self.entries[0..self.count]) |e| {
            const slot_addr = @intFromPtr(image_mem) + e.iat_rva + e.slot_index * 8;
            const slot: *u64 = @ptrFromInt(slot_addr);
            slot.* = e.stub_addr;
        }
    }

    /// Поиск записи по адресу, ПОКРЫВАЮЩЕМУ RIP (для int3-обработчика):
    /// #BP оставляет RIP = адрес ПОСЛЕ int3 (внутри стаба), поэтому
    /// проверяем принадлежность [stub_addr, stub_addr+SIZE) самому RIP.
    /// Возврат — мутабельный entry (ядро инкрементирует hits для CDD-статистики).
    pub fn findByRip(self: *Dispatcher, rip: u64) ?*StubEntry {
        for (self.entries[0..self.count]) |*e| {
            if (rip >= e.stub_addr and rip < e.stub_addr + STUB_CODE_SIZE) {
                return e;
            }
        }
        return null;
    }

    /// Поиск записи по точному адресу стаба (для трейса).
    pub fn findByAddress(self: *Dispatcher, addr: u64) ?*const StubEntry {
        for (self.entries[0..self.count]) |*e| {
            if (e.stub_addr == addr) return e;
        }
        return null;
    }

    /// Общее число срабатываний (hits по всем entry) — CDD-статистика.
    pub fn totalHits(self: *const Dispatcher) usize {
        var n: usize = 0;
        for (self.entries[0..self.count]) |e| n += e.hits;
        return n;
    }

    fn logf(self: *Dispatcher, comptime fmt: []const u8, args: anytype) void {
        if (self.log_fn) |f| {
            var buf: [256]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
            f(self.log_ctx, msg);
        }
    }

    /// Отчёт о вызове (record-режим): лог + фиксация.
    fn report(self: *Dispatcher, entry_id: usize) void {
        self.last_called = entry_id;
        self.call_count += 1;

        if (entry_id >= self.count) {
            self.logf("[WIN32] стаб #{d}: ВНЕ РЕЕСТРА (переполнение?)\n", .{entry_id});
            return;
        }
        const e = &self.entries[entry_id];
        switch (e.func) {
            .by_name => |n| self.logf(
                "[WIN32] ВЫЗОВ {s}!{s} — не реализовано (stub #{d})\n",
                .{ e.dll, n, entry_id },
            ),
            .by_ordinal => |ord| self.logf(
                "[WIN32] ВЫЗОВ {s}!ordinal#{d} — не реализовано (stub #{d})\n",
                .{ e.dll, ord, entry_id },
            ),
        }
    }
};

// ─── Общий обработчик record-стабов (нативные тесты) ───────────────────────

/// Точка входа record-стабов: rdi = entry_id. В ядре НЕ используется
/// (Ring 3 не может вызвать kernel-адрес — см. шапку).
var dispatcher: ?*Dispatcher = null;

pub fn setDispatcher(d: *Dispatcher) void {
    dispatcher = d;
}

pub fn activeDispatcher() ?*Dispatcher {
    return dispatcher;
}

fn stubCommon(entry_id: usize) callconv(.C) void {
    const d = dispatcher orelse {
        asm volatile ("int3");
        return;
    };
    d.report(entry_id);
    // .record — контроль возвращается стабу → ret → вызывающий
}

// ─── Утилита отчёта для шелла ядра (peinfo/pestubs) ─────────────────────────

pub fn fmtEntryName(entry: *const StubEntry, buf: []u8) []const u8 {
    return switch (entry.func) {
        .by_name => |n| std.fmt.bufPrint(buf, "{s}!{s}", .{ entry.dll, n }) catch "!",
        .by_ordinal => |ord| std.fmt.bufPrint(buf, "{s}!ordinal#{d}", .{ entry.dll, ord }) catch "!",
    };
}

// ============================================================================
// Тесты (нативно). Полный CDD-цикл: parse → generate(record) → load → patch
// IAT → ВЫЗОВ импорта → стаб срабатывает → имя зафиксировано. Плюс байтовая
// верификация trap/trampoline-вариантов (kernel-путь, E2E QEMU).
// ============================================================================

const testing = std.testing;

fn loadFixture(comptime name: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(testing.allocator, name, 64 << 20);
}

var test_log_buf: [4096]u8 = undefined;
var test_log_len: usize = 0;

fn testLogger(_: ?*anyopaque, msg: []const u8) void {
    const n = @min(msg.len, test_log_buf.len - test_log_len);
    @memcpy(test_log_buf[test_log_len .. test_log_len + n], msg[0..n]);
    test_log_len += n;
}

fn testLogContains(needle: []const u8) bool {
    return std.mem.indexOf(u8, test_log_buf[0..test_log_len], needle) != null;
}

/// Симуляция «загруженного» образа (как pe_loader.loadImage, но mmap).
fn mmapImage(image: *const Pe, data: []const u8) ![]align(4096) u8 {
    const img_mem = try std.posix.mmap(
        null,
        image.sizeOfImage() + 0x1000,
        std.posix.PROT.READ | std.posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    @memset(img_mem, 0);
    const hdr_len = @min(image.sizeOfHeaders(), data.len);
    @memcpy(img_mem[0..hdr_len], data[0..hdr_len]);
    for (image.sections) |*sec| {
        if (sec.size_of_raw_data == 0) continue;
        const dst = img_mem[sec.virtual_address .. sec.virtual_address + sec.size_of_raw_data];
        const src = data[sec.pointer_to_raw_data .. sec.pointer_to_raw_data + sec.size_of_raw_data];
        @memcpy(dst, src);
    }
    return img_mem;
}

test "record-стабы: полный CDD-цикл на curl.exe" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);

    const image = try Pe.parse(data);
    const counts = image.countImports();
    try testing.expectEqual(@as(usize, 274), counts.functions);

    // RWX-буфер под код стабов (нативный тест; в ядре — RX-страницы в user-VA)
    const n = counts.functions;
    const code_len = n * STUB_CODE_SIZE + 4096;
    const code_mem = try std.posix.mmap(
        null,
        code_len,
        std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(code_mem);

    const img_mem = try mmapImage(&image, data);
    defer std.posix.munmap(img_mem);

    const entries = try testing.allocator.alloc(StubEntry, n);
    defer testing.allocator.free(entries);

    var disp = Dispatcher.init(entries, code_mem[0..code_len], .record);
    disp.log_fn = testLogger;
    disp.log_ctx = null;

    const generated = try disp.generateFor(&image);
    try testing.expectEqual(n, generated);
    setDispatcher(&disp);

    disp.applyToImage(img_mem.ptr);

    // KERNEL32.dll!CreateFileA: IAT-слот → стаб; прямой вызов через слот
    var create_file_a_addr: ?u64 = null;
    var dlls = try image.importDlls();
    outer: while (dlls.next()) |dll| {
        if (!std.ascii.eqlIgnoreCase(dll.name, "KERNEL32.dll")) continue;
        var slot: usize = 0;
        var fns = dll.functions;
        while (fns.next()) |f| {
            switch (f) {
                .by_name => |fname| if (std.mem.eql(u8, fname, "CreateFileA")) {
                    const slot_off = dll.iat_rva + slot * 8;
                    create_file_a_addr = std.mem.readInt(u64, img_mem[slot_off..][0..8], .little);
                    break :outer;
                },
                .by_ordinal => {},
            }
            slot += 1;
        }
    }
    try testing.expect(create_file_a_addr != null);
    try testing.expect(disp.findByAddress(create_file_a_addr.?) != null);

    const CreateFileA: *const fn () callconv(.C) usize = @ptrFromInt(create_file_a_addr.?);
    _ = CreateFileA();

    try testing.expectEqual(@as(usize, 1), disp.call_count);
    try testing.expect(testLogContains("KERNEL32.dll!CreateFileA"));

    // Второй вызов — WS2_32.dll!WSAStartup
    var wsa_addr: ?u64 = null;
    var dlls2 = try image.importDlls();
    outer2: while (dlls2.next()) |dll| {
        if (!std.ascii.eqlIgnoreCase(dll.name, "WS2_32.dll")) continue;
        var slot: usize = 0;
        var fns = dll.functions;
        while (fns.next()) |f| {
            switch (f) {
                .by_name => |fname| if (std.mem.eql(u8, fname, "WSAStartup")) {
                    const slot_off = dll.iat_rva + slot * 8;
                    wsa_addr = std.mem.readInt(u64, img_mem[slot_off..][0..8], .little);
                    break :outer2;
                },
                .by_ordinal => {},
            }
            slot += 1;
        }
    }
    try testing.expect(wsa_addr != null);
    const WSAStartup: *const fn () callconv(.C) usize = @ptrFromInt(wsa_addr.?);
    _ = WSAStartup();
    try testing.expectEqual(@as(usize, 2), disp.call_count);
    try testing.expect(testLogContains("WS2_32.dll!WSAStartup"));
}

test "trap-стаб: байты xor rax,rax / int3 / ret (kernel .int3-режим)" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);
    const counts = image.countImports();
    const n = @min(counts.functions, 8);

    // полный буфер под ВСЕ стабы (generateFor генерирует весь импорт-набор)
    const entries = try testing.allocator.alloc(StubEntry, counts.functions);
    defer testing.allocator.free(entries);
    const code_buf = try testing.allocator.alloc(u8, counts.functions * STUB_CODE_SIZE);
    defer testing.allocator.free(code_buf);

    var disp = Dispatcher.init(entries, code_buf, .int3);
    // логический базовый адрес = user-VA (как в ядре)
    disp.logical_base = 0x200000000;
    // генерируем стабы через публичный API (полный проход)
    const generated = try disp.generateFor(&image);
    try testing.expectEqual(counts.functions, generated);

    // все kind = trap, адреса = logical_base + off
    for (disp.entries[0..n]) |e| {
        try testing.expectEqual(StubKind.trap, e.kind);
        try testing.expectEqual(@as(u64, 0x200000000 + e.code_off), e.stub_addr);
    }
    // байты первого стаба
    try testing.expectEqual(@as(u8, 0x48), code_buf[0]);
    try testing.expectEqual(@as(u8, 0x31), code_buf[1]);
    try testing.expectEqual(@as(u8, 0xC0), code_buf[2]);
    try testing.expectEqual(@as(u8, 0xCC), code_buf[3]); // int3 @3
    try testing.expectEqual(@as(u8, 0xC3), code_buf[4]); // ret @4
    try testing.expectEqual(@as(u8, 0), code_buf[30]); // паддинг нулевой
}

test "impl-стаб: syscall-трамплин Win64→SysV и findByRip" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);

    const entries = try testing.allocator.alloc(StubEntry, 274);
    defer testing.allocator.free(entries);
    const code_len = 274 * STUB_CODE_SIZE;
    const code_buf = try testing.allocator.alloc(u8, code_len);
    defer testing.allocator.free(code_buf);

    var disp = Dispatcher.init(entries, code_buf, .int3);
    disp.logical_base = 0x200000000;
    const generated = try disp.generateFor(&image);
    try testing.expectEqual(@as(usize, 274), generated);

    // GetStdHandle есть в импортах KERNEL32 — помечаем реализованным
    const ok = disp.implementBy("kernel32.dll", "GetStdHandle");
    try testing.expect(ok);

    var found_impl: ?*const StubEntry = null;
    for (disp.entries[0..disp.count]) |*e| {
        switch (e.func) {
            .by_name => |fname| if (std.mem.eql(u8, fname, "GetStdHandle")) {
                found_impl = e;
            },
            .by_ordinal => {},
        }
    }
    const e = found_impl orelse return error.NoGetStdHandle;
    try testing.expectEqual(StubKind.impl, e.kind);

    // байты трамплина: push rsi; push rdi; mov rsi,rcx; mov r10,r8;
    //                   movabs rdi,id; mov rax,6; syscall; pop rdi; pop rsi; ret
    const off = e.code_off;
    try testing.expectEqual(@as(u8, 0x56), code_buf[off + 0]); // push rsi (callee-saved!)
    try testing.expectEqual(@as(u8, 0x57), code_buf[off + 1]); // push rdi (callee-saved!)
    try testing.expectEqual(@as(u8, 0x48), code_buf[off + 2]);
    try testing.expectEqual(@as(u8, 0x89), code_buf[off + 3]);
    try testing.expectEqual(@as(u8, 0xCE), code_buf[off + 4]); // mov rsi,rcx
    try testing.expectEqual(@as(u8, 0x4D), code_buf[off + 5]); // 4D (v0.11: 4C был mov rdx,r8 — латентный баг)
    try testing.expectEqual(@as(u8, 0x89), code_buf[off + 6]);
    try testing.expectEqual(@as(u8, 0xC2), code_buf[off + 7]); // mov r10,r8
    try testing.expectEqual(@as(u8, 0x48), code_buf[off + 8]);
    try testing.expectEqual(@as(u8, 0xBF), code_buf[off + 9]); // movabs rdi,id
    const id = std.mem.readInt(u64, code_buf[off + 10 ..][0..8], .little);
    try testing.expectEqual(@as(u64, off / STUB_CODE_SIZE), id);
    try testing.expectEqual(@as(u8, 0x48), code_buf[off + 18]);
    try testing.expectEqual(@as(u8, 0xC7), code_buf[off + 19]);
    try testing.expectEqual(@as(u8, 0x06), code_buf[off + 21]); // syscall#6
    try testing.expectEqual(@as(u8, 0x0F), code_buf[off + 25]);
    try testing.expectEqual(@as(u8, 0x05), code_buf[off + 26]); // syscall
    try testing.expectEqual(@as(u8, 0x5F), code_buf[off + 27]); // pop rdi
    try testing.expectEqual(@as(u8, 0x5E), code_buf[off + 28]); // pop rsi
    try testing.expectEqual(@as(u8, 0xC3), code_buf[off + 29]); // ret

    // findByRip: RIP после int3 (trap-стаб: int3@3 → rip=base+4) находит entry
    const any_trap = blk: {
        for (disp.entries[0..disp.count]) |*t| {
            if (t.kind == .trap) break :blk t;
        }
        return error.NoTrapStub;
    };
    const rip = any_trap.stub_addr + 4; // RIP ПОСЛЕ int3
    const by_rip = disp.findByRip(rip) orelse return error.FindByRipFailed;
    try testing.expectEqual(any_trap.stub_addr, by_rip.stub_addr);
    // чужой RIP — мимо
    try testing.expect(disp.findByRip(0x7000000000) == null);
}

test "fmtEntryName: имя для CDD-лога" {
    var buf: [128]u8 = undefined;
    const e = StubEntry{
        .dll = "user32.dll",
        .func = .{ .by_name = "CreateWindowExW" },
        .stub_addr = 0,
        .iat_rva = 0,
        .slot_index = 0,
        .code_off = 0,
    };
    const name = fmtEntryName(&e, &buf);
    try testing.expectEqualStrings("user32.dll!CreateWindowExW", name);
}

// ─── v0.11.0: native-стабы — РЕАЛЬНОЕ ИСПОЛНЕНИЕ сгенерированного кода ─────

/// Вызов стаба с Win64-размещением аргументов (RCX/RDX/R8) — так же, как
/// его вызовет PE-приложение из Ring 3. Тестовый драйвер (нативный x86_64):
/// аргументы кладём в регистры сами, адрес — в r11, call *r11.
fn win64Call3(fn_addr: u64, a1: u64, a2: u64, a3: u64) u64 {
    return asm volatile ("call *%[f]"
        : [ret] "={rax}" (-> u64),
        : [f] "{r11}" (fn_addr),
          [a1] "{rcx}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r8}" (a3),
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "rax", "rsi", "rdi", "memory"
    );
}

fn win64Call1(fn_addr: u64, a1: u64) u64 {
    return asm volatile ("call *%[f]"
        : [ret] "={rax}" (-> u64),
        : [f] "{r11}" (fn_addr),
          [a1] "{rcx}" (a1),
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "rax", "rsi", "rdi", "memory"
    );
}

test "native-стабы: memset/memcpy/memmove/strlen на реальном curl.exe-реестре" {
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;

    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);
    const counts = image.countImports();

    const entries = try testing.allocator.alloc(StubEntry, counts.functions);
    defer testing.allocator.free(entries);
    const code_len = counts.functions * STUB_CODE_SIZE;
    // RWX: и запись кода, и исполнение (нативный тест; ядро пишет по identity)
    const code_mem = try std.posix.mmap(
        null,
        code_len + 4096,
        std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(code_mem);

    var disp = Dispatcher.init(entries, code_mem[0..code_len], .int3);
    const generated = try disp.generateFor(&image);
    try testing.expectEqual(counts.functions, generated);

    // Реальные DLL-раскладки curl.exe (проверено парсером PE):
    //   memset/strlen → api-ms-win-crt-string; memcpy/memmove → api-ms-win-crt-private
    const ok1 = disp.implementNative("api-ms-win-crt-string-l1-1-0.dll", "memset", .memset);
    const ok2 = disp.implementNative("api-ms-win-crt-private-l1-1-0.dll", "memcpy", .memcpy);
    const ok3 = disp.implementNative("api-ms-win-crt-private-l1-1-0.dll", "memmove", .memmove);
    const ok4 = disp.implementNative("api-ms-win-crt-string-l1-1-0.dll", "strlen", .strlen);
    try testing.expect(ok1 and ok2 and ok3 and ok4);

    const memset_addr = (disp.findByNameAnyDll("memset") orelse return error.NoMemset).stub_addr;
    const memcpy_addr = (disp.findByNameAnyDll("memcpy") orelse return error.NoMemcpy).stub_addr;
    const memmove_addr = (disp.findByNameAnyDll("memmove") orelse return error.NoMemmove).stub_addr;
    const strlen_addr = (disp.findByNameAnyDll("strlen") orelse return error.NoStrlen).stub_addr;

    // kind установлен
    try testing.expectEqual(StubKind.native, (disp.findByNameAnyDll("memset").?).kind);

    // ── memset: заполнение + ретурн dst ──
    var mbuf: [64]u8 = undefined;
    @memset(&mbuf, 0xAA);
    const ret = win64Call3(memset_addr, @intFromPtr(&mbuf), 0x5A, 32);
    try testing.expectEqual(@intFromPtr(&mbuf), ret); // memset возвращает dst
    for (mbuf[0..32]) |b| try testing.expectEqual(@as(u8, 0x5A), b);
    for (mbuf[32..]) |b| try testing.expectEqual(@as(u8, 0xAA), b); // хвост не тронут

    // memset с val > 0xFF: используется только мл. байт
    _ = win64Call3(memset_addr, @intFromPtr(&mbuf), 0x1234_5678, 8);
    for (mbuf[0..8]) |b| try testing.expectEqual(@as(u8, 0x78), b);

    // memset(0): count=0 → ничего
    @memset(&mbuf, 0x11);
    _ = win64Call3(memset_addr, @intFromPtr(&mbuf), 0x22, 0);
    try testing.expectEqual(@as(u8, 0x11), mbuf[0]);

    // ── memcpy: копирование + ретурн dst ──
    const src = "POLER-OS native memcpy stub!";
    var dbuf: [64]u8 = undefined;
    @memset(&dbuf, 0);
    const src_ptr: [*]const u8 = src.ptr;
    const cret = win64Call3(memcpy_addr, @intFromPtr(&dbuf), @intFromPtr(src_ptr), src.len);
    try testing.expectEqual(@intFromPtr(&dbuf), cret);
    try testing.expectEqualStrings(src, dbuf[0..src.len]);

    // ── memmove: overlap dst > src (backward) и dst < src (forward) ──
    // dst > src: сдвиг вправо на 2 — ветка обратного копирования (std)
    var obuf: [32]u8 = undefined;
    @memcpy(&obuf, "abcdefghijklmnopqrstuvwxyz012345");
    _ = win64Call3(memmove_addr, @intFromPtr(&obuf[2]), @intFromPtr(&obuf[0]), 26);
    try testing.expectEqualStrings("ab" ++ "abcdefghijklmnopqrstuvwx", obuf[0..26]);

    // dst < src: сдвиг влево на 2 — ветка прямого копирования
    @memcpy(&obuf, "abcdefghijklmnopqrstuvwxyz012345");
    _ = win64Call3(memmove_addr, @intFromPtr(&obuf[0]), @intFromPtr(&obuf[2]), 26);
    try testing.expectEqualStrings("cdefghijklmnopqrstuvwxyz01", obuf[0..26]);

    // ── strlen ──
    const s1 = "Hello, POLER-OS!";
    var zbuf: [64]u8 = undefined;
    @memcpy(zbuf[0..s1.len], s1);
    zbuf[s1.len] = 0;
    try testing.expectEqual(@as(u64, s1.len), win64Call1(strlen_addr, @intFromPtr(&zbuf)));
    try testing.expectEqual(@as(u64, 0), win64Call1(strlen_addr, @intFromPtr(&zbuf[s1.len])));

    // memmove-стаб: ret на смещении 40 (41Б код в слоте 48)
    const moff = (disp.findByNameAnyDll("memmove").?).code_off;
    try testing.expectEqual(@as(u8, 0xC3), code_mem[moff + 40]);
}

test "findByNameAnyDll: case-insensitive, все DLL" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);
    const counts = image.countImports();
    const entries = try testing.allocator.alloc(StubEntry, counts.functions);
    defer testing.allocator.free(entries);
    const code_buf = try testing.allocator.alloc(u8, counts.functions * STUB_CODE_SIZE);
    defer testing.allocator.free(code_buf);

    var disp = Dispatcher.init(entries, code_buf, .int3);
    _ = try disp.generateFor(&image);

    // Имя в верхнем регистре, DLL-агностик
    const e = disp.findByNameAnyDll("WSASTARTUP") orelse return error.NotFound;
    try testing.expectEqualStrings("WS2_32.dll", e.dll);
    // несуществующее
    try testing.expect(disp.findByNameAnyDll("NoSuchFuncHere") == null);
}
