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
    /// strcmp(s1=RCX, s2=RDX) → лексикографическая разница (int)
    strcmp,
    /// strncmp(s1=RCX, s2=RDX, n=R8) → разница до n байт (int)
    strncmp,
    /// _initterm(pfnStart=RCX, pfnEnd=RDX): цикл вызова C++-инициализаторов
    /// (msvcrt — 7-Zip; NULL-пропуск, Win64 ABI) — 38Б, слот 48Б
    initterm,
    /// _initterm_e: то же + int-результат (≠0 → немедленный возврат) — 48Б
    initterm_e,
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

/// Номер syscall'а завершения Win64-колбэка (hal.zig: case 7).
pub const CB_SYSCALL_DONE: u64 = 7;
/// Cookie моста колбэка (запекается в trampoline, проверяется callbackDone).
pub const CALLBACK_COOKIE: u64 = 0x504F_4C45_4342_3121; // "POLECB1!"

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
            // strcmp(s1=RCX, s2=RDX) → EAX = (int)(s1[i] - s2[i]) на первом
            // различии (или 0 при равенстве). ⚠ v0.12-урок: trap-стаб отвечал
            // rax=0 = «строки РАВНЫ» — ЛОЖЬ заворачивала curl в дикую ветку
            // (module-walk → exit(1)). strcmp обязан говорить ПРАВДУ.
            //   xor eax,eax
            //   .loop: movzx r8d,[rcx+rax]; movzx r9d,[rdx+rax];
            //           cmp r8d,r9d; jne .done; test r8d,r8d; je .done;
            //           inc rax; jmp .loop
            //   .done:  mov eax,r8d; sub eax,r9d; ret
            .strcmp => {
                out[0] = 0x31; // xor eax, eax
                out[1] = 0xC0;
                out[2] = 0x44; // movzx r8d, byte [rcx + rax]
                out[3] = 0x0F;
                out[4] = 0xB6;
                out[5] = 0x04;
                out[6] = 0x01;
                out[7] = 0x44; // movzx r9d, byte [rdx + rax]
                out[8] = 0x0F;
                out[9] = 0xB6;
                out[10] = 0x0C; // ⚠ modrm reg=001 (+REX.R) → r9d! (04 = r8d — v0.12-уловка objdump)
                out[11] = 0x02;
                out[12] = 0x45; // cmp r8d, r9d
                out[13] = 0x39;
                out[14] = 0xC8;
                out[15] = 0x75; // jne .done (+10 → 27)
                out[16] = 0x0A;
                out[17] = 0x45; // test r8d, r8d
                out[18] = 0x85;
                out[19] = 0xC0;
                out[20] = 0x74; // je .done (+5 → 27)
                out[21] = 0x05;
                out[22] = 0x48; // inc rax
                out[23] = 0xFF;
                out[24] = 0xC0;
                out[25] = 0xEB; // jmp .loop (-25 → 2)
                out[26] = 0xE7;
                out[27] = 0x44; // .done: mov eax, r8d
                out[28] = 0x89;
                out[29] = 0xC0;
                out[30] = 0x44; // sub eax, r9d
                out[31] = 0x29;
                out[32] = 0xC8;
                out[33] = 0xC3; // ret — 34Б (слот 48Б)
            },
            // strncmp(s1=RCX, s2=RDX, n=R8) → EAX — семантика C99:
            //   while(n && *s1 && *s1==*s2) {s1++;s2++;n--;}
            //   return n ? (int)((uchar)*s1 - (uchar)*s2) : 0;
            // ⚠ v0.12-урок №2 (как strcmp): trap-стаб отвечал rax=0 =
            // «строки РАВНЫ» → curl'овский `!strncmp("-", url, 1)` считал
            // ЛЮБОЙ аргумент опцией («option http://…: is unknown»).
            // strncmp обязан говорить ПРАВДУ.
            //   xor eax,eax; test r8,r8; jz .ret0;
            //   .loop: movzx r9d,[rcx+rax]; movzx r10d,[rdx+rax];
            //           cmp r9d,r10d; jne .diff; test r9d,r9d; je .diff;
            //           inc rax; dec r8; jnz .loop;
            //   .ret0: xor eax,eax; ret;        ; ⚠ rax = ИНДЕКС → ОБНУЛИТЬ
            //   .diff: mov eax,r9d; sub eax,r10d; ret
            .strncmp => {
                out[0] = 0x31; // xor eax, eax
                out[1] = 0xC0;
                out[2] = 0x4D; // test r8, r8 — REX.R+B (r8 в reg и rm)
                out[3] = 0x85;
                out[4] = 0xC0;
                out[5] = 0x74; // jz .ret0 (+28 → 35)
                out[6] = 0x1C;
                out[7] = 0x44; // movzx r9d, byte [rcx + rax]
                out[8] = 0x0F;
                out[9] = 0xB6;
                out[10] = 0x0C;
                out[11] = 0x01;
                out[12] = 0x44; // movzx r10d, byte [rdx + rax]
                out[13] = 0x0F;
                out[14] = 0xB6;
                out[15] = 0x14;
                out[16] = 0x02;
                out[17] = 0x4D; // cmp r9d, r10d — REX.R+B
                out[18] = 0x39;
                out[19] = 0xCA;
                out[20] = 0x75; // jne .diff (+16 → 38)
                out[21] = 0x10;
                out[22] = 0x45; // test r9d, r9d — REX.R+B
                out[23] = 0x85;
                out[24] = 0xC9;
                out[25] = 0x74; // je .diff (+11 → 38) — s1 кончился
                out[26] = 0x0B;
                out[27] = 0x48; // inc rax
                out[28] = 0xFF;
                out[29] = 0xC0;
                out[30] = 0x49; // dec r8 — REX.W+B
                out[31] = 0xFF;
                out[32] = 0xC8;
                out[33] = 0x75; // jnz .loop (-28 → 7)
                out[34] = 0xE4;
                out[35] = 0x31; // .ret0: xor eax, eax — rax был ИНДЕКСОМ!
                out[36] = 0xC0;
                out[37] = 0xC3; // ret (eax=0)
                out[38] = 0x44; // .diff: mov eax, r9d
                out[39] = 0x89;
                out[40] = 0xC8;
                out[41] = 0x44; // sub eax, r10d
                out[42] = 0x29;
                out[43] = 0xD0;
                out[44] = 0xC3; // ret — 45Б (слот 48Б)
            },
            // _initterm(pfnStart=RCX, pfnEnd=RDX): цикл C++-инициализаторов
            // msvcrt (7-Zip, MSVC /MD). GNU as (scripts/initterm-native.s):
            //   push rbp; push rbx; mov rbx,rcx; mov rbp,rdx; sub rsp,0x28;
            //   .loop: cmp rbx,rbp; jae .done; mov rax,[rbx]; test rax,rax;
            //   jz .next; call rax; .next: add rbx,8; jmp .loop;
            //   .done: add rsp,0x28; pop rbx; pop rbp; ret — 38Б.
            // ABI: rbx/rbp callee-saved (сохранены), rsp≡0 перед call
            // (entry ≡8; 2 push → ≡8; −0x28 → ≡0), shadow 32Б в 0x28.
            .initterm => {
                out[0] = 0x55; // push rbp
                out[1] = 0x53; // push rbx
                out[2] = 0x48; // mov rbx, rcx
                out[3] = 0x89;
                out[4] = 0xCB;
                out[5] = 0x48; // mov rbp, rdx
                out[6] = 0x89;
                out[7] = 0xD5;
                out[8] = 0x48; // sub rsp, 0x28
                out[9] = 0x83;
                out[10] = 0xEC;
                out[11] = 0x28;
                out[12] = 0x48; // .loop: cmp rbx, rbp
                out[13] = 0x39;
                out[14] = 0xEB;
                out[15] = 0x73; // jae .done (+16 → 33)
                out[16] = 0x10;
                out[17] = 0x48; // mov rax, [rbx]
                out[18] = 0x8B;
                out[19] = 0x03;
                out[20] = 0x48; // test rax, rax
                out[21] = 0x85;
                out[22] = 0xC0;
                out[23] = 0x74; // jz .next (+2 → 27)
                out[24] = 0x02;
                out[25] = 0xFF; // call rax
                out[26] = 0xD0;
                out[27] = 0x48; // .next: add rbx, 8
                out[28] = 0x83;
                out[29] = 0xC3;
                out[30] = 0x08;
                out[31] = 0xEB; // jmp .loop (-21 → 12)
                out[32] = 0xEB;
                out[33] = 0x48; // .done: add rsp, 0x28
                out[34] = 0x83;
                out[35] = 0xC4;
                out[36] = 0x28;
                out[37] = 0x5B; // pop rbx
                out[38] = 0x5D; // pop rbp
                out[39] = 0xC3; // ret — 40Б (слот 48Б)
            },
            // _initterm_e: int-инициализаторы (≠0 → немедленный возврат кода):
            //   … call rax; or eax,eax; jnz .out; … .ok: xor eax,eax; .out: …
            //   — ровно 48Б (слот 48Б). GNU as — байт-в-байт (см. скрипт).
            .initterm_e => {
                out[0] = 0x55; // push rbp
                out[1] = 0x53; // push rbx
                out[2] = 0x48; // mov rbx, rcx
                out[3] = 0x89;
                out[4] = 0xCB;
                out[5] = 0x48; // mov rbp, rdx
                out[6] = 0x89;
                out[7] = 0xD5;
                out[8] = 0x48; // sub rsp, 0x28
                out[9] = 0x83;
                out[10] = 0xEC;
                out[11] = 0x28;
                out[12] = 0x48; // .loop: cmp rbx, rbp
                out[13] = 0x39;
                out[14] = 0xEB;
                out[15] = 0x73; // jae .ok (+20 → 37)
                out[16] = 0x14;
                out[17] = 0x48; // mov rax, [rbx]
                out[18] = 0x8B;
                out[19] = 0x03;
                out[20] = 0x48; // test rax, rax
                out[21] = 0x85;
                out[22] = 0xC0;
                out[23] = 0x74; // jz .next (+6 → 31)
                out[24] = 0x06;
                out[25] = 0xFF; // call rax
                out[26] = 0xD0;
                out[27] = 0x09; // or eax, eax
                out[28] = 0xC0;
                out[29] = 0x75; // jnz .out (+8 → 39)
                out[30] = 0x08;
                out[31] = 0x48; // .next: add rbx, 8
                out[32] = 0x83;
                out[33] = 0xC3;
                out[34] = 0x08;
                out[35] = 0xEB; // jmp .loop (-25 → 12)
                out[36] = 0xE7;
                out[37] = 0x31; // .ok: xor eax, eax
                out[38] = 0xC0;
                out[39] = 0x48; // .out: add rsp, 0x28
                out[40] = 0x83;
                out[41] = 0xC4;
                out[42] = 0x28;
                out[43] = 0x5B; // pop rbx
                out[44] = 0x5D; // pop rbp
                out[45] = 0xC3; // ret — 46Б (слот 48Б)
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

    /// v0.12.0: добавить запись ВНЕ PE-импортов образа (функции, которые
    /// приложение получает НЕ через IAT, а через возвращённые нами таблицы —
    /// SSPI SecurityFunctionTable от InitSecurityInterfaceA). Код пишется в
    /// слоте [count], entry_id = count, счётчик растёт. kind=.impl →
    /// syscall-трамплин (диспетчеризуется ядром); kind=.trap → int3-CDD-лог.
    /// Буфер кода должен быть зарезервирован с запасом (main64).
    pub fn addExtraStub(self: *Dispatcher, dll: []const u8, func_name: []const u8, kind: StubKind) ?*StubEntry {
        if (self.code == null) return null;
        const code_buf = self.code.?;
        if (self.count >= self.entries.len) return null;
        const idx = self.count;
        const code_off = idx * STUB_CODE_SIZE;
        if (code_off + STUB_CODE_SIZE > code_buf.len) return null;

        const out = code_buf[code_off..][0..STUB_CODE_SIZE];
        switch (kind) {
            .trap => writeTrapStub(out),
            .impl => writeImplStub(out, idx),
            .record => writeRecordStub(out, idx, @intFromPtr(&stubCommon)),
            .native => return null, // native-стабы задаются kind-машиной генерации
        }
        self.entries[idx] = .{
            .dll = dll,
            .func = .{ .by_name = func_name },
            .kind = kind,
            .stub_addr = self.stubAddr(code_off),
            .iat_rva = 0, // не привязан к IAT
            .slot_index = 0,
            .code_off = code_off,
        };
        self.count += 1;
        return &self.entries[idx];
    }

    // ─── v0.12.0: мост запуска Win64-колбэка (InitOnceExecuteOnce) ──────────
    //
    // Проблема: InitOnceExecuteOnce(InitOnce, InitFn, Parameter, Context)
    // требует ИСПОЛНИТЬ InitFn — код Ring 3 c Win64-ABI (RCX/RDX/R8). Из
    // syscall-обработчика (CPL=0) прямой call возможен, но колбэк, вызвав
    // любой импорт-трамплин, сделает syscall ИЗ CPL=0 → SYSRET всегда
    // возвращает Ring 3 → ядро-код на CPL=3 → #PF-катастрофа.
    //
    // Решение — мост из трёх артефактов в user-VA (слоты после всех стабов):
    //   mailbox (32Б): {init_once, parameter, context, target} — ядро пишет
    //                  перед запуском (identity-указатель), launcher читает.
    //   launcher:      вход через sysretq (RCX=launcher, RSP=16-aligned):
    //                  mov rcx,[mailbox+0]; mov rdx,[mailbox+8]; mov r8,
    //                  [mailbox+16]; push trampoline; jmp [mailbox+24]
    //                  → колбэк получает Win64-аргументы, его ret уходит на
    //                  trampoline (выравнивание стека — как настоящий call).
    //   trampoline:    mov rsi,rax (результат); movabs rdi,cookie;
    //                  movabs rax,SYSCALL_CB_DONE; syscall — ядро по cookie
    //                  восстанавливает СОХРАНЁННЫЙ syscall-кадр (см.
    //                  win32_api.CallbackState) и возвращает управление в
    //                  точку ПОСЛЕ исходного syscall'а с RAX=TRUE. Если ядро
    //                  не смогло — trampoline крутится в jmp $ (не падает).
    //
    // done_target: адрес, пушимый launcher'ом как return-адрес колбэка.
    // null → собственный trampoline (путь ядра). Нативные тесты подменяют
    // его своим стабом, чтобы исполнить весь мост без реального syscall'а.

    pub const CallbackBridge = struct {
        launcher_va: u64, // user-VA (sysretq RCX)
        trampoline_va: u64, // user-VA (адрес возврата колбэка)
        mailbox_va: u64, // user-VA (32Б: ядро пишет, launcher читает)
        mailbox_off: usize, // смещение в Dispatcher.code (identity-запись)
    };

    /// Сгенерировать мост в слотах [count..count+3). ВАЖНО: вызывать ПОСЛЕ
    /// всех addExtraStub (слоты должны остаться последними в регионе).
    pub fn buildCallbackBridge(self: *Dispatcher, done_target: ?u64, syscall_num: u64, cookie: u64) ?CallbackBridge {
        if (self.code == null) return null;
        const code_buf = self.code.?;
        if (self.count + 3 > self.entries.len) return null;
        const base_off = self.count * STUB_CODE_SIZE;
        if (base_off + 3 * STUB_CODE_SIZE > code_buf.len) return null;

        const launcher_off = base_off;
        const trampoline_off = base_off + STUB_CODE_SIZE;
        const mailbox_off = base_off + 2 * STUB_CODE_SIZE;

        // mailbox: нули (ядро заполнит перед каждым запуском)
        @memset(code_buf[mailbox_off..][0..STUB_CODE_SIZE], 0);

        const launcher_va = self.stubAddr(launcher_off);
        const trampoline_va = self.stubAddr(trampoline_off);
        const mailbox_va = self.stubAddr(mailbox_off);
        // Кому колбэк вернётся: свой trampoline (ядро) или тест-стаб.
        const ret_target = done_target orelse trampoline_va;

        // ── launcher (42Б в слоте 48) ──
        //   48 8B 0D <rel32>   mov rcx, [rip+d]   ; init_once
        //   48 8B 15 <rel32>   mov rdx, [rip+d]   ; parameter
        //   4C 8B 05 <rel32>   mov r8,  [rip+d]   ; context
        //   48 B8 <imm64>      movabs rax, ret_target
        //   50                 push rax            ; return-адрес колбэка
        //   4C 8B 1D <rel32>   mov r11, [rip+d]   ; target (InitFn)
        //   41 FF E3           jmp r11             ; хвостовой уход в колбэк
        // Вход через sysretq: RSP 16-aligned → push → RSP%16==8 на входе
        // колбэка — в точности Win64-контракт настоящего call.
        const L = code_buf[launcher_off..][0..STUB_CODE_SIZE];
        @memset(L, 0);
        L[0] = 0x48;
        L[1] = 0x8B;
        L[2] = 0x0D;
        writeRel32(L[3..7], mailbox_off, launcher_off + 7); // rcx ← [mb+0]
        L[7] = 0x48;
        L[8] = 0x8B;
        L[9] = 0x15;
        writeRel32(L[10..14], mailbox_off + 8, launcher_off + 14); // rdx ← [mb+8]
        L[14] = 0x4C;
        L[15] = 0x8B;
        L[16] = 0x05;
        writeRel32(L[17..21], mailbox_off + 16, launcher_off + 21); // r8 ← [mb+16]
        L[21] = 0x48;
        L[22] = 0xB8; // movabs rax, ret_target
        std.mem.writeInt(u64, L[23..31], ret_target, .little);
        L[31] = 0x50; // push rax
        L[32] = 0x4C;
        L[33] = 0x8B;
        L[34] = 0x1D;
        writeRel32(L[35..39], mailbox_off + 24, launcher_off + 39); // r11 ← [mb+24]
        L[39] = 0x41;
        L[40] = 0xFF;
        L[41] = 0xE3; // jmp r11

        // ── trampoline (27Б) ──
        //   48 89 C6            mov rsi, rax       ; SysV arg2 = результат
        //   48 BF <cookie>      movabs rdi, cookie ; SysV arg1
        //   48 B8 <num>         movabs rax, syscall_num
        //   0F 05               syscall
        //   EB FE               jmp $ (ядро не вернулось — не падаем)
        const T = code_buf[trampoline_off..][0..STUB_CODE_SIZE];
        @memset(T, 0);
        T[0] = 0x48;
        T[1] = 0x89;
        T[2] = 0xC6; // mov rsi, rax
        T[3] = 0x48;
        T[4] = 0xBF; // movabs rdi, cookie
        std.mem.writeInt(u64, T[5..13], cookie, .little);
        T[13] = 0x48;
        T[14] = 0xB8; // movabs rax, num
        std.mem.writeInt(u64, T[15..23], syscall_num, .little);
        T[23] = 0x0F;
        T[24] = 0x05; // syscall
        T[25] = 0xEB;
        T[26] = 0xFE; // jmp $

        return .{
            .launcher_va = launcher_va,
            .trampoline_va = trampoline_va,
            .mailbox_va = mailbox_va,
            .mailbox_off = mailbox_off,
        };
    }

    /// rel32 для rip-адресации: значение по адресу target_off читается
    /// инструкцией, ЗАКАНЧИВАЮЩЕЙСЯ на end_off.
    fn writeRel32(out: []u8, target_off: usize, end_off: usize) void {
        const rel: i32 = @intCast(@as(i64, @intCast(target_off)) - @as(i64, @intCast(end_off)));
        std.mem.writeInt(i32, out[0..4], rel, .little);
    }

    // ─── v0.12.0 (CDD №3, fix-волна): native bsearch (127Б, 3 слота) ────

    /// bsearch(key=RCX, base=RDX, nmemb=R8, size=R9, compar=[rsp+8]):
    /// классический бинарный поиск, вызов компаратора ПО Win64-контракту
    /// (32Б shadow + выравнивание 16 на call). РАБОТАЕТ В RING 3 — компаратор
    /// (код приложения, напр. alias-compare curl) вызывается с привилегиями
    /// ПРИЛОЖЕНИЯ: любые стабы внутри него (strcmp-native, syscall-трамплины)
    /// полностью легальны. ⚠ trap-стаб возвращал NULL = «не найдено» →
    /// getparameter не находил ДАЖЕ «--url» (каждый голый URL — это опция
    /// --url!) → «curl: option http://…: is unknown». БД машинного кода ниже
    /// проверена objdump-дизассемблированием.
    ///
    /// Код:
    ///   push r12; push r13; push r14; push r15; push rbx; push rbp;
    ///   sub rsp,0x28                     ; shadow 32 + выравнивание
    ///   rbx=key, rbp=base, r12=two(nmemb), r13=size, r14=[rsp+0x60]=compar
    ///   test r12,r12; jz .nf
    /// .loop:
    ///   rax=r12; shr rax,1; r15=half; rcx=half; imul rcx,r13;
    ///   lea rdx,[rbp+rcx]  ; p
    ///   mov rcx,rbx; call r14            ; c=compar(key,p)
    ///   test eax,eax; jz .found; js .lower
    ///   ; c>0: base=p+size; two-=half+1; jz .nf; jmp .loop
    /// .lower: r12=half; jmp .loop
    /// .found: rax=rdx → epilogue
    /// .nf:    rax=0     → epilogue
    fn writeNativeBsearch(out: []u8) void {
        @memset(out, 0);
        // Сгенерировано GNU as, проверено objdump (142Б в 3 слотах 144Б).
        // ⚠ v0.12-урок №3 (ГЛАВНЫЙ): p НЕ ХРАНИТЬ В VOLATILE-РЕГИСТРЕ!
        //   Ранняя версия держала p в RDX: после `call r14` компаратор/strcmp
        //   ЗАТРАПЛИВАЛИ RDX (Win64 ABI: RDX volatile) → путь c>0 писал в
        //   base МУСОР (mov rbp,rdx), .found возвращал МУСОР. Теперь p
        //   ПЕРЕСЧИТЫВАЕТСЯ из callee-saved: base(rbp) + half(r15)*size(r13).
        // ⚠ v0.12-урок №3b: test two/two КАЖДУЮ итерацию (while-семантика
        //   glibc): .lower (two=half) может обнулить two при half=0.
        // ⚠ конвенция Win64: arg5 у callee — [entry_rsp+0x28] (ПОСЛЕ 32Б
        //   shadow; подтверждено дизассемблированием вызова MultiByteToWideChar
        //   в curl: arg5 кладётся в 0x20(%rsp) у CALLER'а) → [rsp+0x80].
        const code = [142]u8{
            0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
            0x53, 0x55, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89,
            0xCB, 0x48, 0x89, 0xD5, 0x4D, 0x89, 0xC4, 0x4D,
            0x89, 0xCD, 0x4C, 0x8B, 0xB4, 0x24, 0x80, 0x00,
            0x00, 0x00, 0x4D, 0x85, 0xE4, 0x74, 0x56, 0x4C,
            0x89, 0xE0, 0x48, 0xD1, 0xE8, 0x49, 0x89, 0xC7,
            0x48, 0x89, 0xC1, 0x49, 0x0F, 0xAF, 0xCD, 0x48,
            0x8D, 0x54, 0x0D, 0x00, 0x48, 0x89, 0xD9, 0x41,
            0xFF, 0xD6, 0x85, 0xC0, 0x74, 0x1C, 0x78, 0x15,
            0x49, 0x8D, 0x47, 0x01, 0x49, 0x0F, 0xAF, 0xC5,
            0x48, 0x01, 0xC5, 0x4D, 0x29, 0xFC, 0x49, 0xFF,
            0xCC, 0x74, 0x22, 0xEB, 0xC5, 0x4D, 0x89, 0xFC,
            0xEB, 0xC0, 0x4C, 0x89, 0xF8, 0x49, 0x0F, 0xAF,
            0xC5, 0x48, 0x8D, 0x44, 0x05, 0x00, 0x48, 0x83,
            0xC4, 0x28, 0x5D, 0x5B, 0x41, 0x5F, 0x41, 0x5E,
            0x41, 0x5D, 0x41, 0x5C, 0xC3, 0x31, 0xC0, 0x48,
            0x83, 0xC4, 0x28, 0x5D, 0x5B, 0x41, 0x5F, 0x41,
            0x5E, 0x41, 0x5D, 0x41, 0x5C, 0xC3,
        };
        @memcpy(out[0..code.len], &code);
    }

    /// Пометить dll!func как native-В bsearch (код в слотах [count+3..count+6),
    /// ПОСЛЕ моста). Возврат — нашли ли запись.
    pub fn implementNativeBsearch(self: *Dispatcher, dll_needle: []const u8, func_needle: []const u8) bool {
        if (self.code == null) return false;
        const code_buf = self.code.?;
        const off = (self.count + 3) * STUB_CODE_SIZE; // после launcher/tramp/mailbox
        if (off + 3 * STUB_CODE_SIZE > code_buf.len) return false;
        for (self.entries[0..self.count]) |*e| {
            if (!std.ascii.eqlIgnoreCase(e.dll, dll_needle)) continue;
            switch (e.func) {
                .by_name => |n| if (std.mem.eql(u8, n, func_needle)) {
                    writeNativeBsearch(code_buf[off..][0..3 * STUB_CODE_SIZE]);
                    e.kind = .native;
                    e.stub_addr = self.stubAddr(off);
                    return true;
                },
                .by_ordinal => {},
            }
        }
        return false;
    }

    // ─── v0.14.0 (CDD №5): native qsort (175Б, 4 слота) ──────────────────

    /// qsort(base=RCX, nmemb=RDX, size=R8, compar=R9): insertion-sort с
    /// вызовом компаратора ПРИЛОЖЕНИЯ в Ring 3 (прецедент native-bsearch
    /// v0.12; OpenSSL в curl.exe сортирует cipher-списки — trap-стаб давал
    /// livelock). Код GNU as (scripts/qsort-native.s), 175Б, objdump-
    /// сверен; все указатели — пересчёт из callee-saved (урок v0.12 №3).
    fn writeNativeQsort(out: []u8) void {
        @memset(out, 0);
        const code = [175]u8{
            0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
            0x41, 0x57, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89,
            0xCB, 0x48, 0x89, 0xD5, 0x4D, 0x89, 0xC4, 0x4D,
            0x89, 0xCD, 0x48, 0x85, 0xED, 0x76, 0x7F, 0x4D,
            0x85, 0xE4, 0x74, 0x7A, 0x48, 0x83, 0xFD, 0x01,
            0x76, 0x74, 0x49, 0xC7, 0xC6, 0x01, 0x00, 0x00,
            0x00, 0x49, 0x39, 0xEE, 0x73, 0x68, 0x4D, 0x89,
            0xF7, 0x4D, 0x85, 0xFF, 0x74, 0x5B, 0x4C, 0x89,
            0xF8, 0x48, 0xFF, 0xC8, 0x49, 0x0F, 0xAF, 0xC4,
            0x48, 0x8D, 0x0C, 0x03, 0x4C, 0x89, 0xFA, 0x49,
            0x0F, 0xAF, 0xD4, 0x48, 0x8D, 0x14, 0x13, 0x41,
            0xFF, 0xD5, 0x85, 0xC0, 0x7E, 0x3B, 0x4C, 0x89,
            0xF8, 0x48, 0xFF, 0xC8, 0x49, 0x0F, 0xAF, 0xC4,
            0x4C, 0x8D, 0x04, 0x03, 0x4C, 0x89, 0xFA, 0x49,
            0x0F, 0xAF, 0xD4, 0x4C, 0x8D, 0x0C, 0x13, 0x48,
            0x31, 0xC9, 0x4C, 0x39, 0xE1, 0x73, 0x15, 0x45,
            0x8A, 0x14, 0x08, 0x45, 0x8A, 0x1C, 0x09, 0x45,
            0x88, 0x1C, 0x08, 0x45, 0x88, 0x14, 0x09, 0x48,
            0xFF, 0xC1, 0xEB, 0xE6, 0x49, 0xFF, 0xCF, 0xEB,
            0xA0, 0x49, 0xFF, 0xC6, 0xEB, 0x93, 0x31, 0xC0,
            0x48, 0x83, 0xC4, 0x28, 0x41, 0x5F, 0x41, 0x5E,
            0x41, 0x5D, 0x41, 0x5C, 0x5D, 0x5B, 0xC3,
        };
        @memcpy(out[0..code.len], &code);
    }

    /// Пометить dll!func как native-qsort (код в слотах [count+6..count+10),
    /// ПОСЛЕ моста и bsearch). Возврат — нашли ли запись.
    pub fn implementNativeQsort(self: *Dispatcher, dll_needle: []const u8, func_needle: []const u8) bool {
        if (self.code == null) return false;
        const code_buf = self.code.?;
        const off = (self.count + 6) * STUB_CODE_SIZE; // после моста(3)+bsearch(3)
        if (off + 4 * STUB_CODE_SIZE > code_buf.len) return false;
        for (self.entries[0..self.count]) |*e| {
            if (!std.ascii.eqlIgnoreCase(e.dll, dll_needle)) continue;
            switch (e.func) {
                .by_name => |n| if (std.mem.eql(u8, n, func_needle)) {
                    writeNativeQsort(code_buf[off..][0..4 * STUB_CODE_SIZE]);
                    e.kind = .native;
                    e.stub_addr = self.stubAddr(off);
                    return true;
                },
                .by_ordinal => {},
            }
        }
        return false;
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

/// Вызов Win64-функции с 5 АРГУМЕНТАМИ: arg5 — на стеке вызываемого
/// ([rsp+0x20] у caller'а → [entry_rsp+0x28] у callee, ПОСЛЕ 32Б shadow —
/// конвенция Microsoft x64, подтверждена дизассемблированием curl).
/// Динамическое выравнивание RSP до 16 (and $-16) — как у настоящего ABI.
fn win64Call5(fn_addr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) u64 {
    return asm volatile (
        \\push %%rbp
        \\mov  %%rsp, %%rbp
        \\and  $-16, %%rsp
        \\sub  $0x28, %%rsp
        \\movq %[a5], 0x20(%%rsp)
        \\callq *%[f]
        \\mov  %%rbp, %%rsp
        \\pop  %%rbp
        : [ret] "={rax}" (-> u64),
        : [f] "{r11}" (fn_addr),
          [a1] "{rcx}" (a1),
          [a2] "{rdx}" (a2),
          [a3] "{r8}" (a3),
          [a4] "{r9}" (a4),
          [a5] "r" (a5),
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
    //   memset/strlen/strcmp → api-ms-win-crt-string; memcpy/memmove → api-ms-win-crt-private
    const ok1 = disp.implementNative("api-ms-win-crt-string-l1-1-0.dll", "memset", .memset);
    const ok2 = disp.implementNative("api-ms-win-crt-private-l1-1-0.dll", "memcpy", .memcpy);
    const ok3 = disp.implementNative("api-ms-win-crt-private-l1-1-0.dll", "memmove", .memmove);
    const ok4 = disp.implementNative("api-ms-win-crt-string-l1-1-0.dll", "strlen", .strlen);
    const ok5 = disp.implementNative("api-ms-win-crt-string-l1-1-0.dll", "strcmp", .strcmp);
    const ok6 = disp.implementNative("api-ms-win-crt-string-l1-1-0.dll", "strncmp", .strncmp);
    try testing.expect(ok1 and ok2 and ok3 and ok4 and ok5 and ok6);

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

    // ── strcmp (v0.12.0): ПРАВДА вместо trap-нуля («равны») ──
    const strcmp_addr = (disp.findByNameAnyDll("strcmp") orelse return error.NoStrcmp).stub_addr;
    // equal → 0
    var sbuf1: [32]u8 = undefined;
    var sbuf2: [32]u8 = undefined;
    @memcpy(sbuf1[0..8], "curl.exe");
    @memcpy(sbuf2[0..8], "curl.exe");
    sbuf1[8] = 0;
    sbuf2[8] = 0;
    try testing.expectEqual(@as(u64, 0), win64Call3(strcmp_addr, @intFromPtr(&sbuf1), @intFromPtr(&sbuf2), 0));
    // s1 < s2 → отрицательный (мл. слово; 'a'-'b' = -1)
    @memcpy(sbuf1[0..3], "abc");
    @memcpy(sbuf2[0..3], "abd");
    sbuf1[3] = 0;
    sbuf2[3] = 0;
    // strcmp возвращает int (EAX, знак в 32 битах): 'c'-'d' = -1
    const lt = win64Call3(strcmp_addr, @intFromPtr(&sbuf1), @intFromPtr(&sbuf2), 0);
    try testing.expectEqual(@as(i32, -1), @as(i32, @bitCast(@as(u32, @truncate(lt)))));
    // s1 > s2 → положительный ('d'-'c' = 1)
    const gt = win64Call3(strcmp_addr, @intFromPtr(&sbuf2), @intFromPtr(&sbuf1), 0);
    try testing.expectEqual(@as(i32, 1), @as(i32, @bitCast(@as(u32, @truncate(gt)))));
    // префикс длиннее: "ab" vs "abc" → NUL-'c' < 0
    @memcpy(sbuf1[0..2], "ab");
    sbuf1[2] = 0;
    const lt2 = win64Call3(strcmp_addr, @intFromPtr(&sbuf1), @intFromPtr(&sbuf2), 0);
    try testing.expect(@as(i32, @bitCast(@as(u32, @truncate(lt2)))) < 0);

    // ── strncmp (v0.12-fix №2): РАЗЛИЧИЕ НА ПЕРВОМ БАЙТЕ — а не «равны» ──
    // Драйвер бага: !strncmp("-", "http://example.com", 1) в trap-мире
    // было TRUE → URL классифицирован как ОПЦИЯ. Ядровая ПРАВДА: '-' vs 'h'.
    const strncmp_addr = (disp.findByNameAnyDll("strncmp") orelse return error.NoStrncmp).stub_addr;
    var dash: [2]u8 = .{ '-', 0 };
    var url: [32]u8 = undefined;
    const istr = "http://example.com";
    @memcpy(url[0..istr.len], istr);
    url[istr.len] = 0;
    // n=1: '-'(0x2D) vs 'h'(0x68) → отрицательная разница ≠ 0
    const dash_vs_url = win64Call3(strncmp_addr, @intFromPtr(&dash), @intFromPtr(&url), 1);
    const dvu: i32 = @bitCast(@as(u32, @truncate(dash_vs_url)));
    try testing.expect(dvu != 0 and dvu < 0); // '-' < 'h'
    // n=0 → 0 (ничего не сравнивалось)
    try testing.expectEqual(@as(u64, 0), win64Call3(strncmp_addr, @intFromPtr(&dash), @intFromPtr(&url), 0));
    // равные префиксы до n → 0
    try testing.expectEqual(@as(u64, 0), win64Call3(strncmp_addr, @intFromPtr(&url), @intFromPtr(&url), istr.len));
    // n за пределами равенства: "http" vs "htts" → 'p'-'s' < 0
    var url2: [32]u8 = undefined;
    @memcpy(url2[0..istr.len], istr);
    url2[3] = 's'; // https…
    url2[istr.len] = 0;
    const h_vs_s = win64Call3(strncmp_addr, @intFromPtr(&url), @intFromPtr(&url2), istr.len);
    const hvs: i32 = @bitCast(@as(u32, @truncate(h_vs_s)));
    try testing.expect(hvs != 0 and hvs < 0); // 'p' < 's'
    // s1 короче внутри n: "http" vs "httpx" в n=10 → NUL-'x' < 0
    var short: [8]u8 = undefined;
    @memcpy(short[0..4], "http");
    short[4] = 0;
    var longr: [8]u8 = undefined;
    @memcpy(longr[0..5], "httpx");
    longr[5] = 0;
    const sh = win64Call3(strncmp_addr, @intFromPtr(&short), @intFromPtr(&longr), 10);
    try testing.expect(@as(i32, @bitCast(@as(u32, @truncate(sh)))) < 0);
    // strncmp-стаб: ret на смещениях 37 и 44 (45Б код в слоте 48)
    const noff = (disp.findByNameAnyDll("strncmp").?).code_off;
    try testing.expectEqual(@as(u8, 0xC3), code_mem[noff + 37]);
    try testing.expectEqual(@as(u8, 0xC3), code_mem[noff + 44]);

    // memmove-стаб: ret на смещении 40 (41Б код в слоте 48)
    const moff = (disp.findByNameAnyDll("memmove").?).code_off;
    try testing.expectEqual(@as(u8, 0xC3), code_mem[moff + 40]);
}

test "native-bsearch: бинарный поиск с КОМПАРАТОРОМ приложения (Ring 3)" {
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;
    // Драйвер бага v0.12: curl 8.x подаёт каждый голый URL как опцию «--url»;
    // поиск имени в alias-таблице — bsearch'ом; trap-стаб отвечал NULL =
    // «не найдено» → «curl: option http://…: is unknown». Native-стаб
    // вызывает КОД ПРИЛОЖЕНИЯ (компаратор) с привилегиями Ring 3.
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);
    const counts = image.countImports();
    // запас: мост 3 + bsearch 3 + компаратор 1 + 1
    const entries = try testing.allocator.alloc(StubEntry, counts.functions);
    defer testing.allocator.free(entries);
    // RWX-mmap под код (как в остальных native-тестах; allocator-хип = NX):
    // стабы + мост 3 + bsearch 3 + компаратор 1 + выравнивание страницы
    const code_len = (counts.functions + 10) * STUB_CODE_SIZE + 4096;
    const code_buf = try std.posix.mmap(
        null,
        code_len,
        std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(code_buf);

    var disp = Dispatcher.init(entries, code_buf[0..code_len], .int3);
    // logical_base НЕ ставим: stub_addr = физ. адрес в RWX-mmap (исполняемый
    // в тест-процессе).
    _ = try disp.generateFor(&image);

    try testing.expect(disp.implementNativeBsearch("api-ms-win-crt-utility-l1-1-0.dll", "bsearch"));
    const bs = disp.findByNameAnyDll("bsearch") orelse return error.NoBsearch;
    try testing.expectEqual(StubKind.native, bs.kind);

    // компаратор: int cmp(const void* a, const void* b) → *(u32*)a - *(u32*)b
    //   8B 01    mov eax, [rcx]
    //   2B 02    sub eax, [rdx]
    //   C3       ret
    const cmp_off = (disp.count + 6) * STUB_CODE_SIZE;
    const cmp_code = [_]u8{ 0x8B, 0x01, 0x2B, 0x02, 0xC3 };
    @memcpy(code_buf[cmp_off..][0..cmp_code.len], &cmp_code);
    const cmp_va = disp.stubAddr(cmp_off);

    // таблица 6×8Б (ключ u32@0), сортирована
    var table = [_]u64{ 10, 20, 30, 40, 50, 60 };
    const tbase: u64 = @intFromPtr(&table);

    var key: u32 = 30;
    const r30 = win64Call5(bs.stub_addr, @intFromPtr(&key), tbase, 6, 8, cmp_va);
    try testing.expectEqual(tbase + 2 * 8, r30); // найден элемент №2

    key = 10;
    try testing.expectEqual(tbase, win64Call5(bs.stub_addr, @intFromPtr(&key), tbase, 6, 8, cmp_va)); // первый
    key = 60;
    try testing.expectEqual(tbase + 5 * 8, win64Call5(bs.stub_addr, @intFromPtr(&key), tbase, 6, 8, cmp_va)); // последний
    key = 35;
    try testing.expectEqual(@as(u64, 0), win64Call5(bs.stub_addr, @intFromPtr(&key), tbase, 6, 8, cmp_va)); // между — NULL
    key = 5;
    try testing.expectEqual(@as(u64, 0), win64Call5(bs.stub_addr, @intFromPtr(&key), tbase, 6, 8, cmp_va)); // ниже — NULL
    key = 70;
    try testing.expectEqual(@as(u64, 0), win64Call5(bs.stub_addr, @intFromPtr(&key), tbase, 6, 8, cmp_va)); // выше — NULL
    // пустая таблица → NULL
    key = 30;
    try testing.expectEqual(@as(u64, 0), win64Call5(bs.stub_addr, @intFromPtr(&key), tbase, 0, 8, cmp_va));
    // 1 элемент: попадание и промах
    var one = [_]u64{42};
    key = 42;
    try testing.expectEqual(@intFromPtr(&one), win64Call5(bs.stub_addr, @intFromPtr(&key), @intFromPtr(&one), 1, 8, cmp_va));
    key = 41;
    try testing.expectEqual(@as(u64, 0), win64Call5(bs.stub_addr, @intFromPtr(&key), @intFromPtr(&one), 1, 8, cmp_va));

    // рет-байты стаба: ret на смещениях 0x7C и 0x8D (142Б код в 3 слотах)
    // ⚠ bs.code_off — слот ТРАП-стаба (IAT-позиция); native-код живёт
    // в (count+3)*STUB_CODE_SIZE — читаем его через смещение от буфера.
    const native_off = (disp.count + 3) * STUB_CODE_SIZE;
    try testing.expectEqual(@as(u8, 0xC3), code_buf[native_off + 0x7C]);
    try testing.expectEqual(@as(u8, 0xC3), code_buf[native_off + 0x8D]);
    try testing.expectEqual(bs.stub_addr, @intFromPtr(code_buf.ptr) + native_off);

    // ── РЕГРЕССИЯ v0.12 «p в VOLATILE»: компаратор curl-стиля ЗАТРАПЛИВАЕТ
    // RDX (mov rdx,[rdx]; jmp strcmp) — старый стаб держал p в RDX → путь
    // c>0 (mov rbp,rdx) и .found возвращали МУСОР. Таблица {char* name},
    // строки NUL-терминированы — как alias-таблица curl.
    {
        // strcmp-копия (байты стаба слота 78) в слот [count+7]
        const sc_off = (disp.count + 7) * STUB_CODE_SIZE;
        const sc_code = [_]u8{
            0x31, 0xC0, 0x44, 0x0F, 0xB6, 0x04, 0x01, 0x44, 0x0F, 0xB6, 0x0C, 0x02,
            0x45, 0x39, 0xC8, 0x75, 0x0A, 0x45, 0x85, 0xC0, 0x74, 0x05,
            0x48, 0xFF, 0xC0, 0xEB, 0xE7,
            0x44, 0x89, 0xC0, 0x44, 0x29, 0xC8, 0xC3,
        };
        @memcpy(code_buf[sc_off..][0..sc_code.len], &sc_code);
        const sc_va = disp.stubAddr(sc_off);

        // компаратор: mov rcx,[rcx]; mov rdx,[rdx]; movabs r11,sc_va; jmp r11
        const cc_off = (disp.count + 8) * STUB_CODE_SIZE;
        var ci: usize = 0;
        const CC = code_buf[cc_off..];
        CC[ci] = 0x48; CC[ci+1] = 0x8B; CC[ci+2] = 0x09; ci += 3; // mov rcx,[rcx]
        CC[ci] = 0x48; CC[ci+1] = 0x8B; CC[ci+2] = 0x12; ci += 3; // mov rdx,[rdx]
        CC[ci] = 0x49; CC[ci+1] = 0xBB;                            // movabs r11, sc_va
        std.mem.writeInt(u64, @as(*[8]u8, @ptrCast(CC.ptr + ci + 2)), sc_va, .little); ci += 10;
        CC[ci] = 0x41; CC[ci+1] = 0xFF; CC[ci+2] = 0xE3;           // jmp r11
        const cc_va = disp.stubAddr(cc_off);

        // строки + таблица {char*}×8 — алфавитные, NUL в конце
        var names: [8][16]u8 = undefined;
        const strs = [_][]const u8{ "alpn", "anyauth", "append", "ssl", "url", "user", "verbose", "xattr" };
        var tbl: [8][2]u64 = undefined;
        for (strs, 0..) |s, k| {
            @memcpy(names[k][0..s.len], s);
            names[k][s.len] = 0;
            tbl[k][0] = @intFromPtr(&names[k]);
            tbl[k][1] = 0x1000 + k;
        }
        // ключ "ssl" (elem[3]): 3 итерации (url→lower, append→c>0, ssl→found)
        var keybuf: [8]u8 = undefined;
        @memcpy(keybuf[0..3], "ssl");
        keybuf[3] = 0;
        var key2: [1]u64 = .{@intFromPtr(&keybuf)};
        const found = win64Call5(bs.stub_addr, @intFromPtr(&key2), @intFromPtr(&tbl), 8, 16, cc_va);
        try testing.expectEqual(@intFromPtr(&tbl[3]), found);

        // ключ "zzz": все c>0 → .nf → NULL
        @memcpy(keybuf[0..3], "zzz");
        keybuf[3] = 0;
        try testing.expectEqual(@as(u64, 0), win64Call5(bs.stub_addr, @intFromPtr(&key2), @intFromPtr(&tbl), 8, 16, cc_va));

        // ключ "alpn" (elem[0]): .lower-путь
        @memcpy(keybuf[0..4], "alpn");
        keybuf[4] = 0;
        try testing.expectEqual(@intFromPtr(&tbl[0]), win64Call5(bs.stub_addr, @intFromPtr(&key2), @intFromPtr(&tbl), 8, 16, cc_va));
    }
}

test "native-qsort: insertion-sort с КОМПАРАТОРОМ приложения (Ring 3)" {
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;
    // Драйвер бага v0.14.0 (CDD №5): OpenSSL в curl.exe сортирует
    // cipher-списки qsort'ом — trap-стаб → livelock-kill (как bsearch
    // в v0.12). Native 175Б (scripts/qsort-native.s) вызывает компаратор
    // приложения из Ring 3 по Win64-контракту.
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);
    const counts = image.countImports();
    // запас: мост 3 + bsearch 3 + qsort 4 + компаратор 1 + 1
    const entries = try testing.allocator.alloc(StubEntry, counts.functions);
    defer testing.allocator.free(entries);
    const code_len = (counts.functions + 12) * STUB_CODE_SIZE + 4096;
    const code_buf = try std.posix.mmap(
        null,
        code_len,
        std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(code_buf);

    var disp = Dispatcher.init(entries, code_buf[0..code_len], .int3);
    _ = try disp.generateFor(&image);

    try testing.expect(disp.implementNativeQsort("api-ms-win-crt-utility-l1-1-0.dll", "qsort"));
    const qs = disp.findByNameAnyDll("qsort") orelse return error.NoQsort;
    try testing.expectEqual(StubKind.native, qs.kind);

    // компаратор: int cmp(const void* a, const void* b) → *(u32*)a - *(u32*)b
    const cmp_off = (disp.count + 10) * STUB_CODE_SIZE;
    const cmp_code = [_]u8{ 0x8B, 0x01, 0x2B, 0x02, 0xC3 };
    @memcpy(code_buf[cmp_off..][0..cmp_code.len], &cmp_code);
    const cmp_va = disp.stubAddr(cmp_off);

    // сортировка 8 u32 по возрастанию (элементы 8Б: ключ u32@0 + мусор)
    var arr = [_]u64{ 42, 7, 99, 1, 55, 13, 700, 3 };
    const base: u64 = @intFromPtr(&arr);
    _ = win64Call5(qs.stub_addr, base, 8, 8, cmp_va, 0);
    var expect = [_]u64{ 1, 3, 7, 13, 42, 55, 99, 700 };
    try testing.expectEqualSlices(u64, &expect, &arr);

    // обратный порядок: компаратор (b - a)
    var arr2 = [_]u64{ 5, 1, 9, 2 };
    // cmp_rev: 8B 02 mov eax,[rdx]; 2B 01 sub eax,[rcx]; C3 ret
    const cmp_rev_code = [_]u8{ 0x8B, 0x02, 0x2B, 0x01, 0xC3 };
    @memcpy(code_buf[cmp_off..][0..cmp_rev_code.len], &cmp_rev_code);
    _ = win64Call5(qs.stub_addr, @intFromPtr(&arr2), 4, 8, cmp_va, 0);
    var expect2 = [_]u64{ 9, 5, 2, 1 };
    try testing.expectEqualSlices(u64, &expect2, &arr2);

    // уже сортировано / пусто / 1 элемент — не падает
    var one = [_]u64{77};
    _ = win64Call5(qs.stub_addr, @intFromPtr(&one), 1, 8, cmp_va, 0);
    try testing.expectEqual(@as(u64, 77), one[0]);
    _ = win64Call5(qs.stub_addr, base, 0, 8, cmp_va, 0);

    // элементы НЕкратного размера (5Б): побайтовый свап
    var bytes = [_]u8{ 5, 1, 9, 2, 7, 0, 8, 0, 4, 0, 6, 0, 3, 0, 1, 0, 2, 0, 9, 0 };
    // интерпретируем как 4×5Б структур с ключом u8@0 → лексикографический
    // порядок ключей после сортировки: 0,1,2,4,5... (ключи: 5,1,9,2 | 7,0,8,0 ...)
    _ = win64Call5(qs.stub_addr, @intFromPtr(&bytes), 4, 5, cmp_va, 0);
    try testing.expect(bytes[0] <= bytes[5] and bytes[5] <= bytes[10]);
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

// ─── v0.12.0: extra-записи + мост колбэка ───────────────────────────────────

test "addExtraStub: записи вне PE-импортов (SSPI-таблица) — impl/trap" {
    const data = try loadFixture("testdata/curl.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);
    const counts = image.countImports();
    const total = counts.functions + 8;
    const entries = try testing.allocator.alloc(StubEntry, total);
    defer testing.allocator.free(entries);
    const code_buf = try testing.allocator.alloc(u8, total * STUB_CODE_SIZE);
    defer testing.allocator.free(code_buf);

    var disp = Dispatcher.init(entries, code_buf, .int3);
    disp.logical_base = 0x200000000;
    _ = try disp.generateFor(&image);
    const imports = disp.count;
    try testing.expectEqual(counts.functions, imports);

    // extra-запись .impl: слот [imports], entry_id = imports, код-трамплин
    const e1 = disp.addExtraStub("Secur32.dll", "QuerySecurityPackageInfoA", .impl) orelse return error.ExtraFailed;
    try testing.expectEqual(imports + 1, disp.count);
    try testing.expectEqual(imports * STUB_CODE_SIZE, e1.code_off);
    try testing.expectEqual(@as(u64, 0x200000000 + imports * STUB_CODE_SIZE), e1.stub_addr);
    try testing.expectEqual(StubKind.impl, e1.kind);
    // байты трамплина (entry_id в movabs rdi)
    try testing.expectEqual(@as(u8, 0x56), code_buf[e1.code_off + 0]);
    const id = std.mem.readInt(u64, code_buf[e1.code_off + 10 ..][0..8], .little);
    try testing.expectEqual(@as(u64, imports), id);
    // findByNameAnyDll находит extra-запись (GetProcAddress-резолв)
    try testing.expectEqual(e1, disp.findByNameAnyDll("QUERYSECURITYPACKAGEINFOA").?);
    // findByRip тоже знает extra-слоты (int3-путь)
    try testing.expect(disp.findByRip(e1.stub_addr + 4) != null);

    // extra-запись .trap: int3-CDD-лог
    const e2 = disp.addExtraStub("Secur32.dll", "AcquireCredentialsHandleA", .trap) orelse return error.ExtraFailed2;
    try testing.expectEqual(StubKind.trap, e2.kind);
    try testing.expectEqual(@as(u8, 0xCC), code_buf[e2.code_off + 3]);

    // переполнение entries → null (не паника)
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        _ = disp.addExtraStub("X.dll", "f", .trap);
    }
    try testing.expect(disp.addExtraStub("X.dll", "overflow", .trap) == null);
}

test "callback-мост: launcher/trampoline/mailbox — байты + РЕАЛЬНОЕ ИСПОЛНЕНИЕ" {
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;

    // RWX-регион под код (запись из Zig + исполнение), 16 слотов + запас
    const n_slots: usize = 16;
    const code_len = n_slots * STUB_CODE_SIZE;
    const code_mem = try std.posix.mmap(
        null,
        code_len,
        std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(code_mem);

    var entries: [n_slots]StubEntry = undefined;
    var disp = Dispatcher.init(&entries, code_mem[0..code_len], .int3);
    // logical_base = null → stub_addr = физический адрес (нативный тест)
    _ = disp.addExtraStub("Secur32.dll", "QuerySecurityPackageInfoA", .impl) orelse return error.ExtraFailed;
    _ = disp.addExtraStub("Secur32.dll", "AcquireCredentialsHandleA", .impl) orelse return error.ExtraFailed2;

    // ── тестовые артефакты (В RWX-РЕГИОНЕ — стек не исполняется, NX!) ──
    // callback (Win64-конвенция!): складывает RCX/RDX/R8 по адресам из
    // mailbox (mailbox несёт УКАЗАТЕЛИ на b-блоки), возвращает 77 в RAX:
    //   mov [rcx], rcx ; mov [rdx], rdx ; mov [r8], r8 ; mov rax, 77 ; ret
    // done-стаб (замена trampoline): [rcx+8] ← rax ; ret
    var b: [3][16]u8 align(8) = undefined; // блоки: [0]=&RCX, [1]=&RDX, [2]=&R8
    for (&b) |*blk| @memset(blk, 0);

    const cb_off = 5 * STUB_CODE_SIZE; // слот 5: callback
    const done_off = 6 * STUB_CODE_SIZE; // слот 6: done-стаб
    const C = code_mem[cb_off..][0..STUB_CODE_SIZE];
    @memset(C, 0);
    C[0] = 0x48;
    C[1] = 0x89;
    C[2] = 0x09; // mov [rcx], rcx
    C[3] = 0x48;
    C[4] = 0x89;
    C[5] = 0x12; // mov [rdx], rdx
    // ⚠ REX-дисциплина (урок v0.12): B-бит расширяет R/M! 4C 89 00 =
    // mov [RAX], r8 (B=0 → rm=000=RAX — затирал done-стаб!), а нужно
    // mov [r8], r8 → REX.W+R+B = 4D (reg=r8 по R, rm=r8 по B).
    C[6] = 0x4D;
    C[7] = 0x89;
    C[8] = 0x00; // mov [r8], r8
    C[9] = 0x48;
    C[10] = 0xC7;
    C[11] = 0xC0; // mov rax, imm32
    C[12] = 77;
    C[16] = 0xC3; // ret
    const D = code_mem[done_off..][0..STUB_CODE_SIZE];
    @memset(D, 0);
    D[0] = 0x48;
    D[1] = 0x89;
    D[2] = 0x41;
    D[3] = 0x08; // mov [rcx+8], rax
    D[4] = 0xC3; // ret

    const br = disp.buildCallbackBridge(
        @intFromPtr(code_mem[done_off..].ptr),
        CB_SYSCALL_DONE,
        CALLBACK_COOKIE,
    ) orelse return error.BridgeFailed;
    // слоты моста — после 2 extra-записей
    try testing.expectEqual(4 * STUB_CODE_SIZE, br.mailbox_off); // 2 extra + 2 слота моста до mailbox

    // mailbox = {init_once=&b[0], parameter=&b[1], context=&b[2], target=callback}
    const mb: *[4]u64 = @ptrCast(@alignCast(code_mem[br.mailbox_off..][0..32]));
    mb[0] = @intFromPtr(&b[0]);
    mb[1] = @intFromPtr(&b[1]);
    mb[2] = @intFromPtr(&b[2]);
    mb[3] = @intFromPtr(code_mem[cb_off..].ptr);

    // ── ИСПОЛНЕНИЕ моста: вызываем launcher как обычную функцию ──
    // (launcher игнорирует входные регистры — всё берёт из mailbox; для
    // кернеля вход через sysretq, для теста — call; RSP-семантика общая)
    const Launcher = *const fn () callconv(.C) void;
    const launcher: Launcher = @ptrFromInt(br.launcher_va);
    launcher();

    // колбэк получил Win64-аргументы RCX/RDX/R8 (записал через указатели)
    try testing.expectEqual(@intFromPtr(&b[0]), @as(*align(1) u64, @ptrFromInt(@intFromPtr(&b[0]))).*);
    try testing.expectEqual(@intFromPtr(&b[1]), @as(*align(1) u64, @ptrFromInt(@intFromPtr(&b[1]))).*);
    try testing.expectEqual(@intFromPtr(&b[2]), @as(*align(1) u64, @ptrFromInt(@intFromPtr(&b[2]))).*);
    // результат колбэка (RAX=77) дошёл до done-стаба: [rcx+8] = 77
    try testing.expectEqual(@as(u64, 77), @as(*align(1) u64, @ptrFromInt(@intFromPtr(&b[0]) + 8)).*);

    // ── байтовая верификация trampoline (ядро: done_target = свой) ──
    var entries2: [n_slots]StubEntry = undefined;
    const code2_mem = try std.posix.mmap(
        null,
        code_len,
        std.posix.PROT.READ | std.posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(code2_mem);
    var disp2 = Dispatcher.init(&entries2, code2_mem[0..code_len], .int3);
    const br2 = disp2.buildCallbackBridge(null, CB_SYSCALL_DONE, CALLBACK_COOKIE) orelse return error.BridgeFailed2;
    // launcher пушит СОБСТВЕННЫЙ trampoline
    const push_target = std.mem.readInt(u64, code2_mem[0 + 23 ..][0..8], .little);
    try testing.expectEqual(br2.trampoline_va, push_target);
    // trampoline: mov rsi,rax; movabs rdi,cookie; movabs rax,7; syscall; jmp $
    const T = br2.mailbox_off - STUB_CODE_SIZE; // trampoline стоит перед mailbox
    try testing.expectEqual(@as(u8, 0x48), code2_mem[T + 0]);
    try testing.expectEqual(@as(u8, 0x89), code2_mem[T + 1]);
    try testing.expectEqual(@as(u8, 0xC6), code2_mem[T + 2]); // mov rsi, rax
    try testing.expectEqual(CALLBACK_COOKIE, std.mem.readInt(u64, code2_mem[T + 5 ..][0..8], .little));
    try testing.expectEqual(@as(u64, CB_SYSCALL_DONE), std.mem.readInt(u64, code2_mem[T + 15 ..][0..8], .little));
    try testing.expectEqual(@as(u8, 0x0F), code2_mem[T + 23]);
    try testing.expectEqual(@as(u8, 0x05), code2_mem[T + 24]); // syscall
    try testing.expectEqual(@as(u8, 0xEB), code2_mem[T + 25]);
    try testing.expectEqual(@as(u8, 0xFE), code2_mem[T + 26]); // jmp $ — не падаем
}

// ═══════════════════════════════════════════════════════════════════════════
// v0.17.0 (CDD №8): native-тесты _initterm/_initterm_e (msvcrt — 7-Zip)
// ═══════════════════════════════════════════════════════════════════════════

var t_initterm_calls: u64 = 0;
fn tInitA() callconv(.C) void {
    t_initterm_calls = t_initterm_calls * 10 + 1;
}
fn tInitB() callconv(.C) void {
    t_initterm_calls = t_initterm_calls * 10 + 2;
}
fn tInitC() callconv(.C) i32 {
    t_initterm_calls = t_initterm_calls * 10 + 3;
    return 0; // успех
}
fn tInitFail() callconv(.C) i32 {
    t_initterm_calls = t_initterm_calls * 10 + 4;
    return 42; // ПРОВАЛ: _initterm_e обязан вернуть 42 немедленно
}
fn tInitAfterFail() callconv(.C) i32 {
    t_initterm_calls = t_initterm_calls * 10 + 5;
    return 0;
}

test "native-initterm: цикл C++-инициализаторов msvcrt (7za-реестр, Ring 3)" {
    if (@import("builtin").cpu.arch != .x86_64) return error.SkipZigTest;
    // 7za.exe импортирует msvcrt!_initterm (MSVC /MD CRT): native-стаб
    // вызывает таблицу [start, end) инициализаторов, NULL пропускается.
    const data = try loadFixture("testdata/7za.exe");
    defer testing.allocator.free(data);
    const image = try Pe.parse(data);
    const counts = image.countImports();

    const entries = try testing.allocator.alloc(StubEntry, counts.functions);
    defer testing.allocator.free(entries);
    const code_len = (counts.functions + 4) * STUB_CODE_SIZE + 4096;
    const code_buf = try std.posix.mmap(
        null,
        code_len,
        std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
    defer std.posix.munmap(code_buf);

    var disp = Dispatcher.init(entries, code_buf[0..code_len], .int3);
    _ = try disp.generateFor(&image);
    try testing.expect(disp.implementNative("msvcrt.dll", "_initterm", .initterm));
    const it = disp.findByNameAnyDll("_initterm") orelse return error.NoInitterm;
    try testing.expectEqual(StubKind.native, it.kind);

    // Таблица: NULL, A, B — NULL пропускается, порядок сохраняется
    t_initterm_calls = 0;
    var table = [_]u64{ 0, @intFromPtr(&tInitA), @intFromPtr(&tInitB) };
    _ = win64Call3(it.stub_addr, @intFromPtr(&table), @intFromPtr(&table) + table.len * 8, 0); // void: rax не определён
    try testing.expectEqual(@as(u64, 12), t_initterm_calls); // A(1), B(2) по порядку

    // Пустая таблица: [x, x) — ни одного вызова
    t_initterm_calls = 0;
    _ = win64Call3(it.stub_addr, @intFromPtr(&table), @intFromPtr(&table), 0);
    try testing.expectEqual(@as(u64, 0), t_initterm_calls);

    // ── _initterm_e: int-инициализаторы, провал прерывает цикл ──
    // (npm-7za 19.00 импортирует только _initterm — e-вариант регистрируем
    // через мини-реестр с ручной записью: та же точка входа writeNativeStub)
    var ite_entries = [_]StubEntry{.{
        .dll = "msvcrt.dll",
        .func = .{ .by_name = "_initterm_e" },
        .stub_addr = 0,
        .iat_rva = 0,
        .slot_index = 0,
        .code_off = 0,
    }};
    var disp2 = Dispatcher.init(&ite_entries, code_buf[0..code_len], .int3);
    disp2.count = 1;
    try testing.expect(disp2.implementNative("msvcrt.dll", "_initterm_e", .initterm_e));
    // implementNative не трогает stub_addr (в generateFor он ставится при
    // генерации) — ручной записи адрес нужен явно:
    ite_entries[0].stub_addr = disp2.stubAddr(ite_entries[0].code_off);
    const ite = disp2.findByNameAnyDll("_initterm_e") orelse return error.NoInittermE;
    try testing.expectEqual(StubKind.native, ite.kind);

    t_initterm_calls = 0;
    var table_ok = [_]u64{ @intFromPtr(&tInitC), @intFromPtr(&tInitC) };
    const r_ok = win64Call3(ite.stub_addr, @intFromPtr(&table_ok), @intFromPtr(&table_ok) + table_ok.len * 8, 0);
    try testing.expectEqual(@as(u64, 0), r_ok); // все успешны → 0
    try testing.expectEqual(@as(u64, 33), t_initterm_calls); // C(3), C(3)

    // Провал: Fail возвращает 42 → цикл останавливается ДО AfterFail
    t_initterm_calls = 0;
    var table_fail = [_]u64{ @intFromPtr(&tInitC), @intFromPtr(&tInitFail), @intFromPtr(&tInitAfterFail) };
    const r_fail = win64Call3(ite.stub_addr, @intFromPtr(&table_fail), @intFromPtr(&table_fail) + table_fail.len * 8, 0);
    try testing.expectEqual(@as(u64, 42), r_fail); // код провала
    try testing.expectEqual(@as(u64, 34), t_initterm_calls); // C, Fail — AfterFail НЕ вызван
}
