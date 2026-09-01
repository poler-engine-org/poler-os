// ============================================================================
// POLER-OS VirtIO-Net Driver + минимальный сетевой стек — x86_64
// CDD-цикл №5 (v0.14.0): реальный сетевой обмен через QEMU SLIRP.
// ============================================================================
//
// Паттерн: virtio_blk.zig (legacy I/O, identity-mapped DMA, polling).
// Драйвер: PCI-скан (0x1AF4, subsystem 1 = VIRTIO_ID_NETWORK), очереди
// RX (queue 0) и TX (queue 1), MAC из device-config.
//
// Мини-стек ядра (CDD №5, спека):
//   - ARP-резолвинг шлюза SLIRP (10.0.2.2 → MAC; на запросы 10.0.2.3/DNS
//     и внешние IP SLIRP маршрутизирует ЧЕРЕЗ шлюз → MAC шлюза для всех)
//   - IPv4: header + чексумма (RFC 1071)
//   - TCP: трёхстороннее рукопожатие (SYN → SYN-ACK → ACK), PSH-данные,
//     RX-поллинг с кольцевым буфером на соединение, ACK-машина
//   - DNS: UDP-запрос A-записи на 10.0.2.3 (SLIRP → хост-резолвер)
//
// НАЗНАЧЕНИЕ: curl.exe содержит ВСТРОЕННЫЙ OpenSSL (разведка CDD №5:
// настоящий ClientHello 1539Б из Ring 3) — ВЕСЬ TLS curl делает сам;
// наша задача — доставить его TCP-пакеты до реального example.com.
// Вызов из syscall-контекста (CR3=user): чтение user-страниц CPL=0 ✓,
// DMA-слоты — supervisor identity-страницы, запись CPL=0 ✓ (без SMAP).
//
// ⚠ poll-циклы (waitForRx) блокируют ядро на десятки мс — как в
// virtio_blk.waitForCompletion; для CDD-цикла приемлемо.
// ============================================================================

const hal = @import("hal.zig");
const pmm = @import("pmm64.zig");
const pci = @import("pci.zig");

// ─── VirtIO PCI (legacy / transitional) ─────────────────────────────────────

const VIRTIO_PCI_HOST_FEATURES: u16 = 0x00;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
const VIRTIO_PCI_QUEUE_PFN: u16 = 0x08;
const VIRTIO_PCI_QUEUE_NUM: u16 = 0x0C;
const VIRTIO_PCI_QUEUE_SEL: u16 = 0x0E;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
const VIRTIO_PCI_STATUS: u16 = 0x12;
const VIRTIO_PCI_ISR: u16 = 0x13;
const VIRTIO_PCI_CONFIG: u16 = 0x14; // legacy: MAC(6) + status(2)…

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

const VIRTIO_DESC_F_NEXT: u16 = 1;
const VIRTIO_DESC_F_WRITE: u16 = 2;

// VirtIO-Net features (биты в 32-битном слове)
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
const VIRTIO_NET_F_CSUM: u32 = 1 << 0;

// ─── Очереди ────────────────────────────────────────────────────────────────

const QUEUE_SIZE: u16 = 64; // хватит для SLIRP-трафика
const DESC_TABLE_SIZE: u32 = QUEUE_SIZE * 16; // 1024 = 1 страница (Q=64)
const AVAIL_RING_SIZE: u32 = 4 + QUEUE_SIZE * 2 + 2;
const USED_RING_SIZE: u32 = 4 + QUEUE_SIZE * 8 + 2;

const DESC_PAGES: u32 = (DESC_TABLE_SIZE + 4095) / 4096; // 1
const AVAIL_PAGES: u32 = (AVAIL_RING_SIZE + 4095) / 4096; // 1
const USED_PAGES: u32 = (USED_RING_SIZE + 4095) / 4096; // 1
const VQ_TOTAL_PAGES: u32 = DESC_PAGES + AVAIL_PAGES + USED_PAGES; // 3

const VirtQueueDesc = extern struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

const VirtQueueUsedElem = extern struct {
    id: u32,
    len: u32,
};

// ─── Ethernet/IP/TCP константы ──────────────────────────────────────────────

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_ARP: u16 = 0x0806;
const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_BROADCAST = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

const TCP_FIN: u16 = 0x01;
const TCP_SYN: u16 = 0x02;
const TCP_RST: u16 = 0x04;
const TCP_PSH: u16 = 0x08;
const TCP_ACK: u16 = 0x10;

const MTU: usize = 1500;
const MSS: usize = 1460; // MTU - IP(20) - TCP(20)

// SLIRP-сеть QEMU user-mode
const SLIRP_GW_IP: u32 = 0x0A00_0202; // 10.0.2.2 (BE-представление в байтах: 10,0,2,2)
const SLIRP_DNS_IP: u32 = 0x0A00_0203; // 10.0.2.3
const SLIRP_OUR_IP: u32 = 0x0A00_020F; // 10.0.2.15 — гость

// ─── TCP-соединение (мини-стейт) ────────────────────────────────────────────

pub const MAX_TCP_CONNS: usize = 8;
const RX_RING_PAGES: usize = 16; // 64КБ приёма на соединение
const RX_RING_SIZE: usize = RX_RING_PAGES * 4096;

// v0.15.0 (CDD №6): ретрансмит-буфер [snd_una..snd_nxt) — 32КБ на соединение
const RTX_PAGES: usize = 8;
const RTX_SIZE: usize = RTX_PAGES * 4096;

// v0.15.0 (CDD №6): TCP-таймеры (hal.tick_count = 10мс-джиффи)
const RTO_INITIAL_TICKS: u32 = 20; // 200мс (SLIRP-RTT ≪ — без ложных ретратов)
const RTO_MAX_TICKS: u32 = 300; // 3с — потолок экспоненциального бэкоффа
const RTX_MAX_ATTEMPTS: u8 = 8; // далее — abort соединения
const KA_IDLE_TICKS: u64 = 100; // 1с без встречного трафика → проба
const KA_MAX_PROBES: u8 = 5; // далее — соединение мертво
const WIN_UPDATE_THRESHOLD: u16 = 16384; // окно открылось → window-update ACK

const TcpState = enum(u8) {
    unused,
    syn_sent,
    established,
    fin_wait_1, // наш FIN отправлен, ждём ACK (ретрансмится движком)
    fin_wait_2, // наш FIN ACKed, ждём FIN пир
    time_wait, // FIN пира ACKed финальным ACK — короткий отдых → closed
    closed,
};

pub const TcpConn = struct {
    state: TcpState = .unused,
    peer_ip: [4]u8 = .{ 0, 0, 0, 0 },
    peer_port: u16 = 0,
    src_port: u16 = 0,
    iss: u32 = 0, // initial send seq
    snd_nxt: u32 = 0, // следующий seq для отправки
    snd_una: u32 = 0, // v0.15.0: старейший неподтверждённый seq (RTX-движок)
    rcv_nxt: u32 = 0, // следующий ожидаемый seq
    irs: u32 = 0, // initial recv seq (peer)
    // RX-кольцо (identity-mapped страницы PMM)
    ring_phys: u64 = 0,
    ring_virt: u64 = 0,
    ring_head: usize = 0, // позиция чтения
    ring_tail: usize = 0, // позиция записи
    fin_received: bool = false,
    aborted: bool = false, // v0.15.0: RST / ретрансмит-таймаут (данные не валидны)
    syn_retries: u8 = 0,
    need_ack: bool = false, // отложенный ACK (анти-реентерабельность!)
    // v0.15.0 (CDD №6): sliding window приёма — рекламим РЕАЛЬНОЕ место
    win_advertised: u16 = 0xFFFF, // последнее заявленное окно
    // v0.15.0 (CDD №6): ретрансмиты с экспоненциальным бэкоффом
    rtx_phys: u64 = 0, // RTX-буфер (лениво, RTX_PAGES identity-страниц)
    rtx_virt: u64 = 0,
    rtx_len: usize = 0, // байт в буфере = snd_nxt - snd_una - (fin?1:0)
    fin_unacked: bool = false, // FIN занимает +1 seq в flight
    rto_ticks: u32 = RTO_INITIAL_TICKS,
    rtx_attempts: u8 = 0, // ретрансмиты ПОДРЯД без нового ACK
    last_xmit_tick: u64 = 0, // тик последей передачи (новой или ретрансмита)
    last_ack_tick: u64 = 0, // тик последнего валидного ACK от пира
    // v0.15.0 (CDD №6): keep-alive
    ka_probes: u8 = 0,
};

// ─── Состояние драйвера ─────────────────────────────────────────────────────

pub const VnetError = error{
    NoDevice,
    InitFailed,
    NoDmaSlot,
    Timeout,
    ConnClosed,
    NoFreeConn,
    BadState,
};

var vn: struct {
    initialized: bool = false,
    io_base: u16 = 0,
    pci_dev: ?pci.PciDeviceInfo = null,

    mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },

    // queue 0 (RX)
    rx_vq_phys: u64 = 0,
    rx_desc: u64 = 0,
    rx_avail: u64 = 0,
    rx_used: u64 = 0,
    rx_last_used: u16 = 0,
    rx_avail_idx: u16 = 0, // следующий idx для постинга буферов

    // queue 1 (TX)
    tx_vq_phys: u64 = 0,
    tx_desc: u64 = 0,
    tx_avail: u64 = 0,
    tx_used: u64 = 0,
    tx_last_used: u16 = 0,
    tx_free_head: u16 = 0,
    tx_num_free: u16 = QUEUE_SIZE,
    tx_avail_idx: u16 = 0,

    // RX-буферы: NUM_RX_BUFS страниц, posted в avail-ring
    rx_bufs: [8]u64 = [_]u64{0} ** 8, // phys(=virt) каждой
    rx_posted: [8]bool = [_]bool{false} ** 8,

    // TX-буфер (по одному на фрейм — обмен один-за-раз, поллинг завершения)
    tx_buf: u64 = 0,

    // ARP-кэш (SLIRP-шлюз)
    gw_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
    gw_resolved: bool = false,

    // DNS-ответ (последний резолв)
    dns_last_ip: [4]u8 = .{ 0, 0, 0, 0 },
    dns_have: bool = false,

    conns: [MAX_TCP_CONNS]TcpConn = undefined,
    next_src_port: u16 = 0xC350, // 50000+

    // v0.15.0 (CDD №6): статистика (ifconfig/netstat) + ICMP-состояние
    rx_frames: u64 = 0,
    rx_bytes: u64 = 0,
    tx_frames: u64 = 0,
    tx_bytes: u64 = 0,
    rtx_frames: u64 = 0, // ретрансмиты
    ka_probes_sent: u64 = 0,
    // ICMP echo: последняя пинг-сессия
    icmp_id: u16 = 0,
    icmp_seq: u16 = 0,
    icmp_reply_seq: u16 = 0, // seq последнего Echo Reply
    icmp_reply_seen: bool = false,
    icmp_rx_tsc: u64 = 0, // TSC момента прихода ответа
    icmp_req_seen: bool = false, // входящий Echo Request (для ответа)
    tsc_per_ms: u64 = 0, // калибровка TSC (RTT пинга)
    in_poll: bool = false, // анти-реентерабельность pollRx/service
} = .{};

// ─── I/O-регистры ───────────────────────────────────────────────────────────

fn rd8(off: u16) u8 {
    return hal.inb(vn.io_base + off);
}
fn rd16(off: u16) u16 {
    return hal.inw(vn.io_base + off);
}
fn rd32(off: u16) u32 {
    return hal.inl(vn.io_base + off);
}
fn wr8(off: u16, val: u8) void {
    hal.outb(vn.io_base + off, val);
}
fn wr16(off: u16, val: u16) void {
    hal.outw(vn.io_base + off, val);
}
fn wr32(off: u16, val: u32) void {
    hal.outl(vn.io_base + off, val);
}

fn descAt(base: u64, idx: u16) *volatile VirtQueueDesc {
    const p: [*]volatile VirtQueueDesc = @ptrFromInt(@as(usize, @intCast(base)));
    return &p[idx];
}

fn availFlagsPtr(base: u64) *volatile u16 {
    return @ptrFromInt(@as(usize, @intCast(base)));
}
fn availIdxPtr(base: u64) *volatile u16 {
    return @ptrFromInt(@as(usize, @intCast(base + 2)));
}
fn availRingPtr(base: u64) [*]volatile u16 {
    return @ptrFromInt(@as(usize, @intCast(base + 4)));
}
fn usedIdxPtr(base: u64) *volatile u16 {
    return @ptrFromInt(@as(usize, @intCast(base + 2)));
}
fn usedRingPtr(base: u64) [*]volatile VirtQueueUsedElem {
    return @ptrFromInt(@as(usize, @intCast(base + 4)));
}

fn memBarrier() void {
    asm volatile ("" ::: "memory");
}

// ============================================================================
// Билдеры пакетов (ЧИСТЫЕ функции — юнит-тесты без железа)
// ============================================================================

/// Чексумма Internet (RFC 1071): 16-битные слова в network-порядке
/// (BE — как на проводе), дополнение до двух. Данные могут быть нечётными
/// (последний байт — в старшем разряде слова).
pub fn ipChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum +%= (@as(u32, data[i]) << 8) | data[i + 1];
    }
    if (data.len % 2 == 1) {
        sum +%= @as(u32, data[data.len - 1]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) +% (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

/// Ethernet-заголовок: dst(6) src(6) type(2). Возврат — новая длина.
pub fn buildEthernet(buf: []u8, dst: [6]u8, src: [6]u8, ethertype: u16) usize {
    @memcpy(buf[0..6], &dst);
    @memcpy(buf[6..12], &src);
    buf[12] = @intCast(ethertype >> 8);
    buf[13] = @intCast(ethertype & 0xFF);
    return ETH_HDR_LEN;
}

/// ARP-запрос «кто такой target_ip? скажите our_ip» (28Б payload).
pub fn buildArpRequest(buf: []u8, our_mac: [6]u8, our_ip: [4]u8, target_ip: [4]u8) usize {
    // htype=1 (Ethernet), ptype=0x0800, hlen=6, plen=4, op=1 (request)
    @memcpy(buf[0..2], &[_]u8{ 0x00, 0x01 });
    @memcpy(buf[2..4], &[_]u8{ 0x08, 0x00 });
    buf[4] = 6;
    buf[5] = 4;
    @memcpy(buf[6..8], &[_]u8{ 0x00, 0x01 });
    @memcpy(buf[8..14], &our_mac);
    @memcpy(buf[14..18], &our_ip);
    @memcpy(buf[18..24], &[_]u8{0} ** 6); // неизвестный target MAC
    @memcpy(buf[24..28], &target_ip);
    return 28;
}

/// IPv4-заголовок (20Б, без опций) поверх payload длины payload_len.
/// proto: IP_PROTO_*. Возврат — полная длина (20 + payload_len).
pub fn buildIpv4(buf: []u8, src: [4]u8, dst: [4]u8, proto: u8, payload_len: usize) usize {
    const total_len: u16 = @intCast(20 + payload_len);
    buf[0] = 0x45; // v4, IHL=5
    buf[1] = 0x00; // DSCP
    buf[2] = @intCast(total_len >> 8);
    buf[3] = @intCast(total_len & 0xFF);
    buf[4] = 0x12; // id (можно любой)
    buf[5] = 0x34;
    buf[6] = 0x40; // flags: DF
    buf[7] = 0x00; // frag off
    buf[8] = 64; // TTL
    buf[9] = proto;
    buf[10] = 0; // checksum (placeholder)
    buf[11] = 0;
    @memcpy(buf[12..16], &src);
    @memcpy(buf[16..20], &dst);
    // чексумма
    const csum = ipChecksum(buf[0..20]);
    buf[10] = @intCast(csum >> 8);
    buf[11] = @intCast(csum & 0xFF);
    return 20 + payload_len;
}

/// TCP-сегмент (20Б заголовок + опции до 40Б + данные).
/// опции_len — дополнительные байты (SYN → MSS-опция 4Б).
/// v0.15.0 (CDD №6): window — заявляемое окно приёма (sliding window).
pub fn buildTcpSegment(
    buf: []u8,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    options_len: usize,
    payload: []const u8,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    window: u16,
) usize {
    const data_off: u8 = @intCast((20 + options_len) / 4);
    buf[0] = @intCast(src_port >> 8);
    buf[1] = @intCast(src_port & 0xFF);
    buf[2] = @intCast(dst_port >> 8);
    buf[3] = @intCast(dst_port & 0xFF);
    buf[4] = @intCast(seq >> 24);
    buf[5] = @intCast((seq >> 16) & 0xFF);
    buf[6] = @intCast((seq >> 8) & 0xFF);
    buf[7] = @intCast(seq & 0xFF);
    buf[8] = @intCast(ack >> 24);
    buf[9] = @intCast((ack >> 16) & 0xFF);
    buf[10] = @intCast((ack >> 8) & 0xFF);
    buf[11] = @intCast(ack & 0xFF);
    buf[12] = data_off << 4; // data offset (words)
    buf[13] = @intCast(flags & 0xFF);
    buf[14] = @intCast(window >> 8); // v0.15.0: окно приёма (было 0xFFFF)
    buf[15] = @intCast(window & 0xFF);
    buf[16] = 0; // checksum placeholder
    buf[17] = 0;
    buf[18] = 0; // urgent ptr
    buf[19] = 0;
    // MSS-опция для SYN (kind 2, len 4, mss 1460)
    if (options_len >= 4 and (flags & TCP_SYN) != 0) {
        buf[20] = 2;
        buf[21] = 4;
        buf[22] = MSS >> 8;
        buf[23] = MSS & 0xFF;
    }
    const hdr_len = 20 + options_len;
    if (payload.len > 0) {
        @memcpy(buf[hdr_len .. hdr_len + payload.len], payload);
    }
    // TCP-чексумма: псевдозаголовок + сегмент
    const seg_len = hdr_len + payload.len;
    var sum: u32 = 0;
    sum +%= (@as(u32, src_ip[0]) << 8) | src_ip[1];
    sum +%= (@as(u32, src_ip[2]) << 8) | src_ip[3];
    sum +%= (@as(u32, dst_ip[0]) << 8) | dst_ip[1];
    sum +%= (@as(u32, dst_ip[2]) << 8) | dst_ip[3];
    sum +%= @as(u32, IP_PROTO_TCP);
    sum +%= @as(u32, @intCast(seg_len));
    // сегмент словами (включая header)
    var i: usize = 0;
    while (i + 1 < seg_len) : (i += 2) {
        sum +%= (@as(u32, buf[i]) << 8) | buf[i + 1];
    }
    if (seg_len % 2 == 1) {
        sum +%= @as(u32, buf[seg_len - 1]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) +% (sum >> 16);
    }
    const csum: u16 = ~@as(u16, @truncate(sum));
    buf[16] = @intCast(csum >> 8);
    buf[17] = @intCast(csum & 0xFF);
    return seg_len;
}

/// UDP-дейтаграмма (8Б заголовок) + payload (чексумма 0 — валидно для IPv4).
pub fn buildUdpDatagram(buf: []u8, src_port: u16, dst_port: u16, payload: []const u8) usize {
    buf[0] = @intCast(src_port >> 8);
    buf[1] = @intCast(src_port & 0xFF);
    buf[2] = @intCast(dst_port >> 8);
    buf[3] = @intCast(dst_port & 0xFF);
    const total: u16 = @intCast(8 + payload.len);
    buf[4] = @intCast(total >> 8);
    buf[5] = @intCast(total & 0xFF);
    buf[6] = 0; // checksum 0 = не вычислена (разрешено для IPv4)
    buf[7] = 0;
    if (payload.len > 0) {
        @memcpy(buf[8 .. 8 + payload.len], payload);
    }
    return 8 + payload.len;
}

/// DNS-запрос A-записи (RD=1): {id, flags=0x0100, qd=1, an/ns/ar=0, QNAME, QTYPE=1, QCLASS=1}.
pub fn buildDnsQuery(buf: []u8, txn_id: u16, host: []const u8) usize {
    buf[0] = @intCast(txn_id >> 8);
    buf[1] = @intCast(txn_id & 0xFF);
    buf[2] = 0x01; // RD
    buf[3] = 0x00;
    @memset(buf[4..12], 0); // qd=1 (пишем ниже), an/ns/ar=0
    buf[4] = 0;
    buf[5] = 1; // QDCOUNT
    var p: usize = 12;
    // QNAME: метки
    var it = std.mem.splitScalar(u8, host, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return 0;
        buf[p] = @intCast(label.len);
        p += 1;
        @memcpy(buf[p .. p + label.len], label);
        p += label.len;
    }
    buf[p] = 0; // корень
    p += 1;
    buf[p] = 0;
    buf[p + 1] = 1; // QTYPE = A
    buf[p + 2] = 0;
    buf[p + 3] = 1; // QCLASS = IN
    return p + 4;
}

/// Парсинг DNS-ответа: первая A-запись → ip. null = нет/кривой ответ.
pub fn parseDnsResponse(pkt: []const u8, txn_id: u16) ?[4]u8 {
    if (pkt.len < 12) return null;
    const id = (@as(u16, pkt[0]) << 8) | pkt[1];
    if (id != txn_id) return null;
    const rcode = pkt[3] & 0x0F;
    if (rcode != 0) return null; // ошибка DNS
    const ancount = (@as(u16, pkt[6]) << 8) | pkt[7];
    if (ancount == 0) return null;
    var p: usize = 12;
    // пропустить QNAME (сжатие!)
    p = skipDnsName(pkt, p) orelse return null;
    p += 4; // QTYPE + QCLASS
    var i: usize = 0;
    while (i < ancount) : (i += 1) {
        p = skipDnsName(pkt, p) orelse return null;
        if (p + 10 > pkt.len) return null;
        const rtype = (@as(u16, pkt[p]) << 8) | pkt[p + 1];
        const rdlen = (@as(u16, pkt[p + 8]) << 8) | pkt[p + 9];
        p += 10;
        if (rtype == 1 and rdlen == 4 and p + 4 <= pkt.len) {
            return .{ pkt[p], pkt[p + 1], pkt[p + 2], pkt[p + 3] };
        }
        p += rdlen;
    }
    return null;
}

fn skipDnsName(pkt: []const u8, start: usize) ?usize {
    var p = start;
    var jumps: u8 = 0;
    while (true) {
        if (p >= pkt.len) return null;
        const len = pkt[p];
        if (len & 0xC0 == 0xC0) {
            // указатель сжатия: имя закончилось
            return p + 2;
        }
        if (len == 0) return p + 1;
        p += 1 + len;
        jumps += 1;
        if (jumps > 64) return null;
    }
}

// ============================================================================
// v0.15.0 (CDD №6): ICMP — ping-диагностика (Echo Request / Echo Reply)
// ============================================================================

pub const IcmpEcho = struct { id: u16, seq: u16 };

/// ICMP Echo Request (8Б заголовок + 56Б payload «polerping»): type 8, code 0,
/// checksum RFC 1071 (та же ipChecksum), id+seq.
pub fn buildIcmpEcho(buf: []u8, id: u16, seq: u16) usize {
    buf[0] = 8; // type = echo request
    buf[1] = 0; // code
    buf[2] = 0; // checksum placeholder
    buf[3] = 0;
    buf[4] = @intCast(id >> 8);
    buf[5] = @intCast(id & 0xFF);
    buf[6] = @intCast(seq >> 8);
    buf[7] = @intCast(seq & 0xFF);
    // payload 56Б (стандартный размер ping)
    var i: usize = 8;
    while (i < 64) : (i += 1) buf[i] = @truncate(0x50 + i); // «poler…»
    const csum = ipChecksum(buf[0..64]);
    buf[2] = @intCast(csum >> 8);
    buf[3] = @intCast(csum & 0xFF);
    return 64;
}

/// ICMP Echo Reply из принятого пакета: type 0 + id/seq. null — не reply /
/// битая чексумма / не наш id.
pub fn parseIcmpReply(pkt: []const u8, want_id: u16) ?IcmpEcho {
    if (pkt.len < 16) return null;
    if (pkt[0] != 0) return null; // не echo reply
    if (pkt[1] != 0) return null;
    // чексумма: пересчёт (поле = 0) обязан совпасть с полем пакета
    const expect = (@as(u16, pkt[2]) << 8) | pkt[3];
    var scratch: [64]u8 = undefined;
    const n = @min(pkt.len, 64);
    @memcpy(scratch[0..n], pkt[0..n]);
    scratch[2] = 0;
    scratch[3] = 0;
    if (ipChecksum(scratch[0..n]) != expect) return null; // чексумма битая
    const id = (@as(u16, pkt[4]) << 8) | pkt[5];
    if (id != want_id) return null;
    return .{ .id = id, .seq = (@as(u16, pkt[6]) << 8) | pkt[7] };
}

/// ICMP Echo Request, пришедший НАМ (SLIRP/host probe): type 8 → ответить.
/// Возврат — готовый Echo Reply в buf (зеркалим payload).
pub fn buildIcmpEchoReply(buf: []u8, req: []const u8) usize {
    if (req.len < 8) return 0;
    @memcpy(buf[0..req.len], req);
    buf[0] = 0; // type = echo reply
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    const csum = ipChecksum(buf[0..req.len]);
    buf[2] = @intCast(csum >> 8);
    buf[3] = @intCast(csum & 0xFF);
    return req.len;
}

// ============================================================================
// Инициализация драйвера
// ============================================================================

pub fn init() VnetError!void {
    const dev = pci.findVirtioDevice(1) orelse { // VIRTIO_ID_NETWORK
        hal.Serial.puts("[VNET] No virtio-net device found\n");
        return VnetError.NoDevice;
    };

    vn.pci_dev = dev;
    vn.io_base = dev.io_base;
    if (vn.io_base == 0) {
        hal.Serial.puts("[VNET] ERROR: no I/O base\n");
        return VnetError.InitFailed;
    }

    hal.Serial.puts("[VNET] Found virtio-net at bus=");
    hal.Serial.putHex(dev.bus);
    hal.Serial.puts(" slot=");
    hal.Serial.putHex(dev.slot);
    hal.Serial.puts(" I/O=0x");
    hal.Serial.putHex(vn.io_base);
    hal.Serial.puts("\n");

    pci.enableDevice(dev.bus, dev.slot, dev.func);

    // Reset → ACK → DRIVER
    wr8(VIRTIO_PCI_STATUS, 0);
    wr8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
    wr8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    // Features: MAC (обязательно); STATUS/CSUM не требуем
    const host_features = rd32(VIRTIO_PCI_HOST_FEATURES);
    var guest_features: u32 = 0;
    if (host_features & VIRTIO_NET_F_MAC != 0) guest_features |= VIRTIO_NET_F_MAC;
    wr32(VIRTIO_PCI_GUEST_FEATURES, guest_features);
    wr8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    const st = rd8(VIRTIO_PCI_STATUS);
    if ((st & VIRTIO_STATUS_FEATURES_OK) == 0) {
        hal.Serial.puts("[VNET] feature negotiation failed\n");
        return VnetError.InitFailed;
    }

    // MAC из device-config (legacy: сразу по 0x14)
    var i: u16 = 0;
    while (i < 6) : (i += 1) {
        vn.mac[i] = rd8(VIRTIO_PCI_CONFIG + i);
    }
    hal.Serial.puts("[VNET] MAC ");
    for (vn.mac, 0..) |b, j| {
        hal.Serial.putHex(b);
        if (j < 5) hal.Serial.puts(":");
    }
    hal.Serial.puts("\n");

    // Очереди: 0 = RX, 1 = TX
    try setupQueue(0, &vn.rx_vq_phys, &vn.rx_desc, &vn.rx_avail, &vn.rx_used);
    try setupQueue(1, &vn.tx_vq_phys, &vn.tx_desc, &vn.tx_avail, &vn.tx_used);

    // RX-буферы: 8 страниц, posted в avail-ring (WRITE-дескрипторы)
    for (&vn.rx_bufs, 0..) |*bufp, k| {
        const p = pmm.allocPage() orelse return VnetError.InitFailed;
        bufp.* = p;
        const z: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(p)));
        @memset(z[0..4096], 0);
        postRxBuffer(@intCast(k));
    }

    // TX-буфер: 1 страница (фреймы по одному, поллинг used)
    vn.tx_buf = pmm.allocPage() orelse return VnetError.InitFailed;
    const tz: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(vn.tx_buf)));
    @memset(tz[0..4096], 0);

    // Инициализация TCP-слотов
    for (&vn.conns) |*c| c.* = .{};
    // RX-кольца — лениво при connect

    // IOAPIC: не настраиваем IRQ (поллинг, как virtio-blk)

    wr8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);
    vn.initialized = true;

    // v0.15.0 (CDD №6): TSC-калибровка для RTT пинга (дельта TSC за 2 тика
    // APIC-таймера = 20мс). Гард: таймер не тикает → 0 (ping в тиках).
    calibrateTscPerMs();

    hal.Serial.puts("[VNET] Initialization complete (SLIRP: 10.0.2.15/24 gw 10.0.2.2 dns 10.0.2.3)\n");
}

fn calibrateTscPerMs() void {
    const t0 = hal.readMsr(0x10);
    const tk0 = hal.tick_count;
    var spin: u32 = 0;
    while (hal.tick_count < tk0 + 2) {
        asm volatile ("pause");
        spin += 1;
        if (spin > 8_000_000) break; // таймер не тикает — не зависать
    }
    const t1 = hal.readMsr(0x10);
    if (hal.tick_count >= tk0 + 2 and t1 > t0) {
        vn.tsc_per_ms = (t1 - t0) / 20; // 2 тика = 20мс
    }
}

pub fn isInitialized() bool {
    return vn.initialized;
}

pub fn ourMac() [6]u8 {
    return vn.mac;
}

fn setupQueue(idx: u16, out_phys: *u64, out_desc: *u64, out_avail: *u64, out_used: *u64) VnetError!void {
    wr16(VIRTIO_PCI_QUEUE_SEL, idx);
    const max_size = rd16(VIRTIO_PCI_QUEUE_NUM);
    if (max_size == 0) {
        hal.Serial.puts("[VNET] queue ");
        hal.Serial.putDecimal(idx);
        hal.Serial.puts(" not available\n");
        return VnetError.InitFailed;
    }
    const base = pmm.allocContiguousPages(VQ_TOTAL_PAGES) orelse {
        hal.Serial.puts("[VNET] allocContiguousPages failed\n");
        return VnetError.InitFailed;
    };
    out_phys.* = base;
    out_desc.* = base;
    out_avail.* = base + DESC_PAGES * 4096;
    out_used.* = base + (DESC_PAGES + AVAIL_PAGES) * 4096;

    const zp: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(base)));
    @memset(zp[0 .. VQ_TOTAL_PAGES * 4096], 0);

    // free-list дескрипторов (для TX)
    var i: usize = 0;
    while (i + 1 < QUEUE_SIZE) : (i += 1) {
        descAt(out_desc.*, @intCast(i)).next = @intCast(i + 1);
    }
    descAt(out_desc.*, QUEUE_SIZE - 1).next = 0;

    if (base >= 0x1_0000_0000) {
        hal.Serial.puts("[VNET] ERROR: VQ phys >= 4GB (legacy!)\n");
        return VnetError.InitFailed;
    }
    const pfn: u32 = @intCast(base >> 12);
    wr16(VIRTIO_PCI_QUEUE_NUM, QUEUE_SIZE);
    wr32(VIRTIO_PCI_QUEUE_PFN, pfn);
    hal.Serial.puts("[VNET] queue ");
    hal.Serial.putDecimal(idx);
    hal.Serial.puts(" ready (PFN=0x");
    hal.Serial.putHex(pfn);
    hal.Serial.puts(")\n");
}

/// Пост RX-буфера k: WRITE-дескриптор + avail-ring запись + notify.
/// ⚠ VirtIO-net legacy: кадр в буфере начинается с 10Б виртуального
/// заголовка (flags/gso/csum) — данные Ethernet-кадра с buf+10!
fn postRxBuffer(k: u16) void {
    const d = descAt(vn.rx_desc, k);
    d.addr = vn.rx_bufs[k];
    d.len = 1610; // 10Б virtio-net-hdr + кадр
    d.flags = VIRTIO_DESC_F_WRITE;
    d.next = 0;
    const ring = availRingPtr(vn.rx_avail);
    ring[vn.rx_avail_idx % QUEUE_SIZE] = k;
    memBarrier();
    availIdxPtr(vn.rx_avail).* = vn.rx_avail_idx + 1;
    vn.rx_avail_idx += 1;
    vn.rx_posted[k] = true;
    wr16(VIRTIO_PCI_QUEUE_NOTIFY, 0);
}

/// VirtIO-net legacy: виртуальный заголовок перед каждым кадром (TX и RX).
const VNET_HDR_LEN: usize = 10;

// ============================================================================
// TX: отправка фрейма (поллинг завершения, как virtio-blk)
// ============================================================================

/// Отправить готовый Ethernet-фрейм длины len. Таймаут ~200мс.
/// ⚠ VirtIO-net legacy: буфер = [10Б виртуального заголовка (нули)] + кадр —
/// без этого девайс съедает первые 10Б КАДРА как заголовок (диагноз CDD №5:
/// в pcap уходили обрезанные 32Б-фреймы вместо 42Б ARP).
pub fn sendFrame(frame: []const u8) bool {
    if (!vn.initialized or frame.len > 1600) return false;
    // ждём свободный дескриптор TX
    var spins: u32 = 0;
    while (spins < 200_000) : (spins += 1) {
        // забрать завершённые
        const used_idx = usedIdxPtr(vn.tx_used).*;
        if (used_idx != vn.tx_last_used) {
            _ = usedRingPtr(vn.tx_used)[vn.tx_last_used % QUEUE_SIZE];
            vn.tx_last_used +%= 1;
            vn.tx_num_free += 1;
        }
        if (vn.tx_num_free > 0) break;
        asm volatile ("pause");
    }
    if (vn.tx_num_free == 0) return false;

    // копируем фрейм в DMA-буфер: [10Б hdr][frame]
    const txb: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(vn.tx_buf)));
    @memset(txb[0 .. VNET_HDR_LEN + frame.len], 0);
    var i: usize = 0;
    while (i < frame.len) : (i += 1) txb[VNET_HDR_LEN + i] = frame[i];

    // дескриптор 0 для TX (одиночный, без цепочки)
    const d = descAt(vn.tx_desc, 0);
    d.addr = vn.tx_buf;
    d.len = @intCast(VNET_HDR_LEN + frame.len);
    d.flags = 0;
    d.next = 0;

    const ring = availRingPtr(vn.tx_avail);
    ring[vn.tx_avail_idx % QUEUE_SIZE] = 0;
    memBarrier();
    availIdxPtr(vn.tx_avail).* = vn.tx_avail_idx + 1;
    vn.tx_avail_idx += 1;
    wr16(VIRTIO_PCI_QUEUE_NOTIFY, 1);

    // ждём завершения (device consumed)
    var spins2: u32 = 0;
    while (spins2 < 2_000_000) : (spins2 += 1) {
        const used_idx = usedIdxPtr(vn.tx_used).*;
        if (used_idx != vn.tx_last_used) {
            _ = usedRingPtr(vn.tx_used)[vn.tx_last_used % QUEUE_SIZE];
            vn.tx_last_used +%= 1;
            vn.tx_frames += 1; // v0.15.0: статистика (реальная отправка)
            vn.tx_bytes += frame.len;
            return true;
        }
        asm volatile ("pause");
    }
    hal.Serial.puts("[VNET] TX timeout\n");
    return false;
}

// ============================================================================
// RX: поллинг + диспетчер протоколов
// ============================================================================

/// Обработать все принятые фреймы (вызывается из poll-точек; guard от
/// шторма — не более 8 фреймов за вызов).
/// ⚠ v0.14.0-fix (анти-реентерабельность): ACKи НЕ отправляются из
/// handleTcp (sendTcpAck → sendFrame сидел бы в спине, когда pollRx вызван
/// ИЗ спина sendFrame — вложенный вызов перезаписывал TX-дескриптор, ACKи
/// терялись, сервер ретрансмитил). Вместо этого: need_ack-флаг, а ВЫШЕ —
/// один накопленный ACK после цикла.
/// v0.15.0 (CDD №6): in_poll-гард (служба таймеров TCP — ретрансмиты и
/// keep-alive — гоняется в poll-точках, не из IRQ) + статистика RX.
pub fn pollRx() void {
    if (!vn.initialized) return;
    if (vn.in_poll) return; // анти-реентерабельность
    vn.in_poll = true;
    defer vn.in_poll = false;

    // v0.15.0: таймеры TCP (ретрансмиты с бэкоффом + keep-alive) — каждый
    // poll-такт: во время активного обмена curl вызывает send/recv/select
    // непрерывно → движок дышит на каждом системном вызове.
    tcpTimers();

    var handled_any = false;
    var guard: u8 = 0;
    while (guard < 8) : (guard += 1) {
        const used_idx = usedIdxPtr(vn.rx_used).*;
        if (used_idx == vn.rx_last_used) break;
        const elem = usedRingPtr(vn.rx_used)[vn.rx_last_used % QUEUE_SIZE];
        vn.rx_last_used +%= 1;
        const k: u16 = @intCast(elem.id & 0x3FF);
        // ⚠ legacy: elem.len = 10Б hdr + кадр — Ethernet начинается с +10
        if (k < 8 and elem.len > VNET_HDR_LEN + ETH_HDR_LEN) {
            const frame_len: usize = @intCast(elem.len - VNET_HDR_LEN);
            vn.rx_frames += 1; // v0.15.0: статистика
            vn.rx_bytes += frame_len;
            const buf: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(vn.rx_bufs[k])));
            handleFrame(buf[VNET_HDR_LEN .. VNET_HDR_LEN + frame_len]);
            handled_any = true;
        }
        // ре-пост буфера
        postRxBuffer(k);
    }
    if (handled_any) {
        // отложенные ACKи: по одному на соединение (после цикла приёма)
        for (&vn.conns) |*c| {
            if (c.need_ack) {
                c.need_ack = false;
                sendTcpAck(c);
            }
        }
    }
}

/// Диспетчер Ethernet-фрейма.
fn handleFrame(frame: []volatile u8) void {
    const f: []const u8 = @as([]const u8, @ptrCast(@volatileCast(frame)));
    var dst: [6]u8 = undefined;
    @memcpy(&dst, f[0..6]);
    const ethertype = (@as(u16, f[12]) << 8) | f[13];
    // ARP?
    if (ethertype == ETH_TYPE_ARP and f.len >= ETH_HDR_LEN + 28) {
        const op = (@as(u16, f[ETH_HDR_LEN + 6]) << 8) | f[ETH_HDR_LEN + 7];
        if (op == 2) { // ARP reply
            // is-it-наш-гейтвей?
            var spa: [4]u8 = undefined;
            @memcpy(&spa, f[ETH_HDR_LEN + 14 .. ETH_HDR_LEN + 18]);
            if (spa[0] == 10 and spa[1] == 0 and spa[2] == 2 and spa[3] == 2) {
                @memcpy(&vn.gw_mac, f[ETH_HDR_LEN + 8 .. ETH_HDR_LEN + 14]);
                vn.gw_resolved = true;
                hal.Serial.puts("[VNET] ARP: gateway 10.0.2.2 resolved\n");
            }
            return;
        }
        if (op == 1) { // ARP request к нам (SLIRP probe) — отвечаем
            var tpa: [4]u8 = undefined;
            @memcpy(&tpa, f[ETH_HDR_LEN + 24 .. ETH_HDR_LEN + 28]);
            if (tpa[0] == 10 and tpa[1] == 0 and tpa[2] == 2 and tpa[3] == 15) {
                // Ethernet: dst=src исходного, src=наш MAC
                var reply: [42]u8 = undefined;
                var src_mac: [6]u8 = undefined;
                @memcpy(&src_mac, f[6..12]);
                _ = buildEthernet(&reply, src_mac, vn.mac, ETH_TYPE_ARP);
                var our_ip = [4]u8{ 10, 0, 2, 15 };
                // ARP-reply: op=2, sha=наш MAC, spa=наш IP, tha=запроситель, tpa=его IP
                @memcpy(reply[ETH_HDR_LEN .. ETH_HDR_LEN + 28], f[ETH_HDR_LEN .. ETH_HDR_LEN + 28]);
                reply[ETH_HDR_LEN + 6] = 0;
                reply[ETH_HDR_LEN + 7] = 2; // op reply
                @memcpy(reply[ETH_HDR_LEN + 8 .. ETH_HDR_LEN + 14], &vn.mac);
                @memcpy(reply[ETH_HDR_LEN + 14 .. ETH_HDR_LEN + 18], &our_ip);
                @memcpy(reply[ETH_HDR_LEN + 18 .. ETH_HDR_LEN + 24], &src_mac);
                _ = &our_ip;
                _ = sendFrame(&reply);
                hal.Serial.puts("[VNET] ARP request answered\n");
            }
        }
        return;
    }
    // IPv4?
    if (ethertype == ETH_TYPE_IPV4 and f.len >= ETH_HDR_LEN + 20) {
        const ip_hdr = ETH_HDR_LEN;
        const proto = f[ip_hdr + 9];
        const ihl = (@as(usize, f[ip_hdr] & 0x0F) * 4);
        if (f.len < ETH_HDR_LEN + ihl) return;
        // v0.14.0-fix: обрезка по IP-total_len — Ethernet-кадр ≥ 60Б (минимум),
        // IP-пакет короче: хвост = PADDING. Без обрезки паддинг попадал в
        // TCP-payload → фантомные «данные 6Б» → rcv_nxt сдвинулся → данные
        // сервера отвергались как дубликаты (диагноз: pcap + alert-путь).
        const iplen = (@as(usize, f[ip_hdr + 2]) << 8) | f[ip_hdr + 3];
        const ip_end = @min(ETH_HDR_LEN + iplen, f.len);
        if (ip_end < ETH_HDR_LEN + ihl) return;
        const payload = f[ETH_HDR_LEN + ihl .. ip_end];
        if (proto == IP_PROTO_ICMP and payload.len >= 8) {
            handleIcmp(f, payload);
        } else if (proto == IP_PROTO_UDP and payload.len >= 8) {
            handleUdp(payload);
        } else if (proto == IP_PROTO_TCP and payload.len >= 20) {
            handleTcp(payload);
        }
        return;
    }
}

/// v0.15.0 (CDD №6): ICMP-вход. Echo Request к НАМ (10.0.2.15) — зеркальный
/// ответ (host/SLIRP probe). Echo Reply с нашим id — фиксация для icmpPing.
fn handleIcmp(frame_full: []const u8, icmp: []const u8) void {
    if (icmp[0] == 8) { // echo request → нам?
        if (icmp.len > 128) return; // гард буфера ответа
        // frame: [eth 14][ip 20]: src ip = 14+12..16, dst ip = 14+16..20
        const dst_ip = frame_full[ETH_HDR_LEN + 16 .. ETH_HDR_LEN + 20];
        if (dst_ip[0] == 10 and dst_ip[1] == 0 and dst_ip[2] == 2 and dst_ip[3] == 15) {
            var reply: [ETH_HDR_LEN + 20 + 128]u8 = undefined;
            const n = buildIcmpEchoReply(reply[ETH_HDR_LEN + 20 ..], icmp);
            if (n > 0) {
                const src_ip: [4]u8 = frame_full[ETH_HDR_LEN + 12 .. ETH_HDR_LEN + 16].*;
                _ = buildEthernet(&reply, src_macFromFrame(frame_full), vn.mac, ETH_TYPE_IPV4);
                _ = buildIpv4(reply[ETH_HDR_LEN..], .{ 10, 0, 2, 15 }, src_ip, IP_PROTO_ICMP, n);
                _ = sendFrame(reply[0 .. ETH_HDR_LEN + 20 + n]);
                hal.Serial.puts("[VNET] ICMP: echo request answered\n");
            }
            return;
        }
        return;
    }
    if (icmp[0] == 0) { // echo reply
        const r = parseIcmpReply(icmp, vn.icmp_id) orelse return;
        vn.icmp_reply_seq = r.seq;
        vn.icmp_reply_seen = true;
        vn.icmp_rx_tsc = hal.readMsr(0x10);
    }
}

fn src_macFromFrame(f: []const u8) [6]u8 {
    var m: [6]u8 = undefined;
    @memcpy(&m, f[6..12]);
    return m;
}

/// UDP: только DNS-ответы (10.0.2.3 → нас).
fn handleUdp(udp: []const u8) void {
    const src_port = (@as(u16, udp[0]) << 8) | udp[1];
    const dst_port = (@as(u16, udp[2]) << 8) | udp[3];
    if (src_port != 53 or dst_port != 53) return;
    if (udp.len <= 8) return;
    const dns = udp[8..];
    const ip = parseDnsResponse(dns, vn_dns_txn) orelse {
        hal.Serial.puts("[VNET] DNS: ответ не распознан\n");
        return;
    };
    vn.dns_last_ip = ip;
    vn.dns_have = true;
    hal.Serial.puts("[VNET] DNS resolved\n");
}

var vn_dns_txn: u16 = 0;

/// TCP-вход: сегменты для наших соединений.
/// v0.15.0 (CDD №6): полная ACK-машина (snd_una-продвижение → сброс RTO +
/// KA-таймера), sliding window (окно исчерпано → сегмент НЕ принимается,
/// re-ACK), FIN-стейт fin_wait_1/fin_wait_2/time_wait.
fn handleTcp(seg: []const u8) void {
    const dst_port = (@as(u16, seg[2]) << 8) | seg[3];
    const src_port = (@as(u16, seg[0]) << 8) | seg[1];
    const seq = std.mem.readInt(u32, seg[4..8], .big);
    const ack = std.mem.readInt(u32, seg[8..12], .big);
    const data_off = (@as(usize, seg[12] >> 4) * 4);
    const flags = seg[13];
    const payload = if (seg.len > data_off) seg[data_off..] else seg[0..0];
    const now = hal.tick_count;

    for (&vn.conns, 0..) |*c, ci| {
        const active = c.state == .syn_sent or c.state == .established or
            c.state == .fin_wait_1 or c.state == .fin_wait_2 or c.state == .time_wait;
        if (!active) continue;
        if (c.src_port != dst_port or c.peer_port != src_port) continue;

        // любая активность пира = жив (keep-alive reset)
        c.last_ack_tick = now;
        c.ka_probes = 0;

        if ((flags & TCP_RST) != 0) {
            hal.Serial.puts("[VNET] TCP RST — соединение закрыто\n");
            c.state = .closed;
            c.aborted = true;
            return;
        }

        // v0.15.0: ACK-обработка — продвижение snd_una (ретрансмит-движок).
        // adv ≤ inflight — отсекает и дубликаты (adv-обёртка), и «ACK будущего».
        if ((flags & TCP_ACK) != 0 and c.state != .syn_sent) {
            const inflight = c.snd_nxt -% c.snd_una;
            const adv = ack -% c.snd_una;
            if (adv != 0 and adv <= inflight) {
                if (adv > c.rtx_len) c.fin_unacked = false; // ACK покрыл и FIN
                rtxConsume(c, @intCast(adv));
                c.snd_una +%= adv;
                c.rto_ticks = RTO_INITIAL_TICKS; // свежий ACK → RTO reset
                c.rtx_attempts = 0;
                if (c.state == .fin_wait_1 and c.snd_nxt == c.snd_una) {
                    // наш FIN подтверждён
                    c.state = if (c.fin_received) .time_wait else .fin_wait_2;
                    hal.Serial.puts("[VNET] TCP: наш FIN ACKed (slot ");
                    hal.Serial.putDecimal(ci);
                    hal.Serial.puts(")\n");
                }
            }
        }

        if (c.state == .syn_sent and (flags & TCP_SYN) != 0 and (flags & TCP_ACK) != 0) {
            // SYN-ACK: ack = iss+1 ✓ → ESTABLISHED, шлём ACK
            c.irs = seq;
            c.rcv_nxt = seq +% 1;
            c.snd_nxt = ack; // = iss+1
            c.snd_una = ack; // SYN подтверждён (v0.15.0)
            c.state = .established;
            hal.Serial.puts("[VNET] TCP: SYN-ACK принят — соединение установлено (slot ");
            hal.Serial.putDecimal(ci);
            hal.Serial.puts(")\n");
            sendTcpAck(c);
            return;
        }

        if (c.state == .established or c.state == .fin_wait_1 or
            c.state == .fin_wait_2 or c.state == .time_wait)
        {
            const rel = seq -% c.rcv_nxt;
            if (rel == 0) {
                // ожидаемые данные (или чистый ACK)
                if (payload.len > 0) {
                    // v0.15.0: sliding window — места в RX-ринге нет → сегмент
                    // НЕ принимаем (пиры ретрансмитят после window-update)
                    if (ringSpace(c) <= payload.len) {
                        c.need_ack = true; // re-ACK с нулевым окном
                        return;
                    }
                    ringWrite(c, payload);
                    c.rcv_nxt = seq +% @as(u32, @intCast(payload.len));
                    if ((flags & TCP_FIN) != 0) {
                        c.rcv_nxt +%= 1;
                        c.fin_received = true;
                    }
                    c.need_ack = true; // отложенный ACK (анти-реентерабельность)
                    hal.Serial.puts("[VNET] TCP: данные ");
                    hal.Serial.putDecimal(payload.len);
                    hal.Serial.puts("Б → ring (slot ");
                    hal.Serial.putDecimal(ci);
                    hal.Serial.puts(")\n");
                } else if ((flags & TCP_FIN) != 0) {
                    c.rcv_nxt +%= 1;
                    c.fin_received = true;
                    c.need_ack = true; // финальный ACK
                    if (c.state == .fin_wait_2 or c.state == .time_wait) {
                        c.state = .time_wait; // FIN в момент TIME_WAIT → re-ACK
                    }
                    hal.Serial.puts("[VNET] TCP: FIN принят (slot ");
                    hal.Serial.putDecimal(ci);
                    hal.Serial.puts(")\n");
                }
                // чистый ACK без данных: ничего не шлём (шторм-защита)
            } else if (rel > 0x8000_0000) {
                // дубликат: дублирующий ACK (отложенный)
                c.need_ack = true;
            } else {
                // gap: ACK последнего принятого (пусть ретрансмитит)
                c.need_ack = true;
            }
            return;
        }
    }
}

/// Запись в RX-кольцо соединения.
fn ringWrite(c: *TcpConn, data: []const u8) void {
    if (c.ring_virt == 0) return;
    const rp: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(c.ring_virt)));
    for (data) |b| {
        rp[c.ring_tail] = b;
        c.ring_tail = (c.ring_tail + 1) % RX_RING_SIZE;
        // переполнение: голова догоняет (теряем старое — CDD-упрощение)
    }
    hal.Serial.puts("[VNET] ring-write: ");
    hal.Serial.putDecimal(data.len);
    hal.Serial.puts("Б\n");
}

pub fn ringBytes(c: *const TcpConn) usize {
    if (c.ring_tail >= c.ring_head) {
        return c.ring_tail - c.ring_head;
    }
    return RX_RING_SIZE - c.ring_head + c.ring_tail;
}

/// v0.15.0 (CDD №6): свободное место RX-ринга (sliding window).
/// Инвариант: tail НИКОГДА не догоняет head (drop при нехватке в handleTcp)
/// → ringBytes ≤ RX_RING_SIZE-1, space ≥ 1.
pub fn ringSpace(c: *const TcpConn) usize {
    return RX_RING_SIZE - ringBytes(c);
}

/// v0.15.0 (CDD №6): окно приёма для рекламы (u16, без window scaling).
fn recvWindow(c: *const TcpConn) u16 {
    return @intCast(@min(ringSpace(c), 0xFFFF));
}

// ============================================================================
// ARP / сетевые примитивы (отправка с учётом шлюза)
// ============================================================================

/// Резолв MAC шлюза SLIRP (блокирующий поллинг, ~500мс).
pub fn resolveGateway() bool {
    if (!vn.initialized) return false;
    if (vn.gw_resolved) return true;
    var frame: [ETH_HDR_LEN + 28]u8 = undefined;
    _ = buildEthernet(&frame, ETH_BROADCAST, vn.mac, ETH_TYPE_ARP);
    const arp_len = buildArpRequest(frame[ETH_HDR_LEN..], vn.mac, .{ 10, 0, 2, 15 }, .{ 10, 0, 2, 2 });
    _ = arp_len;
    var attempt: u8 = 0;
    while (attempt < 5) : (attempt += 1) {
        if (!sendFrame(&frame)) continue;
        var spins: u32 = 0;
        while (spins < 3_000_000) : (spins += 1) {
            pollRx();
            if (vn.gw_resolved) {
                hal.Serial.puts("[VNET] gateway MAC resolved\n");
                return true;
            }
            asm volatile ("pause");
        }
    }
    hal.Serial.puts("[VNET] ARP gateway: TIMEOUT\n");
    return false;
}

pub fn gatewayResolved() bool {
    return vn.gw_resolved;
}

/// Отправка IPv4-пакета через шлюз (MAC уже резолвлен).
fn sendIp(proto: u8, payload: []const u8, dst_ip: [4]u8) bool {
    if (!vn.gw_resolved) return false;
    var frame: [ETH_HDR_LEN + 20 + 1600]u8 = undefined;
    _ = buildEthernet(&frame, vn.gw_mac, vn.mac, ETH_TYPE_IPV4);
    const n = buildIpv4(frame[ETH_HDR_LEN..], .{ 10, 0, 2, 15 }, dst_ip, proto, payload.len);
    @memcpy(frame[ETH_HDR_LEN + 20 .. ETH_HDR_LEN + 20 + payload.len], payload);
    return sendFrame(frame[0 .. ETH_HDR_LEN + n]);
}

// ============================================================================
// TCP API (мини-стейт-машина)
// ============================================================================

/// tcpConnect: SYN → SYN-ACK (поллинг) → ACK. Слот или ошибка.
pub fn tcpConnect(peer_ip: [4]u8, peer_port: u16) VnetError!usize {
    if (!vn.initialized) return VnetError.NoDevice;
    if (!resolveGateway()) return VnetError.Timeout;

    // свободный слот
    var slot: ?usize = null;
    for (&vn.conns, 0..) |*c, i| {
        if (c.state == .unused or c.state == .closed) {
            slot = i;
            break;
        }
    }
    const si = slot orelse return VnetError.NoFreeConn;
    const c = &vn.conns[si];

    // RX-кольцо (лениво)
    if (c.ring_phys == 0) {
        const base = pmm.allocContiguousPages(RX_RING_PAGES) orelse return VnetError.InitFailed;
        c.ring_phys = base;
        c.ring_virt = base; // identity
        const zp: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(base)));
        @memset(zp[0..RX_RING_SIZE], 0);
    }
    c.ring_head = 0;
    c.ring_tail = 0;
    c.peer_ip = peer_ip;
    c.peer_port = peer_port;
    c.src_port = vn.next_src_port;
    vn.next_src_port +%= 1;
    if (vn.next_src_port < 0xC350) vn.next_src_port = 0xC350;
    c.iss = @truncate(hal.readMsr(0x10)); // TSC как ISS
    if (c.iss == 0) c.iss = 0x1234;
    c.snd_nxt = c.iss +% 1;
    c.snd_una = c.iss; // v0.15.0: SYN [iss, iss+1) в полёте
    c.rcv_nxt = 0;
    c.fin_received = false;
    c.aborted = false;
    c.syn_retries = 0;
    c.rtx_len = 0; // v0.15.0: ретрансмит-буфер пуст
    c.fin_unacked = false;
    c.rto_ticks = RTO_INITIAL_TICKS;
    c.rtx_attempts = 0;
    c.ka_probes = 0;
    c.last_xmit_tick = hal.tick_count;
    c.last_ack_tick = hal.tick_count;
    c.win_advertised = 0xFFFF; // кольцо пусто на момент connect
    c.state = .syn_sent;

    // SYN с MSS-опцией
    var seg: [64]u8 = undefined;
    const n = buildTcpSegment(&seg, c.src_port, c.peer_port, c.iss, 0, TCP_SYN, 4, &.{}, .{ 10, 0, 2, 15 }, peer_ip, 0xFFFF);
    if (!sendIp(IP_PROTO_TCP, seg[0..n], peer_ip)) {
        c.state = .unused;
        return VnetError.Timeout;
    }
    hal.Serial.puts("[VNET] TCP SYN отправлен (slot ");
    hal.Serial.putDecimal(si);
    hal.Serial.puts(" → ");
    for (peer_ip, 0..) |b, j| {
        hal.Serial.putDecimal(b);
        if (j < 3) hal.Serial.puts(".");
    }
    hal.Serial.putDecimal(peer_port);
    hal.Serial.puts(")\n");

    // ждём SYN-ACK (поллинг RX; ~3 попытки ретрансмита)
    var attempt: u8 = 0;
    while (attempt < 4) : (attempt += 1) {
        var spins: u32 = 0;
        while (spins < 8_000_000) : (spins += 1) {
            pollRx();
            if (c.state == .established) return si;
            if (c.state == .closed) return VnetError.ConnClosed;
            asm volatile ("pause");
        }
        // ретрансмит SYN
        c.syn_retries += 1;
        _ = sendIp(IP_PROTO_TCP, seg[0..n], peer_ip);
        hal.Serial.puts("[VNET] TCP SYN retransmit\n");
    }
    c.state = .unused;
    hal.Serial.puts("[VNET] TCP connect: TIMEOUT\n");
    return VnetError.Timeout;
}

/// Отправка ACK текущего состояния (окно = реальное место ринга).
/// v0.15.0 (CDD №6): заодно window-update — отправитель возобновляет поток.
fn sendTcpAck(c: *TcpConn) void {
    var seg: [64]u8 = undefined;
    const win = recvWindow(c);
    const n = buildTcpSegment(&seg, c.src_port, c.peer_port, c.snd_nxt, c.rcv_nxt, TCP_ACK, 0, &.{}, .{ 10, 0, 2, 15 }, c.peer_ip, win);
    c.win_advertised = win;
    _ = sendIp(IP_PROTO_TCP, seg[0..n], c.peer_ip);
}

/// Отправка данных (PSH+ACK): сегмент ≤ MSS. v0.15.0: данные сохраняются
/// в RTX-буфер [snd_una..snd_nxt) — ретрансмиты с бэкоффом (tcpTimers).
fn sendTcpData(c: *TcpConn, data: []const u8) bool {
    var seg: [ETH_HDR_LEN + 20 + 40 + 1600]u8 = undefined;
    const win = recvWindow(c);
    const n = buildTcpSegment(&seg, c.src_port, c.peer_port, c.snd_nxt, c.rcv_nxt, TCP_ACK | TCP_PSH, 0, data, .{ 10, 0, 2, 15 }, c.peer_ip, win);
    if (!sendIp(IP_PROTO_TCP, seg[0..n], c.peer_ip)) return false;
    // v0.15.0-фикс: rtxStore ТОЛЬКО после успешной отправки — инвариант
    // «буфер покрывает ровно [snd_una, snd_nxt)» не нарушается при TX-фейле
    if (!rtxStore(c, data)) {
        // CDD-граница: >32КБ неподержтверждённых — fire&forget (лог)
        hal.Serial.puts("[VNET] TCP: RTX-буфер полон — сегмент без ретрансмита\n");
    }
    c.snd_nxt +%= @intCast(data.len);
    c.win_advertised = win;
    c.last_xmit_tick = hal.tick_count;
    return true;
}

/// tcpSend: данные с нарезкой по MSS (все чанки подряд, затем RX-полл).
pub fn tcpSend(slot: usize, data: []const u8) VnetError!usize {
    if (slot >= MAX_TCP_CONNS) return VnetError.BadState;
    const c = &vn.conns[slot];
    if (c.state != .established) return VnetError.BadState;
    var sent: usize = 0;
    while (sent < data.len) {
        const chunk = @min(data.len - sent, MSS);
        if (!sendTcpData(c, data[sent .. sent + chunk])) return VnetError.Timeout;
        sent += chunk;
    }
    pollRx(); // забрать ACKи/данные после полной отправки
    return sent;
}

/// tcpRecv: данные из RX-кольца (поллинг с таймаутом ~150мс; 0 = нет данных).
/// v0.15.0 (CDD №6): после дренажа ринга — window-update ACK (открываем
/// окно отправителю) + EOF по fin_received (FIN сервера уже принят).
pub fn tcpRecv(slot: usize, out: []u8, wait: bool) VnetError!usize {
    if (slot >= MAX_TCP_CONNS) return VnetError.BadState;
    const c = &vn.conns[slot];
    if (c.state == .closed and c.aborted) return VnetError.ConnClosed; // RST/timeout
    if (wait) {
        var spins: u32 = 0;
        while (spins < 4_000_000) : (spins += 1) {
            pollRx();
            if (ringBytes(c) > 0 or (c.state == .closed or c.fin_received)) break;
            asm volatile ("pause");
        }
    } else {
        pollRx();
    }
    const avail = ringBytes(c);
    if (avail == 0) {
        // FIN уже принят (и ring пуст) → EOF; TIME_WAIT/CLOSED аналогично
        if (c.fin_received or c.state == .closed or c.state == .time_wait) {
            return VnetError.ConnClosed;
        }
        return 0;
    }
    const n = @min(avail, out.len);
    const rp: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(c.ring_virt)));
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out[i] = rp[c.ring_head];
        c.ring_head = (c.ring_head + 1) % RX_RING_SIZE;
    }
    // v0.15.0: window-update — окно открылось после дренажа
    if (c.win_advertised < WIN_UPDATE_THRESHOLD and recvWindow(c) >= WIN_UPDATE_THRESHOLD) {
        sendTcpAck(c);
        hal.Serial.puts("[VNET] TCP: window-update (slot ");
        hal.Serial.putDecimal(slot);
        hal.Serial.puts(")\n");
    }
    return n;
}

/// tcpPoll: активный поллинг (select-путь). Возврат: байт в ринге после
/// полла; -1 — соединение закрыто (FIN/RST).
pub fn tcpPoll(slot: usize) i64 {
    if (slot >= MAX_TCP_CONNS) return 0;
    pollRx();
    const c = &vn.conns[slot];
    if (c.state == .closed and c.aborted) return -1; // RST — данных нет
    if (c.fin_received and ringBytes(c) == 0) return -1; // EOF после дренажа
    if (c.state == .time_wait and ringBytes(c) == 0) return -1;
    return @intCast(ringBytes(c));
}

pub fn tcpState(slot: usize) TcpState {
    if (slot >= MAX_TCP_CONNS) return .unused;
    return vn.conns[slot].state;
}

pub fn tcpRingBytes(slot: usize) usize {
    if (slot >= MAX_TCP_CONNS) return 0;
    return ringBytes(&vn.conns[slot]);
}

/// tcpClose: v0.15.0 — честный FIN-кланг: FIN|ACK → fin_wait_1 →
/// (ACK нашего FIN) fin_wait_2 → (FIN пира + финальный ACK) time_wait →
/// closed. FIN ретрансмится движком до подтверждения. Данные пира в ринге
/// доигрываются (fin_received).
pub fn tcpClose(slot: usize) void {
    if (slot >= MAX_TCP_CONNS) return;
    const c = &vn.conns[slot];
    if (c.state != .established and c.state != .fin_wait_1) return;
    if (c.fin_unacked) return; // FIN уже в полёте
    var seg: [64]u8 = undefined;
    const win = recvWindow(c);
    const n = buildTcpSegment(&seg, c.src_port, c.peer_port, c.snd_nxt, c.rcv_nxt, TCP_FIN | TCP_ACK, 0, &.{}, .{ 10, 0, 2, 15 }, c.peer_ip, win);
    if (sendIp(IP_PROTO_TCP, seg[0..n], c.peer_ip)) {
        c.snd_nxt +%= 1; // FIN занимает один seq
        c.fin_unacked = true;
        c.state = .fin_wait_1;
        c.last_xmit_tick = hal.tick_count;
        c.win_advertised = win;
        hal.Serial.puts("[VNET] TCP: FIN отправлен (slot ");
        hal.Serial.putDecimal(slot);
        hal.Serial.puts(")\n");
    } else {
        c.state = .closed;
        c.aborted = true;
    }
}

// ============================================================================
// v0.15.0 (CDD №6): RTX-движок — ретрансмиты с экспоненциальным бэкоффом +
// TCP keep-alive. Гоняется в poll-точках (pollRx → tcpTimers): во время
// активного обмена curl шлёт send/recv/select непрерывно — движок дышит на
// каждом системном вызове. Чистая Ring-3 пауза (крипто-вычисления OpenSSL
// без сисколов) таймеры приостанавливает — CDD-граница (IRQ-служба — цикл №7).
// ============================================================================

/// RTX-буфер: ленивая аллокация 8 identity-страниц.
fn rtxEnsure(c: *TcpConn) bool {
    if (c.rtx_virt != 0) return true;
    const base = pmm.allocContiguousPages(RTX_PAGES) orelse return false;
    c.rtx_phys = base;
    c.rtx_virt = base;
    const zp: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(base)));
    @memset(zp[0..RTX_SIZE], 0);
    return true;
}

/// Сохранить данные для ретрансмита (в хвост [snd_una..snd_nxt)).
fn rtxStore(c: *TcpConn, data: []const u8) bool {
    if (!rtxEnsure(c)) return false;
    if (c.rtx_len + data.len > RTX_SIZE) return false;
    const rp: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(c.rtx_virt)));
    var i: usize = 0;
    while (i < data.len) : (i += 1) rp[c.rtx_len + i] = data[i];
    c.rtx_len += data.len;
    return true;
}

/// ACK покрыл adv байт от snd_una — сдвигаем буфер (memmove влево).
fn rtxConsume(c: *TcpConn, adv: usize) void {
    if (adv == 0) return;
    const drop = @min(adv, c.rtx_len);
    const rest = c.rtx_len - drop;
    if (rest > 0 and drop > 0) {
        const rp: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(c.rtx_virt)));
        var i: usize = 0;
        while (i < rest) : (i += 1) rp[i] = rp[drop + i];
    }
    c.rtx_len = rest;
}

/// Ретрансмит: MSS-чанк от snd_una (+FIN если он в хвосте).
fn rtxTransmit(c: *TcpConn) void {
    var seg: [ETH_HDR_LEN + 20 + 40 + 1600]u8 = undefined;
    if (c.rtx_len > 0) {
        const n = @min(c.rtx_len, MSS);
        const rp: [*]const u8 = @ptrFromInt(@as(usize, @intCast(c.rtx_virt)));
        var flags: u16 = TCP_ACK | TCP_PSH;
        if (c.fin_unacked and n == c.rtx_len) flags |= TCP_FIN; // FIN в хвосте
        const seglen = buildTcpSegment(&seg, c.src_port, c.peer_port, c.snd_una, c.rcv_nxt, flags, 0, rp[0..n], .{ 10, 0, 2, 15 }, c.peer_ip, recvWindow(c));
        if (sendIp(IP_PROTO_TCP, seg[0..seglen], c.peer_ip)) {
            vn.rtx_frames += 1;
            hal.Serial.puts("[VNET] TCP: RETRANSMIT ");
            hal.Serial.putDecimal(n);
            hal.Serial.puts("Б, попытка ");
            hal.Serial.putDecimal(c.rtx_attempts + 1);
            hal.Serial.puts("\n");
        }
    } else if (c.fin_unacked) {
        // ретрансмит одинокого FIN
        const seglen = buildTcpSegment(&seg, c.src_port, c.peer_port, c.snd_nxt -% 1, c.rcv_nxt, TCP_FIN | TCP_ACK, 0, &.{}, .{ 10, 0, 2, 15 }, c.peer_ip, recvWindow(c));
        if (sendIp(IP_PROTO_TCP, seg[0..seglen], c.peer_ip)) {
            vn.rtx_frames += 1;
            hal.Serial.puts("[VNET] TCP: FIN retransmit\n");
        }
    }
}

/// Keep-alive проба: seq = snd_nxt-1 (пустой сегмент за границей) —
/// пир отвечает дубль-ACKом (handleTcp сбрасывает ka-счётчик).
fn sendKaProbe(c: *TcpConn) void {
    var seg: [64]u8 = undefined;
    const n = buildTcpSegment(&seg, c.src_port, c.peer_port, c.snd_nxt -% 1, c.rcv_nxt, TCP_ACK, 0, &.{}, .{ 10, 0, 2, 15 }, c.peer_ip, recvWindow(c));
    if (sendIp(IP_PROTO_TCP, seg[0..n], c.peer_ip)) {
        vn.ka_probes_sent += 1;
        hal.Serial.puts("[VNET] TCP: keep-alive проба (slot)\n");
    }
}

/// Таймеры TCP: ретрансмиты (RTO ×2 бэкофф, ≤8 попыток) + keep-alive
/// (1с idle → проба, ≤5 без ответа → abort) + time_wait-истечение.
fn tcpTimers() void {
    const now = hal.tick_count;
    for (&vn.conns, 0..) |*c, si| {
        switch (c.state) {
            .time_wait => {
                if (now -% c.last_xmit_tick > 30) { // ~300мс TIME_WAIT
                    c.state = .closed;
                }
                continue;
            },
            .syn_sent => continue, // SYN-ретрансмиты — зона tcpConnect (свой цикл): SYN не в RTX-буфере, abort-таймер не должен убить ожидание SYN-ACK
            .established, .fin_wait_1, .fin_wait_2 => {},
            else => continue,
        }
        const inflight = c.snd_nxt -% c.snd_una;
        if (inflight > 0) {
            // ретрансмит-таймер: без ACK за RTO → повтор с бэкоффом
            if (now -% c.last_xmit_tick > c.rto_ticks) {
                rtxTransmit(c);
                c.rtx_attempts += 1;
                c.last_xmit_tick = now;
                c.rto_ticks = @min(c.rto_ticks * 2, RTO_MAX_TICKS); // экспоненциальный бэкофф
                if (c.rtx_attempts >= RTX_MAX_ATTEMPTS) {
                    hal.Serial.puts("[VNET] TCP: ретрансмит-таймаут — соединение закрыто (slot ");
                    hal.Serial.putDecimal(si);
                    hal.Serial.puts(")\n");
                    c.state = .closed;
                    c.aborted = true;
                }
            }
        } else {
            // всё подтверждено — RTO в исходное
            c.rto_ticks = RTO_INITIAL_TICKS;
            c.rtx_attempts = 0;
            // keep-alive: тишина KA_IDLE → проба (сервер видит жизнь
            // соединения даже во время долгих TLS-пауз клиента)
            if (c.state == .established and (now -% c.last_ack_tick) > KA_IDLE_TICKS) {
                sendKaProbe(c);
                c.ka_probes += 1;
                c.last_ack_tick = now; // период проб = KA_IDLE
                if (c.ka_probes > KA_MAX_PROBES) {
                    hal.Serial.puts("[VNET] TCP: keep-alive провален — соединение закрыто (slot ");
                    hal.Serial.putDecimal(si);
                    hal.Serial.puts(")\n");
                    c.state = .closed;
                    c.aborted = true;
                }
            }
        }
    }
}

// ============================================================================
// DNS (SLIRP 10.0.2.3)
// ============================================================================

/// dnsResolve: A-запись host через UDP→10.0.2.3 (блокирующий поллинг).
/// Возврат: 4 байта IP (BE-порядок в байтах: ip[0].ip[1]...) или null.
pub fn dnsResolve(host: []const u8) ?[4]u8 {
    if (!vn.initialized) return null;
    if (!resolveGateway()) return null;
    if (host.len == 0 or host.len > 128) return null;

    // IP-литерал? (a.b.c.d) — без DNS
    if (parseIpLiteral(host)) |ip| return ip;

    var query: [256]u8 = undefined;
    const txn: u16 = @as(u16, @truncate(hal.readMsr(0x10) >> 8)) | 1;
    vn_dns_txn = txn;
    const qlen = buildDnsQuery(&query, txn, host);
    if (qlen == 0) return null;

    var udp: [512]u8 = undefined;
    const ulen = buildUdpDatagram(&udp, 53, 53, query[0..qlen]);

    vn.dns_have = false;
    var attempt: u8 = 0;
    while (attempt < 3) : (attempt += 1) {
        if (sendIp(IP_PROTO_UDP, udp[0..ulen], .{ 10, 0, 2, 3 })) {
            var spins: u32 = 0;
            while (spins < 6_000_000) : (spins += 1) {
                pollRx();
                if (vn.dns_have) {
                    dnsCachePut(host, vn.dns_last_ip); // v0.15.0: кэш для netstat
                    return vn.dns_last_ip;
                }
                asm volatile ("pause");
            }
        }
    }
    hal.Serial.puts("[VNET] DNS: timeout\n");
    return null;
}

/// Парс «192.0.2.1» → [192,0,2,1]. null — не IP-литерал.
pub fn parseIpLiteral(s: []const u8) ?[4]u8 {
    var oct: [4]u8 = .{ 0, 0, 0, 0 };
    var oi: usize = 0;
    var val: u32 = 0;
    var digits: u32 = 0;
    for (s) |ch| {
        if (ch == '.') {
            if (digits == 0 or oi >= 4) return null;
            oct[oi] = @intCast(val);
            oi += 1;
            val = 0;
            digits = 0;
        } else if (ch >= '0' and ch <= '9') {
            val = val * 10 + (ch - '0');
            digits += 1;
            if (val > 255) return null;
        } else return null;
    }
    if (digits == 0 or oi != 3) return null;
    oct[3] = @intCast(val);
    return oct;
}

// ============================================================================
// v0.15.0 (CDD №6): ICMP ping (Echo Request/Reply через шлюз SLIRP —
// NAT-режим QEMU user-net пробрасывает ICMP) + статистика для ifconfig
// ============================================================================

pub const PingResult = struct {
    sent: u8 = 0,
    received: u8 = 0,
    rtt_ms: u64 = 0, // лучший (минимальный) RTT
};

/// icmpPing: count проб по ip (блокирующий поллинг, таймаут ~1-3с на пробу).
/// RTT — TSC-дельта (калибровка tsc_per_ms; 0 → тиковая грубость).
/// Каждая проба логируется [PING]-строкой (serial; E2E-маяки).
pub fn icmpPing(ip: [4]u8, count: u8) PingResult {
    var res = PingResult{ .sent = 0, .received = 0 };
    if (!vn.initialized) return res;
    if (!resolveGateway()) return res;
    vn.icmp_id = @as(u16, @truncate(hal.readMsr(0x10) >> 4)) | 1;
    var seq: u16 = 1;
    var probes: u8 = 0;
    while (probes < count) : (probes += 1) {
        var icmp: [64]u8 = undefined;
        const n = buildIcmpEcho(&icmp, vn.icmp_id, seq);
        vn.icmp_seq = seq;
        vn.icmp_reply_seen = false;
        vn.icmp_reply_seq = 0;
        const t0 = hal.readMsr(0x10);
        if (!sendIp(IP_PROTO_ICMP, icmp[0..n], ip)) break;
        res.sent += 1;
        // ждём Echo Reply (поллинг ~1-3с — реальный интернет-RTT ≪)
        var spins: u32 = 0;
        while (spins < 3_000_000) : (spins += 1) {
            pollRx();
            if (vn.icmp_reply_seen and vn.icmp_reply_seq == seq) break;
            asm volatile ("pause");
        }
        if (vn.icmp_reply_seen and vn.icmp_reply_seq == seq) {
            res.received += 1;
            const dt = vn.icmp_rx_tsc -% t0;
            const ms: u64 = if (vn.tsc_per_ms > 0) dt / vn.tsc_per_ms else dt;
            if (res.rtt_ms == 0 or ms < res.rtt_ms) res.rtt_ms = ms;
            hal.Serial.puts("[PING] seq=");
            hal.Serial.putDecimal(seq);
            hal.Serial.puts(": ответ от ");
            for (ip, 0..) |b, j| {
                hal.Serial.putDecimal(b);
                if (j < 3) hal.Serial.puts(".");
            }
            hal.Serial.puts(", время ");
            hal.Serial.putDecimal(ms);
            hal.Serial.puts("мс\n");
        } else {
            hal.Serial.puts("[PING] seq=");
            hal.Serial.putDecimal(seq);
            hal.Serial.puts(": таймаут (нет ответа)\n");
        }
        seq += 1;
    }
    return res;
}

pub const NetStats = struct {
    rx_frames: u64,
    rx_bytes: u64,
    tx_frames: u64,
    tx_bytes: u64,
    rtx_frames: u64,
    ka_probes: u64,
};

pub fn netStats() NetStats {
    return .{
        .rx_frames = vn.rx_frames,
        .rx_bytes = vn.rx_bytes,
        .tx_frames = vn.tx_frames,
        .tx_bytes = vn.tx_bytes,
        .rtx_frames = vn.rtx_frames,
        .ka_probes = vn.ka_probes_sent,
    };
}

/// netstat-строка соединения (для cmd_netstat).
pub const ConnInfo = struct {
    slot: usize,
    state: TcpState,
    peer_ip: [4]u8,
    peer_port: u16,
    src_port: u16,
    ring_bytes: usize,
    inflight: u32, // snd_nxt - snd_una
    fin_received: bool,
    aborted: bool,
};

pub fn connInfo(slot: usize) ?ConnInfo {
    if (slot >= MAX_TCP_CONNS) return null;
    const c = &vn.conns[slot];
    if (c.state == .unused) return null;
    return .{
        .slot = slot,
        .state = c.state,
        .peer_ip = c.peer_ip,
        .peer_port = c.peer_port,
        .src_port = c.src_port,
        .ring_bytes = ringBytes(c),
        .inflight = c.snd_nxt -% c.snd_una,
        .fin_received = c.fin_received,
        .aborted = c.aborted,
    };
}

/// DNS-кэш (последний успешный резолв) для ifconfig/netstat.
pub const DnsCache = struct { host: []const u8, ip: [4]u8 };

var dns_cache_host: [64]u8 = undefined;
var dns_cache_len: usize = 0;
var dns_cache_ip: [4]u8 = .{ 0, 0, 0, 0 };
var dns_cache_valid: bool = false;

pub fn dnsCacheGet() ?DnsCache {
    if (!dns_cache_valid or dns_cache_len == 0) return null;
    return .{ .host = dns_cache_host[0..dns_cache_len], .ip = dns_cache_ip };
}

pub fn dnsCachePut(host: []const u8, ip: [4]u8) void {
    const n = @min(host.len, dns_cache_host.len);
    @memcpy(dns_cache_host[0..n], host[0..n]);
    dns_cache_len = n;
    dns_cache_ip = ip;
    dns_cache_valid = true;
}

const std = @import("std");

// ============================================================================
// Тесты (нативные): билдеры + чексуммы + парсеры — вся байтовая семантика
// сетевого стека без железа.
// ============================================================================

const testing = std.testing;

test "net: ipChecksum — RFC 1071 пример" {
    // классический пример RFC 1071: сумма слов 0001 f203 f4f5 f6f7 = 0xDDF2,
    // чексумма = дополнение до двух = 0x220D
    const data = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    try testing.expectEqual(@as(u16, 0x220D), ipChecksum(&data));
    // нулевая чексумма для нулевых данных = 0xFFFF
    const zero = [_]u8{0} ** 20;
    try testing.expectEqual(@as(u16, 0xFFFF), ipChecksum(&zero));
    // нечётная длина: последний байт в старшем разряде
    const odd = [_]u8{ 0x00, 0x01, 0xf2 };
    try testing.expectEqual(@as(u16, ~@as(u16, 0x0001 + 0xf200)), ipChecksum(&odd));
}

test "net: buildEthernet — порядок байт dst/src/type" {
    var buf: [14]u8 = undefined;
    const n = buildEthernet(&buf, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, .{ 1, 2, 3, 4, 5, 6 }, ETH_TYPE_IPV4);
    try testing.expectEqual(@as(usize, 14), n);
    try testing.expectEqual(@as(u8, 0xAA), buf[0]);
    try testing.expectEqual(@as(u8, 6), buf[11]);
    try testing.expectEqual(@as(u8, 0x08), buf[12]);
    try testing.expectEqual(@as(u8, 0x00), buf[13]);
}

test "net: buildIpv4 — чексумма валидна (пересчёт = 0)" {
    var hdr: [20]u8 = undefined;
    const n = buildIpv4(&hdr, .{ 10, 0, 2, 15 }, .{ 93, 184, 216, 34 }, IP_PROTO_TCP, 20);
    try testing.expectEqual(@as(usize, 40), n);
    // перевыгнутая чексумма (включая поле csum) должна дать 0
    try testing.expectEqual(@as(u16, 0), ipChecksum(hdr[0..20]));
}

test "net: buildTcpSegment — SYN с MSS + чексумма-стенд" {
    var seg: [64]u8 = undefined;
    const n = buildTcpSegment(&seg, 0xC350, 0x01BB, 0x1000, 0, TCP_SYN, 4, &.{}, .{ 10, 0, 2, 15 }, .{ 93, 184, 216, 34 }, 0xFFFF);
    try testing.expectEqual(@as(usize, 24), n); // 20 + 4 (MSS)
    try testing.expectEqual(@as(u8, 0xC3), seg[0]);
    try testing.expectEqual(@as(u8, 0x01), seg[2]); // dst port 443 = 0x01BB
    try testing.expectEqual(@as(u8, 0xBB), seg[3]);
    // MSS-опция
    try testing.expectEqual(@as(u8, 2), seg[20]); // kind
    try testing.expectEqual(@as(u8, 4), seg[21]); // len
    try testing.expectEqual(@as(u8, MSS >> 8), seg[22]);
    // data offset = 6 слов (24/4)
    try testing.expectEqual(@as(u8, 0x60), seg[12]);
    // v0.15.0: window поле
    try testing.expectEqual(@as(u8, 0xFF), seg[14]);
    try testing.expectEqual(@as(u8, 0xFF), seg[15]);
}

test "net: buildTcpSegment — заголовок корректен" {
    var seg: [64]u8 = undefined;
    const n = buildTcpSegment(&seg, 0xC350, 0x01BB, 0x1000, 0x2000, TCP_ACK | TCP_PSH, 0, "hello", .{ 10, 0, 2, 15 }, .{ 10, 0, 2, 2 }, 0x4000);
    try testing.expectEqual(@as(usize, 25), n); // 20 + 5
    try testing.expectEqual(@as(u8, 0x50), seg[12]); // data offset 5
    try testing.expectEqual(@as(u8, TCP_ACK | TCP_PSH), seg[13]);
    try testing.expectEqualStrings("hello", seg[20..25]);
    // v0.15.0: window = 0x4000
    try testing.expectEqual(@as(u8, 0x40), seg[14]);
    try testing.expectEqual(@as(u8, 0x00), seg[15]);
}

test "net: buildArpRequest — поля op/hln/plen" {
    var buf: [28]u8 = undefined;
    const n = buildArpRequest(&buf, .{ 1, 2, 3, 4, 5, 6 }, .{ 10, 0, 2, 15 }, .{ 10, 0, 2, 2 });
    try testing.expectEqual(@as(usize, 28), n);
    try testing.expectEqual(@as(u8, 0), buf[6]);
    try testing.expectEqual(@as(u8, 1), buf[7]); // op=request
    try testing.expectEqual(@as(u8, 4), buf[5]); // plen
    try testing.expectEqual(@as(u8, 10), buf[14]); // sender ip
    try testing.expectEqual(@as(u8, 2), buf[27]); // target ip last
}

test "net: buildUdpDatagram + buildDnsQuery — структура запроса" {
    var udp: [128]u8 = undefined;
    var dns: [64]u8 = undefined;
    const dlen = buildDnsQuery(&dns, 0xABCD, "example.com");
    try testing.expect(dlen > 16);
    try testing.expectEqual(@as(u8, 0xAB), dns[0]);
    try testing.expectEqual(@as(u8, 0xCD), dns[1]);
    try testing.expectEqual(@as(u8, 1), dns[5]); // QDCOUNT
    // QNAME: 7 'example' 3 'com' 0
    try testing.expectEqual(@as(u8, 7), dns[12]);
    try testing.expectEqualStrings("example", dns[13..20]);
    try testing.expectEqual(@as(u8, 3), dns[20]);
    try testing.expectEqualStrings("com", dns[21..24]);
    try testing.expectEqual(@as(u8, 0), dns[24]); // корень
    // QTYPE/QCLASS
    try testing.expectEqual(@as(u8, 0), dns[25]);
    try testing.expectEqual(@as(u8, 1), dns[26]);
    try testing.expectEqual(@as(u8, 0), dns[27]);
    try testing.expectEqual(@as(u8, 1), dns[28]); // CLASS IN

    const ulen = buildUdpDatagram(&udp, 53, 53, dns[0..dlen]);
    try testing.expectEqual(dlen + 8, ulen);
    try testing.expectEqual(@as(u8, 0), udp[0]); // src port hi
    try testing.expectEqual(@as(u8, 53), udp[1]);
}

test "net: parseDnsResponse — A-запись + сжатие имён + ошибки" {
    // синтетический ответ: header + Q(example.com) + answer с указателем
    var pkt: [64]u8 = undefined;
    pkt[0] = 0xAB;
    pkt[1] = 0xCD;
    pkt[2] = 0x81; // response + RD
    pkt[3] = 0x80; // RA, rcode=0
    pkt[4] = 0;
    pkt[5] = 1; // QD
    pkt[6] = 0;
    pkt[7] = 1; // AN
    @memset(pkt[8..12], 0);
    // QNAME
    pkt[12] = 7;
    @memcpy(pkt[13..20], "example");
    pkt[20] = 4;
    @memcpy(pkt[21..25], "com0"); // wait: len4 → 'com' только 3... аккуратно
    // корректнее:
    pkt[20] = 3;
    @memcpy(pkt[21..24], "com");
    pkt[24] = 0;
    pkt[25] = 0;
    pkt[26] = 1; // QTYPE A
    pkt[27] = 0;
    pkt[28] = 1; // QCLASS
    // Answer: имя-указатель 0xC00C
    pkt[29] = 0xC0;
    pkt[30] = 0x0C;
    pkt[31] = 0;
    pkt[32] = 1; // TYPE A
    pkt[33] = 0;
    pkt[34] = 1; // CLASS
    // TTL
    pkt[35] = 0;
    pkt[36] = 0;
    pkt[37] = 0;
    pkt[38] = 60;
    pkt[39] = 0;
    pkt[40] = 4; // RDLENGTH
    pkt[41] = 93;
    pkt[42] = 184;
    pkt[43] = 216;
    pkt[44] = 34;
    const ip = parseDnsResponse(pkt[0..45], 0xABCD);
    try testing.expect(ip != null);
    try testing.expectEqual(@as(u8, 93), ip.?[0]);
    try testing.expectEqual(@as(u8, 34), ip.?[3]);
    // неверный txn → null
    try testing.expectEqual(@as(?[4]u8, null), parseDnsResponse(pkt[0..45], 0x1111));
}

test "net: parseIpLiteral" {
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2, 1 }, &(parseIpLiteral("192.0.2.1") orelse unreachable));
    try testing.expectEqual(@as(?[4]u8, null), parseIpLiteral("example.com"));
    try testing.expectEqual(@as(?[4]u8, null), parseIpLiteral("1.2.3"));
    try testing.expectEqual(@as(?[4]u8, null), parseIpLiteral("300.1.1.1"));
    try testing.expectEqual(@as(?[4]u8, null), parseIpLiteral(""));
}

test "net: skipDnsName — простые и сжатые имена" {
    var buf: [32]u8 = undefined;
    buf[0] = 7;
    @memcpy(buf[1..8], "example");
    buf[8] = 0;
    try testing.expectEqual(@as(?usize, 9), skipDnsName(buf[0..], 0));
    buf[0] = 0xC0;
    buf[1] = 0x0C;
    try testing.expectEqual(@as(?usize, 2), skipDnsName(buf[0..], 0));
}

// ─── v0.15.0 (CDD №6): ICMP + sliding window + RTX-seq-математика ──────────

test "net: buildIcmpEcho → parseIcmpReply — roundtrip (id/seq/чексумма)" {
    var pkt: [64]u8 = undefined;
    const n = buildIcmpEcho(&pkt, 0x1234, 7);
    try testing.expectEqual(@as(usize, 64), n);
    try testing.expectEqual(@as(u8, 8), pkt[0]); // echo request
    // чексумма валидна: пересчёт с нулевым полем = значение поля
    var scratch: [64]u8 = undefined;
    @memcpy(&scratch, &pkt);
    scratch[2] = 0;
    scratch[3] = 0;
    const expect = (@as(u16, pkt[2]) << 8) | pkt[3];
    try testing.expect(ipChecksum(&scratch) == expect);
    // reply: type=0 → чексумму пересчитать (type входит в сумму)
    pkt[0] = 0;
    pkt[2] = 0;
    pkt[3] = 0;
    const cs = ipChecksum(pkt[0..n]);
    pkt[2] = @intCast(cs >> 8);
    pkt[3] = @intCast(cs & 0xFF);
    const r = parseIcmpReply(pkt[0..n], 0x1234);
    try testing.expect(r != null);
    try testing.expectEqual(@as(u16, 0x1234), r.?.id);
    try testing.expectEqual(@as(u16, 7), r.?.seq);
}

test "net: parseIcmpReply — отбрасывания (не reply / чужой id / битая csum)" {
    var pkt: [64]u8 = undefined;
    _ = buildIcmpEcho(&pkt, 0x1234, 1);
    pkt[0] = 0; // reply → чексумму пересчитать
    pkt[2] = 0;
    pkt[3] = 0;
    const cs = ipChecksum(pkt[0..64]);
    pkt[2] = @intCast(cs >> 8);
    pkt[3] = @intCast(cs & 0xFF);
    // валидный baseline (sanity)
    try testing.expect(parseIcmpReply(pkt[0..64], 0x1234) != null);
    // чужой id
    try testing.expectEqual(@as(?IcmpEcho, null), parseIcmpReply(pkt[0..], 0x4321));
    // битая чексумма (портим payload после вычисления)
    pkt[40] ^= 0xFF;
    try testing.expectEqual(@as(?IcmpEcho, null), parseIcmpReply(pkt[0..], 0x1234));
    // не echo reply (тип 3 = destination unreachable)
    var pkt2: [64]u8 = undefined;
    @memcpy(&pkt2, &pkt);
    pkt2[0] = 3;
    try testing.expectEqual(@as(?IcmpEcho, null), parseIcmpReply(pkt2[0..], 0x1234));
    // короткий пакет
    try testing.expectEqual(@as(?IcmpEcho, null), parseIcmpReply(pkt2[0..8], 0x1234));
}

test "net: buildIcmpEchoReply — зеркало запроса с корректной чексуммой" {
    var req: [64]u8 = undefined;
    _ = buildIcmpEcho(&req, 0xBEEF, 42);
    var reply: [64]u8 = undefined;
    const n = buildIcmpEchoReply(&reply, req[0..64]);
    try testing.expectEqual(@as(usize, 64), n);
    try testing.expectEqual(@as(u8, 0), reply[0]); // echo reply
    // id/seq зеркалятся
    try testing.expectEqual(@as(u8, 0xBE), reply[4]);
    try testing.expectEqual(@as(u8, 0xEF), reply[5]);
    try testing.expectEqual(@as(u8, 0), reply[6]);
    try testing.expectEqual(@as(u8, 42), reply[7]);
    // payload зеркалятся
    try testing.expectEqualSlices(u8, req[8..64], reply[8..64]);
    // и reply сам валиден для parseIcmpReply
    const r = parseIcmpReply(reply[0..n], 0xBEEF);
    try testing.expect(r != null);
    try testing.expectEqual(@as(u16, 42), r.?.seq);
}

test "net: ringSpace/recvWindow — sliding window инварианты" {
    var c = TcpConn{};
    c.ring_head = 0;
    c.ring_tail = 0;
    try testing.expectEqual(RX_RING_SIZE, ringSpace(&c));
    try testing.expectEqual(@as(u16, 0xFFFF), recvWindow(&c)); // cap u16
    // 1000Б в ринге
    c.ring_tail = 1000;
    try testing.expectEqual(RX_RING_SIZE - 1000, ringSpace(&c));
    // почти полный ринг → окно крошечное
    c.ring_head = 1;
    c.ring_tail = 0; // wrap: tail догнал-бы head если бы не инвариант
    // bytes = SIZE - 1 + 0 = SIZE-1 → space = 1
    try testing.expectEqual(@as(usize, RX_RING_SIZE - (RX_RING_SIZE - 1)), ringSpace(&c));
    // окно 1Б (нулём не бывает: drop при исчерпании)
    try testing.expectEqual(@as(u16, 1), recvWindow(&c));
}

test "net: TCP seq-математика RTX-движка (обёртка u32)" {
    var c = TcpConn{};
    // 32Б в полёте через границу 2^32
    c.snd_una = 0xFFFFFFF0;
    c.snd_nxt = c.snd_una +% 32;
    const inflight = c.snd_nxt -% c.snd_una;
    try testing.expectEqual(@as(u32, 32), inflight);
    // валидный ACK на 16Б — adv корректен через границу
    const ack = c.snd_una +% 16; // 0x00000000 (wrap!)
    const adv = ack -% c.snd_una;
    try testing.expectEqual(@as(u32, 16), adv);
    try testing.expect(adv <= inflight);
    // ACK «из будущего» (за snd_nxt) — отклоняется
    const bogus = c.snd_nxt +% 100;
    try testing.expect((bogus -% c.snd_una) > inflight);
    // дубликат (старый ack) — обёртка-гигант — отклоняется
    const dup = c.snd_una -% 1;
    try testing.expect((dup -% c.snd_una) > inflight);
    // FIN занимает +1: inflight = rtx_len + 1
    c.rtx_len = 32;
    c.fin_unacked = false;
    c.snd_nxt = c.snd_una +% 32;
    try testing.expectEqual(@as(u32, 32), c.snd_nxt -% c.snd_una);
    c.fin_unacked = true;
    c.snd_nxt +%= 1;
    try testing.expectEqual(@as(u32, 33), c.snd_nxt -% c.snd_una);
    // ACK на 33 (данные+FIN) — adv == 33 > rtx_len(32) → FIN покрыт
    const ack2 = c.snd_una +% 33;
    try testing.expect((ack2 -% c.snd_una) > @as(u32, @intCast(c.rtx_len)));
}

test "net: rtx-бэкофф — экспоненциальный рост с потолком" {
    var rto: u32 = RTO_INITIAL_TICKS; // 20
    var steps: u8 = 0;
    while (steps < 10) : (steps += 1) {
        rto = @min(rto * 2, RTO_MAX_TICKS);
    }
    try testing.expectEqual(RTO_MAX_TICKS, rto); // упёрся в потолок 300
    try testing.expect(RTO_MAX_TICKS == 300);
    try testing.expect(RTO_INITIAL_TICKS == 20);
    // 20→40→80→160→320→cap: 5 шагов до потолка
    var rto2: u32 = RTO_INITIAL_TICKS;
    rto2 = @min(rto2 * 2, RTO_MAX_TICKS);
    try testing.expectEqual(@as(u32, 40), rto2);
    rto2 = @min(rto2 * 2, RTO_MAX_TICKS);
    try testing.expectEqual(@as(u32, 80), rto2);
}
