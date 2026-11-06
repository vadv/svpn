//! local-proxy (feature `local-proxy`): TCP-хендшейк и данные через
//! netstack-smoltcp, UDP-релей, admission-лимиты, SYN-дедуп и закрытие
//! потоков. Все тесты работают на loopback без TUN: пакеты клиента
//! подаются в канал `outgoing`, ответы читаются из канала `events`.

#![cfg(true)]

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use svpn::{
    link_io::{Epoch, Event, Packet},
    local_proxy::{Limits, LocalProxy, start_with},
    packet::{FlowKey, internet_checksum},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
const EPOCH: Epoch = Epoch {
    link: usize::MAX,
    generation: 1,
};

fn client(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(CLIENT_IP, port))
}

fn addr(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ip, port))
}

// ── фикстуры ──────────────────────────────────────────────────────────

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

fn v4(socket: SocketAddr) -> Ipv4Addr {
    match socket.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("IPv6 в фикстурах не бывает"),
    }
}

/// IPv4+TCP сегмент с корректными контрольными суммами.
fn tcp_segment(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let (src_ip, dst_ip) = (v4(src), v4(dst));
    let mut bytes = vec![0u8; 40 + payload.len()];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&src_ip.octets());
    bytes[16..20].copy_from_slice(&dst_ip.octets());
    bytes[20..22].copy_from_slice(&src.port().to_be_bytes());
    bytes[22..24].copy_from_slice(&dst.port().to_be_bytes());
    bytes[24..28].copy_from_slice(&seq.to_be_bytes());
    bytes[28..32].copy_from_slice(&ack.to_be_bytes());
    bytes[32] = 0x50; // data offset 5, без опций
    bytes[33] = flags;
    bytes[34..36].copy_from_slice(&0xffffu16.to_be_bytes());
    bytes[40..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + 20 + payload.len());
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&bytes[20..]);
    bytes[36..38].copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
    let ip_sum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    bytes
}

/// IPv4+UDP датаграмма.
fn udp_datagram(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (src_ip, dst_ip) = (v4(src), v4(dst));
    let length = 8 + payload.len();
    let mut bytes = vec![0u8; 20 + length];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((20 + length) as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&src_ip.octets());
    bytes[16..20].copy_from_slice(&dst_ip.octets());
    bytes[20..22].copy_from_slice(&src.port().to_be_bytes());
    bytes[22..24].copy_from_slice(&dst.port().to_be_bytes());
    bytes[24..26].copy_from_slice(&(length as u16).to_be_bytes());
    bytes[28..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + length);
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(length as u16).to_be_bytes());
    pseudo.extend_from_slice(&bytes[20..]);
    bytes[26..28].copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
    let ip_sum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    bytes
}

/// Разбор ответного TCP-сегмента: (flags, seq, ack, payload).
fn tcp_reply(bytes: &[u8]) -> (u8, u32, u32, &[u8]) {
    let flags = bytes[33];
    let seq = u32::from_be_bytes(bytes[24..28].try_into().unwrap());
    let ack = u32::from_be_bytes(bytes[28..32].try_into().unwrap());
    let offset = ((bytes[32] as usize) >> 4) * 4;
    (flags, seq, ack, &bytes[20 + offset..])
}

async fn spawn_tcp_echo() -> (tokio::task::JoinHandle<()>, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 1024];
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(length) => {
                    let _ = socket.write_all(&buffer[..length]).await;
                }
            }
        }
    });
    (task, port)
}

async fn spawn_udp_echo() -> (tokio::task::JoinHandle<()>, u16) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..length], peer).await;
        }
    });
    (task, port)
}

async fn ready_proxy() -> LocalProxy {
    let mut proxy = start_with(EPOCH, 1400, None, Limits::default())
        .await
        .unwrap();
    drain_ready(&mut proxy).await;
    proxy
}

/// Проглатывает первый Ready от свежего proxy.
async fn drain_ready(proxy: &mut LocalProxy) {
    let (_, event) = tokio::time::timeout(Duration::from_secs(2), proxy.events.recv())
        .await
        .expect("канал событий жив")
        .expect("Ready event");
    assert!(matches!(event, Event::Ready));
}

async fn start_with_ready(limits: Limits) -> LocalProxy {
    let mut proxy = start_with(EPOCH, 1400, None, limits).await.unwrap();
    drain_ready(&mut proxy).await;
    proxy
}

async fn send(proxy: &LocalProxy, id: u64, bytes: Vec<u8>) {
    proxy.outgoing.send(Packet { id, bytes }).await.unwrap();
}

/// Ждёт пакетное событие, удовлетворяющее предикату; остальные пропускает.
async fn expect_packet<F>(proxy: &mut LocalProxy, predicate: F) -> (u64, Vec<u8>)
where
    F: Fn(&(u64, Vec<u8>)) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let event = tokio::time::timeout_at(deadline, proxy.events.recv())
            .await
            .expect("timeout: нет подходящего пакета");
        match event {
            Some((_, Event::Packet(packet))) => {
                if predicate(&(packet.id, packet.bytes.clone())) {
                    return (packet.id, packet.bytes);
                }
            }
            Some((
                _,
                Event::Closed { .. } | Event::Ready | Event::Checking | Event::RoundFailed,
            )) => {}
            None => panic!("канал событий proxy закрылся"),
        }
    }
}

async fn expect_closed(proxy: &mut LocalProxy) -> (u64, FlowKey) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let event = tokio::time::timeout_at(deadline, proxy.events.recv())
            .await
            .expect("timeout: нет Closed");
        match event {
            Some((_, Event::Closed { id, key })) => return (id, key),
            Some((_, Event::Packet(_))) => {}
            Some((_, Event::Ready | Event::Checking | Event::RoundFailed)) => {}
            None => panic!("канал событий proxy закрылся"),
        }
    }
}

/// Ждёт отсутствия событий (проверки дропов).
async fn expect_silence(proxy: &mut LocalProxy, ms: u64) {
    match tokio::time::timeout(Duration::from_millis(ms), proxy.events.recv()).await {
        Ok(Some((_, event))) => panic!("неожidaнное событие: {event:?}"),
        Ok(None) => panic!("канал событий proxy закрылся"),
        Err(_) => {}
    }
}

async fn wait_stat<F>(proxy: &LocalProxy, predicate: F)
where
    F: Fn(&svpn::control::Stats) -> bool,
{
    let mut latest = proxy.latest.clone();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if predicate(&latest.borrow()) {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timeout на статистике: {:?}", latest.borrow());
        }
        tokio::time::timeout_at(deadline, latest.changed())
            .await
            .expect("stats watch жив")
            .unwrap();
    }
}

// ── TCP ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn tcp_handshake_data_close() {
    let (echo, echo_port) = spawn_tcp_echo().await;
    let mut proxy = ready_proxy().await;
    let source = client(40000);
    let destination = addr(Ipv4Addr::LOCALHOST, echo_port);

    send(
        &proxy,
        7,
        tcp_segment(source, destination, 1000, 0, SYN, b""),
    )
    .await;
    let (id, syn_ack) = expect_packet(&mut proxy, |(id, _)| *id == 7).await;
    assert_eq!(id, 7);
    let (flags, server_seq, ack, _) = tcp_reply(&syn_ack);
    assert_eq!(flags & SYN, SYN, "flags: {flags:08b}");
    assert_eq!(flags & ACK, ACK, "flags: {flags:08b}");
    assert_eq!(ack, 1001);

    send(
        &proxy,
        7,
        tcp_segment(source, destination, 1001, server_seq + 1, ACK, b""),
    )
    .await;
    send(
        &proxy,
        7,
        tcp_segment(
            source,
            destination,
            1001,
            server_seq + 1,
            PSH | ACK,
            b"ping",
        ),
    )
    .await;
    let (_, data) = expect_packet(&mut proxy, |(id, bytes)| {
        *id == 7 && tcp_reply(bytes).0 & PSH != 0
    })
    .await;
    let (flags, _, ack, payload) = tcp_reply(&data);
    assert_eq!(flags & PSH, PSH, "flags: {flags:08b}");
    assert_eq!(ack, 1005);
    assert_eq!(payload, b"ping");

    // FIN от клиента → релей доносит half-close → echo-сервер видит EOF →
    // закрывается → proxy шлёт свой FIN. Клиент ACK-ает его (реальный стек
    // делает это сам), после чего сокет в стеке закрывается → Closed.
    send(
        &proxy,
        7,
        tcp_segment(source, destination, 1005, server_seq + 5, FIN | ACK, b""),
    )
    .await;
    let (_, fin) = expect_packet(&mut proxy, |(_, bytes)| {
        tcp_reply(bytes).0 & FIN != 0 && tcp_reply(bytes).0 & SYN == 0
    })
    .await;
    let (_, fin_seq, _, _) = tcp_reply(&fin);
    send(
        &proxy,
        7,
        tcp_segment(source, destination, 1006, fin_seq + 1, ACK, b""),
    )
    .await;
    let (closed_id, key) = expect_closed(&mut proxy).await;
    assert_eq!(closed_id, 7);
    assert_eq!(key.protocol, 6);
    assert_eq!(key.source, CLIENT_IP);
    assert_eq!(key.source_port, 40000);
    assert_eq!(key.destination, Ipv4Addr::LOCALHOST);
    assert_eq!(key.destination_port, echo_port);
    echo.await.unwrap();
}

#[tokio::test]
async fn tcp_connect_refused_resets_and_closes() {
    // Свободный порт: bind + drop.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut proxy = ready_proxy().await;
    let source = client(41000);
    let destination = addr(Ipv4Addr::LOCALHOST, port);
    send(
        &proxy,
        9,
        tcp_segment(source, destination, 2000, 0, SYN, b""),
    )
    .await;
    // SYN-ACK стек выпускает до accept; после ACK клиента accept отдаёт
    // поток, connect в refused-порт падает.
    let (_, syn_ack) = expect_packet(&mut proxy, |(_, _)| true).await;
    let (_, server_seq, _, _) = tcp_reply(&syn_ack);
    send(
        &proxy,
        9,
        tcp_segment(source, destination, 2001, server_seq + 1, ACK, b""),
    )
    .await;
    // До Closed клиент получает RST (0x04) — иначе он завис бы на
    // полуоткрытом сокете после SYN-ACK.
    let (_, rst) = expect_packet(&mut proxy, |(_, _)| true).await;
    let (flags, _, _, _) = tcp_reply(&rst);
    assert_eq!(flags & 0x04, 0x04, "ожидался RST, flags: {flags:08b}");
    let (closed_id, key) = expect_closed(&mut proxy).await;
    assert_eq!(closed_id, 9);
    assert_eq!(key.destination_port, port);
}

#[tokio::test]
async fn tcp_syn_retransmit_deduplicated() {
    let (echo, echo_port) = spawn_tcp_echo().await;
    let mut proxy = ready_proxy().await;
    let source = client(42000);
    let destination = addr(Ipv4Addr::LOCALHOST, echo_port);
    let syn = tcp_segment(source, destination, 3000, 0, SYN, b"");
    send(&proxy, 11, syn.clone()).await;
    let _ = expect_packet(&mut proxy, |(id, _)| *id == 11).await;
    // Ретрансмиссия SYN того же кортежа дропается до стека.
    send(&proxy, 11, syn).await;
    expect_silence(&mut proxy, 300).await;
    echo.abort();
}

#[tokio::test]
async fn tcp_admission_limit_drops_syn() {
    let (echo, echo_port) = spawn_tcp_echo().await;
    let mut proxy = start_with_ready(Limits {
        tcp: 0,
        ..Limits::default()
    })
    .await;
    let source = client(43000);
    let destination = addr(Ipv4Addr::LOCALHOST, echo_port);
    send(
        &proxy,
        13,
        tcp_segment(source, destination, 4000, 0, SYN, b""),
    )
    .await;
    // Admission-отказ уже-владеемого Hub потока: SYN-ACK нет, но поток
    // закрывается событием Closed (иначе route в Hub утёк бы навсегда).
    let (closed_id, key) = expect_closed(&mut proxy).await;
    assert_eq!(closed_id, 13);
    assert_eq!(key.destination_port, echo_port);
    wait_stat(&proxy, |stats| stats.open_failed_flows >= 1).await;
    echo.abort();
}

// ── UDP ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn udp_reply_from_foreign_source() {
    // Regression (e2e sticky-asn, CI run 42192114357): цель ответила с
    // другого адреса хоста (weak-host: primary вместо целевого) —
    // connected-сокет ядро молча дропал, клиент получал timeout.
    // Linux отдаёт весь 127/8, macOS — только 127.0.0.1, поэтому там
    // чужой source моделируется другим портом того же адреса.
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_port = receiver.local_addr().unwrap().port();
    let foreign_addr = if cfg!(target_os = "linux") {
        "127.0.0.2:0"
    } else {
        "127.0.0.1:0"
    };
    let foreign = tokio::net::UdpSocket::bind(foreign_addr).await.unwrap();
    let echo = tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        while let Ok((length, peer)) = receiver.recv_from(&mut buffer).await {
            let _ = foreign.send_to(&buffer[..length], peer).await;
        }
    });
    let mut proxy = start_with_ready(Limits::default()).await;
    let source = client(46000);
    let destination = addr(Ipv4Addr::LOCALHOST, target_port);

    send(&proxy, 41, udp_datagram(source, destination, b"weak-host")).await;
    let (_, reply) = expect_packet(&mut proxy, |(_, bytes)| bytes.len() == 28 + 9).await;
    assert_eq!(
        &reply[12..16],
        &Ipv4Addr::LOCALHOST.octets(),
        "src = цель, а не фактический отправитель"
    );
    assert_eq!(&reply[28..], b"weak-host");
    echo.abort();
}

#[tokio::test]
async fn udp_empty_reply_reaches_client() {
    // Regression: netstack-smoltcp 0.2.5 глотал пустую UDP-датаграмму
    // (0 байт payload) в WriteHalf::start_send — нулевой ответ цели терялся.
    // Форк vadv/netstack-smoltcp строит заголовки с пустым payload.
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = receiver.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        while let Ok((_, peer)) = receiver.recv_from(&mut buffer).await {
            let _ = receiver.send_to(&[], peer).await;
        }
    });
    let mut proxy = start_with_ready(Limits::default()).await;
    let source = client(48000);
    let destination = addr(Ipv4Addr::LOCALHOST, port);

    send(&proxy, 51, udp_datagram(source, destination, b"ping")).await;
    let (_, reply) =
        expect_packet(&mut proxy, |(_, bytes)| bytes.len() == 28 && bytes[9] == 17).await;
    assert_eq!(&reply[12..16], &Ipv4Addr::LOCALHOST.octets(), "src = цель");
    echo.abort();
}

#[tokio::test]
async fn udp_roundtrip_and_idle_close() {
    let (echo, echo_port) = spawn_udp_echo().await;
    let mut proxy = start_with_ready(Limits {
        udp_idle: Duration::from_millis(150),
        ..Limits::default()
    })
    .await;
    let source = client(44000);
    let destination = addr(Ipv4Addr::LOCALHOST, echo_port);

    send(&proxy, 21, udp_datagram(source, destination, b"hello")).await;
    let (id, reply) = expect_packet(&mut proxy, |(id, bytes)| {
        *id == 21 && bytes.len() == 28 + 5 && bytes[9] == 17
    })
    .await;
    assert_eq!(id, 21);
    assert_eq!(&reply[12..16], &Ipv4Addr::LOCALHOST.octets(), "src = цель");
    assert_eq!(&reply[16..20], &CLIENT_IP.octets(), "dst = клиент");
    assert_eq!(&reply[28..], b"hello");

    // Повторный датаграмм того же кортежа — тот же поток.
    send(&proxy, 21, udp_datagram(source, destination, b"again")).await;
    let (_, reply) = expect_packet(&mut proxy, |(_, bytes)| bytes.len() == 28 + 5).await;
    assert_eq!(&reply[28..], b"again");
    wait_stat(&proxy, |stats| stats.opened_flows == 1).await;

    // Простой закрывает поток.
    let (closed_id, key) = expect_closed(&mut proxy).await;
    assert_eq!(closed_id, 21);
    assert_eq!(key.protocol, 17);
    assert_eq!(key.source_port, 44000);
    assert_eq!(key.destination_port, echo_port);
    echo.abort();
}

#[tokio::test]
async fn udp_admission_limit_drops_datagram() {
    // Первый UDP-«сервер» просто держит порт (не отвечает): поток жив.
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buffer = [0u8; 1500];
        loop {
            let _ = sink.recv_from(&mut buffer).await;
        }
    });
    let black_hole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let black_hole_port = black_hole.local_addr().unwrap().port();
    let _ = black_hole;

    let mut proxy = start_with_ready(Limits {
        udp: 1,
        ..Limits::default()
    })
    .await;
    let source = client(45000);
    let one = addr(Ipv4Addr::LOCALHOST, sink_port);
    let two = addr(Ipv4Addr::LOCALHOST, black_hole_port);
    send(&proxy, 31, udp_datagram(source, one, b"x")).await;
    // Второй кортеж — отказ admission: поток уже владеется Hub, поэтому
    // закрывается событием Closed, а не молчаливым дропом.
    send(&proxy, 32, udp_datagram(source, two, b"y")).await;
    let (closed_id, key) = expect_closed(&mut proxy).await;
    assert_eq!(closed_id, 32);
    assert_eq!(key.destination_port, black_hole_port);
    wait_stat(&proxy, |stats| stats.open_failed_flows >= 1).await;
}

// ── ICMP ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn icmp_dropped_without_events() {
    let mut proxy = ready_proxy().await;
    let mut echo_request = vec![0u8; 28];
    echo_request[0] = 0x45;
    echo_request[2..4].copy_from_slice(&28u16.to_be_bytes());
    echo_request[9] = 1;
    echo_request[12..16].copy_from_slice(&CLIENT_IP.octets());
    echo_request[16..20].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
    echo_request[20] = 8; // echo request
    send(&proxy, 41, echo_request).await;
    expect_silence(&mut proxy, 300).await;
}

// ── WAN-парсер ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn parse_route_table_prefers_default_lowest_metric() {
    // Regression: старый код читал колонку Gateway вместо Destination
    // (fields.nth(1)), из-за чего default-маршрут с ненулевым gateway
    // пропускался и WAN-интерфейс не находился вовсе.
    use svpn::local_proxy::egress::parse_route_table;
    let table = "\
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0
wlan0 00000000 FE01A8C0 0003 0 0 50 00000000 0 0 0
tun0 00000000 00000000 0003 0 0 0 00000000 0 0 0
eth0 0001A8C0 00000000 0001 0 0 0 00FFFFFF 0 0 0
";
    assert_eq!(parse_route_table(table, "tun0").as_deref(), Some("wlan0"));
}
