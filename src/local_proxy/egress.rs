//! Egress в WAN: определение интерфейса по умолчанию и привязка сокетов
//! `SO_BINDTODEVICE`, чтобы исходящие потоки не заворачивались обратно в TUN
//! (маршруты /1 перекрывают default и без привязки съели бы весь трафик).

use std::{io, net::SocketAddr, time::Duration};

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
#[cfg(not(target_os = "linux"))]
use anyhow::bail;

/// Парсинг `/proc/net/route`: интерфейс default-маршрута с минимальной
/// метрикой, кроме `skip` (TUN) и loopback. Колонки (hex): Iface Destination
/// Gateway Flags RefCnt Use Metric …
#[cfg(target_os = "linux")]
pub fn parse_route_table(text: &str, skip: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(iface), Some(destination), Some(metric)) =
            (fields.next(), fields.nth(1), fields.nth(3))
        else {
            continue;
        };
        if destination != "00000000" || iface == skip || iface == "lo" {
            continue;
        }
        let Ok(metric) = u32::from_str_radix(metric, 16) else {
            continue;
        };
        if best.as_ref().is_none_or(|(current, _)| metric < *current) {
            best = Some((metric, iface.to_owned()));
        }
    }
    best.map(|(_, iface)| iface)
}

#[cfg(target_os = "linux")]
pub fn wan_device(tun: &str) -> Result<String> {
    let table = std::fs::read_to_string("/proc/net/route").context("read /proc/net/route")?;
    parse_route_table(&table, tun).with_context(|| {
        format!("no default route outside {tun} in /proc/net/route — WAN egress unknown")
    })
}

#[cfg(not(target_os = "linux"))]
pub fn wan_device(_tun: &str) -> Result<String> {
    bail!("local-proxy WAN detection requires Linux (/proc/net/route)")
}

fn bound_socket(
    domain: socket2::Domain,
    kind: socket2::Type,
    device: Option<&str>,
) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(domain, kind, None)?;
    // Привязка к устройству существует только на Linux; вне Linux (тесты на
    // host) device всегда None.
    #[cfg(target_os = "linux")]
    if let Some(device) = device {
        // Без CAP_NET_RAW привязка к устройству запрещена; svpn на роутере
        // и так работает с TUN от root.
        socket.bind_device(Some(device.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = device;
    Ok(socket)
}

/// Исходящий TCP: привязка к WAN, keep-alive, connect с дедлайном.
pub async fn tcp_connect(
    device: Option<&str>,
    target: SocketAddr,
    timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    let socket = bound_socket(
        socket2::Domain::for_address(target),
        socket2::Type::STREAM,
        device,
    )?;
    socket.set_keepalive(true)?;
    socket.set_nonblocking(true)?;
    let stream: std::net::TcpStream = socket.into();
    let socket = tokio::net::TcpSocket::from_std_stream(stream);
    match tokio::time::timeout(timeout, socket.connect(target)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connect {target} timed out"),
        )),
    }
}

/// Исходящий UDP: один unconnected-сокет на поток. Цель может ответить
/// с другого адреса (weak-host: основной адрес интерфейса), connected-сокет
/// такое ядро отбрасывает молча; демультиплексация — по локальному порту.
pub fn udp_socket(device: Option<&str>, target: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let socket = bound_socket(
        socket2::Domain::for_address(target),
        socket2::Type::DGRAM,
        device,
    )?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = tokio::net::UdpSocket::from_std(std_socket)?;
    Ok(socket)
}
