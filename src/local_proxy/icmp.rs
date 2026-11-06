//! ICMP echo через один RAW-сокет: запросы клиента переписываются
//! (identifier → уникальный proxy-id, ядро доставляет в raw-сокет все ICMP
//! хоста), ответы демультиплексируются по proxy-id и инжектируются как
//! цель→клиент с исходным identifier. Ошибки ICMP (type 3/11/12) не
//! транслируются — только echo.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::sync::mpsc;

use crate::{
    link_io::{Delivery, Event, Packet},
    packet::{FlowKey, internet_checksum},
};

/// Простой ping-потока до очистки слота: ping шлёт запросы ежесекундно.
pub const ICMP_IDLE: std::time::Duration = std::time::Duration::from_secs(30);

/// Слот ping-потока: proxy-id и время последнего запроса.
pub struct IcmpSlot {
    pub proxy_id: u16,
    pub seen: std::time::Instant,
}

/// Запрос в relay-задачу: ICMP-сообщение (без IP-заголовка) с уже
/// переписанным proxy-id, ядро строит заголовок само.
pub struct IcmpRequest {
    pub target: SocketAddr,
    pub icmp: Vec<u8>,
}

/// Свободный proxy-id: занятые не более `limits.icmp`, счётчик быстро
/// находит пропуск.
pub fn alloc_proxy_id(ids: &HashMap<u16, FlowKey>, next: &mut u16) -> Option<u16> {
    for _ in 0..=u16::MAX {
        *next = next.wrapping_add(1);
        if !ids.contains_key(next) {
            return Some(*next);
        }
    }
    None
}

/// Echo-запрос клиента → ICMP-сообщение с proxy-id и пересчитанной
/// контрольной суммой. `None` — не echo-запрос или короткий пакет.
pub fn rewrite_echo_request(bytes: &[u8], proxy_id: u16) -> Option<Vec<u8>> {
    if bytes.first().is_none_or(|first| first >> 4 != 4) {
        return None;
    }
    let header = usize::from(bytes[0] & 15) * 4;
    let icmp = bytes.get(header..)?;
    if icmp.len() < 8 || icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    let mut icmp = icmp.to_vec();
    icmp[2..4].copy_from_slice(&[0, 0]);
    icmp[4..6].copy_from_slice(&proxy_id.to_be_bytes());
    let sum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(icmp)
}

/// Ответ из WAN (полный IP-пакет) → proxy-id, либо `None` (не echo-reply,
/// мусор, чужой ICMP хоста).
pub fn reply_proxy_id(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 28 || bytes[0] >> 4 != 4 || bytes[9] != 1 {
        return None;
    }
    let header = usize::from(bytes[0] & 15) * 4;
    let icmp = bytes.get(header..)?;
    if icmp.len() < 8 || icmp[0] != 0 || icmp[1] != 0 {
        return None;
    }
    Some(u16::from_be_bytes([icmp[4], icmp[5]]))
}

/// Кадр цель→клиент: echo-reply с identifier клиента, seq и payload из
/// ответа WAN. Адреса из потока, а не из ответа (weak-host: ответ может
/// прийти с любого адреса хоста).
pub fn build_echo_reply(flow: &FlowKey, reply_icmp: &[u8]) -> Vec<u8> {
    let total = 20 + reply_icmp.len();
    let mut bytes = vec![0u8; total];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&flow.destination.octets());
    bytes[16..20].copy_from_slice(&flow.source.octets());
    bytes[20] = 0; // echo reply
    bytes[24..26].copy_from_slice(&flow.source_port.to_be_bytes());
    bytes[26..].copy_from_slice(&reply_icmp[6..]);
    let sum = internet_checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&sum.to_be_bytes());
    let ip_sum = internet_checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    bytes
}

/// Relay-задача: отправка переписанных запросов в WAN, приём всех ICMP
/// хоста и пересылка ответов владельцу proxy-loop (канал закрывается
/// вместе с ним).
pub async fn relay(
    socket: tokio::net::UdpSocket,
    mut requests: mpsc::Receiver<IcmpRequest>,
    replies: mpsc::Sender<Vec<u8>>,
    delivery: Arc<Delivery>,
) {
    let mut buffer = vec![0u8; 65535];
    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(request) = request else { break };
                if socket.send_to(&request.icmp, request.target).await.is_err() {
                    delivery.dropped();
                }
            }
            received = socket.recv_from(&mut buffer) => {
                match received {
                    Ok((length, _)) => {
                        if replies.try_send(buffer[..length].to_vec()).is_err() {
                            delivery.dropped();
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

/// Ответ из WAN: demux по proxy-id, кадр цель→клиент, событие с id потока.
/// `None`-ветви — ожидаемый шум (чужой ICMP хоста) — считаются дропом.
pub fn handle_reply(
    events: &mpsc::Sender<(crate::link_io::Epoch, Event)>,
    epoch: crate::link_io::Epoch,
    icmp: &mut HashMap<FlowKey, IcmpSlot>,
    icmp_ids: &mut HashMap<u16, FlowKey>,
    ids: &HashMap<FlowKey, u64>,
    delivery: &Delivery,
    bytes: &[u8],
) {
    let Some(proxy_id) = reply_proxy_id(bytes) else {
        delivery.dropped();
        return;
    };
    let Some(flow) = icmp_ids.get(&proxy_id).copied() else {
        delivery.dropped();
        return;
    };
    // Живой поток: ответ продлевает слот до следующего prune-тика.
    if let Some(slot) = icmp.get_mut(&flow) {
        slot.seen = std::time::Instant::now();
    }
    let Some(id) = ids.get(&flow).copied() else {
        delivery.dropped();
        return;
    };
    let header = usize::from(bytes[0] & 15) * 4;
    let frame = build_echo_reply(&flow, &bytes[header..]);
    if events
        .try_send((epoch, Event::Packet(Packet { id, bytes: frame })))
        .is_err()
    {
        delivery.dropped();
    }
}
