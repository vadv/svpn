//! Linux local exit через TCP/UDP/ICMP-echo proxy: userspace-стек
//! netstack-smoltcp терминирует потоки клиента, Tokio-сокеты с
//! `SO_BINDTODEVICE` выносят их в WAN-интерфейс. Замена second-TUN local
//! serve за фичей `local-proxy`.
//!
//! Интеграция с Hub сохраняет контракт `local_exit`: канал исходящих
//! `Packet{id, bytes}` внутрь, события `(Epoch, Event)` наружу. Hub работает
//! с пакетами в терминах primary-клиента без трансляции (identity), поэтому
//! `open_local`/`handle_local_event` не меняются.
//!
//! shortcut: повторный SYN существующего потока дропается до стека (upstream
//! netstack-smoltcp аллоцирует сокет и 4 буфера на каждый SYN), из-за чего
//! ретрансмиссия SYN-ACK невозможна — потеря SYN-ACK роняет одну попытку
//! коннекта; пересмотреть после апстрим-фикса или форка.

mod egress;
pub mod icmp;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{Stack, StackBuilder};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::Interval,
};

use crate::{
    control::Stats,
    link_io::{Delivery, Epoch, Event, Packet},
    packet::{self, FlowKey},
};

/// Владелец фоновой задачи: graceful shutdown с дедлайном, abort при Drop.
pub struct LocalServer {
    task: JoinHandle<Result<()>>,
}

impl LocalServer {
    pub fn new(task: JoinHandle<Result<()>>) -> Self {
        Self { task }
    }

    pub fn abort(&self) {
        self.task.abort();
    }

    pub async fn join(&mut self) -> Result<()> {
        match (&mut self.task).await {
            Ok(result) => result,
            Err(error) => bail!("local task: {error}"),
        }
    }

    pub async fn shutdown(mut self) -> Result<()> {
        match tokio::time::timeout(
            crate::hooks::DEADLINE + crate::session::HEARTBEAT_TIMEOUT,
            self.join(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                self.abort();
                bail!("local task shutdown timeout")
            }
        }
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Память на TCP-поток = 4 × буфер (SocketBuffer recv/send + RingBuffer
/// recv/send внутри адаптера). 64 KiB → 256 KiB на поток, 512 потоков ≈ 128 MiB.
const TCP_BUFFER: u32 = 64 * 1024;
/// Окно ретрансмиссий SYN клиента (Linux tcp_syn_retries=6 ≈ 127 s).
const SYN_TTL: Duration = Duration::from_secs(120);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE: Duration = Duration::from_secs(60);
const STATS_INTERVAL: Duration = Duration::from_secs(1);
/// Ответ из WAN больше MTU TUN не фрагментируется (smoltcp не фрагментирует
/// TX) и будет дропнут на записи в TUN — буфер покрывает любой датаграмм.
const UDP_BUFFER: usize = 65535;

/// Пределы аллокации до создания потоков; превышение дропается со счётчиком.
#[derive(Clone, Copy)]
pub struct Limits {
    pub tcp: usize,
    pub udp: usize,
    /// Одновременные ping-потоки (echo request).
    pub icmp: usize,
    /// Простой UDP-потока до закрытия (тесты ужимают).
    pub udp_idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            tcp: 512,
            udp: 512,
            icmp: 256,
            udp_idle: UDP_IDLE,
        }
    }
}

/// Владелец proxy-задачи со стороны Hub: зеркально полям `local_exit::LocalExit`.
pub struct LocalProxy {
    pub outgoing: mpsc::Sender<Packet>,
    pub events: mpsc::Receiver<(Epoch, Event)>,
    pub latest: watch::Receiver<Stats>,
    pub delivery: Arc<Delivery>,
    pub server: LocalServer,
}

/// Продакшн-вход: автоопределение WAN-интерфейса (Linux), лимиты по умолчанию.
pub async fn start(epoch: Epoch, tun: &str, mtu: u16) -> Result<LocalProxy> {
    let device = egress::wan_device(tun)?;
    crate::info!("local-proxy: egress via {device} (tun {tun}, mtu {mtu})");
    start_with(epoch, mtu, Some(device), Limits::default()).await
}

/// Тестовый/явный вход: `device = None` отключает привязку (loopback-тесты).
pub async fn start_with(
    epoch: Epoch,
    mtu: u16,
    device: Option<String>,
    limits: Limits,
) -> Result<LocalProxy> {
    if !(576..=1400).contains(&mtu) {
        bail!("local-proxy MTU must be between 576 and 1400, got {mtu}");
    }
    let (stack, runner, udp_socket, listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(mtu as usize)
        .tcp_recv_buffer_size(TCP_BUFFER)
        .tcp_send_buffer_size(TCP_BUFFER)
        .build()
        .context("netstack-smoltcp build")?;
    let (Some(runner), Some(udp_socket), Some(listener)) = (runner, udp_socket, listener) else {
        bail!("netstack-smoltcp without runner, UDP or TCP");
    };

    let (outgoing_tx, outgoing_rx) = mpsc::channel(crate::hub::QUEUE);
    let (events_tx, events_rx) = mpsc::channel(crate::hub::QUEUE);
    let (stats_tx, latest) = watch::channel(Stats::default());
    let delivery = Arc::new(Delivery::default());
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    // RAW ICMP — только с WAN-устройством (продакшн); тестовый вход без
    // device дропает echo предсказуемо.
    let icmp_socket = device
        .as_ref()
        .and_then(|device| match egress::icmp_socket(Some(device)) {
            Ok(socket) => Some(socket),
            Err(error) => {
                crate::warn!("local-proxy: ICMP echo unavailable — {error}");
                None
            }
        });

    let task = tokio::spawn(run_proxy(
        ProxyArgs {
            epoch,
            device,
            limits,
        },
        stack,
        runner,
        udp_socket,
        listener,
        icmp_socket,
        outgoing_rx,
        events_tx,
        stats_tx,
        delivery.clone(),
        shutdown_tx,
    ));
    Ok(LocalProxy {
        outgoing: outgoing_tx,
        events: events_rx,
        latest,
        delivery,
        server: LocalServer::new(task),
    })
}

struct ProxyArgs {
    epoch: Epoch,
    device: Option<String>,
    limits: Limits,
}

/// Сообщение от per-flow задач владельцу: поток завершился.
enum FlowMsg {
    Closed(FlowKey),
}

/// Ключ UDP-потока — пара адресов клиент→цель.
type UdpKey = (SocketAddr, SocketAddr);

struct State {
    /// FlowKey → последний Hub id: для `Event::Packet`/`Closed` обратно.
    ids: HashMap<FlowKey, u64>,
    /// Принятые TCP-потоки: защищает их `ids` от prune по SYN_TTL.
    established: HashSet<FlowKey>,
    /// SYN-дедуп и admission: ключи не старше SYN_TTL.
    syns: HashMap<FlowKey, std::time::Instant>,
    udp: HashMap<UdpKey, mpsc::Sender<Vec<u8>>>,
    /// Ping-потоки: flow (identifier клиента в `source_port`) → слот.
    icmp: HashMap<FlowKey, icmp::IcmpSlot>,
    icmp_ids: HashMap<u16, FlowKey>,
    icmp_next: u16,
    stats: Stats,
}

impl State {
    fn prune_syns(&mut self) {
        let now = std::time::Instant::now();
        let expired: Vec<FlowKey> = self
            .syns
            .iter()
            .filter(|(_, seen)| now.duration_since(**seen) >= SYN_TTL)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.syns.remove(&key);
            // Незавершённый хендшейк: его id больше не нужен; принятые
            // потоки чистятся только по Closed.
            if !self.established.contains(&key) {
                self.ids.remove(&key);
            }
        }
    }

    /// Закрытие простаивающих ping-потоков: слоты, proxy-id и события Closed.
    fn prune_icmp(&mut self) -> Vec<(u64, FlowKey)> {
        let now = std::time::Instant::now();
        let expired: Vec<FlowKey> = self
            .icmp
            .iter()
            .filter(|(_, slot)| now.duration_since(slot.seen) >= icmp::ICMP_IDLE)
            .map(|(key, _)| *key)
            .collect();
        let mut closed = Vec::new();
        for key in expired {
            if let Some(slot) = self.icmp.remove(&key) {
                self.icmp_ids.remove(&slot.proxy_id);
            }
            if let Some(id) = self.ids.remove(&key) {
                self.stats.closed_flows += 1;
                closed.push((id, key));
            }
        }
        closed
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_proxy(
    args: ProxyArgs,
    stack: Stack,
    runner: netstack_smoltcp::Runner,
    udp_socket: netstack_smoltcp::UdpSocket,
    listener: netstack_smoltcp::TcpListener,
    icmp_socket: Option<tokio::net::UdpSocket>,
    mut outgoing: mpsc::Receiver<Packet>,
    events: mpsc::Sender<(Epoch, Event)>,
    stats: watch::Sender<Stats>,
    delivery: Arc<Delivery>,
    shutdown: watch::Sender<bool>,
) -> Result<()> {
    let ProxyArgs {
        epoch,
        device,
        limits,
    } = args;
    let _ = events.send((epoch, Event::Ready)).await;

    let (udp_read, udp_write) = udp_socket.split();
    tokio::pin!(udp_read, listener);
    // split() возвращает (sink, stream): sink — пакеты в стек,
    // stream — кадры из стека наружу.
    let (stack_in, stack_out) = stack.split();
    tokio::pin!(stack_out, stack_in);

    let mut runner_task = tokio::spawn(runner);
    let (inject_tx, mut inject_rx) =
        mpsc::channel::<(Vec<u8>, SocketAddr, SocketAddr)>(crate::hub::QUEUE);
    let injector = tokio::spawn(async move {
        let mut udp_write = udp_write;
        while let Some(message) = inject_rx.recv().await {
            if udp_write.send(message).await.is_err() {
                break;
            }
        }
    });

    let (flows_tx, mut flows_rx) = mpsc::channel::<FlowMsg>(crate::hub::QUEUE);
    let (icmp_tx, icmp_rx) = mpsc::channel::<icmp::IcmpRequest>(crate::hub::QUEUE);
    let (icmp_replies_tx, mut icmp_replies_rx) = mpsc::channel::<Vec<u8>>(crate::hub::QUEUE);
    let icmp_relay = icmp_socket.map(|socket| {
        let delivery = delivery.clone();
        let replies = icmp_replies_tx.clone();
        tokio::spawn(async move { icmp::relay(socket, icmp_rx, replies, delivery).await })
    });
    let mut state = State {
        ids: HashMap::new(),
        established: HashSet::new(),
        syns: HashMap::new(),
        udp: HashMap::new(),
        icmp: HashMap::new(),
        icmp_ids: HashMap::new(),
        icmp_next: 0,
        stats: Stats::default(),
    };
    let mut timer = tokio::time::interval(STATS_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut proxy = Proxy {
        epoch,
        device,
        limits,
        events: &events,
        delivery: &delivery,
        stats: &stats,
        state: &mut state,
        flows: &flows_tx,
        inject: &inject_tx,
        icmp: icmp_relay.is_some().then_some(icmp_tx),
        shutdown: &shutdown,
    };
    let result = proxy_loop(
        &mut proxy,
        &mut outgoing,
        &mut stack_in,
        &mut stack_out,
        &mut udp_read,
        &mut listener,
        &mut icmp_replies_rx,
        &mut flows_rx,
        &mut runner_task,
        &mut timer,
    )
    .await;

    // Разбор: погасить per-flow задачи, инжектор и стек.
    let _ = shutdown.send_replace(true);
    injector.abort();
    let _ = injector.await;
    if let Some(relay) = icmp_relay {
        relay.abort();
        let _ = relay.await;
    }
    runner_task.abort();
    let _ = runner_task.await;
    let mut snapshot = proxy.state.stats.clone();
    delivery.apply(&mut snapshot);
    snapshot.active_flows = proxy.state.ids.len();
    let _ = stats.send(snapshot);
    result
}

struct Proxy<'a> {
    epoch: Epoch,
    device: Option<String>,
    limits: Limits,
    events: &'a mpsc::Sender<(Epoch, Event)>,
    delivery: &'a Arc<Delivery>,
    stats: &'a watch::Sender<Stats>,
    state: &'a mut State,
    flows: &'a mpsc::Sender<FlowMsg>,
    inject: &'a mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    /// Канал ping-запросов в relay-задачу; None — без WAN (ICMP дропается).
    icmp: Option<mpsc::Sender<icmp::IcmpRequest>>,
    shutdown: &'a watch::Sender<bool>,
}

#[allow(clippy::too_many_arguments)]
async fn proxy_loop(
    proxy: &mut Proxy<'_>,
    outgoing: &mut mpsc::Receiver<Packet>,
    stack_in: &mut futures::stream::SplitSink<Stack, Vec<u8>>,
    stack_out: &mut futures::stream::SplitStream<Stack>,
    udp_read: &mut (impl futures::Stream<Item = (Vec<u8>, SocketAddr, SocketAddr)> + Unpin),
    listener: &mut netstack_smoltcp::TcpListener,
    icmp_replies: &mut mpsc::Receiver<Vec<u8>>,
    flows: &mut mpsc::Receiver<FlowMsg>,
    runner_task: &mut JoinHandle<std::io::Result<()>>,
    timer: &mut Interval,
) -> Result<()> {
    loop {
        tokio::select! {
            packet = outgoing.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                pump(proxy, stack_in, packet).await;
            }
            frame = stack_out.next() => {
                let Some(frame) = frame else {
                    bail!("netstack-smoltcp stream ended");
                };
                emit(proxy, frame?);
            }
            datagram = udp_read.next() => {
                let Some(datagram) = datagram else {
                    bail!("netstack-smoltcp UDP stream ended");
                };
                relay_udp(proxy, datagram);
            }
            accepted = listener.next() => {
                let Some((stream, client, target)) = accepted else {
                    bail!("netstack-smoltcp TCP listener ended");
                };
                // Хендшейк завершён: SYN-слот свободен, id защищён от prune.
                let key = flow_key(client, target, 6);
                proxy.state.syns.remove(&key);
                proxy.state.established.insert(key);
                relay_tcp(proxy, stream, client, target);
            }
            message = flows.recv() => {
                let Some(FlowMsg::Closed(key)) = message else {
                    bail!("flow channel closed");
                };
                if let Some(id) = proxy.state.ids.remove(&key) {
                    proxy.state.stats.closed_flows += 1;
                    let _ = proxy
                        .events
                        .try_send((proxy.epoch, Event::Closed { id, key }));
                }
                proxy.state.syns.remove(&key);
                proxy.state.established.remove(&key);
                if key.protocol == 17 {
                    proxy
                        .state
                        .udp
                        .remove(&(addr_of(&key, true), addr_of(&key, false)));
                }
            }
            reply = icmp_replies.recv(), if proxy.icmp.is_some() => {
                let Some(reply) = reply else {
                    bail!("icmp relay ended");
                };
                icmp::handle_reply(
                    proxy.events,
                    proxy.epoch,
                    &mut proxy.state.icmp,
                    &mut proxy.state.icmp_ids,
                    &proxy.state.ids,
                    proxy.delivery,
                    &reply,
                );
            }
            _ = timer.tick() => {
                proxy.state.prune_syns();
                for (id, key) in proxy.state.prune_icmp() {
                    let _ = proxy.events.try_send((proxy.epoch, Event::Closed { id, key }));
                }
                // rx-счётчики и дропы берём из Delivery: Hub пишет их на
                // каждой удачной записи в клиентский TUN.
                let mut snapshot = proxy.state.stats.clone();
                proxy.delivery.apply(&mut snapshot);
                snapshot.active_flows = proxy.state.ids.len();
                let _ = proxy.stats.send(snapshot);
            }
            result = &mut *runner_task => match result {
                Ok(Ok(())) => bail!("netstack-smoltcp runner exited"),
                Ok(Err(error)) => bail!("netstack-smoltcp runner: {error}"),
                Err(error) => bail!("netstack-smoltcp runner task: {error}"),
            },
        }
    }
}

/// Hub → стек: дедуп SYN, admission, учёт id.
async fn pump(
    proxy: &mut Proxy<'_>,
    stack_in: &mut futures::stream::SplitSink<Stack, Vec<u8>>,
    packet: Packet,
) {
    let Some(parsed) = packet::parse(&packet.bytes, true) else {
        proxy.delivery.dropped();
        return;
    };
    match parsed.flow.protocol {
        6 => {
            if parsed.can_open {
                if proxy.state.syns.contains_key(&parsed.flow) {
                    proxy.delivery.dropped();
                    return;
                }
                if proxy.state.syns.len() >= proxy.limits.tcp {
                    proxy.state.stats.open_failed_flows += 1;
                    proxy.delivery.dropped();
                    return;
                }
                proxy
                    .state
                    .syns
                    .insert(parsed.flow, std::time::Instant::now());
                proxy.state.stats.opened_flows += 1;
            }
            proxy.state.ids.insert(parsed.flow, packet.id);
        }
        17 => {
            proxy.state.ids.insert(parsed.flow, packet.id);
        }
        // Echo request: переписать identifier на proxy-id и отправить в WAN
        // через raw-сокет; ответы возвращаются icmp::handle_reply.
        1 => {
            let Some(sender) = proxy.icmp.as_ref() else {
                proxy.delivery.dropped();
                return;
            };
            if !parsed.can_open {
                proxy.delivery.dropped();
                return;
            }
            let flow = parsed.flow;
            match proxy.state.icmp.get_mut(&flow) {
                Some(slot) => slot.seen = std::time::Instant::now(),
                None => {
                    if proxy.state.icmp.len() >= proxy.limits.icmp {
                        proxy.state.stats.open_failed_flows += 1;
                        proxy.delivery.dropped();
                        return;
                    }
                    let Some(proxy_id) =
                        icmp::alloc_proxy_id(&proxy.state.icmp_ids, &mut proxy.state.icmp_next)
                    else {
                        proxy.state.stats.open_failed_flows += 1;
                        proxy.delivery.dropped();
                        return;
                    };
                    proxy.state.icmp.insert(
                        flow,
                        icmp::IcmpSlot {
                            proxy_id,
                            seen: std::time::Instant::now(),
                        },
                    );
                    proxy.state.icmp_ids.insert(proxy_id, flow);
                    proxy.state.stats.opened_flows += 1;
                }
            }
            proxy.state.ids.insert(flow, packet.id);
            let Some(proxy_id) = proxy.state.icmp.get(&flow).map(|slot| slot.proxy_id) else {
                proxy.delivery.dropped();
                return;
            };
            let Some(request) = icmp::rewrite_echo_request(&packet.bytes, proxy_id) else {
                proxy.delivery.dropped();
                return;
            };
            let target = SocketAddr::new(IpAddr::V4(flow.destination), 0);
            match sender.try_send(icmp::IcmpRequest {
                target,
                icmp: request,
            }) {
                Ok(()) => proxy.state.stats.inner_tx_packets += 1,
                Err(_) => proxy.delivery.dropped(),
            }
            return; // в стек ICMP не идёт
        }
        // Неизвестный протокол: дроп со счётчиком.
        _ => {
            proxy.delivery.dropped();
            return;
        }
    }
    if stack_in.send(packet.bytes).await.is_err() {
        proxy.delivery.dropped();
        return;
    }
    proxy.state.stats.inner_tx_packets += 1;
}

/// Стек → Hub: пакет потока с известным id, иначе дроп.
fn emit(proxy: &mut Proxy<'_>, frame: Vec<u8>) {
    let Some(parsed) = packet::parse(&frame, false) else {
        crate::debug!(
            "local-proxy: emit drop — unparseable frame ({} bytes)",
            frame.len()
        );
        proxy.delivery.dropped();
        return;
    };
    let Some(id) = proxy.state.ids.get(&parsed.flow).copied() else {
        crate::debug!("local-proxy: emit drop — no flow id for {:?}", parsed.flow);
        proxy.delivery.dropped();
        return;
    };
    match proxy
        .events
        .try_send((proxy.epoch, Event::Packet(Packet { id, bytes: frame })))
    {
        Ok(()) => {}
        Err(_) => proxy.delivery.dropped(),
    }
}

fn relay_tcp(
    proxy: &mut Proxy<'_>,
    stream: netstack_smoltcp::TcpStream,
    client: SocketAddr,
    target: SocketAddr,
) {
    let key = flow_key(client, target, 6);
    let device = proxy.device.clone();
    let mut shutdown = proxy.shutdown.subscribe();
    let flows = proxy.flows.clone();
    tokio::spawn(async move {
        let outbound =
            match egress::tcp_connect(device.as_deref(), target, TCP_CONNECT_TIMEOUT).await {
                Ok(outbound) => outbound,
                Err(error) => {
                    crate::debug!("local-proxy: connect {target} failed — {error}");
                    let _ = flows.try_send(FlowMsg::Closed(key));
                    return;
                }
            };
        let mut stream = stream;
        let mut outbound = outbound;
        let result = tokio::select! {
            _ = shutdown.changed() => Ok(()),
            result = tokio::io::copy_bidirectional(&mut stream, &mut outbound) => {
                result.map(|_| ()).map_err(|error| error.to_string())
            }
        };
        if let Err(error) = result {
            crate::debug!("local-proxy: relay {client} ↔ {target} ended — {error}");
        }
        // Half-close отработан copy_bidirectional; поток для клиента закрыт.
        let _ = flows.try_send(FlowMsg::Closed(key));
    });
}

fn relay_udp(proxy: &mut Proxy<'_>, (payload, client, target): (Vec<u8>, SocketAddr, SocketAddr)) {
    let key = flow_key(client, target, 17);
    let pair = (client, target);
    if !proxy.state.udp.contains_key(&pair) {
        if proxy.state.udp.len() >= proxy.limits.udp {
            proxy.state.stats.open_failed_flows += 1;
            proxy.state.ids.remove(&key);
            proxy.delivery.dropped();
            return;
        }
        let (sender, datagrams) = mpsc::channel::<Vec<u8>>(64);
        let device = proxy.device.clone();
        let idle = proxy.limits.udp_idle;
        let mut shutdown = proxy.shutdown.subscribe();
        let flows = proxy.flows.clone();
        let inject = proxy.inject.clone();
        tokio::spawn(async move {
            udp_flow(
                device,
                datagrams,
                &mut shutdown,
                flows,
                inject,
                client,
                target,
                idle,
            )
            .await;
        });
        proxy.state.udp.insert(pair, sender);
        proxy.state.stats.opened_flows += 1;
        crate::debug!("local-proxy: udp flow {client} → {target} opened");
    }
    let Some(sender) = proxy.state.udp.get(&pair) else {
        proxy.delivery.dropped();
        return;
    };
    match sender.try_send(payload) {
        Ok(()) => proxy.state.stats.inner_tx_packets += 1,
        Err(_) => proxy.delivery.dropped(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn udp_flow(
    device: Option<String>,
    mut datagrams: mpsc::Receiver<Vec<u8>>,
    shutdown: &mut watch::Receiver<bool>,
    flows: mpsc::Sender<FlowMsg>,
    inject: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    client: SocketAddr,
    target: SocketAddr,
    idle: Duration,
) {
    let socket = match egress::udp_socket(device.as_deref(), target) {
        Ok(socket) => socket,
        Err(error) => {
            crate::debug!("local-proxy: udp socket {target} failed — {error}");
            let _ = flows.try_send(FlowMsg::Closed(flow_key(client, target, 17)));
            return;
        }
    };
    let mut buffer = vec![0u8; UDP_BUFFER];
    let key = flow_key(client, target, 17);
    let result = loop {
        tokio::select! {
            _ = shutdown.changed() => break Ok(()),
            datagram = datagrams.recv() => {
                let Some(datagram) = datagram else { break Ok(()) };
                // Unconnected-сокет: цель может ответить с иного адреса (weak-host),
                // поэтому шлём send_to и принимаем любой source — см. egress::udp_socket.
                if socket.send_to(&datagram, target).await.is_err() {
                    break Err("wan send failed");
                }
            }
            received = socket.recv_from(&mut buffer) => {
                match received {
                    Ok((length, _)) => {
                        crate::debug!("local-proxy: udp {target} → {client} reply {length} bytes");
                        // Ответ инжектируется как цель→клиент.
                        if inject
                            .try_send((buffer[..length].to_vec(), target, client))
                            .is_err()
                        {
                            break Err("inject queue full");
                        }
                    }
                    Err(_) => break Err("wan recv failed"),
                }
            }
            _ = tokio::time::sleep(idle) => break Ok(()),
        }
    };
    if let Err(reason) = result {
        crate::debug!("local-proxy: udp flow {client} → {target} ended — {reason}");
    }
    let _ = flows.try_send(FlowMsg::Closed(key));
}

/// IPv6-адресов из TUN не бывает (svpn — IPv4-VPN), отображение defensively.
fn flow_key(source: SocketAddr, destination: SocketAddr, protocol: u8) -> FlowKey {
    let v4 = |addr: &SocketAddr| match addr {
        SocketAddr::V4(addr) => *addr.ip(),
        SocketAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    FlowKey {
        protocol,
        source: v4(&source),
        destination: v4(&destination),
        source_port: source.port(),
        destination_port: destination.port(),
    }
}

/// Адрес источника (`forward = true`) или цели потока из ключа.
fn addr_of(key: &FlowKey, forward: bool) -> SocketAddr {
    let (ip, port) = if forward {
        (key.source, key.source_port)
    } else {
        (key.destination, key.destination_port)
    };
    SocketAddr::new(IpAddr::V4(ip), port)
}
