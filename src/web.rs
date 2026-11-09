//! Read-only dashboard of the client state: servers, rules and live flows.
//!
//! The hub owns the state, so it builds the snapshot; this module only
//! shapes it and (in `serve`) hands the latest one over HTTP. Nothing here
//! changes routing.

pub mod asn;
pub mod lan;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

use crate::{
    control::{RoundReport, Stats},
    hub::{Hub, JobStats, StickyStats, Target},
    proc_stats::ProcessView,
};

/// One server of the pool with its traffic counters.
#[derive(Clone, Serialize)]
pub struct ServerView {
    pub index: usize,
    /// Stable node id (the configured `server` string).
    pub id: String,
    pub label: String,
    pub server: String,
    pub weight: u32,
    /// Configured camouflage candidates; empty means automatic selection.
    pub mimic: Vec<crate::mimic::MimicArg>,
    /// Live selection view: the transport in use and why it won.
    pub selection: SelectionView,
    /// Country of the server address from the loaded table; null without one.
    pub country: Option<String>,
    /// ready, checking, connecting, backoff or failed.
    pub state: &'static str,
    /// Why the link last failed.
    pub reason: String,
    pub stats: Stats,
}

/// Live transport selection of one server: the transport in use and the
/// race that picked it.
#[derive(Clone, Serialize)]
pub struct SelectionView {
    /// Transport in use right now (`quic`, `mosh`, `tcp-ssh`, …); null
    /// before the first verified round.
    pub active: Option<String>,
    /// The last completed selection round; null before the first verdict.
    pub round: Option<RoundReport>,
}

/// One sticky block: what it matches and which server serves it.
#[derive(Clone, Serialize)]
pub struct RuleView {
    pub index: usize,
    pub label: String,
    pub kind: &'static str,
    pub local: bool,
    /// Allowed remote node ids, distinct from the group's current owner.
    pub candidates: Vec<String>,
    pub traffic: TrafficView,
    pub selector: String,
    pub via: String,
    pub every_secs: u64,
    pub resolved_ips: usize,
    /// Server node id owning the group, if the group is pinned.
    pub owner: Option<String>,
}

/// Per-rule IP traffic since client start, including retired flows.
/// `active_flows` counts open flows only; closing ones are separate.
#[derive(Default, Clone, Serialize)]
pub struct TrafficView {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub active_flows: usize,
    pub closing_flows: usize,
}

#[derive(Clone, Serialize)]
pub struct DatabaseView {
    pub kind: &'static str,
    pub configured: bool,
    pub loaded: bool,
    pub pending: Option<String>,
    pub rows: usize,
    pub status: crate::hub::jobs::DatabaseStatus,
}

/// One pinned destination group and the server that serves it.
#[derive(Clone, Serialize)]
pub struct GroupView {
    pub group: String,
    pub server: String,
}

/// Local exit: readiness and counters.
#[derive(Clone, Serialize)]
pub struct LocalView {
    pub enabled: bool,
    pub ready: bool,
    pub opened: u64,
    pub failed: u64,
    pub closed: u64,
    pub active_flows: usize,
    pub closing_flows: usize,
}

/// One active client flow and where it goes.
#[derive(Clone, Serialize)]
pub struct FlowView {
    pub rule: Option<usize>,
    pub protocol: &'static str,
    pub source: String,
    pub destination: String,
    /// Destination metadata from the loaded tables, independent of routing policy.
    pub country: Option<String>,
    pub asn: Option<u32>,
    /// Server node id, or `local`.
    pub via: String,
    /// Both FINs seen: the flow is closing, not open.
    pub closing: bool,
    /// LAN device behind the router's masquerade, from conntrack; null for
    /// the router's own flows or without conntrack.
    pub client: Option<String>,
    /// DHCP hostname of `client`; null without a lease name.
    pub client_name: Option<String>,
    /// This flow's bytes since the hub first saw it; the dashboard derives rates.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Seconds since the hub first saw the flow and since its last packet.
    pub age_secs: u64,
    pub idle_secs: u64,
}

/// Everything the dashboard shows.
#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub generated_at: u64,
    pub generated_at_ms: u64,
    pub started_at: u64,
    pub fallback: TrafficView,
    pub databases: Vec<DatabaseView>,
    /// balance or sticky-asn.
    pub policy: &'static str,
    pub asn_table: bool,
    pub country_table: bool,
    pub servers: Vec<ServerView>,
    pub sticky: StickyStats,
    pub rules: Vec<RuleView>,
    pub groups: Vec<GroupView>,
    pub local: LocalView,
    pub flows: Vec<FlowView>,
    pub jobs: JobStats,
    /// Resource usage of the svpn process itself. Each field may be null.
    pub process: ProcessView,
}

/// Snapshot of the client state for the dashboard.
pub fn snapshot(hub: &Hub) -> Snapshot {
    let servers = hub
        .links
        .iter()
        .enumerate()
        .map(|(index, link)| {
            let stats = link_counters(link);
            ServerView {
                index,
                id: node_id(hub, index),
                label: link.params.label.clone(),
                server: link.params.server.clone(),
                weight: link.params.weight,
                mimic: link.params.mimic.clone(),
                state: crate::hub::link_state(&hub.pool, link, index),
                reason: link.last_reason.clone(),
                selection: SelectionView {
                    active: stats.active_candidate.clone(),
                    round: stats.last_round.clone(),
                },
                // shortcut: only an IPv4 literal gets a country, a hostname stays null —
                // keep the startup resolution on the link if hostnames become common.
                country: hub
                    .country
                    .as_ref()
                    .zip(link.params.server.parse().ok())
                    .and_then(|(table, ip)| table.lookup(ip))
                    .map(crate::geo::unpack_country),
                stats,
            }
        })
        .collect();
    let mut active = std::collections::HashMap::<Option<usize>, usize>::new();
    let mut closing = std::collections::HashMap::<Option<usize>, usize>::new();
    for flow in hub.routes.by_key.values() {
        if flow.closing {
            *closing.entry(flow.rule).or_default() += 1;
        } else {
            *active.entry(flow.rule).or_default() += 1;
        }
    }
    let traffic = |rule| {
        let totals = hub.routes.traffic.get(&rule).copied().unwrap_or_default();
        TrafficView {
            rx_bytes: totals.rx_bytes,
            tx_bytes: totals.tx_bytes,
            active_flows: active.get(&rule).copied().unwrap_or(0),
            closing_flows: closing.get(&rule).copied().unwrap_or(0),
        }
    };
    let rules = hub
        .stickies
        .iter()
        .enumerate()
        .map(|(index, runtime)| RuleView {
            index,
            label: runtime.block.label.clone(),
            kind: match &runtime.block.selector {
                crate::sticky::Selector::Names(_) => "names",
                crate::sticky::Selector::Countries(_) => "countries",
                crate::sticky::Selector::Ips(_) => "ips",
                crate::sticky::Selector::Asn(_) => "asn",
            },
            local: matches!(runtime.block.via, crate::sticky::Via::Local),
            candidates: match hub.sticky_via.get(index) {
                Some(crate::sticky::ResolvedVia::Links(links)) => {
                    links.iter().map(|&link| node_id(hub, link)).collect()
                }
                _ => Vec::new(),
            },
            traffic: traffic(Some(index)),
            selector: runtime.block.selector.to_string(),
            via: runtime.block.via.to_string(),
            every_secs: runtime.block.every.as_secs(),
            resolved_ips: runtime.resolved.len(),
            owner: hub
                .exit_owners
                .get(&crate::sticky::group_key(&runtime.block.canonical_key()))
                .map(|&link| node_id(hub, link)),
        })
        .collect();
    let mut groups: Vec<GroupView> = hub
        .exit_owners
        .iter()
        .map(|(&group, &link)| GroupView {
            group: group_name(hub, group),
            server: node_id(hub, link),
        })
        .collect();
    groups.sort_by(|a, b| a.group.cmp(&b.group));
    let now = Instant::now();
    let mut flows: Vec<FlowView> = hub
        .routes
        .by_key
        .iter()
        .map(|(key, flow)| FlowView {
            rule: flow.rule,
            protocol: protocol_name(key.protocol),
            source: endpoint(key.source, key.source_port),
            destination: endpoint(key.destination, key.destination_port),
            country: hub
                .country
                .as_ref()
                .and_then(|table| table.lookup(key.destination))
                .map(crate::geo::unpack_country),
            asn: hub
                .geo
                .as_ref()
                .and_then(|table| table.lookup(key.destination)),
            via: match flow.target {
                Target::Direct(_) => "local".to_owned(),
                Target::Remote(owner) => node_id(hub, owner.epoch.link),
            },
            closing: flow.closing,
            client: None,
            client_name: None,
            rx_bytes: flow.traffic.rx_bytes,
            tx_bytes: flow.traffic.tx_bytes,
            age_secs: now.saturating_duration_since(flow.opened).as_secs(),
            idle_secs: now.saturating_duration_since(flow.active).as_secs(),
        })
        .collect();
    flows.sort_by(|a, b| {
        (a.protocol, &a.destination, &a.source).cmp(&(b.protocol, &b.destination, &b.source))
    });
    let local = match &hub.local {
        Some(local) => LocalView {
            enabled: true,
            ready: local.ready,
            opened: hub.local_stats.opened,
            failed: hub.local_stats.failed,
            closed: hub.local_stats.closed,
            // shortcut: the local proxy tracks no TCP FIN close, so local-exit
            // flows are never marked closing — track FINs there if needed.
            closing_flows: 0,
            active_flows: local.latest.borrow().active_flows,
        },
        None => LocalView {
            enabled: hub
                .sticky_via
                .iter()
                .any(|via| matches!(via, crate::sticky::ResolvedVia::Local)),
            ready: false,
            opened: hub.local_stats.opened,
            failed: hub.local_stats.failed,
            closed: hub.local_stats.closed,
            closing_flows: 0,
            active_flows: 0,
        },
    };
    let generated = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Snapshot {
        generated_at: generated.as_secs(),
        generated_at_ms: generated.as_millis().min(u128::from(u64::MAX)) as u64,
        started_at: hub.job_stats.started_at,
        fallback: traffic(None),
        databases: vec![
            DatabaseView {
                kind: "geo",
                configured: hub.geo_path.is_some()
                    || hub.geo.is_some()
                    || hub.geo_pending.is_some(),
                loaded: hub.geo.is_some(),
                pending: hub.geo_pending.clone(),
                rows: hub.geo.as_ref().map_or(0, crate::geo::Geo::rows),
                status: hub.job_stats.geo.clone(),
            },
            DatabaseView {
                kind: "country",
                configured: hub.country_path.is_some()
                    || hub.country.is_some()
                    || hub.country_pending.is_some(),
                loaded: hub.country.is_some(),
                pending: hub.country_pending.clone(),
                rows: hub.country.as_ref().map_or(0, crate::geo::Geo::rows),
                status: hub.job_stats.country.clone(),
            },
        ],
        policy: match hub.policy {
            crate::cli::ExitPolicy::Balance => "balance",
            crate::cli::ExitPolicy::StickyAsn => "sticky-asn",
        },
        asn_table: hub.geo.is_some(),
        country_table: hub.country.is_some(),
        servers,
        sticky: hub.sticky.clone(),
        rules,
        groups,
        local,
        flows,
        jobs: hub.job_stats.clone(),
        process: crate::proc_stats::sample(),
    }
}

/// Counters of one link, cumulative across generations: the totals the hub
/// collected plus the live generation's unreported delta. A dead link has no
/// delta left to add.
fn link_counters(link: &crate::hub::Link) -> Stats {
    match &link.latest {
        Some(latest) => link.stats.projected(&latest.borrow()),
        None => link.stats.totals().clone(),
    }
}

/// Node id of a link: the configured `server` string, with the index as
/// fallback for a hub without nodes.
fn node_id(hub: &Hub, link: usize) -> String {
    hub.nodes
        .get(link)
        .map_or_else(|| link.to_string(), |(id, _)| id.clone())
}

/// Human name of a pinned group: the sticky label, an ASN, or the raw key.
fn group_name(hub: &Hub, group: u64) -> String {
    for runtime in &hub.stickies {
        let canonical = runtime.block.canonical_key();
        if crate::sticky::group_key(&canonical) == group {
            return runtime.block.label.clone();
        }
    }
    if group <= u64::from(u32::MAX) {
        format!("asn {group}")
    } else {
        format!("group {group:#x}")
    }
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "other",
    }
}

fn endpoint(address: std::net::Ipv4Addr, port: u16) -> String {
    format!("{address}:{port}")
}

// ── http ──

/// Maximum request head we read before giving up.
pub const MAX_HEAD: usize = 8 * 1024;

/// One user, one tab: a stalled peer must not hold the listener or an FD.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound sockets and file buffers even when several browsers download the CSV.
pub const MAX_CONNECTIONS: usize = 8;

/// Bind the dashboard socket. Only loopback is allowed: the dashboard is
/// private state and the browser of another host must not reach it.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    ensure!(
        addr.ip().is_loopback(),
        "dashboard listens on loopback only: {addr}"
    );
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind dashboard {addr}"))
}

/// Serve until shutdown. Bounded concurrent requests let CSV downloads run
/// without holding up snapshots. Dropping the JoinSet closes every connection.
pub async fn serve(
    listener: TcpListener,
    snapshots: watch::Receiver<Snapshot>,
    geo_path: Option<PathBuf>,
) -> Result<()> {
    let mut requests = tokio::task::JoinSet::new();
    // One shared cache for every request task: the spawned futures are
    // 'static, so the tables are parsed behind an Arc, once per second.
    let lan = std::sync::Arc::new(lan::Cache::new());
    loop {
        tokio::select! {
            finished = requests.join_next(), if !requests.is_empty() => match finished {
                Some(Ok(Err(error))) => crate::warn!("dashboard: {error:#}"),
                Some(Err(error)) => crate::warn!("dashboard request task: {error}"),
                _ => {}
            },
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("dashboard accept")?;
                if !peer.ip().is_loopback() || requests.len() >= MAX_CONNECTIONS { continue; }
                let snapshots = snapshots.clone();
                let path = geo_path.clone();
                let lan = std::sync::Arc::clone(&lan);
                requests.spawn(async move {
                    handle(stream, &snapshots, path.as_deref(), &lan).await
                });
            }
        }
    }
}

/// Answer the read-only snapshot and the embedded page/modules, nothing else.
async fn handle(
    mut stream: TcpStream,
    snapshots: &watch::Receiver<Snapshot>,
    geo_path: Option<&Path>,
    lan: &lan::Cache,
) -> Result<()> {
    let Some(head) = tokio::time::timeout(REQUEST_TIMEOUT, read_head(&mut stream))
        .await
        .context("dashboard read timeout")??
    else {
        return Ok(());
    };
    let mut lines = head.lines();
    let request = lines.next().unwrap_or_default();
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default();
    if method != "GET" {
        return respond(
            &mut stream,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
        )
        .await;
    }
    if !host_is_local(&head) {
        return respond(
            &mut stream,
            403,
            "text/plain; charset=utf-8",
            b"forbidden host",
        )
        .await;
    }
    match path {
        "/api/state" => {
            // Enriched here, not in the hub: conntrack reads belong to this
            // request task, never to the packet loop that builds snapshots.
            let mut snapshot = snapshots.borrow().clone();
            lan.enrich(&mut snapshot.flows).await;
            let json = serde_json::to_vec(&snapshot)?;
            respond(&mut stream, 200, "application/json", &json).await
        }
        "/api/asn.csv" => {
            let loaded = snapshots.borrow().asn_table;
            match geo_path {
                Some(path) if loaded => asn::serve_csv(&mut stream, path).await,
                _ => {
                    respond(
                        &mut stream,
                        404,
                        "text/plain; charset=utf-8",
                        b"ASN database not loaded",
                    )
                    .await
                }
            }
        }
        "/" => {
            respond(
                &mut stream,
                200,
                "text/html; charset=utf-8",
                PAGE.as_bytes(),
            )
            .await
        }
        "/dashboard.mjs" => {
            respond(
                &mut stream,
                200,
                "text/javascript; charset=utf-8",
                include_bytes!("web/dashboard.mjs"),
            )
            .await
        }
        "/state.mjs" => {
            respond(
                &mut stream,
                200,
                "text/javascript; charset=utf-8",
                include_bytes!("web/state.mjs"),
            )
            .await
        }
        _ => respond(&mut stream, 404, "text/plain; charset=utf-8", b"not found").await,
    }
}

/// Read the request head; None when the peer closed before a complete head.
/// Bytes after the terminator are body, not headers, and are not returned.
async fn read_head(stream: &mut TcpStream) -> Result<Option<String>> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        head.extend_from_slice(&chunk[..read]);
        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            ensure!(end + 4 <= MAX_HEAD, "request head too large");
            return Ok(Some(String::from_utf8_lossy(&head[..end + 4]).into_owned()));
        }
        ensure!(head.len() <= MAX_HEAD, "request head too large");
    }
}

/// The Host header must name the loopback: a browser page on another origin
/// must not be able to read the dashboard state. HTTP/1.1 allows exactly one
/// Host; an IPv6 literal keeps its brackets around the optional port.
fn host_is_local(head: &str) -> bool {
    let mut host = None;
    for line in head.lines().skip(1).take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            if host.is_some() {
                return false;
            }
            host = Some(value.trim());
        }
    }
    let Some(host) = host else {
        return false;
    };
    let name = match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    };
    match name.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => name.eq_ignore_ascii_case("localhost"),
    }
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        stream
            .write_all(response_head(status, content_type, body.len() as u64).as_bytes())
            .await
            .context("write head")?;
        stream.write_all(body).await.context("write body")?;
        stream.flush().await.context("flush body")?;
        Ok(())
    })
    .await
    .context("dashboard write timeout")?
}

fn response_head(status: u16, content_type: &str, length: u64) -> String {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let allow = if status == 405 { "allow: GET\r\n" } else { "" };
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         {allow}\
         content-type: {content_type}\r\n\
         content-length: {}\r\n\
         cache-control: no-store\r\n\
         x-content-type-options: nosniff\r\n\
         content-security-policy: default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n\
         referrer-policy: no-referrer\r\n\
         connection: close\r\n\r\n",
        length
    )
}

/// Embedded assets: no runtime files, external hosts or frontend dependencies.
const PAGE: &str = include_str!("web/index.html");
