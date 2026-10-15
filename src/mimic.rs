//! `--mimic` planning: the UDP strategies and TCP camouflage both sides agree
//! on. The serve launch command is built from the same values.

use anyhow::{Context, Result, ensure};

use crate::control::Strategy;
use crate::framing::Camouflage;
use crate::tcp;

/// Default UDP channel strategies: the order the server offers them.
pub const DEFAULT_STRATEGIES: [Strategy; 4] = [
    Strategy::Quic,
    Strategy::WebRtc,
    Strategy::Mosh,
    Strategy::Obfs,
];

/// Default UDP port range: the admin opens it on the firewall.
pub const DEFAULT_PORT_RANGE: &str = "60000-60009";

/// CLI value of `--mimic`: what the traffic pretends to be. UDP strategies
/// are datagram look-alikes; ssh/banner/none are camouflage levels of the TCP fallback.
/// Kept apart from protocol types to keep clap-derive out of control/framing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MimicArg {
    Quic,
    #[value(name = "webrtc")]
    WebRtc,
    Obfs,
    Mosh,
    /// Full SSH-BPP exchange over the TCP stream.
    Ssh,
    /// A single greeting line over the TCP stream.
    Banner,
    /// TCP stream without camouflage.
    None,
}

impl MimicArg {
    pub(crate) fn strategy(self) -> Option<Strategy> {
        match self {
            MimicArg::Quic => Some(Strategy::Quic),
            MimicArg::WebRtc => Some(Strategy::WebRtc),
            MimicArg::Obfs => Some(Strategy::Obfs),
            MimicArg::Mosh => Some(Strategy::Mosh),
            MimicArg::Ssh | MimicArg::Banner | MimicArg::None => None,
        }
    }

    pub(crate) fn camouflage(self) -> Option<Camouflage> {
        match self {
            MimicArg::Ssh => Some(Camouflage::Ssh),
            MimicArg::Banner => Some(Camouflage::Banner),
            MimicArg::None => Some(Camouflage::None),
            _ => None,
        }
    }
}

/// Expansion of `--mimic` (+ `--tcp-port`) into a transport plan.
/// Identical for client and server — the serve launch command is built
/// from the same values, so the sides always agree on the mode.
pub struct MimicPlan {
    pub strategies: Vec<Strategy>,
    /// TCP candidate; `port: None` — the server picks an ephemeral port.
    pub tcp: Option<(Option<u16>, Camouflage)>,
}

pub fn plan_mimic(mimic: &[MimicArg], tcp_port: Option<u16>) -> Result<MimicPlan> {
    let mut strategies = Vec::new();
    let mut camouflage = None;
    for value in mimic {
        if let Some(strategy) = value.strategy() {
            if !strategies.contains(&strategy) {
                strategies.push(strategy);
            }
        } else if let Some(level) = value.camouflage() {
            ensure!(
                camouflage.replace(level).is_none(),
                "--mimic allows only one TCP camouflage level"
            );
        }
    }
    // Empty --mimic = auto: all UDP strategies + TCP fallback (ephemeral).
    // The list stays empty: session treats an empty list as auto
    // (proactive-selector); defaults are applied on the serve side.
    let tcp_enabled = camouflage.is_some() || tcp_port.is_some() || mimic.is_empty();
    if strategies.is_empty() && !mimic.is_empty() {
        ensure!(
            tcp_port.is_some(),
            "--mimic <ssh|banner|none> without UDP strategies requires --tcp-port"
        );
    }
    Ok(MimicPlan {
        strategies,
        tcp: tcp_enabled.then(|| (tcp_port, camouflage.unwrap_or(Camouflage::Ssh))),
    })
}

/// TCP mode of a `--mimic` list without UDP strategies (TCP-only): the port is
/// required and carries the given camouflage. `None` when UDP strategies are
/// present — TCP then stays a fallback candidate handled via endpoints.
pub fn tcp_only_mode(mimic: &[MimicArg], plan: &MimicPlan) -> Result<Option<tcp::Mode>> {
    let tcp_only = !mimic.is_empty() && plan.strategies.is_empty();
    match plan.tcp {
        Some((port, camouflage)) if tcp_only => Ok(Some(tcp::Mode {
            port: port.context("TCP mode requires --tcp-port")?,
            camouflage,
        })),
        _ => Ok(None),
    }
}
