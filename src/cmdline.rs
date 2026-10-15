//! CLI value parsers and the remote serve-command string.

use crate::logging;
use crate::mimic::MimicArg;

pub fn parse_port_range(value: &str) -> Result<(u16, u16), String> {
    let invalid = "expects MIN-MAX, e.g. 60000-60009";
    let (min, max) = value.split_once('-').ok_or(invalid)?;
    let min: u16 = min.parse().map_err(|_| invalid)?;
    let max: u16 = max.parse().map_err(|_| invalid)?;
    if min == 0 || min > max {
        return Err("expects 1<=MIN<=MAX".into());
    }
    Ok((min, max))
}

/// Size from the CLI: a number with a K/M/G suffix (powers of 2, like iperf3), 1..=1G.
pub fn parse_byte_size(value: &str) -> Result<u64, String> {
    let invalid = "expects a number with a K/M/G suffix, e.g. 1M or 1048576";
    let trimmed = value.trim();
    let (digits, shift) = match trimmed.as_bytes().last() {
        Some(b'K' | b'k') => (&trimmed[..trimmed.len() - 1], 10),
        Some(b'M' | b'm') => (&trimmed[..trimmed.len() - 1], 20),
        Some(b'G' | b'g') => (&trimmed[..trimmed.len() - 1], 30),
        _ => (trimmed, 0),
    };
    let base: u64 = digits.parse().map_err(|_| invalid)?;
    base.checked_shl(shift)
        .filter(|total| (1..=(1 << 30)).contains(total))
        .ok_or_else(|| "expects 1..=1G".into())
}

pub fn serve_command(
    remote_bin: &str,
    tun_name: &str,
    log_level: logging::Level,
    udp_ports: (u16, u16),
    mimic: &[MimicArg],
    tcp_port: Option<u16>,
) -> String {
    let mut command = format!(
        "{} serve --tun-name {} --log-level {} --udp-port-range {}-{}",
        shell_quote(remote_bin),
        shell_quote(tun_name),
        match log_level {
            logging::Level::Error => "error",
            logging::Level::Info => "info",
            logging::Level::Debug => "debug",
        },
        udp_ports.0,
        udp_ports.1,
    );
    for value in mimic {
        command.push_str(" --mimic ");
        command.push_str(match value {
            MimicArg::Quic => "quic",
            MimicArg::WebRtc => "webrtc",
            MimicArg::Obfs => "obfs",
            MimicArg::Mosh => "mosh",
            MimicArg::Ssh => "ssh",
            MimicArg::Banner => "banner",
            MimicArg::None => "none",
        });
    }
    // The server builds its mode from the same --mimic and port values (0 — ephemeral).
    if let Some(port) = tcp_port {
        command.push_str(&format!(" --tcp-port {port}"));
    }
    command
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
