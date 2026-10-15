//! CLI grammar and source selection. No network or TUN side effects.

use crate::server_spec::{Globals, ServerSpec, resolve_perf, resolve_servers};
use crate::{DEFAULT_PORT_RANGE, MimicArg, hooks, logging, parse_byte_size, parse_port_range};
use clap::{
    CommandFactory, FromArgMatches, Parser, Subcommand, error::ErrorKind, parser::ValueSource,
};
use std::{ffi::OsString, path::PathBuf};

#[derive(clap::Args)]
pub struct ClientArgs {
    /// Read all client settings from one TOML file instead of CLI options.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// IPv4 address or ASCII hostname with optional SSH port and per-server overrides.
    /// Keys: user, identity, hostkey, mimic (joined by +), remote-bin,
    /// peer-tun, peer-addr, udp-ports, tcp-port; weight is multi-only. Use full identity paths.
    #[arg(long, value_name = "HOST[:PORT][,key=value]", value_parser = clap::value_parser!(ServerSpec))]
    pub server: Vec<ServerSpec>,
    /// Client statistics interval in seconds; 0 disables periodic reports.
    #[arg(long, default_value_t = 30, value_name = "SECONDS")]
    pub stats_interval: u32,
    #[command(flatten)]
    pub hooks: hooks::Args,
    #[command(flatten)]
    pub globals: Globals,
}

#[derive(Parser)]
#[command(
    version,
    arg_required_else_help = true,
    about = "IPv4 VPN: single server by default, or a multi-server pool"
)]
struct RawCli {
    #[command(flatten)]
    client: ClientArgs,
    #[command(subcommand)]
    command: Option<Mode>,
}

#[derive(Subcommand)]
pub enum Mode {
    /// Connect to one or more servers sharing a client TUN.
    #[command(name = "multi")]
    Client(ClientArgs),
    /// Speed measurement over the VPN: session as client, segments through TUN (iperf3-like CLI).
    Perf {
        /// Exactly one server, using the client syntax but without weight.
        #[arg(long, value_name = "HOST[:PORT][,key=value]", value_parser = |value: &str| value.parse::<ServerSpec>().map(Box::new))]
        server: Box<ServerSpec>,
        #[command(flatten)]
        globals: Globals,
        /// Measurement duration, seconds (iperf3 -t).
        #[arg(short = 't', long = "time", default_value_t = 10)]
        time: u64,
        /// Report interval, seconds (iperf3 -i).
        #[arg(short = 'i', long = "interval", default_value_t = 1)]
        interval: u64,
        /// Parallel TCP connections (iperf3 -P).
        #[arg(short = 'P', long = "parallel", default_value_t = 1)]
        parallel: usize,
        /// Segment size with a K/M/G suffix (iperf3 -l).
        #[arg(short = 'l', long = "len", value_parser = parse_byte_size, default_value = "1M")]
        len: u64,
        /// Total volume instead of time, with a K/M/G suffix (iperf3 -n).
        #[arg(short = 'n', long = "bytes", value_parser = parse_byte_size)]
        bytes: Option<u64>,
        /// Upload to the server (POST) instead of download (GET) (iperf3 -R).
        #[arg(short = 'R', long = "reverse")]
        reverse: bool,
        /// Drop the first N seconds from the report (iperf3 -O).
        #[arg(short = 'O', long = "omit", default_value_t = 0)]
        omit: u64,
        /// Machine-readable report to stdout instead of a table on stderr.
        #[arg(long)]
        json: bool,
    },
    /// Serve one SSH session: JSONL over stdin/stdout (Linux only).
    Serve {
        /// Server TUN name; unset or empty — let the kernel pick a name.
        #[arg(long)]
        tun_name: Option<String>,
        /// Server log level; set by the client in the launch command.
        #[arg(long, value_enum, default_value_t = logging::Level::Info)]
        log_level: logging::Level,
        /// Server UDP port range `MIN-MAX`: the admin opens only it on the firewall.
        #[arg(long, value_parser = parse_port_range, default_value = DEFAULT_PORT_RANGE)]
        udp_port_range: (u16, u16),
        /// Allowed camouflages; empty — all UDP strategies + TCP fallback.
        #[arg(long, value_enum)]
        mimic: Vec<MimicArg>,
        /// TCP fallback port; 0 — ephemeral.
        #[arg(long)]
        tcp_port: Option<u16>,
    },
}

pub struct Cli {
    pub command: Mode,
}

impl Cli {
    pub fn parse() -> Self {
        Self::try_parse_from(std::env::args_os()).unwrap_or_else(|error| error.exit())
    }

    pub fn try_parse_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let command = RawCli::command();
        let matches = command.clone().try_get_matches_from(args)?;
        let root_explicit = explicit_settings(&command, &matches);
        let raw = RawCli::from_arg_matches(&matches)?;
        let multi = matches.subcommand_name() == Some("multi");
        if raw.command.is_some() && !root_explicit.is_empty() {
            return Err(clap::Error::raw(
                ErrorKind::ArgumentConflict,
                "connection options must follow the subcommand",
            ));
        }
        let mode = match raw.command {
            Some(Mode::Client(mut client)) => {
                if raw.client.config.is_some() && client.config.is_some() {
                    return Err(clap::Error::raw(
                        ErrorKind::ArgumentConflict,
                        "--config may only be specified once",
                    ));
                }
                client.config = client.config.or(raw.client.config);
                Mode::Client(client)
            }
            Some(mode) => {
                if raw.client.config.is_some() {
                    return Err(clap::Error::raw(
                        ErrorKind::ArgumentConflict,
                        "perf and serve do not accept --config",
                    ));
                }
                mode
            }
            None => Mode::Client(raw.client),
        };
        let mode = match mode {
            Mode::Client(mut client) => {
                let explicit = if multi {
                    let sub = command
                        .find_subcommand("multi")
                        .expect("declared multi command");
                    explicit_settings(
                        sub,
                        matches.subcommand_matches("multi").expect("matched multi"),
                    )
                } else {
                    root_explicit
                };
                let invalid = |error: anyhow::Error| {
                    clap::Error::raw(ErrorKind::ValueValidation, format!("{error:#}"))
                };
                let from_file = client.config.is_some();
                if let Some(path) = client.config.take() {
                    if let Some(flag) = explicit.first() {
                        return Err(clap::Error::raw(
                            ErrorKind::ArgumentConflict,
                            format!(
                                "--config cannot be combined with --{}",
                                flag.replace('_', "-")
                            ),
                        ));
                    }
                    client = crate::config::load(&path, multi).map_err(invalid)?;
                }
                if !multi {
                    if client.server.len() != 1 {
                        return Err(clap::Error::raw(
                            ErrorKind::WrongNumberOfValues,
                            "single mode requires exactly one --server",
                        ));
                    }
                    client.server[0].without_weight("single").map_err(invalid)?;
                }
                // Validate every server before the runtime can open the first SSH session.
                if !from_file {
                    resolve_servers(&client.server, &client.globals).map_err(invalid)?;
                }
                Mode::Client(client)
            }
            Mode::Perf {
                ref server,
                ref globals,
                ..
            } => {
                resolve_perf(server, globals).map_err(|error| {
                    clap::Error::raw(ErrorKind::ValueValidation, format!("{error:#}"))
                })?;
                mode
            }
            mode => mode,
        };
        Ok(Self { command: mode })
    }
}

fn explicit_settings(command: &clap::Command, matches: &clap::ArgMatches) -> Vec<String> {
    command
        .get_arguments()
        .map(|arg| arg.get_id().as_str())
        .filter(|id| *id != "config" && matches.value_source(id) == Some(ValueSource::CommandLine))
        .map(str::to_owned)
        .collect()
}
