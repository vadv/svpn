//! CLI grammar and source selection. No network or TUN side effects.

use crate::server_spec::{Globals, ServerSpec, resolve_perf, resolve_servers};
use crate::{DEFAULT_PORT_RANGE, MimicArg, hooks, logging, parse_byte_size, parse_port_range};
use clap::{
    CommandFactory, FromArgMatches, Parser, Subcommand, error::ErrorKind, parser::ValueSource,
};
use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitPolicy {
    /// Weighted round-robin per new flow (default).
    #[default]
    Balance,
    /// Pin destination groups (destination ASN) to servers.
    StickyAsn,
}

#[derive(clap::Args)]
pub struct ClientArgs {
    /// Read all client settings from one HCL file instead of CLI options.
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
    /// Exit selection: balance (default) or sticky-asn (stable exit per destination ASN).
    #[arg(long, value_enum, default_value_t = ExitPolicy::Balance)]
    pub exit_policy: ExitPolicy,
    /// DB-IP ASN Lite CSV database for sticky-asn.
    #[arg(long, value_name = "FILE")]
    pub geo_db: Option<PathBuf>,
    /// DB-IP Country Lite CSV database for country selectors.
    #[arg(long, value_name = "FILE")]
    pub country_db: Option<PathBuf>,
    /// Sticky owner persistence; default: GEO_DB with a .state.json suffix.
    #[arg(long, value_name = "FILE")]
    pub exit_state: Option<PathBuf>,
    /// Explicit sticky groups (config-file only).
    #[arg(skip)]
    pub stickies: Vec<crate::sticky::StickyBlock>,
    /// Scheduled background jobs (config-file only).
    #[arg(skip)]
    pub jobs: Vec<crate::job::JobSpec>,
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
    /// Install the server binary on Debian/Ubuntu/Rocky/CentOS Stream VPSs.
    Setup {
        #[command(flatten)]
        client: ClientArgs,
    },
    /// Print an embedded hook example to stdout.
    Example {
        /// Example name: client-up, client-down, server-up, server-down,
        /// job-geo-update or job-country-update.
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Scheduled background jobs from the config (systemd-style).
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
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

#[derive(Subcommand)]
pub enum JobCommand {
    /// Run one job now, in the foreground; the exit code is the job's.
    Run {
        /// Job label from the config.
        #[arg(value_name = "NAME")]
        name: String,
        /// Config file with the job definition.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// List the jobs declared in the config.
    List {
        /// Config file with the job definitions.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
}

pub struct Cli {
    pub command: Mode,
}

impl ClientArgs {
    /// Database coupling: ASN grouping (strategy or asn selector) needs the
    /// ASN database, country selectors need the country database. Name/ip
    /// selectors and via = local need neither. An unused database is ignored
    /// at runtime, not here.
    pub(crate) fn validate_geo(&self) -> anyhow::Result<()> {
        let needs_geo = self.exit_policy == ExitPolicy::StickyAsn
            || self
                .stickies
                .iter()
                .any(|s| matches!(s.selector, crate::sticky::Selector::Asn(_)));
        anyhow::ensure!(
            !needs_geo || self.geo_db.is_some(),
            "exit-policy sticky-asn or an asn selector requires geo db"
        );
        let needs_country = self
            .stickies
            .iter()
            .any(|s| matches!(s.selector, crate::sticky::Selector::Countries(_)));
        anyhow::ensure!(
            !needs_country || self.country_db.is_some(),
            "a countries selector requires country db"
        );
        Ok(())
    }
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
                        "perf, serve and setup require their own arguments",
                    ));
                }
                mode
            }
            None => Mode::Client(raw.client),
        };
        let mode = match mode {
            Mode::Setup { client } if client.config.is_some() == !client.server.is_empty() => {
                return Err(clap::Error::raw(
                    ErrorKind::ArgumentConflict,
                    "setup requires exactly one of --config or --server",
                ));
            }
            mode => mode,
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
                    if client.exit_policy != ExitPolicy::Balance {
                        return Err(clap::Error::raw(
                            ErrorKind::ValueValidation,
                            "exit-policy sticky-asn is multi-only",
                        ));
                    }
                }
                // Validate every server before the runtime can open the first SSH session.
                if !from_file {
                    resolve_servers(&client.server, &client.globals).map_err(invalid)?;
                    client.validate_geo().map_err(invalid)?;
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
