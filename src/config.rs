//! One bounded HCL file, with paths relative to its supplied directory.
//!
//! The file is walked structure-by-structure (not via serde) so that block
//! order is preserved (sticky first-match), duplicates and unknown keys are
//! rejected explicitly, and error messages never echo attribute values.

use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::Read,
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;

use crate::{
    MimicArg,
    cli::ClientArgs,
    hooks,
    job::JobSpec,
    logging,
    server_spec::{Globals, ServerSpec, parse_country_code},
    sticky::{IpNet, Selector, StickyBlock, Via, parse_duration, validate_name},
};

pub const MAX_CONFIG: u64 = 1024 * 1024;
/// Maximum length of a server hook command, to keep `ServerHooks` within the
/// control channel line limit (`MAX_LINE`).
pub const MAX_SERVER_HOOK: usize = 1500;

pub fn load(path: &Path, multi: bool) -> Result<ClientArgs> {
    let read = || -> Result<String> {
        // Opening a FIFO must not block before the regular-file check.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(path)?;
        ensure!(file.metadata()?.is_file(), "config must be a regular file");
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= MAX_CONFIG, "config exceeds 1 MiB");
        String::from_utf8(bytes).context("config must be UTF-8")
    };
    let text = read().with_context(|| format!("{}: read config", path.display()))?;
    parse(
        &text,
        path.parent().unwrap_or_else(|| Path::new(".")),
        multi,
    )
    .and_then(|args| {
        crate::server_spec::resolve_servers(&args.server, &args.globals)?;
        Ok(args)
    })
    .map(|mut args| {
        // Sticky owners persist even without any database: default the state
        // file next to the config itself.
        if args.exit_state.is_none()
            && !args.stickies.is_empty()
            && args.geo_db.is_none()
            && args.country_db.is_none()
        {
            args.exit_state = Some(path.with_extension("state.json"));
        }
        args
    })
    .with_context(|| path.display().to_string())
}

pub fn parse(text: &str, base: &Path, multi: bool) -> Result<ClientArgs> {
    let body = hcl::parse(text).map_err(sanitize_parse_error)?;
    let mut top = Top::split(&body)?;

    let globals = Globals {
        ssh_identity: top.take_path("ssh", "identity", base)?,
        ssh_user: top.take_string("ssh", "user")?,
        ssh_port: top.take_port("ssh", "port")?.unwrap_or(22),
        ssh_host_key: top.take_string("ssh", "host_key")?,
        ssh_remote_bin: top
            .take_string("ssh", "remote_bin")?
            .unwrap_or_else(|| "/usr/local/bin/svpn".into()),
        peer_tun_name: top.take_string("tunnel", "peer_name")?,
        tun_name: top.take_string("tunnel", "name")?,
        tun_addr: top.take_ip("tunnel", "addr")?,
        peer_addr: top.take_ip("tunnel", "peer_addr")?,
        mtu: top.take_u16("transport", "mtu")?.unwrap_or(1280),
        log_level: top.take_level("log_level")?.unwrap_or(logging::Level::Info),
        udp_port_range: match top.take_string("transport", "udp_ports")? {
            Some(range) => crate::parse_port_range(&range).map_err(anyhow::Error::msg)?,
            None => (60000, 60009),
        },
        mimic: top.take_mimics("transport", "mimic")?.unwrap_or_default(),
        remeasure_interval: top
            .take_duration_secs("transport", "remeasure")?
            .map(|d| d.as_secs().min(u32::MAX as u64) as u32),
        tcp_port: top.take_u16("transport", "tcp_port")?,
        server_up: top.take_string("hooks", "server_up")?,
        server_down: top.take_string("hooks", "server_down")?,
    };
    // Check raw values before inheritance or join("") can conceal an error.
    globals.validate_fields()?;

    let mut servers = top.servers(base)?;
    if multi {
        ensure!(
            !servers.is_empty(),
            "multi requires at least one server block"
        );
    } else {
        ensure!(
            servers.len() == 1,
            "single mode requires exactly one server block"
        );
    }
    let server_labels: HashSet<String> = servers.iter().map(|(label, _)| label.clone()).collect();
    let server_label_refs: HashSet<&str> = server_labels.iter().map(String::as_str).collect();
    let mut server_specs: Vec<ServerSpec> = Vec::with_capacity(servers.len());
    for (label, mut server) in servers.drain(..) {
        server
            .validate_fields()
            .with_context(|| format!("server {label}"))?;
        server.label = label;
        server_specs.push(server);
    }

    let mut hooks = hooks::Args {
        up_script: top.take_path("hooks", "up_script", base)?,
        down_script: top.take_path("hooks", "down_script", base)?,
        up_command: top.take_string("hooks", "up_command")?,
        down_command: top.take_string("hooks", "down_command")?,
    };
    for (name, script, command) in [
        ("up", &mut hooks.up_script, &hooks.up_command),
        ("down", &mut hooks.down_script, &hooks.down_command),
    ] {
        ensure!(
            script.is_none() || command.is_none(),
            "{name}-script and {name}-command conflict"
        );
        if let Some(path) = script {
            ensure!(
                !path.as_os_str().is_empty(),
                "{name}-script must not be empty"
            );
        }
        if let Some(command) = command {
            ensure!(
                !command.trim().is_empty(),
                "{name}-command must not be empty"
            );
        }
    }

    let stickies = top.stickies()?;
    StickyBlock::validate_all(&stickies, &server_label_refs)?;
    let jobs = top.jobs()?;
    crate::job::JobSpec::validate_all(&jobs)?;

    let args = ClientArgs {
        config: None,
        server: server_specs,
        stats_interval: top
            .take_duration_secs("transport", "stats")?
            .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
            .unwrap_or(30),
        exit_policy: top
            .take_exit_policy("fallback_sticky", "strategy")?
            .unwrap_or_default(),
        geo_db: top.take_path("geo", "db", base)?,
        country_db: top.take_path("country", "db", base)?,
        exit_state: top.take_path("fallback_sticky", "state", base)?,
        stickies,
        jobs,
        hooks,
        globals,
    };
    top.finish()?;
    args.validate_geo()?;
    Ok(args)
}

/// Map an hcl-rs parse error to a sanitized location-only message: the
/// diagnostic line text can contain attribute values, so only line/column
/// and a generic reason are kept.
fn sanitize_parse_error(error: hcl::Error) -> anyhow::Error {
    match error {
        hcl::Error::Parse(parse) => anyhow::anyhow!(
            "line {}, column {}: invalid config syntax",
            parse.location().line(),
            parse.location().column()
        ),
        other => anyhow::anyhow!("invalid config syntax: {other}"),
    }
}

/// True when the text contains a live `${`/`%{` sequence. The escaped forms
/// `$${` and `%%{` are literals, not interpolation.
fn has_interpolation(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(2).enumerate().any(|(index, pair)| {
        (pair == b"${" || pair == b"%{") && index > 0 && bytes[index - 1] != bytes[index]
    })
}

/// Reject expressions we do not evaluate (variables, traversals, function
/// calls, operators, interpolation): the config is data, not a program.
fn literal(expr: &hcl::Expression) -> Result<hcl::Value> {
    use hcl::Expression;
    match expr {
        Expression::Null
        | Expression::Bool(_)
        | Expression::Number(_)
        | Expression::String(_)
        | Expression::Array(_)
        | Expression::Object(_) => Ok(hcl::Value::from(expr.clone())),
        Expression::Parenthesis(inner) => literal(inner),
        Expression::TemplateExpr(template) => {
            let text = template.to_string();
            ensure!(
                !has_interpolation(&text),
                "template expressions are not allowed"
            );
            // A heredoc's final newline is file formatting, not value.
            Ok(hcl::Value::String(
                text.strip_suffix('\n').unwrap_or(&text).to_string(),
            ))
        }
        _ => bail!("expressions are not allowed, only literal values"),
    }
}

/// Split a body into attributes and blocks, rejecting duplicate attributes.
struct Split<'a> {
    attrs: Vec<&'a hcl::Attribute>,
    blocks: Vec<&'a hcl::Block>,
    ctx: String,
}

impl<'a> Split<'a> {
    fn of(body: &'a hcl::Body, ctx: &str) -> Result<Self> {
        let mut attrs = Vec::new();
        let mut blocks = Vec::new();
        let mut keys = HashSet::new();
        for structure in body.iter() {
            match structure {
                hcl::Structure::Attribute(attr) => {
                    ensure!(
                        keys.insert(attr.key()),
                        "{ctx}: duplicate attribute {}",
                        attr.key()
                    );
                    attrs.push(attr);
                }
                hcl::Structure::Block(block) => blocks.push(block),
            }
        }
        Ok(Split {
            attrs,
            blocks,
            ctx: ctx.to_string(),
        })
    }

    fn take_raw(&mut self, key: &str) -> Result<Option<hcl::Expression>> {
        let Some(index) = self.attrs.iter().position(|a| a.key() == key) else {
            return Ok(None);
        };
        Ok(Some(self.attrs.swap_remove(index).expr.clone()))
    }

    fn take_value(&mut self, key: &str) -> Result<Option<hcl::Value>> {
        let Some(index) = self.attrs.iter().position(|a| a.key() == key) else {
            return Ok(None);
        };
        let attr = self.attrs.swap_remove(index);
        literal(&attr.expr)
            .map(Some)
            .with_context(|| format!("{}: attribute {key}", self.ctx))
    }

    fn take_string(&mut self, key: &str) -> Result<Option<String>> {
        match self.take_value(key)? {
            None => Ok(None),
            Some(value) => value
                .as_str()
                .map(str::to_owned)
                .map(Some)
                .with_context(|| format!("{}: attribute {key} must be a string", self.ctx)),
        }
    }

    fn take_u16(&mut self, key: &str) -> Result<Option<u16>> {
        number(self.take_value(key)?, &self.ctx, key).map(|n| {
            n.map(|n| {
                u16::try_from(n)
                    .map_err(|_| anyhow::anyhow!("{}: attribute {key} must be 0..=65535", self.ctx))
            })
            .transpose()
        })?
    }

    fn take_u64(&mut self, key: &str) -> Result<Option<u64>> {
        number(self.take_value(key)?, &self.ctx, key)
    }

    fn take_ip(&mut self, key: &str) -> Result<Option<Ipv4Addr>> {
        match self.take_string(key)? {
            None => Ok(None),
            Some(text) => text
                .parse()
                .map(Some)
                .with_context(|| format!("{}: attribute {key} must be an IPv4 address", self.ctx)),
        }
    }

    fn take_path(&mut self, key: &str, base: &Path) -> Result<Option<PathBuf>> {
        match self.take_string(key)? {
            None => Ok(None),
            // Check raw values before join("") can conceal an empty path.
            Some(text) if text.is_empty() => {
                bail!("{}: attribute {key} must not be empty", self.ctx)
            }
            Some(text) => Ok(Some(base.join(text))),
        }
    }

    fn take_level(&mut self, key: &str) -> Result<Option<logging::Level>> {
        match self.take_string(key)? {
            None => Ok(None),
            Some(text) => logging::Level::from_str(&text, true)
                .map(Some)
                .map_err(|_| anyhow::anyhow!("{}: attribute {key} must be a log level", self.ctx)),
        }
    }

    fn take_mimics(&mut self, key: &str) -> Result<Option<Vec<MimicArg>>> {
        let Some(value) = self.take_value(key)? else {
            return Ok(None);
        };
        let values = value
            .as_array()
            .with_context(|| format!("{}: attribute {key} must be a list", self.ctx))?;
        let mut out = Vec::with_capacity(values.len());
        for value in values {
            let text = value.as_str().with_context(|| {
                format!("{}: attribute {key} must be a list of strings", self.ctx)
            })?;
            out.push(
                MimicArg::from_str(text, true)
                    .map_err(|_| anyhow::anyhow!("{}: attribute {key}: unknown mimic", self.ctx))?,
            );
        }
        Ok(Some(out))
    }

    fn take_duration_secs(&mut self, key: &str) -> Result<Option<std::time::Duration>> {
        match self.take_string(key)? {
            None => Ok(None),
            Some(text) => parse_duration(&text)
                .map(Some)
                .with_context(|| format!("{}: attribute {key}", self.ctx)),
        }
    }

    fn take_exit_policy(&mut self, key: &str) -> Result<Option<crate::cli::ExitPolicy>> {
        match self.take_string(key)? {
            None => Ok(None),
            Some(text) => crate::cli::ExitPolicy::from_str(&text, true)
                .map(Some)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "{}: attribute {key} must be balance or sticky-asn",
                        self.ctx
                    )
                }),
        }
    }

    fn ensure_no_blocks(&self) -> Result<()> {
        ensure!(
            self.blocks.is_empty(),
            "{}: block {} is not allowed here",
            self.ctx,
            self.blocks[0].identifier()
        );
        Ok(())
    }

    fn finish(self) -> Result<()> {
        self.ensure_no_blocks()?;
        ensure!(
            self.attrs.is_empty(),
            "{}: unknown attribute {}",
            self.ctx,
            self.attrs[0].key()
        );
        Ok(())
    }
}

fn number(value: Option<hcl::Value>, ctx: &str, key: &str) -> Result<Option<u64>> {
    match value {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .with_context(|| format!("{ctx}: attribute {key} must be a non-negative integer")),
    }
}

/// Top-level dispatcher: one optional singleton block per subsystem plus
/// ordered `server`/`sticky` blocks.
struct Top<'a> {
    split: Split<'a>,
    singletons: Vec<(&'a str, Split<'a>)>,
    log_level_attrs: Split<'a>,
}

impl<'a> Top<'a> {
    fn split(body: &'a hcl::Body) -> Result<Self> {
        let mut split = Split::of(body, "config")?;
        let mut singletons = Vec::new();
        let mut index = 0;
        while index < split.blocks.len() {
            let block = split.blocks[index];
            index += 1;
            let name = block.identifier();
            if matches!(name, "server" | "sticky" | "job") {
                continue;
            }
            ensure!(
                matches!(
                    name,
                    "ssh"
                        | "transport"
                        | "tunnel"
                        | "geo"
                        | "country"
                        | "hooks"
                        | "fallback_sticky"
                ),
                "config: unknown block {name}"
            );
            ensure!(
                block.labels().is_empty(),
                "config: block {name} must not have a label"
            );
            ensure!(
                !singletons.iter().any(|(n, _)| *n == name),
                "config: duplicate block {name}"
            );
            singletons.push((name, Split::of(&block.body, name)?));
        }
        split
            .blocks
            .retain(|b| matches!(b.identifier(), "server" | "sticky" | "job"));
        // Top-level attributes other than log_level are unknown; keep them
        // in a dedicated split so `take_level` can find log_level.
        let mut log_level_attrs = Split {
            attrs: Vec::new(),
            blocks: Vec::new(),
            ctx: "config".to_string(),
        };
        for attr in split.attrs.drain(..) {
            if attr.key() == "log_level" {
                log_level_attrs.attrs.push(attr);
            } else {
                anyhow::bail!("config: unknown attribute {}", attr.key());
            }
        }
        Ok(Self {
            split,
            singletons,
            log_level_attrs,
        })
    }

    fn section(&mut self, name: &str) -> Result<Option<&mut Split<'a>>> {
        let Some(index) = self.singletons.iter().position(|(n, _)| *n == name) else {
            return Ok(None);
        };
        Ok(Some(&mut self.singletons[index].1))
    }

    // Attribute readers look in an optional singleton block; leftovers are
    // validated once by `finish`.

    fn take_string(&mut self, section: &str, key: &str) -> Result<Option<String>> {
        self.take(section, key, Split::take_string)
    }
    fn take_path(&mut self, section: &str, key: &str, base: &Path) -> Result<Option<PathBuf>> {
        self.take(section, key, |s, k| Split::take_path(s, k, base))
    }
    fn take_u16(&mut self, section: &str, key: &str) -> Result<Option<u16>> {
        self.take(section, key, Split::take_u16)
    }
    fn take_port(&mut self, section: &str, key: &str) -> Result<Option<u16>> {
        self.take(section, key, Split::take_u16)
    }
    fn take_ip(&mut self, section: &str, key: &str) -> Result<Option<Ipv4Addr>> {
        self.take(section, key, Split::take_ip)
    }
    fn take_level(&mut self, key: &str) -> Result<Option<logging::Level>> {
        let value = self.log_level_attrs.take_level(key)?;
        Ok(value)
    }
    fn take_mimics(&mut self, section: &str, key: &str) -> Result<Option<Vec<MimicArg>>> {
        self.take(section, key, Split::take_mimics)
    }
    fn take_duration_secs(
        &mut self,
        section: &str,
        key: &str,
    ) -> Result<Option<std::time::Duration>> {
        self.take(section, key, Split::take_duration_secs)
    }
    fn take_exit_policy(
        &mut self,
        section: &str,
        key: &str,
    ) -> Result<Option<crate::cli::ExitPolicy>> {
        self.take(section, key, Split::take_exit_policy)
    }

    fn take<T>(
        &mut self,
        section: &str,
        key: &str,
        read: impl FnOnce(&mut Split<'a>, &str) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        match self.section(section)? {
            Some(split) => read(split, key),
            None => Ok(None),
        }
    }

    fn servers(&mut self, base: &Path) -> Result<Vec<(String, ServerSpec)>> {
        let mut out = Vec::new();
        let mut labels = HashSet::new();
        let blocks = std::mem::take(&mut self.split.blocks);
        for block in blocks.iter().filter(|b| b.identifier() == "server") {
            ensure!(
                block.labels().len() == 1,
                "server: exactly one block label is required"
            );
            let label = block
                .labels()
                .first()
                .map(|l| l.as_str().to_owned())
                .filter(|l| valid_label(l))
                .context("server: block label must match [a-z0-9_-]{1,32}")?;
            ensure!(
                labels.insert(label.clone()),
                "duplicate server label {label}"
            );
            let mut split = Split::of(&block.body, &format!("server {label}"))?;
            let mut spec = ServerSpec {
                label: label.clone(),
                server: take_host(&mut split, "address")?
                    .with_context(|| format!("server {label}: address is required"))?,
                ssh_port: take_u16_opt(&mut split, "ssh_port")?,
                weight: take_u32_opt(&mut split, "weight")?,
                user: split.take_string("ssh_user")?,
                identity: split.take_path("ssh_identity", base)?,
                host_key: take_host_key(&mut split, "ssh_host_key")?,
                mimic: split.take_mimics("mimic")?,
                remote_bin: split.take_string("ssh_remote_bin")?,
                peer_tun_name: split.take_string("peer_tun_name")?,
                peer_addr: split.take_ip("peer_addr")?,
                udp_port_range: take_port_range(&mut split, "udp_port_range")?,
                tcp_port: take_u16_opt(&mut split, "tcp_port")?,
                server_up: split.take_string("server_up")?,
                server_down: split.take_string("server_down")?,
            };
            spec.udp_port_range = spec
                .udp_port_range
                .or(take_port_range(&mut split, "udp_ports")?);
            split.finish()?;
            out.push((label, spec));
        }
        self.split.blocks = blocks;
        Ok(out)
    }

    fn jobs(&mut self) -> Result<Vec<crate::job::JobSpec>> {
        let mut out = Vec::new();
        let blocks = std::mem::take(&mut self.split.blocks);
        for block in blocks.iter().filter(|b| b.identifier() == "job") {
            ensure!(
                block.labels().len() == 1,
                "job: exactly one block label is required"
            );
            let label = block
                .labels()
                .first()
                .map(|l| l.as_str().to_owned())
                .filter(|l| valid_label(l))
                .context("job: block label must match [a-z0-9_-]{1,32}")?;
            let ctx = format!("job {label}");
            let mut split = Split::of(&block.body, &ctx)?;
            let every = split
                .take_duration_secs("every")?
                .with_context(|| format!("{ctx}: every is required"))?;
            ensure!(
                every >= crate::job::MIN_EVERY,
                "{ctx}: every must be at least {}s",
                crate::job::MIN_EVERY.as_secs()
            );
            let timeout = split
                .take_duration_secs("timeout")?
                .unwrap_or(crate::job::DEFAULT_TIMEOUT);
            ensure!(
                !timeout.is_zero() && timeout <= crate::job::MAX_TIMEOUT,
                "{ctx}: timeout must be 1s..=24h"
            );
            let run_if = split.take_string("run_if")?;
            if let Some(check) = &run_if {
                ensure!(!check.trim().is_empty(), "{ctx}: run_if must not be empty");
            }
            let run = split
                .take_string("run")?
                .with_context(|| format!("{ctx}: run is required"))?;
            ensure!(!run.trim().is_empty(), "{ctx}: run must not be empty");
            let mut reload = Vec::new();
            for item in take_string_list(&mut split, "reload")?.unwrap_or_default() {
                reload.push(
                    crate::job::Reload::parse(&item)
                        .with_context(|| format!("{ctx}: attribute reload"))?,
                );
            }
            let mut seen = std::collections::HashSet::new();
            for reload in &reload {
                ensure!(seen.insert(*reload), "{ctx}: duplicate reload entry");
            }
            split.finish()?;
            out.push(JobSpec {
                label,
                every,
                timeout,
                run_if,
                run,
                reload,
            });
        }
        self.split.blocks = blocks;
        Ok(out)
    }

    fn stickies(&mut self) -> Result<Vec<StickyBlock>> {
        let mut out = Vec::new();
        let blocks = std::mem::take(&mut self.split.blocks);
        for block in blocks.iter().filter(|b| b.identifier() == "sticky") {
            ensure!(
                block.labels().len() == 1,
                "sticky: exactly one block label is required"
            );
            let label = block
                .labels()
                .first()
                .map(|l| l.as_str().to_owned())
                .filter(|l| valid_label(l))
                .context("sticky: block label must match [a-z0-9_-]{1,32}")?;
            let ctx = format!("sticky {label}");
            let mut split = Split::of(&block.body, &ctx)?;
            let mut selector: Option<Selector> = None;
            let mut set = |next: Selector| -> Result<()> {
                ensure!(selector.is_none(), "{ctx}: exactly one selector is allowed");
                selector = Some(next);
                Ok(())
            };
            if let Some(names) = take_string_list(&mut split, "names")? {
                ensure!(!names.is_empty(), "{ctx}: names must not be empty");
                ensure!(names.len() <= 8, "{ctx}: at most 8 names per block");
                for name in &names {
                    validate_name(name).with_context(|| format!("{ctx}: attribute names"))?;
                }
                set(Selector::Names(names))?;
            }
            if let Some(codes) = take_string_list(&mut split, "countries")? {
                ensure!(!codes.is_empty(), "{ctx}: countries must not be empty");
                let codes = codes
                    .iter()
                    .map(|c| parse_country_code(c))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("{ctx}: attribute countries"))?;
                set(Selector::Countries(codes))?;
            }
            if let Some(nets) = take_string_list(&mut split, "ips")? {
                ensure!(!nets.is_empty(), "{ctx}: ips must not be empty");
                ensure!(nets.len() <= 64, "{ctx}: at most 64 networks per block");
                let nets = nets
                    .iter()
                    .map(|n| IpNet::parse(n))
                    .collect::<Result<Vec<_>>>()
                    .with_context(|| format!("{ctx}: attribute ips"))?;
                set(Selector::Ips(nets))?;
            }
            if let Some(asns) = take_u64_list(&mut split, "asn")? {
                ensure!(!asns.is_empty(), "{ctx}: asn must not be empty");
                ensure!(
                    asns.iter().all(|a| *a <= u32::MAX as u64),
                    "{ctx}: ASN must fit u32"
                );
                set(Selector::Asn(asns.iter().map(|a| *a as u32).collect()))?;
            }
            let selector = selector.with_context(|| format!("{ctx}: a selector is required"))?;

            let every = match split.take_duration_secs("every")? {
                Some(every) => {
                    ensure!(
                        matches!(selector, Selector::Names(_)),
                        "{ctx}: every applies only to name selectors"
                    );
                    ensure!(
                        every >= crate::sticky::MIN_EVERY,
                        "{ctx}: every must be at least {}s",
                        crate::sticky::MIN_EVERY.as_secs()
                    );
                    every
                }
                None => crate::sticky::DEFAULT_EVERY,
            };

            let via = match split.take_raw("via")? {
                None => bail!("{ctx}: via is required"),
                // `via = local`: a bare HCL identifier, not a string.
                Some(hcl::Expression::Variable(variable)) if variable.as_str() == "local" => {
                    Via::Local
                }
                Some(expr) => {
                    let value = literal(&expr)
                        .with_context(|| format!("{ctx}: via must be local or a list of labels"))?;
                    let labels = value
                        .as_array()
                        .with_context(|| format!("{ctx}: via must be local or a list of labels"))?
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .map(str::to_owned)
                                .with_context(|| format!("{ctx}: via must be a list of strings"))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    ensure!(!labels.is_empty(), "{ctx}: via must not be empty");
                    Via::Servers(labels)
                }
            };
            split.finish()?;
            out.push(StickyBlock {
                label,
                selector,
                via,
                every,
            });
        }
        self.split.blocks = blocks;
        Ok(out)
    }

    fn finish(mut self) -> Result<()> {
        for (name, split) in self.singletons.drain(..) {
            split.finish().map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
        }
        // server/sticky blocks were validated and consumed by servers()/stickies();
        // leftovers in `split` are exactly those ordered blocks.
        self.log_level_attrs.finish()?;
        Ok(())
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 32
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn take_host(split: &mut Split, key: &str) -> Result<Option<String>> {
    split
        .take_string(key)?
        .map(|host| crate::server_spec::normalize_host(&host))
        .transpose()
}

fn take_u16_opt(split: &mut Split, key: &str) -> Result<Option<u16>> {
    split.take_u16(key)
}

fn take_u32_opt(split: &mut Split, key: &str) -> Result<Option<u32>> {
    split
        .take_u64(key)?
        .map(|n| {
            u32::try_from(n).map_err(|_| {
                anyhow::anyhow!("{}: attribute {key} must be 0..=4294967295", split.ctx)
            })
        })
        .transpose()
}

fn take_host_key(
    split: &mut Split,
    key: &str,
) -> Result<Option<russh::keys::ssh_key::Fingerprint>> {
    match split.take_string(key)? {
        None => Ok(None),
        Some(text) => crate::server_spec::parse_host_key(&text)
            .map(Some)
            .with_context(|| format!("{}: attribute {key} expects a SHA256 pin", split.ctx)),
    }
}

fn take_port_range(split: &mut Split, key: &str) -> Result<Option<(u16, u16)>> {
    match split.take_string(key)? {
        None => Ok(None),
        Some(text) => crate::parse_port_range(&text)
            .map_err(anyhow::Error::msg)
            .map(Some)
            .with_context(|| format!("{}: attribute {key}", split.ctx)),
    }
}

fn take_string_list(split: &mut Split, key: &str) -> Result<Option<Vec<String>>> {
    let Some(value) = split.take_value(key)? else {
        return Ok(None);
    };
    value
        .as_array()
        .with_context(|| format!("{}: attribute {key} must be a list of strings", split.ctx))?
        .iter()
        .map(|v| {
            v.as_str().map(str::to_owned).with_context(|| {
                format!("{}: attribute {key} must be a list of strings", split.ctx)
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn take_u64_list(split: &mut Split, key: &str) -> Result<Option<Vec<u64>>> {
    let Some(value) = split.take_value(key)? else {
        return Ok(None);
    };
    value
        .as_array()
        .with_context(|| format!("{}: attribute {key} must be a list", split.ctx))?
        .iter()
        .map(|v| {
            v.as_u64().with_context(|| {
                format!("{}: attribute {key} must be a list of integers", split.ctx)
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}
