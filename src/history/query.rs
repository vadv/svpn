//! Reading one window of history back for the dashboard.

use anyhow::{Result, bail};
use rusqlite::{ToSql, params_from_iter};
use serde::Serialize;

use super::{
    sample::{LOCAL, Series},
    store::{DAY, HOUR, HOUR_TTL, MINUTE, MINUTE_TTL, Store},
};

/// Points returned per series at most: a longer window comes in coarser buckets.
const MAX_POINTS: u64 = 400;
/// Series returned with points at most.
pub const MAX_TOP: usize = 32;
const DEFAULT_TOP: usize = 8;
const MAX_LINK_ID: usize = 128;
/// The longest window a custom range may span: what the day tier keeps.
const MAX_WINDOW: u64 = 30 * DAY;
/// A window may start this far beyond the age of a tier and still read it:
/// "the last day" is a few seconds more than a day old by the time it is
/// asked for. Its first minutes are then simply missing.
const TIER_SLACK: u64 = 15 * MINUTE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Range {
    Hour,
    Day,
    Week,
    Month,
    /// `[from, to)` in unix seconds, as picked on the dashboard.
    Custom {
        from: u64,
        to: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Link,
    Rule,
    Network,
}

/// One window of one breakdown, as the dashboard asks for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub range: Range,
    pub kind: Kind,
    /// Only the series of this link, when set.
    pub link: Option<String>,
    /// Series with points at most, the busiest first.
    pub top: usize,
}

impl Query {
    /// Parse the query string of `/api/history`. Unknown and repeated
    /// fields are rejected instead of guessed at.
    pub fn parse(query: &str) -> Result<Query> {
        let mut parsed = Query {
            range: Range::Day,
            kind: Kind::Link,
            link: None,
            top: DEFAULT_TOP,
        };
        let mut seen: Vec<&str> = Vec::new();
        let (mut from, mut to) = (None, None);
        for field in query.split('&').filter(|field| !field.is_empty()) {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("history query: expected key=value in {field:?}"))?;
            if seen.contains(&key) {
                bail!("history query: field {key} given twice");
            }
            seen.push(key);
            match (key, value) {
                ("range", "1h") => parsed.range = Range::Hour,
                ("range", "24h") => parsed.range = Range::Day,
                ("range", "7d") => parsed.range = Range::Week,
                ("range", "30d") => parsed.range = Range::Month,
                ("kind", "link") => parsed.kind = Kind::Link,
                ("kind", "rule") => parsed.kind = Kind::Rule,
                ("kind", "network") => parsed.kind = Kind::Network,
                ("top", value) => match value.parse::<usize>() {
                    Ok(top) if (1..=MAX_TOP).contains(&top) => parsed.top = top,
                    _ => bail!("history query: top must be 1..={MAX_TOP}"),
                },
                ("link", value) if is_link_id(value) => parsed.link = Some(value.to_owned()),
                ("from", value) => from = Some(seconds(value)?),
                ("to", value) => to = Some(seconds(value)?),
                _ => bail!("history query: unknown field {field:?}"),
            }
        }
        match (from, to) {
            (None, None) => {}
            (Some(from), Some(to))
                if to > from && to - from <= MAX_WINDOW && !seen.contains(&"range") =>
            {
                parsed.range = Range::Custom { from, to }
            }
            _ => bail!(
                "history query: from and to go together, span at most {MAX_WINDOW} seconds and replace range"
            ),
        }
        Ok(parsed)
    }
}

fn seconds(value: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("history query: from and to are unix seconds"))
}

/// Node ids and rule keys are made of these; anything else is not a series.
fn is_link_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LINK_ID
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".:-_[]".contains(&byte))
}

/// The window a query was answered for and its series, the busiest first.
#[derive(Clone, Debug, Serialize)]
pub struct History {
    /// `1h`, `24h`, `7d`, `30d` or `custom`.
    pub range: &'static str,
    pub kind: &'static str,
    /// Seconds one point covers.
    pub step: u64,
    /// The window, in unix seconds.
    pub from: u64,
    pub to: u64,
    pub series: Vec<SeriesHistory>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SeriesHistory {
    /// `link`, `local`, `rule` or `network`.
    pub kind: &'static str,
    /// Node id of the link; empty for the local exit.
    pub link: String,
    pub rule: Option<String>,
    pub asn: Option<u32>,
    /// Organization of the network from the ASN CSV, for a network the CSV
    /// names; null otherwise.
    pub asn_name: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Active flows over the recorded minutes of the window.
    pub active_avg: f64,
    /// `[start, received bytes, sent bytes]`. A bucket without a point was
    /// not recorded, or lies before the start of history.
    pub points: Vec<[u64; 3]>,
}

impl Store {
    /// Answer one query from the tier that covers its range.
    pub fn query(&self, query: &Query, now: u64) -> Result<History> {
        let (table, step, from, to) = match query.range {
            Range::Hour => (
                "minute",
                MINUTE,
                (now / MINUTE * MINUTE).saturating_sub(HOUR),
                now / MINUTE * MINUTE,
            ),
            Range::Day => (
                "minute",
                MINUTE,
                (now / MINUTE * MINUTE).saturating_sub(DAY),
                now / MINUTE * MINUTE,
            ),
            Range::Week => (
                "hour",
                HOUR,
                (now / HOUR * HOUR).saturating_sub(7 * DAY),
                now / HOUR * HOUR,
            ),
            Range::Month => (
                "day",
                DAY,
                (now / DAY * DAY).saturating_sub(30 * DAY),
                now / DAY * DAY,
            ),
            // Minutes are kept a day and hours a week: the age of the window's
            // start picks the tier that still holds its rows.
            Range::Custom { from, to } => {
                let (table, step) = match now.saturating_sub(from) {
                    age if age <= MINUTE_TTL + TIER_SLACK => ("minute", MINUTE),
                    age if age <= HOUR_TTL + TIER_SLACK => ("hour", HOUR),
                    _ => ("day", DAY),
                };
                let to = to.min(now);
                (table, step, from - from % step, to - to % step)
            }
        };
        let empty = History {
            range: query.range.name(),
            kind: query.kind.name(),
            step,
            from,
            to,
            series: Vec::new(),
        };
        // A window shorter than one step, or lying in the future, holds nothing.
        if to <= from {
            return Ok(empty);
        }
        let bucket = step * ((to - from) / step).div_ceil(MAX_POINTS);
        let kinds = match query.kind {
            Kind::Link => "0, 2",
            Kind::Rule => "1",
            // Thousands of networks had no traffic in the window: they are not ranked.
            Kind::Network => "3",
        };
        let having = match query.kind {
            Kind::Network => " HAVING SUM(m.rx_bytes) + SUM(m.tx_bytes) > 0",
            _ => "",
        };
        let link = query.link.as_deref();
        // The gauge of a coarse row is the mean over its `minutes` minutes;
        // buckets are averaged with as much weight as they hold minutes.
        let (active, weight) = match step {
            MINUTE => ("AVG(m.active)", "COUNT(*)"),
            _ => (
                "SUM(m.active_avg * m.minutes) / MAX(SUM(m.minutes), 1)",
                "SUM(m.minutes)",
            ),
        };
        let sql = format!(
            "WITH top AS (\
             SELECT m.series AS id, SUM(m.rx_bytes) + SUM(m.tx_bytes) AS bytes \
             FROM {table} m JOIN series s ON s.id = m.series \
             WHERE m.ts >= ?1 AND m.ts < ?2 AND s.kind IN ({kinds}){} \
             GROUP BY m.series{having} ORDER BY bytes DESC, m.series LIMIT ?{}) \
             SELECT s.kind, s.link, s.rule, s.asn, (m.ts / ?3) * ?3, SUM(m.rx_bytes), SUM(m.tx_bytes), {active}, {weight}, n.name \
             FROM top JOIN series s ON s.id = top.id JOIN {table} m ON m.series = s.id \
             LEFT JOIN names n ON s.kind = 3 AND n.asn = s.asn \
             WHERE m.ts >= ?1 AND m.ts < ?2 \
             GROUP BY s.id, 5 ORDER BY MAX(top.bytes) DESC, s.id",
            link.map_or("", |_| " AND s.link = ?4"),
            if link.is_some() { 5 } else { 4 },
        );
        let mut values: Vec<Box<dyn ToSql>> = vec![
            Box::new(signed(from)),
            Box::new(signed(to)),
            Box::new(signed(bucket)),
        ];
        if let Some(link) = link {
            values.push(Box::new(link.to_owned()));
        }
        values.push(Box::new(signed(query.top)));

        let mut statement = self.connection().prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(values), |row| {
            Ok(QueryRow {
                kind: row.get(0)?,
                link: row.get(1)?,
                rule: row.get(2)?,
                asn: row.get(3)?,
                point: [row.get(4)?, row.get(5)?, row.get(6)?],
                active_avg: row.get(7)?,
                weight: row.get(8)?,
                asn_name: row.get(9)?,
            })
        })?;
        let mut series: Vec<SeriesHistory> = Vec::new();
        // Per series: the gauge times its weight, and the weight.
        let mut gauges: Vec<(f64, u64)> = Vec::new();
        let mut current: Option<Series> = None;
        for row in rows {
            let row = row?;
            let asn = u32::try_from(row.asn).unwrap_or(0);
            let Some(key) = Series::from_columns(row.kind, &row.link, &row.rule, asn) else {
                continue;
            };
            let point = row.point.map(unsigned);
            // Rows of one series come together, the busiest series first.
            if current.as_ref() == Some(&key) {
                if let Some(last) = series.last_mut() {
                    last.rx_bytes += point[1];
                    last.tx_bytes += point[2];
                    last.points.push(point);
                }
            } else {
                series.push(SeriesHistory {
                    kind: key.name(),
                    link: row.link,
                    rule: matches!(key, Series::Rule { .. }).then(|| key.rule().to_owned()),
                    asn: match key {
                        Series::Network { asn, .. } => Some(asn),
                        _ => None,
                    },
                    asn_name: match key {
                        Series::Network { .. } => row.asn_name.filter(|name| !name.is_empty()),
                        _ => None,
                    },
                    rx_bytes: point[1],
                    tx_bytes: point[2],
                    active_avg: 0.0,
                    points: vec![point],
                });
                gauges.push((0., 0));
                current = Some(key);
            }
            if let Some(gauge) = gauges.last_mut() {
                let weight = unsigned(row.weight);
                gauge.0 += row.active_avg * weight as f64;
                gauge.1 += weight;
            }
        }
        for (series, gauge) in series.iter_mut().zip(gauges) {
            series.active_avg = match gauge.1 {
                0 => 0.,
                weight => gauge.0 / weight as f64,
            };
        }
        Ok(History {
            range: query.range.name(),
            kind: query.kind.name(),
            step: bucket,
            from,
            to,
            series,
        })
    }
}

struct QueryRow {
    kind: i64,
    link: String,
    rule: String,
    asn: i64,
    point: [i64; 3],
    active_avg: f64,
    /// Minutes the gauge of the row stands for.
    weight: i64,
    asn_name: Option<String>,
}

impl Range {
    pub fn name(self) -> &'static str {
        match self {
            Range::Hour => "1h",
            Range::Day => "24h",
            Range::Week => "7d",
            Range::Month => "30d",
            Range::Custom { .. } => "custom",
        }
    }
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Link => "link",
            Kind::Rule => "rule",
            Kind::Network => "network",
        }
    }
}

impl Series {
    /// `link`, `local`, `rule` or `network`.
    pub fn name(&self) -> &'static str {
        match self {
            Series::Link { .. } => "link",
            Series::Local => LOCAL,
            Series::Rule { .. } => "rule",
            Series::Network { .. } => "network",
        }
    }
}

fn signed(value: impl TryInto<i64>) -> i64 {
    value.try_into().unwrap_or(i64::MAX)
}

fn unsigned(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}
