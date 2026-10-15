//! Report side of the perf benchmark: the interval table (per-stream Mbps and
//! RTT quantiles) and its text (stderr) and JSON (stdout) renderings.

use anyhow::Result;

use super::Outcome;

pub struct IntervalRow {
    pub start: u64,
    pub streams_mbit: Vec<f64>,
    pub sum_mbit: f64,
    pub rtt_p50_ms: Option<f64>,
    pub rtt_p95_ms: Option<f64>,
}

pub struct Summary {
    pub min: f64,
    pub median: f64,
    pub mean: f64,
    pub p95: f64,
    pub cv: f64,
}

/// Full intervals after -O: the partial tail is dropped like iperf3 does.
pub fn rows(outcome: &Outcome) -> Vec<IntervalRow> {
    let full = outcome.elapsed.as_secs() / outcome.interval_secs;
    let omit = (outcome.omit_secs / outcome.interval_secs) as usize;
    let mut result = Vec::new();
    for (interval, bucket) in outcome.buckets.iter().enumerate().take(full as usize) {
        if interval < omit {
            continue;
        }
        let streams_mbit: Vec<f64> = bucket
            .iter()
            .map(|agg| mbit(agg.bytes, outcome.interval_secs))
            .collect();
        let sum_mbit = streams_mbit.iter().sum();
        let mut rtts: Vec<u128> = bucket
            .iter()
            .flat_map(|agg| agg.rtts.iter().map(|rtt| rtt.as_micros()))
            .collect();
        rtts.sort_unstable();
        let pick = |quantile: f64| {
            (!rtts.is_empty()).then(|| {
                let idx = (quantile * (rtts.len() - 1) as f64).ceil() as usize;
                rtts[idx.min(rtts.len() - 1)] as f64 / 1000.0
            })
        };
        result.push(IntervalRow {
            start: interval as u64 * outcome.interval_secs,
            streams_mbit,
            sum_mbit,
            rtt_p50_ms: pick(0.50),
            rtt_p95_ms: pick(0.95),
        });
    }
    result
}

pub fn summary(values: &[f64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let n = sorted.len();
    let mean = values.iter().sum::<f64>() / n as f64;
    let variance = values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / n as f64;
    let pick = |quantile: f64| sorted[((quantile * (n - 1) as f64).ceil() as usize).min(n - 1)];
    Some(Summary {
        min: sorted[0],
        median: pick(0.50),
        mean,
        p95: pick(0.95),
        cv: if mean > 0.0 {
            variance.sqrt() / mean
        } else {
            0.0
        },
    })
}

pub fn mbit(bytes: u64, secs: u64) -> f64 {
    bytes as f64 * 8.0 / (secs as f64 * 1_000_000.0)
}

/// Human-readable report to stderr.
pub fn print_text(outcome: &Outcome) {
    let table = rows(outcome);
    let direction = if outcome.reverse {
        "upload"
    } else {
        "download"
    };
    eprintln!(
        "perf {direction}: {} stream(s), interval {} s",
        table_len(&table),
        outcome.interval_secs
    );
    eprintln!("channel ready: {} ms", outcome.ready_ms);
    for (interval, row) in table.iter().enumerate() {
        let streams = row
            .streams_mbit
            .iter()
            .map(|v| format!("{v:8.2}"))
            .collect::<Vec<_>>()
            .join(" ");
        let rtt = row
            .rtt_p50_ms
            .map(|v| format!("| rtt {:>6.1} ms", v))
            .unwrap_or_default();
        eprintln!(
            "[{:>3}] {:>3}-{} s  {} | sum {:8.2} Mbps {}",
            interval + 1,
            row.start,
            row.start + outcome.interval_secs,
            streams,
            row.sum_mbit,
            rtt
        );
    }
    if let Some(total) = summary(&table.iter().map(|row| row.sum_mbit).collect::<Vec<_>>()) {
        eprintln!(
            "summary: min {:.2} median {:.2} mean {:.2} p95 {:.2} CV {:.2} Mbps",
            total.min, total.median, total.mean, total.p95, total.cv
        );
    } else {
        eprintln!("no full intervals: increase --time or --interval");
    }
}

/// JSON report (in the spirit of iperf3: intervals + end_summary) to stdout.
pub fn print_json(outcome: &Outcome) -> Result<()> {
    use serde_json::json;
    let table = rows(outcome);
    let intervals: Vec<_> = table
        .iter()
        .map(|row| {
            json!({
                "start_s": row.start,
                "streams_mbit": row.streams_mbit,
                "sum_mbit": row.sum_mbit,
                "rtt_p50_ms": row.rtt_p50_ms,
                "rtt_p95_ms": row.rtt_p95_ms,
            })
        })
        .collect();
    let end_summary = |values: &[f64]| {
        summary(values).map(
            |s| json!({"min": s.min, "median": s.median, "mean": s.mean, "p95": s.p95, "cv": s.cv}),
        )
    };
    let stream_count = table_len(&table);
    let mut per_stream = Vec::with_capacity(stream_count);
    for stream in 0..stream_count {
        let values: Vec<f64> = table.iter().map(|row| row.streams_mbit[stream]).collect();
        per_stream.push(json!({"stream": stream, "summary": end_summary(&values)}));
    }
    let sums: Vec<f64> = table.iter().map(|row| row.sum_mbit).collect();
    let report = json!({
        "reverse": outcome.reverse,
        "ready_ms": outcome.ready_ms,
        "elapsed_s": outcome.elapsed.as_secs_f64(),
        "interval_s": outcome.interval_secs,
        "omit_s": outcome.omit_secs,
        "intervals": intervals,
        "end_summary": {"sum": end_summary(&sums), "streams": per_stream},
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn table_len(table: &[IntervalRow]) -> usize {
    table.first().map_or(0, |row| row.streams_mbit.len())
}
