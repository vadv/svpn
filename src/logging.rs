use std::{
    io::{self, Write},
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

static SINK: OnceLock<mpsc::SyncSender<Record>> = OnceLock::new();
pub static MAX_LEVEL: AtomicU8 = AtomicU8::new(2);
static START: OnceLock<Instant> = OnceLock::new();

/// Log level; the value order defines the filter.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lower")]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    pub fn as_u8(self) -> u8 {
        match self {
            Level::Error => 0,
            Level::Warn => 1,
            Level::Info => 2,
            Level::Debug => 3,
        }
    }
}

enum Record {
    Text(String),
    Flush(mpsc::Sender<()>),
}

/// Whether the level is allowed after applying `--log-level`.
pub fn enabled(level: Level) -> bool {
    level.as_u8() <= MAX_LEVEL.load(Ordering::Relaxed)
}

pub fn init(level: Level) -> io::Result<()> {
    MAX_LEVEL.store(level.as_u8(), Ordering::Relaxed);
    let (send, receive) = mpsc::sync_channel(128);
    std::thread::Builder::new()
        .name("stderr".into())
        .spawn(move || {
            for record in receive {
                // The critical section is a single write to stderr: holding
                // the lock longer would block panic!/eprintln! of other threads.
                let mut stderr = io::stderr().lock();
                match record {
                    Record::Text(text) => {
                        let _ = stderr.write_all(text.as_bytes());
                    }
                    Record::Flush(done) => {
                        let _ = done.send(());
                    }
                }
            }
        })?;
    let _ = SINK.set(send);
    Ok(())
}

/// Seconds since the first journal record — for the final session summary.
pub fn elapsed_secs() -> f64 {
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

pub fn write(text: String) {
    let start = START.get_or_init(Instant::now);
    if let Some(sink) = SINK.get() {
        // Logging must not delay control, heartbeat, or resource release.
        let _ = sink.try_send(Record::Text(format_record(
            start.elapsed().as_secs_f64(),
            &text,
        )));
    }
}

pub fn format_record(elapsed: f64, text: &str) -> String {
    format!(
        "t+{elapsed:>9.3}s {}\n",
        text.trim_end_matches(['\r', '\n'])
    )
}

pub fn finish() {
    let Some(sink) = SINK.get() else {
        return;
    };
    let (send, receive) = mpsc::channel();
    if sink.try_send(Record::Flush(send)).is_ok() {
        let _ = receive.recv_timeout(Duration::from_millis(50));
    }
}

#[macro_export]
macro_rules! log {
    ($level:ident, $($arg:tt)*) => {{
        let level = $crate::logging::Level::$level;
        if $crate::logging::enabled(level) {
            $crate::logging::write(format!($($arg)*));
        }
    }};
}
pub(crate) use log;

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::logging::log!(Error, $($arg)*) };
}
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::logging::log!(Warn, $($arg)*) };
}
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::logging::log!(Info, $($arg)*) };
}
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::logging::log!(Debug, $($arg)*) };
}
