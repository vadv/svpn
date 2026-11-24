//! The one thread that owns the database connection.
//!
//! The hub hands over minute rows without waiting; a query comes back
//! through a oneshot. A failing store shows up in the status and in the log,
//! never in the VPN.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use serde::Serialize;
use tokio::sync::oneshot;

use super::{
    names,
    query::{History, Query},
    recover::{self, Outcome},
    sample::Row,
    store::{MAX_FILE_BYTES, Store},
};
use crate::{error, info, warn};

/// Minutes the thread keeps while writes fail; the oldest are dropped beyond it.
const QUEUE: usize = 120;
/// Minutes in flight on top of those: the hub never waits for the store.
const CHANNEL: usize = 4;
/// A database that failed to open is tried again no sooner, in seconds.
const RETRY_OPEN: u64 = 600;
/// A persisting failure is logged at most this often, in seconds.
const LOG_EVERY: u64 = 600;
/// Bound on the join at shutdown.
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

enum Command {
    Minute(u64, Vec<Row>),
    Query(Box<Query>, oneshot::Sender<Result<History>>),
    Stop,
}

/// What the dashboard shows of the history database.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Status {
    /// `checking`, `ok` or `error`.
    pub state: &'static str,
    pub error: String,
    /// Bytes of the database file on disk.
    pub bytes: u64,
}

/// Handle of the history thread, shared through an `Arc`.
pub struct Recorder {
    commands: SyncSender<Command>,
    thread: Mutex<Option<JoinHandle<()>>>,
    status: Arc<RwLock<Status>>,
    /// Minutes the channel had no room for, and when that was last logged.
    dropped: AtomicU64,
    dropped_logged_at: AtomicU64,
}

impl Recorder {
    /// Start the history thread, with the ASN CSV to name networks from
    /// when there is one. It cannot fail: until the database is open the
    /// status stays `checking` and minutes queue up in the thread.
    pub fn spawn(path: PathBuf, asn_csv: Option<PathBuf>) -> Arc<Recorder> {
        let (commands, inbox) = mpsc::sync_channel(CHANNEL);
        let status = Arc::new(RwLock::new(Status {
            state: "checking",
            ..Status::default()
        }));
        let thread = thread::Builder::new()
            .name("history".into())
            .spawn({
                let status = Arc::clone(&status);
                move || run(&path, asn_csv.as_deref(), &inbox, &status)
            })
            .inspect_err(|error| {
                // No thread to own the database: say so instead of pretending.
                error!("history: thread could not start: {error}");
                set(&status, "error", "history thread could not start", 0);
            })
            .ok();
        Arc::new(Recorder {
            commands,
            thread: Mutex::new(thread),
            status,
            dropped: AtomicU64::new(0),
            dropped_logged_at: AtomicU64::new(0),
        })
    }

    /// Hand one minute over without waiting. A thread that is behind loses
    /// the minute: the log says so, at most once in ten minutes.
    pub fn record(&self, minute: u64, rows: Vec<Row>) {
        match self.commands.try_send(Command::Minute(minute, rows)) {
            Ok(()) => return,
            // The thread is gone: say so where the dashboard looks.
            Err(TrySendError::Disconnected(_)) => {
                if self
                    .status
                    .read()
                    .is_ok_and(|status| status.state != "error")
                {
                    error!("history: store is not running; minutes are not recorded");
                    set(&self.status, "error", "history store is not running", 0);
                }
                return;
            }
            Err(TrySendError::Full(_)) => {}
        }
        let now = unix();
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        let logged_at = self.dropped_logged_at.load(Ordering::Relaxed);
        if now.saturating_sub(logged_at) >= LOG_EVERY
            && self
                .dropped_logged_at
                .compare_exchange(logged_at, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            warn!("history: store is behind; {dropped} minutes were not recorded");
            self.dropped.store(0, Ordering::Relaxed);
        }
    }

    /// Ask the history thread. The reply arrives when the database answered;
    /// a dropped reply means the thread is gone.
    pub fn query(&self, query: Query) -> Result<oneshot::Receiver<Result<History>>> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .try_send(Command::Query(Box::new(query), reply))
            .map_err(|error| match error {
                TrySendError::Full(_) => anyhow!("history store is busy"),
                TrySendError::Disconnected(_) => anyhow!("history store is not running"),
            })?;
        Ok(answer)
    }

    pub fn status(&self) -> Status {
        self.status
            .read()
            .map(|status| status.clone())
            .unwrap_or_default()
    }

    /// Stop the thread and wait for its last write. The wait is bounded: a
    /// stuck disk cannot hold the shutdown.
    pub fn close(&self) {
        let thread = self.thread.lock().ok().and_then(|mut thread| thread.take());
        let Some(thread) = thread else {
            return;
        };
        let deadline = Instant::now() + JOIN_TIMEOUT;
        loop {
            match self.commands.try_send(Command::Stop) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => break,
                Err(TrySendError::Full(_)) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(TrySendError::Full(_)) => break,
            }
        }
        // The join runs elsewhere: it ends when the thread does, or never.
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            let _ = thread.join();
            let _ = done.send(());
        });
        if finished.recv_timeout(JOIN_TIMEOUT).is_err() {
            warn!(
                "history: store did not stop within {}s; its thread is left behind",
                JOIN_TIMEOUT.as_secs()
            );
        }
    }
}

/// The thread's own state.
#[derive(Default)]
struct Session {
    store: Option<Store>,
    /// Minutes not written yet: the next flush takes them all.
    queue: VecDeque<(u64, Vec<Row>)>,
    /// Unix time of the next attempt to open the database.
    retry_at: u64,
    /// The failure logged last, and when.
    logged: Option<(String, u64)>,
    /// Minutes dropped from the queue since that was logged last, and when.
    dropped: (u64, Option<u64>),
}

impl Session {
    fn open(&mut self, path: &Path, now: u64, status: &RwLock<Status>) {
        if self.store.is_some() || now < self.retry_at {
            return;
        }
        match recover::open(path) {
            Ok(opened) => {
                let name = path.display();
                match opened.outcome {
                    Outcome::Created => info!("history: new database {name}"),
                    Outcome::Opened {
                        rows: [minute, hour, day],
                    } => {
                        info!(
                            "history: database {name} holds {minute} minute, {hour} hour and {day} day rows"
                        );
                    }
                    Outcome::Recovered { rows, reason } => warn!(
                        "history: database damaged ({reason}); kept the {rows} rows that still read"
                    ),
                    Outcome::Discarded { reason } => {
                        warn!("history: database discarded ({reason}); started an empty one")
                    }
                }
                self.logged = None;
                set(status, "ok", "", opened.store.file_bytes());
                self.store = Some(opened.store);
            }
            Err(error) => {
                self.retry_at = now + RETRY_OPEN;
                self.failed(error, now, status);
            }
        }
    }

    fn flush(&mut self, now: u64, asn_csv: Option<&Path>, status: &RwLock<Status>) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        if self.queue.is_empty() {
            return;
        }
        let oldest = self.queue.front().map(|(minute, _)| *minute);
        let written = match store.append(self.queue.iter(), oldest, now) {
            Ok(trimmed) => {
                if let Some(trimmed) = trimmed {
                    warn!(
                        "history: file over {} MiB; {trimmed}",
                        MAX_FILE_BYTES / (1024 * 1024)
                    );
                }
                self.queue.clear();
                self.logged = None;
                set(status, "ok", "", store.file_bytes());
                true
            }
            Err(error) => {
                let waiting = self.queue.len();
                let error = error.context(match waiting {
                    1 => "1 minute is waiting".to_owned(),
                    minutes => format!("{minutes} minutes are waiting"),
                });
                self.failed(error, now, status);
                false
            }
        };
        if written {
            self.name_networks(asn_csv, now, status);
        }
    }

    /// Name the networks the file holds and the CSV may still tell: one pass
    /// over the ASN CSV for all of them. A missing or unreadable CSV costs
    /// the names, never the history.
    fn name_networks(&mut self, asn_csv: Option<&Path>, now: u64, status: &RwLock<Status>) {
        let wanted = match self.store.as_mut() {
            Some(store) => match store.unnamed_networks() {
                Ok(wanted) => wanted,
                Err(error) => return self.failed(error, now, status),
            },
            None => return,
        };
        if wanted.is_empty() {
            return;
        }
        let Some(csv) = asn_csv else {
            return;
        };
        let names = match names::lookup(csv, &wanted) {
            Ok(names) => names,
            Err(error) => {
                return self.warned(format!("history: network names unavailable: {error}"), now);
            }
        };
        // A network the CSV does not name gets an empty name, so that the
        // file is not read again for it.
        let names: Vec<(u32, String)> = wanted
            .into_iter()
            .map(|asn| {
                let name = names
                    .iter()
                    .find(|(known, _)| *known == asn)
                    .map_or_else(String::new, |(_, name)| name.clone());
                (asn, name)
            })
            .collect();
        if let Some(store) = self.store.as_mut()
            && let Err(error) = store.name_networks(&names)
        {
            self.failed(error, now, status);
        }
    }

    /// Keep a failure for the status. It is logged when it is new, then at
    /// most once in ten minutes.
    fn failed(&mut self, error: anyhow::Error, now: u64, status: &RwLock<Status>) {
        let message = format!("{error:#}");
        if !self.repeated(&message, now) {
            error!("history: {message}");
        }
        set(status, "error", &message, 0);
    }

    /// Log a shortcoming that is no failure to record, at most once in ten
    /// minutes while it stays the same.
    fn warned(&mut self, message: String, now: u64) {
        if !self.repeated(&message, now) {
            warn!("{message}");
        }
    }

    /// Whether this very message was logged less than ten minutes ago. A
    /// message that was not repeated becomes the one logged last.
    fn repeated(&mut self, message: &str, now: u64) -> bool {
        let repeated = self
            .logged
            .as_ref()
            .is_some_and(|(last, at)| last == message && now.saturating_sub(*at) < LOG_EVERY);
        if !repeated {
            self.logged = Some((message.to_owned(), now));
        }
        repeated
    }
}

fn run(path: &Path, asn_csv: Option<&Path>, inbox: &Receiver<Command>, status: &RwLock<Status>) {
    let mut session = Session::default();
    session.open(path, unix(), status);
    loop {
        let now = unix();
        // Minutes pile up only while writes fail: take them all before flushing.
        let received = if session.queue.is_empty() {
            inbox.recv().map_err(|_| TryRecvError::Disconnected)
        } else {
            inbox.try_recv()
        };
        match received {
            Ok(Command::Minute(minute, rows)) => {
                session.queue.push_back((minute, rows));
                while session.queue.len() > QUEUE {
                    session.queue.pop_front();
                    session.dropped.0 += 1;
                }
                if session.dropped.0 > 0
                    && session
                        .dropped
                        .1
                        .is_none_or(|at| now.saturating_sub(at) >= LOG_EVERY)
                {
                    warn!(
                        "history: store is behind; {} minutes were dropped",
                        session.dropped.0
                    );
                    session.dropped = (0, Some(now));
                }
            }
            Ok(Command::Query(query, reply)) => {
                // Without a database the dashboard gets the reason, not a bare refusal.
                let answer = session.store.as_ref().map_or_else(
                    || {
                        Err(anyhow!(
                            "{}",
                            session
                                .logged
                                .as_ref()
                                .map_or("history database is not open", |(message, _)| message
                                    .as_str())
                        ))
                    },
                    |store| store.query(&query, now),
                );
                let _ = reply.send(answer);
                continue;
            }
            Ok(Command::Stop) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
        session.open(path, now, status);
        session.flush(now, asn_csv, status);
    }
    // What the hub handed over is written before the file is closed.
    session.flush(unix(), asn_csv, status);
    if let Some(store) = session.store.take()
        && let Err(error) = store.close()
    {
        error!("history: {error:#}");
    }
}

fn set(status: &RwLock<Status>, state: &'static str, error: &str, bytes: u64) {
    if let Ok(mut status) = status.write() {
        *status = Status {
            state,
            error: error.to_owned(),
            bytes,
        };
    }
}

fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |passed| passed.as_secs())
}
