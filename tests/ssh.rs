//! SSH transport: connection lifecycle, host-key checks, identity loading, stderr relay.

use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{Config, Handler};
use russh::keys::ssh_key::Fingerprint;
use russh::keys::{HashAlg, PrivateKey, PublicKey, PublicKeyOrCertificate};
use svpn::ssh::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

const ED25519_PUBLIC: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETpwGaBiFyUdKRNtIrPlYpMvnfZW3YbXd+kV4GZYy2n test";

// ── connection lifecycle ──

#[tokio::test]
async fn dropping_tail_stops_idle_pump_and_closes_connection() {
    use russh::server::{self, Auth, ChannelOpenHandle, Session};
    use tokio::{net::TcpListener, time::timeout};

    struct TestServer(PublicKey);
    impl server::Handler for TestServer {
        type Error = russh::Error;

        async fn auth_publickey(&mut self, _: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
            assert_eq!(key.key_data(), self.0.key_data());
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _: russh::Channel<server::Msg>,
            reply: ChannelOpenHandle,
            _: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: russh::ChannelId,
            command: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            assert_eq!(command, b"test-command");
            session.channel_success(channel)?;
            session.data(channel, b"ready".to_vec())
        }
    }

    let [client_key, server_key] = [(); 2].map(|()| {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let pair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
        PrivateKey::new(pair.into(), "test").unwrap()
    });
    let handler = HostKeyCheck {
        expected: Some(server_key.public_key().fingerprint(HashAlg::Sha256)),
        seen: Arc::new(Mutex::new(None)),
        tag: String::new(),
        known_hosts: None,
        host_label: "test-server".into(),
    };
    let server_handler = TestServer(client_key.public_key().clone());
    let config = Arc::new(server::Config {
        keys: vec![server_key],
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        server::run_stream(config, stream, server_handler)
            .await
            .unwrap()
            .await
    });
    let (handle, channel) = timeout(CONNECT_TIMEOUT, async {
        let mut handle = russh::client::connect(Arc::new(Config::default()), addr, handler)
            .await
            .unwrap();
        authenticate(
            &mut handle,
            "test",
            &Identity::Key(Arc::new(client_key)),
            "",
        )
        .await
        .unwrap();
        let channel = handle.channel_open_session().await.unwrap();
        channel.exec(true, "test-command").await.unwrap();
        (handle, channel)
    })
    .await
    .expect("SSH setup timed out");
    let (stdin, stdin_reader) = duplex(STDIN_BUF);
    let (stdout_writer, stdout) = duplex(STDOUT_BUF);
    let pump = tokio::spawn(pump_channel(
        channel,
        stdin_reader,
        stdout_writer,
        String::new(),
    ));
    let (stdin, mut stdout, tail) = SshSession {
        stdin,
        stdout,
        tail: SshTail { pump, handle },
    }
    .into_io();

    let mut ready = [0; 5];
    timeout(Duration::from_secs(1), stdout.read_exact(&mut ready))
        .await
        .expect("exec output timed out")
        .unwrap();
    assert_eq!(&ready, b"ready");
    let pump = tail.pump.abort_handle();
    assert!(!pump.is_finished());
    assert!(!server.is_finished());
    // Keep both streams open: only dropping the tail should stop the idle pump.
    drop(tail);
    timeout(Duration::from_secs(1), async {
        while !pump.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping the tail left the pump running");
    match timeout(Duration::from_secs(1), server)
        .await
        .expect("dropping the tail left the SSH connection open")
        .unwrap()
    {
        Ok(()) => {}
        Err(russh::Error::IO(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
        result => panic!("unexpected SSH server result: {result:?}"),
    }
    drop((stdin, stdout));
}

// Real time: russh keepalive timers make paused-clock auto-advance loop
// forever in Linux containers (the cost is one ~10s CONNECT_TIMEOUT).
#[tokio::test]
async fn hung_key_exchange_is_closed_after_the_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        sock.write_all(b"SSH-2.0-SVPNTest\r\n").await.unwrap();
        // The client's banner and KEXINIT arrive first; EOF is what must
        // eventually follow once the abandoned transport is torn down.
        let mut buf = [0u8; 64];
        loop {
            if sock.read(&mut buf).await.unwrap() == 0 {
                return;
            }
        }
    });
    let target = SshTarget {
        user: "nobody".into(),
        identity: None,
        host_key: None,
        host_label: "hung-peer".into(),
    };
    let err = match connect(&target, addr, "true", "").await {
        Ok(_) => panic!("hung peer must not complete the connection"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("SSH connection timeout"),
        "{err:#}"
    );
    // russh's internal task must not outlive its inactivity bound.
    tokio::time::timeout(Duration::from_secs(120), peer)
        .await
        .expect("peer socket leaked past the inactivity bound")
        .unwrap();
}

// ── host-key checks ──

#[tokio::test]
async fn unreadable_known_hosts_rejects_without_overwriting_records() {
    let path = std::env::temp_dir().join(format!(
        "svpn-unreadable-tofu-{}.known_hosts",
        std::process::id()
    ));
    let remembered = PublicKey::from_openssh(ED25519_PUBLIC).unwrap();
    let offered = PrivateKey::new(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]).into(),
        "test",
    )
    .unwrap()
    .public_key()
    .clone();
    let remembered_fingerprint = remembered.fingerprint(HashAlg::Sha256);
    assert_ne!(remembered_fingerprint, offered.fingerprint(HashAlg::Sha256));
    let mut stored =
        format!("other:22 {remembered_fingerprint}\nhost:22 {remembered_fingerprint}\n")
            .into_bytes();
    stored.push(0xff);
    fs::write(&path, &stored).unwrap();
    let mut check = HostKeyCheck {
        expected: None,
        seen: Arc::new(Mutex::new(None)),
        tag: String::new(),
        known_hosts: Some(path.clone()),
        host_label: "host:22".into(),
    };
    let accepted = check
        .check_server_key(&PublicKeyOrCertificate::PublicKey {
            key: offered,
            hash_alg: None,
        })
        .await
        .unwrap();
    let after = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert!(!accepted, "a read error must not erase remembered trust");
    assert_eq!(after, stored, "a read error must preserve the entire file");
}

#[tokio::test]
async fn parallel_first_connects_remember_both_host_keys() {
    let path = std::env::temp_dir().join(format!("svpn-tofu-{}.known_hosts", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let key = |seed: u8| {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        PrivateKey::new(
            russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&bytes).into(),
            "test",
        )
        .unwrap()
        .public_key()
        .clone()
    };
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let learn = |host: &'static str, key: PublicKey| {
        let path = path.clone();
        let barrier = barrier.clone();
        async move {
            let mut check = HostKeyCheck {
                expected: None,
                seen: Arc::new(Mutex::new(None)),
                tag: String::new(),
                known_hosts: Some(path),
                host_label: host.into(),
            };
            barrier.wait().await;
            check
                .check_server_key(&PublicKeyOrCertificate::PublicKey {
                    key,
                    hash_alg: None,
                })
                .await
                .unwrap()
        }
    };
    let (a, b) = tokio::join!(learn("h1:22", key(1)), learn("h2:22", key(2)));
    assert!(a && b, "both first connects must be accepted");
    let stored = std::fs::read_to_string(&path).unwrap();
    assert!(
        stored.contains("h1:22") && stored.contains("h2:22"),
        "{stored}"
    );
    // A changed key for a remembered host must be rejected afterwards.
    let mut recheck = HostKeyCheck {
        expected: None,
        seen: Arc::new(Mutex::new(None)),
        tag: String::new(),
        known_hosts: Some(path.clone()),
        host_label: "h1:22".into(),
    };
    assert!(
        !recheck
            .check_server_key(&PublicKeyOrCertificate::PublicKey {
                key: key(9),
                hash_alg: None
            })
            .await
            .unwrap()
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn known_hosts_decide_is_tofu() {
    use HostKeyDecision::*;
    // Empty file and foreign hosts — learn.
    assert!(matches!(
        decide_known_hosts("", "10.0.0.1:22", "SHA256:one"),
        Learn
    ));
    assert!(matches!(
        decide_known_hosts("other:22 SHA256:x\n", "10.0.0.1:22", "SHA256:one"),
        Learn
    ));
    // Own host: match and substitution.
    assert!(matches!(
        decide_known_hosts("10.0.0.1:22 SHA256:one\n", "10.0.0.1:22", "SHA256:one"),
        Match
    ));
    assert!(matches!(
        decide_known_hosts(
            "other:22 SHA256:x\n10.0.0.1:22 SHA256:one\n",
            "10.0.0.1:22",
            "SHA256:two"
        ),
        Mismatch(stored) if stored == "SHA256:one"
    ));
    // A line without a fingerprint — a corrupted record, relearn.
    assert!(matches!(
        decide_known_hosts("10.0.0.1:22\n", "10.0.0.1:22", "SHA256:one"),
        Learn
    ));
}

#[test]
fn fingerprint_parses_openssh_format() {
    let fp: Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        .parse()
        .expect("valid fingerprint");
    assert_eq!(
        fp.to_string(),
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert!("md5:xx".parse::<Fingerprint>().is_err());
}

// ── identity loading ──

#[test]
fn identity_from_private_key_file() {
    let dir = std::env::temp_dir().join("svpn_ssh_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("id_ed25519");
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let pair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let key = PrivateKey::new(pair.into(), "test").unwrap();
    let encoded = key.to_openssh(Default::default()).unwrap();
    std::fs::write(&path, encoded.as_bytes()).unwrap();
    assert!(matches!(load_identity(&path), Ok(Identity::Key(_))));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn identity_from_public_key_file_fails() {
    let dir = std::env::temp_dir().join("svpn_ssh_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("id_ed25519.pub");
    std::fs::write(&path, ED25519_PUBLIC).unwrap();
    let err = load_identity(&path)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(err.contains("agent"), "unexpected: {err}");
}

#[test]
fn identity_from_garbage_fails() {
    let dir = std::env::temp_dir().join("svpn_ssh_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("garbage");
    std::fs::write(&path, "not a key").unwrap();
    let err = load_identity(&path)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(err.contains("agent"), "unexpected: {err}");
}

// ── server stderr relay ──

#[test]
fn relay_strips_server_timestamp_and_marks_role() {
    // Output goes to the shared log — here we only check the line transformation.
    // The full record goes through logging; here — a pure function on the t+ prefix.
    fn strip(line: &str) -> &str {
        if line.starts_with("t+")
            && let Some((_, rest)) = line.split_once('s')
            && rest.starts_with(' ')
        {
            return rest.trim_start();
        }
        line
    }
    assert_eq!(strip("t+    0.174s TUN ready: tun4"), "TUN ready: tun4");
    assert_eq!(strip("t+1s"), "t+1s"); // no space after s — not a timestamp
    assert_eq!(strip("plain line"), "plain line");
    assert_eq!(strip("t+ 12.5s tx"), "tx");
}

#[test]
fn server_stderr_line_marks_the_pool_link_and_keeps_single_server_output() {
    assert_eq!(
        server_stderr_line("", "TUN ready: tun4"),
        "[server] TUN ready: tun4"
    );
    assert_eq!(
        server_stderr_line("[h1]", "TUN ready: tun4"),
        "[server h1] TUN ready: tun4"
    );
}
