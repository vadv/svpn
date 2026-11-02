//! Finite SSH exec: channel windows, EOF, exit status and bounded output.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use russh::{
    ChannelId,
    keys::{HashAlg, PrivateKey, PublicKey},
    server::{self, Auth, ChannelOpenHandle, Session},
};
use svpn::ssh::{self, HostKeyCheck, Identity};
use tokio::net::TcpListener;

struct TestServer {
    client_key: PublicKey,
    command: Vec<u8>,
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, _: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        assert_eq!(key.key_data(), self.client_key.key_data());
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
        channel: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.command = command.to_vec();
        session.channel_success(channel)?;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self.command.as_slice() {
            b"large" => {
                session.data(channel, vec![b'x'; 512 * 1024])?;
                session.extended_data(channel, 1, b"stderr".to_vec())?;
                session.exit_status_request(channel, 0)?;
            }
            b"nonzero" => session.exit_status_request(channel, 7)?,
            b"no-status" => {}
            b"signal" => {
                session.exit_signal_request(channel, russh::Sig::TERM, false, "killed", "en")?;
            }
            b"zero-no-close" => {
                // Status and EOF without Close: the client must wait for close
                // until its bound expires instead of treating EOF as success.
                session.exit_status_request(channel, 0)?;
                session.eof(channel)?;
                return Ok(());
            }
            command => panic!("unexpected command: {command:?}"),
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

async fn connected() -> russh::client::Handle<HostKeyCheck> {
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
        host_label: "exec-test".into(),
    };
    let server_handler = TestServer {
        client_key: client_key.public_key().clone(),
        command: Vec::new(),
    };
    let config = Arc::new(server::Config {
        keys: vec![server_key],
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        server::run_stream(config, stream, server_handler)
            .await
            .unwrap()
            .await
    });
    let mut handle = russh::client::connect(Arc::new(Default::default()), addr, handler)
        .await
        .unwrap();
    ssh::authenticate(
        &mut handle,
        "test",
        &Identity::Key(Arc::new(client_key)),
        "",
    )
    .await
    .unwrap();
    handle
}

#[tokio::test]
async fn large_input_and_output_cross_channel_windows() {
    let handle = connected().await;
    let output = ssh::exec(
        &handle,
        "large",
        &vec![b'y'; 512 * 1024],
        600 * 1024,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert_eq!(output.status, 0);
    assert_eq!(output.stdout, vec![b'x'; 512 * 1024]);
    assert_eq!(output.stderr, b"stderr");
}

#[tokio::test]
async fn nonzero_status_is_returned_and_missing_status_is_an_error() {
    let handle = connected().await;
    let output = ssh::exec(&handle, "nonzero", b"", 1024, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(output.status, 7);

    let handle = connected().await;
    let error = ssh::exec(&handle, "no-status", b"", 1024, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("without exit status"),
        "{error:#}"
    );
}

#[tokio::test]
async fn output_limit_is_enforced() {
    let handle = connected().await;
    let error = ssh::exec(&handle, "large", b"", 1024, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("exceeds 1024 bytes"),
        "{error:#}"
    );
}

#[tokio::test]
async fn exit_signal_and_zero_status_without_close_are_errors() {
    let handle = connected().await;
    let error = ssh::exec(&handle, "signal", b"", 1024, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("terminated by"), "{error:#}");

    let handle = connected().await;
    let error = ssh::exec(&handle, "zero-no-close", b"", 1024, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("timed out after 1s"),
        "{error:#}"
    );
}
