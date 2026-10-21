//! Stderr: a full stderr pipe does not block process exit.

use std::{
    io::{ErrorKind, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn full_stderr_does_not_block_process_exit() {
    let (_reader, mut writer) = UnixStream::pair().unwrap();
    writer.set_nonblocking(true).unwrap();
    loop {
        match writer.write(&[0; 4096]) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill stderr: {error}"),
        }
    }
    writer.set_nonblocking(false).unwrap();
    let stderr: OwnedFd = writer.into();
    let mut child = Command::new(env!("CARGO_BIN_EXE_svpn"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap();
    // Linux rejects JSON before TUN creation; macOS rejects the server role.
    let _ = child.stdin.take().unwrap().write_all(b"invalid JSON\n");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("process blocked on stderr");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
