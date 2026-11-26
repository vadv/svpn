//! DNS relay on the control channel: the messages, the line that carries a
//! whole answer, the sending half used outside the session loop, the EOF a
//! too-old server leaves, and both ends of the session dispatch.

mod common;

use std::io::Cursor;

use svpn::control::{self, Control, MAX_LINE, Message, QUEUE};
use svpn::dns;
use svpn::link_io::{self, Event};
use svpn::session::{self, Plane};
use tokio::io::BufReader;

// ── messages ──

#[test]
fn dns_messages_round_trip() {
    let cases = [
        (
            Message::DnsQuery {
                id: 5,
                data: "AAEC".to_owned(),
            },
            r#"{"type":"dns_query","id":5,"data":"AAEC"}"#,
        ),
        (
            Message::DnsAnswer {
                id: 5,
                data: String::new(),
            },
            r#"{"type":"dns_answer","id":5,"data":""}"#,
        ),
    ];
    for (message, json) in cases {
        assert_eq!(serde_json::to_string(&message).unwrap(), json);
        assert!(matches!(
            serde_json::from_str::<Message>(json).unwrap(),
            ref parsed if matches!(parsed, &Message::DnsQuery { .. } | &Message::DnsAnswer { .. })
        ));
        // As everywhere on the channel, an unknown field is a rejected line.
        let extra = json.replace("\"id\":5", "\"id\":5,\"extra\":1");
        assert!(serde_json::from_str::<Message>(&extra).is_err());
    }
}

#[tokio::test]
async fn a_whole_answer_fits_one_line() {
    // The DNS limit over TCP; base64 of it is 87 380 characters.
    let answer = vec![0x5a; 65535];
    let message = Message::DnsAnswer {
        id: 1,
        data: dns::encode(&answer),
    };
    let mut line = serde_json::to_vec(&message).unwrap();
    line.push(b'\n');
    assert!(line.len() < MAX_LINE, "{}", line.len());
    let mut reader = BufReader::new(Cursor::new(line));
    let read = control::read_message(&mut reader).await.unwrap();
    assert!(matches!(
        read,
        Message::DnsAnswer { id: 1, ref data } if dns::decode(data).as_deref() == Some(answer.as_slice())
    ));
}

#[tokio::test]
async fn the_sender_never_waits() {
    let (left, right) = tokio::io::duplex(64);
    let (read, write) = tokio::io::split(left);
    let control = Control::new(read, write);
    let sender = control.sender();
    let query = |id: u64| Message::DnsQuery {
        id,
        data: String::new(),
    };
    // No await between these: the writer cannot drain, the queue fills up.
    for id in 0..QUEUE as u64 {
        assert!(sender.try_send(query(id)));
    }
    assert!(
        !sender.try_send(query(QUEUE as u64)),
        "a full queue refuses instead of waiting"
    );
    // The waiting form exists for tasks that can afford it.
    sender.send(query(999)).await.unwrap();

    let (read, write) = tokio::io::split(right);
    let mut peer = Control::new(read, write);
    for id in 0..QUEUE as u64 {
        assert!(matches!(
            peer.recv().await.unwrap(),
            Message::DnsQuery { id: got, .. } if got == id
        ));
    }
    assert!(matches!(
        peer.recv().await.unwrap(),
        Message::DnsQuery { id: 999, .. }
    ));
    // The writer task ends on its next poll after the control is dropped.
    drop(control);
    tokio::task::yield_now().await;
    assert!(!sender.try_send(query(1)), "the writer is gone");
}

// ── session ──

/// A link session with a control channel the test holds the other end of.
fn linked() -> (
    session::Session,
    Control,
    tokio::sync::mpsc::Receiver<(link_io::Epoch, link_io::Event)>,
) {
    let (left, right) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(left);
    let (peer_read, peer_write) = tokio::io::split(right);
    let (session, events) = common::session::link_session_with(true, Control::new(read, write));
    (session, Control::new(peer_read, peer_write), events)
}

fn query() -> Vec<u8> {
    common::dns::query(1, "www.example.com", 1, None)
}

#[tokio::test]
async fn a_client_session_hands_answers_to_the_hub() {
    let (mut session, _peer, mut events) = linked();
    session
        .dispatch_control(Message::DnsAnswer {
            id: 9,
            data: dns::encode(&query()),
        })
        .await
        .unwrap();
    let (epoch, event) = events.recv().await.unwrap();
    assert_eq!(
        epoch,
        link_io::Epoch {
            link: 2,
            generation: 7
        }
    );
    assert!(matches!(event, Event::DnsAnswer { id: 9, answer: Some(got) } if got == query()));
    // An empty answer is a failure to resolve, not a message.
    session
        .dispatch_control(Message::DnsAnswer {
            id: 10,
            data: String::new(),
        })
        .await
        .unwrap();
    assert!(matches!(
        events.recv().await.unwrap().1,
        Event::DnsAnswer {
            id: 10,
            answer: None
        }
    ));
}

#[tokio::test]
async fn a_client_never_relays_a_query() {
    let (mut session, _peer, _events) = linked();
    let error = session
        .dispatch_control(Message::DnsQuery {
            id: 1,
            data: dns::encode(&query()),
        })
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "dns_query outside a server session");
}

#[tokio::test]
async fn a_server_answers_what_it_cannot_relay_with_nothing() {
    let (mut session, mut peer, _events) = linked();
    // The same session seen from the server: no client plane.
    if let Plane::Tcp(plane) = &mut session.plane {
        plane.server_ip = None;
    }
    let ask = |id: u64, data: String| Message::DnsQuery { id, data };
    // A query that is not base64 is answered at once, with nothing.
    session
        .dispatch_control(ask(5, "%%%".to_owned()))
        .await
        .unwrap();
    assert!(matches!(
        peer.recv().await.unwrap(),
        Message::DnsAnswer { id: 5, ref data } if data.is_empty()
    ));
    // So is one that finds every relay slot taken.
    let mut held = Vec::new();
    while let Some(permit) = dns::relay::acquire() {
        held.push(permit);
    }
    assert!(!held.is_empty());
    session
        .dispatch_control(ask(6, dns::encode(&query())))
        .await
        .unwrap();
    assert!(matches!(
        peer.recv().await.unwrap(),
        Message::DnsAnswer { id: 6, ref data } if data.is_empty()
    ));
}
