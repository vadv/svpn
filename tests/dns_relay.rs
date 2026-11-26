//! The resolver relay: one query, every nameserver at once, the first
//! well-formed answer inside the budget.

mod common;

use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use common::dns::{self, A, HOST, answered, resolver};
use svpn::dns::relay;

// ── exchange ──

#[tokio::test]
async fn the_first_well_formed_answer_wins() {
    let nameserver = resolver(|socket, query, from| {
        let _ = socket.try_send_to(&answered(query), from);
    })
    .await;
    let query = dns::query(7, HOST, A, None);
    let answer = relay::exchange(&[nameserver], None, &query, Duration::from_secs(2)).await;
    assert_eq!(answer.as_deref(), Some(answered(&query).as_slice()));
}

#[tokio::test]
async fn a_silent_resolver_costs_the_budget_and_nothing_more() {
    let nameserver = resolver(|_, _, _| {}).await;
    let query = dns::query(7, HOST, A, None);
    let started = Instant::now();
    let answer = relay::exchange(&[nameserver], None, &query, Duration::from_millis(200)).await;
    let elapsed = started.elapsed();
    assert!(answer.is_none());
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}

#[tokio::test]
async fn answers_that_do_not_answer_the_query_are_ignored() {
    let nameserver = resolver(|socket, query, from| {
        let good = answered(query);
        let mut wrong_id = good.clone();
        wrong_id[0] ^= 1;
        let mut not_a_response = good.clone();
        not_a_response[2] &= 0x7f;
        let other_question = dns::answer(&dns::query(7, "other.example.com", A, None), &[]);
        let mut cut = good.clone();
        cut.truncate(cut.len() - 4);
        for answer in [wrong_id, not_a_response, other_question, cut, good] {
            let _ = socket.try_send_to(&answer, from);
        }
    })
    .await;
    let query = dns::query(7, HOST, A, None);
    let answer = relay::exchange(&[nameserver], None, &query, Duration::from_secs(2)).await;
    assert_eq!(answer.as_deref(), Some(answered(&query).as_slice()));
}

#[tokio::test]
async fn every_nameserver_is_asked_at_once() {
    let silent = resolver(|_, _, _| {}).await;
    let quick = resolver(|socket, query, from| {
        let _ = socket.try_send_to(&answered(query), from);
    })
    .await;
    let query = dns::query(7, HOST, A, None);
    let started = Instant::now();
    let answer = relay::exchange(&[silent, quick], None, &query, Duration::from_secs(5)).await;
    assert!(answer.is_some());
    // Asked one after the other, the silent one would have held the query.
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn without_a_resolver_there_is_no_answer() {
    let query = dns::query(7, HOST, A, None);
    let answer = relay::exchange(&[], None, &query, Duration::from_millis(100)).await;
    assert!(answer.is_none());
}

#[tokio::test]
async fn at_most_three_resolvers_are_asked() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // The fourth resolver answers; it must never hear the query.
    let asked = std::sync::Arc::new(AtomicUsize::new(0));
    let mut targets = Vec::new();
    for _ in 0..3 {
        let asked = asked.clone();
        targets.push(
            resolver(move |_, _, _| {
                asked.fetch_add(1, Ordering::SeqCst);
            })
            .await,
        );
    }
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let fourth = resolver(move |socket, query, from| {
        counter.fetch_add(1, Ordering::SeqCst);
        let _ = socket.try_send_to(&answered(query), from);
    })
    .await;
    targets.push(fourth);
    let query = dns::query(7, HOST, A, None);
    let answer = relay::exchange(&targets, None, &query, Duration::from_millis(300)).await;
    assert!(answer.is_none(), "the fourth resolver is past MAXNS");
    assert_eq!(asked.load(Ordering::SeqCst), 3);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let answer = relay::exchange(&[fourth], None, &query, Duration::from_secs(2)).await;
    assert_eq!(answer.as_deref(), Some(answered(&query).as_slice()));
}

#[test]
fn relays_are_bounded_per_process() {
    let mut held = Vec::new();
    while let Some(permit) = relay::acquire() {
        held.push(permit);
    }
    assert!(held.len() > 1);
    assert!(relay::acquire().is_none());
    held.pop();
    assert!(relay::acquire().is_some());
}

// ── resolv.conf ──

fn addresses(texts: &[&str]) -> Vec<Ipv4Addr> {
    texts.iter().map(|text| text.parse().unwrap()).collect()
}

#[test]
fn nameservers_are_the_ipv4_lines_in_file_order() {
    let text = "# comment\nsearch lan\nnameserver\t10.0.0.2\nnameserver ::1\nnameserver 1.1.1.1\noptions ndots:1\nnameserver 8.8.8.8\nnameserver not-an-address\n";
    assert_eq!(
        relay::nameservers(text),
        addresses(&["10.0.0.2", "1.1.1.1", "8.8.8.8"])
    );
    assert!(relay::nameservers("").is_empty());
}

#[test]
fn resolvers_become_sockets_on_the_dns_port_up_to_three() {
    let found = addresses(&["10.0.0.2", "1.1.1.1", "8.8.8.8", "9.9.9.9"]);
    let sockets: Vec<String> = relay::sockets(&found)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        sockets,
        ["10.0.0.2:53", "1.1.1.1:53", "8.8.8.8:53"]
            .map(String::from)
            .to_vec()
    );
}

#[test]
fn loopback_is_no_resolver_of_the_local_exit() {
    let text = "nameserver 127.0.0.1\nnameserver ::1\nnameserver 81.200.0.1\nnameserver 127.0.0.53\nnameserver 81.200.2.222\n";
    assert_eq!(
        relay::external(text),
        addresses(&["81.200.0.1", "81.200.2.222"])
    );
    assert!(relay::external("nameserver 127.0.0.1\n").is_empty());
}

#[test]
fn local_resolvers_come_from_the_config_or_the_first_file_that_has_any() {
    let dir = std::env::temp_dir();
    let tag = std::process::id();
    let dnsmasq = dir.join(format!("svpn-resolv-{tag}.conf"));
    let auto = dir.join(format!("svpn-resolv-auto-{tag}.conf"));
    std::fs::write(&dnsmasq, "nameserver 127.0.0.1\n").unwrap();
    std::fs::write(&auto, "nameserver 81.200.0.1\nnameserver 81.200.2.222\n").unwrap();
    let files = [
        dnsmasq.to_str().unwrap(),
        auto.to_str().unwrap(),
        "/nonexistent/resolv.conf",
    ];
    let configured = addresses(&["77.88.8.8"]);
    assert_eq!(
        relay::local_nameservers(&configured, &files),
        configured,
        "configured resolvers win outright"
    );
    assert_eq!(
        relay::local_nameservers(&[], &files),
        addresses(&["81.200.0.1", "81.200.2.222"]),
        "the first file with resolvers outside loopback"
    );
    assert!(relay::local_nameservers(&[], &["/nonexistent/resolv.conf"]).is_empty());
    std::fs::remove_file(dnsmasq).unwrap();
    std::fs::remove_file(auto).unwrap();
}
