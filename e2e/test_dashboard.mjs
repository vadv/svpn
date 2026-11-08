// Dashboard calculations use only Node's built-in test runner; no npm dependencies.
import test from "node:test";
import assert from "node:assert/strict";
import { WINDOW_MS, PAGE_SIZE, bytes, rate, measure, keepHistory, graph, flowPage, selector, localState } from "../src/web/state.mjs";

function snapshot(time, servers = [server("nl", 0, 0)], started = 1) {
  return { generated_at_ms: time, started_at: started, servers };
}
function server(id, rx, tx, drops = 0, failed = 0) {
  return { id, stats: { inner_rx_bytes: rx, inner_tx_bytes: tx, dropped_packets: drops, open_failed_flows: failed } };
}

test("rates use actual snapshot elapsed time and Mbit/s units", () => {
  const before = snapshot(1000, [server("nl", 100, 200)]);
  const after = snapshot(3000, [server("nl", 250100, 500200, 3, 2)]);
  const sample = measure(before, after);
  assert.equal(sample.rx, 1);
  assert.equal(sample.tx, 2);
  assert.equal(sample.drops, 3);
  assert.equal(sample.failed, 2);
});

test("servers are matched by id rather than array position", () => {
  const before = snapshot(1000, [server("nl", 0, 0), server("de", 1000, 1000)]);
  const after = snapshot(2000, [server("de", 1000, 2000), server("nl", 1000, 0)]);
  const sample = measure(before, after);
  assert.equal(sample.servers.nl.rx, 0.008);
  assert.equal(sample.servers.de.tx, 0.008);
  assert.equal(sample.rx, 0.008);
});

test("restart, duplicate/backward timestamps and long gaps are unknown, not zero", () => {
  const before = snapshot(1000);
  for (const after of [snapshot(2000, [server("nl", 10, 10)], 2), snapshot(1000), snapshot(999), snapshot(7000)]) {
    assert.equal(measure(before, after).rx, null);
  }
  assert.equal(measure(null, before).rx, null);
  assert.equal(rate(null), "—");
});

test("counter reset/new server is not a negative rate, and real zero stays zero", () => {
  const before = snapshot(1000, [server("nl", 1000, 1000)]);
  assert.equal(measure(before, snapshot(2000, [server("nl", 2, 3)])).rx, null);
  assert.equal(measure(before, snapshot(2000, [server("new", 2000, 2000)])).rx, null);
  assert.equal(measure(before, snapshot(2000, [server("nl", 1000, 1000)])).rx, 0);
  assert.equal(rate(0), "0.00");
});

test("node ids cannot collide with object prototype keys", () => {
  const before = snapshot(1000, [server("__proto__", 0, 0)]);
  const sample = measure(before, snapshot(2000, [server("__proto__", 1000, 1000)]));
  assert.equal(sample.rx, 0.008);
  assert.equal(sample.servers.__proto__.tx, 0.008);
});

test("history is bounded by five minutes and a sample count", () => {
  let history = [];
  for (let time = 0; time <= 1000000; time += 100) history = keepHistory(history, { time, rx: 1, tx: 2 });
  assert.ok(history.length <= 301);
  assert.ok(history.every(item => item.time > 1000000 - WINDOW_MS));
  history = keepHistory(history, { time: 1, rx: null, tx: null });
  assert.equal(history.length, 1, "future samples are discarded if the clock moves backwards");
});

test("graph leaves a gap instead of joining through an unknown interval", () => {
  const history = [
    { time: 1000, rx: 1, tx: 0, servers: {} }, { time: 2000, rx: 2, tx: 0, servers: {} },
    { time: 8000, rx: null, tx: null, servers: {} }, { time: 9000, rx: 3, tx: 0, servers: {} },
  ];
  const paths = graph(history);
  assert.equal(paths.rx.match(/M/g).length, 2);
  assert.equal(paths.rx.match(/L/g).length, 1);
  assert.ok(!paths.rx.includes("NaN"));
  assert.equal(graph(history, "absent").rx.trim(), "");
});

test("graph can select a server and handles the empty first screen", () => {
  const sample = measure(snapshot(1000), snapshot(2000, [server("nl", 1000, 2000)]));
  assert.equal(graph([sample], "nl").latest.rx, 0.008);
  assert.match(graph([sample], "nl").rx, /^M1000\.00,[\d.]+ l0,0$/, "one visible point, not invented historical traffic");
  assert.equal(graph([]).rx, "");
});

test("flow filters combine, pagination is bounded and disappearing pages clamp", () => {
  const flows = Array.from({ length: 10003 }, (_, i) => ({ source: `10.0.0.1:${i}`, destination: "1.2.3.4:443", protocol: i % 2 ? "tcp" : "udp", via: i % 3 ? "nl" : "local" }));
  const first = flowPage(flows);
  assert.equal(first.rows.length, PAGE_SIZE);
  assert.equal(first.total, 10003);
  const filtered = flowPage(flows, { query: "443", protocol: "tcp", via: "local", page: 99999 });
  assert.ok(filtered.rows.every(flow => flow.protocol === "tcp" && flow.via === "local"));
  assert.equal(filtered.page, filtered.pages - 1);
  const missing = flowPage(flows, { query: "missing", page: 99999 });
  assert.equal(missing.page, 0);
  assert.equal(missing.pages, 1);
  assert.equal(missing.rows.length, 0);
  assert.equal(flowPage(flows, { page: -1 }).page, 0);
});

test("selectors, local states and byte units are explicit", () => {
  assert.equal(selector({ kind: "countries", selector: "cc: RU, BY" }), "Countries: RU, BY");
  assert.equal(selector({ kind: "names", selector: "names: example.test" }), "Domains: example.test");
  assert.equal(localState({ enabled: false, ready: false }), "Disabled");
  assert.equal(localState({ enabled: true, ready: false }), "Unavailable");
  assert.equal(localState({ enabled: true, ready: true }), "Ready");
  assert.equal(bytes(0), "0 B");
  assert.equal(bytes(1024), "1.0 KiB");
  assert.equal(bytes(1048576), "1.0 MiB");
});
