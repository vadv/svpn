// Dashboard calculations use only Node's built-in test runner; no npm dependencies.
import test from "node:test";
import assert from "node:assert/strict";
import { WINDOW_MS, PAGE_SIZE, bytes, rate, measure, keepHistory, graph, areas, spark, sparkScaled, nearestSample, cpuPercent, processRss, uptimeSeconds, duration, flowPage, selector, localState } from "../src/web/state.mjs";

function snapshot(time, servers = [server("nl", 0, 0)], started = 1, process = null) {
  return { generated_at_ms: time, started_at: started, servers, ...(process ? { process } : {}) };
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

test("process CPU is derived from cumulative seconds and the real snapshot gap", () => {
  const before = snapshot(1000, [], 1, { cpu_seconds: 10, rss_bytes: 4096, peak_rss_bytes: 8192, cpus: 8 });
  const after = snapshot(2000, [], 1, { cpu_seconds: 10.25, rss_bytes: 4200, peak_rss_bytes: 8192, cpus: 8 });
  assert.equal(cpuPercent(before, after), 25, "0.25 CPU seconds in 1 wall second = 25% of one core");
  const sample = measure(before, after);
  assert.equal(sample.cpu, 25);
  assert.equal(sample.rss, 4200);
  assert.equal(sample.cpu_seconds, 10.25);
  assert.equal(cpuPercent(before, snapshot(3000, [], 1, { cpu_seconds: 10.5 })), 25, "actual elapsed time, not poll interval");
  assert.equal(cpuPercent(before, snapshot(2000, [], 1, { cpu_seconds: 12.5 })), 250, "multithreaded load may exceed 100% of one core");
});

test("restarts, resets, stale gaps and missing process counters stay unknown", () => {
  const before = snapshot(1000, [], 1, { cpu_seconds: 10 });
  const unusable = [
    snapshot(2000, [], 2, { cpu_seconds: 10.25 }),
    snapshot(2000, [], 1, { cpu_seconds: 9 }),
    snapshot(1000, [], 1, { cpu_seconds: 10.25 }),
    snapshot(7000, [], 1, { cpu_seconds: 10.25 }),
    snapshot(2000, [], 1),
    snapshot(2000, [], 1, { cpu_seconds: null }),
    snapshot(2000, [], 1, { cpu_seconds: Number.NaN }),
  ];
  for (const after of unusable) assert.equal(cpuPercent(before, after), null);
  assert.equal(measure(before, unusable[0]).cpu, null, "a restart gets no CPU baseline");
  assert.equal(measure(snapshot(1000, []), snapshot(2000, [])).cpu, null);
  assert.equal(measure(snapshot(1000, []), snapshot(2000, [])).rss, null);
});

test("process memory uses current RSS and labels a peak-only fallback", () => {
  assert.deepEqual(processRss({ rss_bytes: 1024, peak_rss_bytes: 2048 }), { bytes: 1024, peak: false });
  assert.deepEqual(processRss({ rss_bytes: null, peak_rss_bytes: 2048 }), { bytes: 2048, peak: true });
  assert.deepEqual(processRss({ rss_bytes: -1, peak_rss_bytes: 2048 }), { bytes: 2048, peak: true });
  assert.deepEqual(processRss({ rss_bytes: Number.NaN, peak_rss_bytes: null }), { bytes: null, peak: false });
  assert.deepEqual(processRss(null), { bytes: null, peak: false });
});

test("uptime is derived from started_at and never invents a future session", () => {
  assert.equal(uptimeSeconds({ started_at: 1000 }, 7361000), 7360);
  assert.equal(uptimeSeconds({ started_at: 1000 }, 999), null);
  assert.equal(uptimeSeconds({}, 1000), null);
  assert.equal(duration(0), "00:00:00");
  assert.equal(duration(3661), "01:01:01");
  assert.equal(duration(90061), "1d 01:01:01");
  assert.equal(duration(null), "—");
  assert.equal(duration(-1), "—");
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

test("filled areas close at the baseline and break around unknown intervals", () => {
  const history = [
    { time: 1000, rx: 1, tx: 0, servers: {} }, { time: 2000, rx: 2, tx: 1, servers: {} },
    { time: 8000, rx: null, tx: null, servers: {} }, { time: 9000, rx: 3, tx: 0, servers: {} },
  ];
  const fill = areas(history);
  assert.equal(fill.rx.match(/M/g).length, 2, "a gap starts a second polygon instead of painting a fake value");
  assert.equal(fill.rx.match(/Z/g).length, 2);
  assert.equal(fill.tx.match(/Z/g).length, 2);
  assert.ok(fill.rx.startsWith("M") && fill.rx.includes(",152 Z"), "polygons close on the chart baseline");
  assert.ok(!fill.rx.includes("NaN") && !fill.tx.includes("NaN"));
  assert.equal(areas([]).rx, "");
  assert.equal(areas(history, "absent").rx.trim(), "", "an unknown server has nothing to fill");
});

test("areas and lines use the same scale and can be filtered by server", () => {
  const history = [
    { time: 1000, rx: 2, tx: 1, servers: { nl: { rx: 4, tx: 2 } } },
    { time: 2000, rx: 6, tx: 3, servers: { nl: { rx: 8, tx: 4 } } },
  ];
  const line = graph(history, "nl").rx.split(" ").at(-1).slice(1);
  assert.ok(areas(history, "nl").rx.includes(line), "the area ridge follows the line exactly");
  assert.equal(graph(history, "nl").max, 8.8, "both views scale from the same peak");
  assert.ok(areas(history, "nl").rx.includes("1000.00,35.64"));
});

test("sparklines are bounded to 40 samples, use their own scale and keep gaps", () => {
  let history = [];
  for (let i = 0; i < 60; i++) history = keepHistory(history, { time: i * 1000, rx: i, tx: i / 2, servers: {} });
  const path = spark(history, "rx");
  assert.equal(path.match(/M/g).length, 1);
  assert.equal(path.match(/L/g).length, 39);
  assert.ok(path.startsWith("M0.00,") && path.includes("L120.00,"), "a compact trend is normalised to its own box");
  assert.ok(!path.includes("NaN"));
  assert.equal(spark([], "rx"), "");
  const gap = [
    { time: 1000, rx: 1, tx: 1, servers: {} }, { time: 2000, rx: null, tx: null, servers: {} },
    { time: 3000, rx: 2, tx: 2, servers: {} },
  ];
  assert.equal(spark(gap, "rx").match(/M/g).length, 2, "unknown intervals stay broken");
  assert.equal(spark(gap, "tx").match(/M/g).length, 2);
});

test("scaled sparklines keep flat memory trends finite and break at gaps", () => {
  const history = Array.from({ length: 45 }, (_, index) => ({ rss: 100 + index }));
  history.push({ rss: null }, { rss: 200 });
  const path = sparkScaled(history, "rss");
  assert.equal(path.match(/M/g).length, 2, "only the last 40 samples are drawn, with a real gap");
  assert.ok(path.includes("M120.00,"), "the isolated newest sample reaches the right edge without bridging the gap");
  assert.ok(!path.includes("NaN"));
  const flat = sparkScaled(Array.from({ length: 45 }, () => ({ rss: 100 })), "rss");
  assert.equal(flat.match(/M/g).length, 1);
  assert.equal(flat.match(/L/g).length, 39);
  assert.ok(!flat.includes("NaN"), "a zero-width range never divides by zero");
  assert.equal(sparkScaled([{ rss: null }], "rss"), "");
  assert.equal(sparkScaled([], "rss"), "");
});

test("hover readout picks the nearest real sample and never invents a value", () => {
  const history = [
    { time: 1000, rx: 1, tx: 2, servers: { nl: { rx: 5, tx: 6 } } },
    { time: 3000, rx: null, tx: null, servers: { nl: { rx: 7, tx: 8 } } },
  ];
  assert.deepEqual(nearestSample(history, 900), { time: 1000, rx: 1, tx: 2 });
  assert.deepEqual(nearestSample(history, 2600), { time: 3000, rx: null, tx: null });
  assert.deepEqual(nearestSample(history, 2600, "nl"), { time: 3000, rx: 7, tx: 8 });
  assert.deepEqual(nearestSample(history, 1000, "absent"), { time: 1000, rx: null, tx: null });
  assert.equal(nearestSample([], 1000), null);
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
