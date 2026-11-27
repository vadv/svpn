// Dashboard calculations use only Node's built-in test runner; no npm dependencies.
import test from "node:test";
import assert from "node:assert/strict";
import { WINDOW_MS, LIVE_MIN_MS, PAGE_SIZE, bytes, rate, flowCounts, measure, keepHistory, spark, sparkArea, sparkScaled, latestSample, liveStack, stackPaths, stackIndex, stackMarks, stackTime, rateLabel, cpuPercent, cpuAverage, smoothRates, SMOOTH_MS, trafficAverage, processRss, uptimeSeconds, duration, flowPage, flowSource, flowService, flowAge, withFlowRates, asnLabel, asnOwners, pinnedGroups, flag, addAsnName, readAsnNames, selector, localState, mimicCell, transport, usageRanking, historyQuery, historyStack, historyScale, historyMarks, historyTime, historyName, historyYesterday, historyLive, historyWindowError, historyInputValue, historyInputSeconds, historyStepLabel } from "../src/web/state.mjs";

test("usage ranks raw bytes, not formatted strings, and includes the pooled share", () => {
  const entries = [["a", "Small", { rx_bytes: 99, tx_bytes: 0 }], ["b", "Big", { rx_bytes: 1024, tx_bytes: 4 }], [null, "Other", { rx_bytes: 0, tx_bytes: 7 }]];
  assert.deepEqual(usageRanking(entries, "total").rows.map(r => r.key), ["b", "a", null]);
  assert.deepEqual(usageRanking(entries, "tx").rows.map(r => r.key), [null, "b"]);
  assert.equal(usageRanking(entries, "total").total, 1134);
  assert.deepEqual(usageRanking([], "rx"), { rows: [], total: 0 });
  // A row may name the exit it is pinned to; the ranking keeps it.
  const pinned = usageRanking([["13335", "AS13335", { rx_bytes: 1, tx_bytes: 2 }, "nl"], ["15169", "AS15169", { rx_bytes: 5, tx_bytes: 0 }]], "total").rows;
  assert.deepEqual(pinned.map(row => [row.key, row.via, row.value]), [["15169", null, 5], ["13335", "nl", 3]]);
});

test("pinned groups are named by their network and sorted by what they carried", () => {
  const groups = [{ group: "asn 16509", server: "a" }, { group: "ru", server: "local" }, { group: "asn 15169", server: "b" }, { group: "asn 24429", server: "b" }, { group: "group 0xff", server: "a" }];
  const rules = [{ label: "ru", traffic: { rx_bytes: 50, tx_bytes: 7 } }];
  const networks = { 16509: { rx_bytes: 1000, tx_bytes: 100 }, 24429: { rx_bytes: 300, tx_bytes: 0 }, 15169: { rx_bytes: 10, tx_bytes: 20 } };
  assert.deepEqual(asnOwners(groups), new Map([["16509", "a"], ["15169", "b"], ["24429", "b"]]), "the exit of each ASN group, keyed as the usage names it");
  assert.deepEqual(asnOwners(undefined), new Map());
  assert.deepEqual(pinnedGroups(groups, { rules, networks, names: { 16509: "Amazon.com, Inc.", 15169: "Google LLC" } }).map(group => [group.label, group.server, group.rx_bytes + group.tx_bytes]), [
    ["AS16509 · Amazon.com, Inc.", "a", 1100], ["AS24429", "b", 300], ["ru", "local", 57], ["AS15169 · Google LLC", "b", 30], ["group 0xff", "a", 0],
  ], "busiest first; a network is its number until the dictionary names it");
  assert.equal(pinnedGroups(groups, { rules, networks })[0].label, "AS16509");
  assert.deepEqual(pinnedGroups([{ group: "asn 100", server: "a" }, { group: "asn 9", server: "a" }]).map(group => group.asn), ["9", "100"], "without traffic the order is by number, not as strings");
  assert.deepEqual(pinnedGroups([]), []);
  assert.deepEqual(pinnedGroups(undefined), []);
});

test("destination drill-down matches an IP exactly, not a prefix or a source", () => {
  const flows = ["1.1.1.10:443", "1.1.1.1:53"].map(destination => ({ source: "1.1.1.1:123", destination }));
  assert.deepEqual(flowPage(flows, { drill: { axis: "destinations", key: "1.1.1.1" } }).rows, [flows[1]]);
});

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

test("the CPU headline averages the chart window instead of the last poll", () => {
  // 20% of one core with a 25 CPU-second burst in one poll: that single poll
  // would read 520%, while the window it happened in used 35 of 50 seconds.
  const history = Array.from({ length: 11 }, (_, index) => ({
    time: index * 5000,
    cpu_seconds: index + (index >= 3 ? 25 : 0),
  }));
  const average = cpuAverage(history);
  assert.equal(average.seconds, 50, "the window the percent is averaged over");
  assert.equal(average.percent, 70, "35 CPU seconds over 50 wall seconds");
  assert.equal(cpuAverage([history[0]]), null, "one sample cannot be a rate");
  assert.equal(cpuAverage([{ time: 0 }, history.at(-1)]), null, "a missing counter is not zero load");
  assert.equal(cpuAverage([{ time: 0, cpu_seconds: 40 }, { time: 10_000, cpu_seconds: 5 }]), null,
    "a counter reset inside the window is unknown, not idle");
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

test("history is bounded by the chart window plus one smoothing window and a sample count", () => {
  let history = [];
  for (let time = 0; time <= 1000000; time += 100) history = keepHistory(history, { time, rx: 1, tx: 2 });
  assert.ok(history.length <= 316);
  assert.ok(history.every(item => item.time > 1000000 - WINDOW_MS - SMOOTH_MS));
  history = keepHistory(history, { time: 1, rx: null, tx: null });
  assert.equal(history.length, 1, "future samples are discarded if the clock moves backwards");
});

test("live bands break at a poll without a rate, and a lone sample is a tick", () => {
  const history = [
    { time: 1000, rx: 2, tx: 1, servers: { nl: { rx: 1, tx: 0 }, de: { rx: null, tx: null } } },
    { time: 2000, rx: 4, tx: 1, servers: { nl: { rx: 2, tx: 0 }, de: { rx: 2, tx: 0 } } },
    { time: 8000, rx: null, tx: null, servers: { nl: { rx: null, tx: null } } },
    { time: 9000, rx: 6, tx: 1, servers: { nl: { rx: 3, tx: 0 }, de: { rx: 3, tx: 0 } } },
  ];
  const stack = liveStack(history);
  assert.deepEqual(stack.series.map(item => item.key), ["nl", "de"], "one layer per server that has a rate in the window");
  assert.deepEqual(stack.series.map(item => item.values), [[1, 1.5, null, 2], [null, 2, null, 2.5]], "smoothed like the headline, holes kept");
  assert.deepEqual(stack.xs.map(x => x.toFixed(2)), ["200.00", "300.00", "900.00", "1000.00"], "samples sit on the clock of the window, the newest on its right edge");
  assert.deepEqual([stack.span, stack.from, stack.to], [LIVE_MIN_MS, 9000 - LIVE_MIN_MS, 9000], "a young window is ten seconds wide, not an empty five minutes");
  assert.equal(stack.peak, 4.5, "the peak is the whole stack at its busiest poll");
  const [nl, de] = stackPaths(stack, 5);
  assert.equal((nl.band.match(/M/g) || []).length, 1, "a hole starts a new band instead of painting across the gap");
  assert.ok(nl.band.startsWith("M200.00,126.40 ") && nl.band.includes(" L300.00,152.00 ") && nl.band.endsWith(" 200.00,152.00 Z"), nl.band);
  assert.ok(nl.crest.startsWith("M200.00,126.40 ") && nl.crest.includes(" 300.00,113.60 ") && nl.crest.endsWith(" M1000.00,152.00 L1000.00,100.80"), nl.crest);
  assert.equal(de.band, "", "two lone samples have no width to fill");
  assert.equal(de.crest, "M300.00,113.60 L300.00,62.40 M1000.00,100.80 L1000.00,36.80", "a lone sample is a tick as thick as its layer, over the layers under it");
  assert.ok(!nl.band.includes("NaN") && !de.crest.includes("NaN"));
  // The readout is the averaged value the chart ends on (2, 4, 6), and a lone unknown poll draws nothing.
  assert.equal(latestSample(history).rx, 4);
  assert.equal(latestSample([{ time: 1000, rx: null, tx: null, servers: {} }]).rx, null);
  assert.equal(spark(history, "rx").match(/M/g).length, 2, "the compact trend breaks on the same gap");
});

test("live layers stack, largest server first, and follow one server or one direction", () => {
  const history = [1000, 2000, 3000].map(time => ({ time, rx: 6, tx: 2, servers: { de: { rx: 2, tx: 1 }, nl: { rx: 4, tx: 1 } } }));
  const heights = path => [...new Set(path.match(/,[0-9.]+(?=[ CL]|$)/g))].sort();
  const all = liveStack(history);
  assert.deepEqual(all.series.map(item => [item.key, item.values]), [["nl", [5, 5, 5]], ["de", [3, 3, 3]]]);
  assert.deepEqual(all.xs.map(x => x.toFixed(2)), ["800.00", "900.00", "1000.00"]);
  assert.equal(all.peak, 8);
  const [low, high] = stackPaths(all, 8);
  assert.deepEqual(heights(low.band), [",152.00", ",72.00"], "the larger server lies on the baseline");
  assert.deepEqual(heights(high.band), [",24.00", ",72.00"], "the next one lies on it, nowhere else");
  assert.deepEqual(heights(high.crest), [",24.00"], "the hairline is the top of its band and nothing else");
  assert.ok(high.crest.startsWith("M800.00,24.00 ") && !high.crest.includes(" L"), "the line runs without a break where every poll has a rate");
  assert.deepEqual(liveStack(history, "total", "de").series.map(item => [item.key, item.values]), [["de", [3, 3, 3]]]);
  assert.equal(liveStack(history, "total", "de").peak, 3);
  assert.deepEqual(liveStack(history, "tx").series.map(item => item.values), [[1, 1, 1], [1, 1, 1]], "sent only");
  assert.equal(liveStack(history, "rx").peak, 6, "received only");
});

test("the first screen: one sample is a tick, no sample is an empty stack", () => {
  const sample = measure(snapshot(1000), snapshot(2000, [server("nl", 1000, 2000)]));
  const stack = liveStack([sample]);
  assert.deepEqual(stack.series, [{ key: "nl", values: [0.024] }], "receive and send of the first measured poll");
  assert.deepEqual([stack.xs.map(x => x.toFixed(2)), stack.peak], [["1000.00"], 0.024]);
  const [first] = stackPaths(stack, 0.05);
  assert.equal(first.band, "");
  assert.equal(first.crest, "M1000.00,152.00 L1000.00,90.56", "the first sample is visible at the right edge, without invented history");
  assert.equal(latestSample([sample], "nl").rx, 0.008);
  const empty = liveStack([]);
  assert.deepEqual([empty.xs, empty.span, empty.from, empty.to, empty.series, empty.peak, empty.latest], [[], LIVE_MIN_MS, -LIVE_MIN_MS, 0, [], 0.01, null], "no poll yet is an empty stack the width of the youngest window, not a crash");
  assert.equal(empty.rate(3), 3, "a live stack is already in the unit being drawn");
  assert.deepEqual(stackPaths(liveStack([]), 1), []);
  assert.deepEqual(liveStack([sample], "total", "absent").series, [], "an unknown server has nothing to draw");
  assert.deepEqual(liveStack([{ time: 1000, rx: 1, tx: 1, servers: {} }]).series, [], "totals without a server rate are not a layer");
});

test("headline numbers quote the smoothed rate, never a lone poll", () => {
  const history = [10, 10, 10, 10, 0].map((rx, index) => ({
    time: 1000 * (index + 1), rx, tx: rx / 2, cpu: rx * 10, servers: { nl: { rx, tx: 0 } },
  }));
  assert.equal(latestSample(history).rx, 8, "a zero-delta poll after steady traffic is not 0 Mbit/s");
  assert.equal(latestSample(history).tx, 4);
  assert.equal(latestSample(history, "nl").rx, 8, "server rows use the same average");
  assert.equal(latestSample(history).cpu, 80, "the CPU sparkline is averaged too");
  assert.equal(latestSample([...history, { time: 6000, rx: null, tx: null, cpu: null, servers: {} }]).rx, null,
    "a gap is still unknown, not the average before it");
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
  // The same trend filled to the baseline of its box; a lone sample has no width to fill.
  const filled = sparkArea(history, "rx");
  assert.equal((filled.match(/M/g) || []).length, 1, "one polygon for one run");
  assert.ok(filled.startsWith("M0.00,30 ") && filled.includes("L120.00,") && filled.endsWith(" L120.00,30 Z"), filled);
  assert.equal(sparkArea(gap, "rx"), "", "a lone sample on either side of a gap has no width to fill");
  const partial = [
    { time: 1000, rx: 1, tx: 1, servers: {} }, { time: 2000, rx: null, tx: null, servers: {} },
    { time: 3000, rx: 2, tx: 1, servers: {} }, { time: 4000, rx: 3, tx: 1, servers: {} },
  ];
  assert.equal(sparkArea(partial, "rx"), "M80.00,30 L80.00,10.00 L120.00,4.00 L120.00,30 Z", "the run that has width is filled, to its own ends");
  assert.equal(sparkArea([partial[0]], "rx"), "");
  assert.equal(sparkArea([], "rx"), "");
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

test("the readout finds the sample under the pointer and never invents one", () => {
  const live = liveStack([1000, 2000, 3000].map(time => ({ time, rx: 1, tx: 1, servers: { nl: { rx: 1, tx: 1 }, de: { rx: 2, tx: 2 } } })));
  assert.equal(stackIndex(live, 1400), 0, "the live sample nearest to the pointer");
  assert.equal(stackIndex(live, 2600), 2);
  assert.equal(stackIndex(live, -100000), null, "the empty part of a young window has no sample to show");
  assert.equal(stackIndex(live, 4000), null);
  assert.equal(stackIndex(live, -400000), null, "off the window");
  const day = historyStack(history());
  assert.equal(stackIndex(day, 100), 0, "the bucket that holds the moment");
  assert.equal(stackIndex(day, 700), 2, "an unrecorded bucket is still a place: its values are holes");
  assert.equal(stackIndex(day, 960), 3, "the right edge reads as the last bucket");
  assert.equal(stackIndex(day, -1), null);
  assert.equal(stackIndex(day, 961), null);
  assert.equal(stackIndex({ xs: [], from: 0, to: 0, step: 60 }, 0), null);
});

test("traffic lines average a short wall-time window instead of drawing one-poll spikes", () => {
  const ticks = values => values.map((_, index) => index * 1000);
  const smooth = values => smoothRates(values, ticks(values));
  const flat = Array.from({ length: 6 }, () => 8);
  assert.deepEqual(smooth(flat), flat, "a steady trend is not moved");
  const spiky = [8, 8, 8, 40, 8, 8];
  const smoothed = smooth(spiky);
  assert.equal(smoothed[3], 16, "a one-poll burst is spread over the polls it covers");
  assert.ok(smoothed[3] < spiky[3] && smoothed[3] > spiky[2], "the burst stays visible, it is only not a needle");
  assert.deepEqual(smooth([2, 4]), [2, 3], "a young series averages what exists");
  assert.deepEqual(smooth([null, 4]), [null, 4], "a gap is not filled from the sample after it");
  assert.deepEqual(smooth([1, null, null]), [1, null, null], "unknown stays unknown");
  assert.deepEqual(smoothRates([], []), []);
  assert.equal(SMOOTH_MS, 15000);
  const sixteen = Array.from({ length: 17 }, (_, index) => index === 0 ? 100 : 0);
  assert.equal(smooth(sixteen)[15], 0, "a sample older than the window no longer counts");
  assert.ok(smooth(sixteen)[14] > 0, "a sample inside the window still counts");
  assert.deepEqual(smoothRates([0, 30], [0, 3000]), [0, 15], "slow polls still average by time, not count");
  assert.deepEqual(smoothRates([0, 30], [0, 20000]), [0, 30], "a poll beyond the window does not dilute the rate");
});

test("the chart's oldest point is as smooth as its newest", () => {
  // One poll reads 0, the next a burst: the raw rate saw-tooths, the 15 s average sits near 50.
  let history = [];
  for (let time = 0; time <= WINDOW_MS + 60000; time += 1000) {
    history = keepHistory(history, { time, rx: time / 1000 % 2 ? 100 : 0, tx: 0, servers: { nl: { rx: time / 1000 % 2 ? 100 : 0, tx: 0 } } });
  }
  const stack = liveStack(history);
  const end = stack.to;
  for (const at of [end - WINDOW_MS + 1000, end - WINDOW_MS / 2, end]) {
    const rx = stack.series[0].values[stackIndex(stack, at)];
    assert.ok(rx > 40 && rx < 60, `smoothed at ${end - at} ms before the end: ${rx}`);
  }
  assert.ok(stack.xs[0] >= 0, "samples kept only for the average are not drawn left of the axis");
});

test("traffic average covers the whole history, weighted by measured time", () => {
  const point = (time, rx, tx, servers) => ({ time, rx, tx, servers });
  const history = [
    point(0, null, null, {}),
    point(1000, 10, 1, { a: { rx: 10, tx: 1 } }),
    point(4000, 2, 1, { a: { rx: 2, tx: 1 } }),
    point(5000, null, null, { a: { rx: null, tx: null } }),
    point(6000, 6, 3, {}),
  ];
  assert.deepEqual(trafficAverage(history), { rx: 4.4, tx: 1.4, seconds: 5 }, "intervals are weighted, gaps are skipped");
  assert.deepEqual(trafficAverage(history, "a"), { rx: 4, tx: 1, seconds: 4 }, "a server without a sample is not zero");
  assert.equal(trafficAverage(history, "absent"), null);
  assert.equal(trafficAverage([point(0, 5, 5, {})]), null, "one sample has no interval yet");
  assert.equal(trafficAverage([]), null);
  assert.equal(trafficAverage([point(1000, null, null, {}), point(1000, 9, 9, {})]), null, "a duplicate snapshot is no interval");
});

test("flow rates come from consecutive snapshots and order is stable", () => {
  const flow = (source, rx, tx) => ({ protocol: "tcp", source, destination: "1.2.3.4:443", rx_bytes: rx, tx_bytes: tx });
  const previous = { generated_at_ms: 1000, flows: [flow("a", 100, 0), flow("b", 0, 0), flow("c", 5000, 0)] };
  const current = { generated_at_ms: 3000, flows: [flow("a", 2100, 0), flow("b", 0, 0), flow("c", 10, 0), flow("d", 900, 0)] };
  const rated = withFlowRates(previous, current);
  assert.deepEqual(rated.map(f => f.rate), [1000, 0, null, null], "delta over 2 s; restarted counter and new flow have no rate");
  assert.deepEqual(withFlowRates(null, current).map(f => f.rate), [null, null, null, null], "first snapshot has no rates");
  assert.deepEqual(withFlowRates({ ...previous, generated_at_ms: 3000 }, current).map(f => f.rate), [null, null, null, null], "no elapsed time, no rate");
  const ids = order => flowPage(rated, { order }).rows.map(f => f.source).join("");
  assert.equal(ids(""), "abcd", "address order is the snapshot order");
  assert.equal(ids("rate"), "abcd", "unknown rates sink, ties keep address order");
  assert.equal(ids("total"), "adcb", "largest total first");
  assert.equal(flowPage(rated, { order: "bogus" }).rows.length, 4, "unknown order falls back to address");
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

test("destination country/ASN filters combine and search includes organization names", () => {
  const base = { source: "10.0.0.1:40000", destination: "1.2.3.4:443", protocol: "tcp", via: "nl" };
  const flows = [
    { ...base, country: "US", asn: 13335 }, { ...base, country: "DE", asn: 13335 },
    { ...base, country: "US", asn: 15169 }, { ...base, country: null, asn: null },
    { ...base, country: null, asn: 0 },
  ];
  const names = { 13335: "Cloudflare, Inc.", 15169: "Google LLC" };
  assert.equal(flowPage(flows, { country: "US", asn: "13335", via: "nl", protocol: "tcp", names }).count, 1);
  assert.equal(flowPage(flows, { query: "CLOUDFLARE", names }).count, 2);
  assert.equal(flowPage(flows, { query: "AS15169", names }).count, 1);
  assert.equal(flowPage(flows, { country: "unknown", asn: "unknown" }).count, 1);
  assert.equal(flowPage(flows, { asn: "0" }).count, 1, "zero is not conflated with missing data");
  assert.equal(flowPage(flows, { country: "DE", asn: "15169" }).count, 0);
  assert.equal(asnLabel(13335, names), "AS13335 · Cloudflare, Inc.");
  assert.equal(asnLabel(139341), "AS139341");
  assert.equal(asnLabel(null), "Unknown");
});

test("flow search includes the LAN device behind the masquerade", () => {
  const base = { destination: "1.2.3.4:443", protocol: "tcp", via: "nl" };
  const flows = [
    { ...base, source: "10.77.0.2:49449", client: "192.168.0.23", client_name: "iphone-vadv" },
    { ...base, source: "10.77.0.2:49450", client: "192.168.0.24", client_name: null },
    { ...base, source: "10.77.0.2:49451" },
  ];
  assert.equal(flowPage(flows, { query: "iphone-vadv" }).count, 1, "device name");
  assert.equal(flowPage(flows, { query: "IPHONE" }).count, 1, "search is case-insensitive");
  assert.equal(flowPage(flows, { query: "192.168.0.24" }).count, 1, "LAN address");
  assert.equal(flowPage(flows, { query: "49451" }).count, 1, "the NAT port still matches");
  assert.equal(flowPage(flows, { query: "192.168.0.99" }).count, 0);
});

test("source column names the LAN device or the router itself", () => {
  assert.deepEqual(flowSource({ source: "10.77.0.2:49449", client: "192.168.0.23", client_name: "iphone-vadv" }),
    { main: "iphone-vadv · 192.168.0.23", detail: "via 10.77.0.2:49449" });
  assert.deepEqual(flowSource({ source: "10.77.0.2:49450", client: "192.168.0.24", client_name: null }),
    { main: "192.168.0.24", detail: "via 10.77.0.2:49450" }, "a device without a lease shows its address alone");
  assert.deepEqual(flowSource({ source: "10.77.0.2:49451", client: null, client_name: null }),
    { main: "router", detail: "10.77.0.2:49451" });
  assert.deepEqual(flowSource({ source: "10.77.0.2:49451" }), { main: "router", detail: "10.77.0.2:49451" },
    "a snapshot without the new fields still renders");
});

test("the service is guessed from the protocol and the destination port", () => {
  const service = (protocol, destination) => flowService({ protocol, destination });
  assert.equal(service("tcp", "1.2.3.4:443"), "HTTPS");
  assert.equal(service("udp", "1.2.3.4:443"), "QUIC", "the same port means another protocol over UDP");
  assert.equal(service("udp", "8.8.8.8:53"), "DNS");
  assert.equal(service("tcp", "1.2.3.4:4443"), null, "an unknown port stays unlabeled");
  assert.equal(service("tcp", "1.2.3.4:44"), null, "the port is matched whole, not by prefix");
  assert.equal(service("icmp", "8.8.8.8"), null, "ICMP has no port");
  const flows = [{ protocol: "udp", source: "a", destination: "1.2.3.4:443" }, { protocol: "tcp", source: "b", destination: "1.2.3.4:443" }];
  assert.equal(flowPage(flows, { query: "quic" }).count, 1, "search matches the guessed service");
});

test("flow age shows the lifetime and how long the flow has been silent", () => {
  assert.deepEqual(flowAge({ age_secs: 134, idle_secs: 35 }), { main: "00:02:14", detail: "idle 00:00:35" });
  assert.deepEqual(flowAge({ age_secs: 5, idle_secs: 1 }), { main: "00:00:05", detail: "active now" }, "a packet within a snapshot is activity");
  assert.deepEqual(flowAge({}), { main: "—", detail: "" }, "a snapshot without the fields still renders");
  const flows = [{ source: "a", age_secs: 5, idle_secs: 60 }, { source: "b", age_secs: 90, idle_secs: 0 }, { source: "c" }];
  const ids = order => flowPage(flows, { order }).rows.map(flow => flow.source).join("");
  assert.equal(ids("age"), "bac", "longest-lived first, unknown last");
  assert.equal(ids("idle"), "abc", "most silent first, unknown last");
});

test("country flags come from the ISO code alone", () => {
  assert.equal(flag("US"), "\u{1f1fa}\u{1f1f8}");
  assert.equal(flag("SE"), "\u{1f1f8}\u{1f1ea}");
  for (const code of [null, undefined, "", "unknown", "U", "USA", "us", "1A"]) {
    assert.equal(flag(code), "", `${String(code)} is not a country code`);
  }
});

test("browser ASN parser handles DB-IP quoting, boundaries and duplicate ranges", () => {
  const names = Object.create(null);
  for (const line of [
    '1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."',
    '1.1.1.0,1.1.1.255,13335,Duplicate must not replace first name',
    '2.0.0.0,2.0.0.255,"139341","ACME ""Network"""',
    '0.0.0.0,0.0.0.255,0,Reserved',
    '255.255.255.0,255.255.255.255,4294967295,Last ASN',
    '2001:db8::,2001:db8::ffff,42,IPv6 ignored',
    '5.0.0.0,5.0.0.255,4294967296,Too large',
    '5.0.0.0,5.0.0.255,-1,Negative',
    '5.0.0.0,5.0.0.255,1e3,Not an integer',
    '5.0.0.0,5.0.0.255,42,"Unterminated',
    '5.0.0.0,5.0.0.255,42,', 'start,end,asn,name', '',
    'not an IP,not an IP,42,Invalid', '256.0.0.0,256.0.0.255,42,Invalid',
    '01.0.0.0,01.0.0.255,42,Invalid', '5.0.0.255,5.0.0.0,42,Reversed',
    '5.0.0.0,5.0.0.255,42,"Fourth, column",ignored extra column',
  ]) addAsnName(names, line);
  assert.deepEqual({ ...names }, { 0: "Reserved", 42: "Fourth, column", 13335: "Cloudflare, Inc.", 139341: 'ACME "Network"', 4294967295: "Last ASN" });
  assert.throws(() => addAsnName(names, "x".repeat(4097)), /line too long/);
});

test("browser CSV decoder streams UTF-8 and records across arbitrary chunks", async () => {
  const text = '\ufeff1.0.0.0,1.0.0.255,13335,"Café, ""Network"""\r\n2.0.0.0,2.0.0.255,15169,Google LLC';
  const body = new ReadableStream({ start(controller) {
    for (const byte of new TextEncoder().encode(text)) controller.enqueue(new Uint8Array([byte]));
    controller.close();
  } });
  const result = await readAsnNames(body);
  assert.equal(result.count, 2);
  assert.equal(result.names[13335], 'Café, "Network"');
  assert.equal(result.names[15169], 'Google LLC');
});

test("browser CSV errors cancel the download and release its reader", async () => {
  for (const bytes of [new Uint8Array([255]), new TextEncoder().encode('x'.repeat(4097))]) {
    let cancelled = false;
    const body = new ReadableStream({ start(controller) { controller.enqueue(bytes); }, cancel() { cancelled = true; } });
    await assert.rejects(readAsnNames(body));
    assert.equal(cancelled, true);
    assert.equal(body.locked, false);
  }
  await assert.rejects(readAsnNames(new Response('bad CSV').body), /No IPv4/);
  await assert.rejects(readAsnNames(new Response(new Uint8Array([0xc3])).body));
  const broken = new ReadableStream({ start(controller) { controller.error(new Error('CSV interrupted')); } });
  await assert.rejects(readAsnNames(broken), /CSV interrupted/);
  await assert.rejects(readAsnNames(null), /unavailable/);
  let cancelled = false, released = false;
  const huge = { getReader: () => ({ read: async () => ({ done: false, value: { byteLength: 128 * 1024 * 1024 + 1 } }),
    cancel: async () => { cancelled = true; }, releaseLock: () => { released = true; } }) };
  await assert.rejects(readAsnNames(huge), /too large/);
  assert.ok(cancelled && released);
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

test("flow counts state closing flows instead of folding them into active", () => {
  assert.equal(flowCounts({ active_flows: 3, closing_flows: 2 }), "3 active · 2 closing");
  assert.equal(flowCounts({ active_flows: 3, closing_flows: 0 }), "3 active", "nothing closing omits the note");
  assert.equal(flowCounts(), "0 active", "a missing snapshot is not a zero-flow claim");
});

test("mimic cell shows the live transport and its race, winner first", () => {
  const selection = {
    active: "tcp-ssh",
    round: {
      finished_at_ms: 1730000000000, winner: "tcp",
      entries: [
        { candidate: "quic", status: "verified", rtt_ms: 63, penalty: false },
        { candidate: "tcp", status: "verified", rtt_ms: 41, penalty: true },
        { candidate: "webrtc", status: "failed", reason: "path_timeout" },
        { candidate: "obfs", status: "unanswered", stage: "handshake" },
        { candidate: "mosh", status: "failed", reason: "channel_failed" },
      ],
    },
  };
  assert.deepEqual(mimicCell(selection, ["webrtc", "ssh"]), {
    transport: "tcp-ssh",
    race: "tcp 41 ms (+penalty) · quic 63 ms · webrtc timeout · obfs handshake · mosh channel_failed",
    limited: "limited: webrtc · ssh",
  });
});

test("mimic cell selects before the first verdict and hides empty notes", () => {
  assert.deepEqual(mimicCell(null), { transport: "Selecting…", race: "", limited: "" });
  const allFailed = {
    active: null,
    round: { finished_at_ms: 1, winner: null, entries: [{ candidate: "quic", status: "failed", reason: "path_timeout" }] },
  };
  assert.deepEqual(mimicCell(allFailed), { transport: "Selecting…", race: "quic timeout", limited: "" });
  // A live transport without a published round yet still shows the transport.
  assert.deepEqual(mimicCell({ active: "mosh" }), { transport: "mosh", race: "", limited: "" });
});

test("the pool chip quotes the transport in use and its own distance", () => {
  const server = { selection: { active: "tcp", round: { winner: "tcp", entries: [
    { candidate: "quic", status: "verified", rtt_ms: 63 }, { candidate: "tcp", status: "verified", rtt_ms: 41, penalty: true }] } } };
  assert.deepEqual(transport(server), { active: "tcp", latency: 41 }, "the distance of the line in use, not of the fastest one");
  assert.deepEqual(transport({ selection: { active: "mosh", round: { entries: [{ candidate: "mosh", status: "probing", stage: "probe" }] } } }),
    { active: "mosh", latency: null }, "a line still being probed has no distance");
  assert.deepEqual(transport({ selection: { active: null } }), { active: "", latency: null });
  assert.deepEqual(transport({}), { active: "", latency: null });
});

// ── History kept on the client ──

function history() {
  return { range: "24h", kind: "link", step: 240, from: 0, to: 240 * 4, series: [
    { kind: "link", link: "nl", rule: null, asn: null, rx_bytes: 300, tx_bytes: 30, active_avg: 2, points: [[0, 100, 10], [240, 200, 20]] },
    { kind: "local", link: "", rule: null, asn: null, rx_bytes: 300, tx_bytes: 300, active_avg: 1, points: [[240, 300, 300]] },
  ] };
}

test("history stacks the shown bytes per bucket and keeps unrecorded time apart from zero", () => {
  const total = historyStack(history());
  assert.deepEqual(total.series.map(item => item.values), [[110, 220, null, null], [0, 600, null, null]]);
  assert.equal(total.count, 4);
  // Every bucket sits in the middle of its slot and is held to the slot's edges.
  assert.deepEqual(total.xs, [125, 375, 625, 875]);
  assert.equal(total.hold, 125);
  assert.equal(total.peak, 820 * 8 / 240 / 1e6);
  assert.equal(total.total, 930);
  const sent = historyStack(history(), "tx");
  assert.deepEqual(sent.series.map(item => item.values), [[10, 20, null, null], [0, 300, null, null]]);
  assert.equal(sent.total, 330);
  assert.equal(sent.peak, 320 * 8 / 240 / 1e6);
  // Points outside the window are not drawn; nothing at all is an empty stack, not a crash.
  const edge = historyStack({ step: 60, from: 0, to: 120, series: [{ ...history().series[0], points: [[-60, 5, 5], [120, 5, 5]] }] });
  assert.deepEqual(edge.series[0].values, [null, null]);
  assert.equal(historyStack({ step: 60, from: 0, to: 0, series: [] }).count, 0);
});

test("the history value axis tops out at a round number just above the traffic", () => {
  assert.deepEqual(historyScale(0.0633), { top: 0.1, mid: 0.05 });
  assert.deepEqual(historyScale(0.9), { top: 1, mid: 0.5 });
  assert.deepEqual(historyScale(1.1), { top: 2, mid: 1 });
  assert.deepEqual(historyScale(7), { top: 10, mid: 5 });
  assert.deepEqual(historyScale(0), { top: 0.01, mid: 0.005 });
});

test("history bands are a sandwich of smooth layers with flat ends and honest gaps", () => {
  const day = 240, width = 1000 / day, all = Array(day).fill(true);
  const stack = (values, recorded) => ({
    xs: Array.from({ length: day }, (_, index) => width * (index + 0.5)), hold: width / 2, rate: value => value,
    series: values.map(value => ({ values: value.map((sample, index) => recorded[index] ? sample : null) })),
  });
  const areas = (stack, top) => stackPaths(stack, top).map(layer => layer.band);
  const lines = (stack, top) => stackPaths(stack, top).map(layer => layer.crest);
  const heights = path => [...new Set(path.match(/,[0-9.]+(?=[ CL]|$)/g))].sort();
  // One constant layer over the whole window: a rectangle from the first minute's left edge to the last one's right edge.
  const [flat] = areas(stack([Array(day).fill(1)], all), 4);
  assert.ok(flat.startsWith("M0.00,120.00 C") && flat.includes(" 1000.00,120.00 L1000.00,152.00 C") && flat.endsWith(" 0.00,152.00 Z") && !flat.includes(" M"), flat.slice(0, 90));
  assert.deepEqual(heights(flat), [",120.00", ",152.00"]);
  // Two constant layers: the upper band sits on the lower one, nowhere else.
  const [low, high] = areas(stack([Array(day).fill(1), Array(day).fill(1)], all), 4);
  assert.deepEqual(heights(low), [",120.00", ",152.00"]);
  assert.deepEqual(heights(high), [",120.00", ",88.00"]);
  // An unrecorded minute splits the band in two; each part starts and ends on a minute's edge.
  const recorded = all.slice(); recorded[100] = false;
  const [split] = areas(stack([Array(day).fill(1)], recorded), 4);
  assert.equal((split.match(/M/g) || []).length, 2);
  assert.ok(split.includes(` M${(width * 101).toFixed(2)},120.00 C`) && split.includes(`L${(width * 100).toFixed(2)},152.00`), split.slice(-140));
  // Between two minutes the curve stays within their values: a peak is never sharpened, a dip never deepened.
  const spike = Array(day).fill(0);
  for (const [index, value] of [[50, 10], [150, 0], [151, 10], [152, 0], [200, 10], [201, 20]]) spike[index] = value;
  const [curve] = areas(stack([spike], all), 40);
  const ys = curve.match(/,[0-9.]+(?=[ CL]|$)/g).map(value => Number(value.slice(1)));
  assert.equal(Math.min(...ys), 88);
  assert.equal(Math.max(...ys), 152);
  assert.ok(curve.includes(" L1000.00,152.00 ") && curve.endsWith(" 0.00,152.00 Z"), "the band closes on the edges of the window");
  // A single recorded bucket, as right after a start, is a column as wide as its step.
  const once = Array(day).fill(false); once[day - 1] = true;
  const last = Array(day).fill(0); last[day - 1] = 1;
  const [alone] = areas(stack([last], once), 4);
  const edges = alone.match(/[0-9.]+(?=,)/g).map(Number);
  assert.equal(Math.min(...edges).toFixed(2), (width * (day - 1)).toFixed(2));
  assert.equal(Math.max(...edges), 1000);
  assert.deepEqual(heights(alone), [",120.00", ",152.00"]);
  assert.deepEqual(stackPaths({ ...stack([[]], all), xs: [] }, 4), [{ band: "", crest: "" }]);
  // The hairline of a layer is the top edge of its band and nothing else.
  const [top0, top1] = lines(stack([Array(day).fill(1), Array(day).fill(1)], all), 4);
  assert.deepEqual(heights(top0), [",120.00"]);
  assert.deepEqual(heights(top1), [",88.00"]);
  assert.ok(top0.startsWith("M0.00,120.00 C") && !top0.includes(" L"));
  assert.deepEqual(lines({ ...stack([[]], all), xs: [] }, 4), [""]);
});

test("history time labels grow coarser with the range and its query names the series", () => {
  assert.deepEqual(historyMarks(0, 400), [0, 100, 200, 300, 400]);
  assert.match(historyTime(0, 3600), /^[0-9]{2}:[0-9]{2}$/);
  assert.match(historyTime(0, 86400), /^[0-9]{2}:[0-9]{2}$/);
  // The same weekday comes twice across a week, so the label carries the date.
  assert.match(historyTime(0, 7 * 86400), /^[A-Z][a-z]{2} [0-9]{1,2} [A-Z][a-z]{2}$/);
  assert.match(historyTime(0, 30 * 86400), /^[0-9]{1,2} [A-Z][a-z]{2}$/);
  assert.equal(historyQuery({ range: "7d", kind: "network" }), "/api/history?range=7d&kind=network&top=8");
  assert.equal(historyQuery({ range: "1h", kind: "link", link: "a b:22" }), "/api/history?range=1h&kind=link&top=8&link=a%20b%3A22");
});

test("one axis for every range: the live window counts back, a stored one is a calendar", () => {
  const day = historyStack(history());
  const week = historyStack({ ...history(), from: 0, to: 7 * 86400, step: 3600 });
  const live = liveStack([]);
  // The live window counts back over as much as it holds: seconds, then minutes and seconds, then whole minutes.
  assert.deepEqual(stackMarks(live), ["−10 s", "−8 s", "−5 s", "−3 s", "now"]);
  const grown = liveStack(Array.from({ length: 181 }, (_, index) => ({ time: index * 1000, rx: 1, tx: 1, servers: {} })));
  assert.deepEqual([grown.span, stackMarks(grown)], [180000, ["−3 min", "−2:15", "−1:30", "−45 s", "now"]]);
  const full = liveStack(Array.from({ length: 400 }, (_, index) => ({ time: index * 1000, rx: 1, tx: 1, servers: {} })));
  assert.deepEqual([full.span, stackMarks(full)], [WINDOW_MS, ["−5 min", "−3:45", "−2:30", "−1:15", "now"]], "the window stops growing at five minutes");
  assert.deepEqual(stackMarks(day), [0, 240, 480, 720, 960].map(seconds => historyTime(seconds, 960)));
  assert.deepEqual(stackMarks(week), [0, 7 * 86400 / 4, 7 * 86400 / 2, 3 * 7 * 86400 / 4, 7 * 86400].map(seconds => historyTime(seconds, 7 * 86400)));
  // The moment under the pointer, to the minute for a day, to the hour for a week, to the second live.
  const moment = new Date(2026, 10, 24, 19, 42, 13).getTime() / 1000;
  assert.equal(stackTime({ ...day, from: moment - 86400, to: moment }, moment), "19:42");
  assert.match(stackTime({ ...week, from: moment - 7 * 86400, to: moment }, moment), /^Tue 24 Nov, 19:42$/);
  assert.match(stackTime({ ...week, step: 86400, from: moment - 8 * 86400, to: moment }, moment), /^24 Nov$/);
  assert.equal(stackTime(live, moment * 1000), "19:42:13", "the live clock is in milliseconds, to the second");
  assert.deepEqual([100, 50, 0.05, 2.5, 0.005, 0.25].map(rateLabel), ["100", "50", "0.05", "2.5", "0.005", "0.25"]);
});

test("history series are named by server label, rule label and ASN, the exit kept apart", () => {
  const servers = [{ id: "nl.example.test:22", label: "NL", server: "nl.example.test" }, { id: "de.example.test:22", server: "de.example.test" }];
  const rules = [{ label: "claude", canonical: "names: anthropic.com,claude.ai" }];
  assert.deepEqual(historyName({ kind: "link", link: "nl.example.test:22" }, servers), { label: "NL", via: "" });
  assert.deepEqual(historyName({ kind: "link", link: "de.example.test:22" }, servers), { label: "de.example.test", via: "" });
  assert.deepEqual(historyName({ kind: "link", link: "gone.example:22" }, servers), { label: "gone.example:22", via: "" });
  assert.deepEqual(historyName({ kind: "local", link: "" }, servers), { label: "Local exit", via: "" });
  assert.deepEqual(historyName({ kind: "rule", link: "nl.example.test:22", rule: "names: anthropic.com,claude.ai" }, servers, rules), { label: "claude", via: "NL" });
  assert.deepEqual(historyName({ kind: "rule", link: "local", rule: "fallback" }, servers, rules), { label: "Fallback", via: "Local" });
  assert.deepEqual(historyName({ kind: "rule", link: "nl.example.test:22", rule: "asn:1" }, servers, rules), { label: "asn:1", via: "NL" });
  assert.deepEqual(historyName({ kind: "network", link: "nl.example.test:22", asn: 13335 }, servers, rules), { label: "AS13335", via: "NL" });
  assert.deepEqual(historyName({ kind: "network", link: "nl.example.test:22", asn: 13335 }, servers, rules, { 13335: "Cloudflare" }), { label: "AS13335 · Cloudflare", via: "NL" });
});

test("history windows: yesterday is the browser's own calendar day, a custom one is validated", () => {
  const now = new Date(2026, 10, 24, 19, 42, 13).getTime();
  const yesterday = { from: new Date(2026, 10, 23).getTime() / 1000, to: new Date(2026, 10, 24).getTime() / 1000 };
  assert.deepEqual(historyYesterday(now), yesterday);
  assert.equal(historyQuery({ range: "yesterday", kind: "link" }, now), `/api/history?from=${yesterday.from}&to=${yesterday.to}&kind=link&top=8`);
  assert.equal(historyQuery({ range: "custom", kind: "network", from: 10, to: 20, link: "a b" }), "/api/history?from=10&to=20&kind=network&top=8&link=a%20b");
  assert.equal(historyQuery({ range: "7d", kind: "link" }), "/api/history?range=7d&kind=link&top=8");
  // Only a window that reaches now is worth asking for again.
  assert.equal(historyLive({ range: "24h" }, now), true);
  assert.equal(historyLive({ range: "yesterday" }, now), false);
  assert.equal(historyLive({ range: "custom", from: 1, to: Math.floor(now / 1000) }, now), true);
  assert.equal(historyLive({ range: "custom", from: 1, to: 2 }, now), false);
  assert.equal(historyWindowError({ from: null, to: 2 }), "Pick both ends of the window");
  assert.equal(historyWindowError({ from: 5, to: 5 }), "The end comes after the start");
  assert.equal(historyWindowError({ from: 0, to: 31 * 86400 }), "A window is at most 30 days");
  assert.equal(historyWindowError({ from: 0, to: 30 * 86400 }), null);
  // The picker's own shape goes in and comes out as the same moment.
  const value = historyInputValue(Math.floor(now / 1000));
  assert.equal(value, "2026-11-24T19:42");
  // The picker works to the minute.
  assert.equal(historyInputSeconds(value), Math.floor(now / 60000) * 60);
  assert.equal(historyInputSeconds(""), null);
  assert.equal(historyInputSeconds("not a time"), null);
});

test("a history answer says how wide its points are, and the server's network name wins", () => {
  assert.equal(historyStepLabel(60), "Every minute");
  assert.equal(historyStepLabel(240), "Every 4 min");
  assert.equal(historyStepLabel(3600), "Every hour");
  assert.equal(historyStepLabel(7200), "Every 2 h");
  assert.equal(historyStepLabel(86400), "Every day");
  assert.equal(historyStepLabel(3 * 86400), "Every 3 days");
  const network = { kind: "network", link: "nl.example.test", asn: 24429 };
  const browser = { 24429: "From the browser" };
  assert.deepEqual(historyName({ ...network, asn_name: "From the server" }, [], [], browser), { label: "AS24429 · From the server", via: "nl.example.test" });
  assert.deepEqual(historyName(network, [], [], browser), { label: "AS24429 · From the browser", via: "nl.example.test" });
  assert.deepEqual(historyName(network, [], [], {}), { label: "AS24429", via: "nl.example.test" });
});
