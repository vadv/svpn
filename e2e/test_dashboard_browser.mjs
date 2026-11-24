// Real Chrome self-check and screenshots, using only Node built-ins (no npm install).
// CHROME may override the browser path. DASHBOARD_SCREENSHOTS writes optional render artifacts.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const chrome = process.env.CHROME || (process.platform === "darwin" ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "/usr/bin/google-chrome");
assert.ok(fs.existsSync(chrome), `Chrome not found: ${chrome}; set CHROME to an installed browser`);
const epoch = Date.now();
let scenario = "normal", generation = 1, sequence = 0, lastFrame, namesRequests = 0, historyRequests = 0, historyLast = "";

// Same packets on all three axes. 198.51.100.80 is already closed; unknown and
// pooled contributions keep their bytes even though neither has a provider name.
function usageFixture(interval) {
  const t = () => ({ rx_bytes: 0, tx_bytes: 0 });
  const buckets = () => ({ named: {}, other: t() });
  const usage = { exits: {}, local: t(), networks: buckets(), destinations: buckets(), unknown_asn: t() };
  if (scenario === "empty") return usage;
  for (const [exit, asn, ip, down, up] of [
    [0, 13335, "203.0.113.2", 720, 39], [1, 15169, "203.0.113.3", 320, 65],
    ["local", 13335, "198.51.100.80", 210, 330], [0, 13335, "203.0.113.4", 92, 3],
    [1, null, "203.0.113.1", 28, 4], [0, "other", "other", 8, 2],
  ]) {
    const received = n => Math.round(down * (exit === 1 ? 1600 : exit === "local" ? 0 : 200) * (n + 8 * Math.sin(n / 12)));
    const sent = n => Math.round(up * (exit === "local" ? 0 : 400) * (n + 14 * Math.sin(n / 18)));
    const rx = received(sequence) + (interval ? -received(sequence - 1) : down * 1048576);
    const tx = sent(sequence) + (interval ? -sent(sequence - 1) : up * 1048576);
    const add = b => { b.rx_bytes += rx; b.tx_bytes += tx; };
    add(exit === "local" ? usage.local : usage.exits[exit] ??= t());
    add(asn == null ? usage.unknown_asn : asn === "other" ? usage.networks.other : usage.networks.named[asn] ??= t());
    add(ip === "other" ? usage.destinations.other : usage.destinations.named[ip] ??= t());
  }
  return usage;
}

function frame() {
  const degraded = scenario === "degraded";
  const count = scenario === "large" ? 10003 : scenario === "empty" ? 0 : degraded ? 41 : 123;
  const now = epoch + ++sequence * 1000;
  const started = epoch - 7200000 + generation * 1000;
  const servers = ["nl.example.test", "de.example.test"].map((id, i) => ({
    index: i, id, server: id, label: scenario === "xss" && i === 0 ? '<img src=x onerror="window.pwned=1">' : i ? "DE" : "NL",
    weight: 1, country: i ? null : "NL", mimic: i ? ["webrtc", "ssh"] : [], state: degraded && i ? "backoff" : "ready", reason: degraded && i ? "handshake timeout" : "",
    selection: i
      ? { active: null, round: { finished_at_ms: now - 4000, winner: null, entries: [
        { candidate: "webrtc", status: "failed", reason: "path_timeout" },
        { candidate: "tcp", status: "unanswered", stage: "probe" }] } }
      : { active: "tcp", round: { finished_at_ms: now - 2000, winner: "tcp", entries: [
        { candidate: "quic", status: "verified", rtt_ms: 63, penalty: false },
        { candidate: "tcp", status: "verified", rtt_ms: 41, penalty: true },
        { candidate: "webrtc", status: "failed", reason: "path_timeout" },
        { candidate: "obfs", status: "unanswered", stage: "handshake" }] } },
    stats: { inner_rx_bytes: (i ? 460 : 820) * 1048576 + (degraded && i ? 0 : sequence * (i ? 125000 : 250000)),
      inner_tx_bytes: (i ? 91 : 64) * 1048576 + (degraded && i ? 0 : sequence * (i ? 12500 : 25000)), opened_flows: 85,
      open_failed_flows: degraded && i ? 3 : 0, closed_flows: 12, dropped_packets: degraded && i ? 2 : 0 },
  }));
  const usage = { session: usageFixture(false), interval: usageFixture(true), seconds: 1 };
  if (!degraded) for (const server of servers) {
    const t = usage.session.exits[server.index];
    server.stats.inner_rx_bytes = t?.rx_bytes ?? 0;
    server.stats.inner_tx_bytes = t?.tx_bytes ?? 0;
  }
  const flows = Array.from({ length: count }, (_, i) => ({
    protocol: i % 2 ? "tcp" : "udp", source: `10.77.0.2:${40000 + i}`, destination: `203.0.113.${i % 250 + 1}:443`,
    country: i % 5 === 0 ? null : i % 2 ? "US" : "DE", asn: i % 5 === 0 ? null : i % 2 ? 13335 : 15169,
    via: degraded ? servers[0].id : i % 3 === 0 ? "local" : i % 3 === 1 ? servers[0].id : servers[1].id,
    rule: degraded ? i % 2 ? 0 : null : i % 3 === 0 ? 1 : i % 3 === 1 ? 0 : null,
    // Remote TCP flows closed by FINs: 8 of 123 in `normal`, never local-exit ones.
    closing: i % 2 === 1 && i % 3 !== 0 && i % 10 === 5,
    // LAN devices behind the router's masquerade: every third flow, named on the odd ones.
    client: i % 3 === 1 ? `192.168.0.${20 + i % 40}` : null,
    client_name: i % 3 === 1 && i % 2 ? "iphone-vadv" : null,
    rx_bytes: i === 7 ? sequence * 2000000 : (count - i) * 1000, tx_bytes: 0,
    age_secs: 60 + i, idle_secs: i % 4 ? 0 : 45,
  }));
  const traffic = rule => ({
    rx_bytes: rule === 1 ? 2 * 1073741824 : rule === 0 ? servers[0].stats.inner_rx_bytes / (degraded ? 2 : 1) : servers[1].stats.inner_rx_bytes + (degraded ? servers[0].stats.inner_rx_bytes / 2 : 0),
    tx_bytes: rule === 1 ? 310 * 1048576 : rule === 0 ? servers[0].stats.inner_tx_bytes / (degraded ? 2 : 1) : servers[1].stats.inner_tx_bytes + (degraded ? servers[0].stats.inner_tx_bytes / 2 : 0),
    active_flows: flows.filter(flow => flow.rule === rule && !flow.closing).length,
    closing_flows: flows.filter(flow => flow.rule === rule && flow.closing).length,
  });
  const rules = scenario === "empty" ? [] : [
    { index: 0, label: "claude", canonical: "names: anthropic.com,claude.ai", kind: "names", selector: "names: claude.ai, anthropic.com", via: "servers: nl", local: false, candidates: [servers[0].id],
      owner: servers[0].id, every_secs: 300, resolved_ips: 6, traffic: traffic(0) },
    { index: 1, label: "home", canonical: "cc:RU,BY", kind: "countries", selector: "cc: RU, BY", via: "local", local: true, candidates: [], owner: null, every_secs: 300, resolved_ips: 0, traffic: traffic(1) },
  ];
  const status = { loaded_at: Math.floor(epoch / 1000) - (degraded ? 3900 : 299), attempted_at: Math.floor(epoch / 1000) - 299,
    error: degraded ? "Update failed: exit status: 1; previous table retained" : "" };
  const process = scenario === "peak" ? {
    rss_bytes: null, peak_rss_bytes: 48 * 1048576, cpu_seconds: 12 + sequence * 0.18, cpus: 8,
  } : {
    rss_bytes: 48 * 1048576 + sequence * 65536, peak_rss_bytes: 64 * 1048576,
    cpu_seconds: 12 + sequence * 0.18, cpus: 8,
  };
  const history = { enabled: !["empty", "history-off"].includes(scenario), state: scenario === "history-error" ? "error" : "ok",
    error: scenario === "history-error" ? "1 minute is waiting: disk I/O error" : "", bytes: scenario === "empty" ? 0 : 1908736 };
  return { generated_at: Math.floor(now / 1000), generated_at_ms: now, started_at: started, policy: "balance", asn_table: scenario !== "empty", country_table: true,
    usage, history,
    process, servers: scenario === "empty" ? [] : servers, flows, rules, groups: scenario === "empty" ? [] : [{ group: "claude", server: servers[0].id }], fallback: traffic(null),
    local: { enabled: scenario !== "empty", ready: scenario !== "empty" && !degraded, opened: 41, closed: 5, failed: degraded ? 2 : 0,
      active_flows: flows.filter(flow => flow.via === "local").length, closing_flows: 0 },
    sticky: { lookup_hit: 81, lookup_miss: 2, failover_moves: 0, block_hit: 410, resolve_ok: 8, resolve_fail: 0, resolved_ips: 6, purged_ips: 0 },
    databases: [{ kind: "geo", configured: true, loaded: true, rows: 402389, pending: null, status: { loaded_at: null, attempted_at: null, error: "" } },
      { kind: "country", configured: true, loaded: true, rows: 65123, pending: null, status }],
    jobs: { runs: 8, failures: degraded ? 1 : 0, timeouts: 0, started_at: started, geo: {}, country: status,
      details: scenario === "empty" ? [] : [{ label: "country-update", every_secs: 3600, timeout_secs: 300, reload: ["country"], state: degraded ? "running" : "ok",
        started_at: Math.floor(epoch / 1000) - 300, finished_at: Math.floor(epoch / 1000) - 299,
        success_at: Math.floor(epoch / 1000) - (degraded ? 3900 : 299), next_at: Math.floor(epoch / 1000) + 3301, reason: degraded ? "exit status: 1" : "" }] },
  };
}

// One answer of /api/history per kind. The first fifth of every range was not
// recorded, as when the client was off; the rest carries steady traffic.
function historyFixture(url) {
  const kind = url.searchParams.get("kind"), link = url.searchParams.get("link"), range = url.searchParams.get("range");
  if (!["link", "rule", "network"].includes(kind)) return null;
  const now = Math.floor(Date.now() / 1000);
  let from, to, step, name = range;
  if (range) {
    const length = { "1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000 }[range];
    step = { "1h": 60, "24h": 240, "7d": 3600, "30d": 86400 }[range];
    if (!length) return null;
    to = Math.floor(now / step) * step; from = to - length;
  } else {
    // A picked window, as the server answers it: a start older than a day comes by the hour.
    from = Number(url.searchParams.get("from")); to = Math.min(Number(url.searchParams.get("to")), now);
    step = now - from > 86400 + 900 ? 3600 : 240; name = "custom";
    if (!(to > from) || to - from > 30 * 86400) return null;
    from -= from % step; to -= to % step;
  }
  const all = {
    link: [{ kind: "link", link: "nl.example.test", rule: null, asn: null, rx: 1000000, tx: 200000 },
      { kind: "link", link: "de.example.test", rule: null, asn: null, rx: 500000, tx: 100000 },
      { kind: "local", link: "", rule: null, asn: null, rx: 100000, tx: 0 }],
    rule: [{ kind: "rule", link: "nl.example.test", rule: "names: anthropic.com,claude.ai", asn: null, rx: 900000, tx: 100000 },
      { kind: "rule", link: "local", rule: "cc:RU,BY", asn: null, rx: 100000, tx: 0 },
      { kind: "rule", link: "de.example.test", rule: "fallback", asn: null, rx: 500000, tx: 100000 }],
    // The server names networks from its own ASN CSV; 24429 is in no browser copy.
    network: [{ kind: "network", link: "nl.example.test", rule: null, asn: 13335, asn_name: "Cloudflare, Inc.", rx: 900000, tx: 100000 },
      { kind: "network", link: "de.example.test", rule: null, asn: 15169, asn_name: "Google LLC", rx: 500000, tx: 100000 },
      { kind: "network", link: "nl.example.test", rule: null, asn: 24429, asn_name: "Alibaba (US) Technology Co., Ltd.", rx: 250000, tx: 300000 }],
  };
  const series = all[kind].filter(item => !link || item.link === link).map(({ rx, tx, ...item }) => {
    const points = Array.from({ length: (to - from) / step }, (_, i) => [from + i * step, rx, tx]).slice(Math.floor((to - from) / step / 5));
    if (scenario === "history-once") points.splice(0, points.length - 1);
    return { ...item, rx_bytes: rx * points.length, tx_bytes: tx * points.length, active_avg: 2, points };
  });
  return { range: name, kind, step, from, to, series };
}

// This extra module is injected only by the fixture server, never shipped by SVPN.
const check = `
const $ = id => document.getElementById(id);
const checks = [];
function assert(value, label) { if (!value) throw new Error(label); checks.push(label); }
async function until(condition, label, limit = 7000) {
  const start = performance.now();
  // A condition may be async: one that asks the fixture server.
  while (!(await condition())) { if (performance.now() - start > limit) throw new Error('Timed out: ' + label); await new Promise(resolve => setTimeout(resolve, 100)); }
}
async function control(scenario) { return fetch('/fixture?scenario=' + scenario).then(response => response.json()); }
function input(id, value) { $(id).value = value; $(id).dispatchEvent(new Event(id === 'flow-search' ? 'input' : 'change')); }
try {
  await until(() => $('rx').textContent !== '—' && $('active').textContent === '115', 'live traffic');
  assert($('active-note').textContent.endsWith(' · 8 closing'), 'closing flows are counted in the note, not the headline');
  assert($('rules').tBodies[0].rows[0].cells[3].textContent === '37 active · 4 closing' && $('rules').textContent.includes('41 active'), 'rules split active and closing counts, a rule without closing omits the note');
  assert($('rules').tBodies[0].rows[$('rules').tBodies[0].rows.length - 1].cells[1].textContent === 'Per flow / group', 'fallback exit states per flow / group pinning');
  assert($('local').textContent === 'Ready' && $('local').className === 'compact' && $('ready').className === '', 'local readiness; a healthy summary stays neutral');
  assert($('servers').tBodies[0].rows.length === 2 && !$('servers').textContent.includes('No snapshot'), 'initial server placeholder is removed');
  assert($('chart-rx').getAttribute('d').includes('l0,0') && getComputedStyle($('chart-rx')).strokeLinecap === 'round', 'isolated first chart sample is visible');
  await until(() => $('proc-rss').textContent.includes('MiB') && $('proc-cpu').textContent.includes('%'), 'process RSS and CPU readout');
  assert($('proc-rss-kind').textContent.includes('Current RSS'), 'current RSS is not silently shown as peak');
  assert(Number.parseFloat($('proc-cpu').textContent) > 0, 'CPU percent is derived from cumulative seconds');
  assert(/[0-9]+s average/.test($('proc-cpu-kind').textContent), 'CPU percent states the window it averages over');
  const identity = row => $('servers').tBodies[0].rows[row].cells[0];
  assert(identity(0).querySelector('small').textContent.endsWith(' · NL') && ['nl', '🇳🇱 nl'].some(text => identity(0).querySelector('strong').textContent.toLowerCase().includes(text)), 'server shows its country code, flag only as decoration');
  assert(!identity(1).querySelector('small').textContent.includes(' · ') && !/[\u{1f1e6}-\u{1f1ff}]/u.test(identity(1).textContent), 'server without a country gets no code and no flag');
  const rxCell = $('servers').tBodies[0].rows[0].cells[3];
  await until(() => /^avg [0-9]+s [0-9.]+$/.test(rxCell.querySelector('small')?.textContent ?? ''), 'server RX shows its whole-history average');
  assert(rxCell.querySelector('div').textContent !== '' && rxCell.querySelector('small').textContent.startsWith('avg '), 'current rate stays the headline, average is the note');
  assert($('proc-time').textContent.endsWith(' s'), 'cumulative CPU time is shown');
  assert($('proc-time-note').textContent.includes('8 logical CPUs'), 'logical CPU count is shown');
  assert(/^[0-9]{2}:[0-9]{2}:[0-9]{2}$/.test($('uptime').textContent), 'uptime ticks locally');
  assert($('spark-rss').getAttribute('d').trim() && $('spark-cpu').getAttribute('d').trim(), 'process trends render');
  assert(getComputedStyle(document.body).backgroundImage === 'none', 'no decorative gradient background');
  assert(getComputedStyle($('ready').closest('.card')).borderRadius === '0px', 'sharp instrument-panel cells');
  assert(document.querySelector('header').getBoundingClientRect().height <= 64, 'header stays a single row');
  assert([...document.querySelectorAll('.heading')].every(h => h.getBoundingClientRect().height <= 48), 'panel headings stay on one line');
  const helps = [...document.querySelectorAll('button.help')];
  assert(helps.length >= 5 && helps.every(b => b.getAttribute('aria-describedby') && document.getElementById(b.getAttribute('aria-describedby'))), 'each help trigger has a described tooltip');
  assert(getComputedStyle(document.getElementById(helps[0].getAttribute('aria-describedby'))).display === 'none', 'help is hidden until hover or focus');
  helps[0].focus();
  assert(getComputedStyle(document.getElementById(helps[0].getAttribute('aria-describedby'))).display !== 'none', 'help opens on keyboard focus');
  helps[0].blur();
  const statusTag = document.querySelector('#rules .pill');
  assert(statusTag && getComputedStyle(statusTag).borderTopWidth === '0px', 'status labels are plain text, not button-like boxes');
  assert(!document.querySelector('#rules-panel').textContent.includes('IP bytes since client start'), 'long prose is removed from the rules panel');
  $('theme-toggle').click();
  assert(document.body.dataset.theme === 'light' && document.documentElement.dataset.theme === 'light' && $('theme-toggle').getAttribute('aria-pressed') === 'true' && $('theme-toggle').textContent === 'Theme: light', 'light theme switch');
  $('theme-toggle').click();
  assert(document.body.dataset.theme === 'dark' && $('theme-toggle').getAttribute('aria-pressed') === 'false' && $('theme-toggle').textContent === 'Theme: dark', 'dark theme switch');
  const bodyStyle = getComputedStyle(document.body), titleStyle = getComputedStyle(document.querySelector('.heading h2'));
  assert(/system-ui/.test(bodyStyle.fontFamily) && parseFloat(bodyStyle.fontSize) >= 13 && titleStyle.textTransform === 'none' && parseFloat(titleStyle.fontSize) >= 14, 'interface text is sentence case in the UI face at a readable size');
  assert(!document.querySelector('.caret') && getComputedStyle(document.querySelector('.rail-health'), '::before').animationName === 'none', 'nothing blinks on a healthy dashboard');
  assert([...document.querySelectorAll('#traffic .chart-axis span')].map(span => span.textContent).join('|') === '−5 min|−3:45|−2:30|−1:15|' + $('chart-end').textContent, 'chart carries time ticks');
  assert(Math.abs(Number.parseFloat($('chart-mid').textContent) * 2 - Number.parseFloat($('chart-max').textContent)) < 0.02, 'value axis labels its middle gridline');
  assert($('flow-reset').disabled, 'clear filters stays quiet without filters');
  assert($('rules').textContent.includes('Local only'), 'explicit local rule');
  assert(!$('rules').textContent.includes('0 IPs'), 'country is not a DNS rule');
  assert($('servers').textContent.includes('tcp 41 ms (+penalty) · quic 63 ms · webrtc timeout · obfs handshake'), 'race is shown, winner first');
  assert($('servers').textContent.includes('Selecting…') && $('servers').textContent.includes('limited: webrtc · ssh'), 'pending selection and config restriction are shown');
  assert(!$('servers').textContent.includes('Auto'), 'configured-only mimic text is gone');
  await until(() => $('asn-status').textContent.includes('2 names'), 'CSV parsed and cached in browser');
  assert($('rank-networks').querySelector('button').textContent.includes('Cloudflare'), 'session provider ranks use ASN organization names');
  assert($('rank-exits').querySelector('button').textContent === 'NL', 'session ranks use bytes, including local exit');
  input('usage-direction', 'tx');
  assert($('rank-exits').querySelector('button').textContent === 'Local exit', 'sent bytes reorder exits numerically');
  input('usage-direction', 'total'); $('usage-now').click();
  assert($('rank-exits').querySelector('button').textContent === 'DE' && $('usage-total').textContent.includes('Mbit/s'), 'latest interval has a different busiest exit and rate units');
  $('rank-networks').querySelector('button').click();
  assert([...$('flows').tBodies[0].rows].every(row => row.cells[4].textContent.includes('AS15169')) && $('flow-order').value === 'rate', 'inspect the busy provider by current flow rate');
  $('clear-drill').click(); $('usage-session').click();
  [...$('rank-destinations').querySelectorAll('button')].find(b => b.textContent === '198.51.100.80').click();
  assert($('flows').textContent.includes('Completed traffic remains'), 'retired destination keeps its traffic without a fictitious flow');
  $('clear-drill').click();
  $('rank-destinations').nextElementSibling.click();
  assert($('rank-destinations').textContent.includes('Other · pooled'), 'expanded ranks include the bounded tail');
  $('rank-destinations').nextElementSibling.click();
  const requestsBefore = (await control('normal')).asn_requests;
  await new Promise(resolve => setTimeout(resolve, 1200));
  assert((await control('normal')).asn_requests === requestsBefore, 'CSV is not fetched by one-second snapshot polling');
  // History is read once its section is in view, then once a minute at most.
  $('history-panel').scrollIntoView({ behavior: 'instant', block: 'start' });
  await until(() => document.querySelectorAll('#history-bands .band').length === 3, 'history bands');
  let historyReads = (await control('normal')).history_requests;
  await new Promise(resolve => setTimeout(resolve, 1200));
  assert((await control('normal')).history_requests === historyReads, 'history is not fetched by one-second snapshot polling');
  assert(['cat-1', 'cat-2', 'cat-3'].every((name, i) => $('history-bands').children[i].classList.contains(name)), 'history series take the categorical palette in rank order');
  assert(['NL', 'DE', 'Local exit'].every((label, i) => $('history-legend').children[i].textContent === label), 'history legend names servers by label and the local exit');
  const historyRow = index => [...$('history').tBodies[0].rows[index].cells].map(cell => cell.textContent);
  assert(historyRow(0)[0] === 'NL' && historyRow(0)[1] === '274.7 MiB' && historyRow(0)[3] === '329.6 MiB' && historyRow(0)[4] === '63.2%' && historyRow(0)[5] === '2.0', 'history totals list bytes, share of the range and average flows');
  assert(historyRow(2)[0] === 'Local exit' && $('history').tBodies[0].rows.length === 3, 'history table lists every series of the breakdown');
  assert(Math.abs(Number.parseFloat($('history-mid').textContent) * 2 - Number.parseFloat($('history-max').textContent)) < 0.02 && $('history-max').textContent.endsWith('Mbit/s'), 'history value axis labels its middle gridline');
  assert([...$('history-axis').children].every(span => /^[0-9]{2}:[0-9]{2}$/.test(span.textContent)), 'a day of history is labelled with clock times');
  assert(/^M[0-9.]+,[0-9.]+ C/.test($('history-bands').children[0].getAttribute('d')) && $('history-bands').children[0].getAttribute('d').endsWith('Z') && !$('history-empty').offsetParent, 'recorded minutes draw as smooth stacked bands');
  const drawn = [...document.querySelectorAll('#history-bands .band')], crests = [...document.querySelectorAll('#history-bands .crest')];
  assert(drawn.length === 3 && drawn.every(band => band instanceof SVGPathElement && band.getBoundingClientRect().height > 0 && getComputedStyle(band).fill !== 'none' && getComputedStyle(band).stroke === 'none') && drawn[0].getBoundingClientRect().height > 40, 'bands are filled SVG paths that rise from the baseline');
  assert(crests.length === 3 && crests.every(crest => getComputedStyle(crest).stroke !== 'none' && getComputedStyle(crest).fill === 'none' && crest.getAttribute('d').startsWith('M')), 'each layer has a hairline along its top, so a thin layer stays visible on a thick one');
  assert($('history-resolution').textContent === 'Every 4 min', 'history says how wide its points are');
  // A pressed first button keeps its own border where the next one overlaps it, in every segmented group.
  const rangeButton = name => document.querySelector('#history-ranges [data-range="' + name + '"]');
  rangeButton('1h').click();
  await until(() => $('history-resolution').textContent === 'Every minute' && document.querySelectorAll('#history-bands .band').length === 3, 'one hour of history');
  assert(rangeButton('1h').getAttribute('aria-pressed') === 'true' && getComputedStyle(rangeButton('1h')).zIndex === '1' && getComputedStyle(rangeButton('24h')).zIndex === 'auto' && getComputedStyle($('usage-session')).zIndex === '1', 'a pressed button sits above its neighbours whoever it is');
  rangeButton('24h').click();
  await until(() => $('history-resolution').textContent === 'Every 4 min', 'back to a day of history');
  historyReads = (await control('normal')).history_requests;
  // A database that just started holds one bucket: it is a column, not nothing.
  const bandWidth = () => $('history-bands').children[0].getBoundingClientRect().width;
  await control('history-once'); rangeButton('24h').click();
  await until(() => bandWidth() > 0 && bandWidth() < 5, 'a single recorded bucket');
  assert(bandWidth() > 2 && !$('history-empty').offsetParent, 'one recorded bucket is drawn as a column as wide as its step');
  await control('normal'); rangeButton('24h').click();
  await until(() => bandWidth() > 500, 'the whole day again');
  historyReads = (await control('normal')).history_requests;
  input('history-direction', 'tx');
  assert(historyRow(0)[4] === '66.7%' && (await control('normal')).history_requests === historyReads, 'another direction redraws the same answer');
  input('history-kind', 'network');
  await until(() => $('history-legend').textContent.includes('AS13335'), 'network history');
  assert(document.querySelectorAll('#history-bands .band').length === 3, 'the twenty busiest networks are drawn, here all three');
  assert($('history-legend').textContent.includes('AS13335 · Cloudflare, Inc.') && $('history').tBodies[0].rows[0].cells[0].textContent.includes('via NL'), 'networks are named by ASN and organization, the exit is the second line');
  assert($('history-legend').textContent.includes('AS24429 · Alibaba (US) Technology Co., Ltd.'), 'a network is named by the server, with no browser copy of the ASN CSV');
  input('history-server', 'de.example.test');
  await until(() => document.querySelectorAll('#history-bands .band').length === 1, 'history of one server');
  assert($('history-legend').textContent.includes('AS15169 · Google LLC'), 'the server filter narrows the series');
  document.querySelector('#history-ranges [data-range="7d"]').click();
  await until(() => $('history-axis').children[0].textContent.includes(' '), 'week of history');
  assert(document.querySelector('#history-ranges [data-range="7d"]').getAttribute('aria-pressed') === 'true' && [...$('history-axis').children].every(span => /^[A-Z][a-z][a-z] [0-9]+ [A-Z][a-z][a-z]$/.test(span.textContent)) && $('history-axis').children[0].textContent !== $('history-axis').children[4].textContent, 'range buttons state the choice and the axis names the days: ' + JSON.stringify([...$('history-axis').children].map(span => span.textContent)));
  // Yesterday is one click: the whole local day before this one, by the hour.
  rangeButton('yesterday').click();
  await until(() => $('history-resolution').textContent === 'Every hour' && $('history-axis').children[1].textContent !== $('history-axis').children[3].textContent, 'yesterday');
  const yesterday = new URLSearchParams((await control('normal')).history_last);
  const midnight = new Date(Number(yesterday.get('to')) * 1000);
  assert(yesterday.has('from') && yesterday.has('to') && !yesterday.has('range') && midnight.getHours() === 0 && midnight.getMinutes() === 0 && Math.round((Number(yesterday.get('to')) - Number(yesterday.get('from'))) / 3600) === 24 && rangeButton('yesterday').getAttribute('aria-pressed') === 'true', 'Yesterday asks for the whole local day before this one');
  // Custom opens on the last day and takes any window of up to 30 days.
  rangeButton('custom').click();
  await until(() => !$('history-custom').hidden && $('history-resolution').textContent === 'Every 4 min', 'custom window');
  assert(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}$/.test($('history-from').value) && $('history-to').value > $('history-from').value, 'the picker is filled with the last day');
  $('history-to').value = $('history-from').value; $('history-apply').click();
  assert($('history-note').textContent === 'The end comes after the start' && !$('history-note').classList.contains('bad'), 'a custom window with its ends reversed is refused in place');
  const pad = value => String(value).padStart(2, '0'), day = date => date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate());
  const first = new Date(), last = new Date(); first.setDate(first.getDate() - 2); last.setDate(last.getDate() - 1);
  $('history-from').value = day(first) + 'T03:30'; $('history-to').value = day(last) + 'T21:15'; $('history-apply').click();
  const asked = '?from=' + Math.floor(new Date(day(first) + 'T03:30').getTime() / 1000) + '&to=' + Math.floor(new Date(day(last) + 'T21:15').getTime() / 1000) + '&';
  const firstLabel = new Date(day(first) + 'T03:30').toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short' });
  await until(async () => (await control('normal')).history_last.startsWith(asked) && $('history-axis').children[0].textContent === firstLabel, 'the picked window');
  assert($('history-note').hidden && rangeButton('custom').getAttribute('aria-pressed') === 'true' && $('history-axis').children[0].textContent !== $('history-axis').children[4].textContent, 'the picked window is drawn by the hour');
  await control('history-error');
  await until(() => $('history-note').textContent.includes('not being recorded'), 'history error is visible');
  assert($('history-note').classList.contains('bad') && $('history-note').textContent.includes('disk I/O error') && document.querySelectorAll('#history-bands .band').length === 1, 'a failing history database is the loud case, the last answer stays drawn');
  await control('history-off');
  await until(() => $('history-note').textContent.includes('History is off'), 'history off is explained');
  assert($('history-kind').disabled && $('history-from').disabled && $('history-apply').disabled && rangeButton('custom').disabled && !$('history-note').classList.contains('bad'), 'history controls are quiet while history is off');
  await control('normal');
  await until(() => !$('history-kind').disabled, 'history recovers');
  input('history-server', ''); input('history-kind', 'link');
  input('flow-country', 'US'); input('flow-asn', '13335');
  const countryCells = [...$('flows').tBodies[0].rows].map(row => row.cells[3].textContent);
  // Headless Chrome without an emoji font draws no flag: the code is mandatory, the flag is not.
  assert(new Set(countryCells).size === 1 && ['US', '\u{1f1fa}\u{1f1f8} US'].includes(countryCells[0]), 'country cell is the code, consistently flagged or not');
  assert([...$('flows').tBodies[0].rows].every(row => row.cells[4].textContent.includes('AS13335 · Cloudflare')), 'country and ASN filters combine');
  input('flow-search', 'cloudflare');
  assert(!$('flows').textContent.includes('No flows match'), 'organization search works');
  input('flow-search', ''); input('flow-country', 'unknown'); input('flow-asn', 'unknown');
  assert([...$('flows').tBodies[0].rows].every(row => row.cells[3].textContent === 'Unknown' && row.cells[4].textContent === 'Unknown'), 'unknown Geo metadata has explicit filters');
  input('flow-country', ''); input('flow-asn', '');
  const flowRow = index => $('flows').tBodies[0].rows[index].cells;
  const sourceCell = index => { const cell = flowRow(index)[1]; return { main: cell.querySelector('strong')?.textContent ?? '', note: cell.querySelector('small')?.textContent ?? '' }; };
  const isSource = (index, main, note) => sourceCell(index).main === main && sourceCell(index).note === note;
  assert($('flow-order').value === 'total', 'total order is the default');
  input('flow-order', 'rate');
  await until(() => sourceCell(0).note === 'via 10.77.0.2:40007' && flowRow(0)[7].querySelector('strong')?.textContent === '16.00', 'rate order puts the busiest flow first with its Mbit/s');
  assert(isSource(0, 'iphone-vadv · 192.168.0.27', 'via 10.77.0.2:40007'), 'a LAN device shows as the source with the tunnel address as the note');
  assert(flowRow(1)[7].querySelector('strong').textContent === '0.00' && flowRow(0)[7].querySelector('small').textContent.endsWith('MiB'), 'idle flows read 0, the total sits under the rate');
  input('flow-order', 'total');
  await until(() => sourceCell(0).note === 'via 10.77.0.2:40007', 'total order ranks by bytes so far');
  assert(isSource(1, 'router', '10.77.0.2:40000'), 'a flow without a LAN client is the router itself');
  input('flow-order', '');
  await until(() => sourceCell(0).note === '10.77.0.2:40000', 'address order keeps the snapshot order');
  assert(flowRow(0)[0].textContent === 'UDPQUIC' && flowRow(1)[0].textContent.startsWith('TCPHTTPS'), 'the protocol cell guesses the service from the port');
  assert(flowRow(0)[8].querySelector('strong').textContent === '00:01:00' && flowRow(0)[8].querySelector('small').textContent === 'idle 00:00:45'
    && flowRow(1)[8].querySelector('small').textContent === 'active now', 'the age column shows lifetime and silence');
  input('flow-search', 'iphone-vadv');
  assert($('flows').tBodies[0].rows.length === 21 && isSource(0, 'iphone-vadv · 192.168.0.21', 'via 10.77.0.2:40001'), 'search finds flows by device name');
  input('flow-search', '192.168.0.27');
  assert($('flows').tBodies[0].rows.length === 1 && isSource(0, 'iphone-vadv · 192.168.0.27', 'via 10.77.0.2:40007'), 'search finds flows by LAN address');
  input('flow-search', '');
  assert([...$('flows').tBodies[0].rows].some(row => row.classList.contains('closing')) && $('flows').textContent.includes('closing'), 'closing flows are dimmed and tagged');
  $('asn-load').click();
  await until(() => $('asn-status').textContent.includes('Loading'), 'explicit browser CSV reload');
  await until(() => $('asn-status').textContent.includes('2 names') && !$('asn-load').disabled, 'browser names reload completes');
  const realTimeout = window.setTimeout;
  window.setTimeout = (fn, ms, ...args) => realTimeout(fn, ms === 300000 ? 30 : ms, ...args);
  Object.defineProperty(document, 'hidden', { configurable: true, value: true });
  document.dispatchEvent(new Event('visibilitychange'));
  await until(() => $('asn-status').textContent.startsWith('Freed after 5 min hidden'), 'hidden-tab idle eviction');
  assert(!$('flows').textContent.includes('Cloudflare') && !$('asn-load').disabled, 'eviction releases dictionary and leaves numbers and reload available');
  window.setTimeout = realTimeout; delete document.hidden;
  document.dispatchEvent(new Event('visibilitychange'));
  $('asn-load').click();
  await until(() => $('asn-status').textContent.includes('2 names'), 'explicit load after eviction');
  await control('names-error'); $('asn-load').click();
  await until(() => $('asn-status').textContent.includes('HTTP 503'), 'CSV fetch error is explicit');
  assert($('freshness').textContent === 'Live', 'CSV errors do not break live state polling');
  await control('normal'); $('asn-load').click();
  await until(() => $('asn-status').textContent.includes('2 names'), 'CSV retry recovers');
  const details = document.querySelector('#servers details'); details.open = true;
  await control('large');
  await until(() => $('active').textContent === '9336', 'large flow snapshot');
  assert($('flows').tBodies[0].rows.length === 50, 'large table bounded to 50 rows');
  assert(document.querySelector('#servers details') === details && details.open, 'details identity and open state preserved');
  input('flow-search', '49999'); input('flow-protocol', 'tcp'); input('flow-exit', 'local');
  assert($('flows').tBodies[0].rows.length === 1 && $('flows').textContent.includes('49999'), 'combined flow filters');
  assert(!$('flow-reset').disabled, 'clear filters is offered once a filter is active');
  $('flow-reset').click();
  assert(['flow-search','flow-protocol','flow-exit'].every(id => $(id).value === '') && $('flow-reset').disabled, 'clear filters resets the search and the selectors');
  input('flow-search', ''); input('flow-protocol', ''); input('flow-exit', 'de.example.test');
  input('flow-country', 'US'); input('flow-asn', '13335');
  $('next').click(); assert($('flow-page').textContent.startsWith('2 /'), 'next flow page');
  $('pause').click();
  const frozen = $('flows').textContent, frozenExits = $('flow-exit').textContent;
  const frozenCountries = $('flow-country').textContent, frozenAsns = $('flow-asn').textContent;
  await control('empty');
  await until(() => $('active').textContent === '0', 'live servers removed while paused');
  assert($('flow-exit').value === 'de.example.test' && $('flow-exit').textContent === frozenExits, 'paused exit options and selection use the frozen snapshot');
  assert($('flow-country').value === 'US' && $('flow-asn').value === '13335' && $('flow-country').textContent === frozenCountries && $('flow-asn').textContent === frozenAsns, 'pause freezes Geo metadata, names and filter options');
  assert($('flows').textContent === frozen && frozen.includes('DE'), 'paused server and rule labels survive live config changes');
  await control('normal');
  await until(() => $('active').textContent === '115', 'live summary while paused');
  assert($('flows').textContent === frozen && $('flow-count').textContent.includes('10003') && $('pause').getAttribute('aria-pressed') === 'true', 'flow table stays frozen');
  $('pause').click(); assert($('pause').getAttribute('aria-pressed') === 'false', 'resume live table');
  input('flow-exit', ''); input('flow-country', ''); input('flow-asn', '');
  await control('xss');
  await until(() => $('servers').textContent.includes('<img'), 'untrusted label rendered');
  $('asn-load').click();
  await until(() => $('asn-status').textContent.includes('2 names') && $('flows').textContent.includes('<img'), 'untrusted CSV names loaded in browser');
  assert($('flows').textContent.includes('<img'), 'organization names render as text');
  assert(!document.querySelector('main img') && !window.pwned, 'snapshot text cannot inject HTML');
  const restart = await control('restart');
  await until(() => $('footer').textContent.includes(new Date(restart.started_at).toLocaleString()), 'client restart');
  assert($('rx').textContent === '—' && !$('chart-rx').getAttribute('d').trim(), 'restart clears rates and graph');
  assert($('proc-cpu').textContent === '—', 'restart clears the derived CPU percentage');
  await until(() => $('rx').textContent !== '—', 'rates resume after restart');
  await control('degraded');
  await until(() => $('jobs').tBodies[0].textContent.includes('Previous attempt: '), 'a retrying job keeps its previous failure visible');
  assert($('jobs').tBodies[0].rows[0].cells[4].textContent === 'Running', 'running job shows Running instead of a next-check time');
  assert($('local').className === 'compact bad' && $('ready').className === 'warn' && $('freshness').className === 'pill good', 'trouble is the only coloured thing in the summary');
  assert(!document.querySelector('#servers .pill.bad') && document.querySelector('#servers .pill.warn')?.textContent === 'Backoff', 'state tags read as words');
  await control('normal');
  await until(() => !$('jobs').textContent.includes('Previous attempt:'), 'clean job drops the previous-attempt prefix');
  await control('offline');
  await until(() => $('freshness').textContent === 'Stale data', 'API failure is visible immediately');
  assert($('proc-rss').textContent === '—' && $('proc-cpu').textContent === '—', 'stale process values are not shown as live');
  $('usage-now').click(); assert($('usage-total').textContent === '—' && $('rank-exits').textContent.includes('stale'), 'stale interval is unknown, never zero');
  $('usage-session').click(); assert($('usage-period').textContent.includes('last snapshot'), 'stale session totals are labelled');
  assert((await fetch('/api/state')).status === 503, 'HTTP error fixture');
  const beforeApiGap = $('chart-rx').getAttribute('d');
  await control('frozen');
  await until(() => $('freshness').textContent === 'Live', 'same-timestamp response clears the API error', 2500);
  assert($('chart-rx').getAttribute('d') === beforeApiGap, 'duplicate recovery does not add a chart sample');
  assert($('rx').textContent === '—' && $('legend-rx').textContent.includes('—'), 'duplicate recovery does not reuse a pre-error rate');
  assert(!$('chart-note').textContent.includes('not live'), 'duplicate recovery restores chart freshness');
  const recoveredAt = $('chart-end').textContent;
  await control('normal');
  await until(() => $('chart-end').textContent !== recoveredAt, 'first new snapshot after duplicate recovery');
  assert($('rx').textContent === '—', 'short API gap is not averaged into a rate');
  await until(() => $('rx').textContent !== '—', 'two fresh snapshots restore rates');
  await control('frozen');
  await until(() => $('freshness').textContent === 'Stale data', 'unchanged snapshot becomes stale');
  assert(!$('stale-notice').hidden && $('rx').textContent === '—', 'stale screen has warning and unknown rate');
  await control('empty');
  await until(() => $('active').textContent === '0' && $('freshness').textContent === 'Live', 'recovery and empty flow table');
  assert($('rx').textContent === '—', 'stale recovery starts with an unknown rate');
  assert($('flows').textContent.includes('No active flows'), 'empty flow state');
  assert($('servers').textContent.includes('No servers configured'), 'empty server table is explicit');
  input('flow-search', 'missing'); await control('normal');
  await until(() => $('active').textContent === '115', 'filtered recovery');
  assert($('flows').textContent.includes('No flows match'), 'empty filter message updates');
  assert($('servers').tBodies[0].rows.length === 2 && !$('servers').textContent.includes('No servers'), 'servers recover without a stale placeholder');
  input('flow-search', '');
  await control('peak');
  await until(() => $('proc-rss-kind').textContent.includes('Peak RSS'), 'peak RSS fallback is labelled');
  assert($('proc-note').textContent.includes('not live RSS'), 'fallback note says the value is not live RSS');
  document.documentElement.dataset.browserCheck = JSON.stringify({ status: 'passed', checks });
} catch (error) {
  document.documentElement.dataset.browserCheck = JSON.stringify({ status: 'failed', error: String(error), checks });
}
`;

const server = http.createServer((request, response) => {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/fixture") {
    scenario = url.searchParams.get("scenario");
    if (scenario === "restart") { generation++; scenario = "normal"; }
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ started_at: epoch - 7200000 + generation * 1000, asn_requests: namesRequests, history_requests: historyRequests, history_last: historyLast }));
    return;
  }
  if (url.pathname === "/api/asn.csv") {
    namesRequests++;
    if (scenario === "names-error") { response.writeHead(503); response.end("unavailable"); return; }
    const organization = scenario === "xss" ? '<img src=x onerror="window.pwned=1">' : "Cloudflare, Inc.";
    const csv = `1.0.0.0,1.0.0.255,13335,"${organization.replaceAll('"', '""')}"\n2.0.0.0,2.0.0.255,15169,Google LLC\n`;
    response.setHeader("Content-Type", "text/csv; charset=utf-8");
    setTimeout(() => response.end(csv), 500); return;
  }
  if (url.pathname === "/api/history") {
    historyRequests++; historyLast = url.search;
    if (scenario === "history-off") { response.writeHead(503); response.end("history is off"); return; }
    if (scenario === "history-error") { response.writeHead(503); response.end("1 minute is waiting: disk I/O error"); return; }
    const answer = historyFixture(url);
    response.setHeader("Content-Type", "application/json");
    if (answer) response.end(JSON.stringify(answer)); else { response.writeHead(400); response.end("bad query"); }
    return;
  }
  if (url.pathname === "/api/state") {
    response.setHeader("Content-Type", "application/json");
    if (["offline", "cold"].includes(scenario)) { response.writeHead(503); response.end("{}"); return; }
    if (scenario !== "frozen") lastFrame = frame();
    response.end(JSON.stringify(lastFrame)); return;
  }
  if (url.pathname === "/") {
    scenario = url.searchParams.get("scenario") || "normal";
    if (url.searchParams.has("render")) sequence = 0;
    const html = fs.readFileSync(path.join(root, "src/web/index.html"), "utf8");
    response.setHeader("Content-Type", "text/html");
    response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
    response.end(url.searchParams.has("render") ? html : html.replace("</body>", '<script type="module" src="/check.mjs"></script></body>'));
    return;
  }
  if (url.pathname === "/check.mjs") { response.setHeader("Content-Type", "text/javascript"); response.end(check); return; }
  if (["/dashboard.mjs", "/state.mjs"].includes(url.pathname)) {
    response.setHeader("Content-Type", "text/javascript");
    response.end(fs.readFileSync(path.join(root, "src/web", url.pathname.slice(1)))); return;
  }
  response.writeHead(404); response.end();
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const profiles = [];
async function browser(query = "", screenshot, mobile = false) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "svpn-dashboard-chrome-")); profiles.push(profile);
  // A real emulated viewport avoids Chrome's minimum desktop-window width cropping mobile renders.
  // CDP's built-in NUL-delimited pipe needs neither a WebSocket package nor a debugging TCP port.
  const child = spawn(chrome, ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-background-networking",
    `--user-data-dir=${profile}`, "--hide-scrollbars", "--remote-debugging-pipe", "about:blank"],
    { stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"] });
  const finished = new Promise(resolve => child.once("close", resolve));
  let buffer = "", stderr = "", serial = 0, failure, onLoad;
  const pending = new Map();
  const fail = error => { failure = error; for (const request of pending.values()) request.reject(error); pending.clear(); };
  child.on("error", fail);
  child.on("exit", () => fail(new Error(`Chrome exited: ${stderr}`)));
  child.stderr.on("data", chunk => { stderr = (stderr + chunk).slice(-4000); });
  child.stdio[3].on("error", fail);
  child.stdio[4].on("error", fail);
  child.stdio[4].setEncoding("utf8");
  child.stdio[4].on("data", chunk => {
    buffer += chunk;
    let boundary;
    while ((boundary = buffer.indexOf("\0")) >= 0) {
      const raw = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 1);
      try {
        const message = JSON.parse(raw), request = pending.get(message.id);
        if (message.method === "Page.loadEventFired") onLoad?.();
        if (!request) continue;
        pending.delete(message.id);
        if (message.error) request.reject(new Error(JSON.stringify(message.error)));
        else request.resolve(message.result);
      } catch (error) { fail(error); }
    }
  });
  function call(method, params = {}, sessionId) {
    if (failure) return Promise.reject(failure);
    return new Promise((resolve, reject) => {
      const id = ++serial;
      pending.set(id, { resolve, reject });
      child.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + "\0");
    });
  }
  const timeout = setTimeout(() => { fail(new Error("Chrome check timed out")); child.kill("SIGKILL"); }, 90000);
  try {
    const { targetId } = await call("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await call("Target.attachToTarget", { targetId, flatten: true });
    const page = (method, params) => call(method, params, sessionId);
    const evaluate = async expression => {
      const result = await page("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
      assert.ok(!result.exceptionDetails, JSON.stringify(result.exceptionDetails));
      return result.result.value;
    };
    const width = mobile ? 390 : 1440, height = mobile ? 1100 : 1250;
    await page("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile });
    await page("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });
    await evaluate("new Promise(resolve => { if (document.readyState === 'complete') resolve(); else addEventListener('load', resolve, { once: true }); })");
    await page("Page.enable");
    // Replay five minutes of timestamped fixture snapshots for screenshots. The real
    // module still fetches each frame and derives its own chart, ranks and labels.
    const replay = screenshot && !query.includes("cold");
    if (replay) await page("Page.addScriptToEvaluateOnNewDocument", { source: `{
      const schedule = window.setTimeout;
      window.setTimeout = (fn, ms, ...args) => schedule(fn, ms === 1000 ? 20 : ms, ...args);
    }` });
    const loaded = new Promise(resolve => { onLoad = resolve; });
    await page("Page.navigate", { url: origin + "/" + query });
    await loaded; onLoad = null;
    await evaluate(`new Promise(resolve => { const timer = setInterval(() => {
      const done = ${query ? `document.getElementById('freshness')?.textContent === '${query.includes("cold") ? "API unavailable" : "Live"}' && ${query.includes("cold") ? "true" : "document.getElementById('rx')?.textContent !== '—'"}` : "document.documentElement.dataset.browserCheck"};
      if (done) { clearInterval(timer); resolve(true); }
    }, 100); })`);
    if (replay) await evaluate(`new Promise(resolve => { const timer = setInterval(() => {
      if (parseInt(document.querySelector('#servers tbody tr td:nth-child(4) small')?.textContent.slice(4), 10) >= 300) {
        clearInterval(timer); resolve();
      }
    }, 100); })`);
    const layout = await evaluate(`({ width: innerWidth, scroll: document.documentElement.scrollWidth,
      fontHeight: document.getElementById('chart-max').getBoundingClientRect().height,
      cardsFit: [...document.querySelectorAll('.summary .card, header, .scroll')].every(node => node.getBoundingClientRect().right <= innerWidth),
      navFit: (() => { const nav = document.querySelector('.rail-nav');
        return nav.scrollWidth <= nav.clientWidth + 1 && [...nav.querySelectorAll('a')].every(a =>
          a.getBoundingClientRect().right <= innerWidth && a.scrollWidth <= a.clientWidth + 1); })(),
      cardGaps: [...document.querySelectorAll('.summary .card')].map(card => {
        const visible = [...card.children].filter(ch => ch.getBoundingClientRect().height > 0);
        return Math.round(card.getBoundingClientRect().bottom - Math.max(...visible.map(ch => ch.getBoundingClientRect().bottom))); }),
      jobsTop: document.getElementById('database-title').closest('section').getBoundingClientRect().top + scrollY,
      jobsHeight: document.getElementById('database-title').closest('section').getBoundingClientRect().height,
      helpPopups: (() => { for (const button of document.querySelectorAll('button.help')) {
        const pop = document.getElementById(button.getAttribute('aria-describedby'));
        button.focus();
        const rect = pop.getBoundingClientRect();
        const fits = getComputedStyle(pop).display !== 'none' && document.documentElement.scrollWidth <= innerWidth
          && rect.left >= 0 && rect.right <= document.documentElement.clientWidth;
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
        if (!fits || getComputedStyle(pop).display !== 'none' || document.activeElement !== button)
          return button.getAttribute('aria-label') + ': open popup must fit the viewport and close on Escape';
        button.blur();
      } return true; })() })`);
    assert.equal(layout.width, width, "real browser viewport size");
    assert.ok(layout.scroll <= width, `page overflows: ${JSON.stringify(layout)}`);
    assert.ok(layout.cardsFit, `cards and scroll containers fit viewport: ${JSON.stringify(layout)}`);
    assert.ok(layout.navFit, `all navigation items visible, no hidden horizontal scrolling: ${JSON.stringify(layout)}`);
    assert.ok(layout.helpPopups === true, `help popups fit and close on Escape: ${JSON.stringify(layout)}`);
    // A card may stretch to a neighbour's two-line note; a hidden sparkline used to add ~38px of dead space.
    if (mobile) {
      assert.ok(layout.cardGaps.every(gap => gap <= 28), `KPI cards keep compact bottoms on mobile: ${JSON.stringify(layout)}`);
      assert.ok(await evaluate(`(() => { const select = document.getElementById('usage-axis');
        select.value = 'networks'; select.dispatchEvent(new Event('change'));
        return document.getElementById('rank-networks').offsetWidth > 0 && !document.getElementById('rank-exits').offsetWidth;
      })()`), 'mobile switches to provider ranks without sideways scrolling');
    }
    assert.ok(layout.fontHeight >= 10, "chart axis labels are legible without SVG scaling");
    if (query.includes("cold")) {
      assert.ok(await evaluate("['pause','previous','next','chart-server','flow-search','flow-protocol','flow-exit','flow-country','flow-asn','asn-load','flow-reset'].every(id => document.getElementById(id).disabled)"), "cold controls disabled");
      assert.ok(await evaluate("!document.getElementById('chart-empty').hidden"), "cold chart shows a collecting placeholder");
    }
    if (screenshot) {
      await evaluate("window.scrollTo({top:0, behavior:'instant'})");
      if (query.includes('view=now')) await evaluate("document.getElementById('usage-now').click(); document.getElementById('theme-toggle').click()");
      if (query.includes('view=provider')) await evaluate("document.querySelector('#rank-networks button').click()");
      // History is read once its section is in view, as on a real scroll.
      if (query.includes('view=history')) await evaluate(`(async () => {
        document.getElementById('history-panel').scrollIntoView({ behavior: 'instant', block: 'start' });
        await new Promise(resolve => { const timer = setInterval(() => {
          if (document.getElementById('history-bands').children.length) { clearInterval(timer); resolve(); }
        }, 100); });
      })()`);
      const y = query.includes('view=provider') ? await evaluate("document.getElementById('flows-panel').getBoundingClientRect().top + scrollY - 8")
        : query.includes('view=history') ? await evaluate("document.getElementById('history-panel').getBoundingClientRect().top + scrollY - 8") : 0;
      const image = await page("Page.captureScreenshot", { format: "png", captureBeyondViewport: true,
        clip: { x: 0, y, width, height, scale: 1 } });
      fs.writeFileSync(screenshot, Buffer.from(image.data, "base64"));
      if (query.includes("degraded")) {
        const jobs = await page("Page.captureScreenshot", { format: "png", captureBeyondViewport: true,
          clip: { x: 0, y: layout.jobsTop - 8, width, height: Math.ceil(layout.jobsHeight + 16), scale: 1 } });
        fs.writeFileSync(screenshot.replace(".png", "-jobs.png"), Buffer.from(jobs.data, "base64"));
      }
    }
    return query ? layout : JSON.parse(await evaluate("document.documentElement.dataset.browserCheck"));
  } finally {
    clearTimeout(timeout);
    child.kill("SIGTERM");
    const kill = setTimeout(() => child.kill("SIGKILL"), 5000);
    await finished; clearTimeout(kill);
  }
}
try {
  const report = await browser();
  assert.equal(report.status, "passed", JSON.stringify(report));
  console.log(`PASS Chrome dashboard: ${report.checks.length} UI assertions + viewport/axis checks`);
  const directory = process.env.DASHBOARD_SCREENSHOTS;
  if (directory) fs.mkdirSync(directory, { recursive: true });
  for (const [scenario, mobile] of [["normal", false], ["degraded", false], ["normal", true], ["cold", false], ...(directory ? [["normal&view=now", false], ["normal&view=history", false], ["normal&view=history", true], ["normal&view=provider", false]] : [])]) {
    const name = `${scenario.replace("normal&view=", "")}${mobile ? "-mobile" : ""}.png`;
    const layout = await browser(`?render=1&scenario=${scenario}`, directory ? path.join(directory, name) : undefined, mobile);
    console.log(`PASS layout ${name} (${layout.width}px viewport / ${layout.scroll}px document)${directory ? " + screenshot" : ""}`);
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  for (const profile of profiles) fs.rmSync(profile, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}
