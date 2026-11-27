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
    process, servers: scenario === "empty" ? [] : servers, flows, rules, groups: scenario === "empty" ? [] : [{ group: "claude", server: servers[0].id }, { group: "asn 13335", server: servers[1].id }, { group: "asn 15169", server: servers[0].id }], fallback: traffic(null),
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
  const rangeButton = name => document.querySelector('#chart-ranges [data-range="' + name + '"]');
  // One chart for every range: a day of history on it by default, five minutes measured here on request.
  assert(document.querySelectorAll('.chart').length === 1 && !document.getElementById('history-panel') && document.querySelectorAll('.rail-nav a[data-section="traffic"]').length === 1, 'one chart at a time');
  assert(rangeButton('24h').getAttribute('aria-pressed') === 'true' && rangeButton('5m').getAttribute('aria-pressed') === 'false' && !$('chart-by').hidden, 'a day of history is the chart by default');
  await until(() => $('proc-rss').textContent.includes('MiB') && $('proc-cpu').textContent.includes('%'), 'process RSS and CPU readout');
  // The pool at a glance, in the bar: a lamp for the state, the name, the line it speaks and how far it is.
  const poolChip = label => [...$('pool').children].find(chip => chip.textContent.startsWith(label));
  assert($('pool').children.length === 2 && poolChip('NL').tagName === 'A' && poolChip('NL').querySelector('.led.good') && poolChip('NL').querySelector('.mono').textContent === 'tcp · 41 ms' && poolChip('DE').querySelector('.mono').textContent === 'ready', 'the bar shows the pool: ' + $('pool').textContent);
  assert($('ready-leds').children.length === 2 && [...$('ready-leds').children].every(led => led.classList.contains('led') && led.classList.contains('good') && led.title.includes(': ready')), 'one lamp per server under the number, each naming its server');
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
  // A trend fills once it has two samples; with one it is a dot.
  await until(() => $('spark-tx-area').getAttribute('d').trim(), 'summary trends fill');
  assert($('spark-rx').getAttribute('d').trim() && /^url[(]"#spark-fade-rx"[)]$/.test(getComputedStyle($('spark-rx-area')).fill), 'the summary trends are drawn and filled like the chart');
  // The aurora is a backdrop, not a surface: behind everything, catching nothing.
  const aurora = getComputedStyle(document.body, '::before');
  assert(aurora.position === 'fixed' && aurora.pointerEvents === 'none' && aurora.zIndex === '-1' && aurora.backgroundImage.includes('radial-gradient'), 'the aurora is a backdrop behind the page that catches nothing');
  assert(getComputedStyle($('ready').closest('.card')).borderRadius === '16px' && getComputedStyle(rangeButton('24h')).borderRadius === '8px', 'cards and pills have soft corners');
  assert(document.querySelector('header').getBoundingClientRect().height <= 64, 'header stays a single row');
  assert([...document.querySelectorAll('.heading')].every(h => h.getBoundingClientRect().height <= 64), 'panel headings stay on one line');
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
  // Nothing blinks; the only motion is the live chip's slow breath.
  assert(!document.querySelector('.caret') && getComputedStyle(document.querySelector('.rail-health'), '::before').animationName === 'none' && getComputedStyle($('freshness'), '::before').animationName === 'breathe', 'nothing blinks on a healthy dashboard');
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
  // History is read once its panel is in view, then once a minute at most.
  $('traffic').scrollIntoView({ behavior: 'instant', block: 'start' });
  await until(() => document.querySelectorAll('#chart-bands .band').length === 3, 'history bands');
  let historyReads = (await control('normal')).history_requests;
  await new Promise(resolve => setTimeout(resolve, 1200));
  assert((await control('normal')).history_requests === historyReads, 'history is not fetched by one-second snapshot polling');
  const bandsOf = () => [...document.querySelectorAll('#chart-bands .band')], crestsOf = () => [...document.querySelectorAll('#chart-bands .crest')];
  assert(['cat-1', 'cat-2', 'cat-3'].every((name, i) => bandsOf()[i].classList.contains(name)), 'history series take the categorical palette in rank order');
  assert(bandsOf().every(band => /^url[(]"#fade-[1-8]"[)]$/.test(getComputedStyle(band).fill)), 'each layer fades out of its own colour: ' + bandsOf().map(band => getComputedStyle(band).fill).join(' '));
  assert(['NL', 'DE', 'Local exit'].every((label, i) => $('chart-legend').children[i].textContent.startsWith(label)), 'the legend names servers by label and the local exit');
  assert($('chart-legend').children[0].textContent.endsWith('329.6 MiB'), 'the legend carries what each series moved in the range: ' + $('chart-legend').children[0].textContent);
  const historyRow = index => [...$('history').tBodies[0].rows[index].cells].map(cell => cell.textContent);
  assert(historyRow(0)[0] === 'NL' && historyRow(0)[1] === '274.7 MiB' && historyRow(0)[3] === '329.6 MiB' && historyRow(0)[4] === '63.2%' && historyRow(0)[5] === '2.0', 'history totals list bytes, share of the range and average flows');
  assert(historyRow(2)[0] === 'Local exit' && $('history').tBodies[0].rows.length === 3, 'history table lists every series of the breakdown');
  assert($('history').tBodies[0].rows[0].cells[0].querySelector('i')?.classList.contains('cat-1'), 'a row of the table carries the colour of its layer');
  // Pinned groups sit with the rules, shut until asked for: they are extra reading.
  const groupRow = index => [...$('groups').tBodies[0].rows[index].cells].map(cell => cell.textContent);
  const fold = document.getElementById('groups-panel'), lid = fold.querySelector('summary');
  // A shut details is its lid alone; the table inside is laid out but not shown.
  const shut = fold.getBoundingClientRect().height;
  assert($('groups').closest('section').id === 'rules-panel' && fold.tagName === 'DETAILS' && !fold.open && shut < 60, 'pinned groups sit with the rules, shut by default: ' + [fold.tagName, fold.open, shut].join(' / '));
  assert(lid.textContent.includes('Pinned groups') && lid.textContent.endsWith('3 groups since start'), 'the lid says how many there are, and shows nothing else: ' + lid.textContent);
  lid.click();
  assert(fold.open && fold.getBoundingClientRect().height > shut + 100, 'a click on the lid opens it');
  assert($('groups').tBodies[0].rows.length === 3 && groupRow(0)[0] === 'AS13335 · Cloudflare, Inc.' && groupRow(0)[1] === 'DE' && / (MiB|GiB)$/.test(groupRow(0)[2]) && groupRow(0)[4] === '1.4 GiB' && $('groups').tBodies[0].rows[0].cells[1].firstChild.classList.contains('cat-2'), 'the busiest group first, named by its network, led out by name and colour: ' + JSON.stringify(groupRow(0)));
  assert(groupRow(1)[0] === 'claude' && groupRow(1)[1] === 'NL' && groupRow(2)[0] === 'AS15169 · Google LLC' && groupRow(2)[4].endsWith('MiB') && $('groups-note').textContent === '3 groups since start', 'every group is listed with what it carried');
  assert(!document.getElementById('groups-more'), 'the whole list is there once open: it scrolls, it does not open in stages');
  lid.click();
  assert(!fold.open, 'and a second click shuts it again');
  assert(Math.abs(Number.parseFloat($('chart-mid').textContent) * 2 - Number.parseFloat($('chart-max').textContent)) < 0.002 && /^[0-9]+([.][0-9]+)? Mbit[/]s$/.test($('chart-max').textContent) && $('chart-mid').textContent === String(Number.parseFloat($('chart-max').textContent) / 2), 'the value axis labels its middle gridline in round numbers');
  assert([...$('chart-axis').children].every(span => /^[0-9]{2}:[0-9]{2}$/.test(span.textContent)), 'a day of history is labelled with clock times');
  assert(/^M[0-9.]+,[0-9.]+ C/.test(bandsOf()[0].getAttribute('d')) && bandsOf()[0].getAttribute('d').endsWith('Z') && !$('chart-empty').offsetParent, 'recorded minutes draw as smooth stacked bands');
  assert(bandsOf().length === 3 && bandsOf().every(band => band instanceof SVGPathElement && band.getBoundingClientRect().height > 0 && getComputedStyle(band).stroke === 'none') && bandsOf()[0].getBoundingClientRect().height > 40, 'bands are filled SVG paths that rise from the baseline');
  assert(crestsOf().length === 3 && crestsOf().every(crest => getComputedStyle(crest).stroke !== 'none' && getComputedStyle(crest).fill === 'none' && crest.getAttribute('d').startsWith('M')), 'each layer has a hairline along its top, so a thin layer stays visible on a thick one');
  assert($('chart-resolution').textContent === 'Every 4 min', 'history says how wide its points are');
  const shareBar = $('history').tBodies[0].rows[0].cells[4].querySelector('.share');
  assert(shareBar && shareBar.classList.contains('cat-1') && shareBar.firstChild.style.width === '63.2%' && shareBar.textContent === '', 'a share of the range is a bar in its series colour beside its number: ' + (shareBar?.outerHTML ?? 'none'));
  // A bar takes the colour of the exit it belongs to: an exit its own, a network the one it is pinned to.
  const exitRow = $('rank-exits').querySelector('li[data-key="nl.example.test"]');
  const networkRow = $('rank-networks').querySelector('li[data-key="13335"]'), pooledRow = $('rank-networks').querySelector('li[data-key=""]');
  assert(exitRow.classList.contains('cat-1') && networkRow.classList.contains('cat-2') && pooledRow.className === '' && networkRow.querySelector('small').textContent.endsWith(' · DE'), 'a bar takes the colour of its exit, and a network names it: ' + networkRow.textContent);
  assert(document.querySelector('#chart-bands .halo') && /^cat-[1-8]$/.test(document.querySelector('#chart-bands .halo').classList[1]) && getComputedStyle(document.querySelector('#chart-bands .halo')).filter !== 'none' && $('chart-pulse').hidden, 'the top of the stack glows, and the live point is off for a stored range');
  assert(!$('chart-by').hidden && !$('chart-table').hidden && $('chart-total').children[0].textContent === '↓ 439.5 MiB' && $('chart-total').children[1].textContent === '↑ 82.4 MiB', 'a stored range adds up to received and sent: ' + $('chart-total').textContent);
  // The five minutes measured in this tab are the same chart: the same layers by server.
  // The legend is ordered by size, so a server is found by name, not by position.
  const chipOf = label => [...$('chart-legend').children].find(chip => chip.textContent.startsWith(label));
  const dayTint = chipOf('NL').className, dayTintDE = chipOf('DE').className;
  rangeButton('5m').click();
  await until(() => bandsOf().length === 2 && $('chart-resolution').textContent !== 'Waiting…', 'live bands');
  assert(rangeButton('5m').getAttribute('aria-pressed') === 'true' && rangeButton('24h').getAttribute('aria-pressed') === 'false' && $('chart-by').hidden && $('chart-table').hidden, 'the live window is one breakdown, by server, with no table');
  // The live window counts back from now over as much as it holds: a young tab speaks in seconds, never of time it never saw.
  const liveAxis = [...document.querySelectorAll('#traffic .chart-axis span')].map(span => span.textContent);
  assert(liveAxis[4] === 'now' && liveAxis.slice(0, 4).every(mark => /^−([0-9]+ min|[0-9]+ s|[0-9]+:[0-9]{2})$/.test(mark)) && Number.parseInt(liveAxis[0].slice(1)) >= 10 && Number.parseInt(liveAxis[0].slice(1)) >= Number.parseInt(liveAxis[3].slice(1)), 'the live axis counts back from now: ' + liveAxis.join('|'));
  assert(chipOf('NL')?.className === dayTint && chipOf('DE')?.className === dayTintDE, 'a server keeps its colour from a day to five minutes: ' + dayTint + ',' + dayTintDE + ' → ' + [...$('chart-legend').children].map(chip => chip.className + ' ' + chip.textContent).join(' | '));
  assert(!$('chart-pulse').hidden && /^cat-[1-8]$/.test($('chart-pulse').classList[1]) && Number.parseFloat($('chart-pulse').style.top) > 0 && Number.parseFloat($('chart-pulse').style.top) < $('chart-plot').clientHeight, 'the newest live sample is a point of light on the stack');
  assert(/^(?:[0-9]+s collected|Every second)$/.test($('chart-resolution').textContent) && $('chart-total').textContent.endsWith('Mbit/s')
    && Number.parseFloat($('chart-total').children[0].textContent.slice(1)) === Number.parseFloat($('rx').textContent), 'the live window quotes its newest sample, the number the summary shows');
  const plot = $('chart-plot').getBoundingClientRect();
  // The samples of this tab reach a few seconds back: the pointer goes there, not into the empty part of the window.
  $('chart-plot').dispatchEvent(new PointerEvent('pointermove', { clientX: plot.left + plot.width * 0.995, clientY: plot.top + plot.height / 2, bubbles: true }));
  assert(!$('chart-tooltip').hidden && !$('chart-cursor').hidden && Math.abs(Number.parseFloat($('chart-cursor').style.left) - 99.5) < 0.01 && $('chart-cursor').getBoundingClientRect().width > 0 && $('chart-tooltip').textContent.includes('NL') && $('chart-tooltip').textContent.includes('Total') && $('chart-tooltip').textContent.includes(' Mbit/s'), 'the pointer reads the stack under it: ' + $('chart-tooltip').textContent);
  const tooltip = $('chart-tooltip').getBoundingClientRect();
  assert(tooltip.left >= plot.left && tooltip.right <= plot.right, 'the readout stays inside the plot near its edge');
  $('chart-plot').dispatchEvent(new PointerEvent('pointerleave', { bubbles: true }));
  assert($('chart-tooltip').hidden && $('chart-cursor').hidden, 'the readout leaves with the pointer');
  rangeButton('24h').click();
  await until(() => $('chart-resolution').textContent === 'Every 4 min' && bandsOf().length === 3, 'back to a day of history');
  assert(!$('chart-by').hidden && !$('chart-table').hidden, 'a stored range offers the breakdowns and lists its series');
  // The pointer reads a stored range too: the bucket under it, by series.
  $('chart-plot').dispatchEvent(new PointerEvent('pointermove', { clientX: plot.left + plot.width * 0.6, clientY: plot.top + plot.height / 2, bubbles: true }));
  assert(!$('chart-tooltip').hidden && /^[0-9]{2}:[0-9]{2}$/.test($('chart-tooltip').querySelector('p').textContent) && $('chart-tooltip').textContent.includes('Local exit'), 'a stored range reads to the minute under the pointer');
  $('chart-plot').dispatchEvent(new PointerEvent('pointerleave', { bubbles: true }));
  historyReads = (await control('normal')).history_requests;
  // A database that just started holds one bucket: it is a column, not nothing.
  const bandWidth = () => bandsOf()[0].getBoundingClientRect().width;
  await control('history-once'); rangeButton('24h').click();
  await until(() => bandWidth() > 0 && bandWidth() < 5, 'a single recorded bucket');
  assert(bandWidth() > 1.2 && Math.abs(bandWidth() - $('chart-plot').getBoundingClientRect().width / 360) < 0.5 && !$('chart-empty').offsetParent, 'one recorded bucket is drawn as a column as wide as its step: ' + bandWidth());
  await control('normal'); rangeButton('24h').click();
  await until(() => bandWidth() > 500, 'the whole day again');
  historyReads = (await control('normal')).history_requests;
  input('chart-direction', 'tx');
  assert(historyRow(0)[4] === '66.7%' && (await control('normal')).history_requests === historyReads, 'another direction redraws the same answer');
  input('chart-kind', 'network');
  await until(() => $('chart-legend').textContent.includes('AS13335'), 'network history');
  assert(bandsOf().length === 3, 'the twenty busiest networks are drawn, here all three');
  assert($('chart-legend').textContent.includes('AS13335 · Cloudflare, Inc.') && $('history').tBodies[0].rows[0].cells[0].textContent.includes('via NL'), 'networks are named by ASN and organization, the exit is the second line');
  assert($('chart-legend').textContent.includes('AS24429 · Alibaba (US) Technology Co., Ltd.'), 'a network is named by the server, with no browser copy of the ASN CSV');
  input('chart-server', 'de.example.test');
  await until(() => bandsOf().length === 1, 'history of one server');
  assert($('chart-legend').textContent.includes('AS15169 · Google LLC'), 'the server filter narrows the series');
  rangeButton('7d').click();
  await until(() => $('chart-axis').children[0].textContent.includes(' '), 'week of history');
  assert(rangeButton('7d').getAttribute('aria-pressed') === 'true' && [...$('chart-axis').children].every(span => /^[A-Z][a-z][a-z] [0-9]+ [A-Z][a-z][a-z]$/.test(span.textContent)) && $('chart-axis').children[0].textContent !== $('chart-axis').children[4].textContent, 'range buttons state the choice and the axis names the days: ' + JSON.stringify([...$('chart-axis').children].map(span => span.textContent)));
  // Yesterday is one click: the whole local day before this one, by the hour.
  rangeButton('yesterday').click();
  await until(() => $('chart-resolution').textContent === 'Every hour' && $('chart-axis').children[1].textContent !== $('chart-axis').children[3].textContent, 'yesterday');
  const yesterday = new URLSearchParams((await control('normal')).history_last);
  const midnight = new Date(Number(yesterday.get('to')) * 1000);
  assert(yesterday.has('from') && yesterday.has('to') && !yesterday.has('range') && midnight.getHours() === 0 && midnight.getMinutes() === 0 && Math.round((Number(yesterday.get('to')) - Number(yesterday.get('from'))) / 3600) === 24 && rangeButton('yesterday').getAttribute('aria-pressed') === 'true', 'Yesterday asks for the whole local day before this one');
  // The chosen range is the lit pill of the tray: the accent, with ink that reads on it.
  const lit = getComputedStyle(rangeButton('yesterday')), unlit = getComputedStyle(rangeButton('24h'));
  assert(lit.backgroundImage.includes('gradient') && lit.color !== unlit.color && unlit.backgroundImage === 'none', 'the chosen range is the lit pill of the tray');
  // Custom opens on the last day and takes any window of up to 30 days.
  rangeButton('custom').click();
  await until(() => !$('chart-custom').hidden && $('chart-resolution').textContent === 'Every 4 min', 'custom window');
  assert(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}$/.test($('chart-from').value) && $('chart-to').value > $('chart-from').value, 'the picker is filled with the last day');
  $('chart-to').value = $('chart-from').value; $('chart-apply').click();
  assert($('chart-note').textContent === 'The end comes after the start' && !$('chart-note').classList.contains('bad'), 'a custom window with its ends reversed is refused in place');
  const pad = value => String(value).padStart(2, '0'), day = date => date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate());
  const first = new Date(), last = new Date(); first.setDate(first.getDate() - 2); last.setDate(last.getDate() - 1);
  $('chart-from').value = day(first) + 'T03:30'; $('chart-to').value = day(last) + 'T21:15'; $('chart-apply').click();
  const asked = '?from=' + Math.floor(new Date(day(first) + 'T03:30').getTime() / 1000) + '&to=' + Math.floor(new Date(day(last) + 'T21:15').getTime() / 1000) + '&';
  const firstLabel = new Date(day(first) + 'T03:30').toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short' });
  await until(async () => (await control('normal')).history_last.startsWith(asked) && $('chart-axis').children[0].textContent === firstLabel, 'the picked window');
  assert($('chart-note').hidden && rangeButton('custom').getAttribute('aria-pressed') === 'true' && $('chart-axis').children[0].textContent !== $('chart-axis').children[4].textContent, 'the picked window is drawn by the hour');
  await control('history-error');
  await until(() => $('chart-note').textContent.includes('not being recorded'), 'history error is visible');
  assert($('chart-note').classList.contains('bad') && $('chart-note').textContent.includes('disk I/O error') && bandsOf().length === 1, 'a failing history database is the loud case, the last answer stays drawn');
  await control('history-off');
  await until(() => $('chart-note').textContent.includes('History is off'), 'history off is explained');
  assert($('chart-kind').disabled && $('chart-from').disabled && $('chart-apply').disabled && rangeButton('custom').disabled && !$('chart-note').classList.contains('bad'), 'history controls are quiet while history is off');
  await until(() => rangeButton('5m').getAttribute('aria-pressed') === 'true' && !$('chart-server').disabled, 'without history the chart shows the live window');
  assert(rangeButton('24h').disabled && !rangeButton('5m').disabled, 'only the live range is left');
  await control('normal');
  await until(() => !$('chart-kind').disabled, 'history recovers');
  input('chart-server', ''); input('chart-kind', 'link');
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
  assert(flowRow(0)[5].firstChild.classList.contains('cat-1') && Number.parseFloat(flowRow(0)[7].querySelector('.share.rate b')?.style.width) === 100, 'the busiest flow carries its exit colour and a full rate bar');
  assert(flowRow(1)[7].querySelector('strong').textContent === '0.00' && flowRow(0)[7].querySelector('small').textContent.endsWith('MiB'), 'idle flows read 0, the total sits under the rate');
  assert(!flowRow(1)[7].querySelector('.share'), 'an idle flow draws no rate bar');
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
  $('next').click(); assert($('flow-page').textContent.startsWith('2 /'), 'next flow page: ' + $('flow-page').textContent + ' / ' + $('flow-count').textContent + ' / next disabled ' + $('next').disabled + ' / ' + $('active').textContent);
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
  rangeButton('5m').click();
  const restart = await control('restart');
  await until(() => $('footer').textContent.includes(new Date(restart.started_at).toLocaleString()), 'client restart');
  assert($('rx').textContent === '—' && !$('chart-bands').children.length && !$('chart-empty').hidden, 'restart clears rates and the live chart');
  assert($('proc-cpu').textContent === '—', 'restart clears the derived CPU percentage');
  await until(() => $('rx').textContent !== '—', 'rates resume after restart');
  await control('degraded');
  await until(() => $('jobs').tBodies[0].textContent.includes('Previous attempt: '), 'a retrying job keeps its previous failure visible');
  assert($('jobs').tBodies[0].rows[0].cells[4].textContent === 'Running', 'running job shows Running instead of a next-check time');
  assert($('local').className === 'compact bad' && $('ready').className === 'warn' && $('freshness').className === 'pill good', 'trouble is the only coloured thing in the summary');
  assert($('ready-leds').children[1].classList.contains('warn') && [...$('pool').children][1].querySelector('.led.warn') && [...$('pool').children][1].querySelector('.mono').textContent === 'backoff', 'a server in trouble turns its lamp and its chip with it');
  assert(!document.querySelector('#servers .pill.bad') && document.querySelector('#servers .pill.warn')?.textContent === 'Backoff', 'state tags read as words');
  await control('normal');
  await until(() => !$('jobs').textContent.includes('Previous attempt:'), 'clean job drops the previous-attempt prefix');
  await control('offline');
  await until(() => $('freshness').textContent === 'Stale data', 'API failure is visible immediately');
  assert($('proc-rss').textContent === '—' && $('proc-cpu').textContent === '—', 'stale process values are not shown as live');
  $('usage-now').click(); assert($('usage-total').textContent === '—' && $('rank-exits').textContent.includes('stale'), 'stale interval is unknown, never zero');
  $('usage-session').click(); assert($('usage-period').textContent.includes('last snapshot'), 'stale session totals are labelled');
  assert((await fetch('/api/state')).status === 503, 'HTTP error fixture');
  const beforeApiGap = $('chart-bands').innerHTML;
  await control('frozen');
  await until(() => $('freshness').textContent === 'Live', 'same-timestamp response clears the API error', 2500);
  assert($('chart-bands').innerHTML === beforeApiGap, 'duplicate recovery does not add a chart sample');
  assert($('rx').textContent === '—' && $('chart-total').textContent.includes('↓ —'), 'duplicate recovery does not reuse a pre-error rate');
  assert(!$('chart-resolution').textContent.includes('Last snapshot'), 'duplicate recovery restores chart freshness');
  const recoveredAt = $('chart-bands').innerHTML;
  await control('normal');
  await until(() => $('chart-bands').innerHTML !== recoveredAt, 'first new snapshot after duplicate recovery');
  assert($('rx').textContent === '—', 'short API gap is not averaged into a rate');
  await until(() => $('rx').textContent !== '—', 'two fresh snapshots restore rates');
  await control('frozen');
  await until(() => $('freshness').textContent === 'Stale data', 'unchanged snapshot becomes stale');
  assert(!$('stale-notice').hidden && $('rx').textContent === '—' && !$('spark-rx').getAttribute('d') && $('chart-resolution').textContent === 'Last snapshot' && $('chart-total').textContent.includes('↓ —'), 'stale screen has warning and unknown rate');
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
      // The stored ranges are read once the chart is in view, as on a real scroll. `traffic-live`
      // shows the five minutes measured here, from the replayed samples; `traffic-light` the light theme.
      if (query.includes('view=traffic')) await evaluate(`(async () => {
        document.getElementById('traffic').scrollIntoView({ behavior: 'instant', block: 'start' });
        if ('live' === '${(query.match(/live|day|hour|week/) || [''])[0]}') { document.querySelector('#chart-ranges [data-range="5m"]').click(); await new Promise(resolve => setTimeout(resolve, 1200)); }
        await new Promise(resolve => { const timer = setInterval(() => {
          if (document.getElementById('chart-bands').children.length) { clearInterval(timer); resolve(); }
        }, 100); });
      })()`);
      if (query.includes('light')) await evaluate("document.getElementById('theme-toggle').click()");
      // The sticky bar and rail are their own layers: give them a frame to repaint in the new theme.
      if (query.includes('light')) await evaluate("new Promise(resolve => setTimeout(resolve, 500))");
      const y = query.includes('view=provider') ? await evaluate("document.getElementById('flows-panel').getBoundingClientRect().top + scrollY - 8")
        : query.includes('view=traffic') ? await evaluate("document.getElementById('traffic').getBoundingClientRect().top + scrollY - 8") : 0;
      const image = await page("Page.captureScreenshot", { format: "png", captureBeyondViewport: true,
        clip: { x: 0, y, width, height, scale: 1 } });
      fs.writeFileSync(screenshot, Buffer.from(image.data, "base64"));
      if (query.includes("degraded")) {
        const jobs = await page("Page.captureScreenshot", { format: "png", captureBeyondViewport: true,
          clip: { x: 0, y: layout.jobsTop - 8, width, height: Math.ceil(layout.jobsHeight + 16), scale: 1 } });
        fs.writeFileSync(screenshot.replace(".png", "-jobs.png"), Buffer.from(jobs.data, "base64"));
      }
      // The chart twice over: the readout under the pointer, in detail.
      if (query.includes("view=traffic")) {
        const plot = await evaluate("(() => { const rect = document.getElementById('chart-plot').getBoundingClientRect(); return { left: rect.left, top: rect.top + scrollY, width: rect.width, height: rect.height }; })()");
        await evaluate(`document.getElementById('chart-plot').dispatchEvent(new PointerEvent('pointermove', { clientX: ${plot.left + plot.width * 0.6}, clientY: ${plot.top + plot.height / 2}, bubbles: true }))`);
        const detail = await page("Page.captureScreenshot", { format: "png", captureBeyondViewport: true,
          clip: { x: 0, y: plot.top - 70, width, height: Math.ceil(plot.height + 160), scale: 2 } });
        fs.writeFileSync(screenshot.replace(".png", "-detail.png"), Buffer.from(detail.data, "base64"));
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
  for (const [scenario, mobile] of [["normal", false], ["degraded", false], ["normal", true], ["cold", false], ...(directory ? [["normal&view=now", false], ["normal&view=traffic", false], ["normal&view=traffic-live", false], ["normal&view=traffic-light", false], ["normal&view=traffic", true], ["normal&view=provider", false]] : [])]) {
    const name = `${scenario.replace("normal&view=", "")}${mobile ? "-mobile" : ""}.png`;
    const layout = await browser(`?render=1&scenario=${scenario}`, directory ? path.join(directory, name) : undefined, mobile);
    console.log(`PASS layout ${name} (${layout.width}px viewport / ${layout.scroll}px document)${directory ? " + screenshot" : ""}`);
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  for (const profile of profiles) fs.rmSync(profile, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}
