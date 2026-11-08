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
let scenario = "normal", generation = 1, sequence = 0, lastFrame;

function frame() {
  const degraded = scenario === "degraded";
  const count = scenario === "large" ? 10003 : scenario === "empty" ? 0 : degraded ? 41 : 123;
  const now = epoch + ++sequence * 1000;
  const started = epoch - 7200000 + generation * 1000;
  const servers = ["nl.example.test", "de.example.test"].map((id, i) => ({
    index: i, id, server: id, label: scenario === "xss" && i === 0 ? '<img src=x onerror="window.pwned=1">' : i ? "DE" : "NL",
    weight: 1, state: degraded && i ? "backoff" : "ready", reason: degraded && i ? "handshake timeout" : "",
    stats: { inner_rx_bytes: (i ? 460 : 820) * 1048576 + (degraded && i ? 0 : sequence * (i ? 125000 : 250000)),
      inner_tx_bytes: (i ? 91 : 64) * 1048576 + (degraded && i ? 0 : sequence * (i ? 12500 : 25000)), opened_flows: 85,
      open_failed_flows: degraded && i ? 3 : 0, closed_flows: 12, dropped_packets: degraded && i ? 2 : 0 },
  }));
  const flows = Array.from({ length: count }, (_, i) => ({
    protocol: i % 2 ? "tcp" : "udp", source: `10.77.0.2:${40000 + i}`, destination: `203.0.113.${i % 250 + 1}:443`,
    via: degraded ? servers[0].id : i % 3 === 0 ? "local" : i % 3 === 1 ? servers[0].id : servers[1].id,
    rule: degraded ? i % 2 ? 0 : null : i % 3 === 0 ? 1 : i % 3 === 1 ? 0 : null,
  }));
  const traffic = rule => ({
    rx_bytes: rule === 1 ? 2 * 1073741824 : rule === 0 ? servers[0].stats.inner_rx_bytes / (degraded ? 2 : 1) : servers[1].stats.inner_rx_bytes + (degraded ? servers[0].stats.inner_rx_bytes / 2 : 0),
    tx_bytes: rule === 1 ? 310 * 1048576 : rule === 0 ? servers[0].stats.inner_tx_bytes / (degraded ? 2 : 1) : servers[1].stats.inner_tx_bytes + (degraded ? servers[0].stats.inner_tx_bytes / 2 : 0),
    active_flows: flows.filter(flow => flow.rule === rule).length,
  });
  const rules = scenario === "empty" ? [] : [
    { index: 0, label: "claude", kind: "names", selector: "names: claude.ai, anthropic.com", via: "servers: nl", local: false, candidates: [servers[0].id],
      owner: servers[0].id, every_secs: 300, resolved_ips: 6, traffic: traffic(0) },
    { index: 1, label: "home", kind: "countries", selector: "cc: RU, BY", via: "local", local: true, candidates: [], owner: null, every_secs: 300, resolved_ips: 0, traffic: traffic(1) },
  ];
  const status = { loaded_at: Math.floor(epoch / 1000) - (degraded ? 3900 : 299), attempted_at: Math.floor(epoch / 1000) - 299,
    error: degraded ? "Update failed: exit status: 1; previous table retained" : "" };
  return { generated_at: Math.floor(now / 1000), generated_at_ms: now, started_at: started, policy: "balance", asn_table: false, country_table: true,
    servers: scenario === "empty" ? [] : servers, flows, rules, groups: scenario === "empty" ? [] : [{ group: "claude", server: servers[0].id }], fallback: traffic(null),
    local: { enabled: scenario !== "empty", ready: scenario !== "empty" && !degraded, opened: 41, closed: 5, failed: degraded ? 2 : 0, active_flows: flows.filter(flow => flow.via === "local").length },
    sticky: { lookup_hit: 81, lookup_miss: 2, failover_moves: 0, block_hit: 410, resolve_ok: 8, resolve_fail: 0, resolved_ips: 6, purged_ips: 0 },
    databases: [{ kind: "geo", configured: false, loaded: false, rows: 0, pending: null, status: { loaded_at: null, attempted_at: null, error: "" } },
      { kind: "country", configured: true, loaded: true, rows: 65123, pending: null, status }],
    jobs: { runs: 8, failures: degraded ? 1 : 0, timeouts: 0, started_at: started, geo: {}, country: status,
      details: scenario === "empty" ? [] : [{ label: "country-update", every_secs: 3600, timeout_secs: 300, reload: ["country"], state: degraded ? "failed" : "ok",
        started_at: Math.floor(epoch / 1000) - 300, finished_at: Math.floor(epoch / 1000) - 299,
        success_at: Math.floor(epoch / 1000) - (degraded ? 3900 : 299), next_at: Math.floor(epoch / 1000) + 3301, reason: degraded ? "exit status: 1" : "" }] },
  };
}

// This extra module is injected only by the fixture server, never shipped by SVPN.
const check = `
const $ = id => document.getElementById(id);
const checks = [];
function assert(value, label) { if (!value) throw new Error(label); checks.push(label); }
async function until(condition, label, limit = 7000) {
  const start = performance.now();
  while (!condition()) { if (performance.now() - start > limit) throw new Error('Timed out: ' + label); await new Promise(resolve => setTimeout(resolve, 100)); }
}
async function control(scenario) { return fetch('/fixture?scenario=' + scenario).then(response => response.json()); }
function input(id, value) { $(id).value = value; $(id).dispatchEvent(new Event(id === 'flow-search' ? 'input' : 'change')); }
try {
  await until(() => $('rx').textContent !== '—' && $('active').textContent === '123', 'live traffic');
  assert($('local').textContent === 'Ready', 'local readiness');
  assert($('servers').tBodies[0].rows.length === 2 && !$('servers').textContent.includes('No snapshot'), 'initial server placeholder is removed');
  assert($('chart-rx').getAttribute('d').includes('l0,0') && getComputedStyle($('chart-rx')).strokeLinecap === 'round', 'isolated first chart sample is visible');
  assert($('rules').textContent.includes('Local only'), 'explicit local rule');
  assert(!$('rules').textContent.includes('0 IPs'), 'country is not a DNS rule');
  const details = document.querySelector('#servers details'); details.open = true;
  await control('large');
  await until(() => $('active').textContent === '10003', 'large flow snapshot');
  assert($('flows').tBodies[0].rows.length === 50, 'large table bounded to 50 rows');
  assert(document.querySelector('#servers details') === details && details.open, 'details identity and open state preserved');
  input('flow-search', '49999'); input('flow-protocol', 'tcp'); input('flow-exit', 'local');
  assert($('flows').tBodies[0].rows.length === 1 && $('flows').textContent.includes('49999'), 'combined flow filters');
  input('flow-search', ''); input('flow-protocol', ''); input('flow-exit', 'de.example.test');
  $('next').click(); assert($('flow-page').textContent.startsWith('2 /'), 'next flow page');
  $('pause').click();
  const frozen = $('flows').textContent, frozenExits = $('flow-exit').textContent;
  await control('empty');
  await until(() => $('active').textContent === '0', 'live servers removed while paused');
  assert($('flow-exit').value === 'de.example.test' && $('flow-exit').textContent === frozenExits, 'paused exit options and selection use the frozen snapshot');
  assert($('flows').textContent === frozen && frozen.includes('DE'), 'paused server and rule labels survive live config changes');
  await control('normal');
  await until(() => $('active').textContent === '123', 'live summary while paused');
  assert($('flows').textContent === frozen && $('flow-count').textContent.includes('10003') && $('pause').getAttribute('aria-pressed') === 'true', 'flow table stays frozen');
  $('pause').click(); assert($('pause').getAttribute('aria-pressed') === 'false', 'resume live table');
  input('flow-exit', '');
  await control('xss');
  await until(() => $('servers').textContent.includes('<img'), 'untrusted label rendered');
  assert(!document.querySelector('main img') && !window.pwned, 'snapshot text cannot inject HTML');
  const restart = await control('restart');
  await until(() => $('footer').textContent.includes(new Date(restart.started_at).toLocaleString()), 'client restart');
  assert($('rx').textContent === '—' && !$('chart-rx').getAttribute('d').trim(), 'restart clears rates and graph');
  await until(() => $('rx').textContent !== '—', 'rates resume after restart');
  await control('offline');
  await until(() => $('freshness').textContent === 'Stale data', 'API failure is visible immediately');
  assert((await fetch('/api/state')).status === 503, 'HTTP error fixture');
  const beforeApiGap = $('chart-rx').getAttribute('d');
  await control('frozen');
  await until(() => $('freshness').textContent === 'Live snapshots', 'same-timestamp response clears the API error', 2500);
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
  await until(() => $('active').textContent === '0' && $('freshness').textContent === 'Live snapshots', 'recovery and empty flow table');
  assert($('rx').textContent === '—', 'stale recovery starts with an unknown rate');
  assert($('flows').textContent.includes('No active flows'), 'empty flow state');
  assert($('servers').textContent.includes('No servers configured'), 'empty server table is explicit');
  input('flow-search', 'missing'); await control('normal');
  await until(() => $('active').textContent === '123', 'filtered recovery');
  assert($('flows').textContent.includes('No flows match'), 'empty filter message updates');
  assert($('servers').tBodies[0].rows.length === 2 && !$('servers').textContent.includes('No servers'), 'servers recover without a stale placeholder');
  input('flow-search', '');
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
    response.end(JSON.stringify({ started_at: epoch - 7200000 + generation * 1000 }));
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
    await evaluate("new Promise(resolve => { if (document.readyState === 'complete') resolve(); else addEventListener('load', resolve, { once: true }); })");
    await page("Page.enable");
    const loaded = new Promise(resolve => { onLoad = resolve; });
    await page("Page.navigate", { url: origin + "/" + query });
    await loaded; onLoad = null;
    await evaluate(`new Promise(resolve => { const timer = setInterval(() => {
      const done = ${query ? `document.getElementById('freshness')?.textContent === '${query.includes("cold") ? "API unavailable" : "Live snapshots"}' && ${query.includes("cold") ? "true" : "document.getElementById('rx')?.textContent !== '—'"}` : "document.documentElement.dataset.browserCheck"};
      if (done) { clearInterval(timer); resolve(true); }
    }, 100); })`);
    const layout = await evaluate(`({ width: innerWidth, scroll: document.documentElement.scrollWidth,
      fontHeight: document.getElementById('chart-max').getBoundingClientRect().height,
      cardsFit: [...document.querySelectorAll('.summary .card, header, .scroll')].every(node => node.getBoundingClientRect().right <= innerWidth),
      jobsTop: document.getElementById('database-title').closest('section').getBoundingClientRect().top + scrollY,
      jobsHeight: document.getElementById('database-title').closest('section').getBoundingClientRect().height })`);
    assert.equal(layout.width, width, "real browser viewport size");
    assert.ok(layout.scroll <= width, `page overflows: ${JSON.stringify(layout)}`);
    assert.ok(layout.cardsFit, `cards and scroll containers fit viewport: ${JSON.stringify(layout)}`);
    assert.ok(layout.fontHeight >= 10, "chart axis labels are legible without SVG scaling");
    if (query.includes("cold")) assert.ok(await evaluate("['pause','previous','next','chart-server','flow-search','flow-protocol','flow-exit'].every(id => document.getElementById(id).disabled)"), "cold controls disabled");
    if (screenshot) {
      const image = await page("Page.captureScreenshot", { format: "png", captureBeyondViewport: true,
        clip: { x: 0, y: 0, width, height, scale: 1 } });
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
  for (const [scenario, mobile] of [["normal", false], ["degraded", false], ["normal", true], ["cold", false]]) {
    const name = `${scenario}${mobile ? "-mobile" : ""}.png`;
    const layout = await browser(`?render=1&scenario=${scenario}`, directory ? path.join(directory, name) : undefined, mobile);
    console.log(`PASS layout ${name} (${layout.width}px viewport / ${layout.scroll}px document)${directory ? " + screenshot" : ""}`);
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  for (const profile of profiles) fs.rmSync(profile, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}
