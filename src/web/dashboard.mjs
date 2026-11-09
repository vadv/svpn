import { WINDOW_MS, STALE_MS, PAGE_SIZE, bytes, rate, measure, keepHistory, graph, areas, spark, sparkScaled, nearestSample, processRss, uptimeSeconds, duration, flowPage, asnLabel, flag, readAsnNames, selector, localState, cpuAverage, trafficAverage, mimicCell } from "/state.mjs";

const $ = id => document.getElementById(id);
const endpoint = document.querySelector("main").dataset.endpoint;
let latest = null, point = null, history = [], lastChange = 0, apiError = false;
let frozen = null, page = 0, flowSignature = "";
const serverRows = new Map();
let asnNames = Object.create(null), asnCount = 0, asnState = "idle", asnError = "", asnAbort = null, asnIdleTimer = null;

// Regional-indicator pairs have no flag glyph everywhere: Windows renders the two letters
// again, a Linux without an emoji font renders tofu. A supported pair collapses to one
// glyph, so measuring it against a single indicator tells us whether to draw it at all.
const flagsSupported = (() => {
  const probe = document.createElement("canvas").getContext("2d");
  probe.font = "16px monospace";
  const one = probe.measureText("\u{1f1e6}").width;
  return one > 0 && probe.measureText("\u{1f1e6}\u{1f1e8}").width <= one * 1.6;
})();

function node(tag, text = "", className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function badge(state, label = state) {
  const good = ["ready", "ok"].includes(state);
  const bad = ["failed", "timeout", "reload_failed", "missing"].includes(state);
  const warn = ["checking", "connecting", "backoff", "running", "previous"].includes(state);
  return node("span", label, `pill ${good ? "good" : bad ? "bad" : warn ? "warn" : ""}`);
}

function cell(value, numeric = false) {
  const td = node("td", "", numeric ? "num" : "");
  td.append(value instanceof Node ? value : document.createTextNode(String(value ?? "—")));
  return td;
}

function title(main, detail) {
  const div = node("div");
  div.append(node("strong", main), node("small", detail));
  return div;
}

function table(id, rows, columns, message = "None configured") {
  const body = $(id).tBodies[0];
  if (!rows.length) {
    const td = cell(message); td.colSpan = columns; td.className = "empty";
    const tr = node("tr"); tr.append(td); body.replaceChildren(tr);
    return;
  }
  body.replaceChildren(...rows.map(cells => { const tr = node("tr"); tr.append(...cells); return tr; }));
}

function name(id, state = latest) {
  if (id === "local") return "Local";
  const server = state?.servers.find(server => server.id === id);
  return server?.label || server?.server || id;
}

const time = seconds => seconds ? new Date(seconds * 1000).toLocaleString() : "—";

function options(select, items) {
  const signature = JSON.stringify(items);
  if (select.dataset.options === signature) return;
  const selected = select.value;
  select.replaceChildren(...items.map(([value, label]) => { const item = node("option", label); item.value = value; return item; }));
  if (items.some(([value]) => value === selected)) select.value = selected;
  select.dataset.options = signature;
}

function isStale() { return apiError || !latest || performance.now() - lastChange > STALE_MS; }

function setMeter(id, percent) {
  const width = Number.isFinite(percent) ? Math.max(0, Math.min(100, percent)) : 0;
  $(id).style.width = `${width.toFixed(1)}%`;
}

function renderClock() {
  $("clock").textContent = new Date().toLocaleTimeString("en-GB", { hour12: false });
  if (latest) $("uptime").textContent = duration(uptimeSeconds(latest));
}

function renderProcess() {
  const process = latest.process ?? null;
  const memory = processRss(process);
  const average = cpuAverage(history);
  const cpuTime = Number.isFinite(process?.cpu_seconds) ? process.cpu_seconds : null;
  const cpus = Number.isFinite(process?.cpus) && process.cpus > 0 ? process.cpus : null;
  $("proc-rss").textContent = memory.bytes == null ? "—" : bytes(memory.bytes);
  $("proc-rss-kind").textContent = memory.bytes == null ? "No process sample" : memory.peak ? "Peak RSS · live value unavailable" : "Current RSS · resident set";
  $("proc-cpu").textContent = average ? `${average.percent.toFixed(1)}%` : "—";
  $("proc-cpu-kind").textContent = average
    ? `Of one core · ${Math.round(average.seconds)}s average`
    : "Waiting for two fresh samples";
  $("proc-time").textContent = cpuTime == null ? "—" : `${cpuTime.toFixed(2)} s`;
  $("proc-time-note").textContent = cpus ? `${cpus} logical CPUs · user + system` : "User + system · CPU count unknown";
  const peak = Number.isFinite(process?.peak_rss_bytes) && process.peak_rss_bytes > 0 ? process.peak_rss_bytes : null;
  $("proc-note").textContent = [
    "getrusage: cumulative CPU + peak RSS",
    "Linux: current RSS from /proc/self/status",
    memory.peak ? "fallback shown: PEAK RSS, not live RSS" : peak ? "memory meter: current / peak RSS" : "memory meter unavailable: no peak RSS",
  ].join(" · ");
  setMeter("proc-mem-bar", peak == null || memory.bytes == null ? null : memory.bytes / peak * 100);
  setMeter("proc-cpu-bar", average?.percent ?? null);
  $("spark-rss").setAttribute("d", sparkScaled(history, "rss"));
  $("spark-cpu").setAttribute("d", spark(history, "cpu"));
}

function freshness() {
  const stale = isStale();
  document.body.classList.toggle("stale", stale && Boolean(latest));
  $("stale-notice").hidden = !latest || !stale;
  $("freshness").className = `pill ${stale ? "warn" : "good"}`;
  $("freshness").textContent = !latest ? (apiError ? "API unavailable" : "Connecting…") : stale ? "Stale data" : "Live snapshots";
  if (latest) {
    const age = Math.max(0, Math.floor((performance.now() - lastChange) / 1000));
    $("meta").textContent = `${latest.policy} · snapshot ${new Date(latest.generated_at_ms).toLocaleTimeString()} · ${age}s since change`;
  } else if (apiError) $("meta").textContent = "Cannot load /api/state. Retrying automatically.";
  // Same smoothed value the chart draws; `point` gates it so a duplicate or failed poll shows —.
  const total = point ? graph(history).latest : null;
  $("rx").textContent = stale ? "—" : rate(total?.rx);
  $("tx").textContent = stale ? "—" : rate(total?.tx);
  for (const row of serverRows.values()) {
    const server = point ? graph(history, row.id).latest : null;
    // Second line: the whole-history average, so a burst or a lull reads against the norm.
    const average = trafficAverage(history, row.id);
    const note = average ? `avg ${Math.round(average.seconds)}s` : "avg —";
    row.rx.replaceChildren(node("div", stale ? "—" : rate(server?.rx)), node("small", average ? `${note} ${rate(average.rx)}` : note));
    row.tx.replaceChildren(node("div", stale ? "—" : rate(server?.tx)), node("small", average ? `${note} ${rate(average.tx)}` : note));
  }
  if (stale) {
    $("chart-note").textContent = latest ? "Last successful snapshot · not live" : "Waiting for connection…";
    $("recent-errors").textContent = latest ? "Recent changes unavailable while stale" : "No snapshot available";
    $("legend-rx").textContent = "RX — Mbit/s";
    $("legend-tx").textContent = "TX — Mbit/s";
    $("proc-rss").textContent = "—";
    $("proc-cpu").textContent = "—";
    $("proc-cpu-kind").textContent = "No live process sample";
    $("proc-rss-kind").textContent = latest ? "Live value hidden while stale" : "No process sample";
    setMeter("proc-mem-bar", null);
    setMeter("proc-cpu-bar", null);
    $("spark-rss").setAttribute("d", "");
    $("spark-cpu").setAttribute("d", "");
  }
}

function renderServers() {
  const body = $("servers").tBodies[0];
  const ids = new Set(latest.servers.map(server => server.id));
  for (const [id, row] of serverRows) if (!ids.has(id)) { row.tr.remove(); serverRows.delete(id); }
  if (!serverRows.size) body.replaceChildren();
  latest.servers.forEach((server, index) => {
    let row = serverRows.get(server.id);
    if (!row) {
      const tr = node("tr"), details = node("details"), result = node("p");
      details.append(node("summary", "Details"), result);
      row = { id: server.id, tr, identity: cell(""), state: cell(""), mimic: cell(""), rx: cell("", true), tx: cell("", true), flows: cell("", true), total: cell("", true), result };
      tr.append(row.identity, row.state, row.mimic, row.rx, row.tx, row.flows, row.total, cell(details));
      serverRows.set(server.id, row);
    }
    // Keep details and keyboard focus stable while values update.
    if (body.children[index] !== row.tr) body.insertBefore(row.tr, body.children[index] ?? null);
    row.tr.dataset.state = server.state;
    // The code is always text; the flag only decorates the name where the font draws it.
    const mark = server.country && flagsSupported ? `${flag(server.country)} ` : "";
    row.identity.replaceChildren(title(`${mark}${name(server.id)}`, server.country ? `${server.server} · ${server.country}` : server.server));
    const state = badge(server.state);
    row.state.replaceChildren(state);
    const lines = mimicCell(server.selection, server.mimic);
    row.mimic.replaceChildren(
      node("div", lines.transport),
      ...(lines.race ? [node("small", lines.race)] : []),
      ...(lines.limited ? [node("small", lines.limited)] : []),
    );
    if (server.reason && server.state !== "ready") row.state.append(node("small", server.reason, "reason"));
    row.flows.textContent = latest.flows.filter(flow => flow.via === server.id).length;
    row.total.replaceChildren(node("div", bytes(server.stats.inner_rx_bytes)), node("small", bytes(server.stats.inner_tx_bytes)));
    const stats = server.stats;
    row.result.textContent = `Weight ${server.weight} · ${stats.opened_flows} opened / ${stats.open_failed_flows} failed / ${stats.closed_flows} closed · ${stats.dropped_packets} drops since start. ${server.reason ? `Last failure: ${server.reason}` : "No recorded failure."}`;
  });
  if (!latest.servers.length) table("servers", [], 8, "No servers configured");
  if (point?.drops != null) $("recent-errors").textContent = `Since previous sample: ${point.drops} drops · ${point.failed} failed opens (VPN links)`;
  else $("recent-errors").textContent = "Waiting for two fresh samples to calculate changes";
}

function renderRules() {
  const rows = latest.rules.map(rule => [
    cell(title(`${rule.index + 1}. ${rule.label}`, selector(rule))),
    cell(rule.local ? badge(latest.local.ready ? "ready" : "missing", latest.local.ready ? "Local" : "Local unavailable") : rule.owner ? name(rule.owner) : "Not assigned yet"),
    cell(rule.local ? "Local only" : rule.candidates.map(id => name(id)).join(", ")),
    cell(rule.traffic.active_flows, true), cell(bytes(rule.traffic.rx_bytes), true), cell(bytes(rule.traffic.tx_bytes), true),
    cell(rule.kind === "names" ? `${rule.resolved_ips} IPs · every ${rule.every_secs}s` : "Not a DNS rule"),
  ]);
  rows.push([
    cell(title("Fallback", latest.policy === "sticky-asn" ? "Unmatched traffic → ASN grouping" : "Unmatched traffic → weighted balance")),
    cell("Per flow / group"), cell("VPN pool"), cell(latest.fallback.active_flows, true),
    cell(bytes(latest.fallback.rx_bytes), true), cell(bytes(latest.fallback.tx_bytes), true), cell("—"),
  ]);
  table("rules", rows, 7);
  table("groups", latest.groups.map(group => [cell(group.group), cell(name(group.server))]), 2, "No pinned groups");
}

// Missing metadata stays an explicit "Unknown", never an empty cell or a lone flag.
const countryLabel = code => code && flagsSupported ? `${flag(code)} ${code}` : code ?? "Unknown";

function renderFlows() {
  const state = frozen ?? latest;
  if (!state) return;
  options($("flow-exit"), [["", "All exits"], ...state.servers.map(server => [server.id, name(server.id, state)]),
    ...(state.local.enabled || state.flows.some(flow => flow.via === "local") ? [["local", "Local"]] : [])]);
  const names = state.asn_names ?? {};
  const countries = [...new Set(state.flows.map(flow => flow.country ?? "unknown"))].sort();
  const asns = [...new Set(state.flows.map(flow => String(flow.asn ?? "unknown")))].sort((a, b) => a === "unknown" ? 1 : b === "unknown" ? -1 : Number(a) - Number(b));
  options($("flow-country"), [["", "All countries"], ...countries.map(country => [country, country === "unknown" ? "Unknown" : country])]);
  options($("flow-asn"), [["", "All ASNs"], ...asns.map(asn => [asn, asn === "unknown" ? "Unknown" : asnLabel(asn, names)])]);
  const result = flowPage(state.flows, { query: $("flow-search").value, protocol: $("flow-protocol").value, via: $("flow-exit").value,
    country: $("flow-country").value, asn: $("flow-asn").value, names, page });
  page = result.page;
  const labels = result.rows.map(flow => [flow.protocol.toUpperCase(), flow.source, flow.destination,
    countryLabel(flow.country), asnLabel(flow.asn, names), name(flow.via, state),
    flow.rule == null ? "Fallback" : state.rules.find(rule => rule.index === flow.rule)?.label ?? "Unknown rule"]);
  const signature = JSON.stringify({ labels, empty: result.total === 0 });
  if (flowSignature !== signature) {
    const rows = result.rows.map((flow, index) => [
      cell(node("span", labels[index][0], `tag tag--${flow.protocol}`)),
      cell(node("code", labels[index][1])), cell(node("code", labels[index][2])),
      cell(labels[index][3]), cell(labels[index][4]),
      cell(node("span", labels[index][5], "exit-tag")), cell(node("span", labels[index][6], "rule-tag")),
    ]);
    table("flows", rows, 7, result.total ? "No flows match these filters" : "No active flows");
    flowSignature = signature;
  }
  const start = result.count ? page * PAGE_SIZE + 1 : 0;
  $("flow-count").textContent = `Showing ${start}–${result.count ? start + result.rows.length - 1 : 0} of ${result.count} matching · ${result.total} total`;
  $("flow-page").textContent = `${page + 1} / ${result.pages}`;
  $("previous").disabled = page === 0;
  $("next").disabled = page + 1 >= result.pages;
  $("pause").disabled = false;
  $("pause").textContent = frozen ? "Resume live table" : "Pause table";
  $("pause").setAttribute("aria-pressed", String(Boolean(frozen)));
  $("flow-status").textContent = frozen ? `Paused at ${new Date(frozen.generated_at_ms).toLocaleTimeString()} · filters still work · summary remains live` : "Live ownership table · 50 rows per page";
}

function renderAsnNames() {
  const state = latest?.asn_table ? asnState : "unavailable";
  $("asn-load").disabled = state === "loading" || state === "unavailable";
  $("asn-load").textContent = state === "ready" ? "Reload ASN names" : "Load ASN names";
  $("asn-status").textContent = state === "ready" ? `${asnCount.toLocaleString()} names in this browser · freed after 5 min in a hidden tab`
    : state === "loading" ? "Downloading and parsing ASN CSV in this browser… · numbers remain available"
    : state === "error" ? `ASN names unavailable: ${asnError} · retry with Load ASN names`
    : state === "unavailable" ? "ASN names require a loaded geo-db CSV"
    : state === "evicted" ? "ASN names freed after 5 min hidden · use Load ASN names"
    : "ASN names not loaded";
}

function clearAsnNames(state) {
  const request = asnAbort;
  asnAbort = null; request?.abort();
  asnNames = Object.create(null); asnCount = 0; asnState = state; asnError = "";
  if (latest) latest = { ...latest, asn_names: asnNames };
}

async function loadAsnNames() {
  if (!latest?.asn_table || asnState === "loading") return;
  const request = new AbortController();
  asnAbort = request; asnState = "loading"; asnError = "";
  renderAsnNames();
  try {
    const response = await fetch("/api/asn.csv", { cache: "no-store", signal: AbortSignal.any([request.signal, AbortSignal.timeout(120000)]) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await readAsnNames(response.body);
    if (asnAbort !== request) return;
    asnNames = result.names; asnCount = result.count; asnState = "ready";
    latest = { ...latest, asn_names: asnNames };
  } catch (error) {
    if (asnAbort !== request) return;
    asnState = "error"; asnError = error.message;
  } finally {
    if (asnAbort === request) { asnAbort = null; renderAsnNames(); renderFlows(); }
  }
}

function asnVisibility() {
  clearTimeout(asnIdleTimer);
  if (document.hidden) {
    asnIdleTimer = setTimeout(() => { clearAsnNames("evicted"); renderAsnNames(); renderFlows(); }, 300000);
  } else if (latest?.asn_table && asnState === "idle") void loadAsnNames();
}

function renderJobs() {
  table("databases", latest.databases.map(db => [
    cell(db.kind === "geo" ? "ASN" : "Country"),
    cell(badge(db.loaded ? db.status.error ? "previous" : "ready" : db.configured ? "missing" : "disabled",
      db.loaded ? db.status.error ? "Using previous table" : "Loaded" : db.configured ? "Missing" : "Not configured")),
    cell(db.rows, true), cell(time(db.status.loaded_at)), cell(time(db.status.attempted_at)),
    cell(db.status.error || (db.pending ? `Waiting for job ${db.pending}` : "No update error recorded")),
  ]), 6);
  table("jobs", latest.jobs.details.map(job => [
    cell(title(job.label, `Every ${job.every_secs}s · timeout ${job.timeout_secs}s${job.reload.length ? ` · reload ${job.reload.join(", ")}` : ""}`)),
    cell(badge(job.state)), cell(time(job.started_at)), cell(time(job.success_at)),
    cell(job.state === "running" ? "Running now" : time(job.next_at)), cell(job.reason ? `${job.state === "running" ? "Previous attempt: " : ""}${job.reason}` : job.state === "ok" ? "Completed successfully" : "—"),
  ]), 6, "No scheduled jobs");
}

function renderCounters() {
  const s = latest.sticky, j = latest.jobs, l = latest.local;
  const counters = [
    ["Sticky lookups: hits / misses", `${s.lookup_hit} / ${s.lookup_miss}`], ["Failover moves", s.failover_moves],
    ["Rule matches", s.block_hit], ["Resolver: successes / failures", `${s.resolve_ok} / ${s.resolve_fail}`],
    ["Resolved / purged IPs", `${s.resolved_ips} / ${s.purged_ips}`], ["Local: opened / closed", `${l.opened} / ${l.closed}`],
    ["Local: failures", l.failed], ["Jobs: completed runs", j.runs], ["Jobs: script failures", j.failures], ["Jobs: timeouts", j.timeouts],
  ];
  $("counters").replaceChildren(...counters.map(([label, value]) => { const div = node("div", "", "counter"); div.append(node("small", label), node("strong", value)); return div; }));
}

function renderChart() {
  if (!latest || !history.length) return;
  options($("chart-server"), [["", "All VPN servers"], ...latest.servers.map(server => [server.id, name(server.id)])]);
  const selected = $("chart-server").value;
  const result = graph(history, selected);
  const fill = areas(history, selected);
  $("chart-rx-area").setAttribute("d", fill.rx);
  $("chart-tx-area").setAttribute("d", fill.tx);
  $("spark-rx").setAttribute("d", spark(history, "rx", selected));
  $("spark-tx").setAttribute("d", spark(history, "tx", selected));
  $("chart-rx").setAttribute("d", result.rx);
  $("chart-tx").setAttribute("d", result.tx);
  $("chart-max").textContent = `${result.max.toFixed(2)} Mbit/s`;
  $("chart-end").textContent = new Date(latest.generated_at_ms).toLocaleTimeString();
  const current = point ? result.latest : null;
  $("legend-rx").textContent = `RX ${rate(current?.rx)} Mbit/s`;
  $("legend-tx").textContent = `TX ${rate(current?.tx)} Mbit/s`;
  const collected = Math.max(0, Math.floor((history.at(-1).time - history[0].time) / 1000));
  $("chart-note").textContent = current?.rx == null ? "Collecting fresh samples…" : collected < 30 ? `${collected}s collected · 5-minute window` : "Inner IP · VPN links only";
}

function render() {
  for (const id of ["chart-server", "flow-search", "flow-protocol", "flow-exit", "flow-country", "flow-asn"])  $(id).disabled = false;
  const ready = latest.servers.filter(server => server.state === "ready").length;
  $("ready").textContent = `${ready} / ${latest.servers.length}`;
  $("active").textContent = latest.flows.length;
  const localFlows = latest.flows.filter(flow => flow.via === "local").length;
  $("active-note").textContent = `${latest.flows.length - localFlows} VPN · ${localFlows} local`;
  $("local").textContent = localState(latest.local);
  $("local-note").textContent = latest.local.enabled ? `${localFlows} owned flows · ${latest.local.ready ? "direct WAN egress" : "no new local flows"}` : "No local-exit rules configured";
  const warnings = latest.servers.filter(server => server.state !== "ready").map(server => `${name(server.id)}: ${server.state}${server.reason ? ` — ${server.reason}` : ""}`);
  if (latest.local.enabled && !latest.local.ready) warnings.push("Local exit unavailable; local rules do not fall back to VPN");
  for (const db of latest.databases) if (db.configured && !db.loaded) warnings.push(`${db.kind === "geo" ? "ASN" : "Country"} database missing`);
  $("warnings").textContent = warnings.join(" · ");
  $("warnings").hidden = !warnings.length;
  document.body.dataset.health = warnings.length ? "warn" : "ok";
  $("rail-health").textContent = warnings.length ? `${warnings.length} warning${warnings.length === 1 ? "" : "s"} to review` : ready === latest.servers.length ? "All links ready" : "Pool recovering";
  renderClock(); renderProcess(); renderServers(); renderRules(); renderFlows(); renderAsnNames(); renderJobs(); renderCounters(); renderChart(); freshness();
  $("footer").textContent = `Client started ${time(latest.started_at / 1000)} · no external assets · history stays in this tab only`;
  if (latest.asn_table && asnState === "idle" && !document.hidden) void loadAsnNames();
}

async function refresh() {
  try {
    const response = await fetch(endpoint, { cache: "no-store", signal: AbortSignal.timeout(2500) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const state = await response.json();
    if (!Number.isFinite(state.generated_at_ms) || !Array.isArray(state.servers) || !Array.isArray(state.flows)) throw new Error("Invalid snapshot");
    if (!latest || state.started_at !== latest.started_at || state.generated_at_ms > latest.generated_at_ms) {
      const resumed = isStale();
      if (latest && state.started_at !== latest.started_at) { clearAsnNames("idle"); history = []; point = null; latest = null; }
      point = measure(resumed || !point ? null : latest, state);
      apiError = false;
      history = keepHistory(history, point);
      latest = { ...state, asn_names: asnNames };
      lastChange = performance.now();
      render();
    } else {
      const recovered = apiError;
      apiError = false;
      if (recovered) render();
      else freshness();
    }
  } catch {
    apiError = true;
    point = null;
    freshness();
  } finally {
    setTimeout(refresh, 1000); // One outstanding request, even when the API is slow.
  }
}

function hideCursor() { $("chart-tooltip").hidden = true; $("chart-cursor").hidden = true; }

$("chart-server").addEventListener("change", () => { renderChart(); freshness(); });
for (const id of ["flow-search", "flow-protocol", "flow-exit", "flow-country", "flow-asn"]) $(id).addEventListener(id === "flow-search" ? "input" : "change", () => { page = 0; renderFlows(); });
$("asn-load").addEventListener("click", () => void loadAsnNames());
document.addEventListener("visibilitychange", asnVisibility);
asnVisibility();
$("pause").addEventListener("click", () => {
  if (!latest) return;
  // Freeze only names used by these rows, not the full browser dictionary.
  frozen = frozen ? null : { ...latest, asn_names: Object.fromEntries(latest.flows.filter(flow => asnNames[flow.asn]).map(flow => [flow.asn, asnNames[flow.asn]])) };
  page = 0; renderFlows();
});
$("previous").addEventListener("click", () => { page--; renderFlows(); });
$("next").addEventListener("click", () => { page++; renderFlows(); });

function setTheme(light) {
  document.body.dataset.theme = light ? "light" : "dark";
  $("theme-toggle").setAttribute("aria-pressed", String(light));
  $("theme-toggle").textContent = light ? "DARK" : "LIGHT";
}
setTheme(document.body.dataset.theme === "light");
$("theme-toggle").addEventListener("click", () => setTheme(document.body.dataset.theme !== "light"));

$("chart-plot").addEventListener("pointermove", event => {
  if (!history.length) { hideCursor(); return; }
  const rect = $("chart-plot").getBoundingClientRect();
  if (!rect.width) { hideCursor(); return; }
  const ratio = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
  const end = history.at(-1).time;
  const sample = nearestSample(history, end - WINDOW_MS + ratio * WINDOW_MS, $("chart-server").value);
  if (!sample || (sample.rx == null && sample.tx == null)) { hideCursor(); return; }
  $("chart-tooltip").textContent = `${new Date(sample.time).toLocaleTimeString()} · RX ${rate(sample.rx)} / TX ${rate(sample.tx)} Mbit/s`;
  $("chart-tooltip").style.left = `${(ratio * 100).toFixed(1)}%`;
  const x = (ratio * 1000).toFixed(2);
  $("chart-cursor").setAttribute("x1", x);
  $("chart-cursor").setAttribute("x2", x);
  $("chart-tooltip").hidden = false;
  $("chart-cursor").hidden = false;
});
$("chart-plot").addEventListener("pointerleave", hideCursor);

document.addEventListener("keydown", event => {
  const active = document.activeElement;
  const typing = active && ["INPUT", "SELECT", "TEXTAREA"].includes(active.tagName);
  if (event.key === "/" && !typing) { event.preventDefault(); $("flow-search").focus(); }
  if (event.key === "Escape" && active === $("flow-search")) {
    $("flow-search").value = "";
    $("flow-search").dispatchEvent(new Event("input"));
    $("flow-search").blur();
  }
});

const navLinks = [...document.querySelectorAll(".rail-nav a[data-section]")];
if ("IntersectionObserver" in window) {
  // Keep the full set currently in the reading band: overlapping sections must not
  // fight over the highlight, and document order decides which one owns it.
  const visible = new Set();
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (entry.isIntersecting) visible.add(entry.target.id); else visible.delete(entry.target.id);
    }
    const active = navLinks.find(link => visible.has(link.dataset.section));
    if (!active) return;
    for (const link of navLinks) link.classList.toggle("is-active", link === active);
  }, { rootMargin: "-12% 0px -72% 0px" });
  for (const link of navLinks) {
    const section = document.getElementById(link.dataset.section);
    if (section) observer.observe(section);
  }
}

for (const [id, columns] of [["servers", 7], ["rules", 7], ["flows", 5], ["databases", 6], ["jobs", 6], ["groups", 2]]) table(id, [], columns, "No snapshot yet");
renderClock();
setInterval(() => { renderClock(); freshness(); }, 1000);
refresh();
