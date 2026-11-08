import { STALE_MS, PAGE_SIZE, bytes, rate, measure, keepHistory, graph, flowPage, selector, localState } from "/state.mjs";

const $ = id => document.getElementById(id);
const endpoint = document.querySelector("main").dataset.endpoint;
let latest = null, point = null, history = [], lastChange = 0, apiError = false;
let frozen = null, page = 0, flowSignature = "";
const serverRows = new Map();

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
  $("rx").textContent = stale ? "—" : rate(point?.rx);
  $("tx").textContent = stale ? "—" : rate(point?.tx);
  for (const row of serverRows.values()) {
    row.rx.textContent = stale ? "—" : rate(point?.servers[row.id]?.rx);
    row.tx.textContent = stale ? "—" : rate(point?.servers[row.id]?.tx);
  }
  if (stale) {
    $("chart-note").textContent = latest ? "Last successful snapshot · not live" : "Waiting for connection…";
    $("recent-errors").textContent = latest ? "Recent changes unavailable while stale" : "No snapshot available";
    $("legend-rx").textContent = "↓ Receive — Mbit/s";
    $("legend-tx").textContent = "↑ Send — Mbit/s";
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
      row = { id: server.id, tr, identity: cell(""), state: cell(""), rx: cell("", true), tx: cell("", true), flows: cell("", true), total: cell("", true), result };
      tr.append(row.identity, row.state, row.rx, row.tx, row.flows, row.total, cell(details));
      serverRows.set(server.id, row);
    }
    // Keep details and keyboard focus stable while values update.
    if (body.children[index] !== row.tr) body.insertBefore(row.tr, body.children[index] ?? null);
    row.identity.replaceChildren(title(name(server.id), server.server));
    const state = badge(server.state);
    row.state.replaceChildren(state);
    if (server.reason && server.state !== "ready") row.state.append(node("small", server.reason, "reason"));
    row.flows.textContent = latest.flows.filter(flow => flow.via === server.id).length;
    row.total.replaceChildren(node("div", bytes(server.stats.inner_rx_bytes)), node("small", bytes(server.stats.inner_tx_bytes)));
    const stats = server.stats;
    row.result.textContent = `Weight ${server.weight} · ${stats.opened_flows} opened / ${stats.open_failed_flows} failed / ${stats.closed_flows} closed · ${stats.dropped_packets} drops since start. ${server.reason ? `Last failure: ${server.reason}` : "No recorded failure."}`;
  });
  if (!latest.servers.length) table("servers", [], 7, "No servers configured");
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

function renderFlows() {
  const state = frozen ?? latest;
  if (!state) return;
  options($("flow-exit"), [["", "All exits"], ...state.servers.map(server => [server.id, name(server.id, state)]),
    ...(state.local.enabled || state.flows.some(flow => flow.via === "local") ? [["local", "Local"]] : [])]);
  const result = flowPage(state.flows, { query: $("flow-search").value, protocol: $("flow-protocol").value, via: $("flow-exit").value, page });
  page = result.page;
  const labels = result.rows.map(flow => [flow.protocol.toUpperCase(), flow.source, flow.destination, name(flow.via, state),
    flow.rule == null ? "Fallback" : state.rules.find(rule => rule.index === flow.rule)?.label ?? "Unknown rule"]);
  const signature = JSON.stringify({ labels, empty: result.total === 0 });
  if (flowSignature !== signature) {
    table("flows", labels.map(row => row.map(value => cell(value))), 5, result.total ? "No flows match these filters" : "No active flows");
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
  if (!latest) return;
  options($("chart-server"), [["", "All VPN servers"], ...latest.servers.map(server => [server.id, name(server.id)])]);
  const result = graph(history, $("chart-server").value);
  $("chart-rx").setAttribute("d", result.rx);
  $("chart-tx").setAttribute("d", result.tx);
  $("chart-max").textContent = `${result.max.toFixed(2)} Mbit/s`;
  $("chart-end").textContent = new Date(latest.generated_at_ms).toLocaleTimeString();
  const current = point ? result.latest : null;
  $("legend-rx").textContent = `↓ Receive ${rate(current?.rx)} Mbit/s`;
  $("legend-tx").textContent = `↑ Send ${rate(current?.tx)} Mbit/s`;
  const collected = Math.max(0, Math.floor((history.at(-1).time - history[0].time) / 1000));
  $("chart-note").textContent = current?.rx == null ? "Collecting fresh samples…" : collected < 30 ? `${collected}s collected · 5-minute window` : "Inner IP · VPN links only";
}

function render() {
  for (const id of ["chart-server", "flow-search", "flow-protocol", "flow-exit"]) $(id).disabled = false;
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
  renderServers(); renderRules(); renderFlows(); renderJobs(); renderCounters(); renderChart(); freshness();
  $("footer").textContent = `Client started ${time(latest.started_at / 1000)} · no external assets · history stays in this tab only`;
}

async function refresh() {
  try {
    const response = await fetch(endpoint, { cache: "no-store", signal: AbortSignal.timeout(2500) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const state = await response.json();
    if (!Number.isFinite(state.generated_at_ms) || !Array.isArray(state.servers) || !Array.isArray(state.flows)) throw new Error("Invalid snapshot");
    if (!latest || state.started_at !== latest.started_at || state.generated_at_ms > latest.generated_at_ms) {
      const resumed = isStale();
      if (latest && state.started_at !== latest.started_at) { history = []; point = null; latest = null; }
      point = measure(resumed || !point ? null : latest, state);
      apiError = false;
      history = keepHistory(history, point);
      latest = state;
      lastChange = performance.now();
      render();
    } else if (apiError) {
      apiError = false;
      render();
    } else freshness();
  } catch {
    apiError = true;
    point = null;
    freshness();
  } finally {
    setTimeout(refresh, 1000); // One outstanding request, even when the API is slow.
  }
}

$("chart-server").addEventListener("change", () => { renderChart(); freshness(); });
for (const id of ["flow-search", "flow-protocol", "flow-exit"]) $(id).addEventListener(id === "flow-search" ? "input" : "change", () => { page = 0; renderFlows(); });
$("pause").addEventListener("click", () => { if (latest) { frozen = frozen ? null : latest; page = 0; renderFlows(); } });
$("previous").addEventListener("click", () => { page--; renderFlows(); });
$("next").addEventListener("click", () => { page++; renderFlows(); });
for (const [id, columns] of [["servers", 7], ["rules", 7], ["flows", 5], ["databases", 6], ["jobs", 6], ["groups", 2]]) table(id, [], columns, "No snapshot yet");
setInterval(freshness, 1000);
refresh();
