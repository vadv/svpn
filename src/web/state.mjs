// Pure dashboard calculations: no timers, DOM or persistent storage.
export const WINDOW_MS = 5 * 60 * 1000;
export const STALE_MS = 5000;
export const PAGE_SIZE = 50;
// Wall time, not a sample count: a loaded router answers polls slower than once a second.
export const SMOOTH_MS = 15000;
// The chart's oldest point needs a full smoothing window behind it, so history reaches that far back.
const HISTORY_MS = WINDOW_MS + SMOOTH_MS;

export function bytes(value) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

export const rate = value => value == null ? "—" : value.toFixed(2);

// Closing flows are stated, never folded into the active count; the note is
// omitted entirely when nothing is closing, and a missing field is not a zero.
export const flowCounts = ({ active_flows = 0, closing_flows = 0 } = {}) =>
  closing_flows > 0 ? `${active_flows} active · ${closing_flows} closing` : `${active_flows} active`;

export function change(before, after) {
  if (!Number.isFinite(before) || !Number.isFinite(after) || after < before) return null;
  return after - before;
}

// The Rust snapshot exposes a cumulative CPU counter. A restart, reset counter
// or long API gap must produce "unknown", never an averaged fake percentage.
export function cpuPercent(previous, current, maxGapMs = STALE_MS) {
  if (!previous || !current || previous.started_at !== current.started_at) return null;
  if (!Number.isFinite(previous.started_at) || !Number.isFinite(current.started_at)) return null;
  const elapsed = current.generated_at_ms - previous.generated_at_ms;
  if (!Number.isFinite(elapsed) || elapsed <= 0 || elapsed > maxGapMs) return null;
  const before = previous.process?.cpu_seconds;
  const after = current.process?.cpu_seconds;
  if (!Number.isFinite(before) || !Number.isFinite(after)) return null;
  const delta = change(before, after);
  if (delta == null) return null;
  const percent = delta * 100000 / elapsed; // CPU seconds / wall milliseconds -> % of one core.
  return Number.isFinite(percent) && percent >= 0 ? percent : null;
}

// A poll-length rate is a spike, not a load: the headline averages the whole chart
// window and says over how long. A counter reset inside the window is unknown, not 0.
export function cpuAverage(history) {
  const first = history.find(item => Number.isFinite(item.cpu_seconds));
  const last = history.at(-1);
  if (!first || first === last || !Number.isFinite(last.cpu_seconds)) return null;
  const seconds = (last.time - first.time) / 1000;
  const delta = last.cpu_seconds - first.cpu_seconds;
  if (!(seconds > 0) || !Number.isFinite(delta) || delta < 0) return null;
  const percent = delta * 100 / seconds; // CPU seconds / wall seconds -> % of one core.
  return Number.isFinite(percent) ? { percent, seconds } : null;
}

// Current RSS wins. A peak-only value is explicitly flagged so the UI labels it.
export function processRss(process = null) {
  const usable = value => Number.isFinite(value) && value >= 0 ? value : null;
  const current = usable(process?.rss_bytes);
  if (current != null) return { bytes: current, peak: false };
  const peak = usable(process?.peak_rss_bytes);
  return { bytes: peak, peak: peak != null };
}

export function uptimeSeconds(snapshot, now = Date.now()) {
  if (!Number.isFinite(snapshot?.started_at) || !Number.isFinite(now) || now < snapshot.started_at) return null;
  return Math.floor((now - snapshot.started_at) / 1000);
}

export function duration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const total = Math.floor(seconds);
  const pad = value => String(value).padStart(2, "0");
  const days = Math.floor(total / 86400);
  const clock = `${pad(Math.floor(total % 86400 / 3600))}:${pad(Math.floor(total % 3600 / 60))}:${pad(total % 60)}`;
  return days ? `${days}d ${clock}` : clock;
}

// Use snapshot timestamps and stable node ids, never the polling interval or array position.
// A restart, counter reset, duplicate snapshot or missing interval is not a zero-rate sample.
export function measure(previous, current) {
  const elapsed = previous ? current.generated_at_ms - previous.generated_at_ms : 0;
  const valid = previous && previous.started_at === current.started_at && elapsed > 0 && elapsed <= STALE_MS;
  const before = new Map((previous?.servers ?? []).map(server => [server.id, server.stats]));
  const servers = Object.create(null);
  for (const server of current.servers) {
    const old = valid ? before.get(server.id) : null;
    const diff = field => old ? change(old[field], server.stats[field]) : null;
    const rx = diff("inner_rx_bytes"), tx = diff("inner_tx_bytes");
    servers[server.id] = {
      rx: rx == null ? null : rx * 8 / elapsed / 1000,
      tx: tx == null ? null : tx * 8 / elapsed / 1000,
      drops: diff("dropped_packets"), failed: diff("open_failed_flows"),
    };
  }
  const total = field => {
    const values = Object.values(servers).map(server => server[field]);
    return values.length && values.every(value => value != null) ? values.reduce((a, b) => a + b, 0) : null;
  };
  const memory = processRss(current.process);
  return {
    time: current.generated_at_ms, servers,
    rx: total("rx"), tx: total("tx"), drops: total("drops"), failed: total("failed"),
    rss: memory.bytes, cpu: cpuPercent(previous, current),
    cpu_seconds: Number.isFinite(current.process?.cpu_seconds) ? current.process.cpu_seconds : null,
  };
}

export function keepHistory(history, point) {
  // Even a faulty future-dated or high-frequency source cannot grow history without a bound.
  return [...history.filter(item => item.time > point.time - HISTORY_MS && item.time < point.time), point]
    .slice(-(HISTORY_MS / 1000 + 1));
}

// A rate over one poll is a spike, not a trend: one slow snapshot reads as a traffic burst, so every
// drawn line averages a short window. A missing sample stays missing — averaging across an API gap
// would paint traffic that never crossed a tunnel. Values are already in the unit being drawn.
export function smoothRates(values, times, windowMs = SMOOTH_MS) {
  return values.map((value, index) => {
    if (value == null) return null;
    let sum = 0, count = 0;
    for (let i = index; i >= 0 && times[i] > times[index] - windowMs; i--) {
      const item = values[i];
      if (item != null) { sum += item; count++; }
    }
    return count ? sum / count : null;
  });
}

// The whole-history average of one server (or all of them): every measured interval weighted by its
// length, so the result is bytes over time actually seen. Unmeasured intervals (gaps, restarts) are
// left out rather than read as zero; null until one interval exists.
export function trafficAverage(history, serverId = "") {
  let rx = 0, tx = 0, ms = 0;
  for (let i = 1; i < history.length; i++) {
    const sample = serverId ? history[i].servers?.[serverId] : history[i];
    const elapsed = history[i].time - history[i - 1].time;
    if (sample?.rx == null || sample?.tx == null || !(elapsed > 0)) continue;
    rx += sample.rx * elapsed; tx += sample.tx * elapsed; ms += elapsed;
  }
  return ms ? { rx: rx / ms, tx: tx / ms, seconds: ms / 1000 } : null;
}

// One sample vocabulary for the chart, its sparklines and the headline numbers. Everything
// shows the smoothed rate: a single poll-length rate reads 0 or a spike while the chart says
// otherwise, and two numbers for one quantity is one too many.
function series(history, serverId = "") {
  const raw = history.map(point => ({
    time: point.time,
    ...(serverId ? point.servers?.[serverId] ?? { rx: null, tx: null } : point),
  }));
  const times = raw.map(sample => sample.time);
  const rx = smoothRates(raw.map(sample => sample.rx), times);
  const tx = smoothRates(raw.map(sample => sample.tx), times);
  const cpu = smoothRates(raw.map(sample => sample.cpu), times);
  const end = history.at(-1)?.time ?? 0;
  // Samples older than the window only feed the average: drawn alone they are raw one-poll rates.
  const samples = raw.map((sample, index) => ({ ...sample, rx: rx[index], tx: tx[index], cpu: cpu[index] }))
    .filter(sample => sample.time > end - WINDOW_MS);
  return { samples, end, latest: samples.at(-1) ?? null };
}

// The newest sample, smoothed like the chart: what the headline numbers quote.
export const latestSample = (history, serverId = "") => series(history, serverId).latest;

// A compact trend for the summary cells: last 40 samples, its own scale.
// The points of the trend, run by run: a missing sample is not joined over.
function sparkPoints(history, field) {
  const recent = series(history).samples.slice(-40);
  const max = Math.max(0.01, ...recent.map(sample => sample[field] ?? 0));
  const runs = [];
  let run = [];
  for (const [index, sample] of recent.entries()) {
    if (sample[field] == null) { run = []; continue; }
    const x = recent.length === 1 ? 120 : 120 * index / (recent.length - 1);
    if (!run.length) runs.push(run);
    run.push([x, 28 - 24 * sample[field] / max]);
  }
  return runs;
}

export function spark(history, field) {
  return sparkPoints(history, field).map(run => run.map(([x, y], index) => {
    const position = `${x.toFixed(2)},${y.toFixed(2)}`;
    // Round caps make a zero-length first segment visible without inventing history.
    return index ? `L${position}` : `M${position} l0,0`;
  }).join(" ")).join(" ");
}

// The same trend filled down to its baseline: a card carries the chart's look.
export function sparkArea(history, field) {
  return sparkPoints(history, field).filter(run => run.length > 1).map(run =>
    `M${run[0][0].toFixed(2)},30 ${run.map(([x, y]) => `L${x.toFixed(2)},${y.toFixed(2)}`).join(" ")} L${run.at(-1)[0].toFixed(2)},30 Z`).join(" ");
}

// A trend for values whose useful baseline is not zero, such as resident memory.
// Gaps stay broken and a flat line stays inside the box without dividing by zero.
export function sparkScaled(history, field) {
  const recent = history.slice(-40).map(sample => sample[field]);
  const values = recent.filter(value => Number.isFinite(value));
  if (!values.length) return "";
  const low = Math.min(...values), high = Math.max(...values);
  const padding = Math.max((high - low) * 0.15, Math.abs(high) * 0.01, 1);
  const min = low - padding, span = high - low + 2 * padding;
  let connected = false;
  return recent.map((value, index) => {
    if (!Number.isFinite(value)) { connected = false; return ""; }
    const x = recent.length === 1 ? 120 : 120 * index / (recent.length - 1);
    const position = `${x.toFixed(2)},${(28 - 24 * (value - min) / span).toFixed(2)}`;
    const segment = connected ? `L${position}` : `M${position} l0,0`;
    connected = true;
    return segment;
  }).join(" ");
}

export function asnLabel(asn, names = {}) {
  return asn == null ? "Unknown" : `AS${asn}${names[asn] ? ` · ${names[asn]}` : ""}`;
}

// The exit each ASN group is pinned to, keyed by the ASN as the usage names it.
export function asnOwners(groups) {
  const owners = new Map();
  for (const item of groups ?? []) {
    const asn = /^asn (\d+)$/.exec(item.group)?.[1];
    if (asn != null) owners.set(asn, item.server);
  }
  return owners;
}

// The pinned groups as the table lists them: an ASN group named by its network, every
// group with its exit and what it carried since start, busiest first and then by number.
export function pinnedGroups(groups, { rules = [], networks = {}, names = {} } = {}) {
  const trafficOf = new Map(rules.map(rule => [rule.label, rule.traffic]));
  return (groups ?? []).map(item => {
    const asn = /^asn (\d+)$/.exec(item.group)?.[1] ?? null;
    const traffic = asn == null ? trafficOf.get(item.group) : networks[asn];
    return {
      key: item.group, asn, server: item.server, label: asn == null ? item.group : asnLabel(Number(asn), names),
      rx_bytes: traffic?.rx_bytes ?? 0, tx_bytes: traffic?.tx_bytes ?? 0,
    };
  }).sort((a, b) => b.rx_bytes + b.tx_bytes - a.rx_bytes - a.tx_bytes || (a.asn ?? 0) - (b.asn ?? 0) || a.key.localeCompare(b.key));
}

// Flag for a country code as the regional-indicator pair. The snapshot only ever
// carries two ASCII letters or null, so anything else stays flagless by design.
export function flag(code) {
  return /^[A-Z]{2}$/.test(code ?? "")
    ? String.fromCodePoint(...[...code].map(letter => 0x1f1e6 + letter.charCodeAt(0) - 65)) : "";
}

const flowKey = flow => `${flow.protocol} ${flow.source} ${flow.destination}`;

// The Source column: the LAN device behind the router's masquerade when the
// snapshot names one, otherwise the router itself; the tunnel address stays
// visible as the note under it.
export function flowSource(flow) {
  return flow.client
    ? { main: flow.client_name ? `${flow.client_name} · ${flow.client}` : flow.client, detail: `via ${flow.source}` }
    : { main: "router", detail: flow.source };
}

// A guess from the destination's well-known port: the hub never inspects payloads.
const SERVICES = {
  tcp: { 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
    853: "DoT", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 3389: "RDP", 5222: "XMPP", 5223: "Apple push", 5228: "Google push",
    8080: "HTTP", 8443: "HTTPS" },
  udp: { 53: "DNS", 67: "DHCP", 123: "NTP", 443: "QUIC", 500: "IKE", 853: "DoQ", 1900: "SSDP", 3478: "STUN", 4500: "IPsec",
    5353: "mDNS", 19302: "STUN", 51820: "WireGuard" },
};

export function flowService(flow) {
  const port = Number(flow.destination.slice(flow.destination.lastIndexOf(":") + 1));
  return SERVICES[flow.protocol]?.[port] ?? null;
}

// The Age column: lifetime since the hub saw the flow, and how long it has been silent.
export function flowAge(flow) {
  if (!Number.isFinite(flow.age_secs)) return { main: "—", detail: "" };
  return { main: duration(flow.age_secs), detail: flow.idle_secs >= 2 ? `idle ${duration(flow.idle_secs)}` : "active now" };
}

// Each flow's bytes per second since the previous snapshot; null when the flow is new, the
// clock did not advance or a counter went backwards (a reinserted tuple restarts at zero).
export function withFlowRates(previous, current) {
  const elapsed = previous ? (current.generated_at_ms - previous.generated_at_ms) / 1000 : 0;
  const before = new Map(elapsed > 0 ? previous.flows.map(flow => [flowKey(flow), flow]) : []);
  return current.flows.map(flow => {
    const old = before.get(flowKey(flow));
    const rx = old && change(old.rx_bytes, flow.rx_bytes), tx = old && change(old.tx_bytes, flow.tx_bytes);
    return { ...flow, rate: rx == null || tx == null ? null : (rx + tx) / elapsed };
  });
}

const ORDERS = {
  rate: (a, b) => (b.rate ?? -1) - (a.rate ?? -1),
  total: (a, b) => (b.rx_bytes ?? 0) + (b.tx_bytes ?? 0) - (a.rx_bytes ?? 0) - (a.tx_bytes ?? 0),
  age: (a, b) => (b.age_secs ?? -1) - (a.age_secs ?? -1),
  idle: (a, b) => (b.idle_secs ?? -1) - (a.idle_secs ?? -1),
};

// Each axis is an alternative view of the same bytes, not an additional expense.
export function usageRanking(entries, direction) {
  const amount = t => direction === "rx" ? t.rx_bytes : direction === "tx" ? t.tx_bytes : t.rx_bytes + t.tx_bytes;
  // A row may name the exit it is pinned to: the list colours and labels it by that.
  const rows = entries.map(([key, label, traffic, via = null]) => ({ key, label, ...traffic, value: amount(traffic), via }))
    .filter(row => row.value > 0).sort((a, b) => b.value - a.value || String(a.key).localeCompare(String(b.key), "en"));
  return { rows, total: rows.reduce((sum, row) => sum + row.value, 0) };
}

export function flowPage(flows, { query = "", protocol = "", via = "", country = "", asn = "", drill = null, names = {}, page = 0, order = "" } = {}) {
  const needle = query.trim().toLowerCase();
  const filtered = flows.filter(flow => (!protocol || flow.protocol === protocol) && (!via || flow.via === via) &&
    (!drill || (drill.axis === "exits" ? flow.via : drill.axis === "networks" ? String(flow.asn ?? "unknown") : flow.destination.split(":", 1)[0]) === drill.key) &&
    (!country || (flow.country ?? "unknown") === country) && (!asn || String(flow.asn ?? "unknown") === asn) &&
    (!needle || `${flow.source} ${flow.destination} ${flow.client ?? ""} ${flow.client_name ?? ""} ${flow.country ?? "Unknown"} ${asnLabel(flow.asn, names)} ${flowService(flow) ?? ""}`.toLowerCase().includes(needle)));
  // The snapshot already arrives in address order; a stable sort keeps it as the tie-breaker.
  if (ORDERS[order]) filtered.sort(ORDERS[order]);
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  page = Math.max(0, Math.min(page, pages - 1));
  return { rows: filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), count: filtered.length, total: flows.length, page, pages };
}

function ipv4Number(field) {
  const parts = field.trim().replace(/^"(.*)"$/, "$1").split(".");
  if (parts.length !== 4 || parts.some(part => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((ip, part) => ip * 256 + Number(part), 0);
}

// Keep one organization per IPv4 ASN, not per IP range. The return value is
// the newly retained name length, so the streaming reader can bound memory.
export function addAsnName(names, line) {
  if (line.length > 4096) throw new Error("ASN CSV line too long");
  const first = line.indexOf(","), second = line.indexOf(",", first + 1), third = line.indexOf(",", second + 1);
  if (first < 0 || second < 0 || third < 0 || line.slice(0, first).includes(":")) return 0;
  const raw = line.slice(second + 1, third).trim().replace(/^"(.*)"$/, "$1");
  if (!/^\d{1,10}$/.test(raw)) return 0;
  const asn = Number(raw);
  if (asn > 0xffffffff || Object.hasOwn(names, asn)) return 0;
  const start = ipv4Number(line.slice(0, first)), end = ipv4Number(line.slice(first + 1, second));
  if (start === null || end === null || start > end) return 0;
  let name = line.slice(third + 1).trim();
  if (name.startsWith('"')) {
    const match = /^"((?:[^"]|"")*)"(?:\s*,.*|\s*)$/.exec(name);
    if (!match) return 0;
    name = match[1].replaceAll('""', '"').trim();
  } else {
    name = name.split(",", 1)[0].trim();
    if (name.includes('"')) return 0;
  }
  if (!name || name.length > 1024) return 0;
  names[asn] = name;
  return name.length;
}

export async function readAsnNames(body) {
  if (!body) throw new Error("ASN CSV stream unavailable");
  const reader = body.getReader(), decoder = new TextDecoder("utf-8", { fatal: true });
  const names = Object.create(null);
  let pending = "", total = 0, count = 0, chars = 0;
  function line(value) {
    const added = addAsnName(names, value);
    if (added) {
      count++; chars += added;
      if (count > 200000 || chars > 8 * 1024 * 1024) throw new Error("ASN names exceed browser cache limit");
    }
  }
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > 128 * 1024 * 1024) throw new Error("ASN CSV too large");
      pending += decoder.decode(value, { stream: true });
      let start = 0, end;
      while ((end = pending.indexOf("\n", start)) !== -1) { line(pending.slice(start, end)); start = end + 1; }
      pending = pending.slice(start);
      if (pending.length > 4096) throw new Error("ASN CSV line too long");
    }
    pending += decoder.decode();
    if (pending) line(pending);
    if (!count) throw new Error("No IPv4 ASN organization names in this CSV");
    return { names, count };
  } catch (error) {
    await reader.cancel().catch(() => {}); // Preserve the original decode/network error.
    throw error;
  } finally { reader.releaseLock(); }
}

export function selector(rule) {
  const names = { names: "Domains", countries: "Countries", ips: "IP ranges", asn: "ASN" };
  return `${names[rule.kind] ?? rule.kind}: ${rule.selector.replace(/^[^:]+:\s*/, "")}`;
}

export function localState(local) {
  return !local.enabled ? "Disabled" : local.ready ? "Ready" : "Unavailable";
}

// The MIMIC cell: the transport in use, the race that picked it (winner first)
// and the config restriction as a note — never the configured-only "Auto".
// A verdict that has not arrived yet is "Selecting…"; `path_timeout` is the
// one wire reason with a shorter dashboard spelling.
export function mimicCell(selection, configured = []) {
  const round = selection?.round ?? null;
  const text = entry => entry.status === "verified"
    ? `${entry.candidate} ${entry.rtt_ms} ms${entry.penalty ? " (+penalty)" : ""}`
    : entry.status === "failed"
      ? `${entry.candidate} ${entry.reason === "path_timeout" ? "timeout" : entry.reason}`
      : `${entry.candidate} ${entry.stage ?? ""}`.trimEnd();
  const entries = round?.winner
    ? [...round.entries].sort((a, b) => (b.candidate === round.winner) - (a.candidate === round.winner))
    : round?.entries ?? [];
  return {
    transport: selection?.active ?? "Selecting…",
    race: entries.map(text).join(" · "),
    limited: configured.length ? `limited: ${configured.join(" · ")}` : "",
  };
}

// The line a server speaks right now and how far it is: what a glance at the pool needs.
export function transport(server) {
  const active = server.selection?.active ?? "";
  const { rtt_ms } = server.selection?.round?.entries?.find(entry => entry.candidate === active) ?? {};
  return { active, latency: Number.isFinite(rtt_ms) ? rtt_ms : null };
}

// ── History kept on the client ──

// Ranges the server works out itself end now. Yesterday and Custom send
// their window instead: unix seconds at both ends, at most 30 days apart.
export const HISTORY_PRESETS = ["1h", "24h", "7d", "30d"];
// The shortest range is not history: five minutes measured in this tab.
export const LIVE_RANGE = "5m";
export const HISTORY_MAX_WINDOW = 30 * 86400;

// Yesterday of the browser's own calendar: from midnight to midnight, as
// long as that day really was (a clock change makes it 23 or 25 hours).
export function historyYesterday(now = Date.now()) {
  const today = new Date(now);
  today.setHours(0, 0, 0, 0);
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);
  return {
    from: Math.floor(yesterday.getTime() / 1000),
    to: Math.floor(today.getTime() / 1000),
  };
}

export function historyQuery({ range, kind, link = "", from = 0, to = 0 }, now = Date.now()) {
  const picked = range === "yesterday" ? historyYesterday(now) : { from, to };
  const window = HISTORY_PRESETS.includes(range) ? `range=${range}` : `from=${picked.from}&to=${picked.to}`;
  return `/api/history?${window}&kind=${kind}&top=8${link ? `&link=${encodeURIComponent(link)}` : ""}`;
}

// Whether a window is redrawn once a minute: only one that reaches "now".
export const historyLive = ({ range, from = 0, to = 0 }, now = Date.now()) =>
  HISTORY_PRESETS.includes(range) || (range === "custom" && to >= Math.floor(now / 1000) - 120);

// What may be asked of a custom window. Null when it may.
export function historyWindowError({ from, to }) {
  if (from == null || to == null) return "Pick both ends of the window";
  if (from >= to) return "The end comes after the start";
  if (to - from > HISTORY_MAX_WINDOW) return "A window is at most 30 days";
  return null;
}

// A datetime-local input takes local wall time in this exact shape, and
// gives a string the Date constructor reads as local wall time too.
export function historyInputValue(seconds) {
  const date = new Date(seconds * 1000), pad = value => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function historyInputSeconds(value) {
  const milliseconds = new Date(value).getTime();
  return value && Number.isFinite(milliseconds) ? Math.floor(milliseconds / 1000) : null;
}

// How wide one point of the answer is, in words.
export function historyStepLabel(step) {
  if (step % 86400 === 0) return step === 86400 ? "Every day" : `Every ${step / 86400} days`;
  if (step % 3600 === 0) return step === 3600 ? "Every hour" : `Every ${step / 3600} h`;
  return step === 60 ? "Every minute" : `Every ${step / 60} min`;
}

// One answer of /api/history as the chart draws it: a value per series and
// bucket, in bytes. A bucket without a single point is time nothing was
// recorded, a hole for every series; a series without a point in a recorded
// bucket carried nothing.
export function historyStack(answer, direction = "total") {
  const { from, to, step } = answer;
  const count = Math.max(0, Math.floor((to - from) / step));
  const bytes = point => direction === "rx" ? point[1] : direction === "tx" ? point[2] : point[1] + point[2];
  const series = answer.series.map(item => ({ ...item, values: new Array(count).fill(0) }));
  const recorded = new Array(count).fill(false);
  for (const item of series) {
    for (const point of item.points) {
      const index = Math.floor((point[0] - from) / step);
      if (index >= 0 && index < count) { item.values[index] = bytes(point); recorded[index] = true; }
    }
  }
  let peak = 0;
  for (let index = 0; index < count; index++) {
    if (recorded[index]) peak = Math.max(peak, series.reduce((sum, item) => sum + item.values[index], 0));
  }
  for (const item of series) item.values = item.values.map((value, index) => recorded[index] ? value : null);
  // Bytes of one bucket as Mbit/s.
  const rate = value => value * 8 / step / 1e6;
  const shown = item => direction === "rx" ? item.rx_bytes : direction === "tx" ? item.tx_bytes : item.rx_bytes + item.tx_bytes;
  // Every bucket sits in the middle of its slot and is held to the slot's edges.
  const width = 1000 / Math.max(count, 1);
  return {
    from, to, step, count, series, rate, peak: rate(peak), total: series.reduce((sum, item) => sum + shown(item), 0),
    xs: Array.from({ length: count }, (_, index) => width * (index + 0.5)), hold: width / 2,
  };
}

// The top of the value axis: a round number just above the busiest bucket,
// so the labels read as 0.5 or 2 and not as the traffic itself.
export function historyScale(peak) {
  const rough = Math.max(peak * 1.1, 0.01);
  const power = 10 ** Math.floor(Math.log10(rough));
  const top = [1, 2, 5, 10].find(step => step * power >= rough) * power;
  return { top, mid: top / 2 };
}

// The value axis in few words: 100 and 50, 0.5 and 0.25.
export const rateLabel = value => String(Number(value.toFixed(3)));

// The live window grows from its first ten seconds to the full five minutes,
// so the chart is never a mostly empty box while the tab is young.
export const LIVE_MIN_MS = 10 * 1000;

// The live window as the chart draws it: one smoothed sample per server and
// poll, in Mbit/s, every server on the clock of the whole window. A poll a
// server has no rate for is a hole. Servers are stacked largest first.
export function liveStack(history, direction = "total", serverId = "") {
  const end = history.at(-1)?.time ?? 0;
  const span = Math.min(WINDOW_MS, Math.max(end - (history[0]?.time ?? end - LIVE_MIN_MS), LIVE_MIN_MS));
  const ids = [...new Set(history.flatMap(point => Object.keys(point.servers ?? {})))];
  const shown = sample => sample.rx == null || sample.tx == null ? null
    : direction === "rx" ? sample.rx : direction === "tx" ? sample.tx : sample.rx + sample.tx;
  const xs = series(history).samples.map(sample => 1000 * (sample.time - end + span) / span);
  const size = values => values.reduce((sum, value) => sum + (value ?? 0), 0);
  const stacked = (serverId ? [serverId] : ids)
    .map(id => ({ key: id, values: series(history, id).samples.map(shown) }))
    .filter(item => item.values.some(value => value != null))
    .sort((a, b) => size(b.values) - size(a.values));
  let peak = 0;
  for (let index = 0; index < xs.length; index++) {
    peak = Math.max(peak, stacked.reduce((sum, item) => sum + (item.values[index] ?? 0), 0));
  }
  return { xs, hold: 0, from: end - span, to: end, span, series: stacked, peak: Math.max(0.01, peak), rate: value => value, latest: series(history, serverId).latest };
}

// Stacked bands on the chart's grid (1000 wide, 24..152 high), drawn as a
// sandwich. A layer's thickness is a curve through its samples and the
// boundary above it is the sum of the layers under it, so no layer turns
// negative between two of its own samples. The curve is monotone: between
// two samples it stays within their values, so jitter reads as flow and a
// dip stays where it happened. `hold` keeps the first and last sample of a
// run flat to the edges of their slots, as a stored minute is held to the
// edges of the minute; a live sample is a point on the clock. A run starts
// and ends vertically; a hole breaks it; a lone live sample is a tick.
export function stackPaths(stack, top) {
  const { xs, hold, rate = value => value } = stack;
  // Every stack in the unit being drawn.
  const series = stack.series.map(item => item.values.map(value => value == null ? null : rate(value)));
  const y = value => (152 - 128 * value / top).toFixed(2);
  const zero = [0, 0, 0, 0];
  const flat = value => [value, value, value, value];
  const ramp = (from, to) => [from, from + (to - from) / 3, to - (to - from) / 3, to];
  // Runs of neighbouring samples of a series: [first, one past the last].
  const runs = values => {
    const found = [];
    let start = -1;
    for (let index = 0; index <= values.length; index++) {
      const present = index < values.length && values[index] != null;
      if (present && start < 0) start = index;
      if (!present && start >= 0) { found.push([start, index]); start = -1; }
    }
    return found;
  };
  // Each series' curve over the clock: one segment per interval it has a sample at both ends of.
  // A held run meets its flat edges without a kink.
  const curves = series.map(values => {
    const parts = [];
    for (const [first, last] of runs(values)) {
      const at = xs.slice(first, last), run = values.slice(first, last);
      cubic(at, run, monotone(at, run, Boolean(hold))).forEach((segment, offset) => { parts[first + offset] = segment; });
    }
    return parts;
  });
  // What the next layer lies on, interval by interval: the curves under it,
  // each giving way to the baseline where it has no sample.
  let under = xs.slice(1).map(() => zero);
  return series.map((values, layer) => {
    const bands = [], crests = [];
    for (const [first, last] of runs(values)) {
      const at = xs.slice(first, last);
      const base = under.slice(first, Math.max(first, last - 1));
      // The top of the layer is its own curve over what lies under it.
      const lift = curves[layer].slice(first, Math.max(first, last - 1)).map((segment, i) => segment.map((value, k) => value + base[i][k]));
      if (hold) {
        const low = index => series.slice(0, layer).reduce((sum, lower) => sum + (lower[index] ?? 0), 0);
        const [start, end] = [low(first), low(last - 1)];
        at.unshift(at[0] - hold); at.push(at.at(-1) + hold);
        lift.unshift(flat(start + values[first])); base.unshift(flat(start));
        lift.push(flat(end + values[last - 1])); base.push(flat(end));
      }
      // A lone live sample has no width to fill: it is a tick as thick as its layer.
      if (at.length < 2) {
        const low = series.slice(0, layer).reduce((sum, lower) => sum + (lower[first] ?? 0), 0);
        crests.push(`M${at[0].toFixed(2)},${y(low)} L${at[0].toFixed(2)},${y(low + values[first])}`);
        continue;
      }
      const crest = `M${at[0].toFixed(2)},${y(lift[0][0])} ${band(at, lift, y)}`;
      crests.push(crest);
      bands.push(`${crest} L${at.at(-1).toFixed(2)},${y(base.at(-1)[3])} ${band(at, base, y, true)} Z`);
    }
    under = under.map((part, index) => {
      const from = values[index], to = values[index + 1];
      const added = from == null && to == null ? zero : from == null ? ramp(0, to) : to == null ? ramp(from, 0) : curves[layer][index];
      return part.map((value, k) => value + added[k]);
    });
    return { band: bands.join(" "), crest: crests.join(" ") };
  });
}

// The sample a moment of the window falls in: the bucket that holds it, or
// the live sample nearest to it. Null off the window or where nothing is near.
export function stackIndex(stack, time) {
  if (!stack.xs.length || time < stack.from || time > stack.to) return null;
  if (stack.step) return Math.min(stack.xs.length - 1, Math.floor((time - stack.from) / stack.step));
  const at = 1000 * (time - stack.from) / stack.span;
  let best = null, distance = 5000 * 1000 / stack.span;
  for (const [index, x] of stack.xs.entries()) {
    const gap = Math.abs(x - at);
    if (gap <= distance) { distance = gap; best = index; }
  }
  return best;
}

// How long ago a live mark is: to the second under a minute, whole minutes in
// words, anything else as minutes and seconds.
const ago = ms => {
  const seconds = Math.round(ms / 1000);
  return !seconds ? "now" : seconds % 60 === 0 ? `−${seconds / 60} min` : seconds < 60 ? `−${seconds} s`
    : `−${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
};

// Five labels of the time axis. The live window counts back from now over as
// much as it holds; a stored one is a calendar.
export function stackMarks(stack) {
  if (!stack.step) return [1, 0.75, 0.5, 0.25, 0].map(part => ago(part * stack.span));
  const span = stack.to - stack.from;
  return historyMarks(stack.from, stack.to).map(seconds => historyTime(seconds, span));
}

// The moment under the pointer, in words: to the minute for a day, to the
// hour for a week, to the second for the live window.
export function stackTime(stack, time) {
  const date = new Date(stack.step ? time * 1000 : time);
  const span = stack.step ? stack.to - stack.from : 0;
  const day = date.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short" });
  if (span > 7 * 86400) return date.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
  if (span > 86400) return `${day}, ${date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}`;
  return date.toLocaleTimeString("en-GB", stack.step ? { hour: "2-digit", minute: "2-digit" } : { hour12: false });
}

// One cubic segment per pair of neighbouring samples, in value space.
function cubic(xs, values, tangents) {
  return xs.slice(1).map((x, i) => {
    const third = (x - xs[i]) / 3;
    return [values[i], values[i] + tangents[i] * third, values[i + 1] - tangents[i + 1] * third, values[i + 1]];
  });
}

// Slopes of a curve through the samples that never overshoots them
// (Fritsch and Carlson): a sample between a rise and a fall is a summit.
function monotone(xs, values, held = false) {
  const last = values.length - 1;
  const slopes = xs.slice(1).map((x, i) => (values[i + 1] - values[i]) / (x - xs[i]));
  const tangents = values.map(() => 0);
  // A held run leaves and arrives its end samples flat; a live run keeps its slope.
  tangents[0] = held ? 0 : slopes[0];
  tangents[last] = held ? 0 : slopes.at(-1);
  for (let i = 1; i < last; i++) {
    if (slopes[i - 1] * slopes[i] > 0) tangents[i] = (slopes[i - 1] + slopes[i]) / 2;
  }
  for (let i = 0; i < last; i++) {
    if (slopes[i] === 0) {
      tangents[i] = 0;
      tangents[i + 1] = 0;
      continue;
    }
    const a = tangents[i] / slopes[i], b = tangents[i + 1] / slopes[i];
    const norm = a * a + b * b;
    if (norm > 9) {
      const scale = 3 / Math.sqrt(norm);
      tangents[i] = scale * a * slopes[i];
      tangents[i + 1] = scale * b * slopes[i];
    }
  }
  return tangents;
}

// The SVG curve of `segments` from left to right, or, when `backwards`,
// from the right end back to the start: the same segments in reverse order.
function band(xs, segments, y, backwards = false) {
  const parts = segments.map((segment, i) => {
    const left = xs[i], right = xs[i + 1], third = (right - left) / 3;
    const near = (left + third).toFixed(2), far = (right - third).toFixed(2);
    return backwards
      ? `C${far},${y(segment[2])} ${near},${y(segment[1])} ${left.toFixed(2)},${y(segment[0])}`
      : `C${near},${y(segment[1])} ${far},${y(segment[2])} ${right.toFixed(2)},${y(segment[3])}`;
  });
  if (backwards) parts.reverse();
  return parts.join(" ");
}

// Five marks of the time axis: both ends and the quarters between.
export const historyMarks = (from, to) => [0, 0.25, 0.5, 0.75, 1].map(part => from + (to - from) * part);

// The coarser the range, the coarser the label: a clock for a day, the day
// of the week with its date for a week (the same weekday comes twice there),
// the date for a month.
export function historyTime(seconds, span) {
  const date = new Date(seconds * 1000);
  if (span > 7 * 86400) return date.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
  if (span > 86400) return date.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short" });
  return date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}

// What a series is called. A rule goes by its label and a network by its
// ASN; the exit is kept apart as a second line where more than one exists.
export function historyName(item, servers = [], rules = [], names = {}) {
  const server = servers.find(server => server.id === item.link);
  const via = item.link === "" || item.link === "local" ? "Local" : server?.label || server?.server || item.link;
  if (item.kind === "local") return { label: "Local exit", via: "" };
  if (item.kind === "link") return { label: via, via: "" };
  if (item.kind === "rule") {
    const rule = rules.find(rule => rule.canonical === item.rule);
    return { label: rule?.label ?? (item.rule === "fallback" ? "Fallback" : item.rule), via };
  }
  // The server names the network from its own ASN CSV; the browser's copy is the fallback.
  return { label: asnLabel(item.asn, item.asn_name ? { [item.asn]: item.asn_name } : names), via };
}
