// Pure dashboard calculations: no timers, DOM or persistent storage.
export const WINDOW_MS = 5 * 60 * 1000;
export const STALE_MS = 5000;
export const PAGE_SIZE = 50;

export function bytes(value) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

export const rate = value => value == null ? "—" : value.toFixed(2);

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
  return [...history.filter(item => item.time > point.time - WINDOW_MS && item.time < point.time), point].slice(-301);
}

// One sample vocabulary for the chart, its filled areas, sparklines and the hover readout.
function series(history, serverId = "") {
  const samples = history.map(point => ({
    time: point.time,
    ...(serverId ? point.servers?.[serverId] ?? { rx: null, tx: null } : point),
  }));
  const max = Math.max(0.01, ...samples.flatMap(sample => [sample.rx ?? 0, sample.tx ?? 0])) * 1.1;
  const end = history.at(-1)?.time ?? 0;
  return { samples, max, end };
}

const chartX = (time, end) => 1000 * (time - end + WINDOW_MS) / WINDOW_MS;
const chartY = (value, max) => 152 - 128 * value / max;

export function graph(history, serverId = "") {
  const { samples, max, end } = series(history, serverId);
  const path = field => {
    let connected = false;
    return samples.map(sample => {
      const value = sample[field];
      if (value == null) { connected = false; return ""; }
      const position = `${chartX(sample.time, end).toFixed(2)},${chartY(value, max).toFixed(2)}`;
      // Round caps make a zero-length first segment visible without inventing history.
      const segment = connected ? `L${position}` : `M${position} l0,0`;
      connected = true;
      return segment;
    }).join(" ");
  };
  return { rx: path("rx"), tx: path("tx"), max, latest: samples.at(-1) };
}

// Closed polygons under the lines. A missing interval starts a new polygon
// instead of painting a fake value across the gap.
export function areas(history, serverId = "") {
  const { samples, max, end } = series(history, serverId);
  const area = field => {
    const segments = [];
    let run = [];
    const flush = () => {
      if (!run.length) return;
      const first = run[0], last = run.at(-1);
      const start = `M${chartX(first.time, end).toFixed(2)},152`;
      const ridge = run.map(sample => `L${chartX(sample.time, end).toFixed(2)},${chartY(sample[field], max).toFixed(2)}`).join(" ");
      segments.push(`${start} ${ridge} L${chartX(last.time, end).toFixed(2)},152 Z`);
      run = [];
    };
    for (const sample of samples) {
      if (sample[field] == null) { flush(); continue; }
      run.push(sample);
    }
    flush();
    return segments.join(" ");
  };
  return { rx: area("rx"), tx: area("tx") };
}

// A compact trend for the summary cells: last 40 samples, its own scale.
export function spark(history, field, serverId = "") {
  const { samples } = series(history, serverId);
  const recent = samples.slice(-40);
  const max = Math.max(0.01, ...recent.map(sample => sample[field] ?? 0));
  const count = recent.length;
  let connected = false;
  return recent.map((sample, index) => {
    const value = sample[field];
    if (value == null) { connected = false; return ""; }
    const x = count === 1 ? 120 : 120 * index / (count - 1);
    const position = `${x.toFixed(2)},${(28 - 24 * value / max).toFixed(2)}`;
    const segment = connected ? `L${position}` : `M${position} l0,0`;
    connected = true;
    return segment;
  }).join(" ");
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

export function nearestSample(history, time, serverId = "") {
  const { samples } = series(history, serverId);
  let best = null, distance = Infinity;
  for (const sample of samples) {
    const delta = Math.abs(sample.time - time);
    if (delta < distance) { distance = delta; best = sample; }
  }
  return best && { time: best.time, rx: best.rx ?? null, tx: best.tx ?? null };
}

export function flowPage(flows, { query = "", protocol = "", via = "", page = 0 } = {}) {
  const needle = query.trim().toLowerCase();
  const filtered = flows.filter(flow => (!protocol || flow.protocol === protocol) && (!via || flow.via === via) &&
    (!needle || `${flow.source} ${flow.destination}`.toLowerCase().includes(needle)));
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  page = Math.max(0, Math.min(page, pages - 1));
  return { rows: filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), count: filtered.length, total: flows.length, page, pages };
}

export function selector(rule) {
  const names = { names: "Domains", countries: "Countries", ips: "IP ranges", asn: "ASN" };
  return `${names[rule.kind] ?? rule.kind}: ${rule.selector.replace(/^[^:]+:\s*/, "")}`;
}

export function localState(local) {
  return !local.enabled ? "Disabled" : local.ready ? "Ready" : "Unavailable";
}
