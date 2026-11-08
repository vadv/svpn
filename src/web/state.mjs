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
  return { time: current.generated_at_ms, servers, rx: total("rx"), tx: total("tx"), drops: total("drops"), failed: total("failed") };
}

export function keepHistory(history, point) {
  // Even a faulty future-dated or high-frequency source cannot grow history without a bound.
  return [...history.filter(item => item.time > point.time - WINDOW_MS && item.time < point.time), point].slice(-301);
}

export function graph(history, serverId = "") {
  const samples = history.map(point => ({ time: point.time, ...(serverId ? point.servers[serverId] ?? { rx: null, tx: null } : point) }));
  const max = Math.max(0.01, ...samples.flatMap(sample => [sample.rx ?? 0, sample.tx ?? 0])) * 1.1;
  const end = history.at(-1)?.time ?? 0;
  const path = field => {
    let connected = false;
    return samples.map(sample => {
      const value = sample[field];
      if (value == null) { connected = false; return ""; }
      const x = 1000 * (sample.time - end + WINDOW_MS) / WINDOW_MS;
      const y = 152 - 128 * value / max;
      const position = `${x.toFixed(2)},${y.toFixed(2)}`;
      // Round caps make a zero-length first segment visible without inventing history.
      const segment = connected ? `L${position}` : `M${position} l0,0`;
      connected = true;
      return segment;
    }).join(" ");
  };
  return { rx: path("rx"), tx: path("tx"), max, latest: samples.at(-1) };
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
