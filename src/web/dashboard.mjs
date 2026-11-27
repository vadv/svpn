import { STALE_MS, PAGE_SIZE, bytes, rate, flowCounts, measure, keepHistory, spark, sparkArea, sparkScaled, latestSample, liveStack, stackPaths, stackIndex, stackMarks, stackTime, rateLabel, processRss, uptimeSeconds, duration, flowPage, flowSource, flowService, flowAge, withFlowRates, asnLabel, asnOwners, pinnedGroups, flag, readAsnNames, selector, localState, cpuAverage, trafficAverage, mimicCell, transport, usageRanking, LIVE_RANGE, historyQuery, historyStack, historyLive, historyWindowError, historyInputValue, historyInputSeconds, historyStepLabel, historyScale, historyMarks, historyTime, historyName } from "/state.mjs";

const $ = id => document.getElementById(id);
const endpoint = document.querySelector("main").dataset.endpoint;
let latest = null, point = null, history = [], lastChange = 0, apiError = false;
let frozen = null, page = 0, flowSignature = "";
const serverRows = new Map();
let period = "session", drill = null, usageFrame, usageStale;
// What the chart is asked for and the last answer read from the client's database.
// The shortest range is measured in this tab and needs no answer.
const past = { range: "24h", custom: null, kind: "link", link: "", direction: "total", data: null, version: 0, fetched: -Infinity, error: "", invalid: "", loading: false, request: null, asked: "", live: true };
const SVG = "http://www.w3.org/2000/svg";
const filters = ["flow-search", "flow-protocol", "flow-exit", "flow-country", "flow-asn"];
const expandedRanks = new Set();
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

// What a state is: well, trouble brewing, or failed. Anything else is neutral.
const TONES = { good: ["ready", "ok"], bad: ["failed", "timeout", "reload_failed", "missing"], warn: ["checking", "connecting", "backoff", "running", "previous"] };
const tone = state => Object.keys(TONES).find(severity => TONES[severity].includes(state)) ?? "";

function badge(state, label = state) {
  // "reload_failed" reads as words; the raw enum value never reaches the page.
  const text = label === "ok" ? "OK" : label.replaceAll("_", " ").replace(/^./, letter => letter.toUpperCase());
  return node("span", text, `pill ${tone(state)}`);
}

function cell(value, numeric = false) {
  const td = node("td", "", numeric ? "num" : "");
  td.append(value instanceof Node ? value : document.createTextNode(String(value ?? "—")));
  return td;
}

// A bar under a number saying how big a share it is; `className` names its colour.
function withBar(td, percent, className) {
  if (percent == null) return td;
  const track = node("i", "", `share ${className}`), fill = node("b", "", "");
  fill.style.width = `${Math.max(percent, 1.2).toFixed(1)}%`;
  track.append(fill);
  td.append(track);
  return td;
}

// The colour of a series, wherever it is named: the same from the chart to a table row.
const tintOf = id => {
  const tint = shades.get(id === "local" ? "" : id);
  return tint ? `cat-${tint}` : "";
};

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
  $("proc-rss-kind").textContent = memory.bytes == null ? "No sample" : memory.peak ? "Peak RSS · not live" : "Current RSS";
  $("proc-cpu").textContent = average ? `${average.percent.toFixed(1)}%` : "—";
  $("proc-cpu-kind").textContent = average ? `1 core · ${Math.round(average.seconds)}s average` : "Waiting for samples";
  $("proc-time").textContent = cpuTime == null ? "—" : `${cpuTime.toFixed(2)} s`;
  $("proc-time-note").textContent = cpus ? `${cpus} logical CPUs` : "User + system";
  const peak = Number.isFinite(process?.peak_rss_bytes) && process.peak_rss_bytes > 0 ? process.peak_rss_bytes : null;
  $("proc-note").textContent = memory.peak ? "Peak RSS · not live RSS" : peak ? "Meter against peak RSS" : "No peak RSS";
  setMeter("proc-mem-bar", peak == null || memory.bytes == null ? null : memory.bytes / peak * 100);
  setMeter("proc-cpu-bar", average?.percent ?? null);
  $("spark-rss").setAttribute("d", sparkScaled(history, "rss"));
  $("spark-cpu").setAttribute("d", spark(history, "cpu"));
}

const rankAxes = ["exits", "networks", "destinations"];

function rankList(axis, ranking, format, empty) {
  const list = $(`rank-${axis}`), more = list.nextElementSibling;
  const { rows, total } = ranking;
  more.hidden = rows.length <= 4;
  more.textContent = expandedRanks.has(axis) ? "Show top 4" : `Show all ${rows.length}`;
  more.setAttribute("aria-expanded", String(expandedRanks.has(axis)));
  const visible = expandedRanks.has(axis) ? rows : rows.slice(0, 4);
  const existing = new Map([...list.children].map(li => [li.dataset.key, li]));
  for (const [i, row] of visible.entries()) {
    const key = row.key ?? "", share = row.value / total * 100;
    let li = existing.get(key);
    if (!li) {
      li = node("li"); li.dataset.key = key;
      const line = node("div", "", "rank-line"), meter = node("div", "", "rank-meter");
      const label = node(key ? "button" : "span");
      if (key) label.addEventListener("click", () => inspectFlows(axis, key, label.textContent));
      line.append(label, node("small")); meter.append(node("i")); li.append(line, meter);
    }
    // A bar takes the colour of the exit it belongs to: an exit's own series, a network's the one it is pinned to.
    li.className = tintOf(axis === "exits" ? key : row.via);
    const [line, meter] = li.children;
    line.firstChild.textContent = row.label;
    line.firstChild.title = key ? `Inspect current flows: ${row.label}` : "Bytes pooled when the named-bucket limit was reached";
    line.lastChild.textContent = `${format(row.value)} · ${share < 1 ? "<1" : Math.round(share)}%${row.via != null ? ` · ${name(row.via)}` : ""}`;
    meter.firstChild.style.width = `${share}%`;
    if (list.children[i] !== li) list.insertBefore(li, list.children[i] ?? null);
    existing.delete(key);
  }
  for (const li of existing.values()) li.remove();
  if (!visible.length) list.replaceChildren(node("li", empty, "muted"));
}

function renderUsage(stale) {
  const sample = latest?.usage, now = period === "interval";
  const direction = $("usage-direction").value;
  const data = sample?.[period];
  const available = data && (!now || (!stale && point && sample.seconds > 0));
  const format = n => now ? `${rate(n * 8 / sample.seconds / 1e6)} Mbit/s` : bytes(n);
  const groups = { exits: [], networks: [], destinations: [] };
  if (available) {
    for (const server of latest.servers) {
      const traffic = data.exits[server.index];
      if (traffic) groups.exits.push([server.id, name(server.id), traffic]);
    }
    groups.exits.push(["local", "Local exit", data.local]);
    for (const axis of ["networks", "destinations"]) {
      // A network row names the exit its ASN group is pinned to.
      const owners = asnOwners(latest.groups);
      groups[axis] = Object.entries(data[axis].named).map(([key, t]) => [key, axis === "networks" ? asnLabel(key, asnNames) : key, t, axis === "networks" ? owners.get(key) ?? null : null]);
      groups[axis].push([null, "Other · pooled", data[axis].other]);
    }
    groups.networks.push(["unknown", "Unknown ASN", data.unknown_asn]);
  }
  const rx = groups.exits.reduce((s, [, , t]) => s + t.rx_bytes, 0);
  const tx = groups.exits.reduce((s, [, , t]) => s + t.tx_bytes, 0);
  const empty = !latest ? "Waiting for snapshot" : !sample ? "Accounting unavailable" : !available ? stale ? "Snapshot is stale" : "Measuring first interval…" : "No traffic in this view";
  const window = now ? available ? `Last ${sample.seconds.toFixed(1)} s` : "Latest measurement interval" : stale && latest ? "Since start · last snapshot" : "Since client start";
  $("usage-period").textContent = `${direction === "rx" ? "Received" : direction === "tx" ? "Sent" : "Total traffic"} · ${window}`;
  $("usage-split").textContent = available ? `↓ ${format(rx)} received · ↑ ${format(tx)} sent` : empty;
  for (const axis of rankAxes) {
    const ranking = usageRanking(groups[axis], direction);
    if (axis === "exits") $("usage-total").textContent = available ? format(ranking.total) : "—";
    rankList(axis, ranking, format, empty);
  }
  for (const id of ["usage-session", "usage-now", "usage-direction"]) $(id).disabled = !sample;
  $("usage-session").setAttribute("aria-pressed", String(!now));
  $("usage-now").setAttribute("aria-pressed", String(now));
  usageFrame = latest; usageStale = stale;
}

function inspectFlows(axis, key, label) {
  drill = { axis, key }; frozen = null; page = 0;
  for (const id of filters) $(id).value = "";
  $("flow-order").value = period === "session" ? "total" : "rate";
  $("drill-label").textContent = `Current flows · ${label} (completed flows are not listed)`;
  $("drill-note").hidden = false;
  renderFlows(); $("clear-drill").focus();
}

function freshness() {
  const stale = isStale();
  // Yesterday and a custom window that ended in the past do not change: only a window reaching now is redrawn.
  if (past.live && !document.hidden && chartVisible() && latest?.history?.enabled && performance.now() - past.fetched >= 60000) void loadHistory();
  if (usageFrame !== latest || usageStale !== stale) renderUsage(stale);
  document.body.classList.toggle("stale", stale && Boolean(latest));
  $("stale-notice").hidden = !latest || !stale;
  $("freshness").className = `pill ${!latest ? (apiError ? "bad" : "") : stale ? "warn" : "good"}`;
  $("freshness").textContent = !latest ? (apiError ? "API unavailable" : "Connecting…") : stale ? "Stale data" : "Live";
  if (latest) {
    const age = Math.max(0, Math.floor((performance.now() - lastChange) / 1000));
    $("meta").textContent = `Updated ${age}s ago · ${new Date(latest.generated_at_ms).toLocaleTimeString()} · ${latest.policy}`;
  } else if (apiError) $("meta").textContent = "Retrying /api/state";
  // Same smoothed value the chart draws; `point` gates it so a duplicate or failed poll shows —.
  const total = point ? latestSample(history) : null;
  $("rx").textContent = stale ? "—" : rate(total?.rx);
  $("tx").textContent = stale ? "—" : rate(total?.tx);
  // The two trends of the summary, the whole pool over the same window as the chart.
  $("spark-rx").setAttribute("d", stale ? "" : spark(history, "rx"));
  $("spark-tx").setAttribute("d", stale ? "" : spark(history, "tx"));
  $("spark-rx-area").setAttribute("d", stale ? "" : sparkArea(history, "rx"));
  $("spark-tx-area").setAttribute("d", stale ? "" : sparkArea(history, "tx"));
  // The note sets each number against the whole window.
  const average = trafficAverage(history);
  $("rx-note").textContent = average ? `VPN links · avg ${rate(average.rx)}` : "VPN links";
  $("tx-note").textContent = average ? `VPN links · avg ${rate(average.tx)}` : "VPN links";
  for (const row of serverRows.values()) {
    const server = point ? latestSample(history, row.id) : null;
    // Second line: the whole-history average, so a burst or a lull reads against the norm.
    const average = trafficAverage(history, row.id);
    const note = average ? `avg ${Math.round(average.seconds)}s` : "avg —";
    row.rx.replaceChildren(node("div", stale ? "—" : rate(server?.rx)), node("small", average ? `${note} ${rate(average.rx)}` : note));
    row.tx.replaceChildren(node("div", stale ? "—" : rate(server?.tx)), node("small", average ? `${note} ${rate(average.tx)}` : note));
  }
  if (stale) {
    $("recent-errors").textContent = latest ? "—" : "No snapshot";
    $("proc-rss").textContent = "—";
    $("proc-cpu").textContent = "—";
    $("proc-cpu-kind").textContent = "No sample";
    $("proc-rss-kind").textContent = latest ? "Hidden while stale" : "No sample";
    setMeter("proc-mem-bar", null);
    setMeter("proc-cpu-bar", null);
    $("spark-rss").setAttribute("d", "");
    $("spark-cpu").setAttribute("d", "");
  }
  renderChart();
}

// The range on screen. Until the client says it keeps history there is nothing to
// show but the five minutes measured in this tab.
function chartRange() {
  return latest?.history?.enabled || past.range === LIVE_RANGE ? past.range : LIVE_RANGE;
}

// The chart is read from the client's database when its panel is in view,
// and no more often than the minutes it is made of.
function chartVisible() {
  const rect = $("traffic").getBoundingClientRect();
  return rect.bottom > 0 && rect.top < innerHeight;
}

// What is asked for. Yesterday and Custom carry their own window; the other
// ranges leave it to the server.
function chartAsk() {
  return { range: chartRange(), kind: past.kind, link: past.link, from: past.custom?.from, to: past.custom?.to };
}

function askChart() {
  past.invalid = "";
  // What was on screen stays until the answer is there: no blank chart in between.
  past.error = ""; past.fetched = -Infinity;
  past.live = historyLive(chartAsk());
  renderChart(true);
  void loadHistory();
}

function chooseRange(range) {
  // The live window has no rates for the local exit.
  if (range === LIVE_RANGE && past.link === "local") past.link = "";
  past.range = range;
  // Custom opens on the window it last showed, or on the last day.
  if (range === "custom" && !past.custom) {
    const now = Math.floor(Date.now() / 60000) * 60;
    past.custom = { from: now - 86400, to: now };
  }
  if (range === "custom") {
    $("chart-from").value = historyInputValue(past.custom.from);
    $("chart-to").value = historyInputValue(past.custom.to);
  }
  askChart();
}

function applyChartWindow() {
  const custom = {
    from: historyInputSeconds($("chart-from").value),
    to: historyInputSeconds($("chart-to").value),
  };
  past.invalid = historyWindowError(custom) ?? "";
  if (past.invalid) {
    renderChart();
    return;
  }
  past.custom = custom;
  askChart();
}

async function loadHistory() {
  // The live window is measured here: nothing to read.
  if (chartRange() === LIVE_RANGE || !latest?.history?.enabled) return;
  const asked = historyQuery(chartAsk());
  // A request already out is left to finish unless it answers another question.
  if (past.loading && past.asked === asked) return;
  past.request?.abort();
  past.asked = asked;
  const request = new AbortController();
  past.request = request; past.loading = true;
  try {
    const response = await fetch(asked, { cache: "no-store", signal: AbortSignal.any([request.signal, AbortSignal.timeout(5000)]) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (past.request !== request) return;
    if (!Array.isArray(data.series) || !Number.isFinite(data.step)) throw new Error("Invalid history");
    past.data = data; past.version++; past.error = ""; past.fetched = performance.now();
  } catch (error) {
    if (past.request !== request || request.signal.aborted) return;
    past.error = error.message;
  } finally {
    if (past.request === request) { past.loading = false; renderChart(); }
  }
}

// What a series is across ranges and breakdowns, so the same server is the same
// colour at five minutes and at a month.
const seriesKey = item => item.rule != null ? `${item.rule} via ${item.link}` : item.asn != null ? `${item.asn} via ${item.link}` : item.link ?? item.key;

// A series keeps its colour from one range to the next while it can: the busiest
// take their own first, in the order they come; the rest get the first one free.
const shades = new Map();

function shade(keys) {
  const used = new Set();
  const taken = keys.map(key => {
    const own = shades.get(key);
    if (own == null || used.has(own)) return null;
    used.add(own);
    return own;
  });
  let next = 0;
  keys.forEach((key, index) => {
    if (taken[index] != null) return;
    while (used.has(next % 8 + 1)) next++;
    taken[index] = next++ % 8 + 1;
    shades.set(key, taken[index]);
    used.add(taken[index]);
  });
  return taken;
}

// Everything on the chart follows from what is asked and from the last answer. It
// is redrawn when either changes: on every poll for the five minutes measured here,
// otherwise only once a new answer is in.
let drawn = "", shown = null, pointer = null;

function renderChart(fresh = false) {
  const range = chartRange(), live = range === LIVE_RANGE;
  const status = latest?.history ?? { enabled: false, state: "", error: "" };
  const signature = JSON.stringify([range, live && latest?.generated_at_ms, live && isStale(), Boolean(latest), status, past.kind, past.link, past.direction, past.version, past.error, past.invalid, asnCount]);
  if (signature === drawn) return;
  drawn = signature;
  if (fresh) { const chart = $("traffic").querySelector(".chart"); chart.classList.remove("fresh"); void chart.offsetWidth; chart.classList.add("fresh"); }

  for (const button of $("chart-ranges").querySelectorAll("[data-range]")) {
    button.disabled = button.dataset.range !== LIVE_RANGE && !status.enabled;
    button.setAttribute("aria-pressed", String(button.dataset.range === range));
  }
  // The live window is one breakdown, by server, and has no store to list.
  const usable = Boolean(latest) && (live || status.enabled);
  for (const id of ["chart-server", "chart-direction"]) $(id).disabled = !usable;
  // What only a stored range can ask for waits for the store.
  for (const id of ["chart-kind", "chart-from", "chart-to", "chart-apply"]) $(id).disabled = !status.enabled;
  $("chart-by").hidden = live; $("chart-table").hidden = live;
  // The inputs keep what was typed into them: they are filled when Custom opens and after Apply.
  $("chart-custom").hidden = range !== "custom";
  if (latest) {
    $("chart-kind").value = past.kind; $("chart-direction").value = past.direction;
    options($("chart-server"), [["", "All servers"], ...latest.servers.map(server => [server.id, name(server.id)]),
      ...(live || !latest.local.enabled ? [] : [["local", "Local"]])]);
    $("chart-server").value = past.link;
    // A server that is gone is no longer a filter.
    if ($("chart-server").value !== past.link) past.link = "";
  }
  // One sentence says why there is nothing to read; an error of the database is the loud case.
  const trouble = latest && status.enabled && (status.state === "error" || past.error);
  const note = range === "custom" && past.invalid ? past.invalid
    : !latest ? "" : !status.enabled ? "History is off. Add a stats block to the client config to keep it."
    : status.state === "checking" ? "Opening the history database…"
    : status.state === "error" ? `History is not being recorded: ${status.error}`
    : past.error ? `History unavailable: ${past.error}` : "";
  $("chart-note").textContent = note;
  $("chart-note").className = `chart-note${trouble ? " bad" : ""}`;
  $("chart-note").hidden = !note;
  drawChart(live, live ? (history.length ? liveStack(history, past.direction, past.link) : null)
    : past.data && latest ? historyStack(past.data, past.direction) : null);
}

// A stack on the chart: its layers, chips, totals and, for a stored range, its table.
function drawChart(live, stack) {
  const recorded = item => item.values.some(value => value != null);
  const carried = item => past.direction === "rx" ? item.rx_bytes : past.direction === "tx" ? item.tx_bytes : item.rx_bytes + item.tx_bytes;
  const quote = value => value == null ? "—" : live ? rate(value) : bytes(value);
  const axis = $("chart-axis").children;
  const parts = [], chips = [], rows = [];
  // The topmost layer drawn so far: what the eye follows along the stack.
  let summit = null;
  shown = null;
  if (stack?.series.some(recorded)) {
    const { top, mid } = historyScale(stack.peak);
    const paths = stackPaths(stack, top);
    const labels = stack.series.map(item => live ? { label: name(item.key), via: "" } : historyName(item, latest.servers, latest.rules, asnNames));
    const tints = shade(stack.series.map(seriesKey));
    stackMarks(stack).forEach((mark, index) => { axis[index].textContent = mark; });
    $("chart-max").textContent = `${rateLabel(top)} Mbit/s`;
    $("chart-mid").textContent = rateLabel(mid);
    stack.series.forEach((item, index) => {
      const tint = `cat-${tints[index]}`, { label, via } = labels[index];
      // A series nobody recorded in this window is not drawn, only listed.
      if (recorded(item)) {
        // createElement would make an HTML element, which SVG never draws.
        const band = document.createElementNS(SVG, "path");
        band.setAttribute("class", `band ${tint}`);
        band.setAttribute("d", paths[index].band);
        // The hairline along the top of the band: a thin layer stays visible on a thick one.
        const crest = document.createElementNS(SVG, "path");
        crest.setAttribute("class", `crest ${tint}`);
        crest.setAttribute("d", paths[index].crest);
        parts.push(band, crest);
        summit = { line: paths[index].crest, tint };
        const chip = node("span", "", `legend-item series ${tint}`);
        chip.append(node("i", "", ""), node("span", label), node("small", quote(live ? item.values.at(-1) : carried(item))));
        chips.push(chip);
      }
      if (!live) {
        // The row's first cell carries the colour of its layer, as the chip does.
        const first = cell(via && past.kind !== "link" ? title(label, `via ${via}`) : label);
        first.prepend(node("i", "", `dot ${tint}`));
        rows.push([
          first,
          cell(bytes(item.rx_bytes), true), cell(bytes(item.tx_bytes), true), cell(bytes(item.rx_bytes + item.tx_bytes), true),
          withBar(cell(stack.total ? `${(carried(item) / stack.total * 100).toFixed(1)}%` : "—", true), stack.total ? carried(item) / stack.total * 100 : null, tint),
          cell(item.active_avg.toFixed(1), true),
        ]);
      }
    });
    if (summit) {
      // The top of the stack glows: the same line, blurred.
      const halo = document.createElementNS(SVG, "path");
      halo.setAttribute("class", `halo ${summit.tint}`);
      halo.setAttribute("d", summit.line);
      parts.push(halo);
    }
    shown = { stack, labels: labels.map((label, index) => ({ label: label.label, tint: tints[index] })) };
  } else {
    for (const mark of axis) mark.textContent = "—";
    $("chart-max").textContent = "Mbit/s"; $("chart-mid").textContent = "";
  }
  // What the range adds up to; the live window quotes its newest sample, and nothing while stale.
  const stale = live && (isStale() || !point);
  const sum = field => stack?.series.reduce((total, item) => total + item[field], 0);
  const [down, up, unit] = $("chart-total").children;
  down.textContent = `↓ ${stale ? "—" : quote(live ? stack?.latest?.rx : sum("rx_bytes"))}`;
  up.textContent = `↑ ${stale ? "—" : quote(live ? stack?.latest?.tx : sum("tx_bytes"))}`;
  unit.textContent = live ? "Mbit/s" : "";
  // How wide a point is; for the live window, how much of it is measured.
  const collected = history.length ? Math.floor((history.at(-1).time - history[0].time) / 1000) : 0;
  $("chart-resolution").textContent = !stack ? "" : live
    ? isStale() ? (latest ? "Last snapshot" : "Waiting…") : collected < 30 ? `${collected}s collected` : "Every second"
    : historyStepLabel(stack.step);
  const empty = $("chart-empty");
  if (stack) {
    empty.hidden = stack.series.some(recorded);
    empty.textContent = live ? "collecting samples…" : "Nothing recorded in this range";
  } else {
    empty.hidden = !live && (!latest?.history?.enabled || Boolean(past.error || latest?.history?.error));
    empty.textContent = live || !latest ? "Waiting for the client…" : "No history yet";
  }
  $("chart-bands").replaceChildren(...parts);
  $("chart-legend").replaceChildren(...chips);
  // The newest live sample is a point of light on the top of the stack, at the right edge.
  const pulse = $("chart-pulse");
  pulse.hidden = !live || stale || !summit;
  if (!pulse.hidden) {
    // The line ends at the newest sample: its last pair is the point, in the plot's own units.
    const y = Number(summit.line.match(/,[0-9.]+(?=\s|$)/g).at(-1).slice(1));
    pulse.className = `chart-pulse ${summit.tint}`;
    pulse.style.top = `${(y - 20) / 140 * $("chart-plot").querySelector("svg").clientHeight + 1}px`;
  }
  if (!live) table("history", rows, 6, latest?.history?.enabled ? "Nothing recorded in this range" : "No snapshot yet");
  drawCursor();
}

function hideCursor() { $("chart-tooltip").hidden = true; $("chart-cursor").hidden = true; }

// What the chart carries at the moment under the pointer, series by series.
function drawCursor() {
  const tooltip = $("chart-tooltip"), plot = $("chart-plot");
  if (!pointer || !shown || !plot.clientWidth) return hideCursor();
  const { stack, labels } = shown;
  const time = stack.from + pointer * (stack.step ? stack.to - stack.from : stack.span);
  const index = stackIndex(stack, time);
  const layers = index == null ? [] : stack.series
    .map((item, i) => ({ ...labels[i], value: item.values[index] == null ? null : stack.rate(item.values[index]) }))
    .filter(item => item.value != null).sort((a, b) => b.value - a.value);
  if (!layers.length) return hideCursor();
  const line = (label, value, className = "") => {
    const row = node("div", "", className);
    row.append(node("i", "", ""), node("span", label), node("b", `${rate(value)} Mbit/s`));
    return row;
  };
  tooltip.replaceChildren(node("p", stackTime(stack, time)),
    ...layers.map(item => line(item.label, item.value, `cat-${item.tint}`)),
    ...(layers.length > 1 ? [line("Total", layers.reduce((sum, item) => sum + item.value, 0), "total")] : []));
  // The popup stays inside the plot, whichever end the pointer is at.
  tooltip.hidden = false;
  tooltip.style.left = `${Math.min(Math.max(pointer * plot.clientWidth, tooltip.offsetWidth / 2), plot.clientWidth - tooltip.offsetWidth / 2)}px`;
  $("chart-cursor").style.left = `${(pointer * 100).toFixed(2)}%`;
  $("chart-cursor").hidden = false;
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
    const identity = title(`${mark}${name(server.id)}`, server.country ? `${server.server} · ${server.country}` : server.server);
    identity.prepend(node("i", "", `dot ${tintOf(server.id)}`.trim()));
    row.identity.replaceChildren(identity);
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
    row.result.textContent = `Weight ${server.weight} · ${stats.opened_flows} opened / ${stats.open_failed_flows} failed / ${stats.closed_flows} closed · ${stats.dropped_packets} drops. ${server.reason ? `Last failure: ${server.reason}` : "No failure recorded."}`;
  });
  // The pool at a glance, in the bar: one chip per server leading to its row.
  $("pool").replaceChildren(...latest.servers.map(server => {
    const line = transport(server);
    const chip = node("a", "", "pool-chip");
    chip.href = "#servers-panel";
    chip.title = `${name(server.id)}: ${server.state}`;
    chip.append(node("i", "", `led ${tone(server.state)}`.trim()), node("span", name(server.id)),
      node("span", server.state === "ready" && line.active ? [line.active, line.latency == null ? "" : `${line.latency} ms`].filter(Boolean).join(" · ") : server.state.replaceAll("_", " "), "mono"));
    return chip;
  }));
  // One lamp per server: its state at a glance, its name on hover.
  $("ready-leds").replaceChildren(...latest.servers.map(server => {
    const lamp = node("i", "", `led ${tone(server.state)}`.trim());
    lamp.title = `${name(server.id)}: ${server.state}`;
    return lamp;
  }));
  if (!latest.servers.length) table("servers", [], 8, "No servers configured");
  if (point?.drops != null) $("recent-errors").textContent = `${point.drops} drops · ${point.failed} failed`;
  else $("recent-errors").textContent = "—";
}

function renderRules() {
  const rows = latest.rules.map(rule => [
    cell(title(`${rule.index + 1}. ${rule.label}`, selector(rule))),
    cell(rule.local ? badge(latest.local.ready ? "ready" : "missing", latest.local.ready ? "Local" : "Local unavailable") : rule.owner ? name(rule.owner) : "Not assigned yet"),
    cell(rule.local ? "Local only" : rule.candidates.map(id => name(id)).join(", ")),
    cell(flowCounts(rule.traffic), true), cell(bytes(rule.traffic.rx_bytes), true), cell(bytes(rule.traffic.tx_bytes), true),
    cell(rule.kind === "names" ? `${rule.resolved_ips} IPs / ${rule.every_secs}s` : "—"),
  ]);
  rows.push([
    cell(title("Fallback", "Unmatched traffic")),
    cell("Per flow / group"), cell("VPN pool"), cell(flowCounts(latest.fallback), true),
    cell(bytes(latest.fallback.rx_bytes), true), cell(bytes(latest.fallback.tx_bytes), true), cell("—"),
  ]);
  table("rules", rows, 7);
}

// Where every group is pinned right now, busiest first: the result of the rules
// above, and extra reading — folded shut under them until asked for.
function renderGroups() {
  if (!latest) return;
  const groups = pinnedGroups(latest.groups, { rules: latest.rules, networks: latest.usage?.session?.networks.named, names: asnNames });
  const peak = Math.max(1, ...groups.map(group => group.rx_bytes + group.tx_bytes));
  table("groups", groups.map(group => {
    const tint = tintOf(group.server), total = group.rx_bytes + group.tx_bytes;
    return [
      cell(group.label),
      cell(node("span", name(group.server), `exit-tag ${tint}`.trim())),
      cell(bytes(group.rx_bytes), true), cell(bytes(group.tx_bytes), true),
      withBar(cell(bytes(total), true), total / peak * 100, tint),
    ];
  }), 5, "No groups pinned yet");
  $("groups-note").textContent = groups.length ? `${groups.length} groups since start` : "";
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
    country: $("flow-country").value, asn: $("flow-asn").value, drill, names, page, order: $("flow-order").value });
  page = result.page;
  const sources = result.rows.map(flowSource);
  const labels = result.rows.map((flow, index) => [flow.protocol.toUpperCase(), `${sources[index].main} ${sources[index].detail}`, flow.destination,
    countryLabel(flow.country), asnLabel(flow.asn, names), name(flow.via, state),
    flow.rule == null ? "Fallback" : state.rules.find(rule => rule.index === flow.rule)?.label ?? "Unknown rule",
    rate(flow.rate == null ? null : flow.rate * 8 / 1e6), bytes((flow.rx_bytes ?? 0) + (flow.tx_bytes ?? 0)),
    flowService(flow), flowAge(flow).main, flowAge(flow).detail]);
  const signature = JSON.stringify({ labels, drill, closing: result.rows.map(flow => Boolean(flow.closing)), empty: result.total === 0 });
  if (flowSignature !== signature) {
    // A flow's rate, as a share of the busiest one on the page.
    const peak = Math.max(0.01, ...result.rows.map(flow => flow.rate ?? 0));
    const rows = result.rows.map((flow, index) => {
      const protocol = cell(node("span", labels[index][0], `tag tag--${flow.protocol}`));
      if (labels[index][9]) protocol.append(node("span", labels[index][9], "service"));
      if (flow.closing) protocol.append(node("span", "closing", "tag tag--closing"));
      // The exit carries its series' colour, as it does everywhere else.
      const exit = node("span", labels[index][5], `exit-tag ${tintOf(flow.via)}`.trim());
      return [
      protocol,
      cell(title(sources[index].main, sources[index].detail)), cell(node("code", labels[index][2])),
      cell(labels[index][3]), cell(labels[index][4]),
      cell(exit), cell(node("span", labels[index][6], "rule-tag")),
      withBar(cell(title(labels[index][7], labels[index][8]), true), flow.rate > 0 ? flow.rate / peak * 100 : null, "rate"),
      cell(title(labels[index][10], labels[index][11]), true),
      ];
    });
    table("flows", rows, 9, drill ? "No current flows match. Completed traffic remains in the session totals." : result.total ? "No flows match these filters" : "No active flows");
    // Closing rows dim in place; the tag alone would vanish in the density.
    result.rows.forEach((flow, index) => {
      if (flow.closing) $("flows").tBodies[0].rows[index].classList.add("closing");
    });
    flowSignature = signature;
  }
  const start = result.count ? page * PAGE_SIZE + 1 : 0;
  $("flow-count").textContent = `${start}–${result.count ? start + result.rows.length - 1 : 0} / ${result.count} · ${result.total} total`;
  $("flow-page").textContent = `${page + 1} / ${result.pages}`;
  $("previous").disabled = page === 0;
  $("next").disabled = page + 1 >= result.pages;
  $("pause").disabled = false;
  $("pause").textContent = frozen ? "Resume" : "Pause";
  $("pause").setAttribute("aria-pressed", String(Boolean(frozen)));
  $("flow-status").textContent = frozen ? `Paused ${new Date(frozen.generated_at_ms).toLocaleTimeString()}` : "Live";
  $("flow-reset").disabled = !latest || !(drill || filters.some(id => $(id).value));
}

function renderAsnNames() {
  const state = latest?.asn_table ? asnState : "unavailable";
  $("asn-load").disabled = state === "loading" || state === "unavailable";
  $("asn-load").textContent = state === "ready" ? "Reload" : "ASN names";
  $("asn-status").textContent = state === "ready" ? `${asnCount.toLocaleString()} names`
    : state === "loading" ? "Loading…"
    : state === "error" ? `ASN names unavailable: ${asnError}`
    : state === "unavailable" ? "No geo-db CSV"
    : state === "evicted" ? "Freed after 5 min hidden"
    : "Not loaded";
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
    if (asnAbort === request) { asnAbort = null; renderAsnNames(); renderGroups(); renderFlows(); }
  }
}

function asnVisibility() {
  clearTimeout(asnIdleTimer);
  if (document.hidden) {
    asnIdleTimer = setTimeout(() => { clearAsnNames("evicted"); renderAsnNames(); renderGroups(); renderFlows(); }, 300000);
  } else if (latest?.asn_table && asnState === "idle") void loadAsnNames();
}

function renderJobs() {
  table("databases", latest.databases.map(db => [
    cell(db.kind === "geo" ? "ASN" : "Country"),
    cell(badge(db.loaded ? db.status.error ? "previous" : "ready" : db.configured ? "missing" : "disabled",
      db.loaded ? db.status.error ? "Using previous table" : "Loaded" : db.configured ? "Missing" : "Not configured")),
    cell(db.rows, true), cell(time(db.status.loaded_at)), cell(time(db.status.attempted_at)),
    cell(db.status.error || (db.pending ? `Waiting for job ${db.pending}` : "—")),
  ]), 6);
  table("jobs", latest.jobs.details.map(job => [
    cell(title(job.label, `Every ${job.every_secs}s · timeout ${job.timeout_secs}s${job.reload.length ? ` · reload ${job.reload.join(", ")}` : ""}`)),
    cell(badge(job.state)), cell(time(job.started_at)), cell(time(job.success_at)),
    cell(job.state === "running" ? "Running" : time(job.next_at)), cell(job.reason ? `${job.state === "running" ? "Previous attempt: " : ""}${job.reason}` : job.state === "ok" ? "OK" : "—"),
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

function render() {
  for (const id of ["flow-search", "flow-protocol", "flow-exit", "flow-country", "flow-asn", "flow-order"]) $(id).disabled = false;
  const ready = latest.servers.filter(server => server.state === "ready").length;
  $("ready").textContent = `${ready} / ${latest.servers.length}`;
  // A healthy summary stays neutral; these two are what a reader scans for trouble.
  $("ready").className = latest.servers.length && ready < latest.servers.length ? "warn" : "";
  const open = latest.flows.filter(flow => !flow.closing).length;
  const closing = latest.flows.length - open;
  // The headline stays a bare number so the card fits a phone; closing ones go to the note.
  $("active").textContent = String(open);
  const localFlows = latest.flows.filter(flow => flow.via === "local").length;
  $("active-note").textContent = `${latest.flows.length - localFlows} VPN · ${localFlows} local${closing ? ` · ${closing} closing` : ""}`;
  $("local").textContent = localState(latest.local);
  $("local").className = latest.local.enabled && !latest.local.ready ? "compact bad" : "compact";
  $("local-note").textContent = latest.local.enabled ? `${localFlows} flows · ${latest.local.ready ? "ready" : "unavailable"}` : "Disabled";
  const warnings = latest.servers.filter(server => server.state !== "ready").map(server => `${name(server.id)}: ${server.state}${server.reason ? ` — ${server.reason}` : ""}`);
  if (latest.local.enabled && !latest.local.ready) warnings.push("Local exit unavailable; local rules do not fall back to VPN");
  for (const db of latest.databases) if (db.configured && !db.loaded) warnings.push(`${db.kind === "geo" ? "ASN" : "Country"} database missing`);
  $("warnings").textContent = warnings.join(" · ");
  $("warnings").hidden = !warnings.length;
  document.body.dataset.health = warnings.length ? "warn" : "ok";
  $("rail-health").textContent = warnings.length ? `${warnings.length} warning${warnings.length === 1 ? "" : "s"} to review` : ready === latest.servers.length ? "All links ready" : "Pool recovering";
  renderClock(); renderProcess(); renderServers(); renderRules(); renderGroups(); renderFlows(); renderAsnNames(); renderJobs(); renderCounters(); renderChart(); freshness();
  $("footer").textContent = `Client started ${time(latest.started_at / 1000)}`;
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
      if (latest && state.started_at !== latest.started_at) { clearAsnNames("idle"); history = []; point = null; latest = null; past.fetched = -Infinity; }
      point = measure(resumed || !point ? null : latest, state);
      apiError = false;
      history = keepHistory(history, point);
      latest = { ...state, flows: withFlowRates(resumed ? null : latest, state), asn_names: asnNames };
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

for (const [id, value] of [["usage-session", "session"], ["usage-now", "interval"]]) $(id).addEventListener("click", () => { period = value; renderUsage(isStale()); });
$("usage-axis").addEventListener("change", () => { $("usage-ranks").dataset.axis = $("usage-axis").value; });
$("usage-direction").addEventListener("change", () => renderUsage(isStale()));
for (const button of $("chart-ranges").querySelectorAll("[data-range]")) button.addEventListener("click", () => chooseRange(button.dataset.range));
$("chart-apply").addEventListener("click", applyChartWindow);
for (const id of ["chart-from", "chart-to"]) $(id).addEventListener("keydown", event => { if (event.key === "Enter") applyChartWindow(); });
for (const id of ["chart-kind", "chart-server", "chart-direction"]) $(id).addEventListener("change", () => {
  past.kind = $("chart-kind").value; past.link = $("chart-server").value; past.direction = $("chart-direction").value;
  // Another breakdown or server has no use for the previous answer; another direction redraws it.
  if (id === "chart-direction") renderChart(true); else askChart();
});
for (const axis of rankAxes) $(`rank-${axis}`).nextElementSibling.addEventListener("click", () => {
  if (expandedRanks.has(axis)) expandedRanks.delete(axis); else expandedRanks.add(axis);
  renderUsage(isStale());
});
$("clear-drill").addEventListener("click", () => { drill = null; page = 0; $("drill-note").hidden = true; renderFlows(); $("flow-search").focus(); });
for (const id of [...filters, "flow-order"]) $(id).addEventListener(id === "flow-search" ? "input" : "change", () => { page = 0; renderFlows(); });
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

// Until the user picks, the theme follows the system; like everything else it lives in this tab only.
function setTheme(light) {
  const theme = light ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  document.body.dataset.theme = theme;
  $("theme-toggle").setAttribute("aria-pressed", String(light));
  $("theme-label").textContent = `Theme: ${theme}`;
  $("theme-icon").setAttribute("href", light ? "#i-sun" : "#i-moon");
}
const systemTheme = matchMedia("(prefers-color-scheme: light)");
let followsSystem = true;
setTheme(systemTheme.matches);
// The page keeps following the system until the user makes a choice of their own.
systemTheme.addEventListener("change", () => { if (followsSystem) setTheme(systemTheme.matches); });
$("theme-toggle").addEventListener("click", () => { followsSystem = false; setTheme(document.body.dataset.theme !== "light"); });

// One way back to the unfiltered table, for the keyboard and the pointer alike.
$("flow-reset").addEventListener("click", () => {
  for (const id of filters) $(id).value = "";
  drill = null; page = 0; $("drill-note").hidden = true;
  renderFlows(); $("flow-search").focus();
});

$("chart-plot").addEventListener("pointermove", event => {
  const rect = $("chart-plot").getBoundingClientRect();
  pointer = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
  drawCursor();
});
$("chart-plot").addEventListener("pointerleave", () => { pointer = null; hideCursor(); });

// The absolute-positioned popup can grow a phone document past the viewport, so it is
// nudged back inside on open; the same hooks un-dismiss a popup closed by Escape.
// CSP forbids inline handlers, hence this listener instead of markup attributes.
for (const wrap of document.querySelectorAll(".help-wrap")) {
  const open = () => {
    wrap.classList.remove("dismissed");
    const pop = wrap.querySelector(".help-pop");
    pop.style.left = "";
    const rect = pop.getBoundingClientRect(), edge = document.documentElement.clientWidth - 8;
    const shift = Math.max(0, rect.right - edge, 8 - rect.left);
    if (shift > 0) pop.style.left = `${-shift}px`;
  };
  wrap.addEventListener("focusin", open);
  wrap.addEventListener("pointerenter", open);
}

document.addEventListener("keydown", event => {
  const active = document.activeElement;
  const typing = active && ["INPUT", "SELECT", "TEXTAREA"].includes(active.tagName);
  if (event.key === "/" && !typing) { event.preventDefault(); $("flow-search").focus(); }
  if (event.key === "Escape") {
    // WCAG 1.4.13: Esc must also close the open tooltip, hover-opened included.
    document.querySelector(".help-wrap:focus-within, .help-wrap:hover")?.classList.add("dismissed");
  }
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

for (const [id, columns] of [["servers", 8], ["rules", 7], ["flows", 9], ["history", 6], ["databases", 6], ["jobs", 6], ["groups", 5]]) table(id, [], columns, "No snapshot yet");
renderClock();
setInterval(() => { renderClock(); freshness(); }, 1000);
refresh();
