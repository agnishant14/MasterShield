const state = {
  overview: null,
  attacks: [],
  selectedAttacks: new Set(["atk-001", "atk-003", "atk-005", "atk-008"]),
  intensity: 1.0,
  severityFilter: "all",
  feedbackQueued: 0,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function pct(value, digits = 1) {
  return `${(Number(value || 0) * 100).toFixed(digits)}%`;
}

function compactNumber(value) {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(Number(value || 0));
}

function money(value, currency = "USD") {
  return new Intl.NumberFormat("en", {
    style: "currency",
    currency: currency === "INR" ? "INR" : "USD",
    maximumFractionDigits: value > 1000 ? 0 : 2,
  }).format(Number(value || 0));
}

function refreshIcons() {
  if (window.lucide) window.lucide.createIcons({ attrs: { "stroke-width": 1.7 } });
}

async function requestJSON(url, options = {}) {
  if (window.location.protocol === "file:" && window.MASTERSHIELD_DEMO) {
    if (url === "/api/overview") return structuredClone(window.MASTERSHIELD_DEMO.overview);
    if (url === "/api/attacks") return { attacks: structuredClone(window.MASTERSHIELD_DEMO.attacks) };
    throw new Error("Interactive runs require python3 app.py");
  }
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed: ${response.status}`);
  return payload;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 3300);
}

function switchView(viewName) {
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${viewName}`));
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === viewName));
  $("#crumb-view").textContent = viewName.replaceAll("-", " ").toUpperCase();
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (viewName === "attacks") renderAttackTable();
  if (viewName === "simulate") renderScenarioPicker();
  if (viewName === "defense") renderDefense();
}

function decisionHTML(decision) {
  const clean = ["approve", "review", "decline"].includes(decision) ? decision : "review";
  return `<span class="decision ${clean}">${clean.toUpperCase()}</span>`;
}

function renderTransactions(rows) {
  const body = $("#stream-table");
  body.innerHTML = rows.slice(0, 8).map((row) => `
    <tr>
      <td><span class="tx-main">${escapeHTML(row.id)}</span><span class="tx-sub">${escapeHTML(row.attack_name || "legitimate baseline")}</span></td>
      <td><span class="tx-main">${escapeHTML(row.rail)}</span><span class="tx-sub">${escapeHTML(row.channel)}</span></td>
      <td><span class="tx-main">${money(row.amount, row.currency)}</span><span class="tx-sub">${escapeHTML(row.country)}</span></td>
      <td><div class="risk-cell"><div class="risk-track"><span style="width:${Math.round(row.risk_score * 100)}%"></span></div><b class="mono">${pct(row.risk_score, 0)}</b></div></td>
      <td>${decisionHTML(row.decision)}</td>
    </tr>
  `).join("");
}

function renderAttackMix(items) {
  const max = Math.max(1, ...items.map((item) => item.count));
  $("#attack-mix").innerHTML = items.length ? items.map((item) => `
    <div class="mix-row"><span title="${escapeHTML(item.name)}">${escapeHTML(item.name)}</span><div class="mix-bar"><i style="width:${Math.max(6, item.count / max * 100)}%"></i></div><b>${item.count}</b></div>
  `).join("") : `<div class="empty-state" style="min-height:200px"><strong>No active attacks</strong></div>`;
}

function drawBoundaryChart(metrics) {
  const canvas = $("#boundary-chart");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const ratio = Math.max(1, window.devicePixelRatio || 1);
  canvas.width = Math.max(320, Math.floor(rect.width * ratio));
  canvas.height = Math.floor(240 * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  const width = canvas.width / ratio;
  const height = canvas.height / ratio;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#fbfaf7";
  ctx.fillRect(0, 0, width, height);
  ctx.strokeStyle = "#e5e2dc";
  ctx.lineWidth = 1;
  for (let i = 1; i < 5; i += 1) {
    const x = (width / 5) * i;
    const y = (height / 5) * i;
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
  }
  let seed = 71827;
  const random = () => {
    seed = (seed * 16807) % 2147483647;
    return (seed - 1) / 2147483646;
  };
  const dot = (x, y, color, size = 3) => {
    ctx.beginPath(); ctx.arc(x, y, size, 0, Math.PI * 2); ctx.fillStyle = color; ctx.fill();
  };
  for (let i = 0; i < 58; i += 1) {
    const x = 20 + random() * width * .64;
    const y = 30 + random() * height * .78 + x * .08;
    dot(x, Math.min(height - 12, y), "rgba(23,163,152,.64)", 2.6);
  }
  for (let i = 0; i < 39; i += 1) {
    const x = width * .34 + random() * width * .6;
    const y = 14 + random() * height * .55 - x * .055;
    dot(x, Math.max(10, y), "rgba(239,51,38,.70)", 2.8);
  }
  const threshold = Number(metrics.threshold || .5);
  const boundaryShift = (threshold - .5) * 35;
  ctx.save();
  ctx.setLineDash([5, 5]);
  ctx.strokeStyle = "#6e706d";
  ctx.lineWidth = 1.4;
  ctx.beginPath();
  ctx.moveTo(width * .24 + boundaryShift, height - 4);
  ctx.bezierCurveTo(width * .37 + boundaryShift, height * .57, width * .57 + boundaryShift, height * .46, width * .75 + boundaryShift, 3);
  ctx.stroke();
  ctx.restore();
  ctx.fillStyle = "#767773";
  ctx.font = '8px "DM Mono", monospace';
  ctx.fillText("BEHAVIORAL TRUST →", 12, height - 10);
  ctx.save();
  ctx.translate(9, height - 14);
  ctx.rotate(-Math.PI / 2);
  ctx.fillText("NETWORK RISK →", 0, 0);
  ctx.restore();
}

function renderOverview() {
  const data = state.overview;
  if (!data) return;
  const metrics = data.metrics;
  const latest = data.history.at(-1);
  const previous = data.history.at(-2) || latest;
  const f1Delta = latest.f1 - previous.f1;
  $("#kpi-f1").textContent = pct(metrics.f1);
  $("#kpi-f1-delta").textContent = `${f1Delta >= 0 ? "+" : ""}${pct(f1Delta)} after hard-case retrain`;
  $("#kpi-auc").textContent = metrics.auc.toFixed(3);
  $("#kpi-fpr").textContent = pct(metrics.false_positive_rate);
  $("#kpi-coverage").textContent = latest.attack_coverage;
  $("#intro-model").textContent = data.system.model_version;
  $("#intro-time").textContent = new Date(data.generated_at).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" });
  $("#last-sync").textContent = `sync ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  $("#cycle-badge").textContent = `CYCLE ${String(data.cycle).padStart(2, "0")}`;
  $("#side-cycle").textContent = `Cycle ${String(data.cycle).padStart(2, "0")}`;
  $("#loop-identify").textContent = data.catalog_size;
  $("#loop-generate").textContent = compactNumber(data.training_rows);
  $("#loop-defend").textContent = pct(metrics.recall, 0);
  $("#loop-learn").textContent = `C${data.cycle}`;
  $("#loop-queue").textContent = `${state.feedbackQueued} rows`;
  $("#side-feedback").textContent = `${state.feedbackQueued} queued`;
  $("#threshold-value").textContent = Number(metrics.threshold).toFixed(2);
  renderTransactions(data.recent_transactions || []);
  renderAttackMix(data.attack_mix || []);
  const activeCoverage = Math.max(data.detected_attack_coverage, latest.attack_coverage);
  $("#coverage-ring").style.setProperty("--coverage", `${activeCoverage / data.catalog_size * 100}%`);
  $("#coverage-ring-value").textContent = `${activeCoverage}/${data.catalog_size}`;
  $("#coverage-title").textContent = activeCoverage === data.catalog_size ? "Full frontier coverage" : "Active frontier coverage";
  drawBoundaryChart(metrics);
  renderDefense();
}

function renderAttackTable() {
  const query = ($("#attack-search")?.value || "").trim().toLowerCase();
  const rows = state.attacks.filter((attack) => {
    const matchesSeverity = state.severityFilter === "all" || attack.severity === state.severityFilter;
    const haystack = `${attack.name} ${attack.family} ${attack.rail} ${attack.channel} ${attack.genai_role}`.toLowerCase();
    return matchesSeverity && haystack.includes(query);
  });
  $("#attack-count").textContent = rows.length;
  $("#attack-table-body").innerHTML = rows.map((attack) => {
    const detection = attack.detection_rate == null ? 0 : attack.detection_rate;
    return `
      <tr>
        <td><span class="attack-name"><i class="severity-dot ${escapeHTML(attack.severity)}"></i>${escapeHTML(attack.name)}</span><span class="attack-id">${escapeHTML(attack.id)} / ${escapeHTML(attack.novelty)} novelty</span></td>
        <td><span class="family-tag">${escapeHTML(attack.family.replaceAll("_", " "))}</span></td>
        <td><span class="tx-main">${escapeHTML(attack.rail)}</span><span class="tx-sub">${escapeHTML(attack.channel)}</span></td>
        <td><span class="genai-copy">${escapeHTML(attack.genai_role)}</span></td>
        <td><div class="detection-meter"><div class="risk-track"><span style="width:${detection * 100}%"></span></div><b class="mono">${attack.detection_rate == null ? "—" : pct(detection, 0)}</b></div></td>
        <td><button class="table-action" data-attack-run="${escapeHTML(attack.id)}" title="Simulate ${escapeHTML(attack.name)}" aria-label="Simulate ${escapeHTML(attack.name)}"><i data-lucide="play"></i></button></td>
      </tr>`;
  }).join("");
  $$('[data-attack-run]').forEach((button) => button.addEventListener("click", () => {
    state.selectedAttacks = new Set([button.dataset.attackRun]);
    switchView("simulate");
  }));
  refreshIcons();
}

function renderScenarioPicker() {
  const container = $("#scenario-picker");
  container.innerHTML = state.attacks.map((attack) => `
    <button class="scenario-option ${state.selectedAttacks.has(attack.id) ? "selected" : ""}" data-scenario-id="${escapeHTML(attack.id)}" type="button">
      <span class="scenario-check">${state.selectedAttacks.has(attack.id) ? "✓" : ""}</span>
      <span><strong>${escapeHTML(attack.name)}</strong><small>${escapeHTML(attack.rail)} / ${escapeHTML(attack.severity)}</small></span>
    </button>`).join("");
  $$('[data-scenario-id]', container).forEach((button) => button.addEventListener("click", () => {
    const id = button.dataset.scenarioId;
    if (state.selectedAttacks.has(id)) state.selectedAttacks.delete(id);
    else state.selectedAttacks.add(id);
    renderScenarioPicker();
  }));
}

function renderSimulationResult(result) {
  $("#sim-result-empty").classList.add("hidden");
  $("#sim-result-content").classList.remove("hidden");
  $("#sim-result-title").textContent = `${result.generated} adversarial events scored`;
  $("#sim-run-id").textContent = result.run_id;
  $("#sim-detected").textContent = result.detected;
  $("#sim-missed").textContent = result.missed;
  $("#sim-fps").textContent = result.false_positives;
  $("#sim-risk").textContent = pct(result.mean_risk, 0);
  $("#sim-rate").textContent = pct(result.detection_rate);
  $("#result-bar-fill").style.width = `${result.detection_rate * 100}%`;
  $("#sim-samples").innerHTML = result.sample.map((row) => `
    <div class="sample-row"><div class="sample-name"><strong>${escapeHTML(row.attack_name)}</strong><span>${escapeHTML(row.id)} / ${escapeHTML(row.rail)}</span></div><div class="sample-risk">${pct(row.risk_score, 0)} risk</div>${decisionHTML(row.decision)}</div>
  `).join("");
  state.feedbackQueued = result.feedback_ready;
  $("#simulation-queue").textContent = result.feedback_ready;
  $("#side-feedback").textContent = `${result.feedback_ready} queued`;
  $("#loop-queue").textContent = `${result.feedback_ready} rows`;
}

function renderDefense() {
  if (!state.overview) return;
  const { metrics, feature_importance: importance, history, cycle, system } = state.overview;
  $("#defense-version").textContent = `C${String(cycle).padStart(2, "0")}`;
  $("#def-precision").textContent = pct(metrics.precision);
  $("#def-recall").textContent = pct(metrics.recall);
  $("#def-specificity").textContent = pct(metrics.specificity);
  $("#def-threshold").textContent = Number(metrics.threshold).toFixed(2);
  const matrix = metrics.confusion_matrix;
  $("#matrix-tp").textContent = matrix.tp;
  $("#matrix-fn").textContent = matrix.fn;
  $("#matrix-fp").textContent = matrix.fp;
  $("#matrix-tn").textContent = matrix.tn;
  const maxImportance = Math.max(0.01, ...importance.map((item) => item.importance));
  $("#importance-list").innerHTML = importance.slice(0, 10).map((item) => `
    <div class="importance-row"><span title="${escapeHTML(item.label)}">${escapeHTML(item.label)}</span><div class="importance-bar"><i style="width:${Math.max(3, item.importance / maxImportance * 100)}%"></i></div><b>${item.importance.toFixed(2)}</b></div>
  `).join("");
  $("#history-list").innerHTML = history.map((item) => `
    <div class="history-item"><span>CYCLE ${String(item.cycle).padStart(2, "0")}</span><strong>${escapeHTML(item.name)}</strong><div class="history-stats"><span>F1 <b>${pct(item.f1)}</b></span><span>RECALL <b>${pct(item.recall)}</b></span><span>FPR <b>${pct(item.fpr)}</b></span></div></div>
  `).join("") + `<div class="history-item"><span>PRODUCTION SHAPE</span><strong>${escapeHTML(system.model_version)}</strong><div class="history-stats"><span>P95 <b>${system.latency_ms_p95} ms</b></span><span>RAILS <b>6</b></span></div></div>`;
}

async function loadData() {
  try {
    const [overview, attackPayload] = await Promise.all([
      requestJSON("/api/overview"),
      requestJSON("/api/attacks"),
    ]);
    state.overview = overview;
    state.attacks = attackPayload.attacks;
    renderOverview();
    renderAttackTable();
    renderScenarioPicker();
  } catch (error) {
    toast(`Could not load the defense lab: ${error.message}`);
  }
}

async function runSimulation() {
  if (!state.selectedAttacks.size) {
    toast("Select at least one attack hypothesis.");
    return;
  }
  const button = $("#run-simulation");
  const oldHTML = button.innerHTML;
  button.disabled = true;
  button.textContent = "Generating adversarial stream…";
  try {
    const result = await requestJSON("/api/simulate", {
      method: "POST",
      body: JSON.stringify({
        attack_ids: [...state.selectedAttacks],
        count: Number($("#volume-slider").value),
        intensity: state.intensity,
      }),
    });
    renderSimulationResult(result);
    toast(`${result.detected}/${result.generated} attacks detected; ${result.missed} hard cases queued.`);
    state.overview = await requestJSON("/api/overview");
    renderOverview();
  } catch (error) {
    toast(`Simulation failed: ${error.message}`);
  } finally {
    button.disabled = false;
    button.innerHTML = oldHTML;
    refreshIcons();
  }
}

async function retrainModel() {
  const button = $("#retrain-button");
  const oldHTML = button.innerHTML;
  button.disabled = true;
  button.textContent = "Retraining…";
  try {
    const result = await requestJSON("/api/retrain", { method: "POST", body: "{}" });
    state.feedbackQueued = 0;
    $("#simulation-queue").textContent = "0";
    state.overview = await requestJSON("/api/overview");
    renderOverview();
    const f1Delta = result.deltas.f1;
    toast(`Cycle ${result.cycle} trained on ${result.feedback_rows} feedback rows. F1 ${f1Delta >= 0 ? "+" : ""}${pct(f1Delta)}.`);
  } catch (error) {
    toast(`Retraining failed: ${error.message}`);
  } finally {
    button.disabled = false;
    button.innerHTML = oldHTML;
    refreshIcons();
  }
}

function bindEvents() {
  $$('[data-view]').forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
  $("#attack-search").addEventListener("input", renderAttackTable);
  $$(".filter-button").forEach((button) => button.addEventListener("click", () => {
    state.severityFilter = button.dataset.filter;
    $$(".filter-button").forEach((item) => item.classList.toggle("active", item === button));
    renderAttackTable();
  }));
  $("#volume-slider").addEventListener("input", (event) => {
    $("#volume-output").textContent = `${event.target.value} events`;
  });
  $$("#intensity-picker button").forEach((button) => button.addEventListener("click", () => {
    state.intensity = Number(button.dataset.intensity);
    $$("#intensity-picker button").forEach((item) => item.classList.toggle("active", item === button));
  }));
  $("#run-simulation").addEventListener("click", runSimulation);
  $("#retrain-button").addEventListener("click", retrainModel);
  $("#refresh-overview").addEventListener("click", async () => {
    state.overview = await requestJSON("/api/overview");
    renderOverview();
    toast("Operating picture refreshed.");
  });
  window.addEventListener("resize", () => state.overview && drawBoundaryChart(state.overview.metrics));
}

document.addEventListener("DOMContentLoaded", () => {
  refreshIcons();
  bindEvents();
  loadData();
});
