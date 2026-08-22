const state = {
  overview: null,
  attacks: [],
  selectedAttacks: new Set(["atk-001", "atk-003", "atk-005", "atk-008"]),
  intensity: 1.0,
  severityFilter: "all",
  feedbackQueued: 0,
  transactionIndex: new Map(),
  connectionMode: "loading",
  capabilities: null,
  fidelity: null,
  mutation: null,
};

const API_CONTROLS = {
  "refresh-overview": "overview",
  "run-simulation": "simulate",
  "retrain-button": "retrain",
  "refresh-fidelity": "fidelity",
  "export-report": "report",
  "run-mutation": "mutate",
};

const OUTDATED_BACKEND_MESSAGE = "Backend API is outdated; redeploy the current app.py.";
const OFFLINE_ACTION_MESSAGE = "Interactive actions require the Python server; run python3 app.py.";
const REQUIRED_UI_CAPABILITIES = ["overview", "attacks", "simulate", "retrain", "fidelity", "report", "mutate", "feedback", "models", "rollback", "audit"];
const OFFLINE_CAPABILITIES = ["overview", "attacks", "transactions", "fidelity", "report", "mutate", "simulations"];
const REQUEST_TIMEOUTS_MS = { "/api/retrain": 120000, "/api/fidelity": 90000, "/api/report": 90000, "/api/mutate": 30000 };

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

function boundedRatio(value) {
  const number = Number(value);
  return Math.max(0, Math.min(1, Number.isFinite(number) ? number : 0));
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

function bindRevealMotion() {
  const targets = $$(".surface, .kpi-cell, .page-title-row, .section-head, .feedback-node, .metric-panel");
  targets.forEach((node, index) => {
    node.dataset.reveal = "pending";
    node.style.setProperty("--reveal-delay", `${Math.min(index * 35, 280)}ms`);
  });
  if (!("IntersectionObserver" in window)) {
    targets.forEach((node) => { node.dataset.reveal = "visible"; });
    return;
  }
  const observer = new IntersectionObserver((entries, instance) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.dataset.reveal = "visible";
      instance.unobserve(entry.target);
    });
  }, { threshold: 0.08 });
  targets.forEach((node) => observer.observe(node));
}

function isOfflineDemo() {
  return window.location.protocol === "file:" && Boolean(window.MASTERSHIELD_DEMO);
}

async function requestJSON(url, options = {}) {
  if (isOfflineDemo()) {
    const demo = window.MASTERSHIELD_DEMO;
    if (url === "/api/health") return { status: "offline", api_version: "offline-demo", capabilities: OFFLINE_CAPABILITIES, model_version: `hybrid-logit-c${demo.overview.cycle}` };
    if (url === "/api/overview") return structuredClone(demo.overview);
    if (url === "/api/attacks") return { attacks: structuredClone(demo.attacks) };
    if (url === "/api/transactions") return { transactions: structuredClone(demo.overview.recent_transactions || []) };
    if (url === "/api/simulations") return { simulations: [] };
    if (url === "/api/feedback" && options.method !== "POST") return { feedback: [] };
    if (url === "/api/fidelity") {
      const metrics = demo.overview.metrics || {};
      const recall = Number(metrics.recall || 0);
      return structuredClone(demo.fidelity || {
        synthetic_evidence: true,
        sample_counts: { reference: 0, candidate: 0 },
        feature_distance: {},
        mean_feature_distance: 0,
        scenario_mix_distance: 0,
        robustness: {
          known_low_intensity: { rows: 0, attack_rows: 0, attack_recall: recall, mean_risk: recall },
          unseen_attack_families: { rows: 0, attack_rows: 0, attack_recall: recall, mean_risk: recall },
          missing_features: { rows: 0, attack_rows: 0, attack_recall: recall, mean_risk: recall },
          legitimate_baseline: { rows: 0, attack_rows: 0, attack_recall: 0, mean_risk: 0 },
        },
        policy_tradeoff: {
          synthetic_evidence: true,
          actions: demo.overview.decisions || {},
          estimated_customer_friction: 0,
          estimated_expected_loss: 0,
        },
      });
    }
    if (url === "/api/report") {
      const fidelity = await requestJSON("/api/fidelity");
      return structuredClone(demo.report || {
        synthetic_evidence: true,
        cycle: demo.overview.cycle,
        metrics: demo.overview.metrics,
        validation: demo.overview.validation || {},
        fidelity,
        simulations: [],
        feedback: demo.overview.feedback_buckets || {},
      });
    }
    if (url === "/api/mutate") {
      const row = (demo.overview.recent_transactions || []).find((item) => item.attack_id) || {};
      return {
        original: {
          id: row.id || "offline-snapshot",
          attack_id: row.attack_id || null,
          risk_score: Number(row.risk_score || 0),
          detected: row.decision !== "approve",
        },
        candidate_count: 0,
        blind_spots: 0,
        candidates: [],
        safety: "offline snapshot only; start app.py to run a mutation search",
      };
    }
    throw new Error("Interactive runs require python3 app.py");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUTS_MS[url] || 15000);
  try {
    const response = await fetch(url, {
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
      signal: controller.signal,
    });
    const contentType = response.headers.get("content-type") || "";
    const rawBody = await response.text();
    let payload = {};
    if (rawBody) {
      try {
        payload = JSON.parse(rawBody);
      } catch (_error) {
        if (!response.ok) throw new Error(`Server returned HTTP ${response.status} with a non-JSON response`);
        throw new Error(`Server returned ${contentType || "an unknown content type"}; expected JSON`);
      }
    }
    if (!response.ok) {
      const requestPath = new URL(url, window.location.href).pathname.replace(/\/$/, "");
      if (response.status === 404 && ["/api/fidelity", "/api/mutate", "/api/report"].includes(requestPath)) {
        throw new Error(OUTDATED_BACKEND_MESSAGE);
      }
      throw new Error(payload.error || `Request failed: ${response.status}`);
    }
    return payload;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("The server took too long to respond");
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function toast(message) {
  const node = $("#toast");
  if (!node) return;
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 3300);
}

function setConnectionStatus(mode) {
  state.connectionMode = mode;
  const status = $("#connection-status");
  if (!status) return;
  status.dataset.mode = mode;
  const label = { loading: "Connecting", live: "Live API", offline: "Offline demo", outdated: "Update required", error: "Unavailable" }[mode] || "Unavailable";
  const modelLabel = { loading: "LOADING", live: "LIVE API", offline: "OFFLINE SNAPSHOT", outdated: "OUTDATED API", error: "UNAVAILABLE" }[mode] || "UNAVAILABLE";
  $("#connection-label") && ($("#connection-label").textContent = label);
  $("#model-status-label") && ($("#model-status-label").textContent = modelLabel);
  $("#side-loop-title") && ($("#side-loop-title").innerHTML = `<span class="pulse"></span> ${mode === "live" ? "Closed loop active" : mode === "offline" ? "Static evidence snapshot" : mode === "outdated" ? "Backend update required" : mode === "error" ? "Defense loop unavailable" : "Connecting to model"}`);
  $("#side-loop-copy") && ($("#side-loop-copy").textContent = mode === "live" ? "Simulation feedback is available for the next model cycle." : mode === "offline" ? "Start app.py to run simulations and retraining." : mode === "outdated" ? "Redeploy the current app.py to enable all API-backed controls." : "Loading red-team, model, and feedback state.");
}

function updateCapabilities(health) {
  state.capabilities = new Set(Array.isArray(health?.capabilities) ? health.capabilities : []);
  const currentBackend = REQUIRED_UI_CAPABILITIES.every((capability) => state.capabilities.has(capability));
  const unavailableMessage = isOfflineDemo() ? OFFLINE_ACTION_MESSAGE : OUTDATED_BACKEND_MESSAGE;
  Object.entries(API_CONTROLS).forEach(([id, capability]) => {
    const button = $(`#${id}`);
    if (!button) return;
    const supported = state.capabilities.has(capability);
    button.disabled = !supported;
    button.dataset.apiUnavailable = String(!supported);
    if (!supported) button.title = unavailableMessage;
    else if ([OUTDATED_BACKEND_MESSAGE, OFFLINE_ACTION_MESSAGE].includes(button.title)) button.removeAttribute("title");
  });
  return currentBackend;
}

function requireCapability(capability) {
  if (state.capabilities?.has(capability)) return true;
  toast(isOfflineDemo() ? OFFLINE_ACTION_MESSAGE : OUTDATED_BACKEND_MESSAGE);
  return false;
}

function switchView(viewName) {
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${viewName}`));
  $$(".nav-item").forEach((item) => {
    const active = item.dataset.view === viewName;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  $("#crumb-view").textContent = viewName.replaceAll("-", " ").toUpperCase();
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (viewName === "attacks") renderAttackTable();
  if (viewName === "simulate") renderScenarioPicker();
  if (viewName === "defense") renderDefense();
  if (viewName === "overview" && state.overview) requestAnimationFrame(() => drawBoundaryChart(state.overview));
  if (viewName === "fidelity" && !state.fidelity) loadFidelity();
}

function decisionHTML(decision) {
  const clean = ["approve", "review", "decline"].includes(decision) ? decision : "review";
  return `<span class="decision ${clean}">${clean.toUpperCase()}</span>`;
}

function renderTransactions(rows) {
  const body = $("#stream-table");
  if (!body) return;
  rows = Array.isArray(rows) ? rows : [];
  rows.forEach((row) => state.transactionIndex.set(row.id, row));
  body.innerHTML = rows.slice(0, 8).map((row) => `
    <tr>
      <td><span class="tx-main">${escapeHTML(row.id)}</span><span class="tx-sub">${escapeHTML(row.attack_name || "legitimate baseline")}</span></td>
      <td><span class="tx-main">${escapeHTML(row.rail)}</span><span class="tx-sub">${escapeHTML(row.channel)}</span></td>
      <td><span class="tx-main">${money(row.amount, row.currency)}</span><span class="tx-sub">${escapeHTML(row.country)}</span></td>
      <td><div class="risk-cell"><div class="risk-track"><span style="width:${Math.round(row.risk_score * 100)}%"></span></div><b class="mono">${pct(row.risk_score, 0)}</b></div></td>
      <td>${decisionHTML(row.decision)}</td>
      <td><button class="table-action" data-transaction-detail="${escapeHTML(row.id)}" title="Explain ${escapeHTML(row.id)}" aria-label="Explain ${escapeHTML(row.id)}"><i data-lucide="scan-eye"></i></button></td>
    </tr>
  `).join("");
  $$('[data-transaction-detail]', body).forEach((button) => button.addEventListener("click", () => openTransactionDialog(button.dataset.transactionDetail)));
  refreshIcons();
}

function renderAttackMix(items) {
  items = Array.isArray(items) ? items : [];
  const target = $("#attack-mix");
  if (!target) return;
  const max = Math.max(1, ...items.map((item) => item.count));
  target.innerHTML = items.length ? items.map((item) => `
    <div class="mix-row"><span title="${escapeHTML(item.name)}">${escapeHTML(item.name)}</span><div class="mix-bar"><i style="width:${Math.max(6, item.count / max * 100)}%"></i></div><b>${item.count}</b></div>
  `).join("") : `<div class="empty-state" style="min-height:200px"><strong>No active attacks</strong></div>`;
}

function drawBoundaryChart(data) {
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
  const distribution = data.validation?.risk_distribution || {};
  const legitimate = Array.isArray(distribution.legitimate) ? distribution.legitimate : [];
  const attacks = Array.isArray(distribution.attack) ? distribution.attack : [];
  if (!legitimate.length || !attacks.length) return;
  const pad = { top: 18, right: 16, bottom: 28, left: 28 };
  const chartWidth = width - pad.left - pad.right;
  const chartHeight = height - pad.top - pad.bottom;
  const totals = [legitimate, attacks].map((values) => Math.max(1, values.reduce((sum, value) => sum + value, 0)));
  const rates = [legitimate.map((value) => value / totals[0]), attacks.map((value) => value / totals[1])];
  const maxRate = Math.max(0.05, ...rates[0], ...rates[1]) * 1.15;
  ctx.strokeStyle = "#e5e2dc";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i += 1) {
    const y = pad.top + chartHeight * (i / 4);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(width - pad.right, y); ctx.stroke();
  }
  const groupWidth = chartWidth / legitimate.length;
  const barWidth = Math.max(4, groupWidth * .28);
  rates[0].forEach((rate, index) => {
    const x = pad.left + index * groupWidth + groupWidth * .16;
    const legitimateHeight = chartHeight * (rate / maxRate);
    const attackHeight = chartHeight * ((rates[1][index] || 0) / maxRate);
    ctx.fillStyle = "rgba(22,135,127,.72)";
    ctx.fillRect(x, pad.top + chartHeight - legitimateHeight, barWidth, legitimateHeight);
    ctx.fillStyle = "rgba(217,79,32,.78)";
    ctx.fillRect(x + barWidth + 2, pad.top + chartHeight - attackHeight, barWidth, attackHeight);
  });
  const threshold = boundedRatio(data.metrics?.threshold || .5);
  const thresholdX = pad.left + chartWidth * threshold;
  ctx.save();
  ctx.setLineDash([5, 5]);
  ctx.strokeStyle = "#0b0b0b";
  ctx.lineWidth = 1.4;
  ctx.beginPath();
  ctx.moveTo(thresholdX, pad.top);
  ctx.lineTo(thresholdX, pad.top + chartHeight);
  ctx.stroke();
  ctx.restore();
  ctx.fillStyle = "#767773";
  ctx.font = '9px ui-monospace, monospace';
  for (let i = 0; i <= 5; i += 1) ctx.fillText((i / 5).toFixed(1), pad.left + chartWidth * (i / 5) - 7, height - 9);
  ctx.fillStyle = "#0b0b0b";
  ctx.fillText(`THRESHOLD ${threshold.toFixed(2)}`, Math.min(width - 96, thresholdX + 5), pad.top + 11);
}

function renderOverview() {
  const data = state.overview;
  if (!data) return;
  const metrics = data.metrics || {};
  const system = data.system || {};
  const history = Array.isArray(data.history) ? data.history : [];
  const latest = history.at(-1) || { f1: metrics.f1 || 0, attack_coverage: data.detected_attack_coverage || 0 };
  const previous = history.at(-2) || latest;
  const f1Delta = latest.f1 - previous.f1;
  $("#kpi-f1").textContent = pct(metrics.f1);
  $("#kpi-f1-delta").textContent = `${f1Delta >= 0 ? "+" : ""}${pct(f1Delta)} after frontier feedback`;
  $("#kpi-auc").textContent = Number(metrics.auc || 0).toFixed(3);
  $("#kpi-fpr").textContent = pct(metrics.false_positive_rate);
  $("#kpi-coverage").textContent = latest.attack_coverage;
  $("#kpi-catalog-size").textContent = data.catalog_size;
  $("#intro-model").textContent = system.model_version || "model unavailable";
  $("#topbar-model").textContent = system.model_version || "model unavailable";
  $("#intro-time").textContent = new Date(data.generated_at).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" });
  $("#last-sync").textContent = `synced ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  $("#cycle-badge").textContent = `CYCLE ${String(data.cycle).padStart(2, "0")}`;
  $("#side-cycle").textContent = `Cycle ${String(data.cycle).padStart(2, "0")}`;
  $("#loop-identify").textContent = data.catalog_size;
  $("#loop-generate").textContent = compactNumber(data.training_rows);
  $("#loop-defend").textContent = pct(metrics.recall, 0);
  $("#loop-learn").textContent = `C${data.cycle}`;
  $("#loop-queue").textContent = `${state.feedbackQueued} rows`;
  $("#side-feedback").textContent = `${state.feedbackQueued} queued`;
  $("#topbar-feedback").textContent = `${state.feedbackQueued} queued`;
  $("#threshold-value").textContent = Number(metrics.threshold).toFixed(2);
  $("#latency-p95").textContent = `${Number(system.latency_ms_p95 || 0).toFixed(2)} ms`;
  renderTransactions(data.recent_transactions || []);
  renderAttackMix(data.attack_mix || []);
  const activeCoverage = Number(data.detected_attack_coverage || 0);
  const catalogSize = Math.max(1, Number(data.catalog_size || 0));
  $("#coverage-ring").style.setProperty("--coverage", `${boundedRatio(activeCoverage / catalogSize) * 100}%`);
  $("#coverage-ring-value").textContent = `${activeCoverage}/${data.catalog_size}`;
  $("#coverage-title").textContent = activeCoverage === data.catalog_size ? "Full stream coverage" : "Current stream coverage";
  drawBoundaryChart(data);
  renderDefense();
}

function renderAttackTable() {
  const query = ($("#attack-search")?.value || "").trim().toLowerCase();
  const rows = (Array.isArray(state.attacks) ? state.attacks : []).filter((attack) => {
    const matchesSeverity = state.severityFilter === "all" || attack.severity === state.severityFilter;
    const haystack = `${attack.name} ${attack.family} ${attack.rail} ${attack.channel} ${attack.genai_role}`.toLowerCase();
    return matchesSeverity && haystack.includes(query);
  });
  $("#attack-count").textContent = rows.length;
  $("#attack-count-meta").textContent = `${state.attacks.length} total scenarios in catalog`;
  $("#attack-table-body").innerHTML = rows.length ? rows.map((attack) => {
    const detection = attack.detection_rate == null ? 0 : boundedRatio(attack.detection_rate);
    return `
      <tr>
        <td><span class="attack-name"><i class="severity-dot ${escapeHTML(attack.severity)}"></i>${escapeHTML(attack.name)}</span><span class="attack-id">${escapeHTML(attack.id)} / ${escapeHTML(attack.novelty)} novelty</span></td>
        <td><span class="family-tag">${escapeHTML(String(attack.family || "unknown").replaceAll("_", " "))}</span></td>
        <td><span class="tx-main">${escapeHTML(attack.rail)}</span><span class="tx-sub">${escapeHTML(attack.channel)}</span></td>
        <td><span class="genai-copy">${escapeHTML(attack.genai_role)}</span></td>
        <td><div class="detection-meter"><div class="risk-track"><span style="width:${detection * 100}%"></span></div><b class="mono">${attack.detection_rate == null ? "—" : pct(detection, 0)}</b></div></td>
        <td><button class="table-action" data-attack-detail="${escapeHTML(attack.id)}" title="Inspect ${escapeHTML(attack.name)}" aria-label="Inspect ${escapeHTML(attack.name)}"><i data-lucide="scan-eye"></i></button><button class="table-action" data-attack-run="${escapeHTML(attack.id)}" title="Simulate ${escapeHTML(attack.name)}" aria-label="Simulate ${escapeHTML(attack.name)}"><i data-lucide="play"></i></button></td>
      </tr>`;
  }).join("") : `<tr><td colspan="6" class="empty-table">No scenarios match this search. Clear the query or choose All.</td></tr>`;
  $$('[data-attack-run]').forEach((button) => button.addEventListener("click", () => {
    state.selectedAttacks = new Set([button.dataset.attackRun]);
    switchView("simulate");
  }));
  $$('[data-attack-detail]').forEach((button) => button.addEventListener("click", () => openAttackDialog(button.dataset.attackDetail)));
  refreshIcons();
}

function openAttackDialog(attackId) {
  const attack = state.attacks.find((item) => item.id === attackId);
  if (!attack) return;
  $("#attack-dialog-title").textContent = attack.name;
  $("#attack-dialog-content").innerHTML = `
    <div class="detail-metrics"><div><span>SEVERITY</span><strong>${escapeHTML(attack.severity)}</strong></div><div><span>RAIL</span><strong>${escapeHTML(attack.rail)}</strong></div><div><span>READINESS</span><strong>${escapeHTML(attack.readiness || "simulated")}</strong></div></div>
    <section class="detail-section"><span>WHY IT MATTERS</span><p>${escapeHTML(attack.description)}</p></section>
    <section class="detail-section"><span>SIMULATION RECIPE</span><p>${escapeHTML(attack.simulation_recipe)}</p></section>
    <section class="detail-section"><span>LEADING SIGNALS</span><div class="reason-list">${(attack.leading_signals || []).map((item) => `<div class="reason-row"><span>${escapeHTML(item)}</span><b>signal</b></div>`).join("")}</div></section>
    <section class="detail-section"><span>MITIGATIONS</span><div class="reason-list">${(attack.mitigations || []).map((item) => `<div class="reason-row"><span>${escapeHTML(item)}</span><b>control</b></div>`).join("")}</div></section>`;
  $("#attack-dialog").showModal();
  refreshIcons();
}

function renderScenarioPicker() {
  const container = $("#scenario-picker");
  if (!container) return;
  const attacks = Array.isArray(state.attacks) ? state.attacks : [];
  const summary = $("#scenario-selection-summary");
  if (summary) summary.textContent = `${state.selectedAttacks.size} selected`;
  container.innerHTML = attacks.map((attack) => `
    <button class="scenario-option ${state.selectedAttacks.has(attack.id) ? "selected" : ""}" aria-pressed="${state.selectedAttacks.has(attack.id)}" data-scenario-id="${escapeHTML(attack.id)}" type="button">
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
  $("#sim-fps-denominator").textContent = `${result.false_positives} / ${result.controls} controls`;
  $("#sim-risk").textContent = pct(result.mean_risk, 0);
  $("#sim-rate").textContent = pct(result.detection_rate);
  $("#result-bar-fill").style.width = `${result.detection_rate * 100}%`;
  const stats = result.scenario_stats || {};
  $("#fidelity-strip").innerHTML = `<strong>Fidelity check:</strong> ${stats.coverage || 0} scenario recipes across ${stats.attacks || result.generated} attack events.`;
  $("#sim-samples").innerHTML = (Array.isArray(result.sample) ? result.sample : []).map((row) => `
    <div class="sample-row"><div class="sample-name"><strong>${escapeHTML(row.attack_name)}</strong><span>${escapeHTML(row.id)} / ${escapeHTML(row.rail)}</span></div><div class="sample-risk">${pct(row.risk_score, 0)} risk</div>${decisionHTML(row.decision)}</div>
  `).join("");
  state.feedbackQueued = result.feedback_ready;
  $("#simulation-queue").textContent = result.feedback_ready;
  $("#side-feedback").textContent = `${result.feedback_ready} queued`;
  $("#loop-queue").textContent = `${result.feedback_ready} rows`;
}

function renderFidelity(data) {
  state.fidelity = data;
  $("#fidelity-distance").textContent = Number(data.mean_feature_distance || 0).toFixed(3);
  $("#fidelity-scenario-distance").textContent = Number(data.scenario_mix_distance || 0).toFixed(3);
  $("#fidelity-unseen-recall").textContent = pct(data.robustness?.unseen_attack_families?.attack_recall || 0);
  $("#fidelity-friction").textContent = Number(data.policy_tradeoff?.estimated_customer_friction || 0).toFixed(3);
  const robustness = data.robustness || {};
  const rows = [
    ["Known low-intensity", robustness.known_low_intensity],
    ["Unseen attack families", robustness.unseen_attack_families],
    ["Missing features", robustness.missing_features],
    ["Legitimate baseline", robustness.legitimate_baseline],
    ["Adversarial accuracy", { attack_recall: robustness.adversarial ? robustness.adversarial.adversarial_accuracy : 0 }],
  ];
  $("#robustness-list").innerHTML = rows.map(([label, value]) => `<div class="importance-row"><span>${label}</span><div class="importance-bar"><i style="width:${Math.max(3, Number(value?.attack_recall || 0) * 100)}%"></i></div><b>${pct(value?.attack_recall || 0)}</b></div>`).join("");
  const policy = data.policy_tradeoff || {};
  $("#policy-tradeoff").innerHTML = `<div class="importance-row"><span>Actions</span><div class="importance-bar"><i style="width:100%"></i></div><b>${Object.values(policy.actions || {}).reduce((sum, item) => sum + item, 0)}</b></div><div class="importance-row"><span>Expected loss</span><div class="importance-bar"><i style="width:${Math.min(100, Number(policy.estimated_expected_loss || 0) / 100)}%"></i></div><b>${Number(policy.estimated_expected_loss || 0).toFixed(2)}</b></div><div class="importance-row"><span>Customer friction</span><div class="importance-bar"><i style="width:${Math.min(100, Number(policy.estimated_customer_friction || 0) * 100)}%"></i></div><b>${Number(policy.estimated_customer_friction || 0).toFixed(3)}</b></div>`;
}

function renderMutation(data) {
  state.mutation = data;
  const candidates = data.candidates || [];
  $("#mutation-result").className = "sample-list";
  $("#mutation-result").innerHTML = `<div class="fidelity-strip"><strong>Safety boundary:</strong> ${escapeHTML(data.safety || "synthetic feature mutations only")}</div><div class="sample-row"><div class="sample-name"><strong>Original ${escapeHTML(data.original?.id || "attack")}</strong><span>${escapeHTML(data.original?.attack_id || "synthetic attack")} / ${pct(data.original?.risk_score || 0)} risk</span></div><div class="sample-risk">${data.blind_spots || 0} blind spots</div><span class="decision review">SEARCHED</span></div>${candidates.map((candidate) => `<div class="sample-row"><div class="sample-name"><strong>${escapeHTML(candidate.transaction?.mutation_id || "candidate")}</strong><span>${(candidate.mutations || []).map((item) => escapeHTML(item.feature)).join(" + ")}</span></div><div class="sample-risk">${pct(candidate.risk_score)} risk</div><span class="decision ${candidate.detected ? "decline" : "approve"}">${candidate.detected ? "DETECTED" : "BLIND SPOT"}</span></div>`).join("")}`;
}

function openTransactionDialog(transactionId) {
  const row = state.transactionIndex.get(transactionId);
  if (!row) return;
  $("#transaction-dialog-title").textContent = `${row.id} / ${String(row.decision || "review").toUpperCase()}`;
  const explanations = row.explanations || [];
  $("#transaction-dialog-content").innerHTML = `
    <div class="detail-metrics"><div><span>RISK SCORE</span><strong>${pct(row.risk_score, 0)}</strong></div><div><span>AMOUNT</span><strong>${money(row.amount, row.currency)}</strong></div><div><span>CONTEXT</span><strong>${escapeHTML(row.rail)} / ${escapeHTML(row.channel)}</strong></div></div>
    <section class="detail-section"><span>PAYMENT CONTEXT</span><p>${escapeHTML(row.attack_name || "Legitimate payment baseline")} / ${escapeHTML(row.country || "unknown country")}</p></section>
    <section class="detail-section"><span>REASON CODES</span>${explanations.length ? `<div class="reason-list">${explanations.map((item) => `<div class="reason-row"><span>${escapeHTML(item.label)}</span><div class="reason-bar"><i style="width:${Math.min(100, Math.max(8, Number(item.contribution || 0) * 32))}%"></i></div><b>${Number(item.contribution || 0).toFixed(2)}</b></div>`).join("")}</div>` : "<p>No elevated model contribution crossed the explanation floor.</p>"}</section>
    <section class="detail-section"><span>RECOMMENDED ACTION</span><p>${row.decision === "approve" ? "Approve and continue monitoring." : row.decision === "decline" ? "Decline and retain the model reasons for review." : "Step up or route to analyst review before authorization."}</p></section>
    <section class="detail-section"><span>ANALYST OUTCOME</span><div class="segmented feedback-actions"><button data-feedback-outcome="confirmed_fraud" type="button">CONFIRMED FRAUD</button><button data-feedback-outcome="confirmed_legitimate" type="button">LEGITIMATE</button><button data-feedback-outcome="uncertain" type="button">UNCERTAIN</button></div></section>`;
  $("#transaction-dialog").showModal();
  $$('[data-feedback-outcome]', $("#transaction-dialog-content")).forEach((button) => {
    const feedbackAvailable = state.capabilities?.has("feedback");
    button.disabled = !feedbackAvailable;
    if (!feedbackAvailable) button.title = isOfflineDemo() ? OFFLINE_ACTION_MESSAGE : OUTDATED_BACKEND_MESSAGE;
    button.addEventListener("click", async () => {
      if (!requireCapability("feedback")) return;
      try {
        await requestJSON("/api/feedback", { method: "POST", body: JSON.stringify({ transaction_id: row.id, outcome: button.dataset.feedbackOutcome }) });
        toast(`Analyst outcome recorded for ${row.id}.`);
        button.parentElement.querySelectorAll("button").forEach((item) => item.disabled = true);
      } catch (error) {
        toast(`Feedback failed: ${error.message}`);
      }
    });
  });
  refreshIcons();
}

function renderDefense() {
  if (!state.overview) return;
  const { metrics = {}, feature_importance: rawImportance = [], history = [], cycle = 0, system = {} } = state.overview;
  const importance = Array.isArray(rawImportance) ? rawImportance : [];
  $("#defense-version").textContent = `C${String(cycle).padStart(2, "0")}`;
  $("#def-precision").textContent = pct(metrics.precision);
  $("#def-recall").textContent = pct(metrics.recall);
  $("#def-specificity").textContent = pct(metrics.specificity);
  $("#def-threshold").textContent = Number(metrics.threshold).toFixed(2);
  const matrix = metrics.confusion_matrix || { tp: 0, fn: 0, fp: 0, tn: 0 };
  $("#matrix-tp").textContent = matrix.tp;
  $("#matrix-fn").textContent = matrix.fn;
  $("#matrix-fp").textContent = matrix.fp;
  $("#matrix-tn").textContent = matrix.tn;
  const holdoutSize = Object.values(matrix).reduce((sum, value) => sum + value, 0);
  $("#matrix-footnote").textContent = `Untouched generated holdout / N ${holdoutSize}.`;
  const maxImportance = Math.max(0.01, ...importance.map((item) => Number(item.importance || 0)));
  $("#importance-list").innerHTML = importance.slice(0, 10).map((item) => `
    <div class="importance-row"><span title="${escapeHTML(item.label)}">${escapeHTML(item.label)}</span><div class="importance-bar"><i style="width:${Math.max(3, Number(item.importance || 0) / maxImportance * 100)}%"></i></div><b>${Number(item.importance || 0).toFixed(2)}</b></div>
  `).join("");
  $("#history-list").innerHTML = history.map((item) => `
    <div class="history-item"><span>CYCLE ${String(item.cycle).padStart(2, "0")}</span><strong>${escapeHTML(item.name)}</strong><div class="history-stats"><span>F1 <b>${pct(item.f1)}</b></span><span>RECALL <b>${pct(item.recall)}</b></span><span>FPR <b>${pct(item.fpr)}</b></span></div></div>
  `).join("") + `<div class="history-item"><span>PRODUCTION SHAPE</span><strong>${escapeHTML(system.model_version)}</strong><div class="history-stats"><span>P95 <b>${system.latency_ms_p95} ms</b></span><span>RAILS <b>6</b></span></div></div>`;
  const models = state.overview.model_versions || [];
  $("#model-lifecycle").innerHTML = models.map((model) => `
    <div class="history-item"><span>${escapeHTML(model.status || "UNKNOWN")}</span><strong>${escapeHTML(model.version)}</strong><div class="history-stats"><span>F1 <b>${pct(model.immutable_holdout_metrics?.f1 || 0)}</b></span><span>ROWS <b>${compactNumber(model.training_rows || 0)}</b></span>${model.status !== "ACTIVE" && model.status !== "REJECTED" ? `<button class="table-action" data-rollback-model="${escapeHTML(model.version)}" title="Rollback to ${escapeHTML(model.version)}" aria-label="Rollback to ${escapeHTML(model.version)}"><i data-lucide="undo-2"></i></button>` : ""}</div></div>
  `).join("") || `<div class="empty-state"><strong>No model metadata yet.</strong></div>`;
  $$('[data-rollback-model]').forEach((button) => button.addEventListener("click", () => rollbackModel(button.dataset.rollbackModel)));
  refreshIcons();
}

async function rollbackModel(modelVersion) {
  if (!state.capabilities?.has("rollback")) {
    toast(OUTDATED_BACKEND_MESSAGE);
    return;
  }
  try {
    const result = await requestJSON("/api/models/rollback", { method: "POST", body: JSON.stringify({ model_version: modelVersion }) });
    toast(`Rolled back to ${result.model_version}.`);
    await refreshData();
  } catch (error) {
    toast(`Rollback failed: ${error.message}`);
  }
}

async function loadData() {
  setConnectionStatus("loading");
  try {
    const [health, overview, attackPayload] = await Promise.all([
      requestJSON("/api/health"),
      requestJSON("/api/overview"),
      requestJSON("/api/attacks"),
    ]);
    state.overview = overview;
    state.attacks = Array.isArray(attackPayload.attacks) ? attackPayload.attacks : [];
    state.feedbackQueued = Number(overview.feedback_queue_size || 0);
    const currentBackend = updateCapabilities(health);
    setConnectionStatus(isOfflineDemo() ? "offline" : currentBackend ? "live" : "outdated");
    renderOverview();
    renderAttackTable();
    renderScenarioPicker();
    if (!currentBackend && !isOfflineDemo()) toast(OUTDATED_BACKEND_MESSAGE);
  } catch (error) {
    setConnectionStatus("error");
    toast(`Could not load the defense lab: ${error.message}`);
  }
}

async function loadFidelity() {
  if (!requireCapability("fidelity")) return;
  try {
    const result = await requestJSON("/api/fidelity");
    renderFidelity(result);
  } catch (error) {
    toast(`Evidence run failed: ${error.message}`);
  }
}

async function exportReport() {
  if (!requireCapability("report")) return;
  try {
    const report = await requestJSON("/api/report");
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `mastershield-synthetic-report-c${report.cycle}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    toast("Synthetic evaluation report exported.");
  } catch (error) {
    toast(`Export failed: ${error.message}`);
  }
}

async function runMutation() {
  if (!requireCapability("mutate")) return;
  const button = $("#run-mutation");
  const oldHTML = button.innerHTML;
  button.disabled = true;
  button.textContent = "Searching synthetic variants...";
  try {
    const result = await requestJSON("/api/mutate", { method: "POST", body: JSON.stringify({ count: 24 }) });
    renderMutation(result);
    toast(`${result.blind_spots} synthetic blind spots found in ${result.candidate_count} candidates.`);
  } catch (error) {
    toast(`Mutation search failed: ${error.message}`);
  } finally {
    button.disabled = false;
    button.innerHTML = oldHTML;
    refreshIcons();
  }
}

async function refreshData() {
  const [overview, attackPayload] = await Promise.all([requestJSON("/api/overview"), requestJSON("/api/attacks")]);
  state.overview = overview;
  state.attacks = Array.isArray(attackPayload.attacks) ? attackPayload.attacks : [];
  state.feedbackQueued = Number(overview.feedback_queue_size || state.feedbackQueued || 0);
  renderOverview();
  renderAttackTable();
  renderScenarioPicker();
}

async function runSimulation() {
  if (!requireCapability("simulate")) return;
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
    await refreshData();
  } catch (error) {
    toast(`Simulation failed: ${error.message}`);
  } finally {
    button.disabled = false;
    button.innerHTML = oldHTML;
    refreshIcons();
  }
}

async function retrainModel() {
  if (!requireCapability("retrain")) return;
  const button = $("#retrain-button");
  const oldHTML = button.innerHTML;
  button.disabled = true;
  button.textContent = "Retraining…";
  try {
    const result = await requestJSON("/api/retrain", { method: "POST", body: "{}" });
    state.feedbackQueued = 0;
    $("#simulation-queue").textContent = "0";
    await refreshData();
    const f1Delta = result.deltas.f1;
    const duration = Number(result.duration_ms || 0);
    toast(`${result.accepted ? "Promoted" : "Rejected"} challenger ${result.candidate_model_version} after ${(duration / 1000).toFixed(1)}s. F1 ${f1Delta >= 0 ? "+" : ""}${pct(f1Delta)}.`);
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
  $("#attack-search")?.addEventListener("input", renderAttackTable);
  $$(".filter-button").forEach((button) => button.addEventListener("click", () => {
    state.severityFilter = button.dataset.filter;
    $$(".filter-button").forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", String(active));
    });
    renderAttackTable();
  }));
  $("#volume-slider")?.addEventListener("input", (event) => {
    $("#volume-output").textContent = `${event.target.value} events`;
  });
  $$("#intensity-picker button").forEach((button) => button.addEventListener("click", () => {
    state.intensity = Number(button.dataset.intensity);
    $$("#intensity-picker button").forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", String(active));
    });
  }));
  $("#select-all-scenarios")?.addEventListener("click", () => {
    state.selectedAttacks = new Set(state.attacks.map((attack) => attack.id));
    renderScenarioPicker();
  });
  $("#clear-scenarios")?.addEventListener("click", () => {
    state.selectedAttacks.clear();
    renderScenarioPicker();
  });
  $("#load-demo-scenario")?.addEventListener("click", () => {
    state.selectedAttacks = new Set(["atk-001", "atk-009", "atk-016", "atk-023"]);
    state.intensity = 1.28;
    $("#volume-slider").value = "120";
    $("#volume-output").textContent = "120 events";
    $$("#intensity-picker button").forEach((item) => {
      const active = item.dataset.intensity === "1.28";
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", String(active));
    });
    renderScenarioPicker();
    toast("Judge demo loaded: deepfake, OTP relay, recovery, and voice replay.");
  });
  $("#run-simulation")?.addEventListener("click", runSimulation);
  $("#retrain-button")?.addEventListener("click", retrainModel);
  $("#refresh-fidelity")?.addEventListener("click", loadFidelity);
  $("#export-report")?.addEventListener("click", exportReport);
  $("#run-mutation")?.addEventListener("click", runMutation);
  $("#refresh-overview")?.addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await refreshData();
      toast("Operating picture refreshed.");
    } catch (error) {
      setConnectionStatus("error");
      toast(`Refresh failed: ${error.message}`);
    } finally {
      button.disabled = false;
    }
  });
  $$('[data-dialog-close]').forEach((button) => button.addEventListener("click", () => $("#" + button.dataset.dialogClose).close()));
  $("#transaction-dialog").addEventListener("click", (event) => { if (event.target === event.currentTarget) event.currentTarget.close(); });
  $("#attack-dialog").addEventListener("click", (event) => { if (event.target === event.currentTarget) event.currentTarget.close(); });
  window.addEventListener("resize", () => state.overview && $("#view-overview").classList.contains("active") && drawBoundaryChart(state.overview));
}

document.addEventListener("DOMContentLoaded", () => {
  refreshIcons();
  bindRevealMotion();
  bindEvents();
  loadData();
  setInterval(() => requestJSON("/api/health").then((health) => {
    const currentBackend = updateCapabilities(health);
    setConnectionStatus(isOfflineDemo() ? "offline" : currentBackend ? "live" : "outdated");
  }).catch(() => setConnectionStatus("error")), 30000);
});
