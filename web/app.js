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
  fidelityLoading: false,
  mutation: null,
  securityScore: null,
  overviewRefreshing: false,
  evaluationThreshold: null,
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
const DISPLAY_TIME_ZONE = "Asia/Kolkata";
const LIVE_OVERVIEW_REFRESH_MS = 15000;

const INDIA_EXTERNAL_EVIDENCE = [
  {
    metric: "65.89 lakh+",
    label: "financial-fraud complaints",
    period: "India / 2021-2025",
    detail: "NCRP and CFCFRMS recorded more than ₹55,050 crore in reported financial fraud. This supports coverage of social engineering, account takeover, mule networks, and transfer scams.",
    source: "MHA / I4C via PIB",
    url: "https://www.pib.gov.in/PressReleasePage.aspx?PRID=2287039&reg=1&lang=1",
  },
  {
    metric: "1,01,928",
    label: "registered cybercrime cases",
    period: "India / 2024",
    detail: "NCRB data lists fraud as the largest named cybercrime head, with 29,758 cases. This supports fraud-focused prioritisation, not a production accuracy claim.",
    source: "NCRB / MHA via PIB",
    url: "https://www.pib.gov.in/PressReleasePage.aspx?PRID=2287039&reg=1&lang=1",
  },
  {
    metric: "23,658.35 Mn",
    label: "monthly UPI transactions",
    period: "India / July 2026",
    detail: "NPCI reports ₹29,87,880.49 crore in monthly UPI value. This scale motivates real-time velocity, beneficiary, device, graph, and behavioural controls.",
    source: "NPCI UPI statistics",
    url: "https://www.npci.org.in/product/upi/product-statistics",
  },
  {
    metric: "36,075",
    label: "bank frauds reported",
    period: "India / FY 2023-24",
    detail: "RBI states that card and internet payments were the predominant fraud category by number, supporting payment-channel and digital-session risk signals.",
    source: "RBI Annual Report 2023-24",
    url: "https://rbi.org.in/scripts/AnnualReportPublications.aspx?Id=1406",
  },
];

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

function calculateSecurityScore(data, metrics, recentRows) {
  const attackRows = recentRows.filter((row) => row.attack_id || Number(row.label) === 1);
  const legitimateRows = recentRows.filter((row) => !row.attack_id && Number(row.label) !== 1);
  const liveRecall = attackRows.length
    ? attackRows.filter((row) => row.decision !== "approve").length / attackRows.length
    : Number(metrics.recall || 0);
  const liveFalsePositiveRate = legitimateRows.length
    ? legitimateRows.filter((row) => row.decision !== "approve").length / legitimateRows.length
    : Number(metrics.false_positive_rate || 0);
  const catalogSize = Math.max(1, Number(data.catalog_size || 0));
  const coverage = boundedRatio(Number(data.detected_attack_coverage || 0) / catalogSize);
  const modelQuality = (
    Number(metrics.precision || 0) * 0.25
    + Number(metrics.recall || 0) * 0.35
    + Number(metrics.specificity || 0) * 0.25
    + (1 - Number(metrics.false_positive_rate || 0)) * 0.15
  );
  const liveQuality = liveRecall * 0.30 + (1 - liveFalsePositiveRate) * 0.15 + coverage * 0.10;
  const queuePressure = Math.min(0.08, Number(data.feedback_queue_size || 0) / Math.max(50, recentRows.length) * 0.08);
  return Math.round(Math.max(0, Math.min(100, (modelQuality * 0.45 + liveQuality) * 100 * (1 - queuePressure))) * 10) / 10;
}

function renderSecurityScore(nextScore) {
  const score = Math.max(0, Math.min(100, Number(nextScore || 0)));
  const hasPrevious = Number.isFinite(state.securityScore);
  const previous = hasPrevious ? state.securityScore : score;
  const delta = hasPrevious ? score - state.securityScore : null;
  state.securityScore = score;
  const kpi = $("#kpi-f1");
  const gaugeValue = $("#security-score");
  const gauge = $("#risk-gauge");
  const paint = (value) => {
    const label = value.toFixed(1);
    if (kpi) kpi.textContent = label;
    if (gaugeValue) gaugeValue.textContent = label;
    if (gauge) gauge.style.setProperty("--score", `${value * 3.6}deg`);
  };
  if (!hasPrevious || window.matchMedia?.("(prefers-reduced-motion: reduce)").matches || Math.abs(score - previous) < 0.05) {
    paint(score);
    return delta;
  }
  const started = performance.now();
  const duration = 700;
  const step = (timestamp) => {
    const progress = Math.min(1, (timestamp - started) / duration);
    const eased = 1 - ((1 - progress) ** 3);
    paint(previous + (score - previous) * eased);
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
  return delta;
}

function compactNumber(value) {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(Number(value || 0));
}

function formatIST(value, options) {
  return `${new Intl.DateTimeFormat("en-GB", { timeZone: DISPLAY_TIME_ZONE, ...options }).format(new Date(value))} IST`;
}

function money(value, currency = "USD") {
  const currencyCode = String(currency || "USD").trim().toUpperCase();
  try {
    return new Intl.NumberFormat("en", {
      style: "currency",
      currency: currencyCode,
      maximumFractionDigits: Number(value || 0) > 1000 ? 0 : 2,
    }).format(Number(value || 0));
  } catch (_error) {
    return `${currencyCode || "USD"} ${Number(value || 0).toFixed(2)}`;
  }
}

function refreshIcons() {
  if (window.lucide) window.lucide.createIcons({ attrs: { "stroke-width": 1.7 } });
}

function renderExternalEvidence() {
  const container = $("#external-evidence-list");
  if (!container) return;
  container.innerHTML = INDIA_EXTERNAL_EVIDENCE.map((item) => `
    <article class="external-evidence-row">
      <div class="external-evidence-metric"><strong>${escapeHTML(item.metric)}</strong><span>${escapeHTML(item.label)}</span></div>
      <div class="external-evidence-copy"><span class="external-evidence-period">${escapeHTML(item.period)}</span><p>${escapeHTML(item.detail)}</p></div>
      <a href="${escapeHTML(item.url)}" target="_blank" rel="noreferrer" aria-label="Open ${escapeHTML(item.source)} source"><span>${escapeHTML(item.source)}</span><i data-lucide="external-link"></i></a>
    </article>
  `).join("");
  refreshIcons();
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

function renderBreadcrumb(viewName) {
  const navLabel = $(`.nav-item[data-view="${viewName}"] span`)?.textContent || viewName.replaceAll("-", " ");
  const compact = window.matchMedia("(max-width: 760px)").matches;
  $("#crumb-view").textContent = (compact ? navLabel.split(" ").at(-1) : navLabel).toUpperCase();
}

function revealActiveView(viewName) {
  const activeView = $(`#view-${viewName}`);
  if (!activeView) return;
  $$('[data-reveal="pending"]', activeView).forEach((node) => { node.dataset.reveal = "visible"; });
}

function switchView(viewName) {
  const previousView = document.body.dataset.view;
  document.body.dataset.view = viewName;
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${viewName}`));
  $$(".nav-item").forEach((item) => {
    const active = item.dataset.view === viewName;
    item.classList.toggle("active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  renderBreadcrumb(viewName);
  revealActiveView(viewName);
  if (previousView !== viewName) window.scrollTo({ top: 0, behavior: "smooth" });
  if (viewName === "attacks") renderAttackTable();
  if (viewName === "simulate") renderScenarioPicker();
  if (viewName === "defense") { renderDefense(); activatePipeline("#risk-engine-pipeline"); }
  if (viewName === "overview" && state.overview) requestAnimationFrame(() => { drawBoundaryChart(state.overview); drawEvaluationCurves(state.overview); });
  if (viewName === "evidence" && state.overview) requestAnimationFrame(() => drawEvaluationCurves(state.overview));
  if (viewName === "fidelity" && !state.fidelity) loadFidelity();
}

function openCommandPalette() {
  const palette = $("#command-palette");
  if (!palette) return;
  palette.showModal();
  const search = $("#command-search");
  if (search) search.value = "";
  renderCommandResults("");
  $$('[data-command-view]', $("#command-list")).forEach((item) => { item.hidden = false; });
  requestAnimationFrame(() => $("#command-search")?.focus());
}

function renderCommandResults(query) {
  const target = $("#command-results");
  if (!target) return;
  const normalized = String(query || "").trim().toLowerCase();
  if (!normalized) {
    target.hidden = true;
    target.innerHTML = "";
    return;
  }
  const transactions = [...state.transactionIndex.values()].filter((row) => {
    const haystack = [row.id, row.customer_id, row.merchant_id, row.device_id, row.country, row.rail, row.channel, row.attack_name, row.decision].join(" ").toLowerCase();
    return haystack.includes(normalized);
  }).slice(0, 5);
  const threats = (Array.isArray(state.attacks) ? state.attacks : []).filter((attack) => {
    const haystack = [attack.id, attack.name, attack.family, attack.rail, attack.channel, attack.severity, attack.genai_role].join(" ").toLowerCase();
    return haystack.includes(normalized);
  }).slice(0, 5);
  const resultCount = transactions.length + threats.length;
  target.hidden = false;
  target.innerHTML = resultCount ? `${transactions.length ? `<div class="command-result-group"><span class="command-result-label">TRANSACTIONS / ENTITIES</span>${transactions.map((row) => `<button type="button" data-command-transaction="${escapeHTML(row.id)}"><i data-lucide="scan-eye"></i><span><strong>${escapeHTML(row.id)}</strong><small>${escapeHTML(row.attack_name || "legitimate baseline")} · ${escapeHTML(row.customer_id || "customer")}</small></span><b>${escapeHTML(String(row.decision || "review").toUpperCase())}</b></button>`).join("")}</div>` : ""}${threats.length ? `<div class="command-result-group"><span class="command-result-label">THREAT SCENARIOS</span>${threats.map((attack) => `<button type="button" data-command-attack="${escapeHTML(attack.id)}"><i data-lucide="scan-search"></i><span><strong>${escapeHTML(attack.name)}</strong><small>${escapeHTML(attack.family || "scenario")} · ${escapeHTML(attack.severity || "synthetic")}</small></span><b>THREAT</b></button>`).join("")}</div>` : ""}` : `<div class="command-no-results">No matching synthetic transactions, entities, or threats.</div>`;
  refreshIcons();
  $$('[data-command-transaction]', target).forEach((button) => button.addEventListener("click", () => {
    $("#command-palette")?.close();
    openTransactionDialog(button.dataset.commandTransaction);
  }));
  $$('[data-command-attack]', target).forEach((button) => button.addEventListener("click", () => {
    $("#command-palette")?.close();
    openAttackDialog(button.dataset.commandAttack);
  }));
}

function bindCommandPalette() {
  $("#command-trigger")?.addEventListener("click", openCommandPalette);
  $("#search-trigger")?.addEventListener("click", openCommandPalette);
  $("#command-search")?.addEventListener("input", (event) => {
    const query = event.target.value.trim().toLowerCase();
    $$("[data-command-view]", $("#command-list")).forEach((item) => {
      item.hidden = query && !item.textContent.toLowerCase().includes(query);
    });
    renderCommandResults(query);
  });
  $$('[data-command-view]').forEach((button) => button.addEventListener("click", () => {
    $("#command-palette")?.close();
    switchView(button.dataset.commandView);
  }));
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openCommandPalette();
    }
    if ((event.metaKey || event.ctrlKey) && /^[1-6]$/.test(event.key)) {
      event.preventDefault();
      const view = ["overview", "attacks", "simulate", "defense", "evidence", "fidelity"][Number(event.key) - 1];
      switchView(view);
    }
  });
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
  const prioritized = [...rows].sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
  body.innerHTML = prioritized.slice(0, 8).map((row) => `
    <tr class="event-row severity-${escapeHTML(row.risk_level || "low")}" data-transaction-row="${escapeHTML(row.id)}">
      <td><span class="tx-main">${escapeHTML(row.id)}</span><span class="tx-sub">${escapeHTML(row.attack_name || "legitimate baseline")}</span></td>
      <td><span class="tx-main">${escapeHTML(row.rail)}</span><span class="tx-sub">${escapeHTML(row.channel)}</span></td>
      <td><span class="tx-main">${money(row.amount, row.currency)}</span><span class="tx-sub">${escapeHTML(row.country)}</span></td>
      <td><div class="risk-cell"><div class="risk-track"><span style="width:${boundedRatio(row.risk_score) * 100}%"></span></div><b class="mono">${pct(boundedRatio(row.risk_score), 0)}</b></div></td>
      <td>${decisionHTML(row.decision)}</td>
      <td><button class="table-action" data-transaction-detail="${escapeHTML(row.id)}" title="Explain ${escapeHTML(row.id)}" aria-label="Explain ${escapeHTML(row.id)}"><i data-lucide="scan-eye"></i></button></td>
    </tr>
  `).join("");
  $$('[data-transaction-detail]', body).forEach((button) => button.addEventListener("click", () => openTransactionDialog(button.dataset.transactionDetail)));
  $$('[data-transaction-row]', body).forEach((row) => row.addEventListener("dblclick", () => openTransactionDialog(row.dataset.transactionRow)));
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

function renderThreatLandscape(items) {
  const target = $("#threat-landscape");
  if (!target) return;
  const rows = Array.isArray(items) ? items.slice(0, 7) : [];
  const max = Math.max(1, ...rows.map((item) => Number(item.count || 0)));
  target.innerHTML = rows.length ? rows.map((item, index) => `
    <button class="landscape-row" data-landscape-name="${escapeHTML(item.name)}" type="button" aria-label="Filter by ${escapeHTML(item.name)}">
      <span class="landscape-rank">0${index + 1}</span><span class="landscape-name">${escapeHTML(item.name)}</span><span class="landscape-bar"><i style="width:${Math.max(8, Number(item.count || 0) / max * 100)}%"></i></span><b>${item.count}</b>
    </button>`).join("") : `<div class="landscape-empty">No active threats in the current stream.</div>`;
  $$('[data-landscape-name]', target).forEach((button) => button.addEventListener("click", () => {
    const matching = state.attacks.find((item) => item.name === button.dataset.landscapeName);
    if (matching) {
      state.selectedAttacks = new Set([matching.id]);
      switchView("simulate");
      toast(`Simulation focused on ${matching.name}.`);
    }
  }));
}

function renderAttackBubbles(items) {
  const target = $("#attack-bubble-field");
  if (!target) return;
  const rows = Array.isArray(items) ? items.slice(0, 16) : [];
  const max = Math.max(1, ...rows.map((item) => Number(item.samples || 0)));
  target.innerHTML = rows.length ? rows.map((item, index) => {
    const samples = Number(item.samples || 0);
    const size = 54 + (samples / max) * 48;
    return `<button class="attack-bubble severity-${escapeHTML(item.severity || "Medium")}" style="--bubble-size:${size}px;--bubble-x:${12 + ((index * 29) % 78)}%;--bubble-y:${24 + ((index * 41) % 54)}%" data-bubble-attack="${escapeHTML(item.attack_id || item.id)}" type="button" title="Focus ${escapeHTML(item.name)}"><span>${escapeHTML(item.name)}</span><small>${samples} event${samples === 1 ? "" : "s"}</small></button>`;
  }).join("") : `<div class="network-empty">No attack samples in the current stream.</div>`;
  $$('[data-bubble-attack]', target).forEach((button) => button.addEventListener("click", () => {
    const attack = state.attacks.find((item) => item.id === button.dataset.bubbleAttack);
    if (!attack) return;
    $("#attack-search").value = attack.name;
    renderAttackTable();
    toast(`Threat intelligence focused on ${attack.name}.`);
  }));
}

function renderThreatNetwork(rows) {
  const target = $("#threat-network");
  if (!target) return;
  const candidates = (Array.isArray(rows) ? rows : []).filter((row) => Number(row.risk_score || 0) >= 0.7).slice(0, 3);
  const row = candidates[0] || (Array.isArray(rows) ? rows[0] : null);
  if (!row) {
    target.innerHTML = `<div class="network-empty">Waiting for synthetic events…</div>`;
    return;
  }
  const entities = [
    { key: "customer", label: "CUSTOMER", value: row.customer_id || "c-unknown", x: 14, y: 50, tone: "entity" },
    { key: "transaction", label: "TRANSACTION", value: row.id || "tx-unknown", x: 36, y: 50, tone: "signal", tx: true },
    { key: "merchant", label: "MERCHANT", value: row.merchant_id || "m-unknown", x: 59, y: 27, tone: "entity" },
    { key: "device", label: "DEVICE", value: row.device_id || "d-unknown", x: 59, y: 73, tone: "entity" },
    { key: "ip", label: "NETWORK", value: row.country ? `${row.country} / IP` : "ip reputation", x: 82, y: 26, tone: "signal" },
    { key: "location", label: "LOCATION", value: row.country || "unknown", x: 82, y: 74, tone: "entity" },
    { key: "risk", label: "RISK EVENT", value: `${Math.round(Number(row.risk_score || 0) * 100)} / ${String(row.decision || "review").toUpperCase()}`, x: 91, y: 50, tone: "critical" },
  ];
  const edges = [[0,1],[1,2],[1,3],[2,4],[3,5],[4,6],[5,6]];
  const svg = `<svg class="network-svg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true"><defs><linearGradient id="network-gradient" x1="0" x2="1"><stop stop-color="#eb001b"/><stop offset=".5" stop-color="#ff5f00"/><stop offset=".82" stop-color="#f79e1b"/><stop offset="1" stop-color="#78bfc3"/></linearGradient><filter id="network-glow"><feGaussianBlur stdDeviation=".8" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>${edges.map(([from, to]) => `<line class="network-edge" data-edge-from="${escapeHTML(entities[from].key)}" data-edge-to="${escapeHTML(entities[to].key)}" x1="${entities[from].x}" y1="${entities[from].y}" x2="${entities[to].x}" y2="${entities[to].y}" />`).join("")}</svg>`;
  delete target.dataset.networkSelection;
  target.classList.remove("network-focus");
  target.innerHTML = `${svg}<div class="network-grid-lines"></div>${entities.map((item) => `<button class="network-node ${item.tone} ${item.tx ? "transaction-node" : ""}" style="left:${item.x}%;top:${item.y}%" data-network-node="${escapeHTML(item.key)}" aria-label="Inspect ${escapeHTML(item.label)} ${escapeHTML(item.value)}" ${item.tx ? `data-network-transaction="${escapeHTML(row.id)}"` : ""}><span class="node-orbit"></span><strong>${escapeHTML(item.label)}</strong><small>${escapeHTML(item.value)}</small></button>`).join("")}<div class="network-caption"><span class="status-dot"></span> Tracing selected high-risk event / ${escapeHTML(row.id)}</div>`;
  const nodes = $$('[data-network-node]', target);
  const edgesByNode = new Map(entities.map((item) => [item.key, new Set([item.key])]));
  edges.forEach(([from, to]) => {
    edgesByNode.get(entities[from].key).add(entities[to].key);
    edgesByNode.get(entities[to].key).add(entities[from].key);
  });
  const focusNetworkNode = (key) => {
    const connected = edgesByNode.get(key) || new Set([key]);
    target.classList.add("network-focus");
    nodes.forEach((node) => node.classList.toggle("network-connected", connected.has(node.dataset.networkNode)));
    nodes.forEach((node) => node.classList.toggle("network-dimmed", !connected.has(node.dataset.networkNode)));
    $$('[data-edge-from]', target).forEach((edge) => {
      const active = edge.dataset.edgeFrom === key || edge.dataset.edgeTo === key;
      edge.classList.toggle("network-connected", active);
      edge.classList.toggle("network-dimmed", !active);
    });
  };
  const clearNetworkFocus = () => {
    if (target.dataset.networkSelection) {
      focusNetworkNode(target.dataset.networkSelection);
      return;
    }
    target.classList.remove("network-focus");
    nodes.forEach((node) => node.classList.remove("network-connected", "network-dimmed"));
    $$('[data-edge-from]', target).forEach((edge) => edge.classList.remove("network-connected", "network-dimmed"));
  };
  nodes.forEach((button) => {
    button.addEventListener("mouseenter", () => focusNetworkNode(button.dataset.networkNode));
    button.addEventListener("focus", () => focusNetworkNode(button.dataset.networkNode));
    button.addEventListener("mouseleave", clearNetworkFocus);
    button.addEventListener("blur", clearNetworkFocus);
    button.addEventListener("click", () => {
      target.dataset.networkSelection = button.dataset.networkNode;
      nodes.forEach((node) => node.classList.toggle("network-selected", node === button));
      focusNetworkNode(button.dataset.networkNode);
      openTransactionDialog(button.dataset.networkTransaction || row.id);
    });
  });
}

function renderRobustnessHeatmap(data) {
  const target = $("#robustness-heatmap");
  if (!target) return;
  const robust = data?.robustness || {};
  const grid = robust.robustness_grid || {};
  const fallbackSeries = (value) => [value || 0, value || 0, value || 0, value || 0];
  const rows = [
    ["KNOWN ATTACK", ...(grid.known_attack || fallbackSeries(robust.known_low_intensity?.attack_recall)).map((item) => item.attack_recall ?? item)],
    ["UNKNOWN ATTACK", ...(grid.unknown_attack || fallbackSeries(robust.unseen_attack_families?.attack_recall)).map((item) => item.attack_recall ?? item)],
    ["MISSING FEATURES", ...(grid.missing_features || fallbackSeries(robust.missing_features?.attack_recall)).map((item) => item.attack_recall ?? item)],
    ["BEHAVIOR DRIFT", ...(grid.behavior_drift || fallbackSeries(robust.unseen_attack_families?.attack_recall)).map((item) => item.attack_recall ?? item)],
    ["NOISE", ...(grid.noise || fallbackSeries(robust.legitimate_baseline?.attack_recall)).map((item) => item.attack_recall ?? item)],
  ].map(([label, ...values]) => [label, ...[0, 1, 2, 3].map((index) => values[index] ?? values.at(-1) ?? 0)]);
  const levels = ["LOW", "MEDIUM", "HIGH", "EXTREME"];
  target.innerHTML = `<div class="heatmap-corner">DETECTION RECALL</div>${levels.map((level) => `<div class="heatmap-heading">${level}</div>`).join("")}${rows.map(([label, ...values]) => `<div class="heatmap-row-label">${label}</div>${values.map((value, index) => { const bounded = boundedRatio(value); const heatClass = bounded >= .85 ? "heat-high" : bounded >= .65 ? "heat-mid" : "heat-low"; return `<button class="heatmap-cell ${heatClass}" data-heat-label="${escapeHTML(label)}" data-heat-level="${levels[index]}" data-heat-value="${Number(value || 0)}" type="button"><strong>${pct(value, 0)}</strong><small>${index === 0 ? "observed" : index === 1 ? "stress" : index === 2 ? "high stress" : "edge case"}</small></button>`; }).join("")}`).join("")}`;
  $$('[data-heat-label]', target).forEach((cell) => cell.addEventListener("click", () => {
    const value = Number(cell.dataset.heatValue || 0);
    $("#heatmap-detail").innerHTML = `<strong>${escapeHTML(cell.dataset.heatLabel)} / ${escapeHTML(cell.dataset.heatLevel)}</strong><span>Detection recall: <b>${pct(value, 1)}</b> · synthetic evidence · the measured scenario output represents the confidence band.</span>`;
    $$('[data-heat-label]', target).forEach((other) => other.classList.toggle("selected", other === cell));
  }));
}

function activatePipeline(selector) {
  const stages = $$(`${selector} > div, ${selector} > .pipeline-stage`);
  stages.forEach((stage, index) => {
    if (stage.classList.contains("pipeline-link") || stage.tagName === "B") return;
    stage.classList.remove("active", "complete");
    setTimeout(() => stage.classList.add("active"), index * 230);
    setTimeout(() => { stage.classList.remove("active"); stage.classList.add("complete"); }, index * 230 + 750);
  });
}

function animateSimulationStory(result) {
  activatePipeline("#simulation-pipeline");
  const status = $("#simulation-story-status");
  if (status) {
    status.innerHTML = `<span class="status-dot"></span> ANALYZED / ${pct(result.detection_rate, 0)} DETECTED`;
    status.classList.add("story-complete");
  }
  const sample = Array.isArray(result.sample) ? result.sample[0] : null;
  const risk = sample ? Math.round(Number(sample.risk_score || result.mean_risk || 0) * 100) : Math.round(Number(result.mean_risk || 0) * 100);
  const control = result.control_sample || null;
  const comparison = $("#simulation-comparison");
  if (comparison) comparison.dataset.risk = String(risk);
  const controlsRisk = control ? Math.round(Number(control.risk_score || 0) * 100) : 0;
  $("#simulation-comparison")?.querySelector("div:first-child strong") && ($("#simulation-comparison").querySelector("div:first-child strong").textContent = controlsRisk);
  $("#simulation-comparison")?.querySelector(".critical-comparison strong") && ($("#simulation-comparison").querySelector(".critical-comparison strong").textContent = risk);
  $("#simulation-comparison")?.querySelector("div:first-child small") && ($("#simulation-comparison").querySelector("div:first-child small").textContent = control ? "measured legitimate control sample" : "control unavailable");
  $("#simulation-comparison")?.querySelector(".critical-comparison small") && ($("#simulation-comparison").querySelector(".critical-comparison small").textContent = `${pct(result.detection_rate, 0)} detection rate / action required`);
  const factors = $("#simulation-comparison")?.querySelector(".comparison-factors");
  if (factors && sample && control) factors.innerHTML = `
    <span>1-hour velocity <b>${Number(control.velocity_1h || 0).toFixed(0)} → ${Number(sample.velocity_1h || 0).toFixed(0)}</b></span>
    <span>network risk <b>${pct(control.ip_risk || 0, 0)} → ${pct(sample.ip_risk || 0, 0)}</b></span>
    <span>behavior consistency <b>${pct(control.typing_consistency || 0, 0)} → ${pct(sample.typing_consistency || 0, 0)}</b></span>`;
}

function bindInteractiveAmbient() {
  const root = document.documentElement;
  let frame = 0;
  let pointer = { x: window.innerWidth * 0.5, y: window.innerHeight * 0.35 };
  const commit = () => {
    frame = 0;
    root.style.setProperty("--cursor-x", `${pointer.x}px`);
    root.style.setProperty("--cursor-y", `${pointer.y}px`);
  };
  document.addEventListener("pointermove", (event) => {
    pointer = { x: event.clientX, y: event.clientY };
    if (!frame) frame = requestAnimationFrame(commit);
  }, { passive: true });
  $$(".surface, .network-panel, .signal-panel, .simulation-story-panel, .risk-engine-panel, .fidelity-hero-panel, .attack-landscape-panel").forEach((surface) => {
    surface.addEventListener("pointermove", (event) => {
      const rect = surface.getBoundingClientRect();
      surface.style.setProperty("--card-x", `${((event.clientX - rect.left) / rect.width) * 100}%`);
      surface.style.setProperty("--card-y", `${((event.clientY - rect.top) / rect.height) * 100}%`);
      surface.style.setProperty("--card-tilt-x", `${((event.clientY - rect.top) / rect.height - .5) * -1.2}deg`);
      surface.style.setProperty("--card-tilt-y", `${((event.clientX - rect.left) / rect.width - .5) * 1.2}deg`);
    }, { passive: true });
    surface.addEventListener("pointerleave", () => {
      surface.style.removeProperty("--card-x");
      surface.style.removeProperty("--card-y");
      surface.style.removeProperty("--card-tilt-x");
      surface.style.removeProperty("--card-tilt-y");
    });
  });
}

function drawBoundaryChart(data) {
  const canvas = $("#boundary-chart");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const ratio = Math.max(1, window.devicePixelRatio || 1);
  // Size the backing store from the measured box; the CSS height differs per breakpoint.
  const cssWidth = Math.max(160, rect.width || 660);
  const cssHeight = Math.max(120, rect.height || 240);
  canvas.width = Math.floor(cssWidth * ratio);
  canvas.height = Math.floor(cssHeight * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  const width = canvas.width / ratio;
  const height = canvas.height / ratio;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#ffffff";
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
  ctx.strokeStyle = "rgba(117,98,82,.16)";
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
    ctx.fillStyle = "rgba(247,158,27,.72)";
    ctx.fillRect(x, pad.top + chartHeight - legitimateHeight, barWidth, legitimateHeight);
    ctx.fillStyle = "rgba(235,0,27,.82)";
    ctx.fillRect(x + barWidth + 2, pad.top + chartHeight - attackHeight, barWidth, attackHeight);
  });
  const threshold = boundedRatio(data.metrics?.threshold || .5);
  const thresholdX = pad.left + chartWidth * threshold;
  ctx.save();
  ctx.setLineDash([5, 5]);
  ctx.strokeStyle = "#ff5f00";
  ctx.lineWidth = 1.4;
  ctx.beginPath();
  ctx.moveTo(thresholdX, pad.top);
  ctx.lineTo(thresholdX, pad.top + chartHeight);
  ctx.stroke();
  ctx.restore();
  ctx.fillStyle = "#7b726b";
  ctx.font = '9px ui-monospace, monospace';
  for (let i = 0; i <= 5; i += 1) ctx.fillText((i / 5).toFixed(1), pad.left + chartWidth * (i / 5) - 7, height - 9);
  ctx.fillStyle = "#8e4c28";
  ctx.fillText(`THRESHOLD ${threshold.toFixed(2)}`, Math.min(width - 96, thresholdX + 5), pad.top + 11);
}

function drawEvaluationCurves(data) {
  const canvas = $("#evaluation-curves");
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  const ratio = Math.max(1, window.devicePixelRatio || 1);
  const cssWidth = Math.max(280, Math.floor(rect.width || 900));
  const compact = cssWidth < 560;
  const cssHeight = compact ? 430 : 250;
  const width = Math.floor(cssWidth * ratio);
  const height = Math.floor(cssHeight * ratio);
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  const w = width / ratio;
  const h = height / ratio;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, w, h);
  const pad = { left: 42, right: 22, top: 28, bottom: 32 };
  const graphGap = compact ? 54 : 44;
  const graphW = compact ? w - pad.left - pad.right : (w - pad.left - pad.right - graphGap) / 2;
  const graphH = compact ? (h - pad.top - pad.bottom - graphGap) / 2 : h - pad.top - pad.bottom;
  const dist = data?.validation?.risk_distribution || {};
  const legitimate = Array.isArray(dist.legitimate) ? dist.legitimate : [];
  const attacks = Array.isArray(dist.attack) ? dist.attack : [];
  const totalNormal = Math.max(1, legitimate.reduce((sum, value) => sum + value, 0));
  const totalAttack = Math.max(1, attacks.reduce((sum, value) => sum + value, 0));
  const points = Math.max(legitimate.length, attacks.length, 2);
  const cumulativeFromHigh = (values, total) => {
    let running = 0;
    return values.map((_, index) => { running += values[values.length - index - 1] || 0; return running / total; });
  };
  const fpr = cumulativeFromHigh(legitimate, totalNormal);
  const tpr = cumulativeFromHigh(attacks, totalAttack);
  const rocPoints = [[0, 0], ...Array.from({ length: points }, (_, index) => [fpr[index] ?? 1, tpr[index] ?? 1]), [1, 1]];
  const precisionRecall = [[0, 1], ...Array.from({ length: points }, (_, index) => {
    const tp = (attacks[attacks.length - index - 1] || 0) + (index ? tpr[index - 1] * totalAttack : 0);
    const fp = (legitimate[legitimate.length - index - 1] || 0) + (index ? fpr[index - 1] * totalNormal : 0);
    return [Math.min(1, tp / Math.max(1, tp + fp)), tpr[index] ?? 0];
  })];
  if (!Number.isFinite(state.evaluationThreshold)) state.evaluationThreshold = boundedRatio(data?.metrics?.threshold ?? .5);
  const threshold = boundedRatio(state.evaluationThreshold);
  const thresholdControl = $("#evaluation-threshold");
  const thresholdOutput = $("#evaluation-threshold-value");
  if (thresholdControl && document.activeElement !== thresholdControl) thresholdControl.value = threshold.toFixed(2);
  if (thresholdOutput) thresholdOutput.textContent = threshold.toFixed(2);
  const operatingIndex = Math.max(0, Math.min(points - 1, Math.round((1 - threshold) * (points - 1))));
  const operatingFpr = fpr[operatingIndex] ?? 0;
  const operatingTpr = tpr[operatingIndex] ?? 0;
  const operatingPr = precisionRecall[operatingIndex + 1] || [1, 0];
  const drawGraph = (originX, originY, title, xLabel, yLabel, curve, color, marker) => {
    ctx.strokeStyle = "rgba(117,98,82,.16)"; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i += 1) { const y = originY + graphH * i / 4; ctx.beginPath(); ctx.moveTo(originX, y); ctx.lineTo(originX + graphW, y); ctx.stroke(); const x = originX + graphW * i / 4; ctx.beginPath(); ctx.moveTo(x, originY); ctx.lineTo(x, originY + graphH); ctx.stroke(); }
    ctx.fillStyle = "#3e3935"; ctx.font = "600 9px ui-monospace, monospace"; ctx.fillText(title, originX, originY - 9); ctx.fillStyle = "#7b726b"; ctx.font = "500 8px ui-monospace, monospace"; const xLabelWidth = ctx.measureText(xLabel).width; ctx.fillText(xLabel, Math.max(originX, originX + graphW - xLabelWidth), originY + graphH + 20); ctx.save(); ctx.translate(originX - 28, originY + graphH / 2 + 20); ctx.rotate(-Math.PI / 2); ctx.fillText(yLabel, 0, 0); ctx.restore();
    ctx.save(); ctx.beginPath(); curve.forEach(([x, y], index) => { const px = originX + x * graphW; const py = originY + (1 - y) * graphH; index ? ctx.lineTo(px, py) : ctx.moveTo(px, py); }); ctx.strokeStyle = color; ctx.lineWidth = 2.4; ctx.shadowColor = color; ctx.shadowBlur = 8; ctx.stroke(); ctx.restore();
    if (marker) {
      const markerX = originX + marker[0] * graphW;
      const markerY = originY + (1 - marker[1]) * graphH;
      ctx.save();
      ctx.strokeStyle = "rgba(23,23,23,.28)";
      ctx.setLineDash([3, 3]);
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(markerX, originY); ctx.lineTo(markerX, originY + graphH); ctx.moveTo(originX, markerY); ctx.lineTo(originX + graphW, markerY); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = "#171717"; ctx.beginPath(); ctx.arc(markerX, markerY, 5, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(markerX, markerY, 8, 0, Math.PI * 2); ctx.stroke();
      ctx.restore();
    }
  };
  drawGraph(pad.left, pad.top, "ROC CURVE", "false positive rate", "true positive rate", rocPoints, "#ff5f00", [operatingFpr, operatingTpr]);
  drawGraph(compact ? pad.left : pad.left + graphW + graphGap, compact ? pad.top + graphH + graphGap : pad.top, "PRECISION / RECALL", "recall", "precision", precisionRecall.map(([precision, recall]) => [recall, precision]), "#f79e1b", [operatingPr[1], operatingPr[0]]);
  $("#evaluation-auc") && ($("#evaluation-auc").textContent = Number(data?.metrics?.auc || 0).toFixed(3));
  $("#evaluation-pr-auc") && ($("#evaluation-pr-auc").textContent = Number(data?.metrics?.pr_auc || 0).toFixed(3));
  $("#evaluation-operating-point") && ($("#evaluation-operating-point").textContent = `${pct(operatingTpr)} recall · ${pct(operatingFpr)} FPR`);
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
  const recentRows = Array.isArray(data.recent_transactions) ? data.recent_transactions : [];
  const highRisk = recentRows.filter((row) => Number(row.risk_score || 0) >= 0.7).length;
  const securityScore = calculateSecurityScore(data, metrics, recentRows);
  const scoreDelta = renderSecurityScore(securityScore);
  const scoreDeltaNode = $("#kpi-f1-delta");
  if (scoreDeltaNode) {
    const changed = scoreDelta !== null && Math.abs(scoreDelta) >= 0.05;
    scoreDeltaNode.textContent = changed ? `${scoreDelta > 0 ? "+" : ""}${scoreDelta.toFixed(1)} since last refresh` : "live composite • auto-refresh";
    scoreDeltaNode.classList.toggle("positive", !changed || scoreDelta > 0);
    scoreDeltaNode.classList.toggle("negative", changed && scoreDelta < 0);
  }
  $("#kpi-auc").textContent = compactNumber(data.stream_size || recentRows.length);
  $("#kpi-fpr").textContent = highRisk;
  $("#kpi-coverage").textContent = latest.attack_coverage;
  $("#kpi-catalog-size").textContent = data.catalog_size;
  $("#intro-model").textContent = system.model_version || "model unavailable";
  $("#topbar-model").textContent = system.model_version || "model unavailable";
  $("#intro-time").textContent = formatIST(data.generated_at, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  $("#last-sync").textContent = `synced ${formatIST(Date.now(), { hour: "2-digit", minute: "2-digit" })}`;
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
  renderThreatLandscape(data.attack_mix || []);
  renderThreatNetwork(data.recent_transactions || []);
  const activeCoverage = Number(data.detected_attack_coverage || 0);
  const catalogSize = Math.max(1, Number(data.catalog_size || 0));
  $("#coverage-ring").style.setProperty("--coverage", `${boundedRatio(activeCoverage / catalogSize) * 100}%`);
  $("#coverage-ring-value").textContent = `${activeCoverage}/${data.catalog_size}`;
  $("#coverage-title").textContent = activeCoverage === data.catalog_size ? "Full stream coverage" : "Current stream coverage";
  drawBoundaryChart(data);
  drawEvaluationCurves(data);
  $("#system-feedback-status") && ($("#system-feedback-status").textContent = state.feedbackQueued ? `${state.feedbackQueued} QUEUED` : "ARMED");
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
  $("#attack-count-meta").textContent = `${state.attacks.length} total scenarios in the catalog`;
  renderAttackBubbles(state.attacks);
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

function queueCategoryLabel(category) {
  return String(category || "feedback")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function renderFeedbackQueue(items, message = "") {
  const content = $("#queue-dialog-content");
  if (!content) return;
  if (message) {
    content.innerHTML = `<div class="queue-state"><i data-lucide="loader-circle"></i><strong>${escapeHTML(message)}</strong></div>`;
    refreshIcons();
    return;
  }
  if (!items.length) {
    content.innerHTML = `<div class="queue-state"><i data-lucide="inbox"></i><strong>No feedback is queued.</strong><span>Run a simulation or submit analyst feedback to create hard cases.</span></div>`;
    refreshIcons();
    return;
  }
  content.innerHTML = `<div class="queue-summary"><strong>${items.length}</strong><span>most recently queued items</span></div><div class="queue-list">${items.map((item) => {
    const row = item.row || item;
    const category = item.category || item.outcome || "feedback";
    const risk = Number(row.risk_score);
    return `<article class="queue-item"><div class="queue-item-head"><strong>${escapeHTML(row.id || item.transaction_id || "Unknown transaction")}</strong><span>${escapeHTML(queueCategoryLabel(category))}</span></div><div class="queue-item-meta"><span>${escapeHTML(row.attack_name || row.attack_id || row.rail || "Synthetic event")}</span>${Number.isFinite(risk) ? `<b>${pct(risk, 0)} risk</b>` : ""}</div><small>${escapeHTML(row.decision ? `${row.decision} decision` : "Awaiting retraining")}</small></article>`;
  }).join("")}</div>`;
}

async function openFeedbackQueue() {
  const dialog = $("#queue-dialog");
  if (!dialog) return;
  dialog.showModal();
  renderFeedbackQueue([], "Loading queued feedback...");
  try {
    const payload = await requestJSON("/api/feedback?limit=500");
    renderFeedbackQueue(Array.isArray(payload.feedback) ? payload.feedback : []);
  } catch (error) {
    renderFeedbackQueue([], `Queue unavailable: ${error.message}`);
  }
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
  $("#topbar-feedback").textContent = `${result.feedback_ready} queued`;
  $("#loop-queue").textContent = `${result.feedback_ready} rows`;
  animateSimulationStory(result);
}

function renderFidelity(data) {
  state.fidelity = data;
  renderRobustnessHeatmap(data);
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
  const riskScore = Math.round(boundedRatio(row.risk_score) * 100);
  const riskLabel = riskScore >= 80 ? "CRITICAL" : riskScore >= 60 ? "HIGH" : riskScore >= 35 ? "ELEVATED" : "LOW";
  const recommendedAction = row.decision === "approve" ? "Approve and continue monitoring." : row.decision === "decline" ? "Contain the event and retain model reasons for review." : "Require additional verification before authorization.";
  $("#transaction-dialog-title").textContent = `${row.id} / INVESTIGATION`;
  const explanations = row.explanations || [];
  $("#transaction-dialog-content").innerHTML = `
    <div class="investigation-hero"><div class="investigation-score" style="--risk:${riskScore * 3.6}deg"><strong>${riskScore}</strong><span>${riskLabel} RISK</span></div><div><span class="investigation-status">${escapeHTML(String(row.decision || "review").toUpperCase())}</span><h3>${escapeHTML(row.attack_name || "Payment behavior review")}</h3><p>${escapeHTML(row.rail)} / ${escapeHTML(row.channel)} / ${escapeHTML(row.country || "unknown")}</p></div></div>
    <div class="detail-metrics"><div><span>AMOUNT</span><strong>${money(row.amount, row.currency)}</strong></div><div><span>CUSTOMER</span><strong class="mono">${escapeHTML(row.customer_id || "—")}</strong></div><div><span>DEVICE</span><strong class="mono">${escapeHTML(row.device_id || "—")}</strong></div></div>
    <section class="detail-section"><span>WHY WAS THIS FLAGGED?</span>${explanations.length ? `<div class="reason-list">${explanations.map((item) => `<div class="reason-row"><span>${escapeHTML(item.label)}</span><div class="reason-bar"><i style="width:${Math.max(10, boundedRatio(item.contribution_share || item.contribution) * 100)}%"></i></div><b>${pct(item.contribution_share || 0, 0)}</b></div>`).join("")}</div>` : "<p>No model contribution exceeded the explanation threshold.</p>"}</section>
    <section class="detail-section ai-explanation"><span>AI EXPLANATION</span><p>This event deviates from its synthetic baseline across ${Math.max(1, explanations.length)} measured dimensions. The strongest factor is ${escapeHTML(explanations[0]?.label || "transaction context")}; the model has surfaced each contribution for analyst review.</p></section>
    <section class="detail-section"><span>ENTITY RELATIONSHIP</span><div class="entity-chain"><span><i data-lucide="user-round"></i>${escapeHTML(row.customer_id || "Customer")}</span><i data-lucide="arrow-right"></i><span><i data-lucide="smartphone"></i>${escapeHTML(row.device_id || "Device")}</span><i data-lucide="arrow-right"></i><span><i data-lucide="store"></i>${escapeHTML(row.merchant_id || "Merchant")}</span><i data-lucide="arrow-right"></i><span class="entity-risk"><i data-lucide="shield-alert"></i>${riskLabel}</span></div></section>
    <section class="detail-section recommendation"><span>RECOMMENDED ACTION</span><div><i data-lucide="badge-check"></i><p>${recommendedAction}</p></div></section>
    <section class="detail-section"><span>ACTION CENTER</span><div class="action-center"><button class="secondary-action" data-feedback-outcome="confirmed_legitimate" data-override-decision="approve" type="button"><i data-lucide="check"></i> Approve</button><button class="secondary-action" data-feedback-outcome="uncertain" data-override-decision="step_up" type="button"><i data-lucide="fingerprint"></i> Verify</button><button class="danger-action" data-feedback-outcome="confirmed_fraud" data-override-decision="decline" type="button"><i data-lucide="ban"></i> Block</button></div></section>`;
  $("#transaction-dialog").showModal();
  $$('[data-feedback-outcome]', $("#transaction-dialog-content")).forEach((button) => {
    const feedbackAvailable = state.capabilities?.has("feedback");
    button.disabled = !feedbackAvailable;
    if (!feedbackAvailable) button.title = isOfflineDemo() ? OFFLINE_ACTION_MESSAGE : OUTDATED_BACKEND_MESSAGE;
    button.addEventListener("click", async () => {
      if (!requireCapability("feedback")) return;
      try {
        await requestJSON("/api/feedback", { method: "POST", body: JSON.stringify({ transaction_id: row.id, outcome: button.dataset.feedbackOutcome, override_decision: button.dataset.overrideDecision }) });
        toast(`${button.dataset.overrideDecision === "decline" ? "BLOCKED — event contained" : button.dataset.overrideDecision === "approve" ? "APPROVED — outcome recorded" : "VERIFICATION REQUESTED"} for ${row.id}.`);
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
  $("#matrix-footnote").textContent = `Untouched generated holdout / N = ${holdoutSize}.`;
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
  if (state.fidelityLoading) return;
  state.fidelityLoading = true;
  try {
    const result = await requestJSON("/api/fidelity");
    renderFidelity(result);
  } catch (error) {
    toast(`Evidence run failed: ${error.message}`);
  } finally {
    state.fidelityLoading = false;
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

async function refreshLiveOverview() {
  if (document.hidden || isOfflineDemo() || state.overviewRefreshing || !state.capabilities?.has("overview")) return;
  state.overviewRefreshing = true;
  try {
    const overview = await requestJSON("/api/overview");
    state.overview = overview;
    state.feedbackQueued = Number(overview.feedback_queue_size || 0);
    renderOverview();
    setConnectionStatus("live");
  } catch (_error) {
    setConnectionStatus("error");
  } finally {
    state.overviewRefreshing = false;
  }
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
  // document.body also carries data-view: it drives the body[data-view="..."] theme
  // selectors in styles.css. Binding it here would make every bubbled click on the
  // page re-run switchView, which scrolls the document back to the top.
  $$('[data-view]').filter((node) => node !== document.body).forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
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
  $("#evaluation-threshold")?.addEventListener("input", (event) => {
    state.evaluationThreshold = boundedRatio(event.target.value);
    if (state.overview) drawEvaluationCurves(state.overview);
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
  $(".feedback-chip")?.addEventListener("click", openFeedbackQueue);
  $(".feedback-chip")?.setAttribute("role", "button");
  $(".feedback-chip")?.setAttribute("tabindex", "0");
  $(".feedback-chip")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openFeedbackQueue();
    }
  });
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
  $("#queue-dialog").addEventListener("click", (event) => { if (event.target === event.currentTarget) event.currentTarget.close(); });
  window.addEventListener("resize", () => {
    renderBreadcrumb(document.body.dataset.view || "overview");
    if (!state.overview) return;
    if ($("#view-overview").classList.contains("active")) drawBoundaryChart(state.overview);
    if ($("#view-evidence").classList.contains("active")) drawEvaluationCurves(state.overview);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.body.dataset.view = "overview";
  renderBreadcrumb("overview");
  revealActiveView("overview");
  refreshIcons();
  renderExternalEvidence();
  bindRevealMotion();
  bindEvents();
  bindCommandPalette();
  bindInteractiveAmbient();
  loadData();
  setInterval(() => requestJSON("/api/health").then((health) => {
    const currentBackend = updateCapabilities(health);
    setConnectionStatus(isOfflineDemo() ? "offline" : currentBackend ? "live" : "outdated");
  }).catch(() => setConnectionStatus("error")), 30000);
  setInterval(refreshLiveOverview, LIVE_OVERVIEW_REFRESH_MS);
});
