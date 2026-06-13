const STEP_IDS = [
  "step-generating",
  "step-compiling",
  "step-executing",
  "step-proving",
  "step-on-chain",
  "step-complete",
];

const CHAIN_NAMES = {
  31337: "local anvil",
  11155111: "Sepolia",
  8453: "Base",
  84532: "Base Sepolia",
  10: "Optimism",
  11155420: "OP Sepolia",
};

function chainName(id) {
  if (id == null) return "chain ID ?";
  return CHAIN_NAMES[id] || "chain ID " + id;
}

function shortAddr(addr) {
  if (!addr || typeof addr !== "string" || addr.length < 12) return addr || "";
  return addr.slice(0, 6) + "…" + addr.slice(-4);
}

const HASH_FIELDS = [
  ["program_hash", "hash-program"],
  ["input_hash", "hash-input"],
  ["tool_responses_hash", "hash-tool-responses"],
  ["output_hash", "hash-output"],
  ["attestation_hash", "hash-tls"],
  ["policy_hash", "hash-policy"],
];

function $(id) {
  return document.getElementById(id);
}

const stepTimers = {
  startTimes: new Map(),
  durations: new Map(),
  ticker: null,
};

function formatDuration(ms) {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return "";
  if (ms < 1000) return ms.toFixed(0) + " ms";
  const secs = ms / 1000;
  if (secs < 10) return secs.toFixed(2) + " s";
  if (secs < 60) return secs.toFixed(1) + " s";
  const m = Math.floor(secs / 60);
  const s = (secs - m * 60).toFixed(0).padStart(2, "0");
  return m + "m " + s + "s";
}

function renderStepTime(id) {
  const row = $(id);
  if (!row) return;
  const status = row.querySelector(".step-status");
  if (!status) return;

  const frozen = stepTimers.durations.get(id);
  if (frozen != null) {
    status.textContent = formatDuration(frozen);
    return;
  }

  const start = stepTimers.startTimes.get(id);
  if (start != null) {
    status.textContent = formatDuration(performance.now() - start);
  }
}

function startStepTimerTicker() {
  if (stepTimers.ticker != null) return;
  stepTimers.ticker = setInterval(() => {
    for (const id of stepTimers.startTimes.keys()) {
      if (!stepTimers.durations.has(id)) renderStepTime(id);
    }
    if (
      Array.from(stepTimers.startTimes.keys()).every((id) =>
        stepTimers.durations.has(id),
      )
    ) {
      stopStepTimerTicker();
    }
  }, 100);
}

function stopStepTimerTicker() {
  if (stepTimers.ticker != null) {
    clearInterval(stepTimers.ticker);
    stepTimers.ticker = null;
  }
}

function resetStepTimers() {
  stopStepTimerTicker();
  stepTimers.startTimes.clear();
  stepTimers.durations.clear();
  for (const id of STEP_IDS) {
    const row = $(id);
    if (!row) continue;
    const status = row.querySelector(".step-status");
    if (status) status.textContent = "";
  }
}

function setStep(id, state) {
  const row = $(id);
  if (!row) return;
  row.classList.remove("active", "done", "failed");
  if (state) row.classList.add(state);

  if (state === "active") {
    if (!stepTimers.startTimes.has(id)) {
      stepTimers.startTimes.set(id, performance.now());
    }
    renderStepTime(id);
    startStepTimerTicker();
  } else if (state === "done" || state === "failed") {
    const start = stepTimers.startTimes.get(id);
    if (start != null && !stepTimers.durations.has(id)) {
      stepTimers.durations.set(id, performance.now() - start);
    }
    renderStepTime(id);
  }
}

function resetUI() {
  $("lua-source").classList.add("hidden");
  $("lua-source").textContent = "";

  const toolCalls = $("tool-calls");
  toolCalls.classList.add("hidden");
  toolCalls.innerHTML = "";

  const banner = $("result-banner");
  banner.classList.add("hidden");
  banner.classList.remove("success", "failure");
  banner.textContent = "";

  for (const id of STEP_IDS) setStep(id, null);
  resetStepTimers();

  for (const [, rowId] of HASH_FIELDS) {
    const row = $(rowId);
    row.classList.remove("tampered");
    const tamperMsg = row.querySelector(".tamper-msg");
    if (tamperMsg) tamperMsg.remove();

    const code = row.querySelector("code");
    code.textContent = "——";
    const tooltip = code.getAttribute("data-tooltip");
    if (tooltip) {
      code.setAttribute("title", tooltip);
    } else {
      code.removeAttribute("title");
    }

    const copyBtn = row.querySelector(".copy-btn");
    if (copyBtn) copyBtn.remove();
  }

  hideAttackSimulator();

  $("panel-onchain").classList.add("hidden");
  $("onchain-chain").textContent = "——";
  const verifierEl = $("onchain-verifier");
  verifierEl.innerHTML = "<code>——</code>";
  const statusEl = $("onchain-status");
  statusEl.textContent = "——";
  statusEl.classList.remove("ok", "bad");
}

function truncate(text, max) {
  if (text == null) return "";
  const s = String(text);
  return s.length > max ? s.slice(0, max) + "…" : s;
}

function appendToolCallRow({ name, args, response }) {
  const toolCalls = $("tool-calls");
  toolCalls.classList.remove("hidden");

  const row = document.createElement("div");
  row.className = "tool-call-row";

  const nameEl = document.createElement("span");
  nameEl.className = "tool-call-name";
  nameEl.textContent = name;

  const argsEl = document.createElement("code");
  argsEl.className = "tool-call-args";
  argsEl.textContent = truncate(args, 80);
  argsEl.title = String(args ?? "");

  const respEl = document.createElement("code");
  respEl.className = "tool-call-response";
  respEl.textContent = "→ " + truncate(response, 80);
  respEl.title = String(response ?? "");

  row.appendChild(nameEl);
  row.appendChild(argsEl);
  row.appendChild(respEl);
  toolCalls.appendChild(row);
}

function ensureCopyButton(row, code, value) {
  let wrapper = row.querySelector(".hash-value-row");
  if (!wrapper) {
    wrapper = document.createElement("div");
    wrapper.className = "hash-value-row";
    code.parentNode.insertBefore(wrapper, code);
    wrapper.appendChild(code);
  }

  let btn = wrapper.querySelector(".copy-btn");
  if (!btn) {
    btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.title = "Copy hash to clipboard";
    btn.setAttribute("aria-label", "Copy hash to clipboard");
    btn.textContent = "📋";
    wrapper.appendChild(btn);
  }

  btn.onclick = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const ta = document.createElement("textarea");
        ta.value = value;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
      btn.classList.add("copied");
      btn.textContent = "✓";
      setTimeout(() => {
        btn.classList.remove("copied");
        btn.textContent = "📋";
      }, 1200);
    } catch (err) {
      console.error("Copy failed", err);
    }
  };
}

function showHashes(hashes) {
  for (const [field, rowId] of HASH_FIELDS) {
    const row = $(rowId);
    const value = hashes && hashes[field] ? String(hashes[field]) : "";
    const code = row.querySelector("code");
    const tooltip = code.getAttribute("data-tooltip");

    if (!value) {
      code.textContent = "——";
      if (tooltip) {
        code.setAttribute("title", tooltip);
      } else {
        code.removeAttribute("title");
      }
      const existingBtn = row.querySelector(".copy-btn");
      if (existingBtn) existingBtn.remove();
      continue;
    }

    code.textContent = value;
    if (tooltip) code.setAttribute("title", tooltip);
    ensureCopyButton(row, code, value);
  }
}

const ATTACKS = [
  {
    label: "Swap API response",
    rowId: "hash-tool-responses",
    message:
      "tool_responses_hash breaks — proof rejects (on-chain verifier would revert with ProofInvalid)",
  },
  {
    label: "Backdate timestamp",
    rowId: "hash-tls",
    message:
      "attestation_hash breaks — on-chain verifier rejects (on-chain verifier would revert with ProofInvalid)",
  },
  {
    label: "Change the question",
    rowId: "hash-input",
    message:
      "input_hash breaks — proof rejects (on-chain verifier would revert with ProofInvalid)",
  },
  {
    label: "Modify the Lua code",
    rowId: "hash-program",
    message:
      "program_hash breaks — proof rejects (on-chain verifier would revert with ProofInvalid)",
  },
];

let attackTimers = new Map();

function clearTamper(rowId) {
  const row = $(rowId);
  if (!row) return;
  row.classList.remove("tampered");
  const msg = row.querySelector(".tamper-msg");
  if (msg) msg.remove();
}

function triggerAttack(attack) {
  const row = $(attack.rowId);
  if (!row) return;

  const prev = attackTimers.get(attack.rowId);
  if (prev) {
    clearTimeout(prev);
    clearTamper(attack.rowId);
  }

  row.classList.add("tampered");

  let msg = row.querySelector(".tamper-msg");
  if (!msg) {
    msg = document.createElement("div");
    msg.className = "tamper-msg";
    row.appendChild(msg);
  }
  msg.textContent = attack.message;

  const timer = setTimeout(() => {
    clearTamper(attack.rowId);
    attackTimers.delete(attack.rowId);
  }, 3000);
  attackTimers.set(attack.rowId, timer);
}

function showAttackSimulator() {
  const container = $("attack-simulator");
  container.innerHTML = "";

  const heading = document.createElement("p");
  heading.className = "attack-heading";
  heading.textContent = "Try to cheat:";
  container.appendChild(heading);

  for (const attack of ATTACKS) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "attack-btn";
    btn.textContent = attack.label;
    btn.addEventListener("click", () => triggerAttack(attack));
    container.appendChild(btn);
  }

  container.classList.remove("hidden");
}

function hideAttackSimulator() {
  const container = $("attack-simulator");
  container.classList.add("hidden");
  container.innerHTML = "";

  for (const timer of attackTimers.values()) clearTimeout(timer);
  attackTimers.clear();
}

function showResultBanner(text, kind) {
  const banner = $("result-banner");
  banner.classList.remove("hidden", "success", "failure");
  banner.classList.add(kind);
  banner.textContent = text;
}

function enableRunButton() {
  const btn = $("run-btn");
  btn.disabled = false;
  btn.textContent = "Run & Prove";
}

function handleEvent(event) {
  const stage = event && event.stage;
  const data = (event && event.data) || {};

  switch (stage) {
    case "generating_lua":
      setStep("step-generating", "active");
      break;

    case "lua_ready":
      setStep("step-generating", "done");
      $("lua-source").textContent = data.lua || "";
      $("lua-source").classList.remove("hidden");
      break;

    case "compiling":
      setStep("step-compiling", "active");
      break;

    case "executing":
      setStep("step-compiling", "done");
      setStep("step-executing", "active");
      break;

    case "tool_call":
      appendToolCallRow(data);
      break;

    case "proving":
      setStep("step-executing", "done");
      setStep("step-proving", "active");
      break;

    case "complete": {
      setStep("step-proving", "done");
      setStep("step-complete", "done");
      showHashes(data.hashes || {});
      const result = data.result;
      const text =
        typeof result === "string" ? result : JSON.stringify(result);
      showResultBanner("Result: " + text, "success");
      showAttackSimulator();
      enableRunButton();
      break;
    }

    case "verifying_on_chain": {
      setStep("step-on-chain", "active");

      const panel = $("panel-onchain");
      panel.classList.remove("hidden");

      $("onchain-chain").textContent = chainName(data.chain_id);

      const verifierEl = $("onchain-verifier");
      const addr = data.verifier_addr || "";
      const short = shortAddr(addr);
      const explorer = data.explorer_base;
      if (explorer) {
        const a = document.createElement("a");
        a.href = explorer + "/address/" + addr;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = short;
        a.title = addr;
        verifierEl.innerHTML = "";
        verifierEl.appendChild(a);
      } else {
        const code = document.createElement("code");
        code.textContent = short;
        code.title = addr;
        verifierEl.innerHTML = "";
        verifierEl.appendChild(code);
      }

      const statusEl = $("onchain-status");
      statusEl.classList.remove("ok", "bad");
      statusEl.textContent = "submitting…";
      break;
    }

    case "verified_on_chain": {
      const accepted = data.accepted === true;
      const reason = data.reason || "unknown";
      const statusEl = $("onchain-status");
      statusEl.classList.remove("ok", "bad");

      if (accepted) {
        setStep("step-on-chain", "done");
        statusEl.classList.add("ok");
        statusEl.textContent = "✓ accepted by HonkVerifier";

        const banner = $("result-banner");
        if (banner && !banner.classList.contains("hidden")) {
          const extra = document.createElement("div");
          extra.className = "result-onchain-note";
          extra.textContent = "verified on chain";
          banner.appendChild(extra);
        }
      } else {
        setStep("step-on-chain", "failed");
        statusEl.classList.add("bad");
        statusEl.textContent = "✗ rejected: " + reason;
        showResultBanner("Rejected on chain: " + reason, "failure");
      }
      break;
    }

    case "error": {
      const msg = data.message || "Unknown error";
      const at = data.at_stage ? " (" + data.at_stage + ")" : "";
      showResultBanner("Error" + at + ": " + msg, "failure");
      for (const id of STEP_IDS) {
        const row = $(id);
        if (row && row.classList.contains("active")) setStep(id, "failed");
      }
      stopStepTimerTicker();
      enableRunButton();
      break;
    }

    default:
      // Unknown stage — ignore so future schema additions don't break the UI.
      break;
  }
}

async function runPipeline(task) {
  let response;
  try {
    response = await fetch("http://localhost:3001/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ task }),
    });
  } catch (err) {
    showResultBanner("Network error: " + err.message, "failure");
    enableRunButton();
    return;
  }

  if (!response.ok || !response.body) {
    showResultBanner(
      "Server error: HTTP " + response.status,
      "failure",
    );
    enableRunButton();
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let sep;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);

      for (const line of frame.split("\n")) {
        if (!line.startsWith("data: ")) continue;
        const payload = line.slice(6);
        try {
          handleEvent(JSON.parse(payload));
        } catch (err) {
          console.error("Failed to parse SSE event", err, payload);
        }
      }
    }
  }
}

function onSubmit() {
  const task = $("task-input").value.trim();
  if (!task) return;

  resetUI();

  const btn = $("run-btn");
  btn.disabled = true;
  btn.textContent = "Running…";

  runPipeline(task);
}

function init() {
  for (const btn of document.querySelectorAll(".preset-btn")) {
    btn.addEventListener("click", () => {
      $("task-input").value = btn.textContent.trim();
    });
  }

  $("run-btn").addEventListener("click", onSubmit);

  $("task-input").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      onSubmit();
    }
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
