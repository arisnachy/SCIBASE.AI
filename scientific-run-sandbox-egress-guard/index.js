const crypto = require("node:crypto");

const BLOCK = "block";
const HOLD = "hold";
const ALLOW = "allow";

const restrictedDataClasses = new Set([
  "controlled_access",
  "restricted_human_subjects",
  "private_sponsor",
  "export_controlled",
  "embargoed"
]);

const dangerousCapabilities = new Set([
  "SYS_ADMIN",
  "NET_ADMIN",
  "DAC_READ_SEARCH",
  "SYS_PTRACE"
]);

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((result, key) => {
        result[key] = stable(value[key]);
        return result;
      }, {});
  }
  return value;
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(stable(value)))
    .digest("hex");
}

function hasPinnedImage(runtime = {}) {
  const digest = runtime.imageDigest || "";
  const image = runtime.image || "";
  return (
    /^sha256:[a-f0-9]{64}$/i.test(digest) ||
    /@sha256:[a-f0-9]{64}$/i.test(image)
  );
}

function highestInputRisk(inputs = []) {
  if (inputs.some((input) => restrictedDataClasses.has(input.dataClass))) {
    return "restricted";
  }
  if (inputs.some((input) => input.access === "private" || input.access === "internal")) {
    return "private";
  }
  return "public";
}

function addFinding(findings, severity, code, message, action) {
  findings.push({ severity, code, message, action });
}

function evaluateRunPlan(plan, options = {}) {
  const findings = [];
  const runtime = plan.runtime || {};
  const network = plan.network || {};
  const resources = plan.resources || {};
  const outputs = asArray(plan.outputs);
  const inputs = asArray(plan.inputs);
  const commands = asArray(plan.commands);
  const mounts = asArray(runtime.mounts);
  const inputRisk = highestInputRisk(inputs);

  if (!plan.runId) {
    addFinding(findings, BLOCK, "missing-run-id", "Run plan must include a stable runId.", "Add a runId before queueing the compute trigger.");
  }

  if (!hasPinnedImage(runtime)) {
    addFinding(findings, BLOCK, "unpinned-runtime-image", "Runtime image is not pinned by sha256 digest.", "Pin the Docker image with an immutable sha256 digest.");
  }

  if (runtime.privileged || runtime.allowPrivilegeEscalation) {
    addFinding(findings, BLOCK, "privileged-runtime", "Runtime requests privileged execution.", "Run the workload without privileged mode or privilege escalation.");
  }

  for (const capability of asArray(runtime.capabilities)) {
    if (dangerousCapabilities.has(capability)) {
      addFinding(findings, BLOCK, "dangerous-capability", `Runtime requests dangerous Linux capability ${capability}.`, "Drop dangerous capabilities from the sandbox profile.");
    }
  }

  for (const mount of mounts) {
    if (mount.type === "docker-socket") {
      addFinding(findings, BLOCK, "docker-socket-mount", "Run plan mounts the host Docker socket.", "Remove Docker socket access from sandboxed runs.");
    }
    if (mount.type === "hostPath" && mount.mode !== "readOnly") {
      addFinding(findings, BLOCK, "writable-host-mount", `Host path ${mount.path || "(unknown)"} is writable.`, "Use content-addressed artifact mounts or read-only mounts only.");
    }
    if (mount.type === "secret" && inputRisk !== "public") {
      addFinding(findings, HOLD, "secret-mount-review", "Secret mount is present for a non-public input run.", "Require reviewer approval and redact secret names from output artifacts.");
    }
  }

  if (!network.mode) {
    addFinding(findings, HOLD, "missing-network-policy", "Run plan has no explicit network policy.", "Set network.mode to deny, allowlist, or open with a documented reason.");
  } else if (network.mode === "open" && inputRisk !== "public") {
    addFinding(findings, BLOCK, "restricted-open-egress", "Restricted or private inputs cannot run with open network egress.", "Use deny egress or a reviewed allowlist for restricted data.");
  } else if (network.mode === "allowlist") {
    const allowlist = asArray(network.allowlist);
    if (allowlist.length === 0) {
      addFinding(findings, HOLD, "empty-egress-allowlist", "Allowlist network mode has no allowed destinations.", "Add exact domains or switch to deny mode.");
    }
    if (allowlist.some((entry) => entry === "*" || entry.startsWith("*."))) {
      addFinding(findings, BLOCK, "wildcard-egress", "Network allowlist contains wildcard egress.", "Replace wildcard entries with exact reviewed domains.");
    }
    if (inputRisk === "restricted" && !network.reviewerApproved) {
      addFinding(findings, HOLD, "restricted-egress-needs-review", "Restricted data egress allowlist lacks reviewer approval.", "Record reviewer approval for each allowed destination.");
    }
  }

  if (network.mode === "deny" && commands.some((command) => /\b(curl|wget|fetch|http|https)\b/i.test(command))) {
    addFinding(findings, HOLD, "command-network-mismatch", "Commands appear to fetch network resources while egress is denied.", "Vendor dependencies into the artifact bundle or remove network fetch commands.");
  }

  if (!resources.cpuCores || !resources.memoryMb || !resources.timeoutMinutes) {
    addFinding(findings, HOLD, "missing-resource-ceilings", "CPU, memory, and timeout ceilings are all required.", "Set cpuCores, memoryMb, and timeoutMinutes before enabling compute triggers.");
  }

  if (resources.timeoutMinutes > 240 || resources.memoryMb > 65536) {
    addFinding(findings, HOLD, "oversized-resource-request", "Resource request exceeds reviewer-ready sandbox defaults.", "Route oversized runs to manual compute review.");
  }

  if (outputs.length === 0) {
    addFinding(findings, HOLD, "missing-output-manifest", "Run plan declares no output manifest.", "Declare expected outputs with path, mediaType, checksum, and access.");
  }

  for (const output of outputs) {
    if (!output.path || !output.mediaType || !output.checksum) {
      addFinding(findings, HOLD, "incomplete-output-entry", `Output ${output.path || "(unknown)"} lacks path, mediaType, or checksum.`, "Complete output manifest metadata before publication.");
    }
    if (output.access === "public" && inputRisk !== "public" && !output.redactionApproval) {
      addFinding(findings, BLOCK, "restricted-public-output", `Output ${output.path || "(unknown)"} is public without redaction approval.`, "Keep output private or attach data steward redaction approval.");
    }
  }

  if (plan.schedule && plan.schedule.enabled) {
    if (inputs.some((input) => !input.version)) {
      addFinding(findings, HOLD, "scheduled-unpinned-input", "Scheduled rerun has at least one input without a version pin.", "Pin every scheduled input to a dataset version.");
    }
    if (!plan.reproducibility || !plan.reproducibility.seed) {
      addFinding(findings, HOLD, "scheduled-missing-seed", "Scheduled rerun lacks deterministic seed evidence.", "Record a deterministic seed or explain why the run is deterministic without one.");
    }
  }

  const blockers = findings.filter((finding) => finding.severity === BLOCK);
  const holds = findings.filter((finding) => finding.severity === HOLD);
  const decision = blockers.length > 0 ? BLOCK : holds.length > 0 ? HOLD : ALLOW;
  const score = Math.max(0, 100 - blockers.length * 25 - holds.length * 10);

  const result = {
    runId: plan.runId || "missing-run-id",
    title: plan.title || "Untitled run",
    decision,
    score,
    inputRisk,
    blockers: blockers.map(({ code, message, action }) => ({ code, message, action })),
    holds: holds.map(({ code, message, action }) => ({ code, message, action })),
    actions: findings.map((finding) => finding.action),
    reviewedAt: options.now || new Date().toISOString()
  };

  result.auditHash = sha256({ plan, decision: result.decision, findings });
  return result;
}

function evaluateBatch(plans, options = {}) {
  return asArray(plans).map((plan) => evaluateRunPlan(plan, options));
}

function renderMarkdownReport(results) {
  const lines = [
    "# Sandbox Egress Guard Report",
    "",
    "| Run | Decision | Score | Input risk | Findings | Audit hash |",
    "| --- | --- | ---: | --- | ---: | --- |"
  ];

  for (const result of results) {
    const findingCount = result.blockers.length + result.holds.length;
    lines.push(
      `| ${result.runId} | ${result.decision.toUpperCase()} | ${result.score} | ${result.inputRisk} | ${findingCount} | \`${result.auditHash.slice(0, 12)}\` |`
    );
  }

  lines.push("", "## Required Actions", "");
  for (const result of results) {
    lines.push(`### ${result.runId}`);
    if (result.actions.length === 0) {
      lines.push("- No action required.");
    } else {
      for (const action of result.actions) lines.push(`- ${action}`);
    }
    lines.push("");
  }

  return lines.join("\n").trimEnd();
}

function escapeXml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderDecisionSvg(results) {
  const width = 960;
  const rowHeight = 86;
  const height = 120 + results.length * rowHeight;
  const colorFor = {
    [ALLOW]: "#2f9e44",
    [HOLD]: "#f08c00",
    [BLOCK]: "#c92a2a"
  };
  const rows = results
    .map((result, index) => {
      const y = 86 + index * rowHeight;
      const barWidth = Math.max(8, Math.round(result.score * 4.6));
      const findingCount = result.blockers.length + result.holds.length;
      return `
  <g transform="translate(40 ${y})">
    <rect x="0" y="0" width="880" height="64" rx="8" fill="#111827" stroke="#273449"/>
    <text x="20" y="24" fill="#e5e7eb" font-size="16" font-family="Arial">${escapeXml(result.runId)}</text>
    <text x="20" y="46" fill="#9ca3af" font-size="12" font-family="Arial">${escapeXml(result.title)}</text>
    <rect x="420" y="18" width="${barWidth}" height="14" rx="7" fill="${colorFor[result.decision]}"/>
    <text x="420" y="50" fill="#d1d5db" font-size="13" font-family="Arial">score ${result.score} / findings ${findingCount}</text>
    <text x="760" y="38" fill="${colorFor[result.decision]}" font-size="18" font-family="Arial" font-weight="700">${result.decision.toUpperCase()}</text>
  </g>`;
    })
    .join("");

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <rect width="100%" height="100%" fill="#0b1020"/>
  <text x="40" y="42" fill="#f8fafc" font-size="28" font-family="Arial" font-weight="700">Scientific Run Sandbox Egress Guard</text>
  <text x="40" y="68" fill="#9ca3af" font-size="14" font-family="Arial">Synthetic run-plan decisions for issue #14 executable hosting safety</text>
${rows}
</svg>
`;
}

module.exports = {
  ALLOW,
  BLOCK,
  HOLD,
  evaluateBatch,
  evaluateRunPlan,
  hasPinnedImage,
  renderDecisionSvg,
  renderMarkdownReport,
  sha256
};
