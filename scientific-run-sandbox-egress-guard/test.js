const assert = require("node:assert/strict");
const plans = require("./data/sample-plans.json");
const {
  ALLOW,
  BLOCK,
  HOLD,
  evaluateBatch,
  evaluateRunPlan,
  hasPinnedImage,
  renderDecisionSvg,
  renderMarkdownReport
} = require("./index");

const fixedNow = "2026-05-29T11:20:00.000Z";
const results = evaluateBatch(plans, { now: fixedNow });
const byRun = Object.fromEntries(results.map((result) => [result.runId, result]));

assert.equal(byRun["safe-notebook-deny-egress"].decision, ALLOW);
assert.equal(byRun["safe-notebook-deny-egress"].blockers.length, 0);
assert.equal(byRun["restricted-open-egress"].decision, BLOCK);
assert.ok(byRun["restricted-open-egress"].blockers.some((finding) => finding.code === "restricted-open-egress"));
assert.ok(byRun["restricted-open-egress"].blockers.some((finding) => finding.code === "unpinned-runtime-image"));
assert.equal(byRun["scheduled-rerun-needs-seed"].decision, HOLD);
assert.ok(byRun["scheduled-rerun-needs-seed"].holds.some((finding) => finding.code === "scheduled-unpinned-input"));
assert.ok(byRun["scheduled-rerun-needs-seed"].holds.some((finding) => finding.code === "scheduled-missing-seed"));
assert.equal(byRun["restricted-allowlist-review"].decision, HOLD);
assert.ok(byRun["restricted-allowlist-review"].holds.some((finding) => finding.code === "restricted-egress-needs-review"));

assert.equal(
  hasPinnedImage({ image: "registry.example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }),
  true
);
assert.equal(hasPinnedImage({ image: "registry.example/app:latest" }), false);

const first = evaluateRunPlan(plans[0], { now: fixedNow });
const second = evaluateRunPlan(plans[0], { now: fixedNow });
assert.equal(first.auditHash, second.auditHash);

const markdown = renderMarkdownReport(results);
assert.match(markdown, /safe-notebook-deny-egress/);
assert.match(markdown, /restricted-open-egress/);

const svg = renderDecisionSvg(results);
assert.match(svg, /Scientific Run Sandbox Egress Guard/);
assert.match(svg, /BLOCK/);

console.log("All sandbox egress guard tests passed.");
