const fs = require("node:fs");
const path = require("node:path");
const {
  evaluateBatch,
  renderDecisionSvg,
  renderMarkdownReport
} = require("./index");

const root = __dirname;
const samplePath = path.join(root, "data", "sample-plans.json");
const reportsDir = path.join(root, "reports");
const plans = JSON.parse(fs.readFileSync(samplePath, "utf8"));
const results = evaluateBatch(plans);

fs.mkdirSync(reportsDir, { recursive: true });
fs.writeFileSync(path.join(reportsDir, "demo-output.json"), `${JSON.stringify(results, null, 2)}\n`);
fs.writeFileSync(path.join(reportsDir, "demo-report.md"), `${renderMarkdownReport(results)}\n`);
fs.writeFileSync(path.join(reportsDir, "decision-matrix.svg"), renderDecisionSvg(results));

for (const result of results) {
  const findingCount = result.blockers.length + result.holds.length;
  console.log(`${result.runId}: ${result.decision.toUpperCase()} score=${result.score} findings=${findingCount}`);
}

console.log(`Reports written to ${reportsDir}`);
