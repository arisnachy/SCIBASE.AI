const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { chromium } = require("playwright");

const root = path.resolve(__dirname, "..");
const reportsDir = path.join(root, "reports");
const outputPath = path.join(reportsDir, "demo-output.json");
const videoDir = path.join(reportsDir, ".video-tmp");
const finalVideoPath = path.join(reportsDir, "sandbox-egress-demo.webm");

function ensureDemoOutput() {
  if (!fs.existsSync(outputPath)) {
    execFileSync(process.execPath, ["demo.js"], {
      cwd: root,
      stdio: "inherit"
    });
  }
}

function htmlFor(results) {
  const cards = results
    .map((result, index) => {
      const findingCount = result.blockers.length + result.holds.length;
      const color = result.decision === "allow" ? "#2f9e44" : result.decision === "hold" ? "#f08c00" : "#c92a2a";
      const actions = result.actions.slice(0, 3).map((action) => `<li>${escapeHtml(action)}</li>`).join("");
      return `<section class="card" data-index="${index}">
        <div class="decision" style="color:${color}">${result.decision.toUpperCase()}</div>
        <h2>${escapeHtml(result.runId)}</h2>
        <p>${escapeHtml(result.title)}</p>
        <div class="bar"><span style="width:${result.score}% ; background:${color}"></span></div>
        <div class="meta">Score ${result.score} / Findings ${findingCount} / Risk ${result.inputRisk}</div>
        <ul>${actions || "<li>No action required.</li>"}</ul>
      </section>`;
    })
    .join("");

  return `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8" />
    <style>
      * { box-sizing: border-box; }
      body {
        margin: 0;
        width: 1280px;
        height: 720px;
        overflow: hidden;
        background: #07111f;
        color: #e5e7eb;
        font-family: Arial, sans-serif;
      }
      .frame { padding: 42px 54px; }
      h1 { margin: 0 0 8px; font-size: 34px; }
      .subtitle { color: #9ca3af; margin-bottom: 26px; font-size: 18px; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
      .card {
        min-height: 242px;
        border: 1px solid #243247;
        border-radius: 12px;
        background: #0f1b2d;
        padding: 22px;
        opacity: 0.54;
        transform: scale(0.985);
        transition: all 240ms ease;
      }
      .card.active {
        opacity: 1;
        transform: scale(1);
        border-color: #60a5fa;
        box-shadow: 0 0 0 3px rgba(96,165,250,0.18);
      }
      h2 { margin: 10px 0 6px; font-size: 22px; }
      p { color: #cbd5e1; min-height: 42px; margin: 0 0 16px; line-height: 1.35; }
      .decision { font-weight: 800; letter-spacing: 0.08em; font-size: 16px; }
      .bar { height: 12px; background: #1f2937; border-radius: 999px; overflow: hidden; }
      .bar span { display: block; height: 100%; border-radius: 999px; }
      .meta { margin-top: 10px; color: #93c5fd; font-size: 14px; }
      ul { margin: 12px 0 0; padding-left: 18px; color: #d1d5db; font-size: 13px; line-height: 1.35; }
      .footer { position: absolute; left: 54px; right: 54px; bottom: 28px; color: #94a3b8; font-size: 14px; }
    </style>
  </head>
  <body>
    <main class="frame">
      <h1>Scientific Run Sandbox Egress Guard</h1>
      <div class="subtitle">Issue #14 executable hosting safety demo from synthetic run plans</div>
      <div class="grid">${cards}</div>
      <div class="footer">Generated locally with Playwright. No external APIs, secrets, or private data.</div>
    </main>
    <script>
      const cards = [...document.querySelectorAll(".card")];
      let index = 0;
      function tick() {
        cards.forEach((card, cardIndex) => card.classList.toggle("active", cardIndex === index));
        index = (index + 1) % cards.length;
      }
      tick();
      setInterval(tick, 1250);
    </script>
  </body>
  </html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function main() {
  ensureDemoOutput();
  fs.mkdirSync(videoDir, { recursive: true });
  const results = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    recordVideo: {
      dir: videoDir,
      size: { width: 1280, height: 720 }
    }
  });
  const page = await context.newPage();
  await page.setContent(htmlFor(results), { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(6200);
  const video = page.video();
  await page.close();
  await context.close();
  await browser.close();

  const recordedPath = await video.path();
  fs.copyFileSync(recordedPath, finalVideoPath);
  fs.rmSync(videoDir, { recursive: true, force: true });
  console.log(`Demo video written to ${finalVideoPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
