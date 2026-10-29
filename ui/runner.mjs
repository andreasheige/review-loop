// review-loop ui runner: one side (base or head) of a UI check, driven by review_loop/ui.py.
//
// usage: node runner.mjs <config.json>
// config: {nodeModules, baseUrl, stories: [id], viewports: [{name, width, height}], schemes: ["light", "dark"],
//          shots: <dir>, out: <results.json>}
//
// For every story x viewport x colour scheme: load <baseUrl>/iframe.html?id=<id>&viewMode=story with every
// request to a host other than 127.0.0.1/localhost aborted, run axe-core (WCAG 2.0/2.1/2.2 A and AA tags),
// press Tab up to 25 times to find a keyboard trap, and take a screenshot. Playwright and axe-core come from
// the repo under review (nodeModules), so review-loop installs nothing.
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
const require = createRequire(path.join(config.nodeModules, "noop.js"));
const { chromium } = require("playwright");
const axeSource = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const LOCAL = /^(https?:\/\/)(127\.0\.0\.1|localhost)(:\d+)?\//;

mkdirSync(config.shots, { recursive: true });
const browser = await chromium.launch();
const results = [];
try {
  for (const scheme of config.schemes) {
    for (const vp of config.viewports) {
      const context = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, colorScheme: scheme,
                                                 reducedMotion: "reduce" });
      await context.route("**/*", (route) => (LOCAL.test(route.request().url()) ? route.continue() : route.abort()));
      const page = await context.newPage();
      for (const id of config.stories) {
        const key = `${id}|${vp.name}|${scheme}`;
        const entry = { story: id, viewport: vp.name, scheme, violations: [], trap: null, shot: null, error: null };
        try {
          await page.goto(`${config.baseUrl}/iframe.html?id=${encodeURIComponent(id)}&viewMode=story`,
                          { waitUntil: "networkidle", timeout: 30000 });
          await page.waitForTimeout(150);
          await page.addScriptTag({ content: axeSource });
          const axe = await page.evaluate(async (tags) => {
            const r = await window.axe.run(document, { runOnly: { type: "tag", values: tags }, resultTypes: ["violations"] });
            return r.violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help,
                                              targets: v.nodes.map((n) => n.target.join(" ")).slice(0, 10) }));
          }, TAGS);
          entry.violations = axe;
          entry.trap = await keyboardTrap(page);
          const file = path.join(config.shots, `${key.replace(/[^a-zA-Z0-9_.-]/g, "_")}.png`);
          await page.screenshot({ path: file, fullPage: true, animations: "disabled" });
          entry.shot = file;
        } catch (e) {
          entry.error = String(e && e.message ? e.message : e).slice(0, 300);
        }
        results.push(entry);
      }
      await context.close();
    }
  }
} finally {
  await browser.close();
}
writeFileSync(config.out, JSON.stringify(results, null, 1));

// A trap: focus reaches an element and the next 8 Tabs (and Shift+Tab) never move it, while the page has
// other focusable elements. Returns a selector-ish description of the trapped element, or null.
async function keyboardTrap(page) {
  const focusable = await page.evaluate(() =>
    document.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select,textarea,[tabindex]:not([tabindex="-1"])').length);
  if (focusable < 2) return null;
  const describe = () => page.evaluate(() => {
    const el = document.activeElement;
    if (!el || el === document.body) return null;
    return `${el.tagName.toLowerCase()}${el.id ? "#" + el.id : ""}${el.getAttribute("aria-label") ? `[aria-label="${el.getAttribute("aria-label")}"]` : ""}`;
  });
  let last = null, same = 0;
  for (let i = 0; i < 25; i++) {
    await page.keyboard.press("Tab");
    const now = await describe();
    same = now && now === last ? same + 1 : 0;
    last = now;
    if (same >= 8) {
      await page.keyboard.press("Shift+Tab");
      const back = await describe();
      if (back === now) return now;
      return null;
    }
  }
  return null;
}
