import { chromium } from "playwright-core";
const exe = "/home/z/.cache/ms-playwright/chromium-1200/chrome-linux64/chrome";
const t0 = Date.now();
const browser = await chromium.launch({ executablePath: exe, args: ["--no-sandbox", "--disable-dev-shm-usage"] });
const page = await browser.newPage();
try {
  const resp = await page.goto("https://example.com", { waitUntil: "domcontentloaded", timeout: 20000 });
  const title = await page.title();
  const html = await page.content();
  console.log(JSON.stringify({ status: resp?.status(), title, ms: Date.now() - t0, htmlLen: html.length, hasH1: html.includes("<h1") }));
} catch (e) {
  console.error("ERR:", e.message?.slice(0, 200));
} finally {
  await browser.close();
}
