// node tools/make-icons.js, renders web/icon.svg to the PNG sizes app stores / Android need.
import { chromium } from 'playwright-core';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const svg = await fs.readFile(path.join(ROOT, 'web', 'icon.svg'), 'utf8');
let browser;
for (const channel of process.platform === 'win32' ? ['msedge', 'chrome', undefined] : [undefined, 'chrome']) {
  try { browser = await chromium.launch({ channel, headless: true }); break; } catch { /* next */ }
}
const page = await browser.newPage();
for (const size of [192, 512]) {
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<html><body style="margin:0;background:transparent">${svg.replace('<svg ', `<svg width="${size}" height="${size}" `)}</body></html>`);
  await page.screenshot({ path: path.join(ROOT, 'web', `icon-${size}.png`), omitBackground: true });
  console.log(`web/icon-${size}.png`);
}
await browser.close();
