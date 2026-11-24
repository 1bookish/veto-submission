// node tools/render-pet.js, renders Kiki's 8 moods (the sprites cut by tools/extract-pet.js from the team's
// drawing) into docs/img/kiki-states.png for the README / deck, on light and dark backgrounds.
import { chromium } from 'playwright-core';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const states = [['idle', 'On guard'], ['listening', 'Listening'], ['investigating', 'Investigating'], ['thinking', 'Thinking'],
  ['advising', 'Advising'], ['caution', 'Caution'], ['stop', 'STOP!'], ['verified', 'Verified']];
const img = async s => 'data:image/png;base64,' + (await fs.readFile(path.join(ROOT, 'web', 'pet', `${s}.png`))).toString('base64');
const cells = await Promise.all(states.map(async ([s, l]) => `<div class="c"><img src="${await img(s)}"><b>${l.toUpperCase()}</b></div>`));
const html = `<!doctype html><html><head><style>
body{margin:0;font-family:Segoe UI,Arial,sans-serif}
.g{display:grid;grid-template-columns:repeat(4,190px);gap:10px;padding:16px}
.light{background:#eef3f7}.dark{background:#111a22}
.c{border-radius:16px;padding:10px;text-align:center;height:190px;display:flex;flex-direction:column;align-items:center;justify-content:flex-end}
.light .c{background:#fff;box-shadow:0 4px 14px rgba(15,59,76,.1)}.dark .c{background:#1b2732}
.c img{max-width:170px;max-height:150px;object-fit:contain}
.c b{margin-top:6px;letter-spacing:.5px;font-size:13px}.light b{color:#0f3b4c}.dark b{color:#cfe3ee}
</style></head><body><div class="g light">${cells.join('')}</div><div class="g dark">${cells.join('')}</div></body></html>`;
let browser;
for (const channel of process.platform === 'win32' ? ['msedge', 'chrome', undefined] : [undefined, 'chrome']) {
  try { browser = await chromium.launch({ channel, headless: true }); break; } catch { /* next */ }
}
const page = await browser.newPage({ viewport: { width: 832, height: 860 }, deviceScaleFactor: 1.5 });
await page.setContent(html);
await fs.mkdir(path.join(ROOT, 'docs', 'img'), { recursive: true });
const out = path.join(ROOT, 'docs', 'img', 'kiki-states.png');
await page.screenshot({ path: out, fullPage: true });
await browser.close();
console.log(out);
