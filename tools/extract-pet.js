// node tools/extract-pet.js [--debug]
// Cuts the team's pet drawing (assets/pet-sheet.webp: 2 rows x 4 moods, each with a label underneath)
// into 8 transparent PNG sprites, the original art, unchanged, only the white background and the
// labels removed:
//   web/pet/<mood>.png  and  android/app/src/main/res/drawable-nodpi/pet_<mood>.png
//
// How: decode the WebP in headless Edge, then in Node
//   1. flood-fill the white background from the image border (it cannot get inside the dark outlines),
//   2. "colour to alpha" on the background-connected pixels only, so anti-aliased edges and soft glows
//      (sound waves, magnifier beam, sparkles) stay soft on dark screens while the white body stays solid,
//   3. connected components -> drop the label letters -> give every other piece to the nearest pet body,
//   4. crop each pet with a small margin and write PNG (own tiny encoder, no image library needed).
import { chromium } from 'playwright-core';
import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'assets', 'pet-sheet.webp');
const MOODS = [['idle', 'listening', 'investigating', 'thinking'], ['advising', 'caution', 'stop', 'verified']];
const DEBUG = process.argv.includes('--debug');

async function decode(file) {
  const b64 = (await fs.readFile(file)).toString('base64');
  let browser;
  for (const channel of process.platform === 'win32' ? ['msedge', 'chrome', undefined] : [undefined, 'chrome']) {
    try { browser = await chromium.launch({ channel, headless: true }); break; } catch { /* try next */ }
  }
  if (!browser) throw new Error('No Chromium-based browser found (install Edge or Chrome).');
  const page = await browser.newPage();
  const out = await page.evaluate(async src => {
    const img = new Image();
    img.src = src;
    await img.decode();
    const c = document.createElement('canvas');
    c.width = img.naturalWidth; c.height = img.naturalHeight;
    const g = c.getContext('2d', { colorSpace: 'srgb' });
    g.drawImage(img, 0, 0);
    const d = g.getImageData(0, 0, c.width, c.height).data;
    let s = '';
    for (let i = 0; i < d.length; i += 0x8000) s += String.fromCharCode.apply(null, d.subarray(i, i + 0x8000));
    return { w: c.width, h: c.height, b64: btoa(s) };
  }, 'data:image/webp;base64,' + b64);
  await browser.close();
  return { w: out.w, h: out.h, px: Buffer.from(out.b64, 'base64') };
}

// ---------- tiny PNG encoder (RGBA, 8-bit) ----------
const CRC = new Int32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c; });
const crc32 = buf => { let c = -1; for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
function encodePNG(w, h, rgba) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

// ---------- 1+2: background flood and colour-to-alpha ----------
const { w, h, px } = await decode(SRC);
const N = w * h;
const minC = i => Math.min(px[i * 4], px[i * 4 + 1], px[i * 4 + 2]);
const LIGHT = 150;          // the flood may cross light pixels (white, pale glows); dark outlines stop it
const bg = new Uint8Array(N);
{
  const q = new Int32Array(N); let qh = 0, qt = 0;
  const push = i => { if (!bg[i] && minC(i) >= LIGHT) { bg[i] = 1; q[qt++] = i; } };
  for (let x = 0; x < w; x++) { push(x); push((h - 1) * w + x); }
  for (let y = 0; y < h; y++) { push(y * w); push(y * w + w - 1); }
  while (qh < qt) {
    const i = q[qh++], x = i % w;
    if (x > 0) push(i - 1);
    if (x < w - 1) push(i + 1);
    if (i >= w) push(i - w);
    if (i < N - w) push(i + w);
  }
}
const rgba = Buffer.alloc(N * 4);
const NOISE = 10;           // WebP ringing on the white paper
for (let i = 0; i < N; i++) {
  let r = px[i * 4], g = px[i * 4 + 1], b = px[i * 4 + 2], a = 255;
  if (bg[i]) {
    const m = Math.max(255 - r, 255 - g, 255 - b);
    if (m <= NOISE) { r = g = b = a = 0; }
    else {
      const k = 255 / m;
      r = Math.round(255 - (255 - r) * k); g = Math.round(255 - (255 - g) * k); b = Math.round(255 - (255 - b) * k);
      a = Math.round((m - NOISE) * 255 / (255 - NOISE));
    }
  }
  rgba[i * 4] = r; rgba[i * 4 + 1] = g; rgba[i * 4 + 2] = b; rgba[i * 4 + 3] = a;
}

// ---------- 3: connected components on visible pixels ----------
const ALPHA_MIN = 24;
const comp = new Int32Array(N).fill(-1);
const comps = [];
{
  const q = new Int32Array(N);
  for (let s = 0; s < N; s++) {
    if (comp[s] !== -1 || rgba[s * 4 + 3] < ALPHA_MIN) continue;
    const id = comps.length;
    const c = { id, area: 0, x0: w, y0: h, x1: 0, y1: 0, dark: 0 };
    let qh = 0, qt = 0;
    comp[s] = id; q[qt++] = s;
    while (qh < qt) {
      const i = q[qh++], x = i % w, y = (i / w) | 0;
      c.area++;
      if (x < c.x0) c.x0 = x; if (x > c.x1) c.x1 = x; if (y < c.y0) c.y0 = y; if (y > c.y1) c.y1 = y;
      if (minC(i) < 110 && Math.max(px[i * 4], px[i * 4 + 1], px[i * 4 + 2]) - minC(i) < 40) c.dark++;
      for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
        const nx = x + dx, ny = y + dy;
        if (nx < 0 || ny < 0 || nx >= w || ny >= h) continue;
        const j = ny * w + nx;
        if (comp[j] === -1 && rgba[j * 4 + 3] >= ALPHA_MIN) { comp[j] = id; q[qt++] = j; }
      }
    }
    comps.push(c);
  }
}
const big = comps.filter(c => c.area >= 12);
const bodies = [...big].sort((a, b) => b.area - a.area).slice(0, 8);
// order bodies into the 2 x 4 grid: by row (y centre), then by x
bodies.sort((a, b) => (a.y0 + a.y1) - (b.y0 + b.y1));
const rows = [bodies.slice(0, 4), bodies.slice(4)].map(r => r.sort((a, b) => a.x0 - b.x0));
const mood = new Map();
rows.forEach((r, ri) => r.forEach((c, ci) => mood.set(c.id, MOODS[ri][ci])));

// Label letters: short pieces that sit on a shared text line, many components with the same top and
// bottom (the captions "IDLE", "LISTENING" ... are set in one font size on two baselines).
const sameLine = c => big.filter(o => o !== c && Math.abs(o.y0 - c.y0) <= 2 && Math.abs(o.y1 - c.y1) <= 2).length;
const isLabel = c => !mood.has(c.id) && (c.y1 - c.y0) >= 8 && (c.y1 - c.y0) <= 40 && c.dark / c.area > 0.25 && sameLine(c) >= 6;
const gap = (a, b) => Math.hypot(Math.max(0, a.x0 - b.x1, b.x0 - a.x1), Math.max(0, a.y0 - b.y1, b.y0 - a.y1));
const owner = new Map(); // component id -> mood
for (const c of big) {
  if (mood.has(c.id)) { owner.set(c.id, mood.get(c.id)); continue; }
  if (isLabel(c)) continue;
  let best = null, bd = Infinity;
  for (const b of bodies) { const d = gap(c, b); if (d < bd) { bd = d; best = b; } }
  if (best && bd < 90) owner.set(c.id, mood.get(best.id));
}

if (DEBUG) {
  console.log(`sheet ${w}x${h}, ${comps.length} components (${big.length} with area >= 12)`);
  for (const c of big) console.log(String(c.id).padStart(4), `x ${c.x0}-${c.x1}`.padEnd(13), `y ${c.y0}-${c.y1}`.padEnd(11),
    `area ${c.area}`.padEnd(11), `dark ${(c.dark / c.area).toFixed(2)}`, mood.has(c.id) ? `BODY ${mood.get(c.id)}` : owner.has(c.id) ? `-> ${owner.get(c.id)}` : isLabel(c) ? 'label' : 'dropped');
}

// ---------- 4: crop + write ----------
const outDirs = [path.join(ROOT, 'web', 'pet'), path.join(ROOT, 'android', 'app', 'src', 'main', 'res', 'drawable-nodpi')];
for (const d of outDirs) await fs.mkdir(d, { recursive: true });
const PAD = 6, GROW = 8;
const report = [];
for (const m of MOODS.flat()) {
  const ids = new Set([...owner].filter(([, v]) => v === m).map(([k]) => k));
  const parts = big.filter(c => ids.has(c.id));
  const x0 = Math.max(0, Math.min(...parts.map(c => c.x0)) - PAD), y0 = Math.max(0, Math.min(...parts.map(c => c.y0)) - PAD);
  const x1 = Math.min(w - 1, Math.max(...parts.map(c => c.x1)) + PAD), y1 = Math.min(h - 1, Math.max(...parts.map(c => c.y1)) + PAD);
  const cw = x1 - x0 + 1, ch = y1 - y0 + 1;
  // keep: pixels of this pet's components + faint glow pixels within GROW px of them (not owned by others)
  const keep = new Uint8Array(cw * ch);
  for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) {
    const id = comp[y * w + x];
    if (id >= 0 && ids.has(id)) {
      for (let dy = -GROW; dy <= GROW; dy++) for (let dx = -GROW; dx <= GROW; dx++) {
        const nx = x + dx - x0, ny = y + dy - y0;
        if (nx >= 0 && ny >= 0 && nx < cw && ny < ch) keep[ny * cw + nx] = keep[ny * cw + nx] || 1;
      }
      keep[(y - y0) * cw + (x - x0)] = 2;
    }
  }
  const out = Buffer.alloc(cw * ch * 4);
  for (let y = 0; y < ch; y++) for (let x = 0; x < cw; x++) {
    const k = keep[y * cw + x];
    if (!k) continue;
    const i = (y + y0) * w + (x + x0);
    const id = comp[i];
    if (k === 1 && id >= 0) continue;               // a solid pixel that belongs to someone else (or a label)
    rgba.copy(out, (y * cw + x) * 4, i * 4, i * 4 + 4);
  }
  const file = encodePNG(cw, ch, out);
  for (const d of outDirs) await fs.writeFile(path.join(d, (d.includes('drawable') ? 'pet_' : '') + m + '.png'), file);
  report.push(`${m.padEnd(13)} ${cw}x${ch}  from (${x0},${y0})  ${parts.length} parts  ${(file.length / 1024).toFixed(1)} KB`);
}
console.log(report.join('\n'));
