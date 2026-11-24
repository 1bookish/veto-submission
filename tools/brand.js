// node tools/brand.js: makes every brand asset from the team's logo (assets/veto-logo.jpg):
//   web/brand/veto-mark.png       shield + check, transparent (for dark surfaces)
//   web/brand/veto-wordmark.png   "VETO.ai", transparent
//   web/icon-192.png, web/icon-512.png, android res/drawable-nodpi/ic_launcher.png   app icons (mark on navy)
//   android res/drawable-nodpi/veto_mark.png, veto_wordmark.png
// The logo is light on a dark navy background, so the background is removed by "un-screening" it:
// subtract the navy, treat what is left as light (alpha = brightest channel). Composited back on a dark
// surface it looks identical to the original.
import { chromium } from 'playwright-core';
import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CRC = new Int32Array(256).map((_, k) => { let c = k; for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c; });
const crc32 = b => { let c = -1; for (const x of b) c = CRC[(c ^ x) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
function png(w, h, rgba) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  const chunk = (t, d) => { const l = Buffer.alloc(4); l.writeUInt32BE(d.length); const td = Buffer.concat([Buffer.from(t, 'latin1'), d]); const c = Buffer.alloc(4); c.writeUInt32BE(crc32(td)); return Buffer.concat([l, td, c]); };
  const ih = Buffer.alloc(13); ih.writeUInt32BE(w, 0); ih.writeUInt32BE(h, 4); ih[8] = 8; ih[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ih), chunk('IDAT', zlib.deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

let browser;
for (const channel of process.platform === 'win32' ? ['msedge', 'chrome', undefined] : [undefined, 'chrome']) {
  try { browser = await chromium.launch({ channel, headless: true }); break; } catch { /* next */ }
}
const page = await browser.newPage();
const src = 'data:image/jpeg;base64,' + (await fs.readFile(path.join(ROOT, 'assets', 'veto-logo.jpg'))).toString('base64');
const { w, h, b64 } = await page.evaluate(async s => {
  const img = new Image(); img.src = s; await img.decode();
  const c = document.createElement('canvas'); c.width = img.naturalWidth; c.height = img.naturalHeight;
  const g = c.getContext('2d'); g.drawImage(img, 0, 0);
  const d = g.getImageData(0, 0, c.width, c.height).data;
  let out = ''; for (let i = 0; i < d.length; i += 0x8000) out += String.fromCharCode.apply(null, d.subarray(i, i + 0x8000));
  return { w: c.width, h: c.height, b64: btoa(out) };
}, src);
const px = Buffer.from(b64, 'base64');

// background colour: median of the four corners
const corner = (x, y) => [px[(y * w + x) * 4], px[(y * w + x) * 4 + 1], px[(y * w + x) * 4 + 2]];
const cs = [corner(4, 4), corner(w - 5, 4), corner(4, h - 5), corner(w - 5, h - 5)];
const bg = [0, 1, 2].map(k => cs.map(c => c[k]).sort((a, b) => a - b)[1]);
const BGLIFT = 14; // the navy gets a little lighter towards the centre; treat that glow as background too
const out = Buffer.alloc(w * h * 4);
for (let i = 0; i < w * h; i++) {
  const c = [px[i * 4], px[i * 4 + 1], px[i * 4 + 2]].map((v, k) => Math.max(0, v - bg[k] - BGLIFT) / (255 - bg[k] - BGLIFT));
  let a = Math.max(...c);
  if (a < 0.06) a = 0;
  const col = a ? c.map(v => Math.min(255, Math.round((v / a) * 255))) : [0, 0, 0];
  out[i * 4] = col[0]; out[i * 4 + 1] = col[1]; out[i * 4 + 2] = col[2]; out[i * 4 + 3] = Math.round(Math.min(1, a * 1.08) * 255);
}
// split mark (top) and wordmark (bottom) at the widest empty horizontal band
const rowInk = y => { let s = 0; for (let x = 0; x < w; x++) if (out[(y * w + x) * 4 + 3] > 90) s++; return s; };
const rows = Array.from({ length: h }, (_, y) => rowInk(y));
let best = { len: 0, at: h / 2 }, run = 0;
for (let y = Math.round(h * 0.3); y < Math.round(h * 0.85); y++) { if (rows[y] === 0) { run++; if (run > best.len) best = { len: run, at: y - Math.floor(run / 2) }; } else run = 0; }
function bbox(y0, y1) {
  let x0 = w, x1 = 0, t = h, b = 0;
  for (let y = y0; y < y1; y++) for (let x = 0; x < w; x++) if (out[(y * w + x) * 4 + 3] > 40) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < t) t = y; if (y > b) b = y; }
  return { x0, x1, t, b };
}
function crop(bb, pad) {
  const x0 = Math.max(0, bb.x0 - pad), y0 = Math.max(0, bb.t - pad), x1 = Math.min(w - 1, bb.x1 + pad), y1 = Math.min(h - 1, bb.b + pad);
  const cw = x1 - x0 + 1, ch = y1 - y0 + 1, buf = Buffer.alloc(cw * ch * 4);
  for (let y = 0; y < ch; y++) out.copy(buf, y * cw * 4, ((y + y0) * w + x0) * 4, ((y + y0) * w + x1 + 1) * 4);
  return { cw, ch, buf };
}
// the gap we want lies BETWEEN ink (shield above, letters below), not in the margins
{
  const first = rows.findIndex(r => r > 0), last = h - 1 - [...rows].reverse().findIndex(r => r > 0);
  best = { len: 0, at: Math.round((first + last) / 2) }; run = 0;
  for (let y = first; y <= last; y++) { if (rows[y] === 0) { run++; if (run > best.len) best = { len: run, at: y - Math.floor(run / 2) }; } else run = 0; }
}
const markBB = bbox(0, best.at), wordBB = bbox(best.at, h);
const mark = crop(markBB, 24), word = crop(wordBB, 16);
await fs.mkdir(path.join(ROOT, 'web', 'brand'), { recursive: true });
const DN = path.join(ROOT, 'android', 'app', 'src', 'main', 'res', 'drawable-nodpi');
await fs.mkdir(DN, { recursive: true });
await fs.writeFile(path.join(ROOT, 'web', 'brand', 'veto-mark.png'), png(mark.cw, mark.ch, mark.buf));
await fs.writeFile(path.join(ROOT, 'web', 'brand', 'veto-wordmark.png'), png(word.cw, word.ch, word.buf));
await fs.writeFile(path.join(DN, 'veto_mark.png'), png(mark.cw, mark.ch, mark.buf));
await fs.writeFile(path.join(DN, 'veto_wordmark.png'), png(word.cw, word.ch, word.buf));
// the same wordmark for LIGHT surfaces: the white letters become navy, the cyan ".ai" a deeper blue
// that keeps contrast on white (same shapes, same anti-aliasing, only the ink changes)
const dark = Buffer.from(word.buf);
for (let i = 0; i < word.cw * word.ch; i++) {
  if (!dark[i * 4 + 3]) continue;
  const r = dark[i * 4], g = dark[i * 4 + 1], b = dark[i * 4 + 2];
  const mx = Math.max(r, g, b), sat = mx ? (mx - Math.min(r, g, b)) / mx : 0;
  const ink = sat < 0.3 ? [0x0b, 0x16, 0x30] : [0x0a, 0x6c, 0xe8];
  dark[i * 4] = ink[0]; dark[i * 4 + 1] = ink[1]; dark[i * 4 + 2] = ink[2];
}
await fs.writeFile(path.join(ROOT, 'web', 'brand', 'veto-wordmark-dark.png'), png(word.cw, word.ch, dark));
await fs.writeFile(path.join(DN, 'veto_wordmark_dark.png'), png(word.cw, word.ch, dark));

// app icons: the original mark (with its own navy) centred on a navy rounded square, rendered in the browser
const markData = 'data:image/png;base64,' + png(mark.cw, mark.ch, mark.buf).toString('base64');
for (const size of [512, 192]) {
  const data = await page.evaluate(async ({ m, size }) => {
    const img = new Image(); img.src = m; await img.decode();
    const c = document.createElement('canvas'); c.width = c.height = size;
    const g = c.getContext('2d');
    const grd = g.createRadialGradient(size * 0.5, size * 0.42, size * 0.05, size * 0.5, size * 0.5, size * 0.75);
    grd.addColorStop(0, '#12285a'); grd.addColorStop(0.55, '#0a1634'); grd.addColorStop(1, '#050b1c');
    g.fillStyle = grd; g.fillRect(0, 0, size, size);
    const s = size * 0.64, r = img.width / img.height;
    const dw = r >= 1 ? s : s * r, dh = r >= 1 ? s / r : s;
    g.drawImage(img, (size - dw) / 2, (size - dh) / 2 + size * 0.02, dw, dh);
    return c.toDataURL('image/png').split(',')[1];
  }, { m: markData, size });
  const buf = Buffer.from(data, 'base64');
  await fs.writeFile(path.join(ROOT, 'web', `icon-${size}.png`), buf);
  if (size === 512) await fs.writeFile(path.join(DN, 'ic_launcher.png'), buf);
}
await browser.close();
console.log(`background rgb(${bg}) · mark ${mark.cw}x${mark.ch} · wordmark ${word.cw}x${word.ch} · split at y=${best.at}`);
