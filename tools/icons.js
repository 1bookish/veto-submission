// node tools/icons.js: turns the Lucide icon set (assets/icons/lucide/*.svg, ISC licence, v0.460.0) into
//   web/icons.js                                   inline SVG strings for the web app
//   android/app/src/main/res/drawable/ic_*.xml     Android vector drawables (tinted at runtime)
// Every SVG shape (path, circle, rect, line, polyline, polygon, ellipse) becomes vector path data, and path
// data is re-tokenised so compact arc flags ("a1 1 0 001 1") are always valid for Android's parser.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC = path.join(ROOT, 'assets', 'icons', 'lucide');
const DRAW = path.join(ROOT, 'android', 'app', 'src', 'main', 'res', 'drawable');
fs.mkdirSync(DRAW, { recursive: true });

const n = v => +(+v).toFixed(3);
const attrs = s => Object.fromEntries([...s.matchAll(/([\w-]+)="([^"]*)"/g)].map(m => [m[1], m[2]]));

// ---- SVG path re-tokeniser (handles arc flags written without separators)
function normalizePath(d) {
  const out = [];
  let i = 0, cmd = null;
  const ws = () => { while (i < d.length && /[\s,]/.test(d[i])) i++; };
  const num = () => {
    ws();
    const m = /^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?/i.exec(d.slice(i));
    if (!m) throw new Error(`bad number at ${i} in "${d}"`);
    i += m[0].length;
    return n(m[0]);
  };
  const flag = () => { ws(); const c = d[i++]; if (c !== '0' && c !== '1') throw new Error(`bad arc flag in "${d}"`); return c; };
  const ARGS = { m: 2, l: 2, h: 1, v: 1, c: 6, s: 4, q: 4, t: 2, a: 7, z: 0 };
  while (true) {
    ws();
    if (i >= d.length) break;
    if (/[a-z]/i.test(d[i])) { cmd = d[i++]; out.push(cmd); if (/z/i.test(cmd)) continue; }
    else if (!cmd) throw new Error(`path without command: "${d}"`);
    const k = ARGS[cmd.toLowerCase()];
    if (!k) continue;
    if (cmd.toLowerCase() === 'a') out.push([num(), num(), num(), flag(), flag(), num(), num()].join(' '));
    else out.push(Array.from({ length: k }, num).join(' '));
    ws();
    if (i < d.length && !/[a-z]/i.test(d[i]) && cmd === 'm') cmd = 'l';
    else if (i < d.length && !/[a-z]/i.test(d[i]) && cmd === 'M') cmd = 'L';
  }
  return out.join(' ');
}

function toPath(tag, a) {
  if (tag === 'path') return normalizePath(a.d);
  if (tag === 'circle') { const cx = +a.cx, cy = +a.cy, r = +a.r; return `M ${n(cx - r)} ${n(cy)} A ${r} ${r} 0 1 0 ${n(cx + r)} ${n(cy)} A ${r} ${r} 0 1 0 ${n(cx - r)} ${n(cy)} Z`; }
  if (tag === 'ellipse') { const cx = +a.cx, cy = +a.cy, rx = +a.rx, ry = +a.ry; return `M ${n(cx - rx)} ${n(cy)} A ${rx} ${ry} 0 1 0 ${n(cx + rx)} ${n(cy)} A ${rx} ${ry} 0 1 0 ${n(cx - rx)} ${n(cy)} Z`; }
  if (tag === 'line') return `M ${n(a.x1)} ${n(a.y1)} L ${n(a.x2)} ${n(a.y2)}`;
  if (tag === 'polyline' || tag === 'polygon') {
    const p = a.points.trim().split(/[\s,]+/).map(Number);
    let s = `M ${p[0]} ${p[1]}`;
    for (let j = 2; j < p.length; j += 2) s += ` L ${p[j]} ${p[j + 1]}`;
    return tag === 'polygon' ? s + ' Z' : s;
  }
  if (tag === 'rect') {
    const x = +(a.x || 0), y = +(a.y || 0), w = +a.width, h = +a.height;
    const rx = Math.min(+(a.rx || a.ry || 0), w / 2), ry = Math.min(+(a.ry || a.rx || 0), h / 2);
    if (!rx) return `M ${x} ${y} H ${x + w} V ${y + h} H ${x} Z`;
    return `M ${n(x + rx)} ${y} H ${n(x + w - rx)} A ${rx} ${ry} 0 0 1 ${n(x + w)} ${n(y + ry)} V ${n(y + h - ry)} A ${rx} ${ry} 0 0 1 ${n(x + w - rx)} ${n(y + h)} `
      + `H ${n(x + rx)} A ${rx} ${ry} 0 0 1 ${x} ${n(y + h - ry)} V ${n(y + ry)} A ${rx} ${ry} 0 0 1 ${n(x + rx)} ${y} Z`;
  }
  throw new Error('unsupported element ' + tag);
}

const web = {};
// direction icons flip in Arabic (right-to-left) on Android
const MIRROR = new Set(['arrow-left', 'arrow-right', 'chevron-left', 'chevron-right']);
const names =fs.readdirSync(SRC).filter(f => f.endsWith('.svg')).sort();
for (const f of names) {
  const name = f.replace(/\.svg$/, '');
  const svg = fs.readFileSync(path.join(SRC, f), 'utf8');
  const shapes = [...svg.matchAll(/<(path|circle|line|polyline|polygon|rect|ellipse)\b([^>]*?)\/?>/g)].map(m => ({ tag: m[1], a: attrs(m[2]) }));
  if (!shapes.length) throw new Error('no shapes in ' + f);
  // web: keep the original shapes (already safe, static markup)
  const inner = shapes.map(({ tag, a }) => `<${tag} ${Object.entries(a).map(([k, v]) => `${k}="${v}"`).join(' ')}/>`).join('');
  web[name] = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${inner}</svg>`;
  // android
  const paths = shapes.map(({ tag, a }) => `  <path android:pathData="${toPath(tag, a)}" android:fillColor="#00000000" android:strokeColor="#FFFFFFFF"\n      android:strokeWidth="2" android:strokeLineCap="round" android:strokeLineJoin="round" />`).join('\n');
  fs.writeFileSync(path.join(DRAW, `ic_${name.replace(/-/g, '_')}.xml`),
    `<?xml version="1.0" encoding="utf-8"?>\n<!-- Lucide "${name}" (ISC licence), converted by tools/icons.js -->\n<vector xmlns:android="http://schemas.android.com/apk/res/android"\n    android:width="24dp" android:height="24dp" android:viewportWidth="24" android:viewportHeight="24"${MIRROR.has(name) ? ' android:autoMirrored="true"' : ''}>\n${paths}\n</vector>\n`);
}
fs.writeFileSync(path.join(ROOT, 'web', 'icons.js'),
  `// Generated by tools/icons.js from Lucide v0.460.0 (ISC licence, assets/icons/lucide/LICENSE). Static, trusted markup.\n` +
  `export const ICONS = ${JSON.stringify(web, null, 0).replace(/","/g, '",\n  "')};\n\n` +
  `/** <span class="ico">…svg…</span> for buttons and labels; size and colour come from CSS (1em, currentColor). */\n` +
  `export function icon(name, cls = '') {\n  const s = document.createElement('span');\n  s.className = 'ico' + (cls ? ' ' + cls : '');\n  s.innerHTML = ICONS[name] || '';\n  return s;\n}\n`);
console.log(`${names.length} icons -> web/icons.js + ${names.length} Android vector drawables`);
