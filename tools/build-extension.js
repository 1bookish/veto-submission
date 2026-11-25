// npm run build:extension
// Builds the Veto.ai browser extension (Chrome, Edge, Brave, Opera; Manifest V3) into build/extension/ and
// build/veto-extension.zip. The extension runs the same engine files as the server: they are copied, not rewritten.
// Guards: no engine file with Node-only imports is shipped, and every relative import in the package resolves.
// Load it: chrome://extensions (or edge://extensions) -> Developer mode -> Load unpacked -> build/extension
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeZip } from '../server/zip.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'build', 'extension');
const ZIP = path.join(ROOT, 'build', 'veto-extension.zip');
const NODE_ONLY = /from\s+['"]node:|require\(['"]node:/;

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(path.join(OUT, 'engine'), { recursive: true });
fs.mkdirSync(path.join(OUT, 'data'), { recursive: true });
fs.mkdirSync(path.join(OUT, 'icons'), { recursive: true });

// 1. the extension's own files
for (const f of fs.readdirSync(path.join(ROOT, 'extension'))) {
  if (f === 'README.md') continue;
  fs.copyFileSync(path.join(ROOT, 'extension', f), path.join(OUT, f));
}
fs.copyFileSync(path.join(ROOT, 'web', 'icon-192.png'), path.join(OUT, 'icons', 'icon-192.png'));

// 2. the engine (browser-safe files only)
const skipped = [];
for (const f of fs.readdirSync(path.join(ROOT, 'engine'))) {
  if (!f.endsWith('.js')) continue;
  const src = fs.readFileSync(path.join(ROOT, 'engine', f), 'utf8');
  if (NODE_ONLY.test(src)) { skipped.push(f); continue; }
  fs.writeFileSync(path.join(OUT, 'engine', f), src);
}

// 3. data: the rulebook, the models and the popularity list (not the server's logos or reports)
const DATA = ['institutions.js', 'uae-brands.js', 'evidence.js', 'radar.js', 'brands.js', 'urlml-model.js', 'hosting-providers.js', 'urlml2-model.json.gz', 'tranco-top100k.txt.gz'];
for (const f of DATA) fs.copyFileSync(path.join(ROOT, 'data', f), path.join(OUT, 'data', f));

// 4. guards: every relative import resolves inside the package, and nothing imports Node
const files = [];
(function walk(d) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else files.push(p); } })(OUT);
const problems = [];
for (const f of files.filter(x => x.endsWith('.js'))) {
  const src = fs.readFileSync(f, 'utf8');
  if (NODE_ONLY.test(src)) problems.push(`${path.relative(OUT, f)} imports Node`);
  for (const m of src.matchAll(/(?:^|\n)\s*(?:import|export)\s[^'"]*?from\s+['"](\.{1,2}\/[^'"]+)['"]/g)) {
    const target = path.resolve(path.dirname(f), m[1]);
    if (!fs.existsSync(target)) problems.push(`${path.relative(OUT, f)} imports missing ${m[1]}`);
  }
}
const manifest = JSON.parse(fs.readFileSync(path.join(OUT, 'manifest.json'), 'utf8'));
for (const f of [manifest.background.service_worker, manifest.action.default_popup, manifest.options_page, ...manifest.content_scripts.flatMap(c => c.js)]) {
  if (!fs.existsSync(path.join(OUT, f))) problems.push(`manifest names a missing file: ${f}`);
}
if (problems.length) { console.error('build-extension: ' + problems.join('\n  ')); process.exit(1); }

// 5. zip for sharing (the same folder, packed)
fs.writeFileSync(ZIP, makeZip(files.map(f => ({ name: path.relative(OUT, f).split(path.sep).join('/'), data: fs.readFileSync(f) }))));
const kb = n => `${Math.round(n / 1024)} KB`;
const total = files.reduce((s, f) => s + fs.statSync(f).size, 0);
console.log(`Veto.ai extension ${manifest.version}: ${files.length} files, ${kb(total)} -> build/extension/ and build/veto-extension.zip (${kb(fs.statSync(ZIP).size)})`);
if (skipped.length) console.log(`  server-only engine files left out: ${skipped.join(', ')}`);
console.log('  Load it: chrome://extensions or edge://extensions -> Developer mode -> Load unpacked -> build/extension');
