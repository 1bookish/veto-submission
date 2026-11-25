// node tools/build-web-demo.js
// Builds the public live check (web-demo/) with the shared engine into build/web-demo/ (the page body, for hosting as a
// claude.ai Artifact) and build/web-demo/site/ (a full HTML document, for GitHub Pages or any static host).
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'build', 'web-demo');
const NODE_ONLY = /from\s+['"]node:/;
fs.rmSync(OUT, { recursive: true, force: true });
for (const base of [OUT, path.join(OUT, 'site')]) {
  fs.mkdirSync(path.join(base, 'engine'), { recursive: true });
  fs.mkdirSync(path.join(base, 'data'), { recursive: true });
  for (const f of fs.readdirSync(path.join(ROOT, 'engine'))) {
    const src = fs.readFileSync(path.join(ROOT, 'engine', f), 'utf8');
    if (f.endsWith('.js') && !NODE_ONLY.test(src)) fs.writeFileSync(path.join(base, 'engine', f), src);
  }
  for (const f of ['institutions.js', 'uae-brands.js', 'evidence.js', 'radar.js', 'brands.js', 'urlml-model.js', 'hosting-providers.js', 'smsmodel-data.js'].filter(f => fs.existsSync(path.join(ROOT, 'data', f)))) {
    fs.copyFileSync(path.join(ROOT, 'data', f), path.join(base, 'data', f));
  }
  fs.writeFileSync(path.join(base, 'data', 'urlml2-model.json'), zlib.gunzipSync(fs.readFileSync(path.join(ROOT, 'data', 'urlml2-model.json.gz'))));
  fs.writeFileSync(path.join(base, 'data', 'tranco-top100k.txt'), zlib.gunzipSync(fs.readFileSync(path.join(ROOT, 'data', 'tranco-top100k.txt.gz'))));
  fs.copyFileSync(path.join(ROOT, 'web-demo', 'app.js'), path.join(base, 'app.js'));
}
const body = fs.readFileSync(path.join(ROOT, 'web-demo', 'index.html'), 'utf8');
fs.writeFileSync(path.join(OUT, 'index.html'), body);
fs.writeFileSync(path.join(OUT, 'site', 'index.html'), `<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">\n${body.replace('<meta name="claude:viewport-fit-sides" content="cover">\n', '')}\n</html>\n`);
const list = [];
(function walk(d) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) { if (p !== path.join(OUT, 'site')) walk(p); } else list.push(path.relative(OUT, p).split(path.sep).join('/')); } })(OUT);
fs.writeFileSync(path.join(OUT, 'files.json'), JSON.stringify(list.filter(f => f !== 'index.html' && f !== 'files.json')));
console.log('build/web-demo:', list.length, 'files;', 'site/ for static hosting');
