// node tools/video-render.js [--fps 30] [--seconds 60] [--still 8.5]
// Renders build/video/video.html frame by frame (exact timing, no screen-recording jitter) and encodes the frames to
// build/video/veto-demo.webm with the ffmpeg that ships with Playwright. --still t writes one frame as a PNG to check.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { chromium } from 'playwright-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, 'build', 'video');
const args = process.argv.slice(2);
const arg = (k, d) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : d; };
const FPS = Number(arg('--fps', '30')), SECONDS = Number(arg('--seconds', '60')), STILL = arg('--still', null);
const browser = await chromium.launch({ channel: 'msedge', headless: true });
const page = await browser.newPage({ viewport: { width: 1280, height: 720 }, deviceScaleFactor: 1.5 });
await page.goto(pathToFileURL(path.join(DIR, 'video.html')).href);
await page.waitForLoadState('load');
await page.evaluate(() => Promise.all([...document.images].map(i => i.decode().catch(() => {}))));
if (STILL !== null) {
  for (const t of String(STILL).split(',')) { await page.evaluate(x => window.render(x), Number(t)); await page.screenshot({ path: path.join(DIR, `still-${t}.png`) }); }
  await browser.close(); process.exit(0);
}
const frames = path.join(os.tmpdir(), 'veto-frames.mjpeg');
const fd = fs.openSync(frames, 'w');
const total = Math.round(FPS * SECONDS);
for (let i = 0; i < total; i++) {
  await page.evaluate(x => window.render(x), i / FPS);
  fs.writeSync(fd, await page.screenshot({ type: 'jpeg', quality: 92 }));
  if (i % 300 === 0) console.log(`frame ${i} of ${total}`);
}
fs.closeSync(fd);
await browser.close();
const pw = path.join(os.homedir(), 'AppData', 'Local', 'ms-playwright');
const ff = fs.readdirSync(pw).filter(d => d.startsWith('ffmpeg')).map(d => path.join(pw, d, 'ffmpeg-win64.exe')).find(f => fs.existsSync(f));
const out = path.join(DIR, 'veto-demo.webm');
execFileSync(ff, ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'mjpeg', '-i', frames,
  '-c:v', 'libvpx-vp9', '-b:v', '7M', '-deadline', 'good', '-cpu-used', '5', '-row-mt', '1', '-pix_fmt', 'yuv420p', out], { stdio: 'inherit' });
fs.rmSync(frames, { force: true });
console.log('wrote', out, Math.round(fs.statSync(out).size / 1024), 'KB');
