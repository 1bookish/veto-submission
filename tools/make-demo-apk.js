// node tools/make-demo-apk.js, builds the harmless demo app files used by the X-ray demo pages:
//   demo-sites/files/demo-app.apk      "SecureBank Update"   (bank-app-update.localhost)
//   demo-sites/files/demo-cleaner.apk  "Phone Cleaner Pro"   (phone-cleaner.localhost)
// They contain NO CODE; they only declare a banking-trojan permission set so the app inspector has
// something real to read. Needs the Android SDK build-tools (aapt2) and a platform android.jar.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SDK = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || path.join(os.homedir(), 'AppData', 'Local', 'Android', 'Sdk');
const newest = dir => fs.readdirSync(dir).filter(d => /^\d/.test(d) || /^android-\d+$/.test(d))
  .sort((a, b) => b.localeCompare(a, 'en', { numeric: true }))[0];
const bt = path.join(SDK, 'build-tools', newest(path.join(SDK, 'build-tools')));
const jar = path.join(SDK, 'platforms', newest(path.join(SDK, 'platforms')), 'android.jar');
const aapt2 = path.join(bt, process.platform === 'win32' ? 'aapt2.exe' : 'aapt2');
const template = fs.readFileSync(path.join(ROOT, 'demo-sites', 'apk-src', 'AndroidManifest.xml'), 'utf8');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'veto-apk-'));
for (const [file, label, pkg] of [['demo-app.apk', 'SecureBank Update', 'demo.veto.securebank.update'], ['demo-cleaner.apk', 'Phone Cleaner Pro', 'demo.veto.phonecleaner']]) {
  const man = path.join(tmp, 'AndroidManifest.xml');
  fs.writeFileSync(man, template.replace('android:label="SecureBank Update"', `android:label="${label}"`).replace('package="demo.veto.securebank.update"', `package="${pkg}"`));
  const out = path.join(ROOT, 'demo-sites', 'files', file);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  execFileSync(aapt2, ['link', '-o', out, '-I', jar, '--manifest', man], { stdio: 'inherit' });
  console.log(`${file}: "${label}" ${fs.statSync(out).size} bytes`);
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`built with ${path.basename(bt)} / ${path.basename(path.dirname(jar))}`);
