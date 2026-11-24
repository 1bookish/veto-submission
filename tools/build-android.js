// node tools/build-android.js, builds android/build/veto.apk with ONLY the Android SDK + a JDK.
// No Gradle, no AndroidX, no downloads: aapt2 (resources) -> javac (Java 8 level) -> d8 (dex) ->
// zipalign -> apksigner (debug key). The engine (engine/, data/) is copied in as assets, so the phone
// runs exactly the same rulebook as the web app.
//
// Env: ANDROID_HOME (default %LOCALAPPDATA%\Android\Sdk), JAVA_HOME (default: java on PATH).
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const AND = path.join(ROOT, 'android');
const SRC = path.join(AND, 'app', 'src', 'main');
const OUT = path.join(AND, 'build');
const SDK = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || path.join(os.homedir(), 'AppData', 'Local', 'Android', 'Sdk');
const exe = n => (process.platform === 'win32' ? n + '.exe' : n);
const newest = (dir, re) => fs.readdirSync(dir).filter(d => re.test(d)).sort((a, b) => b.localeCompare(a, 'en', { numeric: true }))[0];
const BT = path.join(SDK, 'build-tools', newest(path.join(SDK, 'build-tools'), /^\d/));
const PLATFORM = path.join(SDK, 'platforms', newest(path.join(SDK, 'platforms'), /^android-\d+$/));
const JAR = path.join(PLATFORM, 'android.jar');
const JBIN = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, 'bin') : '';
const java = t => (JBIN ? path.join(JBIN, exe(t)) : t);
const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: ['ignore', 'inherit', 'inherit'], ...opts });
const step = s => console.log(`\n▶ ${s}`);
const MIN_SDK = '29', TARGET_SDK = '35';

console.log(`SDK ${SDK}\nbuild-tools ${path.basename(BT)} · platform ${path.basename(PLATFORM)} · java ${JBIN || '(PATH)'}`);
fs.rmSync(OUT, { recursive: true, force: true });
for (const d of ['gen', 'classes', 'dex', 'assets/www']) fs.mkdirSync(path.join(OUT, d), { recursive: true });

step('assets: engine + rulebook + bridge');
fs.cpSync(path.join(ROOT, 'engine'), path.join(OUT, 'assets', 'www', 'engine'), { recursive: true });
// server-only data (URL Judge model, popularity list, logo fingerprints, reports) stays off the phone
const SERVER_ONLY = /(urlml2-model.json.gz|tranco-top100k.txt.gz|logos.js|judge-report.json|urlml2-report.json)$/;
fs.cpSync(path.join(ROOT, 'data'), path.join(OUT, 'assets', 'www', 'data'), { recursive: true, filter: src => !SERVER_ONLY.test(src) });
fs.cpSync(path.join(SRC, 'assets', 'www'), path.join(OUT, 'assets', 'www'), { recursive: true });

step('resources (aapt2)');
const icon = path.join(SRC, 'res', 'drawable-nodpi', 'ic_launcher.png');
if (!fs.existsSync(icon)) fs.copyFileSync(path.join(ROOT, 'web', 'icon-192.png'), icon);
run(path.join(BT, exe('aapt2')), ['compile', '--dir', path.join(SRC, 'res'), '-o', path.join(OUT, 'res.zip')]);
run(path.join(BT, exe('aapt2')), ['link', '-o', path.join(OUT, 'base.apk'), '-I', JAR, '--manifest', path.join(SRC, 'AndroidManifest.xml'),
  '--java', path.join(OUT, 'gen'), '--min-sdk-version', MIN_SDK, '--target-sdk-version', TARGET_SDK,
  '--version-code', '3', '--version-name', '0.3', path.join(OUT, 'res.zip')]);
// NOTE: assets are NOT passed to aapt2 (-A). On Windows aapt2 stores them as "assets/www\bridge.html"
// (backslashes), Android cannot find them, and the on-phone engine never starts. jar (below) always
// writes forward slashes.

step('java (javac)');
const list = [];
const walk = d => { for (const f of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, f.name); if (f.isDirectory()) walk(p); else if (p.endsWith('.java')) list.push(p); } };
walk(path.join(SRC, 'java'));
walk(path.join(OUT, 'gen'));
fs.writeFileSync(path.join(OUT, 'sources.txt'), list.map(p => `"${p.replace(/\\/g, '/')}"`).join('\n'));
run(java('javac'), ['-source', '8', '-target', '8', '-bootclasspath', JAR, '-encoding', 'UTF-8', '-Xlint:-options', '-nowarn',
  '-d', path.join(OUT, 'classes'), '@' + path.join(OUT, 'sources.txt')]);

step('dex (d8)');
const classes = [];
const walkc = d => { for (const f of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, f.name); if (f.isDirectory()) walkc(p); else if (p.endsWith('.class')) classes.push(p); } };
walkc(path.join(OUT, 'classes'));
run(java('java'), ['-cp', path.join(BT, 'lib', 'd8.jar'), 'com.android.tools.r8.D8', '--release', '--lib', JAR, '--min-api', MIN_SDK,
  '--output', path.join(OUT, 'dex'), ...classes]);

step('package');
run(java('jar'), ['uf', path.join(OUT, 'base.apk'), '-C', path.join(OUT, 'dex'), 'classes.dex', '-C', OUT, 'assets']);
{ // guard: every asset entry must use forward slashes, or the phone's engine silently never loads
  const bad = execFileSync(java('jar'), ['tf', path.join(OUT, 'base.apk')], { encoding: 'utf8' }).split(/\r?\n/).filter(n => n.includes('\\'));
  if (bad.length) throw new Error('APK has backslash paths (Android cannot read them): ' + bad.slice(0, 3).join(', '));
  if (!execFileSync(java('jar'), ['tf', path.join(OUT, 'base.apk')], { encoding: 'utf8' }).includes('assets/www/bridge.html')) throw new Error('engine assets missing from the APK');
}
run(path.join(BT, exe('zipalign')), ['-f', '-p', '4', path.join(OUT, 'base.apk'), path.join(OUT, 'aligned.apk')]);

step('sign (debug key)');
const ks = path.join(AND, 'debug.keystore');
if (!fs.existsSync(ks)) {
  run(java('keytool'), ['-genkeypair', '-keystore', ks, '-storepass', 'android', '-keypass', 'android', '-alias', 'veto-debug',
    '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000', '-dname', 'CN=Veto Debug,O=Veto,C=AE']);
}
// Use the key the keystore actually holds (it was created as "kestrel-debug" before the rename;
// keeping the same key lets an installed debug build be updated in place).
const listing = execFileSync(java('keytool'), ['-list', '-keystore', ks, '-storepass', 'android'], { encoding: 'utf8' });
const alias = (listing.match(/^([^,\r\n]+),[^\r\n]*PrivateKeyEntry/m) || [])[1] || 'veto-debug';
const apk = path.join(OUT, 'veto.apk');
run(java('java'), ['-jar', path.join(BT, 'lib', 'apksigner.jar'), 'sign', '--ks', ks, '--ks-pass', 'pass:android', '--key-pass', 'pass:android',
  '--ks-key-alias', alias, '--out', apk, path.join(OUT, 'aligned.apk')]);
run(java('java'), ['-jar', path.join(BT, 'lib', 'apksigner.jar'), 'verify', apk]);
console.log(`\n✔ ${apk} (${(fs.statSync(apk).size / 1024).toFixed(0)} KB)`);
