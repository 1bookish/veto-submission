// Veto full-URL model (v2), server / CLI side. The scorer is engine/urlml2-core.js, which has no Node-only code and is
// shared with the browser extension; this file only tells it to read the weights and the Tranco list from disk.
import fs from 'node:fs';
import zlib from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setUrlml2Source } from './urlml2-core.js';

export * from './urlml2-core.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
setUrlml2Source({
  model: () => JSON.parse(zlib.gunzipSync(fs.readFileSync(process.env.VETO_MODEL2 || path.join(ROOT, 'data', 'urlml2-model.json.gz'))).toString('utf8')),
  tranco: () => zlib.gunzipSync(fs.readFileSync(path.join(ROOT, 'data', 'tranco-top100k.txt.gz'))).toString('utf8'),
});
