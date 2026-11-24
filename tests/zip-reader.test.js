// The ZIP/APK reader (server/apk.js unzipEntry), tested on real archive bytes: stored and deflated entries, a
// declared method that is wrong (Android ignores it, and so must we), a missing entry, and a file that is not a ZIP.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { makeZip, crc32 } from '../server/zip.js';
import { unzipEntry } from '../server/apk.js';

// Binary XML starts with the bytes 03 00 (RES_XML_TYPE), which is what the reader returns as manifest data.
const AXML = Buffer.concat([Buffer.from([0x03, 0x00, 0x08, 0x00]), Buffer.from('manifest-body-for-test')]);

// Builds a one-entry ZIP by hand, so the declared method and the stored bytes can be chosen independently.
function buildZip(name, payload, declaredMethod, storedBytes) {
  const nameBuf = Buffer.from(name);
  const crc = crc32(payload);
  const lh = Buffer.alloc(30);
  lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 6); lh.writeUInt16LE(declaredMethod, 8);
  lh.writeUInt16LE(0, 10); lh.writeUInt16LE(0, 12); lh.writeUInt32LE(crc, 14);
  lh.writeUInt32LE(storedBytes.length, 18); lh.writeUInt32LE(payload.length, 22);
  lh.writeUInt16LE(nameBuf.length, 26); lh.writeUInt16LE(0, 28);
  const local = Buffer.concat([lh, nameBuf, storedBytes]);
  const ch = Buffer.alloc(46);
  ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0, 8);
  ch.writeUInt16LE(declaredMethod, 10); ch.writeUInt16LE(0, 12); ch.writeUInt16LE(0, 14); ch.writeUInt32LE(crc, 16);
  ch.writeUInt32LE(storedBytes.length, 20); ch.writeUInt32LE(payload.length, 24); ch.writeUInt16LE(nameBuf.length, 28);
  ch.writeUInt16LE(0, 30); ch.writeUInt16LE(0, 32); ch.writeUInt16LE(0, 34); ch.writeUInt16LE(0, 36); ch.writeUInt32LE(0, 38);
  ch.writeUInt32LE(0, 42);
  const central = Buffer.concat([ch, nameBuf]);
  const eo = Buffer.alloc(22);
  eo.writeUInt32LE(0x06054b50, 0); eo.writeUInt16LE(0, 4); eo.writeUInt16LE(0, 6); eo.writeUInt16LE(1, 8);
  eo.writeUInt16LE(1, 10); eo.writeUInt32LE(central.length, 12); eo.writeUInt32LE(local.length, 16); eo.writeUInt16LE(0, 20);
  return Buffer.concat([local, central, eo]);
}

test('a ZIP written by our own writer is read back, names and manifest data', () => {
  const zip = makeZip([{ name: 'AndroidManifest.xml', data: AXML }, { name: 'assets/readme.txt', data: 'hi' }]);
  const r = unzipEntry(zip, 'AndroidManifest.xml');
  assert.deepEqual(r.names.sort(), ['AndroidManifest.xml', 'assets/readme.txt']);
  assert.ok(r.data && r.data.equals(AXML));
});

test('a stored (method 0) entry is returned as it was written', () => {
  const zip = buildZip('AndroidManifest.xml', AXML, 0, AXML);
  assert.ok(unzipEntry(zip, 'AndroidManifest.xml').data.equals(AXML));
});

test('a deflated (method 8) entry is inflated, as real APKs store their manifests', () => {
  const deflated = zlib.deflateRawSync(AXML);
  const zip = buildZip('AndroidManifest.xml', AXML, 8, deflated);
  assert.ok(unzipEntry(zip, 'AndroidManifest.xml').data.equals(AXML));
});

test('a wrong declared method is recovered: the reader tries the other method too', () => {
  // declared as stored, but the bytes are deflated (a header trick malware uses)
  const zip = buildZip('AndroidManifest.xml', AXML, 0, zlib.deflateRawSync(AXML));
  assert.ok(unzipEntry(zip, 'AndroidManifest.xml').data.equals(AXML));
  // declared as deflated, but the bytes are stored
  const zip2 = buildZip('AndroidManifest.xml', AXML, 8, AXML);
  assert.ok(unzipEntry(zip2, 'AndroidManifest.xml').data.equals(AXML));
});

test('a missing entry gives no data, and the names of what is there', () => {
  const zip = makeZip([{ name: 'a.txt', data: 'x' }]);
  const r = unzipEntry(zip, 'AndroidManifest.xml');
  assert.equal(r.data, null);
  assert.deepEqual(r.names, ['a.txt']);
});

test('an entry that is not binary XML is not returned as manifest data', () => {
  const zip = makeZip([{ name: 'AndroidManifest.xml', data: '<manifest/>' }]);
  assert.equal(unzipEntry(zip, 'AndroidManifest.xml').data, null);
});

test('a file that is not a ZIP or APK is refused with a clear error', () => {
  assert.throws(() => unzipEntry(Buffer.from('this is not a zip file at all, just text'), 'x'), /not a ZIP\/APK file/);
});
