// The certificate log reader used by the live watch (server/ctparse.js): tile paths, tile entries, and the fast
// certificate reader, which must agree with Node's full X.509 parser. The certificate below is a throwaway self-signed
// test certificate made with openssl for this test (names under example, which is reserved for documentation).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { tilePath, tileLeaves, fastCert } from '../server/ctparse.js';

const CERT = Buffer.from('MIICJTCCAcugAwIBAgIUc8O1iP5s7Ns1RBQ5O6ntPUaHLKgwCgYIKoZIzj0EAwIwQzELMAkGA1UEBhMCQUUxGDAWBgNVBAoMD1ZldG8gVGVzdCwgSW5jLjEaMBgGA1UEAwwRdmV0by10ZXN0LmV4YW1wbGUwHhcNMjYxMTI0MjI1NjIyWhcNMjYxMjI0MjI1NjIyWjBDMQswCQYDVQQGEwJBRTEYMBYGA1UECgwPVmV0byBUZXN0LCBJbmMuMRowGAYDVQQDDBF2ZXRvLXRlc3QuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNAhwkd1pmPul4aO5IAAjWBEEFroie+9IMvN4zOcmTDYr2S5dPx6QCvUf/uNd3DKQILDdvwsOrHIAtYA1xkVYsWjgZwwgZkwHQYDVR0OBBYEFJQu0q3o1fxOsQzWm5pbQ455Zy37MB8GA1UdIwQYMBaAFJQu0q3o1fxOsQzWm5pbQ455Zy37MA8GA1UdEwEB/wQFMAMBAf8wRgYDVR0RBD8wPYIRdmV0by10ZXN0LmV4YW1wbGWCEyoudmV0by10ZXN0LmV4YW1wbGWCE2FkbmNvLWxvZ2luLmV4YW1wbGUwCgYIKoZIzj0EAwIDSAAwRQIgMrirdCHw/CkQ9eUBX1HoSjk67ifi+WlLSdnZON1RuDUCIQCpCmE46KUczJf1tcITVnKY5ubzoSLrb8Qd88gOtgVSUg==', 'base64');

test('tile paths: groups of three digits, all but the last prefixed with x', () => {
  assert.equal(tilePath(1234067), 'x001/x234/067');
  assert.equal(tilePath(5), '005');
  assert.equal(tilePath(1000), 'x001/000');
});

test('the fast reader agrees with the full X.509 parser', () => {
  const f = fastCert(CERT);
  const c = new crypto.X509Certificate(CERT);
  const names = c.subjectAltName.split(', ').filter(x => x.startsWith('DNS:')).map(x => x.slice(4).toLowerCase());
  assert.deepEqual(f.names, names);
  assert.deepEqual(f.names, ['veto-test.example', '*.veto-test.example', 'adnco-login.example']);
  assert.equal(f.notBefore, Date.parse(c.validFrom));
  assert.equal(f.issuer, 'Veto Test, Inc.');
});

test('a tile with one x509 entry and one precertificate entry is read back', () => {
  const u24 = n => Buffer.from([(n >> 16) & 255, (n >> 8) & 255, n & 255]);
  const u16 = n => Buffer.from([(n >> 8) & 255, n & 255]);
  const ts = Buffer.alloc(8); ts.writeBigUInt64BE(1764000000000n);
  const x509 = Buffer.concat([ts, u16(0), u24(CERT.length), CERT, u16(0), u16(32), Buffer.alloc(32, 7)]);
  const tbs = Buffer.from([0x30, 0x00]);
  const pre = Buffer.concat([ts, u16(1), Buffer.alloc(32, 1), u24(tbs.length), tbs, u16(0), u24(CERT.length), CERT, u16(0)]);
  const leaves = tileLeaves(Buffer.concat([x509, pre]));
  assert.equal(leaves.length, 2);
  assert.equal(leaves[0].type, 'x509');
  assert.equal(leaves[1].type, 'precert');
  assert.equal(leaves[1].sct, 1764000000000);
  assert.deepEqual(fastCert(leaves[1].der).names, fastCert(CERT).names);
});

test('a broken certificate or tile throws instead of returning wrong data', () => {
  assert.throws(() => fastCert(CERT.subarray(0, 100)));
  assert.throws(() => tileLeaves(Buffer.from([0, 0, 0, 0, 0, 0, 0, 1, 0, 9])));
});
