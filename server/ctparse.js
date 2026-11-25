// Certificate Transparency parsing for the live watch (tools/ct-watch.js).
//  - tilePath / tileLeaves: the static CT API's data tiles (tiled logs)
//  - fastCert: the three things the watch needs from a certificate (the names it covers, notBefore, the issuer's
//    organisation), read straight from the DER bytes. Node's full X509Certificate parse costs about 1 ms per
//    certificate, which caps one core near 1,000 certificates a second, below what the logs publish. The watch checks
//    fastCert against X509Certificate on the first entries of every run and reports any difference.

/** Tile index N as path segments of three digits, all but the last prefixed with "x": 1234067 -> x001/x234/067. */
export function tilePath(n) {
  const s = String(n);
  const d = s.padStart(Math.ceil(s.length / 3) * 3, '0');
  const parts = [];
  for (let i = 0; i < d.length; i += 3) parts.push(d.slice(i, i + 3));
  return parts.map((p, i) => (i < parts.length - 1 ? 'x' + p : p)).join('/');
}

/** One data tile: TileLeaf entries back to back. Returns { sct (ms), type, der } per entry. */
export function tileLeaves(buf) {
  const out = [];
  let o = 0;
  while (o < buf.length) {
    const sct = Number(buf.readBigUInt64BE(o)); o += 8;
    const type = buf.readUInt16BE(o); o += 2;
    let der;
    if (type === 0) {
      const n = buf.readUIntBE(o, 3); o += 3; der = buf.subarray(o, o + n); o += n;
      o += 2 + buf.readUInt16BE(o); // extensions
    } else if (type === 1) {
      o += 32; // issuer key hash
      o += 3 + buf.readUIntBE(o, 3); // TBS certificate
      o += 2 + buf.readUInt16BE(o); // extensions
      const n = buf.readUIntBE(o, 3); o += 3; der = buf.subarray(o, o + n); o += n; // the precertificate
    } else throw new Error('unknown entry type ' + type);
    o += 2 + buf.readUInt16BE(o); // chain fingerprints
    if (o > buf.length) throw new Error('truncated tile');
    out.push({ sct, type: type === 0 ? 'x509' : 'precert', der });
  }
  return out;
}

// ---- DER ---------------------------------------------------------------------------------------------------------------
function tl(b, o, end) {
  if (o + 2 > end) throw new Error('DER: past end');
  const tag = b[o];
  let len = b[o + 1], hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4 || o + 2 + n > end) throw new Error('DER: bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[o + 2 + i];
    hdr = 2 + n;
  }
  if (o + hdr + len > end) throw new Error('DER: length past end');
  return { tag, start: o + hdr, end: o + hdr + len };
}
const OID_SAN = [0x55, 0x1d, 0x11];   // 2.5.29.17 subjectAltName
const OID_O = [0x55, 0x04, 0x0a];     // 2.5.4.10 organizationName
const OID_CN = [0x55, 0x04, 0x03];    // 2.5.4.3 commonName
const same = (b, s, e, oid) => e - s === oid.length && oid.every((x, i) => b[s + i] === x);

function time(b, t) {
  const s = b.toString('latin1', t.start, t.end);
  let y, rest;
  if (t.tag === 0x17) { const yy = +s.slice(0, 2); y = yy >= 50 ? 1900 + yy : 2000 + yy; rest = s.slice(2); }
  else if (t.tag === 0x18) { y = +s.slice(0, 4); rest = s.slice(4); }
  else throw new Error('DER: not a time');
  return Date.UTC(y, +rest.slice(0, 2) - 1, +rest.slice(2, 4), +rest.slice(4, 6), +rest.slice(6, 8), +rest.slice(8, 10));
}

function issuerName(b, s, e) {
  let org = null, cn = null;
  for (let o = s; o < e;) {
    const set = tl(b, o, e); o = set.end;
    for (let p = set.start; p < set.end;) {
      const atv = tl(b, p, set.end); p = atv.end;
      const oid = tl(b, atv.start, atv.end);
      const val = tl(b, oid.end, atv.end);
      if (same(b, oid.start, oid.end, OID_O)) org = org ?? b.toString('utf8', val.start, val.end);
      else if (same(b, oid.start, oid.end, OID_CN)) cn = cn ?? b.toString('utf8', val.start, val.end);
    }
  }
  return (org || cn || 'unknown').trim();
}

/** { names: [dNSName...], notBefore: ms, issuer: organisation or common name } from a certificate's DER. */
export function fastCert(der) {
  const b = der, E = b.length;
  const cert = tl(b, 0, E);
  const tbs = tl(b, cert.start, cert.end);
  let o = tbs.start;
  let t = tl(b, o, tbs.end);
  if (t.tag === 0xa0) { o = t.end; t = tl(b, o, tbs.end); } // version
  o = t.end;                                                // serial number
  o = tl(b, o, tbs.end).end;                                // signature algorithm
  const iss = tl(b, o, tbs.end); o = iss.end;               // issuer
  const val = tl(b, o, tbs.end); o = val.end;               // validity
  const notBefore = time(b, tl(b, val.start, val.end));
  o = tl(b, o, tbs.end).end;                                // subject
  o = tl(b, o, tbs.end).end;                                // subject public key info
  const names = [];
  while (o < tbs.end) {
    const x = tl(b, o, tbs.end); o = x.end;
    if (x.tag !== 0xa3) continue;                           // [1], [2] unique IDs
    const exts = tl(b, x.start, x.end);
    for (let p = exts.start; p < exts.end;) {
      const ext = tl(b, p, exts.end); p = ext.end;
      const oid = tl(b, ext.start, ext.end);
      if (!same(b, oid.start, oid.end, OID_SAN)) continue;
      let q = oid.end;
      let v = tl(b, q, ext.end);
      if (v.tag === 0x01) { q = v.end; v = tl(b, q, ext.end); } // critical flag
      const seq = tl(b, v.start, v.end);
      for (let r = seq.start; r < seq.end;) {
        const gn = tl(b, r, seq.end); r = gn.end;
        if (gn.tag === 0x82) names.push(b.toString('latin1', gn.start, gn.end).toLowerCase());
      }
    }
  }
  return { names, notBefore, issuer: issuerName(b, iss.start, iss.end) };
}
