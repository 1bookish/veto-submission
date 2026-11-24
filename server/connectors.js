// Optional search and maps connectors for Sentinel. OFF unless the operator sets a key:
//   BRAVE_API_KEY       Brave Search API, web results  (https://api.search.brave.com, free tier available)
//   GOOGLE_PLACES_KEY   Google Places API (New) Text Search, business listings with phone + website
//                       (phone fields are billed at the Enterprise SKU: keep sweeps small)
//   SERPAPI_KEY         SerpApi: Google results INCLUDING PAID ADS, and Google Maps listings (phone, website), one key
//                       for both (free plan: 100 searches a month)
// Only queries ABOUT institutions are sent ("Emirates NBD customer care number"), never any user data.
// Google's Custom Search JSON API is closed to new customers (2026), so web search uses Brave.

import { analyzeUrl, splitDomain, officialFor } from '../engine/url.js';
import { findInstitutions } from '../engine/extract.js';
import { matchForm } from '../engine/normalize.js';
import { NEUTRAL_DOMAINS } from '../data/institutions.js';
import { listingSuspect } from './sentinel.js';

const BRAVE = () => process.env.BRAVE_API_KEY || '';
const PLACES = () => process.env.GOOGLE_PLACES_KEY || '';
const SERP = () => process.env.SERPAPI_KEY || process.env.SERPAPI_API_KEY || '';
export const connectorsConfigured = () => ({ search: !!(BRAVE() || SERP()), maps: !!(PLACES() || SERP()), ads: !!SERP() });

/** Google results through SerpApi: organic results AND the paid ads scammers buy for "<bank> customer care". */
export async function serpGoogle(q) {
  if (!SERP()) return null;
  const r = await fetch(`https://serpapi.com/search.json?engine=google&q=${encodeURIComponent(q)}&gl=ae&hl=en&num=20&api_key=${encodeURIComponent(SERP())}`, { signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`SerpApi HTTP ${r.status}`);
  const j = await r.json();
  const ads = [...(j.ads || []), ...(j.top_ads || []), ...(j.bottom_ads || [])].map((x, i) => ({ rank: i + 1, ad: true, title: x.title || '', url: x.link || x.tracking_link || '', description: x.description || x.snippet || '' }));
  const organic = (j.organic_results || []).map(x => ({ rank: x.position, ad: false, title: x.title || '', url: x.link || '', description: x.snippet || '' }));
  return [...ads, ...organic];
}
/** Google Maps listings through SerpApi (name, phone, website, address). */
export async function serpMaps(q) {
  if (!SERP()) return null;
  const r = await fetch(`https://serpapi.com/search.json?engine=google_maps&type=search&q=${encodeURIComponent(q)}&ll=${encodeURIComponent('@24.4539,54.3773,9z')}&hl=en&api_key=${encodeURIComponent(SERP())}`, { signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`SerpApi Maps HTTP ${r.status}`);
  const j = await r.json();
  return (j.local_results || []).map(p => ({ name: p.title || '', phone: p.phone || null, website: p.website || null, address: p.address || null, mapsUri: p.place_id ? `https://www.google.com/maps/place/?q=place_id:${p.place_id}` : null, placeId: p.place_id || null }));
}
const NEUTRAL = new Set(NEUTRAL_DOMAINS || []);
const PHONE_RX = /(?:\+|00)971[\s-]?\d{1,2}[\s-]?\d{3}[\s-]?\d{3,4}|\b0\d[\s-]?\d{3}[\s-]?\d{4}\b|\b(?:800|600)[\s-]?\d{3,7}\b/g;

export async function braveSearch(q, count = 20) {
  if (!BRAVE()) return null;
  const r = await fetch(`https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(q)}&count=${count}&safesearch=off`, {
    signal: AbortSignal.timeout(10000), headers: { accept: 'application/json', 'x-subscription-token': BRAVE() }
  });
  if (!r.ok) throw new Error(`Brave HTTP ${r.status}`);
  const j = await r.json();
  return (j.web?.results || []).map((x, i) => ({ rank: i + 1, title: x.title || '', url: x.url || '', description: (x.description || '').replace(/<[^>]+>/g, '') }));
}

export async function placesSearch(textQuery) {
  if (!PLACES()) return null;
  const r = await fetch('https://places.googleapis.com/v1/places:searchText', {
    method: 'POST', signal: AbortSignal.timeout(10000),
    headers: { 'content-type': 'application/json', 'x-goog-api-key': PLACES(),
      'x-goog-fieldmask': 'places.id,places.displayName,places.formattedAddress,places.nationalPhoneNumber,places.internationalPhoneNumber,places.websiteUri,places.googleMapsUri' },
    body: JSON.stringify({ textQuery, regionCode: 'AE', languageCode: 'en', pageSize: 20 })
  });
  if (!r.ok) throw new Error(`Places HTTP ${r.status}`);
  const j = await r.json();
  return (j.places || []).map(p => ({ name: p.displayName?.text || '', phone: p.internationalPhoneNumber || p.nationalPhoneNumber || null, website: p.websiteUri || null,
    address: p.formattedAddress || null, mapsUri: p.googleMapsUri || null, placeId: p.id }));
}

const QUERIES = inst => [`${inst.name.en} customer care number`, `${inst.name.en} login`, `${inst.name.en} refund`, `${inst.name.ar} رقم خدمة العملاء`];

/** Sentinel hook: suspects found in search results and map listings for these institutions. */
export const connectors = {
  async suspects(insts, say = () => {}) {
    const out = [];
    const on = connectorsConfigured();
    if (!on.search && !on.maps) { say('search & maps: no API keys set, skipped'); return out; }
    for (const inst of insts) {
      if (on.search) {
        for (const q of QUERIES(inst)) {
          let res = [];
          try { res = BRAVE() ? await braveSearch(q) : await serpGoogle(q); } catch (e) { say(`search "${q}": ${e.message}`); continue; }
          for (const r of res) {
            let host;
            try { host = new URL(r.url).hostname.toLowerCase(); } catch { continue; }
            const reg = splitDomain(host).registrable;
            const blob = `${r.title} ${r.description}`;
            // a phone number shown in the result for this institution, which the institution does not publish
            for (const m of blob.match(PHONE_RX) || []) {
              const s = listingSuspect({ name: inst.name.en, phone: m }, { source: 'search', query: q });
              if (s && s.listing.verdict !== 'official') out.push({ ...s, how: `number in search result #${r.rank} for “${q}”`, resultUrl: r.url });
            }
            if (officialFor(reg) || NEUTRAL.has(reg)) continue;
            const a = analyzeUrl(r.url);
            const claims = findInstitutions(matchForm(blob), blob).some(c => c.inst.id === inst.id);
            if (a.lookalike || a.brand || (claims && /login|sign in|verify|refund|customer care|خدمة العملاء|تسجيل الدخول/i.test(blob))) {
              out.push({ host, inst: inst.id, how: `${r.ad ? 'PAID AD' : 'search result'} #${r.rank} for “${q}”`, sources: r.ad ? ['search', 'ad'] : ['search'], query: q });
            }
          }
        }
        say(`search: ${inst.name.en} done`);
      }
      if (on.maps) {
        const q = `${inst.name.en} customer service`;
        let places = [];
        try { places = PLACES() ? await placesSearch(q) : await serpMaps(q); } catch (e) { say(`maps "${q}": ${e.message}`); }
        for (const p of places) { const s = listingSuspect(p, { source: 'maps', query: q }); if (s) out.push(s); }
        say(`maps: ${inst.name.en}, ${places.length} listings checked`);
      }
    }
    return out;
  }
};
