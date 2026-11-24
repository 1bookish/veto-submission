// Offline support: network-first for everything, falling back to the cached copy, so the
// on-device engine keeps working with no signal. /api/* (X-ray, AI) is never cached.
const CACHE = 'veto-v4';
const SHELL = ['/', '/index.html', '/app.js', '/app.css', '/i18n.js', '/examples.js', '/pet.js', '/pet/idle.png', '/pet/listening.png', '/pet/investigating.png', '/pet/thinking.png', '/pet/advising.png', '/pet/caution.png', '/pet/stop.png', '/pet/verified.png', '/icon-192.png', '/icons.js', '/brand/veto-wordmark-dark.png', '/manifest.webmanifest', '/engine/context.js',
  '/engine/index.js', '/engine/normalize.js', '/engine/lexicon.js', '/engine/extract.js', '/engine/url.js', '/engine/urlml.js', '/engine/ledger.js', '/quiz.js', '/engine/otp.js',
  '/engine/playbooks.js', '/engine/redact.js', '/data/institutions.js', '/data/evidence.js', '/data/radar.js', '/data/urlml-model.js', '/data/brands.js'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api/')) return;
  e.respondWith(
    fetch(e.request).then(res => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
      return res;
    }).catch(() => caches.match(e.request).then(m => m || (url.pathname === '/share' ? caches.match('/index.html') : undefined)))
  );
});
