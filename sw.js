// Service Worker:アプリのファイルをスマホに保存し、電波がなくても開けるようにする係
// ファイルを更新して公開するときは、CACHE の番号を1つ上げる(v1 → v2)
const CACHE = 'vault-v4';
const FILES = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k.startsWith('vault-') && k !== CACHE) /* 同じ住所のほかのアプリのキャッシュは消さない */.map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// 自分のサイトのファイルだけを返す(保存済みがあればそれを使う)
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  if (new URL(e.request.url).origin !== location.origin) return;
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});
