'use strict';

// ===================================================
// 設定
// ===================================================
const ITERATIONS = 600000;          // PBKDF2の繰り返し回数(多いほど総当たりに強い)
const MIN_LENGTH = 12;              // マスターパスワードの最低文字数
const AUTO_LOCK_MS = 3 * 60 * 1000; // 3分操作がなければロック
const CLIP_CLEAR_MS = 30 * 1000;    // コピーから30秒でクリップボードを消す(style.css のバーも30秒)
const DOTS = '●●●●●●●●●●';

// ===================================================
// アプリの状態(ロック中は key と entries を空にする)
// ===================================================
let vault = null;     // IndexedDBに保存している暗号化データ { salt, iterations, iv, data }
let key = null;       // マスターパスワードから作った鍵(メモリ上だけ。保存しない)
let entries = [];     // 復号した一覧 [{ id, site, uid, pw, memo }]
let currentId = null; // 詳細で見ている項目のid
let editingId = null; // 編集中の項目のid(新規追加ならnull)
let pwShown = false;  // 詳細でパスワードを表示中か

const $ = (id) => document.getElementById(id);

// ===================================================
// アイコン(線画SVG。外部のアイコン集は使わない)
// <i data-icon="lock"> の中身をSVGに差し替える
// ===================================================
const ICONS = {
  lock: '<rect x="5" y="11" width="14" height="9" rx="2.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  copy: '<rect x="8" y="8" width="11" height="12" rx="2.5"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><path d="M4 4l16 16"/>',
  list: '<path d="M8 7h12M8 12h12M8 17h12M4 7h.01M4 12h.01M4 17h.01"/>',
  save: '<path d="M12 4v11M7.5 10.5L12 15l4.5-4.5M5 20h14"/>',
  back: '<path d="M15 5l-7 7 7 7"/>',
  chev: '<path d="M9 5l7 7-7 7"/>',
  shield: '<path d="M12 3l7 3v5.5c0 4.5-3 8-7 9.5-4-1.5-7-5-7-9.5V6z"/><path d="M9 12l2.2 2.2L15.5 10"/>',
};
const svg = (name) => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;

function setIcon(el, name) {
  el.innerHTML = svg(name); // 中身は上の決まった文字だけ(登録データは入れない)
}
document.querySelectorAll('[data-icon]').forEach((el) => setIcon(el, el.dataset.icon));

// ===================================================
// IndexedDB(スマホ内のデータ置き場)
// 「store」という箱に、"vault" という名前で暗号化データを1つだけ入れる
// ===================================================
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('password-vault', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('store');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGet(name) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const req = db.transaction('store').objectStore('store').get(name);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbPut(name, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('store', 'readwrite');
    tx.objectStore('store').put(value, name);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ===================================================
// 暗号化(ブラウザ標準の Web Crypto API だけを使う。外部ライブラリなし)
//  - PBKDF2: マスターパスワード → 鍵 を、わざと時間をかけて作る
//  - AES-GCM: 鍵でデータを暗号化。鍵が違うと復号が「失敗」するので、
//             パスワードが正しいかの確認にもなる
// ===================================================
function toBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

async function deriveKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false, // 鍵を取り出せないようにする
    ['encrypt', 'decrypt']
  );
}

async function encryptEntries(k, list) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 毎回新しい乱数
  const plain = new TextEncoder().encode(JSON.stringify(list));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, plain);
  return { iv: toBase64(iv), data: toBase64(new Uint8Array(cipher)) };
}

async function decryptEntries(k, v) {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(v.iv) }, k, fromBase64(v.data)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

// 一覧を暗号化して保存する
async function save() {
  const enc = await encryptEntries(key, entries);
  const next = { ...vault, ...enc };
  await dbPut('vault', next);
  vault = next; // 保存に成功してから差し替える
}

// ===================================================
// 画面切り替え・お知らせ
// ===================================================
function show(screenId) {
  document.querySelectorAll('.screen').forEach((el) => { el.hidden = el.id !== screenId; });
  window.scrollTo(0, 0);
}

let toastTimer = null;
// copy: true のときはコピー用(アイコン+30秒で縮むバー付き)
function toast(text, copy = false) {
  $('toast-text').textContent = text;
  $('toast-sub').textContent = copy ? '30秒後か金庫に戻ると消去' : '';
  $('toast-icon').hidden = !copy;
  const bar = $('toast-bar');
  bar.hidden = !copy;
  bar.classList.remove('run');
  if (copy) {
    void bar.offsetWidth; // アニメーションを最初からやり直すためのおまじない
    bar.classList.add('run');
  }
  $('toast').hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(hideToast, copy ? CLIP_CLEAR_MS : 2500);
}
function hideToast() {
  $('toast').hidden = true;
}

// 文字数(絵文字なども1文字と数える)
const charCount = (s) => [...s].length;

// 「表示」ボタン:入力欄の ●●● と文字を切り替える
document.querySelectorAll('.peek').forEach((btn) => {
  btn.addEventListener('click', () => {
    const input = $(btn.dataset.for);
    const hide = input.type === 'text';
    input.type = hide ? 'password' : 'text';
    btn.textContent = hide ? '表示' : '隠す';
  });
});
function hideAllInputs() {
  document.querySelectorAll('.peek').forEach((btn) => {
    $(btn.dataset.for).type = 'password';
    btn.textContent = '表示';
  });
}

// サイト名の頭文字と、名前から決まる色(c0〜c5)
function setAvatar(el, site) {
  const first = [...site][0] || '?';
  let sum = 0;
  for (const ch of site) sum += ch.codePointAt(0);
  el.textContent = first.toUpperCase();
  el.className = `av c${sum % 6}`;
}

// ===================================================
// ① 初回設定
// ===================================================
$('setup-pw1').addEventListener('input', () => {
  const n = charCount($('setup-pw1').value);
  const bars = Math.min(4, Math.floor(n / 3)); // 3文字ごとに1本、12文字で4本
  $('setup-seg').querySelectorAll('i').forEach((el, i) => el.classList.toggle('on', i < bars));
  $('setup-count').textContent = `${n} / ${MIN_LENGTH}`;
});

$('setup-btn').addEventListener('click', async () => {
  const pw1 = $('setup-pw1').value;
  const pw2 = $('setup-pw2').value;
  const msg = $('setup-msg');

  if (charCount(pw1) < MIN_LENGTH) { msg.textContent = `${MIN_LENGTH}文字以上にしてください`; return; }
  if (pw1 !== pw2) { msg.textContent = '2回の入力が一致しません'; return; }

  msg.textContent = '準備中…';
  $('setup-btn').disabled = true;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  try {
    key = await deriveKey(pw1, salt, ITERATIONS);
    vault = { version: 1, salt: toBase64(salt), iterations: ITERATIONS };
    entries = [];
    await save();
  } catch (e) {
    key = null;
    vault = null;
    msg.textContent = '保存できませんでした';
    $('setup-btn').disabled = false;
    return;
  }

  $('setup-pw1').value = '';
  $('setup-pw2').value = '';
  $('setup-btn').disabled = false;
  msg.textContent = '';
  hideAllInputs();
  await requestPersist();
  openList();
});

// ===================================================
// ② ロック解除・ロック
// ===================================================
async function unlock() {
  const pw = $('lock-pw').value;
  const msg = $('lock-msg');
  if (!pw) return;

  msg.textContent = '確認中…';
  $('unlock-btn').disabled = true;
  try {
    const k = await deriveKey(pw, fromBase64(vault.salt), vault.iterations);
    entries = await decryptEntries(k, vault); // 鍵が違うとここで失敗する
    key = k;
    $('lock-pw').value = '';
    msg.textContent = '';
    hideAllInputs();
    await requestPersist();
    openList();
  } catch (e) {
    msg.textContent = 'マスターパスワードが違います';
  } finally {
    $('unlock-btn').disabled = false;
  }
}
$('unlock-btn').addEventListener('click', unlock);
$('lock-pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });

// ロックする:鍵と中身をメモリから消し、画面に出ていた文字も消す
function lock() {
  if (!key) return;
  key = null;
  entries = [];
  currentId = null;
  editingId = null;
  pwShown = false;
  $('list').replaceChildren();
  ['f-site', 'f-id', 'f-pw', 'f-memo', 'search'].forEach((id) => { $(id).value = ''; });
  ['d-site', 'd-uid', 'd-pw', 'd-memo', 'd-av'].forEach((id) => { $(id).textContent = ''; });
  hideAllInputs();
  hideToast();
  clearTimeout(idleTimer);
  show('screen-lock');
}
$('lock-btn').addEventListener('click', lock);

// ===================================================
// ③ 一覧・検索
// ===================================================
function openList() {
  currentId = null;
  pwShown = false;
  show('screen-list');
  renderList();
  resetIdleTimer();
}

function renderList() {
  const word = $('search').value.trim().toLowerCase();
  const list = entries
    .filter((e) => e.site.toLowerCase().includes(word))
    .sort((a, b) => a.site.localeCompare(b.site, 'ja'));

  // 登録した文字は textContent で入れる
  // (変なタグが入っていても、プログラムとして動かないようにするため)
  const ul = $('list');
  ul.replaceChildren();
  for (const e of list) {
    const li = document.createElement('li');
    const row = document.createElement('button');
    row.className = 'item';

    const av = document.createElement('div');
    setAvatar(av, e.site);

    const meta = document.createElement('div');
    meta.className = 'meta';
    const site = document.createElement('div');
    site.className = 'site';
    site.textContent = e.site;
    const uid = document.createElement('div');
    uid.className = 'uid';
    uid.textContent = e.uid;
    meta.append(site, uid);

    const chev = document.createElement('span');
    chev.className = 'chev';
    setIcon(chev, 'chev');

    row.append(av, meta, chev);
    row.addEventListener('click', () => openDetail(e.id));
    li.append(row);
    ul.append(li);
  }

  $('count').textContent = entries.length;
  const empty = $('empty');
  empty.hidden = list.length > 0;
  empty.textContent = entries.length === 0
    ? 'まだ登録がありません。下の ＋ から追加できます。'
    : '見つかりませんでした。';
}

$('search').addEventListener('input', renderList);
$('add-btn').addEventListener('click', () => openEdit(null));
$('add-btn-top').addEventListener('click', () => openEdit(null));

// ===================================================
// ④ 詳細(見る・コピー・削除)
// ===================================================
function openDetail(id) {
  currentId = id;
  pwShown = false;
  renderDetail();
  show('screen-detail');
}

function renderDetail() {
  const e = entries.find((x) => x.id === currentId);
  setAvatar($('d-av'), e.site);
  $('d-site').textContent = e.site;
  $('d-uid').textContent = e.uid || '—';
  $('d-pw').textContent = pwShown ? e.pw : DOTS;
  setIcon($('d-eye'), pwShown ? 'eyeOff' : 'eye');
  $('d-eye').setAttribute('aria-label', pwShown ? 'パスワードを隠す' : 'パスワードを表示');
  $('d-memo').textContent = e.memo;
  $('d-memo-row').hidden = !e.memo;
}

$('d-eye').addEventListener('click', () => {
  pwShown = !pwShown;
  renderDetail();
});
$('d-copy-pw').addEventListener('click', () => {
  copyPassword(entries.find((x) => x.id === currentId).pw);
});
$('d-copy-id').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(entries.find((x) => x.id === currentId).uid);
    toast('IDをコピーしました');
  } catch (e) {
    toast('コピーできませんでした');
  }
});
$('detail-back').addEventListener('click', openList);
$('detail-edit').addEventListener('click', () => openEdit(currentId));

$('delete-btn').addEventListener('click', async () => {
  const e = entries.find((x) => x.id === currentId);
  if (!confirm(`「${e.site}」を削除しますか?`)) return;
  const backup = entries;
  entries = entries.filter((x) => x.id !== currentId);
  $('delete-btn').disabled = true; // 処理中の二度押しを防ぐ
  try {
    await save();
  } catch (err) {
    entries = backup;
    toast('保存できませんでした(削除されていません)');
    return;
  } finally {
    $('delete-btn').disabled = false;
  }
  toast('削除しました');
  openList();
});

// ===================================================
// ⑤ 追加・編集
// ===================================================
function openEdit(id) {
  editingId = id;
  const e = entries.find((x) => x.id === id) || { site: '', uid: '', pw: '', memo: '' };
  $('edit-title').textContent = id ? '編集' : '追加';
  $('f-site').value = e.site;
  $('f-id').value = e.uid;
  $('f-pw').value = e.pw;
  $('f-memo').value = e.memo;
  hideAllInputs();
  $('edit-msg').textContent = '';
  show('screen-edit');
}

function clearForm() {
  ['f-site', 'f-id', 'f-pw', 'f-memo'].forEach((id) => { $(id).value = ''; });
  hideAllInputs();
}

async function saveEntry() {
  const data = {
    site: $('f-site').value.trim(),
    uid: $('f-id').value,
    pw: $('f-pw').value,
    memo: $('f-memo').value,
  };
  if (!data.site) { $('edit-msg').textContent = 'サイト名を入れてください'; return; }

  // 連打で二重登録しないよう、処理中は両方の保存ボタンを押せなくする
  $('save-btn').disabled = true;
  $('save-btn-top').disabled = true;
  const backup = structuredClone(entries); // 失敗したときに元へ戻す用
  let id = editingId;
  try {
    if (id) {
      Object.assign(entries.find((x) => x.id === id), data);
    } else {
      id = crypto.randomUUID();
      entries.push({ id, ...data });
    }
    await save();
  } catch (e) {
    entries = backup;
    $('edit-msg').textContent = '保存できませんでした';
    toast('保存できませんでした');
    return;
  } finally {
    $('save-btn').disabled = false;
    $('save-btn-top').disabled = false;
  }
  // 保存できたあとの画面の切り替え(ここでエラーが出ても「保存失敗」とは扱わない)
  clearForm();
  editingId = null;
  toast('保存しました');
  openDetail(id);
}
$('save-btn').addEventListener('click', saveEntry);
$('save-btn-top').addEventListener('click', saveEntry);

// キャンセル:編集なら詳細へ、新規なら一覧へ戻る
$('cancel-btn').addEventListener('click', () => {
  const id = editingId;
  clearForm();
  editingId = null;
  if (id) openDetail(id);
  else openList();
});

// ===================================================
// パスワードのコピー(30秒後に消す)
// ※ アプリが裏にいる間はブラウザの制限で消せないので、戻ってきた時に消す
// ===================================================
let clipTimer = null;
let clipPending = false; // まだ消せていないコピーがあるか
let clipDeadline = 0;     // 消す予定の時刻

async function copyPassword(pw) {
  try {
    await navigator.clipboard.writeText(pw);
  } catch (e) {
    toast('コピーできませんでした');
    return;
  }
  clipPending = true;
  clipDeadline = Date.now() + CLIP_CLEAR_MS;
  clearTimeout(clipTimer);
  clipTimer = setTimeout(clearClipboard, CLIP_CLEAR_MS);
  toast('パスワードをコピー', true);
}

async function clearClipboard() {
  if (!clipPending) return;
  try {
    await navigator.clipboard.writeText('');
    clipPending = false;
  } catch (e) {
    // 裏にいる・画面に焦点がない時は失敗する → 次に戻ってきた時に再挑戦
  }
}

// ===================================================
// 自動ロック(3分操作なし / アプリを裏に回した)
// ===================================================
let idleTimer = null;

function resetIdleTimer() {
  if (!key) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, AUTO_LOCK_MS);
}

['pointerdown', 'keydown', 'input', 'scroll'].forEach((type) => {
  document.addEventListener(type, resetIdleTimer, { passive: true, capture: true });
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden) lock();
});

// アプリに戻ってきた時、30秒が過ぎていれば消し残しを消す
window.addEventListener('focus', () => {
  if (clipPending && Date.now() >= clipDeadline) setTimeout(clearClipboard, 300);
});

// ===================================================
// バックアップ(暗号化したまま書き出す / 読み込む)
// ===================================================
$('export-btn').addEventListener('click', () => {
  const text = JSON.stringify({ app: 'password-vault', ...vault }, null, 2);
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const today = new Date().toISOString().slice(0, 10);
  a.href = url;
  a.download = `password-vault-${today}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('書き出しました(中身は暗号化されています)');
});

document.querySelectorAll('.restore-btn').forEach((btn) => {
  btn.addEventListener('click', () => $('restore-file').click());
});

$('restore-file').addEventListener('change', async (ev) => {
  const file = ev.target.files[0];
  ev.target.value = '';
  if (!file) return;

  let data;
  try {
    data = JSON.parse(await file.text());
  } catch (e) {
    alert('ファイルを読み込めませんでした');
    return;
  }
  const ok = data && data.app === 'password-vault'
    && typeof data.salt === 'string' && typeof data.iv === 'string'
    && typeof data.data === 'string' && Number.isInteger(data.iterations)
    && data.iterations >= 100000;
  if (!ok) { alert('パスワード金庫のバックアップファイルではありません'); return; }

  if (vault && !confirm('今のデータはバックアップの内容で上書きされます。よろしいですか?')) return;

  vault = { version: 1, salt: data.salt, iterations: data.iterations, iv: data.iv, data: data.data };
  await dbPut('vault', vault);
  show('screen-lock');
  $('lock-msg').textContent = '';
  toast('復元しました。バックアップ時のマスターパスワードで開けてください');
});

// ===================================================
// 永続ストレージ(容量不足のとき勝手に消されにくくする)
// ===================================================
async function requestPersist() {
  if (navigator.storage && navigator.storage.persist) {
    const already = await navigator.storage.persisted();
    if (!already) await navigator.storage.persist();
  }
}

// ===================================================
// 起動
// ===================================================
(async function start() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js');
  }
  vault = await dbGet('vault');
  show(vault ? 'screen-lock' : 'screen-setup');
})();
