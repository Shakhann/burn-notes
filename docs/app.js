/* ============================================================
   burn-notes — бір сайт, екі таб: «Жазба жасау» + «Жазба оқу»
   Vanilla JS + Web Crypto API (AES-256-GCM, E2EE)

   Жасату:
   1. Кездейсоқ AES-256 кілт генерацияланады, мәтін шифрланады:
      payload = base64url( IV(12) || ciphertext ).
   2. Кілт URL #fragment-іне жасырылады (серверге кетпейді):
      құпия сөзсіз: #k=<кілт>   |   құпия сөзі бар: #k=<wrapped>&s=<salt>&pw=1
   3. Серверге тек POST /api/notes { data, ttl } кетеді.
   4. Сілтеме: <origin>/note/<id>#<кілт> — ашылса, «Жазба оқу»
      табы автоматты белсендіріледі.

   Оқу:
   1. Кілт URL-ден алынады (құпия сөзбен болса — PBKDF2 арқылы «салынады»;
      қате құпия сөзде серверге сұрау түспейді, жазба жойылмайды).
   2. GET /api/notes/<id> атомдық «оқу + өшіру» (GETDEL) жасайды.
   3. Ciphertext браузерде дешифрланады; екінші кіру — 404.
   ============================================================ */
'use strict';

const $ = (s) => document.querySelector(s);
const te = new TextEncoder();
const td = new TextDecoder();
const PBKDF2_ITERATIONS = 210_000;
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));

if (!window.isSecureContext || !crypto?.subtle) {
  const w = document.createElement('div');
  w.className = 'mx-4 mt-4 rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-300';
  w.textContent = 'Web Crypto API үшін HTTPS немесе localhost қажет (secure context).';
  document.body.prepend(w);
}

/* ---------- Режим: 'server' (Express + in-memory store)
   немесе 'url' (серверсіз — деректер тікелей шифрленген сілтемеде,
   мысалы GitHub Pages). Автоматты анықталады. ---------- */
const MODE = (async () => {
  if (new URLSearchParams(location.search).get('static') === '1') return 'url'; // локалды тест
  try {
    const r = await fetch('/api/health', { cache: 'no-store' });
    return r.ok ? 'server' : 'url';
  } catch { return 'url'; }
})();
MODE.then((m) => {
  if (m === 'url') {
    const h = document.getElementById('files-hint');
    if (h) h.textContent = 'Ең көбі 5 файл, әрқайсысы 250 КБ (шифрленген деректер сілтемеде жүреді)';
  }
});

/* ---------- Шрифт: қазақ әріптерінің (cyrillic-ext) subset-ін
   алдын ала жүктеу — тақырып аралас шрифтпен көрінбесін ---------- */
const KAZ_FONT_CHARS = 'БАРДЖЗЙКЛМНӨПСТУХҲФЦЧШЫЭЮЯәғқңөұүһіБІРТЕТКЖАЗС0123456789';
(async () => {
  try {
    await Promise.all([
      document.fonts.load('400 1em "Montserrat"', KAZ_FONT_CHARS),
      document.fonts.load('600 1em "Montserrat"', KAZ_FONT_CHARS),
      document.fonts.load('700 1em "Montserrat"', KAZ_FONT_CHARS),
      document.fonts.load('800 1em "Montserrat"', KAZ_FONT_CHARS),
      document.fonts.load('900 1em "Montserrat"', KAZ_FONT_CHARS),
    ]);
  } catch { /* шрифт жүктелмесе де бет ашылады */ }
  document.documentElement.classList.remove('fonts-pending');
})();
// Қорғау: бәрібір 4 сектен кейін бет ашылады
setTimeout(() => document.documentElement.classList.remove('fonts-pending'), 4000);

/* ---------- base64url ---------- */
function toB64u(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, arr.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ---------- Бір реттік (серверсіз режим): құрылғы деңгейіндегі «жоғалту» ----------
   Сілтеме ашылған құрылғыда/браузерде бір рет ғана оқылады: ciphertext-тің
   SHA-256 «саусақ ізі» localStorage-қа жазылады, қайта ашу — «жоқталған». */
const READ_FP_KEY = 'burnNotes.readFp';
const getReadFps = () => {
  try { return JSON.parse(localStorage.getItem(READ_FP_KEY)) || []; } catch { return []; }
};
const isNoteRead = (fp) => getReadFps().includes(fp);
const markNoteRead = (fp) => {
  const list = getReadFps();
  if (!list.includes(fp)) {
    list.unshift(fp);
    try { localStorage.setItem(READ_FP_KEY, JSON.stringify(list.slice(0, 300))); } catch { /* квота */ }
  }
};
const sha256Hex = async (s) => {
  const buf = await crypto.subtle.digest('SHA-256', te.encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
};

/* ---------- AES-256-GCM (Web Crypto API) ---------- */
function makeAesKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function aesEncrypt(key, plainBytes) {
  const iv = rnd(12); // GCM үшін 96 бит IV
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return toB64u(out); // payload = IV || ciphertext
}
async function aesDecrypt(key, b64Payload) {
  const raw = fromB64u(b64Payload);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.subarray(0, 12) }, key, raw.subarray(12)
  );
  return td.decode(pt);
}

/* ---------- Құпия сөз: PBKDF2 → AES-GCM кілті ---------- */
async function derivePwKey(password, salt) {
  const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}
/* Кездейсоқ AES кілтінің құпия сөзбен «оралған» нұсқасы (URL-ге қою үшін) */
async function wrapKeyWithPassword(key, password) {
  const salt = rnd(16);
  const wkey = await derivePwKey(password, salt);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  const iv = rnd(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wkey, raw));
  const wrapped = new Uint8Array(12 + ct.length);
  wrapped.set(iv, 0);
  wrapped.set(ct, 12);
  return { k: toB64u(wrapped), s: toB64u(salt), pw: '1' };
}
/* URL fragment-інен кілтті қайтару (құпия сөзбен болса — оны пайдаланып) */
async function keyFromFragment(frag, password) {
  if (frag.pw !== '1') {
    return crypto.subtle.importKey('raw', fromB64u(frag.k), { name: 'AES-GCM' }, true, ['decrypt']);
  }
  const wkey = await derivePwKey(password, fromB64u(frag.s));
  const raw = fromB64u(frag.k);
  const keyBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.subarray(0, 12) }, wkey, raw.subarray(12)
  );
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, true, ['decrypt']);
}
const parseFragment = () => {
  const p = new URLSearchParams(location.hash.replace(/^#/, ''));
  return { k: p.get('k'), s: p.get('s'), pw: p.get('pw'), d: p.get('d') };
};

/* ============================================================
 * ТАПТАР
 * ============================================================ */
/* Дизайн CSS-те: .tab-btn / .is-active (index.html) */
function switchTab(name) {
  const isCreate = name === 'create';
  $('#tab-create').classList.toggle('is-active', isCreate);
  $('#tab-read').classList.toggle('is-active', !isCreate);
  $('#panel-create').classList.toggle('hidden', !isCreate);
  $('#panel-read').classList.toggle('hidden', isCreate);
}
$('#tab-create').addEventListener('click', () => switchTab('create'));
$('#tab-read').addEventListener('click', () => switchTab('read'));

/* Hero-дағы батырмалар: жұмыс бөлігіне тартып, тиісті табты ашады */
function goToApp(tab) {
  switchTab(tab);
  document.getElementById('app-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
$('#cta-create').addEventListener('click', () => goToApp('create'));
$('#cta-read').addEventListener('click', () => goToApp('read'));

/* ============================================================
 * ТАБ 1: ЖАЗБА ЖАСАУ
 * ============================================================ */

/* ---------- Сақтау уақыты: сағат / минут / секунд ---------- */
const TTL_MAX = 7 * 24 * 3600; // максимум — 7 күн (секунд)
const readTtl = () =>
  (Math.max(0, parseInt($('#ttl-h').value, 10) || 0) * 3600 +
   Math.max(0, parseInt($('#ttl-m').value, 10) || 0) * 60 +
   Math.max(0, parseInt($('#ttl-s').value, 10) || 0));
function updateTtlHint() {
  const t = readTtl();
  MODE.then((m) => {
    $('#ttl-hint').textContent =
      m === 'url'
        ? (t === 0
            ? 'Мерзімсіз — уақыт бойынша өтпейді, бірақ әр құрылғыда бір рет ғана ашылады.'
            : `Барлығы: ${t} секунд — мерзімі өткенде сілтеме ашылмайды. Деректер серверде емес, тікелей сілтемеде.`)
        : (t === 0
            ? 'Мерзімсіз — жазба тек ашылғанша сақталады.'
            : `Барлығы: ${t} секунд — мерзімі өтсе автоматты жойылады, ашылған сәтте бірден күйеді.`);
  });
}
['ttl-h', 'ttl-m', 'ttl-s'].forEach((id) =>
  $('#' + id).addEventListener('input', updateTtlHint)
);
document.querySelectorAll('.ttl-chip').forEach((btn) =>
  btn.addEventListener('click', () => {
    $('#ttl-h').value = btn.dataset.h;
    $('#ttl-m').value = btn.dataset.m;
    $('#ttl-s').value = btn.dataset.s;
    updateTtlHint();
  })
);

/* ---------- Файлдар: сурет / аудио / видео / кез келген файл ---------- */
const MAX_FILES = 5;
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 МБ (серверлік режим)
const MAX_FILE_SIZE_URL = 250 * 1024;   // 250 КБ (серверсіз режим: деректер сілтемеде жүреді)
let pendingFiles = []; // { name, type, size, buf: Uint8Array }
const fmtSize = (b) =>
  b >= 1048576 ? (b / 1048576).toFixed(1) + ' МБ'
  : b >= 1024 ? Math.round(b / 1024) + ' КБ'
  : b + ' Б';

function renderFileList() {
  const ul = $('#file-list');
  ul.innerHTML = '';
  pendingFiles.forEach((f, i) => {
    const li = document.createElement('li');
    li.className = 'flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-xs';
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide',
      f.type.startsWith('image/') ? 'image'
      : f.type.startsWith('audio/') ? 'music'
      : f.type.startsWith('video/') ? 'video'
      : 'file');
    icon.className = 'h-4 w-4 shrink-0 text-fuchsia-300';
    const name = document.createElement('span');
    name.className = 'min-w-0 flex-1 truncate text-slate-200';
    name.textContent = f.name; // textContent — қауіпсіз
    const size = document.createElement('span');
    size.className = 'shrink-0 text-slate-500';
    size.textContent = fmtSize(f.size);
    const rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'shrink-0 text-slate-500 transition hover:text-rose-400';
    rm.title = 'Алып тастау';
    rm.innerHTML = '<i data-lucide="x" class="h-4 w-4"></i>';
    rm.addEventListener('click', () => { pendingFiles.splice(i, 1); renderFileList(); });
    li.append(icon, name, size, rm);
    ul.appendChild(li);
  });
  if (ul.children.length) lucide.createIcons();
}

$('#btn-add-files').addEventListener('click', () => $('#note-files').click());
async function addFiles(fileList) {
  for (const f of fileList) {
    if (pendingFiles.length >= MAX_FILES) { alert('Ең көбі ' + MAX_FILES + ' файл қосуға болады.'); break; }
    const limit = (await MODE) === 'url' ? MAX_FILE_SIZE_URL : MAX_FILE_SIZE;
    if (f.size > limit) { alert('«' + f.name + '» тым үлкен: ең көбі ' + fmtSize(limit) + ' — қосылмады.'); continue; }
    pendingFiles.push({
      name: f.name,
      type: f.type || 'application/octet-stream',
      size: f.size,
      buf: new Uint8Array(await f.arrayBuffer()),
    });
  }
  renderFileList();
}
$('#note-files').addEventListener('change', (e) => {
  addFiles(e.target.files);
  e.target.value = '';
});

/* ---------- Drag & drop: файлдарды аймаққа тастау ---------- */
const dropZone = $('#btn-add-files');
['dragenter', 'dragover'].forEach((ev) =>
  dropZone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropZone.classList.add('border-fuchsia-400/70', 'bg-fuchsia-400/10');
  })
);
['dragleave', 'drop'].forEach((ev) =>
  dropZone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropZone.classList.remove('border-fuchsia-400/70', 'bg-fuchsia-400/10');
  })
);
dropZone.addEventListener('drop', (e) => {
  const files = Array.from(e.dataTransfer.files || []);
  if (files.length) addFiles(files);
});

$('#btn-create').addEventListener('click', async () => {
  const text = $('#note-text').value.trim();
  const ttl = readTtl();
  const password = $('#note-pw').value;
  const btn = $('#btn-create');
  if (!text && !pendingFiles.length) return alert('Мәтін жазыңыз немесе кем дегенде бір файл таңдаңыз.');
  if (ttl > TTL_MAX) return alert('Максимум сақтау мерзімі — 7 күн.');
  btn.disabled = true;
  try {
    const mode = await MODE;
    const key = await makeAesKey();
    // Ашық «конверт»: мәтін + файлдар (base64). Бүкіл конверт
    // бір AES-256-GCM кілтімен шифрланады.
    // v:2 — серверсіз режим: ts/exp конверт ішінде, мерзім оқушының
    // браузерінде тексеріледі; v:1 — серверлік режим (ескі жазбалар).
    const envelope = JSON.stringify({
      v: mode === 'url' ? 2 : 1,
      ts: Date.now(),
      exp: mode === 'url' && ttl > 0 ? Date.now() + ttl * 1000 : null,
      t: text || null,
      f: pendingFiles.map((f) => ({ n: f.name, m: f.type, d: toB64u(f.buf) })),
    });
    const payload = await aesEncrypt(key, te.encode(envelope));
    const frag = password
      ? await wrapKeyWithPassword(key, password)
      : { k: toB64u(new Uint8Array(await crypto.subtle.exportKey('raw', key))) };

    let id, fullUrl;
    if (mode === 'server') {
      const resp = await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: payload, ttl }),
      });
      if (!resp.ok) throw new Error('сервер қатесі: ' + resp.status);
      ({ id } = await resp.json());
      fullUrl = location.origin + '/note/' + id + '#' + new URLSearchParams(frag).toString();
    } else {
      // Серверсіз: кілт + деректер — екеуі де шифрлы түрде тікелей сілтемеде
      const p = new URLSearchParams();
      p.set('k', frag.k);
      if (frag.s) p.set('s', frag.s);
      if (frag.pw) p.set('pw', frag.pw);
      p.set('d', payload);
      id = (window.crypto.randomUUID ? crypto.randomUUID() : 'u' + Date.now().toString(36) + Math.random().toString(36).slice(2));
      fullUrl = location.href.split('#')[0].split('?')[0] + '#' + p.toString();
    }
    $('#link-box').textContent = fullUrl;
    // QR-код: тек қысқа сілтемеге (QR сыйымдылығы ~2.9 КБ)
    if (fullUrl.length <= 2200) {
      try {
        await QRCode.toCanvas($('#qr-canvas'), fullUrl, {
          width: 160, margin: 1,
          color: { dark: '#0c0a14', light: '#ffffff' },
        });
        document.getElementById('qr-box').classList.remove('hidden');
      } catch { /* QR-кітапхана жүктелмесе — опциялдық */ }
    } else {
      document.getElementById('qr-box').classList.add('hidden');
    }
    // Бөлісу сілтемелері
    $('#share-wa').href = 'https://wa.me/?text=' + encodeURIComponent(fullUrl);
    $('#share-tg').href = 'https://t.me/share/url?url=' + encodeURIComponent(fullUrl) +
      '&text=' + encodeURIComponent('Бір реттік кұпия жазба — оқылған сәтте күйеді!');
    if (navigator.share) $('#btn-native-share').classList.remove('hidden');
    // «Менің жазбаларым» (жергілікті тізім)
    saveMyNote({ id, url: fullUrl, ttl, createdAt: Date.now(), exp: ttl > 0 ? Date.now() + ttl * 1000 : null, mode });
    renderMyNotes();
    $('#url-mode-note').classList.toggle('hidden', mode !== 'url');
    const fnote = $('#created-files-note');
    if (pendingFiles.length) {
      fnote.textContent = 'Қосылған файлдар: ' + pendingFiles.map((f) => f.name).join(', ') +
        ' (' + fmtSize(pendingFiles.reduce((s, f) => s + f.size, 0)) + ') — бәрі бір шифрмен қорғалған.';
      fnote.classList.remove('hidden');
    } else {
      fnote.classList.add('hidden');
    }
    $('#create-form').classList.add('hidden');
    $('#create-result').classList.remove('hidden');
  } catch (e) {
    alert('Сілтеме жасалмады: ' + e.message);
  } finally {
    btn.disabled = false;
  }
});

$('#btn-copy').addEventListener('click', async () => {
  const url = $('#link-box').textContent;
  try {
    await navigator.clipboard.writeText(url);
  } catch {
    const t = document.createElement('textarea');
    t.value = url;
    document.body.appendChild(t);
    t.select();
    document.execCommand('copy');
    t.remove();
  }
  const b = $('#btn-copy');
  const old = b.innerHTML;
  b.textContent = '✓ Көшірілді';
  setTimeout(() => { b.innerHTML = old; }, 1500);
});

$('#btn-new').addEventListener('click', () => {
  $('#note-text').value = '';
  $('#note-pw').value = '';
  pendingFiles = [];
  renderFileList();
  $('#created-files-note').classList.add('hidden');
  $('#url-mode-note').classList.add('hidden');
  document.getElementById('qr-box').classList.remove('hidden');
  $('#create-result').classList.add('hidden');
  $('#create-form').classList.remove('hidden');
});

/* ============================================================
 * ТАБ 2: ЖАЗБА ОҚУ
 * ============================================================ */
const noteMatch = location.pathname.match(/^\/note\/([a-f0-9]{32})$/);
const frag = parseFragment();

function showReadIntro() {
  $('#read-intro').classList.remove('hidden');
  $('#note-ui').classList.add('hidden');
  $('#view-revealed').classList.add('hidden');
  $('#view-gone').classList.add('hidden');
}
function showNoteUi() {
  $('#read-intro').classList.add('hidden');
  $('#note-ui').classList.remove('hidden');
  $('#view-revealed').classList.add('hidden');
  $('#view-gone').classList.add('hidden');
}
function showGoneView(title, desc) {
  $('#read-intro').classList.add('hidden');
  $('#note-ui').classList.add('hidden');
  $('#view-revealed').classList.add('hidden');
  $('#view-gone').classList.remove('hidden');
  if (title) $('#gone-title').textContent = title;
  if (desc) $('#gone-desc').textContent = desc;
}
function resetReadTab() {
  revealFrag = null;
  $('#read-link').value = '';
  $('#read-pw').value = '';
  history.replaceState(null, '', location.pathname + location.search); // hash-тен деректерді аластаймыз
  switchTab('read');
  showReadIntro();
}
$('#btn-again').addEventListener('click', resetReadTab);
$('#btn-home').addEventListener('click', resetReadTab);

/* «Оқу» — жапсырылған сілтемені талдап, оған ауысады */
$('#btn-read').addEventListener('click', () => {
  const errEl = $('#read-intro-error');
  errEl.classList.add('hidden');
  const fail = (msg) => {
    errEl.textContent = msg;
    errEl.classList.remove('hidden');
  };
  const raw = $('#read-link').value.trim();
  if (!raw) return fail('Сілтемені енгізіңіз.');
  let u;
  try {
    u = new URL(raw, location.origin);
  } catch {
    return fail('Бұл сілтеме сияқты емес.');
  }
  const pp = new URLSearchParams(u.hash.replace(/^#/, ''));
  if (pp.get('d')) {
    // Серверсіз сілтеме: деректер хэштегте — бетті ауыртпай, тікелей оқимыз
    if (!pp.get('k')) return fail('Сілтемеде кілт жоқ — толық сілтемені көшіріп алыңыз.');
    revealFrag = { k: pp.get('k'), s: pp.get('s'), pw: pp.get('pw'), d: pp.get('d') };
    switchTab('read');
    showNoteUi();
    if (pp.get('pw') === '1') {
      $('#read-pw-wrap').classList.remove('hidden');
      $('#note-ui-sub').textContent = 'Бұл жазба құпия сөзбен қорғалған';
      $('#read-pw').focus();
    } else {
      doReveal();
    }
    return;
  }
  if (!/^\/note\/[a-f0-9]{32}$/.test(u.pathname)) {
    return fail('Сілтеме дұрыс емес: /note/<id> формасы немесе #d=... хэштегі керек.');
  }
  if (!u.hash) {
    return fail('Сілтемеде кілт жоқ — # хэштегімен бірге көшіріп алыңыз.');
  }
  location.replace(u.pathname + u.hash); // роутер «Жазба оқу» табын ашады
});

/* қате хабарламасы көмекшілері */
const readErrorEl = $('#read-error');
const readErrorShow = (msg) => {
  readErrorEl.textContent = msg;
  readErrorEl.classList.remove('hidden');
};
const readErrorHide = () => readErrorEl.classList.add('hidden');

/* ---------- Ашылған жазбаны көрсету: мәтін + файлдар ---------- */
let revealedObjectUrls = [];
function revokeRevealedUrls() {
  revealedObjectUrls.forEach((u) => URL.revokeObjectURL(u));
  revealedObjectUrls = [];
}
function showRevealedContent(plain) {
  const textWrap = $('#revealed-text-wrap');
  const textEl = $('#revealed-text');
  const filesEl = $('#revealed-files');
  filesEl.innerHTML = '';
  revokeRevealedUrls();

  // Ашық мәтін — JSON-конверт (жаңа жазбалар) немесе жай мәтін (ескі)
  let env = null;
  try {
    const j = JSON.parse(plain);
    if (j && typeof j === 'object' && (j.v === 1 || j.v === 2)) env = j;
  } catch { /* жай мәтін */ }

  const text = env ? (env.t || '') : plain;
  if (text) {
    textWrap.classList.remove('hidden');
    textEl.textContent = text;
  } else {
    textWrap.classList.add('hidden');
  }
  $('#revealed-actions').classList.toggle('hidden', !text);

  for (const f of (env && Array.isArray(env.f) ? env.f : [])) {
    const bytes = fromB64u(f.d);
    const url = URL.createObjectURL(new Blob([bytes], { type: f.m || 'application/octet-stream' }));
    revealedObjectUrls.push(url);

    const mime = f.m || '';
    const isImg = mime.startsWith('image/');
    const isAudio = mime.startsWith('audio/');
    const isVideo = mime.startsWith('video/');
    let mediaHtml = '';
    if (isImg) mediaHtml = '<img src="' + url + '" alt="" class="max-h-96 w-full bg-black/40 object-contain" />';
    else if (isAudio) mediaHtml = '<audio controls src="' + url + '" class="w-full"></audio>';
    else if (isVideo) mediaHtml = '<video controls src="' + url + '" class="max-h-96 w-full bg-black/40"></video>';

    const card = document.createElement('div');
    card.className = 'overflow-hidden rounded-xl border border-white/10 bg-black/30';
    card.innerHTML =
      (mediaHtml ? mediaHtml + '<div class="flex items-center gap-2 border-t border-white/10 p-3">' : '<div class="flex items-center gap-2 p-3">') +
      '<i data-lucide="' + (isImg ? 'image' : isAudio ? 'music' : isVideo ? 'video' : 'file') + '" class="h-4 w-4 shrink-0 text-fuchsia-300"></i>' +
      '<span class="file-name min-w-0 flex-1 truncate text-xs text-slate-300"></span>' +
      '<span class="shrink-0 text-xs text-slate-500">' + fmtSize(bytes.length) + '</span>' +
      '<a href="' + url + '" download="" class="flex shrink-0 items-center gap-1 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1.5 text-xs text-slate-200 transition hover:bg-white/10">' +
      '<i data-lucide="download" class="h-3.5 w-3.5"></i>Жүктеу</a></div>';
    card.querySelector('.file-name').textContent = f.n; // файл атауы — мәтін ретінде (XSS-қауіпсіз)
    card.querySelector('a[download]').setAttribute('download', f.n);
    filesEl.appendChild(card);
  }
  if (filesEl.children.length) lucide.createIcons();
}

/* «Ашу» — бір функция: қолмен басу (құпия сөзбен) немесе сілтеме
   ашылғанда автоматты (құпия сөзсіз). Сілтемені ашу = кіру.
   Екі режим: серверлік (d жоқ, деректер серверде) және серверсіз
   (d бар — деректер тікелей сілтемеде). */
let revealFrag = null; // «Сілтемемен ашу» арқылы жапсырылған URL-дің фрагменті
async function doReveal() {
  readErrorHide();
  const f = revealFrag || frag;
  const btn = $('#btn-reveal');
  if (btn) btn.disabled = true;

  if (f.d) {
    /* ---------- Серверсіз режим: деректер тікелей сілтемеде ---------- */
    $('#note-ui-sub').textContent = 'Ашылуда… жазба шифрлі түрде сілтемеде сақталған';
    try {
      // Бір реттік: бұл құрылғыда бұрын оқылған ма? (дешифрлауға араласпай тексереміз)
      const fp = await sha256Hex(f.d);
      if (isNoteRead(fp)) {
        history.replaceState(null, '', location.pathname + location.search);
        return showGoneView('Жазба оқылды', 'Бұл жазба осы құрылғыда бұрын оқылған — ол күйіп, қайта ашылмайды.');
      }
      let key;
      try {
        key = await keyFromFragment(f, $('#read-pw').value);
      } catch {
        readErrorShow('Құпия сөз қате. Жазба әлі ашық — қайталап көріңіз.');
        return;
      }
      const plain = await aesDecrypt(key, f.d);
      history.replaceState(null, '', location.pathname + location.search); // деректер URL-ден аластайды
      let env = null;
      try { const j = JSON.parse(plain); if (j && typeof j === 'object' && (j.v === 1 || j.v === 2)) env = j; } catch { /* жай мәтін */ }
      if (env && env.exp && Date.now() > env.exp) {
        markNoteRead(fp);
        return showGoneView('Жазбаның мерзімі өтті', 'Бұл жазбаның мерзімі өтті — ол күйіп, енді ашылмайды.');
      }
      showRevealedContent(plain);
      markNoteRead(fp); // бір реттік белгі: енді бұл құрылғыда ашылмайды
      document.getElementById('revealed-burn-msg').innerHTML =
        'Жазба оқылды және бұл құрылғыда <b>толығымен жойылды</b> — бұл сілтеме қайта ашылмайды.';
      $('#read-intro').classList.add('hidden');
      $('#note-ui').classList.add('hidden');
      $('#view-gone').classList.add('hidden');
      $('#view-revealed').classList.remove('hidden');
    } catch (e) {
      showGoneView('Жазбаны оқу мүмкін болмады', e.message);
    } finally {
      if (btn) btn.disabled = false;
    }
    return;
  }

  /* ---------- Серверлік режим: деректер серверде, атомдық оқу + өшіру ---------- */
  if (!noteMatch || !f.k) {
    return showGoneView('Сілтеме толық емес', 'Кілт (URL-дің # бөлігі) жоқ болғандықтан жазбаны ашу мүмкін емес.');
  }
  $('#note-ui-sub').textContent = 'Ашылуда… жазба бір реттік толығымен жойылады';
  try {
    let key;
    try {
      key = await keyFromFragment(f, $('#read-pw').value);
    } catch {
      // Қате құпия сөз: серверден сұрау ЖАСАМАЙМЫЗ, яғни жазба әлі жойылмайды
      readErrorShow('Құпия сөз қате. Жазба әлі жойылмады — қайталап көріңіз.');
      return;
    }
    const resp = await fetch('/api/notes/' + noteMatch[1]);
    if (resp.status === 404) return showGoneView(); // «Жазба табылмады немесе жойылған»
    if (!resp.ok) throw new Error('сервер қатесі: ' + resp.status);
    const { data } = await resp.json();
    const plain = await aesDecrypt(key, data);
    history.replaceState(null, '', location.pathname); // кілт енді қажет емес — URL-ден аластаймыз
    showRevealedContent(plain);
    document.getElementById('revealed-burn-msg').innerHTML =
      'Жазба оқылды және <b>толығымен жойылды</b>. Бұл сілтеме одан әрі жұмыс істемейді.';
    $('#read-intro').classList.add('hidden');
    $('#note-ui').classList.add('hidden');
    $('#view-gone').classList.add('hidden');
    $('#view-revealed').classList.remove('hidden');
  } catch (e) {
    showGoneView('Жазбаны оқу мүмкін болмады', e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}
$('#btn-reveal').addEventListener('click', doReveal);
$('#read-pw').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doReveal();
});

/* ---------- «Менің жазбаларым»: жіберілген сілтемелердің жергілікті тізімі ---------- */
const MY_NOTES_KEY = 'burnNotes.myLinks';
const loadMyNotes = () => {
  try { return JSON.parse(localStorage.getItem(MY_NOTES_KEY)) || []; } catch { return []; }
};
const saveMyNotes = (list) => {
  try { localStorage.setItem(MY_NOTES_KEY, JSON.stringify(list.slice(0, 50))); } catch { /* квота */ }
};
function saveMyNote(note) {
  const list = loadMyNotes().filter((n) => n.id !== note.id);
  list.unshift(note);
  saveMyNotes(list);
}
const fmtAgo = (ts) => {
  const d = Date.now() - ts;
  if (d < 60_000) return 'жаңа';
  if (d < 3_600_000) return Math.floor(d / 60_000) + ' мин бұрын';
  if (d < 86_400_000) return Math.floor(d / 3_600_000) + ' сағ бұрын';
  return Math.floor(d / 86_400_000) + ' күн бұрын';
};
const ttlLabel = (ttl) =>
  ttl === 0 ? 'мерзімсіз'
  : ttl < 3600 ? Math.ceil(ttl / 60) + ' мин'
  : ttl < 86_400 ? (ttl / 3600).toFixed(ttl % 3600 ? 1 : 0) + ' сағ'
  : Math.round(ttl / 86_400) + ' күн';

async function checkNoteStatus(item, el) {
  const m = item.mode || await MODE; // ескі жазбаларда mode белгісі жоқ болуы мүмкін
  if (m === 'url') {
    item.status = item.exp && Date.now() > item.exp ? 'gone' : 'alive';
  } else {
    try {
      const resp = await fetch('/api/notes/' + item.id + '/status');
      item.status = resp.ok ? 'alive' : 'gone';
    } catch { item.status = 'unknown'; }
  }
  const dot = el.querySelector('.status-dot');
  const label = el.querySelector('.status-label');
  if (!dot || !label) return;
  dot.className = 'status-dot h-2 w-2 shrink-0 rounded-full ' +
    (item.status === 'alive' ? 'bg-emerald-400' : item.status === 'gone' ? 'bg-rose-400' : 'bg-slate-500');
  label.classList.toggle('line-through', item.status === 'gone');
  label.title = m === 'url'
    ? (item.status === 'alive' ? 'мерзімі өткенше ашылады' : 'мерзімі өтті')
    : (item.status === 'alive' ? 'әлі оқылмады' : item.status === 'gone' ? 'оқылды немесе мерзімі өтті' : 'тексерілуде');
}
function renderMyNotes() {
  const wrap = $('#my-notes');
  const ul = $('#my-notes-list');
  const list = loadMyNotes();
  wrap.classList.toggle('hidden', list.length === 0);
  ul.innerHTML = '';
  list.forEach((item) => {
    const li = document.createElement('li');
    li.className = 'flex items-center gap-2.5 rounded-2xl border border-white/10 bg-white/[.03] px-3 py-2.5';
    li.innerHTML =
      '<span class="status-dot h-2 w-2 shrink-0 rounded-full bg-slate-500"></span>' +
      '<span class="status-label min-w-0 flex-1 truncate text-xs text-slate-300" title=""></span>' +
      '<span class="shrink-0 text-[10px] text-slate-600">' + fmtAgo(item.createdAt) + ' · ' + ttlLabel(item.ttl || 0) + '</span>' +
      '<button data-act="copy" title="Көшіру" class="shrink-0 text-slate-500 transition hover:text-fuchsia-300"><i data-lucide="copy" class="h-3.5 w-3.5"></i></button>' +
      '<button data-act="check" title="Тексеру" class="shrink-0 text-slate-500 transition hover:text-fuchsia-300"><i data-lucide="refresh-cw" class="h-3.5 w-3.5"></i></button>' +
      '<button data-act="del" title="Тізімнен өшіру" class="shrink-0 text-slate-500 transition hover:text-rose-400"><i data-lucide="trash-2" class="h-3.5 w-3.5"></i></button>';
    const label = li.querySelector('.status-label');
    label.textContent = item.url.replace(location.origin, '');
    label.title = '';
    li.querySelector('[data-act="copy"]').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(item.url); } catch { /* */ }
    });
    li.querySelector('[data-act="check"]').addEventListener('click', () => checkNoteStatus(item, li));
    li.querySelector('[data-act="del"]').addEventListener('click', () => {
      saveMyNotes(loadMyNotes().filter((n) => n.id !== item.id));
      renderMyNotes();
    });
    ul.appendChild(li);
  });
  if (ul.children.length) lucide.createIcons();
  // белсенді жазбалардың жағдайын автоматты жаңарту
  Array.from(ul.children).forEach((li, i) => {
    const item = list[i];
    if (item && item.status !== 'gone') checkNoteStatus(item, li);
  });
}
renderMyNotes();
setInterval(() => {
  if (document.hidden) return;
  const list = loadMyNotes();
  const ul = $('#my-notes-list');
  Array.from(ul.children).forEach((li, i) => {
    const item = list[i];
    if (item && item.status !== 'gone') checkNoteStatus(item, li);
  });
}, 12_000);
$('#btn-clear-notes').addEventListener('click', () => {
  saveMyNotes([]);
  renderMyNotes();
});

/* ---------- Ашылған жазба: мәтінді көшіру / жүктеу ---------- */
$('#btn-copy-text').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('#revealed-text').textContent); } catch { /* */ }
  const b = $('#btn-copy-text');
  const old = b.innerHTML;
  b.textContent = '✓ Көшірілді';
  setTimeout(() => { b.innerHTML = old; lucide.createIcons(); }, 1400);
});
$('#btn-download-text').addEventListener('click', () => {
  const blob = new Blob([$('#revealed-text').textContent], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'burn-note.txt';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
});

/* ---------- Роутер: сілтеме ашылса — «Жазба оқу» табын ашып,
   құпия сөзсіз жазбаны АВТОМАТТЫ оқиды (сілтеме = кіру) ---------- */
(function route() {
  const isUrlNote = !!frag.d;
  // Сілтеме ашылса (алымышы үшін) — тақырыпты жасырып, тікелей оқуға өтеміз
  if (noteMatch || isUrlNote) document.getElementById('hero').classList.add('hidden');
  if (isUrlNote) {
    switchTab('read');
    showNoteUi();
    if (frag.pw === '1') {
      $('#read-pw-wrap').classList.remove('hidden');
      $('#note-ui-sub').textContent = 'Бұл жазба құпия сөзбен қорғалған';
      $('#read-pw').focus();
    } else {
      doReveal();
    }
    renderMyNotes();
  } else if (noteMatch && frag.k) {
    switchTab('read');
    showNoteUi();
    if (frag.pw === '1') {
      // құпия сөзбен қорғалған — сөзді сұрап, «Ашу» басуды күтеді
      $('#read-pw-wrap').classList.remove('hidden');
      $('#note-ui-sub').textContent = 'Бұл жазба құпия сөзбен қорғалған';
      $('#read-pw').focus();
    } else {
      doReveal(); // құпия сөзсіз: ашылған сәтте бірден оқу + жойылу
    }
    renderMyNotes(); // ашылса — тізімдегі жағдай да жаңарып қалады
  } else if (noteMatch) {
    // /note/<id> ашылды, бірақ кілт жоқ
    switchTab('read');
    showGoneView('Сілтеме толық емес', 'Кілт (URL-дің # бөлігі) жоқ болғандықтан жазбаны ашу мүмкін емес.');
  } else {
    switchTab('create');
    showReadIntro();
    $('#create-form').classList.remove('hidden');
    $('#create-result').classList.add('hidden');
  }
})();
