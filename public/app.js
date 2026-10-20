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
  return { k: p.get('k'), s: p.get('s'), pw: p.get('pw') };
};

/* ============================================================
 * ТАПТАР
 * ============================================================ */
const TAB_ON =
  'flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-3 py-2.5 text-sm font-semibold text-slate-950';
const TAB_OFF =
  'flex items-center justify-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium text-slate-400 transition hover:text-slate-200';

function switchTab(name) {
  const isCreate = name === 'create';
  $('#tab-create').className = isCreate ? TAB_ON : TAB_OFF;
  $('#tab-read').className = isCreate ? TAB_OFF : TAB_ON;
  $('#panel-create').classList.toggle('hidden', !isCreate);
  $('#panel-read').classList.toggle('hidden', isCreate);
}
$('#tab-create').addEventListener('click', () => switchTab('create'));
$('#tab-read').addEventListener('click', () => switchTab('read'));

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
  $('#ttl-hint').textContent = t === 0
    ? 'Мерзімсіз — жазба тек ашылғанша сақталады.'
    : `Барлығы: ${t} секунд — мерзімі өтсе автоматты жойылады, ашылған сәтте бірден күйеді.`;
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

$('#btn-create').addEventListener('click', async () => {
  const text = $('#note-text').value;
  const ttl = readTtl();
  const password = $('#note-pw').value;
  const btn = $('#btn-create');
  if (!text.trim()) return alert('Алдымен хабарлама мәтінін жазыңыз.');
  if (ttl > TTL_MAX) return alert('Максимум сақтау мерзімі — 7 күн.');
  btn.disabled = true;
  try {
    const key = await makeAesKey();
    const payload = await aesEncrypt(key, te.encode(text)); // серверге тек бұл кетеді
    const frag = password
      ? await wrapKeyWithPassword(key, password)
      : { k: toB64u(new Uint8Array(await crypto.subtle.exportKey('raw', key))) };

    const resp = await fetch('/api/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: payload, ttl }),
    });
    if (!resp.ok) throw new Error('сервер қатесі: ' + resp.status);
    const { id } = await resp.json();

    $('#link-box').textContent =
      location.origin + '/note/' + id + '#' + new URLSearchParams(frag).toString();
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
  $('#read-link').value = '';
  $('#read-pw').value = '';
  history.replaceState(null, '', location.pathname === '/' ? '/' : '/');
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
  if (!/^\/note\/[a-f0-9]{32}$/.test(u.pathname)) {
    return fail('Сілтеме дұрыс емес: /note/<id> формасы керек.');
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

/* «Ашу» — бір функция: қолмен басу (құпия сөзбен) немесе сілтеме
   ашылғанда автоматты (құпия сөзсіз). Сілтемені ашу = кіру. */
async function doReveal() {
  readErrorHide();
  if (!noteMatch || !frag.k) {
    return showGoneView('Сілтеме толық емес', 'Кілт (URL-дің # бөлігі) жоқ болғандықтан жазбаны ашу мүмкін емес.');
  }
  const btn = $('#btn-reveal');
  if (btn) btn.disabled = true;
  $('#note-ui-sub').textContent = 'Ашылуда… жазба бір реттік толығымен жойылады';
  try {
    let key;
    try {
      key = await keyFromFragment(frag, $('#read-pw').value);
    } catch {
      // Қате құпия сөз: серверден сұрау ЖАСАМАЙМЫЗ, яғни жазба әлі жойылмайды
      readErrorShow('Құпия сөз қате. Жазба әлі жойылмады — қайталап көріңіз.');
      return;
    }
    const resp = await fetch('/api/notes/' + noteMatch[1]);
    if (resp.status === 404) return showGoneView(); // «Жазба табылмады немесе жойылған»
    if (!resp.ok) throw new Error('сервер қатесі: ' + resp.status);
    const { data } = await resp.json();
    const text = await aesDecrypt(key, data);
    history.replaceState(null, '', location.pathname); // кілт енді қажет емес — URL-ден аластаймыз
    $('#revealed-text').textContent = text;
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

/* ---------- Роутер: сілтеме ашылса — «Жазба оқу» табын ашып,
   құпия сөзсіз жазбаны АВТОМАТТЫ оқиды (сілтеме = кіру) ---------- */
(function route() {
  if (noteMatch && frag.k) {
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
