'use strict';

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { NoteStore } = require('./store');

/**
 * БІР САЙТ, екі таб:
 *   🔥 «Жазба жасау» — шифрланған жазба жасайды, бірегей сілтеме береді
 *   👁 «Жазба оқу»   — сілтемені жапсырып (немесе ашып) жазбаны оқиды
 *
 * /note/<id>#<кілт> сілтемесін ашқанда бет өзін-өзі «Жазба оқу» табына
 * ауыстырып, жазбаны дайындайды.
 *
 * ЕСКЕРТУ (E2EE): сервер тек шифрланған мәтінді (base64 payload) және ttl-ді
 * алады. Дешифрлау кілті URL-дің #fragment-інде жүреді, ал браузер fragment-ті
 * серверге ЕШҚАШАН жібермейді. Яғни серверде ашық мәтін болмайды.
 */

const PORT = Number(process.env.PORT || 3000);
const store = new NoteStore({ sweepMs: 30_000 });

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '512kb' }));

// Қауіпсіздік тілбастары:
//  Referrer-Policy: no-referrer — кілтті Referrer арқылы ұрлаудан қорғау
//  Cache-Control: no-store      — деректер кеширмейді
//  X-Content-Type-Options       — MIME sniffing-тен қорғау
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// TTL (секунд): 0 — мерзімсіз (жазба ашылғанша өшпейді),
// 1..604800 — 1 секундтан 7 күнге дейін (пайдаланушы өзі қояды)
const MAX_TTL = 7 * 24 * 3600;

/** Жазба жасау: тек ciphertext сақталады. */
app.post('/api/notes', (req, res) => {
  const { data, ttl } = req.body ?? {};
  if (typeof data !== 'string' || data.length < 16 || data.length > 500_000) {
    return res.status(400).json({ error: 'invalid_data' });
  }
  const t = Number(ttl);
  if (!Number.isInteger(t) || t < 0 || t > MAX_TTL) {
    return res.status(400).json({ error: 'invalid_ttl' });
  }
  const id = crypto.randomBytes(16).toString('hex'); // 128 бит кездейсоқ id
  store.set(id, data, t);
  // Логқа: тек id мен параметрлер — мазмұн мен кілт логта БӨЛМЕЙДІ
  console.log(`[note] created id=${id} ttl=${t}s`);
  res.status(201).json({ id });
});

/** Атомдық оқу: GET + DELETE бір уақытта (Redis баламасы — GETDEL).
 *  Екінші сұрау — 404 «Жазба табылмады немесе жойылған». */
app.get('/api/notes/:id', (req, res) => {
  const { id } = req.params;
  if (!/^[a-f0-9]{32}$/.test(id)) return res.status(400).json({ error: 'bad_id' });

  const data = store.consume(id);
  if (data === null) {
    // Жазба бұрын ашылған, мерзімі өткен немесе болмаған — барлығы 404,
    // алушы жазбаның «бар-жоғын» анықтай алмайды (timing oracle жоқ).
    console.log(`[note] miss id=${id}`);
    return res.status(404).json({ error: 'not_found' });
  }
  console.log(`[note] consumed id=${id}`);
  res.json({ data });
});

app.get('/api/health', (_req, res) => res.json({ ok: true, notes: store.size() }));

// Статикалық файлдар + SPA маршрут ( /note/:id -> сол бір index.html )
app.use(express.static(path.join(__dirname, 'public')));
app.get('/note/:id', (_req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

// Қате өңдеуші: request body логқа түспейді
app.use((err, _req, res, _next) => {
  console.error(`[error] ${err.message}`);
  res.status(err.status === 400 ? 400 : 500).json({ error: 'request_error' });
});

app.listen(PORT, () => {
  console.log(`🔥 burn-notes: http://localhost:${PORT}  (таптар: жасау + оқу)`);
});
