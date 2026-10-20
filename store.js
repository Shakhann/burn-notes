'use strict';

/**
 * Жазбаларды in-memory сақтау:
 *  - TTL: жазба ашылмаса, таңдалған мерзімде автоматты жойылады;
 *  - consume(): атомдық «оқу + өшіру». JavaScript бір ағынды (single-thread)
 *    болғандықтан, екі параллель сұрау бір жазбаны екеуі де оқи алмайды —
 *    алушы бір ғана.
 *
 * Production (Redis) баламасы — README.md-де:
 *   SET note:<id> <data> EX <ttl>   // сақтау
 *   GETDEL note:<id>                // атомдық оқу + өшіру (Redis >= 6.2)
 */
class NoteStore {
  constructor({ sweepMs = 30_000 } = {}) {
    /** @type {Map<string, { data: string, expiresAt: number|null }>} */
    this.map = new Map();
    this._timer = setInterval(() => this._sweep(), sweepMs);
    this._timer.unref?.();
  }

  /** ttlSeconds: 0 — мерзімсіз (жазба ашылғанша өшпейді) */
  set(id, data, ttlSeconds) {
    this.map.set(id, {
      data,
      expiresAt: ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : null,
    });
  }

  /** Жазбаны оқып, бір мезгілде жояды. Жоқ/мерзімі өткен болса — null. */
  consume(id) {
    const note = this.map.get(id);
    if (!note) return null;
    if (note.expiresAt !== null && note.expiresAt <= Date.now()) {
      this.map.delete(id);
      return null;
    }
    this.map.delete(id); // алынып қарау алдында жоямыз — жазба «күйіп» бітеді
    return note.data;
  }

  size() {
    this._sweep();
    return this.map.size;
  }

  /** Мерзімі өткен жазбаларды тазарту */
  _sweep() {
    const now = Date.now();
    for (const [id, note] of this.map) {
      if (note.expiresAt !== null && note.expiresAt <= now) this.map.delete(id);
    }
  }
}

module.exports = { NoteStore };
