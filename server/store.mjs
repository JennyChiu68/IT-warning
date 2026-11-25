import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const snapshot = JSON.parse(readFileSync(new URL('../miniprogram/shared/snapshot.json', import.meta.url), 'utf8'));
const defaultPath = fileURLToPath(new URL('../var/alerts.sqlite', import.meta.url));
export const priority = item => item.level === 'critical' || !!item.kev ||
  (item.category === 'incident' && item.level === 'high');
export const KEV_SOURCE = { name: 'CISA KEV', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' };
const read = row => JSON.parse(row.content);
const isIsoDate = date => /^\d{4}-\d{2}-\d{2}$/.test(date) && Number.isFinite(Date.parse(date));
export const CVE_ID = /^CVE-\d{4}-\d{4,}$/;

export function kevCve(item) {
  if (CVE_ID.test(item.id || '')) return item.id;
  return item.category === 'incident' && Array.isArray(item.aliases) && item.aliases.length === 1 && CVE_ID.test(item.aliases[0])
    ? item.aliases[0] : null;
}

export function publicationTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.test(value)) return null;
  const instant = Date.parse(value);
  if (!Number.isFinite(instant)) return null;
  return { publishedAt: new Date(instant).toISOString(), date: new Date(instant + 8 * 3600000).toISOString().slice(0, 10) };
}

export function validSource(source) {
  if (!source || typeof source.name !== 'string' || !source.name.trim() || source.name.length > 40) return false;
  try {
    const url = new URL(source.url);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      !/(?:^|[./_-])(?:exploit-db|metasploit|pastebin)(?:[./_-]|$)/i.test(url.hostname + url.pathname);
  } catch {
    return false;
  }
}

export function validateItem(item) {
  if (!item || !/^[A-Z\d-]{4,45}$/.test(item.id || '') || !isIsoDate(item.date) ||
      (item.kev && (!kevCve(item) || !isIsoDate(item.kev))) ||
      !['server','runtime','system','mobile','incident'].includes(item.category) ||
      !['critical','high','notice'].includes(item.level) ||
      !Array.isArray(item.products) || !item.products.length || item.products.length > 8 ||
      !item.products.every(p => typeof p === 'string' && p.trim() && p.length <= 40) ||
      !Array.isArray(item.sources) || !item.sources.length || item.sources.length > 8 ||
      !item.sources.every(validSource)) throw new Error('请核对编号、日期、类别、风险、产品和 HTTPS 来源。');
  const publication = publicationTime(item.publishedAt);
  if (item.publishedAt != null && !publication) throw new Error('公布时间须包含明确时区。');
  for (const field of ['title','summary','impact','fix','badge']) {
    if (typeof item[field] !== 'string' || !item[field].trim() ||
        item[field].length > (field === 'badge' ? 14 : field === 'title' ? 80 : 650) ||
        /https?:\/\/|<[^>]*>|```/.test(item[field])) throw new Error('请填写简短的防护信息字段 ' + field);
  }
  if (item.score != null && (typeof item.score !== 'number' || item.score < 0 || item.score > 10 ||
      !/^CVSS [34](?:\.[01x])?$/.test(item.metric || ''))) throw new Error('请使用可核验的 CVSS 版本和分值。');
  const aliases = item.aliases || [];
  if (!Array.isArray(aliases) || aliases.length > 100 || !aliases.every(id => CVE_ID.test(id) && id !== item.id)) throw new Error('请核对关联 CVE。');
  return {
    id: item.id, date: publication?.date || item.date, ...(publication && { publishedAt: publication.publishedAt }),
    kev: item.kev || null, category: item.category,
    kind: item.category === 'incident' ? 'incident' : 'vulnerability', products: [...new Set(item.products)],
    level: item.level, badge: item.badge, aliases: [...new Set(aliases)],
    title: item.title, summary: item.summary, impact: item.impact, fix: item.fix,
    sources: item.sources.map(s => ({ name: s.name, url: s.url })),
    score: item.score ?? null, metric: item.score == null ? null : item.metric
  };
}

export function openStore(path = process.env.DB_PATH || defaultPath) {
  if (path !== ':memory:') mkdirSync(dirname(resolve(path)), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA busy_timeout=5000;
    PRAGMA journal_mode=WAL;
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY, content TEXT NOT NULL, origin TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1, updated TEXT NOT NULL, display_date TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS candidates (
      id TEXT PRIMARY KEY, content TEXT NOT NULL, updated TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending'
    );
    CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS recipients (
      openid TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, following TEXT NOT NULL, registered TEXT
    );
    CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, created TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS deliveries (
      openid TEXT NOT NULL, event TEXT NOT NULL, state TEXT NOT NULL, updated TEXT NOT NULL,
      PRIMARY KEY(openid,event)
    );
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY, alert TEXT NOT NULL, content TEXT NOT NULL, approved_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      endpoint TEXT PRIMARY KEY, keys TEXT NOT NULL, created TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS push_deliveries (
      endpoint TEXT NOT NULL REFERENCES push_subscriptions(endpoint) ON DELETE CASCADE,
      event TEXT NOT NULL, next_attempt INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
      done INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(endpoint,event)
    );
    CREATE INDEX IF NOT EXISTS push_due ON push_deliveries(done,next_attempt);
  `);
  const q = sql => db.prepare(sql);
  const time = () => new Date().toISOString();
  function transact(fn) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const value = fn();
      db.exec('COMMIT');
      return value;
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }
  function meta(key) {
    return q('SELECT value FROM metadata WHERE key=?').get(key)?.value;
  }
  function setMeta(key,value) {
    q('INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,String(value));
  }
  function save(raw, origin = 'review', notify = true) {
    const item = validateItem(raw);
    const previous = q('SELECT * FROM alerts WHERE id=?').get(item.id);
    if (origin === 'auto' && previous && (!previous.active || previous.origin !== 'auto')) return false;
    const serialized = JSON.stringify(item);
    if (previous?.content === serialized && previous.active) return false;
    const now = time();
    q(`INSERT INTO alerts VALUES(?,?,?,1,?,?) ON CONFLICT(id) DO UPDATE SET
      content=excluded.content,origin=excluded.origin,active=1,updated=excluded.updated,display_date=excluded.display_date`)
      .run(item.id,serialized,origin,now,item.date);
    if (notify && priority(item) &&
        (!previous?.active || !priority(read(previous)) || (!read(previous).kev && item.kev))) {
      q('INSERT OR IGNORE INTO events VALUES(?,?)').run(item.id,now);
    }
    q("UPDATE candidates SET state='published' WHERE id=?").run(item.id);
    const covered = q("UPDATE candidates SET state='published' WHERE id=? AND state='pending' AND (json_extract(content,'$.kev') IS NULL OR json_extract(content,'$.kev')=?)");
    for (const id of item.aliases) covered.run(id,id === kevCve(item) ? item.kev : null);
    return true;
  }
  function candidate(item, reopen = false) {
    const content = JSON.stringify(item);
    q(`INSERT INTO candidates (id,content,updated) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET
      content=excluded.content,updated=excluded.updated,
      state=CASE WHEN ? AND state='published' THEN 'pending' ELSE state END
      WHERE content<>excluded.content OR (? AND state='published')`).run(item.id,content,time(),Number(reopen),Number(reopen));
  }
  function withdraw(id) {
    q('UPDATE alerts SET active=0,updated=? WHERE id=?').run(time(),id);
    q("UPDATE candidates SET state='withdrawn' WHERE id=?").run(id);
    const grouped = q(`SELECT * FROM alerts WHERE active=1 AND
      EXISTS (SELECT 1 FROM json_each(content,'$.aliases') WHERE value=?)`).all(id);
    for (const row of grouped) {
      const item = read(row);
      save({ ...item, aliases:item.aliases.filter(alias => alias !== id) },row.origin,false);
    }
  }

  transact(() => {
    if (!meta('publicationOrder')) {
      db.exec("UPDATE alerts SET display_date=json_extract(content,'$.date') WHERE display_date<>json_extract(content,'$.date')");
      setMeta('publicationOrder','1');
    }
    if ((meta('snapshotDate') || '') >= snapshot.checkedAt) return;
    for (const item of snapshot.items) {
      const previous = q('SELECT origin,active FROM alerts WHERE id=?').get(item.id);
      if (!previous || (previous.active && previous.origin === 'seed')) save(item,'seed',false);
    }
    if (!meta('checkedAt')) setMeta('checkedAt',snapshot.checkedAt);
    if (!meta('kevVersion')) setMeta('kevVersion',snapshot.kevVersion);
    setMeta('snapshotDate',snapshot.checkedAt);
  });

  return {
    db, q, transact, meta, setMeta, save, candidate, withdraw,
    origin: id => q('SELECT origin FROM alerts WHERE id=?').get(id)?.origin,
    all: () => q('SELECT * FROM alerts WHERE active=1').all().map(read),
    lookup: id => {
      const direct = q('SELECT * FROM alerts WHERE id=? AND active=1').get(id);
      return direct ? read(direct) : q('SELECT * FROM alerts WHERE active=1').all().map(read).find(item => item.aliases.includes(id));
    },
    feed: () => {
      const checkedAt = meta('checkedAt');
      const fresh = ['kevOK','nvdOK'].every(key => Date.now() - Date.parse(meta(key)) < 75 * 60000);
      return {
        checkedAt, status: fresh ? 'live' : 'snapshot', kevVersion: meta('kevVersion'),
        items: q("SELECT * FROM alerts WHERE active=1 ORDER BY display_date DESC, json_extract(content,'$.publishedAt') DESC, id LIMIT 160").all().map(read)
      };
    },
    candidates: () => q("SELECT * FROM candidates WHERE state='pending' ORDER BY updated DESC,id LIMIT 150").all().map(read)
  };
}
