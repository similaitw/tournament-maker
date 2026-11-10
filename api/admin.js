// 超級管理者後台 API
// 需要環境變數 ADMIN_PASSWORD（超級管理密碼）；自動清理排程使用 CRON_SECRET
//
// POST /api/admin?action=login     { password }        → { token }（12 小時有效）
// GET  /api/admin?action=list                          → 所有賽事摘要
// POST /api/admin?action=delete    { id }              → 刪除賽事
// POST /api/admin?action=resetpw   { id, password }    → 重設主辦密碼（舊主辦金鑰、管理連結失效）
// GET  /api/admin?action=config                        → 網站設定
// POST /api/admin?action=config    { requireCode, codes, retentionDays }
// POST /api/admin?action=cleanup   { dryRun }          → 清理超過保存天數未更新的賽事
// GET  /api/admin?action=cron                          → Vercel 排程呼叫（需 CRON_SECRET）
import { del, list } from '@vercel/blob';
import crypto from 'node:crypto';
import {
  ID_RE, hash, validPw, sleep, sealKey, newKey, readJSON, readT, writeT,
  getConfig, saveConfig, normCode, body, isPrecondition,
} from './_lib.js';

const TOKEN_HOURS = 12;
const adminPw = () => process.env.ADMIN_PASSWORD || '';
const secret = () => crypto.createHash('sha256').update('tm-admin:' + adminPw() + ':' + (process.env.BLOB_READ_WRITE_TOKEN || '')).digest();
const sign = (payload) => crypto.createHmac('sha256', secret()).update(payload).digest('hex');
function makeToken() {
  const exp = Date.now() + TOKEN_HOURS * 3600e3;
  return exp + '.' + sign('admin.' + exp);
}
function checkToken(tok) {
  if (!adminPw() || typeof tok !== 'string') return false;
  const [exp, sig] = tok.split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const want = Buffer.from(sign('admin.' + exp)), got = Buffer.from(sig);
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}
function pwEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest(), y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

async function allBlobs() {
  const out = []; let cursor;
  do {
    const r = await list({ prefix: 't/', limit: 1000, cursor });
    out.push(...r.blobs); cursor = r.hasMore ? r.cursor : undefined;
  } while (cursor);
  return out;
}
async function mapLimit(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}
async function summaries() {
  const blobs = await allBlobs();
  const rows = await mapLimit(blobs, 8, async (b) => {
    const id = b.pathname.replace(/^t\//, '').replace(/\.json$/, '');
    try {
      const r = await readJSON(b.pathname);
      if (!r) return null;
      const t = r.doc.t || {};
      const cats = Array.isArray(t.cats) ? t.cats : [t];
      const sum = (f) => cats.reduce((a, c) => a + f(c), 0);
      return {
        id, name: t.name || '(未命名)', sport: [...new Set(cats.map((c) => c.sport).filter(Boolean))].join('、'),
        format: cats.length > 1 ? 'multi' : (cats[0].format || ''), cats: cats.length,
        participants: sum((c) => (Array.isArray(c.participants) ? c.participants.length : 0)),
        matches: sum((c) => (Array.isArray(c.matches) ? c.matches.length : 0)),
        results: sum((c) => (c.results ? Object.keys(c.results).length : 0)),
        created: t.created || null, updated: r.doc.updated || null, size: r.size,
        hasPw: !!r.doc.pw, hasScorer: !!r.doc.scorerHash, createdWith: r.doc.createdWith || null,
      };
    } catch { return { id, name: '(讀取失敗)', broken: true, size: b.size, updated: new Date(b.uploadedAt).getTime() }; }
  });
  return rows.filter(Boolean).sort((a, b) => (b.updated || 0) - (a.updated || 0));
}
async function cleanup(dryRun) {
  const { cfg, etag } = await getConfig();
  const days = Number(cfg.retentionDays) || 0;
  if (days <= 0) return { days: 0, removed: [] };
  const cutoff = Date.now() - days * 86400e3;
  const rows = await summaries();
  const old = rows.filter((r) => (r.updated || 0) < cutoff);
  if (!dryRun) {
    for (const r of old) { try { await del(`t/${r.id}.json`); } catch { /* 略過 */ } }
    try { cfg.lastCleanup = { at: Date.now(), removed: old.length }; await saveConfig(cfg, etag); } catch { /* 略過 */ }
  }
  return { days, removed: old.map((r) => ({ id: r.id, name: r.name, updated: r.updated })) };
}
function sanitizeCodes(codes) {
  if (!Array.isArray(codes)) return [];
  const seen = new Set();
  return codes.slice(0, 200).map((c) => ({
    code: normCode(c.code).slice(0, 32), label: String(c.label || '').slice(0, 40),
    uses: Number(c.uses) || 0, created: Number(c.created) || Date.now(), disabled: !!c.disabled,
  })).filter((c) => /^[A-Z0-9-]{4,32}$/.test(c.code) && !seen.has(c.code) && seen.add(c.code));
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const action = String(req.query.action || '');
  try {
    if (action === 'cron') {
      const cs = process.env.CRON_SECRET;
      if (!cs || req.headers.authorization !== `Bearer ${cs}`) return res.status(401).json({ error: 'unauthorized' });
      const r = await cleanup(false);
      return res.status(200).json({ ok: true, removed: r.removed.length });
    }

    if (action === 'login') {
      if (!adminPw()) return res.status(503).json({ error: 'admin_not_configured' });
      const { password } = body(req);
      if (typeof password !== 'string' || !pwEqual(password, adminPw())) { await sleep(1000); return res.status(401).json({ error: 'wrong_password' }); }
      return res.status(200).json({ ok: true, token: makeToken(), hours: TOKEN_HOURS });
    }
    if (action === 'status') return res.status(200).json({ configured: !!adminPw() });

    if (!checkToken(req.headers['x-admin-token'])) return res.status(401).json({ error: 'unauthorized' });

    if (action === 'list') {
      const [rows, { cfg }] = await Promise.all([summaries(), getConfig()]);
      return res.status(200).json({ ok: true, rows, config: cfg });
    }
    if (action === 'delete' && req.method === 'POST') {
      const { id } = body(req);
      if (!ID_RE.test(String(id || ''))) return res.status(400).json({ error: 'bad_id' });
      await del(`t/${id}.json`);
      return res.status(200).json({ ok: true });
    }
    if (action === 'resetpw' && req.method === 'POST') {
      const { id, password } = body(req);
      if (!ID_RE.test(String(id || '')) || !validPw(password)) return res.status(400).json({ error: 'bad_request' });
      const r = await readT(id);
      if (!r) return res.status(404).json({ error: 'not_found' });
      const k = newKey();
      await writeT(id, { ...r.doc, keyHash: hash(k), pw: await sealKey(k, password) }, r.etag);
      return res.status(200).json({ ok: true });
    }
    if (action === 'config') {
      if (req.method === 'GET') return res.status(200).json({ ok: true, config: (await getConfig()).cfg });
      const b = body(req);
      const { cfg, etag } = await getConfig();
      if (b.requireCode !== undefined) cfg.requireCode = !!b.requireCode;
      if (b.codes !== undefined) cfg.codes = sanitizeCodes(b.codes);
      if (b.retentionDays !== undefined) cfg.retentionDays = Math.max(0, Math.min(3650, Math.floor(Number(b.retentionDays) || 0)));
      if (cfg.requireCode && !cfg.codes.some((c) => !c.disabled)) return res.status(400).json({ error: 'no_active_code' });
      await saveConfig(cfg, etag);
      return res.status(200).json({ ok: true, config: cfg });
    }
    if (action === 'cleanup' && req.method === 'POST') {
      const { dryRun } = body(req);
      return res.status(200).json({ ok: true, ...(await cleanup(!!dryRun)) });
    }
    return res.status(400).json({ error: 'bad_action' });
  } catch (e) {
    if (isPrecondition(e)) return res.status(409).json({ error: 'conflict' });
    console.error('api/admin error', e);
    return res.status(500).json({ error: 'server_error' });
  }
}
