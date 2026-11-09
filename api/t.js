// 賽事雲端儲存 API（Vercel Blob，私人儲存區）
// GET    /api/t                     → 健康檢查
// GET    /api/t?id=xxx[&key=]       → 讀取賽事（公開）；附 key 時回傳 canEdit；hasPw 表示是否設有管理密碼
// PUT    /api/t?id=xxx              → 寫入賽事 { key, t }；第一次寫入時以 key 認領
// DELETE /api/t?id=xxx              → 刪除賽事 { key }
// POST   /api/t?id=xxx&action=login   { password }          → 密碼正確時回傳管理金鑰
// POST   /api/t?id=xxx&action=setpw   { key, password|null } → 設定／更改／移除管理密碼
// POST   /api/t?id=xxx&action=rotate  { key, newKey }       → 更換管理金鑰（舊連結與密碼全部失效）
import { get, put, del } from '@vercel/blob';
import crypto from 'node:crypto';

const ID_RE = /^[a-z0-9]{6,24}$/;
const MAX_BYTES = 900 * 1024;
const hash = (k) => crypto.createHash('sha256').update('tm:' + String(k)).digest('hex');
const pathOf = (id) => `t/${id}.json`;
const validKey = (k) => typeof k === 'string' && /^[a-f0-9]{32,64}$/.test(k);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function scrypt(pw, salt) {
  return new Promise((res, rej) =>
    crypto.scrypt(String(pw).normalize('NFKC'), salt, 32, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k))));
}
// 用密碼加密管理金鑰（AES-256-GCM），密碼錯誤時解密會失敗
async function sealKey(key, pw) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', await scrypt(pw, salt), iv);
  const ct = Buffer.concat([c.update(key, 'utf8'), c.final()]);
  return { salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
}
async function openKey(pwRec, pw) {
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', await scrypt(pw, Buffer.from(pwRec.salt, 'base64')), Buffer.from(pwRec.iv, 'base64'));
    d.setAuthTag(Buffer.from(pwRec.tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(pwRec.ct, 'base64')), d.final()]).toString('utf8');
  } catch { return null; }
}

async function read(id) {
  const r = await get(pathOf(id), { access: 'private', useCache: false });
  if (!r || r.statusCode !== 200) return null;
  const txt = await new Response(r.stream).text();
  return { doc: JSON.parse(txt), etag: r.blob.etag, url: r.blob.url };
}
async function write(id, doc, etag) {
  const json = JSON.stringify(doc);
  if (Buffer.byteLength(json) > MAX_BYTES) { const e = new Error('too_large'); e.code = 413; throw e; }
  await put(pathOf(id), json, {
    access: 'private', addRandomSuffix: false, allowOverwrite: true,
    contentType: 'application/json', cacheControlMaxAge: 60,
    ...(etag ? { ifMatch: etag } : {}),
  });
}
function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  try { return JSON.parse(req.body || '{}'); } catch { return {}; }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const id = String(req.query.id || '');
  try {
    if (req.method === 'GET' && !id) return res.status(200).json({ ok: true });
    if (!ID_RE.test(id)) return res.status(400).json({ error: 'bad_id' });

    if (req.method === 'GET') {
      const r = await read(id);
      if (!r) return res.status(404).json({ error: 'not_found' });
      const key = req.query.key;
      return res.status(200).json({
        t: r.doc.t, updated: r.doc.updated, hasPw: !!r.doc.pw,
        canEdit: key ? hash(key) === r.doc.keyHash : false,
      });
    }

    if (req.method === 'PUT') {
      const { key, t } = body(req);
      if (!validKey(key) || !t || t.id !== id) return res.status(400).json({ error: 'bad_request' });
      const r = await read(id);
      if (r && r.doc.keyHash !== hash(key)) return res.status(403).json({ error: 'forbidden' });
      const updated = Date.now();
      t.updated = updated;
      await write(id, { keyHash: hash(key), t, updated, pw: r ? r.doc.pw || null : null }, r && r.etag);
      return res.status(200).json({ ok: true, updated });
    }

    if (req.method === 'DELETE') {
      const { key } = body(req);
      const r = await read(id);
      if (!r) return res.status(200).json({ ok: true });
      if (r.doc.keyHash !== hash(key)) return res.status(403).json({ error: 'forbidden' });
      await del(r.url);
      return res.status(200).json({ ok: true });
    }

    if (req.method === 'POST') {
      const action = String(req.query.action || '');
      const b = body(req);
      const r = await read(id);
      if (!r) return res.status(404).json({ error: 'not_found' });

      if (action === 'login') {
        if (!r.doc.pw) return res.status(400).json({ error: 'no_password' });
        const pw = typeof b.password === 'string' ? b.password : '';
        const key = pw ? await openKey(r.doc.pw, pw) : null;
        if (!key || hash(key) !== r.doc.keyHash) { await sleep(800); return res.status(401).json({ error: 'wrong_password' }); }
        return res.status(200).json({ ok: true, key });
      }

      if (r.doc.keyHash !== hash(b.key)) return res.status(403).json({ error: 'forbidden' });

      if (action === 'setpw') {
        if (b.password === null || b.password === '') {
          await write(id, { ...r.doc, pw: null }, r.etag);
          return res.status(200).json({ ok: true, hasPw: false });
        }
        if (typeof b.password !== 'string' || b.password.length < 4 || b.password.length > 64) {
          return res.status(400).json({ error: 'bad_password' });
        }
        await write(id, { ...r.doc, pw: await sealKey(b.key, b.password) }, r.etag);
        return res.status(200).json({ ok: true, hasPw: true });
      }

      if (action === 'rotate') {
        if (!validKey(b.newKey)) return res.status(400).json({ error: 'bad_request' });
        await write(id, { ...r.doc, keyHash: hash(b.newKey), pw: null }, r.etag);
        return res.status(200).json({ ok: true, hasPw: false });
      }
      return res.status(400).json({ error: 'bad_action' });
    }

    res.setHeader('Allow', 'GET, PUT, DELETE, POST');
    return res.status(405).json({ error: 'method_not_allowed' });
  } catch (e) {
    if (e && e.code === 413) return res.status(413).json({ error: 'too_large' });
    const name = (e && (e.name || e.constructor?.name)) || '';
    if (/Precondition/i.test(name) || /precondition/i.test(String(e && e.message))) {
      return res.status(409).json({ error: 'conflict' });
    }
    console.error('api/t error', e);
    return res.status(500).json({ error: 'server_error' });
  }
}
