// 賽事雲端儲存 API（Vercel Blob，私人儲存區）
// GET    /api/t            → 健康檢查
// GET    /api/t?id=xxx     → 讀取賽事（公開讀取）；附 key 參數時回傳 canEdit
// PUT    /api/t?id=xxx     → 寫入賽事，body: { key, t }；第一次寫入時以 key 認領，之後須相同 key
// DELETE /api/t?id=xxx     → 刪除賽事，body: { key }
import { get, put, del } from '@vercel/blob';
import crypto from 'node:crypto';

const ID_RE = /^[a-z0-9]{6,24}$/;
const MAX_BYTES = 900 * 1024;
const hash = (k) => crypto.createHash('sha256').update('tm:' + String(k)).digest('hex');
const pathOf = (id) => `t/${id}.json`;

async function read(id) {
  const r = await get(pathOf(id), { access: 'private', useCache: false });
  if (!r || r.statusCode !== 200) return null;
  const txt = await new Response(r.stream).text();
  return { doc: JSON.parse(txt), etag: r.blob.etag, url: r.blob.url };
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
        t: r.doc.t,
        updated: r.doc.updated,
        canEdit: key ? hash(key) === r.doc.keyHash : false,
      });
    }

    if (req.method === 'PUT') {
      const { key, t } = body(req);
      if (!key || typeof key !== 'string' || key.length < 16 || !t || t.id !== id) {
        return res.status(400).json({ error: 'bad_request' });
      }
      const r = await read(id);
      if (r && r.doc.keyHash !== hash(key)) return res.status(403).json({ error: 'forbidden' });
      const updated = Date.now();
      t.updated = updated;
      const json = JSON.stringify({ keyHash: hash(key), t, updated });
      if (Buffer.byteLength(json) > MAX_BYTES) return res.status(413).json({ error: 'too_large' });
      await put(pathOf(id), json, {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: 'application/json',
        cacheControlMaxAge: 60,
        ...(r ? { ifMatch: r.etag } : {}),
      });
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

    res.setHeader('Allow', 'GET, PUT, DELETE');
    return res.status(405).json({ error: 'method_not_allowed' });
  } catch (e) {
    const name = (e && (e.name || e.constructor?.name)) || '';
    if (/Precondition/i.test(name) || /precondition/i.test(String(e && e.message))) {
      return res.status(409).json({ error: 'conflict' });
    }
    console.error('api/t error', e);
    return res.status(500).json({ error: 'server_error' });
  }
}
