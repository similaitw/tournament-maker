// 賽事雲端儲存 API（Vercel Blob，私人儲存區）
//
// 權限角色
//   owner  主辦：全部權限（主辦金鑰；可用主辦密碼換取）
//   scorer 計分員：只能修改比分、賽程時間、產生下一輪（計分員金鑰；可用計分員密碼換取）
//   其他人：只能讀取
//
// GET    /api/t                     → 健康檢查
// GET    /api/t?id=xxx[&key=]       → 讀取賽事（公開）；附 key 時回傳 role
// PUT    /api/t?id=xxx              → 寫入賽事 { key, t }；第一次寫入以主辦金鑰建立（必須同時給 ownerPw）
// DELETE /api/t?id=xxx              → 刪除賽事 { key }（主辦）
// POST   /api/t?id=xxx&action=login   { password }                     → 回傳 { key, role }
// POST   /api/t?id=xxx&action=setpw   { key, password }                → 設定／更改主辦密碼（主辦）
// POST   /api/t?id=xxx&action=scorer  { key, password|null, scorerKey } → 設定／移除計分員密碼（主辦）
// POST   /api/t?id=xxx&action=rotate  { key, newKey }                  → 更換主辦金鑰，所有連結、密碼、計分員失效（主辦）
import { get, put, del } from '@vercel/blob';
import crypto from 'node:crypto';

const ID_RE = /^[a-z0-9]{6,24}$/;
const MAX_BYTES = 900 * 1024;
const hash = (k) => crypto.createHash('sha256').update('tm:' + String(k)).digest('hex');
const pathOf = (id) => `t/${id}.json`;
const validKey = (k) => typeof k === 'string' && /^[a-f0-9]{32,64}$/.test(k);
const validPw = (p) => typeof p === 'string' && p.length >= 4 && p.length <= 64;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 計分員可以改的欄位；其他欄位必須與原本完全相同
const SCORER_FIELDS = ['results', 'sched', 'matches', 'updated'];
function stable(v) {
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
const lockedPart = (t) => { const o = { ...t }; SCORER_FIELDS.forEach((f) => delete o[f]); return stable(o); };

function scrypt(pw, salt) {
  return new Promise((res, rej) =>
    crypto.scrypt(String(pw).normalize('NFKC'), salt, 32, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k))));
}
// 用密碼加密金鑰（AES-256-GCM），密碼錯誤時解密會失敗；伺服器不保存密碼本身
async function sealKey(key, pw) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', await scrypt(pw, salt), iv);
  const ct = Buffer.concat([c.update(key, 'utf8'), c.final()]);
  return { salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
}
async function openKey(rec, pw) {
  if (!rec) return null;
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', await scrypt(pw, Buffer.from(rec.salt, 'base64')), Buffer.from(rec.iv, 'base64'));
    d.setAuthTag(Buffer.from(rec.tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(rec.ct, 'base64')), d.final()]).toString('utf8');
  } catch { return null; }
}
function roleOf(doc, key) {
  if (!key) return null;
  const h = hash(key);
  if (h === doc.keyHash) return 'owner';
  if (doc.scorerHash && h === doc.scorerHash) return 'scorer';
  return null;
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
    if (req.method === 'GET' && !id) return res.status(200).json({ ok: true, v: 2 });
    if (!ID_RE.test(id)) return res.status(400).json({ error: 'bad_id' });

    if (req.method === 'GET') {
      const r = await read(id);
      if (!r) return res.status(404).json({ error: 'not_found' });
      const role = roleOf(r.doc, req.query.key);
      return res.status(200).json({
        t: r.doc.t, updated: r.doc.updated, role,
        hasPw: !!r.doc.pw, hasScorer: !!r.doc.scorerHash,
        canEdit: role === 'owner',
      });
    }

    if (req.method === 'PUT') {
      const { key, t, ownerPw } = body(req);
      if (!validKey(key) || !t || t.id !== id) return res.status(400).json({ error: 'bad_request' });
      const r = await read(id);
      const updated = Date.now();
      if (!r) {
        // 新賽事：必須同時設定主辦密碼
        if (!validPw(ownerPw)) return res.status(400).json({ error: 'owner_pw_required' });
        t.updated = updated;
        await write(id, { keyHash: hash(key), pw: await sealKey(key, ownerPw), scorerHash: null, spw: null, t, updated });
        return res.status(200).json({ ok: true, updated, role: 'owner' });
      }
      const role = roleOf(r.doc, key);
      if (!role) return res.status(403).json({ error: 'forbidden' });
      if (role === 'scorer' && lockedPart(t) !== lockedPart(r.doc.t)) {
        return res.status(403).json({ error: 'scorer_forbidden' });
      }
      t.updated = updated;
      await write(id, { ...r.doc, t, updated }, r.etag);
      return res.status(200).json({ ok: true, updated, role });
    }

    if (req.method === 'DELETE') {
      const { key } = body(req);
      const r = await read(id);
      if (!r) return res.status(200).json({ ok: true });
      if (roleOf(r.doc, key) !== 'owner') return res.status(403).json({ error: 'forbidden' });
      await del(r.url);
      return res.status(200).json({ ok: true });
    }

    if (req.method === 'POST') {
      const action = String(req.query.action || '');
      const b = body(req);
      const r = await read(id);
      if (!r) return res.status(404).json({ error: 'not_found' });

      if (action === 'login') {
        const pw = typeof b.password === 'string' ? b.password : '';
        if (pw) {
          const ok = await openKey(r.doc.pw, pw);
          if (ok && hash(ok) === r.doc.keyHash) return res.status(200).json({ ok: true, key: ok, role: 'owner' });
          const sk = await openKey(r.doc.spw, pw);
          if (sk && r.doc.scorerHash && hash(sk) === r.doc.scorerHash) return res.status(200).json({ ok: true, key: sk, role: 'scorer' });
        }
        await sleep(800);
        return res.status(401).json({ error: 'wrong_password' });
      }

      if (roleOf(r.doc, b.key) !== 'owner') return res.status(403).json({ error: 'forbidden' });

      if (action === 'setpw') {
        if (!validPw(b.password)) return res.status(400).json({ error: 'bad_password' });
        await write(id, { ...r.doc, pw: await sealKey(b.key, b.password) }, r.etag);
        return res.status(200).json({ ok: true, hasPw: true });
      }
      if (action === 'scorer') {
        if (b.password === null || b.password === '') {
          await write(id, { ...r.doc, scorerHash: null, spw: null }, r.etag);
          return res.status(200).json({ ok: true, hasScorer: false });
        }
        if (!validPw(b.password) || !validKey(b.scorerKey)) return res.status(400).json({ error: 'bad_password' });
        const ownerPwSame = await openKey(r.doc.pw, b.password);
        if (ownerPwSame) return res.status(400).json({ error: 'same_as_owner' });
        await write(id, { ...r.doc, scorerHash: hash(b.scorerKey), spw: await sealKey(b.scorerKey, b.password) }, r.etag);
        return res.status(200).json({ ok: true, hasScorer: true });
      }
      if (action === 'rotate') {
        if (!validKey(b.newKey) || !validPw(b.password)) return res.status(400).json({ error: 'bad_request' });
        await write(id, { ...r.doc, keyHash: hash(b.newKey), pw: await sealKey(b.newKey, b.password), scorerHash: null, spw: null }, r.etag);
        return res.status(200).json({ ok: true });
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
