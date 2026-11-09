// 賽事雲端儲存 API（Vercel Blob，私人儲存區）
//
// 權限角色
//   owner  主辦：全部權限（主辦金鑰；可用主辦密碼換取）
//   scorer 計分員：只能修改比分、賽程時間、產生下一輪（計分員金鑰；可用計分員密碼換取）
//   其他人：只能讀取
//
// GET    /api/t                     → 健康檢查，回傳是否需要建立碼
// GET    /api/t?checkcode=XXX       → 檢查建立碼是否有效
// GET    /api/t?id=xxx[&key=]       → 讀取賽事（公開）；附 key 時回傳 role
// PUT    /api/t?id=xxx              → 寫入賽事 { key, t }；新賽事須附 ownerPw（與建立碼 code，若有開啟）
// DELETE /api/t?id=xxx              → 刪除賽事 { key }（主辦）
// POST   /api/t?id=xxx&action=login   { password }                     → 回傳 { key, role }
// POST   /api/t?id=xxx&action=setpw   { key, password }                → 更改主辦密碼（主辦）
// POST   /api/t?id=xxx&action=scorer  { key, password|null, scorerKey } → 設定／移除計分員密碼（主辦）
// POST   /api/t?id=xxx&action=rotate  { key, newKey, password }        → 更換主辦金鑰，其他權限全部失效（主辦）
import { del } from '@vercel/blob';
import {
  ID_RE, hash, validKey, validPw, sleep, stable, sealKey, openKey,
  readT, writeT, getConfig, saveConfig, normCode, body, isPrecondition,
} from './_lib.js';

// 計分員可以改的欄位；其他欄位必須與原本完全相同
const SCORER_FIELDS = ['results', 'sched', 'matches', 'updated'];
const lockedPart = (t) => { const o = { ...t }; SCORER_FIELDS.forEach((f) => delete o[f]); return stable(o); };

function roleOf(doc, key) {
  if (!key) return null;
  const h = hash(key);
  if (h === doc.keyHash) return 'owner';
  if (doc.scorerHash && h === doc.scorerHash) return 'scorer';
  return null;
}
function findCode(cfg, code) {
  const c = normCode(code);
  return c ? (cfg.codes || []).find((x) => normCode(x.code) === c && !x.disabled) : null;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const id = String(req.query.id || '');
  try {
    if (req.method === 'GET' && !id) {
      const { cfg } = await getConfig();
      if (req.query.checkcode !== undefined) {
        const ok = !cfg.requireCode || !!findCode(cfg, req.query.checkcode);
        if (!ok) await sleep(500);
        return res.status(200).json({ ok });
      }
      return res.status(200).json({ ok: true, v: 3, requireCode: !!cfg.requireCode });
    }
    if (!ID_RE.test(id)) return res.status(400).json({ error: 'bad_id' });

    if (req.method === 'GET') {
      const r = await readT(id);
      if (!r) return res.status(404).json({ error: 'not_found' });
      const role = roleOf(r.doc, req.query.key);
      return res.status(200).json({
        t: r.doc.t, updated: r.doc.updated, role,
        hasPw: !!r.doc.pw, hasScorer: !!r.doc.scorerHash,
        canEdit: role === 'owner',
      });
    }

    if (req.method === 'PUT') {
      const { key, t, ownerPw, code } = body(req);
      if (!validKey(key) || !t || t.id !== id) return res.status(400).json({ error: 'bad_request' });
      const r = await readT(id);
      const updated = Date.now();
      if (!r) {
        // 新賽事：必須設定主辦密碼；若網站開啟建立碼，也必須提供有效的建立碼
        if (!validPw(ownerPw)) return res.status(400).json({ error: 'owner_pw_required' });
        const { cfg, etag } = await getConfig();
        let codeRec = null;
        if (cfg.requireCode) {
          codeRec = findCode(cfg, code);
          if (!codeRec) { await sleep(500); return res.status(403).json({ error: code ? 'bad_code' : 'code_required' }); }
        }
        t.updated = updated;
        await writeT(id, {
          keyHash: hash(key), pw: await sealKey(key, ownerPw), scorerHash: null, spw: null,
          createdWith: codeRec ? codeRec.label || codeRec.code : null, t, updated,
        });
        if (codeRec) {
          try { codeRec.uses = (codeRec.uses || 0) + 1; await saveConfig(cfg, etag); } catch { /* 計數失敗不影響建立 */ }
        }
        return res.status(200).json({ ok: true, updated, role: 'owner' });
      }
      const role = roleOf(r.doc, key);
      if (!role) return res.status(403).json({ error: 'forbidden' });
      if (role === 'scorer' && lockedPart(t) !== lockedPart(r.doc.t)) {
        return res.status(403).json({ error: 'scorer_forbidden' });
      }
      t.updated = updated;
      await writeT(id, { ...r.doc, t, updated }, r.etag);
      return res.status(200).json({ ok: true, updated, role });
    }

    if (req.method === 'DELETE') {
      const { key } = body(req);
      const r = await readT(id);
      if (!r) return res.status(200).json({ ok: true });
      if (roleOf(r.doc, key) !== 'owner') return res.status(403).json({ error: 'forbidden' });
      await del(r.url);
      return res.status(200).json({ ok: true });
    }

    if (req.method === 'POST') {
      const action = String(req.query.action || '');
      const b = body(req);
      const r = await readT(id);
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
        await writeT(id, { ...r.doc, pw: await sealKey(b.key, b.password) }, r.etag);
        return res.status(200).json({ ok: true, hasPw: true });
      }
      if (action === 'scorer') {
        if (b.password === null || b.password === '') {
          await writeT(id, { ...r.doc, scorerHash: null, spw: null }, r.etag);
          return res.status(200).json({ ok: true, hasScorer: false });
        }
        if (!validPw(b.password) || !validKey(b.scorerKey)) return res.status(400).json({ error: 'bad_password' });
        if (await openKey(r.doc.pw, b.password)) return res.status(400).json({ error: 'same_as_owner' });
        await writeT(id, { ...r.doc, scorerHash: hash(b.scorerKey), spw: await sealKey(b.scorerKey, b.password) }, r.etag);
        return res.status(200).json({ ok: true, hasScorer: true });
      }
      if (action === 'rotate') {
        if (!validKey(b.newKey) || !validPw(b.password)) return res.status(400).json({ error: 'bad_request' });
        await writeT(id, { ...r.doc, keyHash: hash(b.newKey), pw: await sealKey(b.newKey, b.password), scorerHash: null, spw: null }, r.etag);
        return res.status(200).json({ ok: true });
      }
      return res.status(400).json({ error: 'bad_action' });
    }

    res.setHeader('Allow', 'GET, PUT, DELETE, POST');
    return res.status(405).json({ error: 'method_not_allowed' });
  } catch (e) {
    if (e && e.code === 413) return res.status(413).json({ error: 'too_large' });
    if (isPrecondition(e)) return res.status(409).json({ error: 'conflict' });
    console.error('api/t error', e);
    return res.status(500).json({ error: 'server_error' });
  }
}
