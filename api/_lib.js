// 共用工具（檔名以底線開頭，Vercel 不會把它當成 API）
import { get, put } from '@vercel/blob';
import crypto from 'node:crypto';

export const ID_RE = /^[a-z0-9]{6,24}$/;
export const MAX_BYTES = 900 * 1024;
export const CONFIG_PATH = 'config/settings.json';
export const hash = (k) => crypto.createHash('sha256').update('tm:' + String(k)).digest('hex');
export const pathOf = (id) => `t/${id}.json`;
export const validKey = (k) => typeof k === 'string' && /^[a-f0-9]{32,64}$/.test(k);
export const validPw = (p) => typeof p === 'string' && p.length >= 4 && p.length <= 64;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const newKey = () => crypto.randomBytes(16).toString('hex');

export function stable(v) {
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
  return JSON.stringify(v);
}

function scrypt(pw, salt) {
  return new Promise((res, rej) =>
    crypto.scrypt(String(pw).normalize('NFKC'), salt, 32, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k))));
}
// 用密碼加密金鑰（AES-256-GCM）；密碼錯誤時解密會失敗。伺服器不保存密碼本身
export async function sealKey(key, pw) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', await scrypt(pw, salt), iv);
  const ct = Buffer.concat([c.update(key, 'utf8'), c.final()]);
  return { salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
}
export async function openKey(rec, pw) {
  if (!rec) return null;
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', await scrypt(pw, Buffer.from(rec.salt, 'base64')), Buffer.from(rec.iv, 'base64'));
    d.setAuthTag(Buffer.from(rec.tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(rec.ct, 'base64')), d.final()]).toString('utf8');
  } catch { return null; }
}

export async function readJSON(pathname) {
  const r = await get(pathname, { access: 'private', useCache: false });
  if (!r || r.statusCode !== 200) return null;
  const txt = await new Response(r.stream).text();
  return { doc: JSON.parse(txt), etag: r.blob.etag, url: r.blob.url, size: Buffer.byteLength(txt) };
}
export async function writeJSON(pathname, doc, etag) {
  const json = JSON.stringify(doc);
  if (Buffer.byteLength(json) > MAX_BYTES) { const e = new Error('too_large'); e.code = 413; throw e; }
  await put(pathname, json, {
    access: 'private', addRandomSuffix: false, allowOverwrite: true,
    contentType: 'application/json', cacheControlMaxAge: 60,
    ...(etag ? { ifMatch: etag } : {}),
  });
}
export const readT = (id) => readJSON(pathOf(id));
export const writeT = (id, doc, etag) => writeJSON(pathOf(id), doc, etag);

// 網站設定（建立碼、自動清理）
export const DEFAULT_CONFIG = { requireCode: false, codes: [], retentionDays: 0, lastCleanup: null };
export async function getConfig() {
  try {
    const r = await readJSON(CONFIG_PATH);
    return { cfg: { ...DEFAULT_CONFIG, ...(r ? r.doc : {}) }, etag: r ? r.etag : null };
  } catch { return { cfg: { ...DEFAULT_CONFIG }, etag: null }; }
}
export const saveConfig = (cfg, etag) => writeJSON(CONFIG_PATH, cfg, etag);
export const normCode = (c) => String(c || '').trim().toUpperCase();

export function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  try { return JSON.parse(req.body || '{}'); } catch { return {}; }
}
export function isPrecondition(e) {
  const name = (e && (e.name || e.constructor?.name)) || '';
  return /Precondition/i.test(name) || /precondition/i.test(String(e && e.message));
}
