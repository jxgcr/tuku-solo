// 存链-私有版(solo) — 单人自持文件/图片云盘。
// 部署到「你自己」的 Cloudflare：纯 R2 存储(图片也存 R2)，元数据 D1，限流用 Durable Object。
// 无多租户、无畅密、无运营台、无购买。首次打开 /setup 设个密码即用，数据全在你账号里，只归你。
// 配置见 wrangler.jsonc 的 vars：BRAND_NAME / BRAND_LOGO / PUBLIC_BASE / BYTE_LIMIT。
// 机密可选：SESSION_SECRET（不设则首次自动生成并存进 D1）。
const VERSION = "cloud-solo-1-20260712";
const MAX_FILE = 100 * 1024 * 1024;       // 单次直传上限；更大自动走分片
const MAX_MPU = 5 * 1024 * 1024 * 1024;   // 分片单文件上限 5GB
const GB = 1073741824;
const DEFAULT_SESSION_TTL = 7 * 24 * 3600;
const DEFAULT_BYTE_LIMIT = 9 * GB;        // 默认容量上限，压在 R2 免费额度(10GB)内

/* ---------- 基础工具 ---------- */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
function brandName(env) { return (env && env.BRAND_NAME) || "我的云盘"; }
function brandLogo(env) { return (env && env.BRAND_LOGO) || "云"; }
function htmlResponse(body, env) {
  // 逐请求随机 nonce，去掉 CSP 的 unsafe-inline；同时把品牌/域名占位替换掉。
  const nonce = btoa(String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(16)))).replace(/[+/=]/g, "");
  const html = String(body)
    .split("__CSP_NONCE__").join(nonce)
    .split("__BRAND_NAME__").join(brandName(env))
    .split("__BRAND_LOGO__").join(brandLogo(env))
    .split("__PUBLIC_BASE__").join(env.PUBLIC_BASE || "");
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
    },
  });
}
function clientIp(request) {
  return request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "0.0.0.0";
}
function envNumber(env, key, fallback) {
  const n = Number(env[key]);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}
function byteLimit(env) { return envNumber(env, "BYTE_LIMIT", DEFAULT_BYTE_LIMIT); }
function fmtGB(b) { const g = Number(b) / GB; return (g >= 10 || g === Math.floor(g) ? g.toFixed(0) : g.toFixed(1)) + "GB"; }
function safeName(n) { return String(n || "file").replace(/[^\w.\-]/g, "_").slice(-80) || "file"; }
function b64u(bytes) { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); }
function b64uToBytes(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); }
async function hmac(secret, value) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}
function ctEqual(a, b) {
  const enc = new TextEncoder();
  const aa = typeof a === "string" ? enc.encode(a) : a;
  const bb = typeof b === "string" ? enc.encode(b) : b;
  const len = Math.max(aa.length, bb.length);
  let diff = aa.length ^ bb.length;
  for (let i = 0; i < len; i++) diff |= (aa[i] || 0) ^ (bb[i] || 0);
  return diff === 0;
}

/* ---------- 密码哈希（PBKDF2-SHA256） ---------- */
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iter = 100000;
  const km = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, km, 256);
  return "pbkdf2$" + iter + "$" + b64u(salt) + "$" + b64u(new Uint8Array(bits));
}
async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith("pbkdf2$")) return false;
  const [, iterStr, saltB, hashB] = stored.split("$");
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: b64uToBytes(saltB), iterations: Number(iterStr), hash: "SHA-256" }, km, 256);
  return ctEqual(new Uint8Array(bits), b64uToBytes(hashB));
}

/* ---------- 单账户配置（config 表） ---------- */
async function ensureTables(env) {
  const stmts = [
    "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)",
    "CREATE TABLE IF NOT EXISTS albums (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, album_id INTEGER, kind TEXT NOT NULL DEFAULT 'file', r2_key TEXT NOT NULL, has_thumb INTEGER NOT NULL DEFAULT 0, mime TEXT, filename TEXT, bytes INTEGER, uploaded_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS pending_deletes (id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_files_album ON files(album_id)",
    "CREATE INDEX IF NOT EXISTS idx_files_uploaded ON files(uploaded_at)",
  ];
  for (const s of stmts) await env.DB.prepare(s).run();
}
async function getConf(env, key) {
  try { const r = await env.DB.prepare("SELECT value FROM config WHERE key=?").bind(key).first(); return r ? r.value : null; }
  catch (e) { return null; } // 表还没建（全新库）时返回 null
}
async function setConf(env, key, value) {
  await env.DB.prepare("INSERT INTO config (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key, value).run();
}
async function isInitialized(env) { return !!(await getConf(env, "owner_hash")); }
// 会话/直链签名串：优先用 secret，其次 D1 里存的（首次自动生成）
async function secretOf(env) {
  if (env.SESSION_SECRET) return env.SESSION_SECRET;
  let s = await getConf(env, "session_secret");
  if (!s) { s = b64u(crypto.getRandomValues(new Uint8Array(32))); await setConf(env, "session_secret", s); }
  return s;
}

/* ---------- 会话（HMAC） + 文件直链令牌 ---------- */
async function signSession(secret, env) {
  const ttl = envNumber(env, "SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL);
  const now = Math.floor(Date.now() / 1000);
  const body = b64u(new TextEncoder().encode(JSON.stringify({ iat: now, exp: now + ttl })));
  const sig = b64u(await hmac(secret, body));
  return body + "." + sig;
}
async function verifySession(secret, token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const expected = b64u(await hmac(secret, parts[0]));
  if (!ctEqual(expected, parts[1])) return null;
  let p; try { p = JSON.parse(new TextDecoder().decode(b64uToBytes(parts[0]))); } catch { return null; }
  if (!p || Number(p.exp) <= Math.floor(Date.now() / 1000)) return null;
  return p;
}
function bearer(request) { const h = request.headers.get("authorization") || ""; return h.startsWith("Bearer ") ? h.slice(7).trim() : ""; }
async function fileToken(secret, id) { return b64u(await hmac(secret, "file:" + id)).slice(0, 24); }
async function fileLink(env, secret, id) { return (env.PUBLIC_BASE || "") + "/f/" + id + "~" + (await fileToken(secret, id)); }
function imgThumbLink(link) { return link + (link.indexOf("?") >= 0 ? "&" : "?") + "thumb=1"; }

/* ---------- 登录鉴权中间件（单 owner） ---------- */
async function requireOwner(request, env, secret) {
  const s = await verifySession(secret, bearer(request));
  if (!s) return { error: json({ error: "未登录" }, 401) };
  return { ok: true };
}

/* ---------- 用量 / 待清理 ---------- */
async function usedBytesOf(env) {
  const r = await env.DB.prepare("SELECT COALESCE(SUM(bytes),0) AS b FROM files").first();
  return Number(r?.b || 0);
}
async function countFiles(env) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM files").first();
  return Number(r?.n || 0);
}
async function recordPending(env, ref) {
  try { await env.DB.prepare("INSERT INTO pending_deletes (ref, attempts, created_at) VALUES (?,0,?)").bind(ref, Math.floor(Date.now() / 1000)).run(); }
  catch (e) { console.log("recordPending fail: " + ref); }
}

/* ---------- 初始化 / 登录 ---------- */
async function handleSetup(request, env) {
  if (await isInitialized(env)) return json({ error: "已初始化" }, 403);
  const body = await request.json().catch(() => ({}));
  const password = String(body.password || "");
  if (password.length < 8) return json({ error: "请设至少 8 位密码" }, 400);
  await ensureTables(env);
  await setConf(env, "owner_hash", await hashPassword(password));
  await setConf(env, "initialized_at", String(Math.floor(Date.now() / 1000)));
  const secret = await secretOf(env);
  return json({ ok: true, token: await signSession(secret, env) });
}
async function handleLogin(request, env, secret) {
  const body = await request.json().catch(() => ({}));
  const password = String(body.password || "");
  const ownerHash = await getConf(env, "owner_hash");
  if (!ownerHash) return json({ error: "尚未初始化，请先设置密码", needSetup: true }, 409);
  if (!password) return json({ error: "请输入密码" }, 400);
  if (!(await verifyPassword(password, ownerHash))) return json({ error: "密码不正确" }, 401);
  return json({ ok: true, token: await signSession(secret, env) });
}

/* ---------- 上传核心（纯 R2；图片可带前端生成的缩略图） ---------- */
async function storeUpload(env, file, albumId, thumb) {
  if (file.size > MAX_FILE) return { error: "单个文件超过 100MB（更大文件请用分片上传）", status: 413 };
  const used = await usedBytesOf(env);
  const lim = byteLimit(env);
  if (used + file.size > lim) return { error: "容量不足（上限 " + fmtGB(lim) + "，已用 " + fmtGB(used) + "），请清理文件", status: 402 };
  const isImage = String(file.type || "").startsWith("image/");
  const now = Math.floor(Date.now() / 1000);
  const key = crypto.randomUUID() + "-" + safeName(file.name);
  try {
    await env.R2.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type || "application/octet-stream" } });
    let hasThumb = 0;
    if (isImage && thumb && typeof thumb !== "string" && thumb.size > 0) {
      try { await env.R2.put(key + ".thumb", await thumb.arrayBuffer(), { httpMetadata: { contentType: thumb.type || "image/jpeg" } }); hasThumb = 1; } catch (e) {}
    }
    const ins = await env.DB.prepare(
      "INSERT INTO files (album_id, kind, r2_key, has_thumb, mime, filename, bytes, uploaded_at) VALUES (?,?,?,?,?,?,?,?)"
    ).bind(albumId, isImage ? "image" : "file", key, hasThumb, file.type || "application/octet-stream", file.name || "file", file.size, now).run();
    // TOCTOU 兜底
    if ((await usedBytesOf(env)) > lim) {
      try { await env.R2.delete(key); } catch (e) {}
      if (hasThumb) { try { await env.R2.delete(key + ".thumb"); } catch (e) {} }
      await env.DB.prepare("DELETE FROM files WHERE id=?").bind(ins.meta.last_row_id).run();
      return { error: "容量不足（上限 " + fmtGB(lim) + "），请清理文件", status: 402 };
    }
    return { record: { id: ins.meta.last_row_id, kind: isImage ? "image" : "file", filename: file.name || "file", mime: file.type || "", bytes: file.size, has_thumb: hasThumb } };
  } catch (e) {
    try { await env.R2.delete(key); } catch (e2) { await recordPending(env, key); }
    console.log("upload fail, rolled back: " + (e && e.message ? e.message : e));
    return { error: "上传失败，请重试", status: 502 };
  }
}
async function handleUpload(request, env, secret) {
  const form = await request.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") return json({ error: "缺少文件" }, 400);
  let albumId = Number(form.get("album_id")) || null;
  if (albumId) { const a = await env.DB.prepare("SELECT id FROM albums WHERE id=?").bind(albumId).first(); if (!a) albumId = null; }
  const thumb = form.get("thumb");
  const r = await storeUpload(env, file, albumId, thumb);
  if (r.error) return json({ error: r.error }, r.status || 400);
  const link = await fileLink(env, secret, r.record.id);
  return json({ ok: true, id: r.record.id, kind: r.record.kind, filename: r.record.filename, link, thumb: r.record.has_thumb ? imgThumbLink(link) : (r.record.kind === "image" ? link : null) });
}

/* ---------- 大文件分片（R2 multipart） ---------- */
async function handleMpuCreate(request, env) {
  const body = await request.json().catch(() => ({}));
  const size = Number(body.size) || 0;
  if (size <= 0) return json({ error: "缺少文件大小" }, 400);
  if (size > MAX_MPU) return json({ error: "单个文件超过 5GB 上限" }, 413);
  const lim = byteLimit(env);
  const used = await usedBytesOf(env);
  if (used + size > lim) return json({ error: "容量不足（上限 " + fmtGB(lim) + "，已用 " + fmtGB(used) + "）" }, 402);
  const key = "mpu/" + crypto.randomUUID() + "-" + safeName(body.filename);
  const mpu = await env.R2.createMultipartUpload(key, { httpMetadata: { contentType: body.mime || "application/octet-stream" } });
  return json({ ok: true, key, uploadId: mpu.uploadId });
}
async function handleMpuPart(request, env, url) {
  const key = url.searchParams.get("key") || "";
  const uploadId = url.searchParams.get("uploadId") || "";
  const partNum = Number(url.searchParams.get("part")) || 0;
  if (!key.startsWith("mpu/") || !uploadId || partNum < 1) return json({ error: "参数错误" }, 400);
  try {
    const mpu = env.R2.resumeMultipartUpload(key, uploadId);
    const part = await mpu.uploadPart(partNum, await request.arrayBuffer());
    return json({ ok: true, part: part.partNumber, etag: part.etag });
  } catch (e) { console.log("mpu part fail: " + (e && e.message ? e.message : e)); return json({ error: "分片上传失败" }, 502); }
}
async function handleMpuComplete(request, env, secret) {
  const body = await request.json().catch(() => ({}));
  const key = String(body.key || "");
  const uploadId = String(body.uploadId || "");
  if (!key.startsWith("mpu/") || !uploadId) return json({ error: "参数错误" }, 400);
  const parts = (Array.isArray(body.parts) ? body.parts : []).map((p) => ({ partNumber: Number(p.part || p.partNumber), etag: p.etag }));
  if (!parts.length) return json({ error: "没有分片" }, 400);
  try { await env.R2.resumeMultipartUpload(key, uploadId).complete(parts); }
  catch (e) { console.log("mpu complete fail: " + (e && e.message ? e.message : e)); return json({ error: "合并失败，请重试" }, 502); }
  // 以 R2 实际大小为准，复核容量
  let realSize = Number(body.size) || 0;
  try { const head = await env.R2.head(key); if (head && Number.isFinite(head.size)) realSize = head.size; } catch (e) {}
  const lim = byteLimit(env);
  const used = await usedBytesOf(env);
  if (used + realSize > lim) { try { await env.R2.delete(key); } catch (e) {} return json({ error: "容量不足（上限 " + fmtGB(lim) + "）" }, 402); }
  let albumId = Number(body.album_id) || null;
  if (albumId) { const a = await env.DB.prepare("SELECT id FROM albums WHERE id=?").bind(albumId).first(); if (!a) albumId = null; }
  const now = Math.floor(Date.now() / 1000);
  const mime = String(body.mime || "application/octet-stream");
  const ins = await env.DB.prepare(
    "INSERT INTO files (album_id, kind, r2_key, has_thumb, mime, filename, bytes, uploaded_at) VALUES (?,?,?,0,?,?,?,?)"
  ).bind(albumId, mime.startsWith("image/") ? "image" : "file", key, mime, String(body.filename || "file"), realSize, now).run();
  const link = await fileLink(env, secret, ins.meta.last_row_id);
  return json({ ok: true, id: ins.meta.last_row_id, kind: mime.startsWith("image/") ? "image" : "file", link });
}

/* ---------- 列表 / 删除 / 相册 ---------- */
async function handleList(env, secret, url) {
  const albumParam = url.searchParams.get("album_id");
  let rows;
  if (albumParam === "none") rows = await env.DB.prepare("SELECT * FROM files WHERE album_id IS NULL ORDER BY id DESC LIMIT 1000").all();
  else if (albumParam) rows = await env.DB.prepare("SELECT * FROM files WHERE album_id=? ORDER BY id DESC LIMIT 1000").bind(Number(albumParam)).all();
  else rows = await env.DB.prepare("SELECT * FROM files ORDER BY id DESC LIMIT 1000").all();
  const images = await Promise.all((rows.results || []).map(async (im) => {
    const link = await fileLink(env, secret, im.id);
    return {
      id: im.id, kind: im.kind === "image" ? "image" : "file", filename: im.filename, mime: im.mime, bytes: im.bytes,
      album_id: im.album_id, uploaded_at: im.uploaded_at, link,
      thumb: im.kind === "image" ? (im.has_thumb ? imgThumbLink(link) : link) : null,
    };
  }));
  return json({ images });
}
async function handleDelete(env, id) {
  const row = await env.DB.prepare("SELECT r2_key, has_thumb FROM files WHERE id=?").bind(id).first();
  if (!row) return json({ error: "文件不存在" }, 404);
  if (row.r2_key) { try { await env.R2.delete(row.r2_key); } catch (e) { await recordPending(env, row.r2_key); } }
  if (row.has_thumb) { try { await env.R2.delete(row.r2_key + ".thumb"); } catch (e) { await recordPending(env, row.r2_key + ".thumb"); } }
  await env.DB.prepare("DELETE FROM files WHERE id=?").bind(id).run();
  return json({ ok: true });
}
async function handleAlbums(env) {
  const rows = await env.DB.prepare("SELECT a.id, a.name, a.created_at, (SELECT COUNT(*) FROM files f WHERE f.album_id=a.id) AS count FROM albums a ORDER BY a.id DESC").all();
  return json({ albums: rows.results || [] });
}
async function handleCreateAlbum(request, env) {
  const body = await request.json().catch(() => ({}));
  const name = String(body.name || "").trim().slice(0, 40);
  if (!name) return json({ error: "请输入相册名" }, 400);
  const ins = await env.DB.prepare("INSERT INTO albums (name, created_at) VALUES (?,?)").bind(name, Math.floor(Date.now() / 1000)).run();
  return json({ ok: true, id: ins.meta.last_row_id, name });
}
async function handleDeleteAlbum(env, id) {
  const a = await env.DB.prepare("SELECT id FROM albums WHERE id=?").bind(id).first();
  if (!a) return json({ error: "相册不存在" }, 404);
  await env.DB.prepare("UPDATE files SET album_id=NULL WHERE album_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM albums WHERE id=?").bind(id).run();
  return json({ ok: true });
}
async function handleMove(request, env, id) {
  const body = await request.json().catch(() => ({}));
  let albumId = body.album_id === null || body.album_id === 0 ? null : Number(body.album_id);
  if (albumId) { const a = await env.DB.prepare("SELECT id FROM albums WHERE id=?").bind(albumId).first(); if (!a) return json({ error: "相册不存在" }, 404); }
  const r = await env.DB.prepare("UPDATE files SET album_id=? WHERE id=?").bind(albumId, id).run();
  if (!r.meta.changes) return json({ error: "文件不存在" }, 404);
  return json({ ok: true });
}
async function handleRename(request, env, id) {
  const body = await request.json().catch(() => ({}));
  const name = String(body.filename || "").trim().replace(/[\r\n\t]/g, "").slice(0, 120);
  if (!name) return json({ error: "名字不能为空" }, 400);
  const r = await env.DB.prepare("UPDATE files SET filename=? WHERE id=?").bind(name, id).run();
  if (!r.meta.changes) return json({ error: "文件不存在" }, 404);
  return json({ ok: true, filename: name });
}
async function handleMe(env) {
  const count = await countFiles(env);
  const used = await usedBytesOf(env);
  const lim = byteLimit(env);
  return json({ count, usedBytes: used, byteLimit: lim, usedGB: fmtGB(used), limitGB: fmtGB(lim) });
}

/* ---------- 文件直链 /f/:id（公开，带 HMAC 令牌防枚举；支持 Range 与缩略图） ---------- */
async function serveFile(request, env, secret, id, token) {
  if (!token || !ctEqual(token, await fileToken(secret, id))) return new Response("Not Found", { status: 404 });
  const row = await env.DB.prepare("SELECT r2_key, filename, mime, has_thumb FROM files WHERE id=?").bind(id).first();
  if (!row || !row.r2_key) return new Response("Not Found", { status: 404 });
  const wantThumb = new URL(request.url).searchParams.get("thumb") && row.has_thumb;
  const objKey = wantThumb ? row.r2_key + ".thumb" : row.r2_key;
  const hasRange = !wantThumb && !!request.headers.get("range");
  const obj = await env.R2.get(objKey, hasRange ? { range: request.headers } : undefined);
  if (!obj) return new Response("Not Found", { status: 404 });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  if (obj.httpEtag) headers.set("etag", obj.httpEtag);
  const mime = wantThumb ? "image/jpeg" : (row.mime || headers.get("content-type") || "application/octet-stream");
  headers.set("content-type", mime);
  headers.set("cache-control", "public, max-age=3600");
  headers.set("accept-ranges", "bytes");
  headers.set("x-content-type-options", "nosniff");
  // 存储型 XSS 加固：html/svg/xml 强制下载 + sandbox
  const dangerous = /(html|svg|xml)/i.test(mime);
  const wantDl = !!new URL(request.url).searchParams.get("dl");
  if (dangerous) headers.set("content-security-policy", "sandbox");
  if (dangerous || wantDl) headers.set("content-disposition", "attachment; filename*=UTF-8''" + encodeURIComponent(row.filename || "file"));
  if (hasRange && obj.range) {
    const off = obj.range.offset || 0;
    const len = obj.range.length != null ? obj.range.length : (obj.size - off);
    headers.set("content-range", "bytes " + off + "-" + (off + len - 1) + "/" + obj.size);
    headers.set("content-length", String(len));
    return new Response(obj.body, { status: 206, headers });
  }
  headers.set("content-length", String(obj.size));
  return new Response(obj.body, { status: 200, headers });
}

/* ---------- 登录暴破限流 Durable Object ---------- */
export class AuthLimiter {
  constructor(state) { this.state = state; }
  async fetch(request) {
    const url = new URL(request.url);
    const max = Number(url.searchParams.get("max")) || 8;
    const lock = Number(url.searchParams.get("lock")) || 900;
    let rec = (await this.state.storage.get("rec")) || { fails: 0, until: 0 };
    const now = Math.floor(Date.now() / 1000);
    if (url.pathname === "/check") { const locked = rec.until > now; return json({ locked, retryIn: locked ? rec.until - now : 0 }); }
    if (url.pathname === "/fail") { rec.fails = (rec.until > now ? rec.fails : 0) + 1; if (rec.fails >= max) rec.until = now + lock; await this.state.storage.put("rec", rec); return json({ ok: true, fails: rec.fails }); }
    if (url.pathname === "/reset") { await this.state.storage.put("rec", { fails: 0, until: 0 }); return json({ ok: true }); }
    return json({ error: "bad" }, 400);
  }
}
function limiter(env, name) { if (!env.AUTH_LIMITER) return null; return env.AUTH_LIMITER.get(env.AUTH_LIMITER.idFromName(name)); }

/* ---------- 入口 ---------- */
export default {
  async scheduled(event, env, ctx) {
    try {
      const rows = await env.DB.prepare("SELECT id, ref, attempts FROM pending_deletes ORDER BY id LIMIT 200").all();
      for (const r of (rows.results || [])) {
        let done = false;
        try { await env.R2.delete(r.ref); done = true; } catch (e) { done = false; }
        if (done || r.attempts >= 10) await env.DB.prepare("DELETE FROM pending_deletes WHERE id=?").bind(r.id).run();
        else await env.DB.prepare("UPDATE pending_deletes SET attempts=attempts+1 WHERE id=?").bind(r.id).run();
      }
    } catch (e) { console.log("scheduled cleanup fail: " + (e && e.message ? e.message : e)); }
  },
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    request.__ctx = ctx;
    const secret = await secretOf(env);

    if (path === "/health") return json({ ok: true, service: "cloud-solo", version: VERSION });
    if (path === "/" || path === "/index.html") return htmlResponse((await isInitialized(env)) ? PAGE_HTML : SETUP_HTML, env);
    if (path === "/setup") return htmlResponse(SETUP_HTML, env);
    if (path === "/privacy") return htmlResponse(privacyHtml(env), env);
    if (path === "/terms") return htmlResponse(termsHtml(env), env);

    const fm = path.match(/^\/f\/(\d+)~([A-Za-z0-9_-]+)$/);
    if (fm) return serveFile(request, env, secret, Number(fm[1]), fm[2]);

    try {
      if (request.method === "POST" && path === "/api/setup") return await handleSetup(request, env);

      if (request.method === "POST" && path === "/api/login") {
        const ip = clientIp(request);
        const lim = limiter(env, "login:" + ip);
        const max = envNumber(env, "AUTH_MAX_FAILURES", 8), lock = envNumber(env, "AUTH_LOCK_SECONDS", 900);
        if (lim) { const c = await (await lim.fetch("https://do/check?max=" + max + "&lock=" + lock)).json(); if (c.locked) return json({ error: "尝试过于频繁，请 " + Math.ceil(c.retryIn / 60) + " 分钟后再试" }, 429); }
        const resp = await handleLogin(request, env, secret);
        if (lim) { if (resp.status === 401) await lim.fetch("https://do/fail?max=" + max + "&lock=" + lock); else if (resp.status === 200) await lim.fetch("https://do/reset"); }
        return resp;
      }

      // 以下均需 owner 登录
      const auth = await requireOwner(request, env, secret);
      if (auth.error) return auth.error;

      if (request.method === "GET" && path === "/api/me") return handleMe(env);
      if (request.method === "POST" && path === "/api/upload") return await handleUpload(request, env, secret);
      if (request.method === "POST" && path === "/api/mpu/create") return await handleMpuCreate(request, env);
      if (request.method === "POST" && path === "/api/mpu/part") return await handleMpuPart(request, env, url);
      if (request.method === "POST" && path === "/api/mpu/complete") return await handleMpuComplete(request, env, secret);
      if (request.method === "GET" && path === "/api/list") return handleList(env, secret, url);
      if (request.method === "GET" && path === "/api/albums") return handleAlbums(env);
      if (request.method === "POST" && path === "/api/albums") return handleCreateAlbum(request, env);

      let m;
      if ((m = path.match(/^\/api\/file\/(\d+)$/)) && request.method === "DELETE") return handleDelete(env, Number(m[1]));
      if ((m = path.match(/^\/api\/file\/(\d+)\/album$/)) && request.method === "POST") return handleMove(request, env, Number(m[1]));
      if ((m = path.match(/^\/api\/file\/(\d+)\/rename$/)) && request.method === "POST") return handleRename(request, env, Number(m[1]));
      if ((m = path.match(/^\/api\/albums\/(\d+)$/)) && request.method === "DELETE") return handleDeleteAlbum(env, Number(m[1]));

      return json({ error: "not_found" }, 404);
    } catch (err) {
      console.log("solo error: " + (err && err.message ? err.message : err));
      return json({ error: "服务器繁忙，请稍后重试" }, 500);
    }
  },
};

/* ---------- 共用样式片段 ---------- */
const BASE_CSS = `
:root{--bg:#080910;--bg2:#0b0d15;--card:#10131c;--ink:#EEF1F7;--mut:#8A93A6;--line:rgba(255,255,255,.08);--g1:#a855f7;--g2:#6d5efc;--ok:#34D39A;--amber:#F3B44C;--bad:#F2726F}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);min-height:100vh;line-height:1.5;-webkit-font-smoothing:antialiased}
.bg{position:fixed;inset:0;z-index:-1;background:radial-gradient(900px 500px at 12% -5%,rgba(124,92,255,.20),transparent 60%),radial-gradient(800px 500px at 100% 110%,rgba(45,212,191,.12),transparent 55%)}
input,button,select{font:inherit}
input,select{width:100%;border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.05);color:var(--ink);padding:12px 13px;outline:0}
input:focus,select:focus{border-color:rgba(124,108,255,.55)}
button{border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.06);color:var(--ink);font-weight:700;cursor:pointer;padding:11px 16px;transition:.15s}
button:hover{background:rgba(255,255,255,.11)}
button.pri{border:0;background:linear-gradient(135deg,var(--g2),var(--g1));color:#fff}
button.pri:hover{filter:brightness(1.1)}
button.sm{padding:6px 10px;font-size:.8rem}
button.danger{color:var(--bad);border-color:rgba(242,114,111,.35)}
.muted{color:var(--mut);font-size:.85rem}
.hide{display:none!important}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--g2),var(--g1));display:flex;align-items:center;justify-content:center;font-weight:900;color:#fff;flex-shrink:0}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);opacity:0;background:rgba(14,16,26,.95);border:1px solid var(--line);border-radius:12px;padding:12px 16px;transition:.2s;pointer-events:none;z-index:50}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}`;

const SETUP_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>__BRAND_NAME__ · 首次设置</title><style>${BASE_CSS}
.wrap{max-width:400px;margin:14vh auto;padding:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 30px 80px rgba(0,0,0,.5)}
.card>*+*{margin-top:12px}
.brand{display:flex;align-items:center;gap:10px;font-size:1.3rem;font-weight:800}
</style></head><body><div class="bg"></div>
<div class="wrap"><div class="card">
  <div class="brand"><span class="logo">__BRAND_LOGO__</span>__BRAND_NAME__</div>
  <div class="muted">第一次使用：给你的云盘设一个登录密码（≥8 位）。以后凭这个密码进入，数据只归你。</div>
  <input id="pw" type="password" placeholder="设置密码（至少 8 位）">
  <input id="pw2" type="password" placeholder="再输一次确认">
  <button class="pri" id="go" style="width:100%">创建我的云盘</button>
  <div id="err" class="muted" style="color:var(--bad);min-height:20px"></div>
</div></div>
<div class="toast" id="toast"></div>
<script nonce="__CSP_NONCE__">
function $(i){return document.getElementById(i)}
function go(){
  var p=$("pw").value,p2=$("pw2").value;$("err").textContent="";
  if(p.length<8){$("err").textContent="密码至少 8 位";return}
  if(p!==p2){$("err").textContent="两次密码不一致";return}
  $("go").disabled=true;
  fetch("/api/setup",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:p})}).then(function(r){return r.json().then(function(d){
    $("go").disabled=false;
    if(!r.ok){$("err").textContent=d.error||"设置失败";return}
    sessionStorage.setItem("cloud_token",d.token);location.href="/";
  })}).catch(function(){$("go").disabled=false;$("err").textContent="网络错误"});
}
$("go").addEventListener("click",go);
$("pw2").addEventListener("keydown",function(e){if(e.key==="Enter")go()});
</script></body></html>`;

const PAGE_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>__BRAND_NAME__</title><style>${BASE_CSS}
.login{max-width:400px;margin:14vh auto;padding:20px}
.login .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 30px 80px rgba(0,0,0,.5)}
.login .card>*+*{margin-top:12px}
.login .brand{display:flex;align-items:center;gap:10px;font-size:1.3rem;font-weight:800}
.shell{display:flex;min-height:100vh}
.side{width:240px;flex-shrink:0;background:var(--bg2);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:16px 12px;position:sticky;top:0;height:100vh;overflow-y:auto}
.side .brand{display:flex;align-items:center;gap:10px;font-size:1.2rem;font-weight:800;padding:6px 8px 14px}
.side .brand .x{margin-left:auto;font-size:1.3rem;color:var(--mut);cursor:pointer;display:none}
.navgrp{font-size:.68rem;color:var(--mut);letter-spacing:.08em;padding:12px 10px 5px}
.navitem{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:10px;color:var(--mut);font-weight:600;cursor:pointer;font-size:.9rem;transition:.14s}
.navitem:hover{background:rgba(255,255,255,.05);color:var(--ink)}
.navitem.on{background:linear-gradient(135deg,rgba(109,94,252,.22),rgba(168,85,247,.16));color:#fff;box-shadow:inset 0 0 0 1px rgba(124,108,255,.3)}
.navitem .ni{font-size:1.05rem;width:20px;text-align:center}
.navitem .cnt{margin-left:auto;font-size:.75rem;color:var(--mut);font-variant-numeric:tabular-nums}
.sidefoot{margin-top:auto;padding-top:10px;border-top:1px solid var(--line)}
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:30;display:none}.scrim.show{display:block}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;gap:12px;padding:14px 24px;border-bottom:1px solid var(--line);background:rgba(10,12,18,.6);backdrop-filter:blur(8px);position:sticky;top:0;z-index:6}
.topbar .burger{font-size:1.4rem;cursor:pointer;display:none}
.topbar .pt{font-size:1.15rem;font-weight:700}
.topbar .sp{margin-left:auto}
.uchip{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:999px;padding:6px 14px;font-size:.85rem;color:var(--mut)}
.uchip .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.content{padding:24px 32px;width:100%}
.panel{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px;box-shadow:0 12px 40px rgba(0,0,0,.32)}
.ph{font-size:.95rem;font-weight:700;margin-bottom:16px}
.usebar{height:10px;background:rgba(255,255,255,.08);border-radius:6px;overflow:hidden}
.usebar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--g2),var(--g1));border-radius:6px;transition:width .6s cubic-bezier(.2,.7,.2,1)}
.usebar>i.warn{background:linear-gradient(90deg,var(--amber),#fb7185)}.usebar>i.full{background:linear-gradient(90deg,#fb7185,#ef4444)}
.usetxt{display:flex;justify-content:space-between;margin-top:10px;font-size:.85rem;font-variant-numeric:tabular-nums}
.spacefoot{margin-top:14px;border-top:1px solid var(--line);padding-top:4px}
.info{display:flex;justify-content:space-between;gap:12px;padding:7px 0;font-size:.9rem}.info .il{color:var(--mut)}
.recentrow{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:12px}
.rtile{aspect-ratio:1.618;border-radius:10px;overflow:hidden;background:#0a0b10;border:1px solid var(--line);cursor:pointer;transition:transform .16s}
.rtile:hover{transform:translateY(-2px)}
.rtile img{width:100%;height:100%;object-fit:cover;display:block}
.rfi{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:1.9rem}
.setbar{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:14px;color:var(--mut);font-size:.85rem}
.setbar .chk{display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none}
.setbar input{width:auto}
.drop{border:2px dashed var(--line);border-radius:16px;padding:44px 20px;text-align:center;color:var(--mut);cursor:pointer;margin-bottom:16px;transition:.15s}
.drop:hover{border-color:rgba(124,108,255,.4)}.drop.on{border-color:var(--g2);background:rgba(124,108,255,.06)}
.dropico{font-size:2.4rem;margin-bottom:10px}
.prog{display:grid;gap:8px;margin-bottom:16px}
.pitem{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:9px 12px}
.pn{font-size:.8rem;display:flex;justify-content:space-between;gap:8px;margin-bottom:6px}
.pn>span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pct{color:var(--mut);flex-shrink:0}
.pbar{height:6px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden}
.pbar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--g2),var(--g1));transition:width .2s}
.pitem.done .pbar>i{background:var(--ok);width:100%}.pitem.err .pbar>i{background:var(--bad)}.pitem.err .pct{color:var(--bad)}
.pitem.paused .pbar>i{background:var(--amber)}.pitem.paused .pct{color:var(--amber)}
.pitem.canceled{opacity:.55}.pitem.canceled .pbar>i{background:var(--mut)}.pitem.canceled .pct{color:var(--mut)}
.pacts{display:flex;justify-content:flex-end;gap:8px;margin-top:8px}.pacts:empty{margin-top:0}
.pbtn{padding:4px 10px;font-size:.74rem;font-weight:600;border-radius:8px}.pbtn.del{color:var(--bad);border-color:rgba(242,114,111,.35)}
.ftool{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.ftitle{font-size:1.05rem;font-weight:700;margin-right:auto}
.srch{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:10px;padding:0 12px;min-width:170px}
.srch input{border:0;background:transparent;padding:9px 0}
.ftool select{width:auto;padding:9px 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px}
.tile{position:relative;aspect-ratio:1.618;border-radius:14px;overflow:hidden;background:#0a0b10;border:1px solid var(--line);cursor:pointer}
.tile.sel{box-shadow:0 0 0 2px var(--g2);border-color:transparent}
.tile img{width:100%;height:100%;object-fit:cover;display:block;transition:transform .3s}.tile:hover img{transform:scale(1.05)}
.tile .fileic{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:2.6rem}
.tile .cap{position:absolute;left:0;right:0;bottom:0;background:rgba(0,0,0,.62);padding:6px 9px;font-size:.74rem;pointer-events:none}
.tile .cap .nm{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tile .cap .tm{color:#b9c0cc;font-size:.68rem}
.tile .chk{position:absolute;top:8px;left:8px;width:21px;height:21px;border-radius:50%;border:1.5px solid rgba(255,255,255,.75);background:rgba(0,0,0,.35);display:flex;align-items:center;justify-content:center;font-size:.8rem;color:transparent;opacity:0;transition:.12s}
.tile:hover .chk,.tile.sel .chk,.selmode .tile .chk{opacity:1}
.tile.sel .chk{background:var(--g2);border-color:var(--g2);color:#fff}
.tile .more{position:absolute;top:7px;right:7px;width:24px;height:24px;border-radius:8px;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;color:#fff;opacity:0;transition:.12s}
.tile:hover .more{opacity:1}
.tile .badge{position:absolute;bottom:26px;left:8px;padding:1px 7px;border-radius:6px;font-size:.62rem;font-weight:700;background:rgba(124,108,255,.22)}
@media(hover:none){.tile .more,.tile .chk{opacity:1}}
.batch{position:fixed;left:50%;bottom:22px;transform:translateX(-50%) translateY(30px);opacity:0;pointer-events:none;display:flex;align-items:center;gap:8px;background:#12141d;border:1px solid rgba(124,108,255,.4);border-radius:999px;padding:8px 10px 8px 18px;box-shadow:0 18px 50px rgba(0,0,0,.55);z-index:25;transition:.18s;font-size:.86rem}
.batch.show{opacity:1;transform:translateX(-50%) translateY(0);pointer-events:auto}
.batch b{color:#c9beff}.batch .bd{width:1px;height:18px;background:rgba(255,255,255,.14);margin:0 3px}.batch button{border-radius:999px;padding:7px 13px}
.empty{text-align:center;padding:56px 20px;color:var(--mut)}.empty .ei{font-size:2.6rem;opacity:.5;margin-bottom:10px}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:35;padding:16px}.overlay.show{display:flex}
.modal{background:#0d0f16;border:1px solid var(--line);border-radius:16px;padding:20px;width:100%;max-width:420px;box-shadow:0 30px 80px rgba(0,0,0,.6)}
.modal h3{font-size:1.02rem;margin-bottom:14px;word-break:break-all}
.acts{display:grid;gap:4px}
.acts .a{display:flex;align-items:center;gap:11px;padding:11px 12px;border-radius:10px;cursor:pointer;font-size:.92rem}
.acts .a:hover{background:rgba(255,255,255,.06)}.acts .a .ai{width:20px;text-align:center}.acts .a.del{color:var(--bad)}.acts .sep{height:1px;background:var(--line);margin:5px 8px}
.foot{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
.cval{display:flex;align-items:center;gap:8px;margin-top:8px}.cval input{font-size:.8rem;padding:9px 11px}
.lb{position:fixed;inset:0;background:rgba(0,0,0,.92);display:none;align-items:center;justify-content:center;z-index:40}.lb.show{display:flex}
.lb img{max-width:92vw;max-height:88vh;border-radius:8px}
.lb .x{position:absolute;top:16px;right:22px;font-size:1.7rem;color:#fff;cursor:pointer}
.lb .nav{position:absolute;top:50%;transform:translateY(-50%);font-size:2.6rem;color:#fff;cursor:pointer;opacity:.7;padding:10px 18px;user-select:none}.lb .nav:hover{opacity:1}.lb .prev{left:6px}.lb .next{right:6px}
@media(max-width:820px){
.side{position:fixed;left:0;top:0;height:100vh;z-index:31;transform:translateX(-100%);transition:transform .22s}.side.open{transform:translateX(0)}.side .brand .x{display:block}
.topbar .burger{display:block}.content{padding:16px}.topbar{padding:12px 16px}.grid{grid-template-columns:repeat(2,1fr);gap:10px}
.overlay{align-items:flex-end;padding:0}.overlay .modal{max-width:100%;border-radius:18px 18px 0 0}
.batch{left:12px;right:12px;bottom:12px;transform:translateY(30px);justify-content:center;border-radius:14px}.batch.show{transform:translateY(0)}
}
</style></head><body><div class="bg"></div>

<div id="loginView" class="login"><div class="card">
  <div class="brand"><span class="logo">__BRAND_LOGO__</span>__BRAND_NAME__</div>
  <div class="muted">输入密码进入你的云盘。</div>
  <input id="pw" type="password" placeholder="密码">
  <button class="pri" id="loginBtn" style="width:100%">进入</button>
  <div id="loginErr" class="muted" style="color:var(--bad);min-height:20px"></div>
</div></div>

<div id="appShell" class="shell hide">
  <div class="scrim" id="scrim"></div>
  <aside class="side" id="side">
    <div class="brand"><span class="logo">__BRAND_LOGO__</span>__BRAND_NAME__<span class="x" id="sideClose">✕</span></div>
    <div id="nav"></div>
    <div class="sidefoot"><div class="navitem" id="logoutBtn"><span class="ni">↩</span>退出登录</div></div>
  </aside>
  <div class="main">
    <header class="topbar"><span class="burger" id="burger">☰</span><div class="pt" id="pageTitle">我的云盘</div><span class="sp"></span><div class="uchip"><span class="dot"></span>只有你可见</div></header>
    <div class="content">
      <div id="view-dash" class="view">
        <div class="panel space">
          <div class="ph" style="display:flex;justify-content:space-between;align-items:center">我的空间<span class="muted" style="font-weight:400"><span id="sCount">0</span> 个文件</span></div>
          <div class="usetxt" style="margin-bottom:9px"><span id="dUseTxt" style="font-size:1.5rem;font-weight:800">0 / 0</span><span id="dPct" class="muted">0%</span></div>
          <div class="usebar"><i id="dBar"></i></div>
          <div id="catBars" style="margin-top:16px"></div>
          <div class="spacefoot"><div class="info"><span class="il">隐私</span><span>🔒 文件仅你可见，数据在你自己账号</span></div></div>
          <button class="pri" id="goUpload" style="margin-top:16px">☁️ 上传文件</button>
        </div>
        <div class="panel" style="margin-top:16px">
          <div class="ph" style="display:flex;justify-content:space-between;align-items:center">最近上传<span class="muted" id="recMore" style="cursor:pointer;font-weight:400">查看全部 ›</span></div>
          <div class="recentrow" id="recent"></div>
        </div>
      </div>
      <div id="view-upload" class="view hide">
        <div class="setbar"><label class="chk"><input type="checkbox" id="cmp" checked> 图片上传前压缩（省空间/更快）</label></div>
        <div class="drop" id="drop"><div class="dropico">☁️</div><div style="font-size:1.05rem;color:var(--ink)"><b>拖文件到这里</b>，或点击选择</div><div class="muted" style="margin-top:6px">图片 / 视频 / 音频 / PDF / 压缩包… 可多选</div><input id="file" type="file" multiple class="hide"></div>
        <div id="progress" class="prog hide"></div>
        <div class="muted" style="font-size:.82rem">大文件自动分片直传；也可直接 <b>Ctrl+V</b> 粘贴图片上传。</div>
      </div>
      <div id="view-files" class="view hide">
        <div class="ftool">
          <span class="ftitle" id="ftitle">全部文件</span>
          <div class="srch"><span>🔍</span><input id="q" placeholder="搜索文件名"></div>
          <select id="sort"><option value="new">最新</option><option value="old">最早</option><option value="big">最大</option><option value="name">名称</option></select>
          <button id="delAlbumBtn" class="sm danger hide">删除相册</button>
        </div>
        <div class="grid" id="grid"></div>
        <div id="empty" class="empty hide"><div class="ei">📭</div>这里还没有文件</div>
      </div>
    </div>
  </div>
</div>

<div class="batch" id="batch"><span>已选 <b id="selN">0</b></span><span class="bd"></span><button id="bDown">⬇ 下载</button><button id="bDel" class="danger">🗑 删除</button><button id="bCancel">取消</button></div>
<div class="lb" id="lightbox"><span class="x" id="lbClose">✕</span><span class="nav prev" id="lbPrev">‹</span><img id="lbImg" src="" alt=""><span class="nav next" id="lbNext">›</span></div>
<div class="overlay" id="menuOverlay"><div class="modal"><h3 id="mTitle">操作</h3><div class="acts" id="mActs"></div></div></div>
<div class="overlay" id="detailOverlay"><div class="modal"><h3>详细信息</h3><div id="dBody"></div><div class="foot"><button id="dClose">关闭</button></div></div></div>
<div class="overlay" id="renameOverlay"><div class="modal"><h3>重命名</h3><input id="renameInput" placeholder="新文件名"><div class="foot"><button id="renCancel">取消</button><button class="pri" id="renSave">保存</button></div></div></div>
<div class="overlay" id="moveOverlay"><div class="modal"><h3 id="moveTitle">移动到相册</h3><div class="acts" id="moveActs"></div><div class="foot"><button id="moveCancel">取消</button></div></div></div>
<div class="overlay" id="setOverlay"><div class="modal"><h3>设置</h3><div id="setBody"></div><div class="foot"><button id="setLogout" class="danger">退出登录</button><button id="setClose">关闭</button></div></div></div>
<div class="toast" id="toast"></div>
<script nonce="__CSP_NONCE__">
var TOKEN=sessionStorage.getItem("cloud_token")||"";
var ALLFILES=[],ALBUMS=[],VIEW="dash",NAV={type:"all"},Q="",SORT="new",SEL={},LB=[],LBI=0,MENU_IM=null,REN_IM=null;
var CATS=[["all","全部文件","🗂️"],["image","图片","🖼️"],["video","视频","🎬"],["audio","音频","🎵"],["doc","文档","📄"],["zip","压缩包","🗜️"],["other","其他","📎"]];
function $(i){return document.getElementById(i)}
function show(i){$(i).classList.add("show")}function hide(i){$(i).classList.remove("show")}
function toast(m){var t=$("toast");t.textContent=m;t.classList.add("show");setTimeout(function(){t.classList.remove("show")},2200)}
function esc(s){return String(s==null?"":s).replace(/[<>&"']/g,function(c){return c==="<"?"&lt;":c===">"?"&gt;":c==="&"?"&amp;":c==='"'?"&quot;":"&#39;"})}
function fmtSize(b){b=Number(b)||0;if(b<1024)return b+" B";if(b<1048576)return (b/1024).toFixed(1)+" KB";if(b<1073741824)return (b/1048576).toFixed(1)+" MB";return (b/1073741824).toFixed(2)+" GB"}
function relTime(t){t=Number(t);if(!t)return"";if(t>1e12)t=Math.floor(t/1000);var s=Math.floor(Date.now()/1000)-t;if(s<0)s=0;if(s<60)return"刚刚";if(s<3600)return Math.floor(s/60)+" 分钟前";if(s<86400)return Math.floor(s/3600)+" 小时前";if(s<2592000)return Math.floor(s/86400)+" 天前";var d=new Date(t*1000);return (d.getMonth()+1)+"-"+d.getDate()}
function typeOf(im){if(im.kind==="image")return"image";var m=String(im.mime||"");if(m.indexOf("video")===0)return"video";if(m.indexOf("audio")===0)return"audio";if(m.indexOf("pdf")>=0||m.indexOf("text")===0||m.indexOf("word")>=0||m.indexOf("document")>=0||m.indexOf("sheet")>=0||m.indexOf("presentation")>=0)return"doc";if(/zip|rar|7z|compress|tar|gzip/.test(m))return"zip";return"other"}
function typeIcon(t){return t==="video"?"🎬":t==="audio"?"🎵":t==="doc"?"📄":t==="zip"?"🗜️":"📎"}
function extOf(im){var n=String(im.filename||"");var d=n.lastIndexOf(".");return d>0?n.slice(d+1).toUpperCase().slice(0,4):"文件"}
function catCount(c){if(c==="all")return ALLFILES.length;var n=0;for(var i=0;i<ALLFILES.length;i++)if(typeOf(ALLFILES[i])===c)n++;return n}
function catLabel(t){for(var i=0;i<CATS.length;i++)if(CATS[i][0]===t)return CATS[i][1];return"全部文件"}
function api(p,o){o=o||{};o.headers=Object.assign({authorization:"Bearer "+TOKEN},o.headers||{});return fetch(p,o).then(function(r){return r.json().then(function(d){if(r.status===401){logout();throw new Error(d.error||"未登录")}if(!r.ok)throw new Error(d.error||("HTTP "+r.status));return d})})}
function logout(){sessionStorage.removeItem("cloud_token");TOKEN="";$("appShell").classList.add("hide");$("loginView").classList.remove("hide")}
$("loginBtn").addEventListener("click",doLogin);
$("pw").addEventListener("keydown",function(e){if(e.key==="Enter")doLogin()});
function doLogin(){var pw=$("pw").value;$("loginErr").textContent="";
  fetch("/api/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:pw})}).then(function(r){return r.json().then(function(d){
    if(!r.ok){if(d.needSetup){location.href="/setup";return}$("loginErr").textContent=d.error||"登录失败";return}
    TOKEN=d.token;sessionStorage.setItem("cloud_token",TOKEN);enterApp();
  })}).catch(function(){$("loginErr").textContent="网络错误"});
}
function enterApp(){$("loginView").classList.add("hide");$("appShell").classList.remove("hide");Promise.all([loadAlbums(),loadFiles()]).then(function(){navTo({view:"dash"})}).catch(function(){navTo({view:"dash"})})}
function loadFiles(){return api("/api/list").then(function(d){ALLFILES=d.images||[]})}
function loadAlbums(){return api("/api/albums").then(function(d){ALBUMS=d.albums||[]})}
function loadMe(){api("/api/me").then(function(d){
  $("sCount").textContent=d.count;
  var pct=d.byteLimit>0?Math.min(100,d.usedBytes/d.byteLimit*100):0;
  var bar=$("dBar");bar.style.width=(pct<1.5&&pct>0?1.5:pct).toFixed(1)+"%";bar.className=pct>=95?"full":pct>=80?"warn":"";
  $("dUseTxt").textContent=fmtSize(d.usedBytes)+" / "+fmtSize(d.byteLimit);
  $("dPct").textContent=pct.toFixed(pct<10?1:0)+"%";
}).catch(function(){})}
function renderCatBars(){var box=$("catBars");if(!box)return;box.innerHTML="";var tot=0,sums={};
  ALLFILES.forEach(function(x){var t=typeOf(x),b=Number(x.bytes)||0;sums[t]=(sums[t]||0)+b;tot+=b});
  if(!tot){box.innerHTML="<div class='muted' style='font-size:.8rem'>上传后这里显示空间构成</div>";return}
  var col={image:"#a855f7",video:"#2dd4bf",audio:"#f3b44c",doc:"#6d5efc",zip:"#fb7185",other:"#8A93A6"};
  CATS.forEach(function(c){if(c[0]==="all")return;var b=sums[c[0]]||0;if(!b)return;var pc=Math.max(1,Math.round(b/tot*100));
    var d=document.createElement("div");d.style.marginBottom="9px";
    d.innerHTML="<div style='display:flex;justify-content:space-between;font-size:.78rem;color:var(--mut);margin-bottom:3px'><span>"+c[2]+" "+c[1]+"</span><span>"+fmtSize(b)+" · "+pc+"%</span></div><div class='pbar'><i style='width:"+pc+"%;background:"+col[c[0]]+"'></i></div>";
    box.appendChild(d);});
}
function renderRecent(){var box=$("recent");if(!box)return;var arr=ALLFILES.slice().sort(function(a,b){return (b.uploaded_at||0)-(a.uploaded_at||0)}).slice(0,10);box.innerHTML="";
  if(!arr.length){box.innerHTML="<div class='muted'>还没有文件，去上传第一个吧</div>";return}
  arr.forEach(function(im){var t=document.createElement("div");t.className="rtile";
    if(im.kind==="image"){var g=document.createElement("img");g.src=im.thumb;g.loading="lazy";t.appendChild(g)}else{var fi=document.createElement("div");fi.className="rfi";fi.textContent=typeIcon(typeOf(im));t.appendChild(fi)}
    t.onclick=function(){if(im.kind==="image")openLightboxAll(im);else window.open(im.link,"_blank")};box.appendChild(t);});
}
function navTo(spec){clearSel();closeDrawer();closeOverlays();
  if(spec.view)VIEW=spec.view;else if(spec.type){VIEW="files";NAV={type:spec.type}}else{VIEW="files";NAV={album:spec.album,name:spec.name}}
  $("view-dash").classList.toggle("hide",VIEW!=="dash");$("view-upload").classList.toggle("hide",VIEW!=="upload");$("view-files").classList.toggle("hide",VIEW!=="files");
  $("pageTitle").textContent=VIEW==="dash"?"我的云盘":VIEW==="upload"?"上传文件":"我的文件";
  renderNav();if(VIEW==="dash"){loadMe();renderRecent();renderCatBars()}if(VIEW==="files")renderFiles();
}
function renderNav(){var nav=$("nav");nav.innerHTML="";
  var grp=function(t){var g=document.createElement("div");g.className="navgrp";g.textContent=t;nav.appendChild(g)};
  var item=function(icon,label,active,cnt,fn){var a=document.createElement("div");a.className="navitem"+(active?" on":"");a.innerHTML="<span class='ni'>"+icon+"</span>"+esc(label);if(cnt!=null){var c=document.createElement("span");c.className="cnt";c.textContent=cnt;a.appendChild(c)}a.onclick=fn;nav.appendChild(a)};
  grp("常规");item("🏠","我的云盘",VIEW==="dash",null,function(){navTo({view:"dash"})});item("☁️","上传文件",VIEW==="upload",null,function(){navTo({view:"upload"})});
  grp("分类");CATS.forEach(function(c){item(c[2],c[1],VIEW==="files"&&NAV.type===c[0],catCount(c[0]),function(){navTo({type:c[0]})})});
  grp("相册");ALBUMS.forEach(function(al){item("📁",al.name,VIEW==="files"&&String(NAV.album)===String(al.id),al.count,function(){navTo({album:al.id,name:al.name})})});
  item("➕","新建相册",false,null,newAlbum);grp("账户");item("⚙️","设置",false,null,openSettings);
}
function currentList(){var arr=ALLFILES.slice();
  if(NAV.album!=null&&NAV.type==null)arr=arr.filter(function(x){return String(x.album_id)===String(NAV.album)});
  else if(NAV.type&&NAV.type!=="all")arr=arr.filter(function(x){return typeOf(x)===NAV.type});
  if(Q){var q=Q.toLowerCase();arr=arr.filter(function(x){return String(x.filename||"").toLowerCase().indexOf(q)>=0})}
  arr.sort(function(a,b){if(SORT==="new")return (b.uploaded_at||0)-(a.uploaded_at||0);if(SORT==="old")return (a.uploaded_at||0)-(b.uploaded_at||0);if(SORT==="big")return (b.bytes||0)-(a.bytes||0);return String(a.filename||"").localeCompare(String(b.filename||""))});
  return arr;
}
function renderFiles(){var isAlbum=NAV.album!=null&&NAV.type==null;$("ftitle").textContent=isAlbum?(NAV.name||"相册"):catLabel(NAV.type);$("delAlbumBtn").classList.toggle("hide",!isAlbum);
  var arr=currentList(),g=$("grid");g.innerHTML="";$("empty").classList.toggle("hide",arr.length>0);
  arr.forEach(function(im){var t=document.createElement("div");t.className="tile"+(SEL[im.id]?" sel":"");t.setAttribute("data-id",im.id);
    if(im.kind==="image"){var g2=document.createElement("img");g2.src=im.thumb;g2.loading="lazy";t.appendChild(g2)}else{var fi=document.createElement("div");fi.className="fileic";fi.textContent=typeIcon(typeOf(im));t.appendChild(fi);var bd=document.createElement("span");bd.className="badge";bd.textContent=extOf(im);t.appendChild(bd)}
    var chk=document.createElement("span");chk.className="chk";chk.textContent="✓";chk.onclick=function(e){e.stopPropagation();toggleSel(im.id)};t.appendChild(chk);
    var more=document.createElement("span");more.className="more";more.textContent="⋯";more.onclick=function(e){e.stopPropagation();openMenu(im)};t.appendChild(more);
    var cap=document.createElement("div");cap.className="cap";cap.innerHTML="<div class='nm'>"+esc(im.filename||"文件")+"</div><div class='tm'>"+relTime(im.uploaded_at)+"</div>";t.appendChild(cap);
    t.onclick=function(){if(im.kind==="image")openLightbox(im);else window.open(im.link,"_blank")};g.appendChild(t);});
}
function toggleSel(id){if(SEL[id])delete SEL[id];else SEL[id]=true;updateSelUI()}
function selIds(){return Object.keys(SEL).map(Number)}
function clearSel(){SEL={};updateSelUI()}
function updateSelUI(){var n=selIds().length;document.body.classList.toggle("selmode",n>0);$("selN").textContent=n;$("batch").classList.toggle("show",n>0);
  var tiles=document.querySelectorAll("#grid .tile");for(var i=0;i<tiles.length;i++){var id=tiles[i].getAttribute("data-id");tiles[i].classList.toggle("sel",!!SEL[id])}}
function openMenu(im){MENU_IM=im;$("mTitle").textContent=im.filename||"操作";var box=$("mActs");box.innerHTML="";
  var add=function(icon,label,fn,cls){var a=document.createElement("div");a.className="a"+(cls?" "+cls:"");a.innerHTML="<span class='ai'>"+icon+"</span>"+label;a.onclick=fn;box.appendChild(a)};
  add("🔗","复制直链",function(){hide("menuOverlay");navigator.clipboard.writeText(im.link).then(function(){toast("直链已复制")})});
  add("⬇","下载",function(){hide("menuOverlay");downloadOne(im)});
  add("↗","新窗口打开",function(){hide("menuOverlay");window.open(im.link,"_blank")});
  add("✏","重命名",function(){hide("menuOverlay");openRename(im)});
  add("ℹ","详细信息",function(){hide("menuOverlay");openDetail(im)});
  add("📁","移动到相册",function(){hide("menuOverlay");openMove([im.id])});
  var sep=document.createElement("div");sep.className="sep";box.appendChild(sep);
  add("🗑","删除",function(){hide("menuOverlay");delItems([im.id])},"del");show("menuOverlay");
}
function downloadOne(im){var a=document.createElement("a");a.href=im.kind==="image"?im.link:(im.link+"?dl=1");a.download=im.filename||"";document.body.appendChild(a);a.click();a.remove()}
function downloadSel(){var arr=ALLFILES.filter(function(x){return SEL[x.id]});var i=0;(function nx(){if(i>=arr.length)return;downloadOne(arr[i]);i++;setTimeout(nx,500)})();toast("开始下载 "+arr.length+" 个")}
function openDetail(im){var b=$("dBody");b.innerHTML="";
  if(im.kind==="image"){var img=document.createElement("img");img.style.cssText="width:100%;height:180px;object-fit:contain;background:#000;border-radius:10px;margin-bottom:14px";img.src=im.thumb;b.appendChild(img)}
  var row=function(k,v){var d=document.createElement("div");d.className="info";d.style.borderBottom="1px solid var(--line)";d.innerHTML="<span class='il'>"+k+"</span><span>"+esc(v)+"</span>";b.appendChild(d)};
  row("文件名",im.filename||"—");row("类型",im.mime||(im.kind==="image"?"图片":"文件"));row("大小",fmtSize(im.bytes));row("上传时间",relTime(im.uploaded_at));
  var lk=document.createElement("div");lk.className="cval";var inp=document.createElement("input");inp.readOnly=true;inp.value=im.link;var cp=document.createElement("button");cp.className="sm";cp.textContent="复制";cp.onclick=function(){navigator.clipboard.writeText(im.link).then(function(){toast("已复制")})};lk.appendChild(inp);lk.appendChild(cp);b.appendChild(lk);show("detailOverlay");
}
function openRename(im){REN_IM=im;$("renameInput").value=im.filename||"";show("renameOverlay");setTimeout(function(){$("renameInput").focus()},50)}
function doRename(){if(!REN_IM)return;var nm=$("renameInput").value.trim();if(!nm)return toast("名字不能为空");api("/api/file/"+REN_IM.id+"/rename",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({filename:nm})}).then(function(r){REN_IM.filename=r.filename||nm;hide("renameOverlay");renderFiles();toast("已重命名")}).catch(function(e){toast(e.message)})}
function openMove(ids){var box=$("moveActs");box.innerHTML="";
  var add=function(label,albumId){var a=document.createElement("div");a.className="a";a.innerHTML="<span class='ai'>📁</span>"+esc(label);a.onclick=function(){doMove(ids,albumId)};box.appendChild(a)};
  add("未分组",null);ALBUMS.forEach(function(al){add(al.name+"（"+al.count+"）",al.id)});
  $("moveTitle").textContent="移动 "+ids.length+" 个到相册";show("moveOverlay");
}
function doMove(ids,albumId){var i=0;(function nx(){if(i>=ids.length){hide("moveOverlay");clearSel();reloadFiles();toast("已移动");return}api("/api/file/"+ids[i]+"/album",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({album_id:albumId})}).then(function(){i++;nx()}).catch(function(e){toast(e.message);i++;nx()})})()}
function delItems(ids){if(!ids.length)return;if(!confirm("删除选中的 "+ids.length+" 个文件？不可恢复。"))return;var i=0;(function nx(){if(i>=ids.length){clearSel();reloadFiles();toast("已删除");return}api("/api/file/"+ids[i],{method:"DELETE"}).then(function(){i++;nx()}).catch(function(e){toast(e.message);i++;nx()})})()}
function reloadFiles(){return Promise.all([loadFiles(),loadAlbums()]).then(function(){renderNav();renderFiles();loadMe();renderCatBars()})}
function newAlbum(){var name=prompt("相册名字");if(!name)return;api("/api/albums",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:name})}).then(function(){return loadAlbums()}).then(function(){renderNav();toast("已新建相册")}).catch(function(e){toast(e.message)})}
function delAlbum(id){if(!confirm("删除相册？里面的文件会变成未分组，不会删文件。"))return;api("/api/albums/"+id,{method:"DELETE"}).then(function(){return loadAlbums()}).then(function(){navTo({type:"all"})}).catch(function(e){toast(e.message)})}
function openSettings(){var b=$("setBody");b.innerHTML="";closeDrawer();
  api("/api/me").then(function(d){
    var row=function(k,v){var x=document.createElement("div");x.className="info";x.style.borderBottom="1px solid var(--line)";x.innerHTML="<span class='il'>"+k+"</span><span>"+esc(v)+"</span>";b.appendChild(x)};
    row("已用",fmtSize(d.usedBytes)+" / "+fmtSize(d.byteLimit));row("文件数",d.count);row("隐私","🔒 仅你可见");
    var links=document.createElement("div");links.className="muted";links.style.cssText="margin-top:14px;text-align:center";links.innerHTML="<a href='/privacy' target='_blank' style='color:var(--mut)'>隐私政策</a> · <a href='/terms' target='_blank' style='color:var(--mut)'>服务条款</a>";b.appendChild(links);
  }).catch(function(){});show("setOverlay");
}
var drop=$("drop"),fileInput=$("file");
drop.addEventListener("click",function(){fileInput.click()});
fileInput.addEventListener("change",function(){uploadFiles(fileInput.files);fileInput.value=""});
drop.addEventListener("dragover",function(e){e.preventDefault();drop.classList.add("on")});
drop.addEventListener("dragleave",function(){drop.classList.remove("on")});
drop.addEventListener("drop",function(e){e.preventDefault();drop.classList.remove("on");uploadFiles(e.dataTransfer.files)});
function makeThumb(file){return new Promise(function(res){if(String(file.type).indexOf("image/")!==0){res(null);return}var url=URL.createObjectURL(file),img=new Image();img.onload=function(){URL.revokeObjectURL(url);var d=400,sc=Math.min(1,d/Math.max(img.width,img.height)),w=Math.max(1,Math.round(img.width*sc)),h=Math.max(1,Math.round(img.height*sc));var cv=document.createElement("canvas");cv.width=w;cv.height=h;cv.getContext("2d").drawImage(img,0,0,w,h);cv.toBlob(function(b){res(b)},"image/jpeg",0.72)};img.onerror=function(){URL.revokeObjectURL(url);res(null)};img.src=url})}
function compressImage(file){return new Promise(function(res){if(String(file.type).indexOf("image/")!==0||file.type==="image/gif"){res(file);return}var url=URL.createObjectURL(file),img=new Image();img.onload=function(){URL.revokeObjectURL(url);var d=2560,sc=Math.min(1,d/Math.max(img.width,img.height)),w=Math.max(1,Math.round(img.width*sc)),h=Math.max(1,Math.round(img.height*sc));var cv=document.createElement("canvas");cv.width=w;cv.height=h;cv.getContext("2d").drawImage(img,0,0,w,h);cv.toBlob(function(b){if(!b||b.size>=file.size){res(file);return}var nm=file.name,dot=nm.lastIndexOf(".");res(new File([b],(dot>0?nm.slice(0,dot):nm)+".jpg",{type:"image/jpeg"}))},"image/jpeg",0.85)};img.onerror=function(){URL.revokeObjectURL(url);res(file)};img.src=url})}
function xhrUpload(file,thumb,albumId,onprog,ctrl){return new Promise(function(resolve,reject){if(ctrl&&ctrl.canceled)return reject(new Error("已取消"));var fd=new FormData();fd.append("file",file);if(thumb)fd.append("thumb",thumb,"t.jpg");if(albumId)fd.append("album_id",albumId);var x=new XMLHttpRequest();x.open("POST","/api/upload");x.setRequestHeader("authorization","Bearer "+TOKEN);if(ctrl){ctrl.abort=function(){try{x.abort()}catch(e){}}}x.upload.onprogress=function(e){if(e.lengthComputable&&onprog)onprog(e.loaded/e.total)};x.onload=function(){var d={};try{d=JSON.parse(x.responseText)}catch(e){}if(x.status>=200&&x.status<300)resolve(d);else{if(x.status===401)logout();reject(new Error(d.error||("HTTP "+x.status)))}};x.onerror=function(){reject(new Error("网络错误"))};x.onabort=function(){reject(new Error("已取消"))};x.send(fd)})}
function ctrlGate(ctrl){return new Promise(function(res,rej){(function chk(){if(ctrl&&ctrl.canceled)return rej(new Error("已取消"));if(!ctrl||!ctrl.paused)return res();setTimeout(chk,300)})()})}
function fileSig(f){return "cloud_mpu_"+encodeURIComponent(f.name)+"_"+f.size+"_"+(f.lastModified||0)}
function mpuSave(s,st){try{localStorage.setItem(s,JSON.stringify(st))}catch(e){}}
function mpuLoad(s){try{var v=localStorage.getItem(s);return v?JSON.parse(v):null}catch(e){return null}}
function mpuClear(s){try{localStorage.removeItem(s)}catch(e){}}
function multipartUpload(file,albumId,onprog,ctrl){var CHUNK=40*1024*1024,sig=fileSig(file),st=mpuLoad(sig),resumed=false;
  function ensure(){if(st&&st.uploadId&&st.key&&st.chunk===CHUNK&&Array.isArray(st.parts)){resumed=true;return Promise.resolve()}return api("/api/mpu/create",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({filename:file.name,mime:file.type||"application/octet-stream",size:file.size,album_id:albumId})}).then(function(init){st={key:init.key,uploadId:init.uploadId,chunk:CHUNK,parts:[]};mpuSave(sig,st)})}
  return ensure().then(function(){var total=Math.ceil(file.size/CHUNK),done={};st.parts.forEach(function(p){done[p.part]=true});
    function rb(){if(onprog)onprog(Math.min(1,(st.parts.length*CHUNK)/file.size))}rb();
    function up(n,at){return new Promise(function(res,rej){var start=(n-1)*CHUNK,ch=file.slice(start,Math.min(file.size,start+CHUNK));var x=new XMLHttpRequest();x.open("POST","/api/mpu/part?key="+encodeURIComponent(st.key)+"&uploadId="+encodeURIComponent(st.uploadId)+"&part="+n);x.setRequestHeader("authorization","Bearer "+TOKEN);if(ctrl){ctrl.abort=function(){try{x.abort()}catch(e){}}}x.upload.onprogress=function(e){if(e.lengthComputable&&onprog){var base=st.parts.length*CHUNK;onprog(Math.min(1,(base+e.loaded)/file.size))}};x.onload=function(){var d={};try{d=JSON.parse(x.responseText)}catch(e){}if(x.status>=200&&x.status<300){st.parts.push({part:d.part,etag:d.etag});mpuSave(sig,st);rb();res()}else{if(x.status===401)logout();rej(new Error(d.error||("分片"+n+"失败")))}};x.onerror=function(){rej(new Error("网络中断"))};x.onabort=function(){rej(new Error("已取消"))};x.send(ch)}).catch(function(e){if(ctrl&&ctrl.canceled)throw new Error("已取消");if(at<3)return new Promise(function(r){setTimeout(r,900*at)}).then(function(){return up(n,at+1)});throw e})}
    function loop(n){if(n>total)return Promise.resolve();if(done[n])return loop(n+1);return ctrlGate(ctrl).then(function(){return up(n,1)}).then(function(){return loop(n+1)})}
    return loop(1).catch(function(e){if(ctrl&&ctrl.canceled)mpuClear(sig);throw e});
  }).then(function(){return api("/api/mpu/complete",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({key:st.key,uploadId:st.uploadId,parts:st.parts,filename:file.name,mime:file.type||"application/octet-stream",size:file.size,album_id:albumId})})}).then(function(r){mpuClear(sig);return r});
}
function uploadFiles(files){files=Array.prototype.slice.call(files||[]);if(!files.length)return;navTo({view:"upload"});var pc=$("progress");pc.classList.remove("hide");pc.innerHTML="";var doCompress=$("cmp").checked,albumId=(NAV.album!=null&&NAV.type==null)?NAV.album:null,done=0,fail=0,canceled=0;
  var runOne=function(i){if(i>=files.length){toast("完成 "+done+" 个"+(fail?("，失败 "+fail):"")+(canceled?("，取消 "+canceled):""));reloadFiles();setTimeout(function(){if(!fail&&!canceled)pc.classList.add("hide")},1600);return}
    var f=files[i],ctrl={canceled:false,paused:false,abort:null};
    var item=document.createElement("div");item.className="pitem";item.innerHTML="<div class='pn'><span>"+esc(f.name)+"</span><span class='pct'>0%</span></div><div class='pbar'><i></i></div><div class='pacts'></div>";pc.appendChild(item);
    var bar=item.querySelector("i"),pct=item.querySelector(".pct"),acts=item.querySelector(".pacts");
    var cancelBtn=document.createElement("button");cancelBtn.className="pbtn del";cancelBtn.textContent="✕ 取消";cancelBtn.onclick=function(){ctrl.canceled=true;if(ctrl.abort)ctrl.abort()};acts.appendChild(cancelBtn);
    (doCompress?compressImage(f):Promise.resolve(f)).then(function(uf){if(ctrl.canceled)throw new Error("已取消");
      var prog=function(p){if(ctrl.paused)return;var v=Math.round(p*100);bar.style.width=v+"%";pct.textContent=v+"%"};var big=uf.size>90*1024*1024;
      if(big){var pauseBtn=document.createElement("button");pauseBtn.className="pbtn";pauseBtn.textContent="⏸ 暂停";pauseBtn.onclick=function(){ctrl.paused=!ctrl.paused;pauseBtn.textContent=ctrl.paused?"▶ 继续":"⏸ 暂停";item.classList.toggle("paused",ctrl.paused);if(ctrl.paused)pct.textContent="已暂停"};acts.insertBefore(pauseBtn,cancelBtn);return multipartUpload(uf,albumId,prog,ctrl)}
      return makeThumb(uf).then(function(th){return xhrUpload(uf,th,albumId,prog,ctrl)});
    }).then(function(){done++;item.classList.add("done");pct.textContent="完成";acts.innerHTML=""}).catch(function(e){if(ctrl.canceled||/已取消/.test(e.message||"")){canceled++;item.classList.add("canceled");pct.textContent="已取消";acts.innerHTML=""}else{fail++;item.classList.add("err");pct.textContent=e.message;acts.innerHTML=""}}).then(function(){runOne(i+1)});
  };toast("上传中…");runOne(0);
}
function openLightbox(im){var imgs=currentList().filter(function(x){return x.kind==="image"});LB=imgs;LBI=0;for(var k=0;k<LB.length;k++){if(LB[k].id===im.id){LBI=k;break}}if(!LB.length)return;$("lbImg").src=LB[LBI].link;show("lightbox")}
function openLightboxAll(im){var imgs=ALLFILES.filter(function(x){return x.kind==="image"});LB=imgs;LBI=0;for(var k=0;k<LB.length;k++){if(LB[k].id===im.id){LBI=k;break}}if(!LB.length)return;$("lbImg").src=LB[LBI].link;show("lightbox")}
function lbNav(d){if(!LB.length)return;LBI=(LBI+d+LB.length)%LB.length;$("lbImg").src=LB[LBI].link}
$("lbClose").onclick=function(){hide("lightbox")};$("lbPrev").onclick=function(){lbNav(-1)};$("lbNext").onclick=function(){lbNav(1)};
$("lightbox").addEventListener("click",function(e){if(e.target.id==="lightbox")hide("lightbox")});
function closeOverlays(){var ov=document.querySelectorAll(".overlay");for(var i=0;i<ov.length;i++)ov[i].classList.remove("show")}
["menuOverlay","detailOverlay","renameOverlay","moveOverlay","setOverlay"].forEach(function(id){$(id).addEventListener("click",function(e){if(e.target===this)this.classList.remove("show")})});
$("dClose").onclick=function(){hide("detailOverlay")};$("renCancel").onclick=function(){hide("renameOverlay")};$("renSave").onclick=doRename;
$("renameInput").addEventListener("keydown",function(e){if(e.key==="Enter")doRename()});
$("moveCancel").onclick=function(){hide("moveOverlay")};$("setClose").onclick=function(){hide("setOverlay")};$("setLogout").onclick=function(){hide("setOverlay");logout()};
$("goUpload").addEventListener("click",function(){navTo({view:"upload"})});$("recMore").addEventListener("click",function(){navTo({type:"all"})});
$("logoutBtn").addEventListener("click",logout);$("delAlbumBtn").addEventListener("click",function(){if(NAV.album!=null)delAlbum(NAV.album)});
$("q").addEventListener("input",function(){Q=this.value;renderFiles()});$("sort").addEventListener("change",function(){SORT=this.value;renderFiles()});
$("bDown").onclick=downloadSel;$("bDel").onclick=function(){delItems(selIds())};$("bCancel").onclick=clearSel;
$("burger").addEventListener("click",openDrawer);$("sideClose").addEventListener("click",closeDrawer);$("scrim").addEventListener("click",closeDrawer);
function openDrawer(){$("side").classList.add("open");$("scrim").classList.add("show")}function closeDrawer(){$("side").classList.remove("open");$("scrim").classList.remove("show")}
document.addEventListener("keydown",function(e){if($("lightbox").classList.contains("show")){if(e.key==="Escape")hide("lightbox");else if(e.key==="ArrowLeft")lbNav(-1);else if(e.key==="ArrowRight")lbNav(1);return}if($("appShell").classList.contains("hide"))return;var inField=/INPUT|TEXTAREA|SELECT/.test((document.activeElement||{}).tagName||"");if(e.key==="Escape"){clearSel();closeOverlays();closeDrawer();return}if(VIEW!=="files"||inField)return;if(e.key==="Delete"&&selIds().length)delItems(selIds());else if((e.ctrlKey||e.metaKey)&&(e.key==="a"||e.key==="A")){e.preventDefault();currentList().forEach(function(x){SEL[x.id]=true});updateSelUI()}});
document.addEventListener("paste",function(e){if($("appShell").classList.contains("hide"))return;var items=(e.clipboardData||{}).items||[],fs=[];for(var i=0;i<items.length;i++){if(items[i].kind==="file"){var f=items[i].getAsFile();if(f)fs.push(f)}}if(fs.length)uploadFiles(fs)});
if(TOKEN)enterApp();
</script></body></html>`;

/* ---------- 信任页：隐私政策 / 服务条款 ---------- */
function legalDoc(env, title, bodyHtml) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} · ${brandName(env)}</title><style>
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#080910;color:#c3cad6;line-height:1.75;max-width:760px;margin:0 auto;padding:40px 22px 80px}
h1{color:#EEF1F7;font-size:1.5rem;margin:6px 0}h2{color:#c9beff;font-size:1.05rem;margin:24px 0 8px}a{color:#a78bfa;text-decoration:none}ul{margin:6px 0 6px 20px}
.foot{margin-top:40px;padding-top:18px;border-top:1px solid rgba(255,255,255,.08);color:#8A93A6;font-size:.85rem}
</style></head><body><h1>${brandName(env)} · ${title}</h1>${bodyHtml}
<div class="foot"><a href="/">← 返回</a> · <a href="/privacy">隐私政策</a> · <a href="/terms">服务条款</a></div></body></html>`;
}
function privacyHtml(env) {
  return legalDoc(env, "隐私政策", `
<p>这是一套部署在你自己 Cloudflare 账号里的私人云盘。文件与元数据全部存放在你的账号中，运营方不持有、不访问。</p>
<h2>存放什么</h2><ul><li>你上传的文件（存于你账号的 R2）</li><li>文件名/大小/类型/相册等元数据，以及登录密码的哈希值（不保存明文）</li></ul>
<h2>是否公开</h2><ul><li>文件不列入任何公开目录、不被搜索到</li><li>分享直链带不可枚举的签名令牌；删除即真删</li></ul>
<h2>Cookie</h2><p>不使用第三方追踪。登录令牌仅存于浏览器 sessionStorage。</p>`);
}
function termsHtml(env) {
  return legalDoc(env, "服务条款", `
<p>本软件按“现状”提供，部署与数据均在你自己的 Cloudflare 账号中，请遵守 Cloudflare 服务条款及所在地法律。</p>
<h2>使用</h2><ul><li>不得存储或分发违法内容</li><li>容量与账单由你的 Cloudflare 账号决定；默认容量压在免费额度内，超出部分按 Cloudflare 价格由你承担</li></ul>
<h2>责任</h2><p>对不可抗力或第三方基础设施故障导致的损失不承担责任，重要文件请自行额外备份。</p>`);
}
