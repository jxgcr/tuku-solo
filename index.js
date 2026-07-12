// 图床 tuku Worker — 多租户图片托管 SaaS
// 账号 Hannah；图片存 Cloudflare Images；元数据存 D1(DB)；卡密来自畅密(changmi)
// 机密(wrangler secret)：CF_IMAGES_TOKEN、SESSION_SECRET、APP_KEY_TU_BASIC、APP_KEY_TU_PRO
const VERSION = "tuku-v1-20260712";
const MAX_SIZE = 10 * 1024 * 1024; // CF Images 图片单张上限 10MB
const MAX_FILE = 100 * 1024 * 1024; // 非图片单文件上限 100MB（更大走直传，二期再说）
const GB = 1073741824;
const DEFAULT_SESSION_TTL = 7 * 24 * 3600;
// 档位：容量上限（字节）。价格是运营侧的事，这里只管容量闸。改档位改这里重新部署。
const TIERS = {
  basic: { byteLimit: 5 * GB, label: "存链-基础" },
  pro: { byteLimit: 50 * GB, label: "存链-专业" },
};
function fmtGB(b) { const g = Number(b) / GB; return (g >= 10 || g === Math.floor(g) ? g.toFixed(0) : g.toFixed(1)) + "GB"; }
function safeName(n) { return String(n || "file").replace(/[^\w.\-]/g, "_").slice(-80) || "file"; }

/* ---------- 基础工具 ---------- */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
function htmlResponse(body) {
  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://imagedelivery.net; connect-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'",
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
function b64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
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

/* ---------- 密码哈希（PBKDF2-SHA256，Worker 原生） ---------- */
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iter = 100000;
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, keyMaterial, 256);
  return "pbkdf2$" + iter + "$" + b64u(salt) + "$" + b64u(new Uint8Array(bits));
}
async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith("pbkdf2$")) return false;
  const [, iterStr, saltB, hashB] = stored.split("$");
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: b64uToBytes(saltB), iterations: Number(iterStr), hash: "SHA-256" }, keyMaterial, 256);
  return ctEqual(new Uint8Array(bits), b64uToBytes(hashB));
}

/* ---------- 会话（HMAC，负载含客户 id + 卡号） ---------- */
async function signSession(env, cid, card) {
  const ttl = envNumber(env, "SESSION_TTL_SECONDS", DEFAULT_SESSION_TTL);
  const now = Math.floor(Date.now() / 1000);
  const payload = { cid, card, iat: now, exp: now + ttl };
  const body = b64u(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = b64u(await hmac(env.SESSION_SECRET, body));
  return body + "." + sig;
}
async function verifySession(env, token) {
  if (!token || !env.SESSION_SECRET) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const expected = b64u(await hmac(env.SESSION_SECRET, parts[0]));
  if (!ctEqual(expected, parts[1])) return null;
  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(b64uToBytes(parts[0]))); } catch { return null; }
  if (!payload || Number(payload.exp) <= Math.floor(Date.now() / 1000)) return null;
  return payload;
}
function bearer(request) {
  const h = request.headers.get("authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

/* ---------- CF Images / 畅密 ---------- */
function imagesBase(env) {
  return "https://api.cloudflare.com/client/v4/accounts/" + (env.ACCOUNT_ID) + "/images/v1";
}
async function imagesApi(env, path, init = {}) {
  const headers = { authorization: "Bearer " + env.CF_IMAGES_TOKEN, ...(init.headers || {}) };
  const res = await fetch(imagesBase(env) + path, { ...init, headers });
  const data = await res.json().catch(() => ({ success: false, errors: [{ message: "Images API invalid JSON" }] }));
  if (!res.ok && data.success !== false) data.success = false;
  return data;
}
// 调畅密验卡：返回 { valid, status, expires_at?, duration_days? }
async function changmiVerify(env, card, appKey) {
  if (!appKey) return { valid: false, status: 0 };
  const res = await fetch(env.CHANGMI_URL.replace(/\/+$/, "") + "/api/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code: card, app_key: appKey }),
  });
  const data = await res.json().catch(() => ({}));
  return { valid: res.ok && data.valid === true, status: res.status, expires_at: data.expires_at, duration_days: data.duration_days };
}

/* ---------- 客户（D1） ---------- */
function normCard(v) {
  return String(v || "").trim().toUpperCase();
}
async function getCustomerByCard(env, card) {
  return await env.DB.prepare("SELECT * FROM customers WHERE card=?").bind(card).first();
}
async function countImages(env, cid) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM images WHERE customer_id=?").bind(cid).first();
  return Number(r?.n || 0);
}
async function usedBytesOf(env, cid) {
  const r = await env.DB.prepare("SELECT COALESCE(SUM(bytes),0) AS b FROM images WHERE customer_id=?").bind(cid).first();
  return Number(r?.b || 0);
}
function customerActive(c) {
  if (!c || c.status !== "active") return false;
  if (c.expires_at && Number(c.expires_at) <= Math.floor(Date.now() / 1000)) return false;
  return true;
}

/* ---------- 登录鉴权中间件 ---------- */
async function requireCustomer(request, env) {
  const s = await verifySession(env, bearer(request));
  if (!s) return { error: json({ error: "未登录" }, 401) };
  const c = await env.DB.prepare("SELECT * FROM customers WHERE id=?").bind(s.cid).first();
  if (!customerActive(c)) return { error: json({ error: "账号已停用或到期" }, 403) };
  return { customer: c };
}

/* ---------- 登录 / 开通（一体） ---------- */
async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const card = normCard(body.card);
  const password = String(body.password || "");
  if (!card || !password) return json({ error: "请输入卡号和密码" }, 400);
  if (password.length < 4) return json({ error: "密码至少 4 位" }, 400);

  const existing = await getCustomerByCard(env, card);
  if (existing) {
    if (!customerActive(existing)) return json({ error: "账号已停用或到期" }, 403);
    if (!(await verifyPassword(password, existing.password_hash))) return json({ error: "密码不正确" }, 401);
    const token = await signSession(env, existing.id, card);
    return json({ ok: true, token, tier: existing.tier });
  }

  // 首次：验卡开通（逐档试，畅密对不匹配的 app_key 返回 404）
  let tier = null, expiresAt = null;
  const basic = await changmiVerify(env, card, env.APP_KEY_TU_BASIC);
  if (basic.valid) { tier = "basic"; expiresAt = basic.expires_at || null; }
  else if (basic.status !== 404 && basic.status !== 0) return json({ error: "卡密无效" }, 400);
  else {
    const pro = await changmiVerify(env, card, env.APP_KEY_TU_PRO);
    if (pro.valid) { tier = "pro"; expiresAt = pro.expires_at || null; }
    else return json({ error: "卡密无效" }, 400);
  }

  const preset = TIERS[tier];
  const now = Math.floor(Date.now() / 1000);
  const pwHash = await hashPassword(password);
  const ins = await env.DB.prepare(
    "INSERT INTO customers (card, tier, password_hash, img_limit, byte_limit, expires_at, status, created_at) VALUES (?,?,?,?,?,?,'active',?)"
  ).bind(card, tier, pwHash, 9999999, preset.byteLimit, expiresAt, now).run();
  const cid = ins.meta.last_row_id;
  const token = await signSession(env, cid, card);
  return json({ ok: true, token, tier, firstTime: true });
}

/* ---------- 上传 ---------- */
async function handleUpload(request, env, customer) {
  const form = await request.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") return json({ error: "缺少文件" }, 400);
  const isImage = String(file.type || "").startsWith("image/");
  if (isImage && file.size > MAX_SIZE) return json({ error: "图片单张超过 10MB" }, 413);
  if (!isImage && file.size > MAX_FILE) return json({ error: "单个文件超过 100MB 上限" }, 413);

  const usedBytes = await usedBytesOf(env, customer.id);
  if (usedBytes + file.size > customer.byte_limit) {
    return json({ error: "容量不足（上限 " + fmtGB(customer.byte_limit) + "，已用 " + fmtGB(usedBytes) + "），请删文件或升级" }, 402);
  }

  let albumId = Number(form.get("album_id")) || null;
  if (albumId) {
    const a = await env.DB.prepare("SELECT id FROM albums WHERE id=? AND customer_id=?").bind(albumId, customer.id).first();
    if (!a) albumId = null;
  }
  const now = Math.floor(Date.now() / 1000);

  if (isImage) {
    const fd = new FormData();
    fd.append("file", file, file.name || "upload.png");
    fd.append("requireSignedURLs", "false");
    fd.append("metadata", JSON.stringify({ owner: String(customer.id) }));
    const data = await imagesApi(env, "", { method: "POST", body: fd });
    if (!data.success) return json({ error: (data.errors && data.errors[0] && data.errors[0].message) || "图片上传失败" }, 502);
    const cfId = data.result.id;
    const ins = await env.DB.prepare(
      "INSERT INTO images (customer_id, album_id, kind, cf_id, filename, mime, bytes, uploaded_at) VALUES (?,?,'image',?,?,?,?,?)"
    ).bind(customer.id, albumId, cfId, file.name || "", file.type || "image/*", file.size, now).run();
    return json({
      ok: true, id: ins.meta.last_row_id, kind: "image",
      link: (env.PUBLIC_BASE || "") + "/i/" + cfId,
      thumb: "https://imagedelivery.net/" + env.IMAGES_HASH + "/" + cfId + "/public",
    });
  }

  // 非图片 → R2
  const key = customer.id + "/" + crypto.randomUUID() + "-" + safeName(file.name);
  try {
    const buf = await file.arrayBuffer();
    await env.R2.put(key, buf, { httpMetadata: { contentType: file.type || "application/octet-stream" } });
    const ins = await env.DB.prepare(
      "INSERT INTO images (customer_id, album_id, kind, cf_id, r2_key, filename, mime, bytes, uploaded_at) VALUES (?,?,'file','',?,?,?,?,?)"
    ).bind(customer.id, albumId, key, file.name || "file", file.type || "application/octet-stream", file.size, now).run();
    return json({
      ok: true, id: ins.meta.last_row_id, kind: "file", filename: file.name || "file",
      link: (env.PUBLIC_BASE || "") + "/f/" + ins.meta.last_row_id,
    });
  } catch (e) {
    console.log("file upload fail: " + (e && e.message ? e.message : e));
    return json({ error: "文件上传失败，请稍后重试" }, 502);
  }
}

/* ---------- 大文件分片上传（R2 multipart，绕过 Worker 100MB 限制） ---------- */
async function handleMpuCreate(request, env, customer) {
  const body = await request.json().catch(() => ({}));
  const size = Number(body.size) || 0;
  if (size <= 0) return json({ error: "缺少文件大小" }, 400);
  if (size > 5 * 1024 * 1024 * 1024) return json({ error: "单个文件超过 5GB 上限" }, 413);
  const usedBytes = await usedBytesOf(env, customer.id);
  if (usedBytes + size > customer.byte_limit) return json({ error: "容量不足（上限 " + fmtGB(customer.byte_limit) + "，已用 " + fmtGB(usedBytes) + "）" }, 402);
  const key = customer.id + "/" + crypto.randomUUID() + "-" + safeName(body.filename);
  const mpu = await env.R2.createMultipartUpload(key, { httpMetadata: { contentType: body.mime || "application/octet-stream" } });
  return json({ ok: true, key, uploadId: mpu.uploadId });
}
async function handleMpuPart(request, env, customer, url) {
  const key = url.searchParams.get("key") || "";
  const uploadId = url.searchParams.get("uploadId") || "";
  const partNum = Number(url.searchParams.get("part")) || 0;
  if (!key.startsWith(customer.id + "/") || !uploadId || partNum < 1) return json({ error: "参数错误" }, 400);
  try {
    const mpu = env.R2.resumeMultipartUpload(key, uploadId);
    const buf = await request.arrayBuffer();
    const part = await mpu.uploadPart(partNum, buf);
    return json({ ok: true, part: part.partNumber, etag: part.etag });
  } catch (e) {
    console.log("mpu part fail: " + (e && e.message ? e.message : e));
    return json({ error: "分片上传失败" }, 502);
  }
}
async function handleMpuComplete(request, env, customer) {
  const body = await request.json().catch(() => ({}));
  const key = String(body.key || "");
  const uploadId = String(body.uploadId || "");
  if (!key.startsWith(customer.id + "/") || !uploadId) return json({ error: "参数错误" }, 400);
  const parts = (Array.isArray(body.parts) ? body.parts : []).map((p) => ({ partNumber: Number(p.part || p.partNumber), etag: p.etag }));
  if (!parts.length) return json({ error: "没有分片" }, 400);
  try {
    const mpu = env.R2.resumeMultipartUpload(key, uploadId);
    await mpu.complete(parts);
  } catch (e) {
    console.log("mpu complete fail: " + (e && e.message ? e.message : e));
    return json({ error: "合并失败，请重试" }, 502);
  }
  let albumId = Number(body.album_id) || null;
  if (albumId) {
    const a = await env.DB.prepare("SELECT id FROM albums WHERE id=? AND customer_id=?").bind(albumId, customer.id).first();
    if (!a) albumId = null;
  }
  const now = Math.floor(Date.now() / 1000);
  const ins = await env.DB.prepare(
    "INSERT INTO images (customer_id, album_id, kind, cf_id, r2_key, filename, mime, bytes, uploaded_at) VALUES (?,?,'file','',?,?,?,?,?)"
  ).bind(customer.id, albumId, key, String(body.filename || "file"), String(body.mime || "application/octet-stream"), Number(body.size) || 0, now).run();
  return json({ ok: true, id: ins.meta.last_row_id, kind: "file", link: (env.PUBLIC_BASE || "") + "/f/" + ins.meta.last_row_id });
}

/* ---------- 列表 / 删除 / 相册 ---------- */
async function handleList(request, env, customer, url) {
  const albumParam = url.searchParams.get("album_id");
  let rows;
  if (albumParam === "none") {
    rows = await env.DB.prepare("SELECT * FROM images WHERE customer_id=? AND album_id IS NULL ORDER BY id DESC LIMIT 500").bind(customer.id).all();
  } else if (albumParam) {
    rows = await env.DB.prepare("SELECT * FROM images WHERE customer_id=? AND album_id=? ORDER BY id DESC LIMIT 500").bind(customer.id, Number(albumParam)).all();
  } else {
    rows = await env.DB.prepare("SELECT * FROM images WHERE customer_id=? ORDER BY id DESC LIMIT 500").bind(customer.id).all();
  }
  const images = (rows.results || []).map((im) => {
    const isImage = im.kind !== "file";
    return {
      id: im.id, kind: isImage ? "image" : "file", filename: im.filename, mime: im.mime, bytes: im.bytes,
      album_id: im.album_id, uploaded_at: im.uploaded_at,
      link: isImage ? (env.PUBLIC_BASE || "") + "/i/" + im.cf_id : (env.PUBLIC_BASE || "") + "/f/" + im.id,
      thumb: isImage ? "https://imagedelivery.net/" + env.IMAGES_HASH + "/" + im.cf_id + "/public" : null,
    };
  });
  return json({ images });
}
async function handleDeleteImg(request, env, customer, id) {
  const row = await env.DB.prepare("SELECT * FROM images WHERE id=? AND customer_id=?").bind(id, customer.id).first();
  if (!row) return json({ error: "文件不存在" }, 404);
  if (row.kind === "file" && row.r2_key) await env.R2.delete(row.r2_key);
  else if (row.cf_id) await imagesApi(env, "/" + encodeURIComponent(row.cf_id), { method: "DELETE" });
  await env.DB.prepare("DELETE FROM images WHERE id=?").bind(id).run();
  return json({ ok: true });
}
async function handleAlbums(request, env, customer) {
  const rows = await env.DB.prepare(
    "SELECT a.id, a.name, a.created_at, (SELECT COUNT(*) FROM images i WHERE i.album_id=a.id) AS count FROM albums a WHERE a.customer_id=? ORDER BY a.id DESC"
  ).bind(customer.id).all();
  return json({ albums: rows.results || [] });
}
async function handleCreateAlbum(request, env, customer) {
  const body = await request.json().catch(() => ({}));
  const name = String(body.name || "").trim().slice(0, 40);
  if (!name) return json({ error: "请输入相册名" }, 400);
  const now = Math.floor(Date.now() / 1000);
  const ins = await env.DB.prepare("INSERT INTO albums (customer_id, name, created_at) VALUES (?,?,?)").bind(customer.id, name, now).run();
  return json({ ok: true, id: ins.meta.last_row_id, name });
}
async function handleDeleteAlbum(request, env, customer, id) {
  const a = await env.DB.prepare("SELECT id FROM albums WHERE id=? AND customer_id=?").bind(id, customer.id).first();
  if (!a) return json({ error: "相册不存在" }, 404);
  await env.DB.prepare("UPDATE images SET album_id=NULL WHERE album_id=? AND customer_id=?").bind(id, customer.id).run();
  await env.DB.prepare("DELETE FROM albums WHERE id=?").bind(id).run();
  return json({ ok: true });
}
async function handleMoveImg(request, env, customer, id) {
  const body = await request.json().catch(() => ({}));
  let albumId = body.album_id === null || body.album_id === 0 ? null : Number(body.album_id);
  if (albumId) {
    const a = await env.DB.prepare("SELECT id FROM albums WHERE id=? AND customer_id=?").bind(albumId, customer.id).first();
    if (!a) return json({ error: "相册不存在" }, 404);
  }
  const r = await env.DB.prepare("UPDATE images SET album_id=? WHERE id=? AND customer_id=?").bind(albumId, id, customer.id).run();
  if (!r.meta.changes) return json({ error: "图片不存在" }, 404);
  return json({ ok: true });
}
async function handleRenameImg(request, env, customer, id) {
  const body = await request.json().catch(() => ({}));
  let name = String(body.filename || "").trim().replace(/[\r\n\t]/g, "").slice(0, 120);
  if (!name) return json({ error: "名字不能为空" }, 400);
  const r = await env.DB.prepare("UPDATE images SET filename=? WHERE id=? AND customer_id=?").bind(name, id, customer.id).run();
  if (!r.meta.changes) return json({ error: "文件不存在" }, 404);
  return json({ ok: true, filename: name });
}
async function handleMe(request, env, customer) {
  const count = await countImages(env, customer.id);
  const usedBytes = await usedBytesOf(env, customer.id);
  return json({
    card: customer.card, tier: customer.tier, tierLabel: (TIERS[customer.tier] || {}).label || customer.tier,
    count, usedBytes, byteLimit: customer.byte_limit, usedGB: fmtGB(usedBytes), limitGB: fmtGB(customer.byte_limit),
    expiresAt: customer.expires_at ? new Date(customer.expires_at * 1000).toISOString() : null,
  });
}

/* ---------- 图片直链 /i/:cf_id（公开，代理 imagedelivery，隐藏账户哈希 + 缓存） ---------- */
async function serveImage(request, env, cfId) {
  const variant = new URL(request.url).searchParams.get("v") === "thumb" ? "public" : "public";
  const cacheKey = new Request(new URL(request.url).origin + "/i/" + cfId, request);
  const cached = await caches.default.match(cacheKey);
  if (cached) return cached;
  const src = "https://imagedelivery.net/" + env.IMAGES_HASH + "/" + encodeURIComponent(cfId) + "/" + variant;
  const res = await fetch(src, { cf: { cacheEverything: true, cacheTtl: 86400 } });
  if (!res.ok) return new Response("Not Found", { status: 404 });
  const out = new Response(res.body, res);
  out.headers.set("cache-control", "public, max-age=86400");
  out.headers.set("x-content-type-options", "nosniff");
  request.__ctx && request.__ctx.waitUntil(caches.default.put(cacheKey, out.clone()));
  return out;
}

/* ---------- 文件直链 /f/:id（公开，R2；支持 Range 让视频/音频可拖动播放） ---------- */
async function serveFile(request, env, id) {
  const row = await env.DB.prepare("SELECT r2_key, filename, mime FROM images WHERE id=? AND kind='file'").bind(id).first();
  if (!row || !row.r2_key) return new Response("Not Found", { status: 404 });
  const hasRange = !!request.headers.get("range");
  const obj = await env.R2.get(row.r2_key, hasRange ? { range: request.headers } : undefined);
  if (!obj) return new Response("Not Found", { status: 404 });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  if (obj.httpEtag) headers.set("etag", obj.httpEtag);
  headers.set("content-type", row.mime || headers.get("content-type") || "application/octet-stream");
  headers.set("cache-control", "public, max-age=3600");
  headers.set("accept-ranges", "bytes");
  if (new URL(request.url).searchParams.get("dl")) headers.set("content-disposition", "attachment; filename*=UTF-8''" + encodeURIComponent(row.filename || "file"));
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

/* ---------- 运营管理（页面 /scfw，API /api/admin，ADMIN_KEY 鉴权，带暴破锁） ---------- */
function requireAdmin(request, env) {
  const supplied = request.headers.get("x-admin-key") || "";
  return !!env.ADMIN_KEY && ctEqual(supplied, env.ADMIN_KEY);
}
async function adminGate(request, env) {
  const lim = limiter(env, "admin:" + clientIp(request));
  const max = envNumber(env, "AUTH_MAX_FAILURES", 8), lock = envNumber(env, "AUTH_LOCK_SECONDS", 900);
  if (lim) {
    const c = await (await lim.fetch("https://do/check?max=" + max + "&lock=" + lock)).json();
    if (c.locked) return { error: json({ error: "尝试过于频繁，请稍后再试" }, 429) };
  }
  if (!requireAdmin(request, env)) {
    if (lim) await lim.fetch("https://do/fail?max=" + max + "&lock=" + lock);
    return { error: json({ error: "管理密钥不正确" }, 401) };
  }
  if (lim) await lim.fetch("https://do/reset");
  return { ok: true };
}
async function handleAdminList(env) {
  const rows = await env.DB.prepare(
    "SELECT c.id, c.card, c.tier, c.byte_limit, c.expires_at, c.status, c.created_at, " +
    "COALESCE((SELECT SUM(bytes) FROM images i WHERE i.customer_id=c.id),0) AS used_bytes, " +
    "(SELECT COUNT(*) FROM images i WHERE i.customer_id=c.id) AS files FROM customers c ORDER BY c.id DESC"
  ).all();
  const customers = (rows.results || []).map((c) => ({
    id: c.id, card: c.card, tier: c.tier, tierLabel: (TIERS[c.tier] || {}).label || c.tier,
    byteLimit: c.byte_limit, usedBytes: c.used_bytes, files: c.files,
    usedGB: fmtGB(c.used_bytes || 0), limitGB: fmtGB(c.byte_limit || 0),
    expiresAt: c.expires_at ? new Date(c.expires_at * 1000).toISOString() : null,
    status: c.status, createdAt: c.created_at ? new Date(c.created_at * 1000).toISOString() : null,
  }));
  const totalBytes = customers.reduce((s, c) => s + Number(c.usedBytes || 0), 0);
  const stats = {
    total: customers.length,
    active: customers.filter((c) => c.status === "active").length,
    totalFiles: customers.reduce((s, c) => s + Number(c.files || 0), 0),
    totalGB: fmtGB(totalBytes),
  };
  return json({ customers, stats });
}
async function handleAdminUpdate(env, id, body) {
  const sets = [], binds = [];
  if (body.status === "active" || body.status === "disabled") { sets.push("status=?"); binds.push(body.status); }
  if (body.tier && TIERS[body.tier]) { sets.push("tier=?", "byte_limit=?"); binds.push(body.tier, TIERS[body.tier].byteLimit); }
  if (body.byteLimit != null && Number.isFinite(Number(body.byteLimit))) { sets.push("byte_limit=?"); binds.push(Number(body.byteLimit)); }
  if (body.expiresAt !== undefined) { sets.push("expires_at=?"); binds.push(body.expiresAt ? Math.floor(new Date(body.expiresAt).getTime() / 1000) : null); }
  if (!sets.length) return json({ error: "没有要改的项" }, 400);
  binds.push(id);
  await env.DB.prepare("UPDATE customers SET " + sets.join(",") + " WHERE id=?").bind(...binds).run();
  return json({ ok: true });
}
async function handleAdminDelete(env, id) {
  const files = await env.DB.prepare("SELECT cf_id, r2_key, kind FROM images WHERE customer_id=?").bind(id).all();
  for (const f of (files.results || [])) {
    try {
      if (f.kind === "file" && f.r2_key) await env.R2.delete(f.r2_key);
      else if (f.cf_id) await imagesApi(env, "/" + encodeURIComponent(f.cf_id), { method: "DELETE" });
    } catch (e) { /* 尽力删，不阻断 */ }
  }
  await env.DB.prepare("DELETE FROM images WHERE customer_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM albums WHERE customer_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM customers WHERE id=?").bind(id).run();
  return json({ ok: true });
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
    if (url.pathname === "/check") {
      const locked = rec.until > now;
      return json({ locked, retryIn: locked ? rec.until - now : 0 });
    }
    if (url.pathname === "/fail") {
      rec.fails = (rec.until > now ? rec.fails : 0) + 1;
      if (rec.fails >= max) rec.until = now + lock;
      await this.state.storage.put("rec", rec);
      return json({ ok: true, fails: rec.fails });
    }
    if (url.pathname === "/reset") {
      await this.state.storage.put("rec", { fails: 0, until: 0 });
      return json({ ok: true });
    }
    return json({ error: "bad" }, 400);
  }
}
function limiter(env, name) {
  if (!env.AUTH_LIMITER) return null;
  return env.AUTH_LIMITER.get(env.AUTH_LIMITER.idFromName(name));
}

/* ---------- 入口 ---------- */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    request.__ctx = ctx;

    if (path === "/health") return json({ ok: true, service: "tuku", version: VERSION });
    if (path === "/" || path === "/index.html") return htmlResponse(PAGE_HTML);
    if (path === "/scfw") return htmlResponse(ADMIN_HTML);

    // 图片直链（公开）
    const im = path.match(/^\/i\/([A-Za-z0-9_-]+)$/);
    if (im) return serveImage(request, env, im[1]);
    // 文件直链（公开，R2）
    const fm = path.match(/^\/f\/(\d+)$/);
    if (fm) return serveFile(request, env, Number(fm[1]));

    try {
      // 登录/开通：带暴破锁
      if (request.method === "POST" && path === "/api/login") {
        const ip = clientIp(request);
        const lim = limiter(env, "login:" + ip);
        if (lim) {
          const c = await (await lim.fetch("https://do/check?max=" + envNumber(env, "AUTH_MAX_FAILURES", 8) + "&lock=" + envNumber(env, "AUTH_LOCK_SECONDS", 900))).json();
          if (c.locked) return json({ error: "尝试过于频繁，请 " + Math.ceil(c.retryIn / 60) + " 分钟后再试" }, 429);
        }
        const resp = await handleLogin(request, env);
        if (lim) {
          if (resp.status === 401 || resp.status === 400) await lim.fetch("https://do/fail?max=" + envNumber(env, "AUTH_MAX_FAILURES", 8) + "&lock=" + envNumber(env, "AUTH_LOCK_SECONDS", 900));
          else if (resp.status === 200) await lim.fetch("https://do/reset");
        }
        return resp;
      }

      // 运营管理 API（ADMIN_KEY，不走客户会话）
      if (path === "/api/admin/customers" && request.method === "GET") {
        const g = await adminGate(request, env); if (g.error) return g.error;
        return await handleAdminList(env);
      }
      let am;
      if ((am = path.match(/^\/api\/admin\/customers\/(\d+)$/))) {
        const g = await adminGate(request, env); if (g.error) return g.error;
        if (request.method === "POST") return await handleAdminUpdate(env, Number(am[1]), await request.json().catch(() => ({})));
        if (request.method === "DELETE") return await handleAdminDelete(env, Number(am[1]));
      }

      // 以下都要登录
      const auth = await requireCustomer(request, env);
      if (auth.error) return auth.error;
      const customer = auth.customer;

      if (request.method === "GET" && path === "/api/me") return handleMe(request, env, customer);
      if (request.method === "POST" && path === "/api/upload") return await handleUpload(request, env, customer);
      if (request.method === "POST" && path === "/api/mpu/create") return await handleMpuCreate(request, env, customer);
      if (request.method === "POST" && path === "/api/mpu/part") return await handleMpuPart(request, env, customer, url);
      if (request.method === "POST" && path === "/api/mpu/complete") return await handleMpuComplete(request, env, customer);
      if (request.method === "GET" && path === "/api/list") return handleList(request, env, customer, url);
      if (request.method === "GET" && path === "/api/albums") return handleAlbums(request, env, customer);
      if (request.method === "POST" && path === "/api/albums") return handleCreateAlbum(request, env, customer);

      let m;
      if ((m = path.match(/^\/api\/img\/(\d+)$/)) && request.method === "DELETE") return handleDeleteImg(request, env, customer, Number(m[1]));
      if ((m = path.match(/^\/api\/img\/(\d+)\/album$/)) && request.method === "POST") return handleMoveImg(request, env, customer, Number(m[1]));
      if ((m = path.match(/^\/api\/img\/(\d+)\/rename$/)) && request.method === "POST") return handleRenameImg(request, env, customer, Number(m[1]));
      if ((m = path.match(/^\/api\/albums\/(\d+)$/)) && request.method === "DELETE") return handleDeleteAlbum(request, env, customer, Number(m[1]));

      return json({ error: "not_found" }, 404);
    } catch (err) {
      console.log("tuku error: " + (err && err.message ? err.message : err));
      return json({ error: "服务器繁忙，请稍后重试" }, 500);
    }
  },
};

/* ---------- 前端页面 ---------- */
const PAGE_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>存链</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='24' fill='%236d5efc'/><text x='50' y='73' font-size='58' text-anchor='middle' fill='%23ffffff' font-family='sans-serif' font-weight='bold'>存</text></svg>"><style>
:root{--bg:#080910;--bg2:#0b0d15;--card:#10131c;--ink:#EEF1F7;--mut:#8A93A6;--line:rgba(255,255,255,.08);--g1:#a855f7;--g2:#6d5efc;--ok:#34D39A;--amber:#F3B44C;--bad:#F2726F}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);min-height:100vh;line-height:1.5;-webkit-font-smoothing:antialiased}
.bg{position:fixed;inset:0;z-index:-1;background:radial-gradient(900px 500px at 12% -5%,rgba(124,92,255,.20),transparent 60%),radial-gradient(800px 500px at 100% 110%,rgba(45,212,191,.12),transparent 55%)}
input,button,select,textarea{font:inherit}
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
.login{max-width:400px;margin:12vh auto;padding:20px}
.login .card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 30px 80px rgba(0,0,0,.5)}
.login .card>*+*{margin-top:12px}
.login .brand{display:flex;align-items:center;gap:10px;font-size:1.3rem;font-weight:800;margin-bottom:4px}
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
.navitem.on .cnt{color:#c9beff}
.sidefoot{margin-top:auto;padding-top:10px;border-top:1px solid var(--line)}
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:30;display:none}
.scrim.show{display:block}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;gap:12px;padding:14px 24px;border-bottom:1px solid var(--line);background:rgba(10,12,18,.6);backdrop-filter:blur(8px);position:sticky;top:0;z-index:6}
.topbar .burger{font-size:1.4rem;cursor:pointer;display:none;line-height:1}
.topbar .pt{font-size:1.15rem;font-weight:700}
.topbar .sp{margin-left:auto}
.uchip{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:999px;padding:6px 14px;font-size:.85rem;color:var(--mut)}
.uchip .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.content{padding:24px 32px;width:100%}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.scard{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;display:flex;align-items:center;gap:15px;box-shadow:0 12px 40px rgba(0,0,0,.32)}
.scard .ico{width:52px;height:52px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;flex-shrink:0}
.scard .ico.i1{background:rgba(109,94,252,.16)}
.scard .ico.i2{background:rgba(52,211,154,.16)}
.scard .ico.i3{background:rgba(243,180,76,.16)}
.scard .ico.i4{background:rgba(168,85,247,.16)}
.scard .k{font-size:.8rem;color:var(--mut);margin-bottom:3px}
.scard .v{font-size:1.5rem;font-weight:800;font-variant-numeric:tabular-nums;line-height:1.1}
.panels{display:grid;grid-template-columns:1.618fr 1fr;gap:16px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px;box-shadow:0 12px 40px rgba(0,0,0,.32)}
.panel .ph{font-size:.95rem;font-weight:700;margin-bottom:16px}
.usebar{height:10px;background:rgba(255,255,255,.08);border-radius:6px;overflow:hidden}
.usebar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--g2),var(--g1));border-radius:6px;transition:width .6s cubic-bezier(.2,.7,.2,1)}
.usebar>i.warn{background:linear-gradient(90deg,var(--amber),#fb7185)}
.usebar>i.full{background:linear-gradient(90deg,#fb7185,#ef4444)}
.usetxt{display:flex;justify-content:space-between;margin-top:10px;font-size:.85rem;font-variant-numeric:tabular-nums}
.recentrow{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:12px}
.rtile{aspect-ratio:1.618;border-radius:10px;overflow:hidden;background:#0a0b10;border:1px solid var(--line);cursor:pointer;transition:transform .16s,border-color .16s}
.rtile:hover{transform:translateY(-2px);border-color:rgba(124,108,255,.45)}
.rtile img{width:100%;height:100%;object-fit:cover;display:block}
.rfi{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:1.9rem}
.info{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid var(--line);font-size:.9rem}
.info:last-child{border-bottom:0}
.info .il{color:var(--mut)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}
.tierbadge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.72rem;font-weight:700;border:1px solid rgba(124,108,255,.4);background:rgba(124,108,255,.14);color:#c9beff}
.setbar{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:14px;color:var(--mut);font-size:.85rem}
.setbar .chk{display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none}
.setbar input:not([type=checkbox]){width:auto;padding:8px 10px}
.drop{border:2px dashed var(--line);border-radius:16px;padding:44px 20px;text-align:center;color:var(--mut);cursor:pointer;margin-bottom:16px;transition:.15s}
.drop:hover{border-color:rgba(124,108,255,.4)}
.drop.on{border-color:var(--g2);background:rgba(124,108,255,.06)}
.dropico{font-size:2.4rem;line-height:1;margin-bottom:10px;opacity:.9}
.prog{display:grid;gap:8px;margin-bottom:16px}
.pitem{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:9px 12px}
.pn{font-size:.8rem;display:flex;justify-content:space-between;gap:8px;margin-bottom:6px}
.pn>span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pct{color:var(--mut);flex-shrink:0}
.pbar{height:6px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden}
.pbar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--g2),var(--g1));transition:width .2s}
.pitem.done .pbar>i{background:var(--ok);width:100%}
.pitem.err .pbar>i{background:var(--bad)}
.pitem.err .pct{color:var(--bad)}
.ftool{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.ftitle{font-size:1.05rem;font-weight:700;margin-right:auto}
.srch{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:10px;padding:0 12px;min-width:170px}
.srch .si{color:var(--mut)}
.srch input{border:0;background:transparent;padding:9px 0}
.ftool select{width:auto;padding:9px 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:14px}
.tile{position:relative;aspect-ratio:1.618;border-radius:14px;overflow:hidden;background:#0a0b10;border:1px solid var(--line);cursor:pointer}
.tile.sel{box-shadow:0 0 0 2px var(--g2);border-color:transparent}
.tile img{width:100%;height:100%;object-fit:cover;display:block;transition:transform .3s}
.tile:hover img{transform:scale(1.05)}
.tile .fileic{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:2.6rem}
.tile .cap{position:absolute;left:0;right:0;bottom:0;background:rgba(0,0,0,.62);padding:6px 9px;font-size:.74rem;pointer-events:none}
.tile .cap .nm{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tile .cap .tm{color:#b9c0cc;font-size:.68rem}
.tile .chk{position:absolute;top:8px;left:8px;width:21px;height:21px;border-radius:50%;border:1.5px solid rgba(255,255,255,.75);background:rgba(0,0,0,.35);display:flex;align-items:center;justify-content:center;font-size:.8rem;color:transparent;opacity:0;transition:.12s}
.tile:hover .chk,.tile.sel .chk,.selmode .tile .chk{opacity:1}
.tile.sel .chk{background:var(--g2);border-color:var(--g2);color:#fff}
.tile .more{position:absolute;top:7px;right:7px;width:24px;height:24px;border-radius:8px;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;font-size:1rem;color:#fff;opacity:0;transition:.12s}
.tile:hover .more{opacity:1}
.tile .badge{position:absolute;bottom:26px;left:8px;padding:1px 7px;border-radius:6px;font-size:.62rem;font-weight:700}
@media(hover:none){.tile .more{opacity:1}.tile .chk{opacity:1}}
.batch{position:fixed;left:50%;bottom:22px;transform:translateX(-50%) translateY(30px);opacity:0;pointer-events:none;display:flex;align-items:center;gap:8px;background:#12141d;border:1px solid rgba(124,108,255,.4);border-radius:999px;padding:8px 10px 8px 18px;box-shadow:0 18px 50px rgba(0,0,0,.55);z-index:25;transition:.18s;font-size:.86rem}
.batch.show{opacity:1;transform:translateX(-50%) translateY(0);pointer-events:auto}
.batch b{color:#c9beff}
.batch .bd{width:1px;height:18px;background:rgba(255,255,255,.14);margin:0 3px}
.batch button{border-radius:999px;padding:7px 13px}
.empty{text-align:center;padding:56px 20px;color:var(--mut)}
.empty .ei{font-size:2.6rem;opacity:.5;margin-bottom:10px}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:35;padding:16px}
.overlay.show{display:flex}
.modal{background:#0d0f16;border:1px solid var(--line);border-radius:16px;padding:20px;width:100%;max-width:420px;box-shadow:0 30px 80px rgba(0,0,0,.6)}
.modal h3{font-size:1.02rem;margin-bottom:14px;word-break:break-all}
.acts{display:grid;gap:4px}
.acts .a{display:flex;align-items:center;gap:11px;padding:11px 12px;border-radius:10px;cursor:pointer;font-size:.92rem;transition:.12s}
.acts .a:hover{background:rgba(255,255,255,.06)}
.acts .a .ai{width:20px;text-align:center;font-size:1.05rem}
.acts .a.del{color:var(--bad)}
.acts .sep{height:1px;background:var(--line);margin:5px 8px}
.fmt{display:grid;gap:8px}
.fmt button{width:100%;justify-content:flex-start;text-align:left}
.foot{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
.dprev{width:100%;height:180px;object-fit:contain;background:#000;border-radius:10px;margin-bottom:14px}
.dico{height:120px;display:flex;align-items:center;justify-content:center;font-size:3rem;background:#0a0b10;border-radius:10px;margin-bottom:14px}
.cval{display:flex;align-items:center;gap:8px;margin-top:8px}
.cval input{font-size:.8rem;padding:9px 11px}
.lb{position:fixed;inset:0;background:rgba(0,0,0,.92);display:none;align-items:center;justify-content:center;z-index:40}
.lb.show{display:flex}
.lb img{max-width:92vw;max-height:88vh;border-radius:8px}
.lb .x{position:absolute;top:16px;right:22px;font-size:1.7rem;color:#fff;cursor:pointer;opacity:.85}
.lb .nav{position:absolute;top:50%;transform:translateY(-50%);font-size:2.6rem;color:#fff;cursor:pointer;opacity:.7;padding:10px 18px;user-select:none}
.lb .nav:hover{opacity:1}
.lb .prev{left:6px}
.lb .next{right:6px}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);opacity:0;background:rgba(14,16,26,.95);border:1px solid var(--line);border-radius:12px;padding:12px 16px;transition:.2s;pointer-events:none;z-index:50}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(max-width:820px){
.cards{grid-template-columns:repeat(2,1fr)}
.panels{grid-template-columns:1fr}
.side{position:fixed;left:0;top:0;height:100vh;z-index:31;transform:translateX(-100%);transition:transform .22s;box-shadow:0 0 60px rgba(0,0,0,.6)}
.side.open{transform:translateX(0)}
.side .brand .x{display:block}
.topbar .burger{display:block}
.content{padding:16px}
.topbar{padding:12px 16px}
.grid{grid-template-columns:repeat(2,1fr);gap:10px}
.overlay{align-items:flex-end;padding:0}
.overlay .modal{max-width:100%;border-radius:18px 18px 0 0}
.batch{left:12px;right:12px;bottom:12px;transform:translateY(30px);justify-content:center;border-radius:14px}
.batch.show{transform:translateY(0)}
.ftitle{width:100%}
}
</style></head><body><div class="bg"></div>

<div id="loginView" class="login"><div class="card">
  <div class="brand"><span class="logo">存</span>存链</div>
  <div class="muted">第一次用：输入卡号 + 给自己设个密码，即完成开通。以后凭卡号+密码登录。</div>
  <input id="card" placeholder="卡号 CM-XXXX-XXXX-XXXX" autocomplete="off">
  <input id="pw" type="password" placeholder="访问密码（至少4位）">
  <button class="pri" id="loginBtn" style="width:100%">进入</button>
  <div id="loginErr" class="muted" style="color:var(--bad);min-height:20px"></div>
</div></div>

<div id="appShell" class="shell hide">
  <div class="scrim" id="scrim"></div>
  <aside class="side" id="side">
    <div class="brand"><span class="logo">存</span>存链<span class="x" id="sideClose">✕</span></div>
    <div id="nav"></div>
    <div class="sidefoot"><div class="navitem" id="logoutBtn"><span class="ni">↩</span>退出登录</div></div>
  </aside>
  <div class="main">
    <header class="topbar"><span class="burger" id="burger">☰</span><div class="pt" id="pageTitle">仪表盘</div><span class="sp"></span><div class="uchip"><span class="dot"></span><span id="who">—</span></div></header>
    <div class="content">

      <div id="view-dash" class="view">
        <div class="cards">
          <div class="scard"><div class="ico i1">🖼️</div><div><div class="k">文件数量</div><div class="v" id="sCount">0</div></div></div>
          <div class="scard"><div class="ico i2">💾</div><div><div class="k">已用容量</div><div class="v" id="sUsed">0</div></div></div>
          <div class="scard"><div class="ico i3">📦</div><div><div class="k">可用容量</div><div class="v" id="sFree">0</div></div></div>
          <div class="scard"><div class="ico i4">🗄️</div><div><div class="k">总容量</div><div class="v" id="sTotal">0</div></div></div>
        </div>
        <div class="panels">
          <div class="panel">
            <div class="ph">容量用量</div>
            <div class="usebar"><i id="dBar"></i></div>
            <div class="usetxt"><span id="dUseTxt">0 / 0</span><span id="dPct" class="muted">0%</span></div>
            <button class="pri" id="goUpload" style="margin-top:18px">☁️ 上传文件</button>
          </div>
          <div class="panel">
            <div class="ph">我的信息</div>
            <div class="info"><span class="il">档位</span><span class="tierbadge" id="iTier">—</span></div>
            <div class="info"><span class="il">卡号</span><span class="mono" id="iCard">—</span></div>
            <div class="info"><span class="il">到期</span><span id="iExp">—</span></div>
          </div>
        </div>
        <div class="panel" style="margin-top:16px">
          <div class="ph" style="display:flex;justify-content:space-between;align-items:center">最近上传<span class="muted" id="recMore" style="cursor:pointer;font-weight:400">查看全部 ›</span></div>
          <div class="recentrow" id="recent"></div>
        </div>
      </div>

      <div id="view-upload" class="view hide">
        <div class="setbar">
          <label class="chk"><input type="checkbox" id="cmp" checked style="width:auto"> 图片上传前压缩（省空间/更快）</label>
          <input id="wm" placeholder="水印文字（留空=无，仅加在图片上）" style="max-width:240px">
        </div>
        <div class="drop" id="drop"><div class="dropico">☁️</div><div style="font-size:1.05rem;color:var(--ink)"><b>拖文件到这里</b>，或点击选择</div><div class="muted" style="margin-top:6px">图片 / 视频 / 音频 / PDF / 压缩包… 可多选</div><input id="file" type="file" multiple class="hide"></div>
        <div id="progress" class="prog hide"></div>
        <div class="muted" style="font-size:.82rem">大文件自动分片直传；也可直接 <b>Ctrl+V</b> 粘贴图片上传。</div>
      </div>

      <div id="view-files" class="view hide">
        <div class="ftool">
          <span class="ftitle" id="ftitle">全部文件</span>
          <div class="srch"><span class="si">🔍</span><input id="q" placeholder="搜索文件名"></div>
          <select id="sort"><option value="new">最新</option><option value="old">最早</option><option value="big">最大</option><option value="name">名称</option></select>
          <button id="delAlbumBtn" class="sm danger hide">删除相册</button>
        </div>
        <div class="grid" id="grid"></div>
        <div id="empty" class="empty hide"><div class="ei">📭</div>这里还没有文件</div>
      </div>

    </div>
  </div>
</div>

<div class="batch" id="batch">
  <span>已选 <b id="selN">0</b> 张</span><span class="bd"></span>
  <button id="bMove">📁 移动</button>
  <button id="bDown">⬇ 下载</button>
  <button id="bDel" class="danger">🗑 删除</button>
  <button id="bCancel">取消</button>
</div>

<div class="lb" id="lightbox"><span class="x" id="lbClose">✕</span><span class="nav prev" id="lbPrev">‹</span><img id="lbImg" src="" alt=""><span class="nav next" id="lbNext">›</span></div>

<div class="overlay" id="menuOverlay"><div class="modal"><h3 id="mTitle">操作</h3><div class="acts" id="mActs"></div></div></div>
<div class="overlay" id="copyOverlay"><div class="modal"><h3 id="cmTitle">复制链接</h3><div class="fmt" id="cmFmt"></div><div class="foot"><button id="cmClose">关闭</button></div></div></div>
<div class="overlay" id="detailOverlay"><div class="modal"><h3>详细信息</h3><div id="dBody"></div><div class="foot"><button id="dClose">关闭</button></div></div></div>
<div class="overlay" id="renameOverlay"><div class="modal"><h3>重命名</h3><input id="renameInput" placeholder="新文件名"><div class="foot"><button id="renCancel">取消</button><button class="pri" id="renSave">保存</button></div></div></div>
<div class="overlay" id="moveOverlay"><div class="modal"><h3 id="moveTitle">移动到相册</h3><div class="acts" id="moveActs"></div><div class="foot"><button id="moveCancel">取消</button></div></div></div>
<div class="overlay" id="setOverlay"><div class="modal"><h3>账户设置</h3><div id="setBody"></div><div class="foot"><button id="setLogout" class="danger">退出登录</button><button id="setClose">关闭</button></div></div></div>
<div class="toast" id="toast"></div>
<script>
var TOKEN=sessionStorage.getItem("tuku_token")||"";
var ALLFILES=[],ALBUMS=[],VIEW="dash";
var NAV={type:"all"};
var Q="",SORT="new";
var SEL={};
var LB=[],LBI=0;
var MENU_IM=null,REN_IM=null,MOVE_IDS=[],ME=null;
var CATS=[["all","全部文件","🗂️"],["image","图片","🖼️"],["video","视频","🎬"],["audio","音频","🎵"],["doc","文档","📄"],["zip","压缩包","🗜️"],["other","其他","📎"]];
function $(id){return document.getElementById(id)}
function show(id){$(id).classList.add("show")}
function hide(id){$(id).classList.remove("show")}
function toast(m){var t=$("toast");t.textContent=m;t.classList.add("show");setTimeout(function(){t.classList.remove("show")},2200)}
function esc(s){return String(s==null?"":s).replace(/[<>&]/g,function(c){return c==="<"?"&lt;":c===">"?"&gt;":"&amp;"})}
function fmtSize(b){b=Number(b)||0;if(b<1024)return b+" B";if(b<1048576)return (b/1024).toFixed(1)+" KB";if(b<1073741824)return (b/1048576).toFixed(1)+" MB";return (b/1073741824).toFixed(2)+" GB"}
function relTime(t){t=Number(t);if(!t)return"";if(t>1e12)t=Math.floor(t/1000);var s=Math.floor(Date.now()/1000)-t;if(s<0)s=0;if(s<60)return"刚刚";if(s<3600)return Math.floor(s/60)+" 分钟前";if(s<86400)return Math.floor(s/3600)+" 小时前";if(s<2592000)return Math.floor(s/86400)+" 天前";var d=new Date(t*1000);return (d.getMonth()+1)+"-"+d.getDate()}
function typeOf(im){if(im.kind==="image")return"image";var m=String(im.mime||"");if(m.indexOf("video")===0)return"video";if(m.indexOf("audio")===0)return"audio";if(m.indexOf("pdf")>=0||m.indexOf("text")===0||m.indexOf("word")>=0||m.indexOf("document")>=0||m.indexOf("sheet")>=0||m.indexOf("presentation")>=0)return"doc";if(/zip|rar|7z|compress|tar|gzip/.test(m))return"zip";return"other"}
function typeIcon(t){return t==="video"?"🎬":t==="audio"?"🎵":t==="doc"?"📄":t==="zip"?"🗜️":"📎"}
function extOf(im){var n=String(im.filename||"");var d=n.lastIndexOf(".");return d>0?n.slice(d+1).toUpperCase().slice(0,4):"文件"}
function catCount(cat){if(cat==="all")return ALLFILES.length;var n=0;for(var i=0;i<ALLFILES.length;i++)if(typeOf(ALLFILES[i])===cat)n++;return n}
function catLabel(t){for(var i=0;i<CATS.length;i++)if(CATS[i][0]===t)return CATS[i][1];return"全部文件"}
function api(path,opts){opts=opts||{};opts.headers=Object.assign({authorization:"Bearer "+TOKEN},opts.headers||{});return fetch(path,opts).then(function(r){return r.json().then(function(d){if(r.status===401){logout();throw new Error(d.error||"未登录")}if(!r.ok)throw new Error(d.error||("HTTP "+r.status));return d})})}
function logout(){sessionStorage.removeItem("tuku_token");TOKEN="";$("appShell").classList.add("hide");$("loginView").classList.remove("hide");$("who").textContent="—"}
$("loginBtn").addEventListener("click",doLogin);
$("pw").addEventListener("keydown",function(e){if(e.key==="Enter")doLogin()});
function doLogin(){
  var card=$("card").value.trim(),pw=$("pw").value;
  $("loginErr").textContent="";
  fetch("/api/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({card:card,password:pw})}).then(function(r){return r.json().then(function(d){
    if(!r.ok){$("loginErr").textContent=d.error||"登录失败";return}
    TOKEN=d.token;sessionStorage.setItem("tuku_token",TOKEN);
    if(d.firstTime)toast("开通成功，欢迎使用");
    enterApp();
  })}).catch(function(e){$("loginErr").textContent="网络错误"});
}
function enterApp(){$("loginView").classList.add("hide");$("appShell").classList.remove("hide");Promise.all([loadAlbums(),loadFiles()]).then(function(){navTo({view:"dash"})}).catch(function(){navTo({view:"dash"})})}
function loadFiles(){return api("/api/list").then(function(d){ALLFILES=d.images||[]})}
function loadAlbums(){return api("/api/albums").then(function(d){ALBUMS=d.albums||[]})}
function loadMe(){api("/api/me").then(function(d){ME=d;
  $("who").textContent=d.tierLabel;
  $("sCount").textContent=d.count;
  $("sUsed").textContent=fmtSize(d.usedBytes);
  $("sFree").textContent=fmtSize(Math.max(0,d.byteLimit-d.usedBytes));
  $("sTotal").textContent=fmtSize(d.byteLimit);
  $("iTier").textContent=d.tierLabel;
  $("iCard").textContent=d.card;
  $("iExp").textContent=d.expiresAt?d.expiresAt.slice(0,10):"永久";
  var pct=d.byteLimit>0?Math.min(100,d.usedBytes/d.byteLimit*100):0;
  var bar=$("dBar");bar.style.width=(pct<1.5&&pct>0?1.5:pct).toFixed(1)+"%";bar.className=pct>=95?"full":pct>=80?"warn":"";
  $("dUseTxt").textContent=fmtSize(d.usedBytes)+" / "+fmtSize(d.byteLimit);
  $("dPct").textContent=pct.toFixed(pct<10?1:0)+"%";
}).catch(function(){})}
function renderRecent(){
  var box=$("recent");if(!box)return;
  var arr=ALLFILES.slice().sort(function(a,b){return (b.uploaded_at||0)-(a.uploaded_at||0)}).slice(0,10);
  box.innerHTML="";
  if(!arr.length){box.innerHTML="<div class='muted'>还没有文件，去上传第一个吧</div>";return}
  arr.forEach(function(im){
    var t=document.createElement("div");t.className="rtile";
    if(im.kind==="image"){var img=document.createElement("img");img.src=im.thumb;img.loading="lazy";t.appendChild(img)}
    else{var fi=document.createElement("div");fi.className="rfi";fi.textContent=typeIcon(typeOf(im));t.appendChild(fi)}
    t.onclick=function(){if(im.kind==="image"){LB=ALLFILES.filter(function(x){return x.kind==="image"});LBI=0;for(var k=0;k<LB.length;k++){if(LB[k].id===im.id){LBI=k;break}}$("lbImg").src=LB[LBI].link;show("lightbox")}else window.open(im.link,"_blank")};
    box.appendChild(t);
  });
}
function navTo(spec){
  clearSel();closeDrawer();closeOverlays();
  if(spec.view){VIEW=spec.view}
  else if(spec.type){VIEW="files";NAV={type:spec.type}}
  else{VIEW="files";NAV={album:spec.album,name:spec.name}}
  $("view-dash").classList.toggle("hide",VIEW!=="dash");
  $("view-upload").classList.toggle("hide",VIEW!=="upload");
  $("view-files").classList.toggle("hide",VIEW!=="files");
  $("pageTitle").textContent=VIEW==="dash"?"仪表盘":VIEW==="upload"?"上传文件":"我的文件";
  renderNav();
  if(VIEW==="dash"){loadMe();renderRecent()}
  if(VIEW==="files")renderFiles();
}
function renderNav(){
  var nav=$("nav");nav.innerHTML="";
  var grp=function(t){var g=document.createElement("div");g.className="navgrp";g.textContent=t;nav.appendChild(g)};
  var item=function(icon,label,active,cnt,fn){var a=document.createElement("div");a.className="navitem"+(active?" on":"");a.innerHTML="<span class='ni'>"+icon+"</span>"+esc(label);if(cnt!=null){var c=document.createElement("span");c.className="cnt";c.textContent=cnt;a.appendChild(c)}a.onclick=fn;nav.appendChild(a)};
  grp("常规");
  item("📊","仪表盘",VIEW==="dash",null,function(){navTo({view:"dash"})});
  item("☁️","上传文件",VIEW==="upload",null,function(){navTo({view:"upload"})});
  grp("分类");
  CATS.forEach(function(c){item(c[2],c[1],VIEW==="files"&&NAV.type===c[0],catCount(c[0]),function(){navTo({type:c[0]})})});
  grp("相册");
  ALBUMS.forEach(function(al){item("📁",al.name,VIEW==="files"&&String(NAV.album)===String(al.id),al.count,function(){navTo({album:al.id,name:al.name})})});
  item("➕","新建相册",false,null,newAlbum);
  grp("账户");
  item("⚙️","设置",false,null,openSettings);
}
function currentList(){
  var arr=ALLFILES.slice();
  if(NAV.album!=null&&NAV.type==null){arr=arr.filter(function(x){return String(x.album_id)===String(NAV.album)})}
  else if(NAV.type&&NAV.type!=="all"){arr=arr.filter(function(x){return typeOf(x)===NAV.type})}
  if(Q){var q=Q.toLowerCase();arr=arr.filter(function(x){return String(x.filename||"").toLowerCase().indexOf(q)>=0})}
  arr.sort(function(a,b){
    if(SORT==="new")return (b.uploaded_at||0)-(a.uploaded_at||0);
    if(SORT==="old")return (a.uploaded_at||0)-(b.uploaded_at||0);
    if(SORT==="big")return (b.bytes||0)-(a.bytes||0);
    return String(a.filename||"").localeCompare(String(b.filename||""));
  });
  return arr;
}
function renderFiles(){
  var isAlbum=NAV.album!=null&&NAV.type==null;
  $("ftitle").textContent=isAlbum?(NAV.name||"相册"):catLabel(NAV.type);
  $("delAlbumBtn").classList.toggle("hide",!isAlbum);
  var arr=currentList();
  var g=$("grid");g.innerHTML="";
  $("empty").classList.toggle("hide",arr.length>0);
  arr.forEach(function(im){
    var t=document.createElement("div");t.className="tile"+(SEL[im.id]?" sel":"");t.setAttribute("data-id",im.id);
    if(im.kind==="image"){var img=document.createElement("img");img.src=im.thumb;img.loading="lazy";t.appendChild(img)}
    else{var fi=document.createElement("div");fi.className="fileic";fi.textContent=typeIcon(typeOf(im));t.appendChild(fi);var bd=document.createElement("span");bd.className="badge";var ty=typeOf(im);bd.textContent=extOf(im);bd.style.background=ty==="video"?"rgba(45,212,191,.22)":ty==="audio"?"rgba(168,85,247,.22)":ty==="zip"?"rgba(243,180,76,.22)":"rgba(124,108,255,.22)";bd.style.color="#EEF1F7";t.appendChild(bd)}
    var chk=document.createElement("span");chk.className="chk";chk.textContent="✓";chk.onclick=function(e){e.stopPropagation();toggleSel(im.id)};t.appendChild(chk);
    var more=document.createElement("span");more.className="more";more.textContent="⋯";more.onclick=function(e){e.stopPropagation();openMenu(im)};t.appendChild(more);
    var cap=document.createElement("div");cap.className="cap";cap.innerHTML="<div class='nm'>"+esc(im.filename||"文件")+"</div><div class='tm'>"+relTime(im.uploaded_at)+"</div>";t.appendChild(cap);
    t.onclick=function(){if(im.kind==="image")openLightbox(im);else window.open(im.link,"_blank")};
    g.appendChild(t);
  });
}
function toggleSel(id){if(SEL[id])delete SEL[id];else SEL[id]=true;updateSelUI()}
function selIds(){return Object.keys(SEL).map(Number)}
function clearSel(){SEL={};updateSelUI()}
function updateSelUI(){
  var n=selIds().length;
  document.body.classList.toggle("selmode",n>0);
  $("selN").textContent=n;
  $("batch").classList.toggle("show",n>0);
  var tiles=document.querySelectorAll("#grid .tile");
  for(var i=0;i<tiles.length;i++){var id=tiles[i].getAttribute("data-id");tiles[i].classList.toggle("sel",!!SEL[id])}
}
function openMenu(im){MENU_IM=im;$("mTitle").textContent=im.filename||"操作";var box=$("mActs");box.innerHTML="";
  var add=function(icon,label,fn,cls){var a=document.createElement("div");a.className="a"+(cls?" "+cls:"");a.innerHTML="<span class='ai'>"+icon+"</span>"+label;a.onclick=fn;box.appendChild(a)};
  add("🔗","复制链接",function(){hide("menuOverlay");openCopyMenu(im)});
  add("⬇","下载",function(){hide("menuOverlay");downloadOne(im)});
  add("↗","新窗口打开",function(){hide("menuOverlay");window.open(im.link,"_blank")});
  add("✏","重命名",function(){hide("menuOverlay");openRename(im)});
  add("ℹ","详细信息",function(){hide("menuOverlay");openDetail(im)});
  add("📁","移动到相册",function(){hide("menuOverlay");openMove([im.id])});
  var sep=document.createElement("div");sep.className="sep";box.appendChild(sep);
  add("🗑","删除",function(){hide("menuOverlay");delImgs([im.id])},"del");
  show("menuOverlay");
}
function openCopyMenu(im){
  var link=im.link,name=im.filename||"file",isImg=im.kind==="image";
  var fmts=[["直链",link]];
  if(isImg){fmts.push(["Markdown","!["+name+"]("+link+")"]);fmts.push(["Markdown 带链接","[!["+name+"]("+link+")]("+link+")"]);fmts.push(["HTML","<img src='"+link+"' alt='"+name+"'>"]);fmts.push(["BBCode","[img]"+link+"[/img]"]);fmts.push(["缩略图直链",im.thumb]);}
  else{fmts.push(["Markdown","["+name+"]("+link+")"]);fmts.push(["HTML","<a href='"+link+"'>"+name+"</a>"]);fmts.push(["BBCode","[url]"+link+"[/url]"]);}
  var box=$("cmFmt");box.innerHTML="";
  fmts.forEach(function(f){var b=document.createElement("button");b.className="sm";b.textContent=f[0];b.onclick=function(){navigator.clipboard.writeText(f[1]).then(function(){toast(f[0]+" 已复制")});hide("copyOverlay")};box.appendChild(b)});
  $("cmTitle").textContent="复制 · "+name;show("copyOverlay");
}
function downloadOne(im){var a=document.createElement("a");a.href=im.kind==="image"?im.link:(im.link+"?dl=1");a.download=im.filename||"";document.body.appendChild(a);a.click();a.remove()}
function downloadSel(){var arr=ALLFILES.filter(function(x){return SEL[x.id]});var i=0;(function nx(){if(i>=arr.length)return;downloadOne(arr[i]);i++;setTimeout(nx,500)})();toast("开始下载 "+arr.length+" 个")}
function openDetail(im){
  var b=$("dBody");b.innerHTML="";
  if(im.kind==="image"){var img=document.createElement("img");img.className="dprev";img.src=im.thumb;b.appendChild(img)}
  else{var ic=document.createElement("div");ic.className="dico";ic.textContent=typeIcon(typeOf(im));b.appendChild(ic)}
  var row=function(k,v){var d=document.createElement("div");d.className="info";d.innerHTML="<span class='il'>"+k+"</span><span>"+esc(v)+"</span>";b.appendChild(d);return d};
  row("文件名",im.filename||"—");
  row("类型",im.mime||(im.kind==="image"?"图片":"文件"));
  row("大小",fmtSize(im.bytes));
  var dim=row("尺寸",im.kind==="image"?"读取中…":"—");
  row("上传时间",relTime(im.uploaded_at));
  var lk=document.createElement("div");lk.className="cval";var inp=document.createElement("input");inp.readOnly=true;inp.value=im.link;var cp=document.createElement("button");cp.className="sm";cp.textContent="复制直链";cp.onclick=function(){navigator.clipboard.writeText(im.link).then(function(){toast("直链已复制")})};lk.appendChild(inp);lk.appendChild(cp);b.appendChild(lk);
  if(im.kind==="image"){var pi=new Image();pi.onload=function(){dim.querySelector("span:last-child").textContent=pi.naturalWidth+" × "+pi.naturalHeight};pi.src=im.link}
  show("detailOverlay");
}
function openRename(im){REN_IM=im;$("renameInput").value=im.filename||"";show("renameOverlay");setTimeout(function(){$("renameInput").focus()},50)}
function doRename(){if(!REN_IM)return;var nm=$("renameInput").value.trim();if(!nm)return toast("名字不能为空");api("/api/img/"+REN_IM.id+"/rename",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({filename:nm})}).then(function(r){REN_IM.filename=r.filename||nm;hide("renameOverlay");renderFiles();toast("已重命名")}).catch(function(e){toast(e.message)})}
function openMove(ids){MOVE_IDS=ids;var box=$("moveActs");box.innerHTML="";
  var add=function(label,albumId){var a=document.createElement("div");a.className="a";a.innerHTML="<span class='ai'>📁</span>"+esc(label);a.onclick=function(){doMove(ids,albumId)};box.appendChild(a)};
  add("未分组",null);
  ALBUMS.forEach(function(al){add(al.name+"（"+al.count+"）",al.id)});
  var sep=document.createElement("div");sep.className="sep";box.appendChild(sep);
  var na=document.createElement("div");na.className="a";na.innerHTML="<span class='ai'>➕</span>新建相册并移入";na.onclick=function(){var name=prompt("相册名字");if(!name)return;api("/api/albums",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:name})}).then(function(res){return loadAlbums().then(function(){var na2=ALBUMS.filter(function(a){return a.name===name});doMove(ids,na2.length?na2[na2.length-1].id:null)})}).catch(function(e){toast(e.message)})};box.appendChild(na);
  $("moveTitle").textContent="移动 "+ids.length+" 个到相册";show("moveOverlay");
}
function doMove(ids,albumId){
  var i=0;(function nx(){if(i>=ids.length){hide("moveOverlay");clearSel();reloadFiles();toast("已移动");return}api("/api/img/"+ids[i]+"/album",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({album_id:albumId})}).then(function(){i++;nx()}).catch(function(e){toast(e.message);i++;nx()})})();
}
function delImgs(ids){
  if(!ids.length)return;
  if(!confirm("删除选中的 "+ids.length+" 个文件？不可恢复。"))return;
  var i=0;(function nx(){if(i>=ids.length){clearSel();reloadFiles();toast("已删除");return}api("/api/img/"+ids[i],{method:"DELETE"}).then(function(){i++;nx()}).catch(function(e){toast(e.message);i++;nx()})})();
}
function reloadFiles(){return Promise.all([loadFiles(),loadAlbums()]).then(function(){renderNav();renderFiles();loadMe()})}
function newAlbum(){var name=prompt("相册名字");if(!name)return;api("/api/albums",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:name})}).then(function(){return loadAlbums()}).then(function(){renderNav();toast("已新建相册")}).catch(function(e){toast(e.message)})}
function delAlbum(id){if(!confirm("删除相册？里面的文件会变成未分组，不会删文件。"))return;api("/api/albums/"+id,{method:"DELETE"}).then(function(){return loadAlbums()}).then(function(){navTo({type:"all"})}).catch(function(e){toast(e.message)})}
function openSettings(){var b=$("setBody");b.innerHTML="";closeDrawer();
  var row=function(k,v){var d=document.createElement("div");d.className="info";d.innerHTML="<span class='il'>"+k+"</span><span>"+esc(v)+"</span>";b.appendChild(d)};
  if(ME){row("档位",ME.tierLabel);row("卡号",ME.card);row("到期",ME.expiresAt?ME.expiresAt.slice(0,10):"永久");row("已用",fmtSize(ME.usedBytes)+" / "+fmtSize(ME.byteLimit))}
  show("setOverlay");
}
var drop=$("drop"),fileInput=$("file");
drop.addEventListener("click",function(){fileInput.click()});
fileInput.addEventListener("change",function(){uploadFiles(fileInput.files);fileInput.value=""});
drop.addEventListener("dragover",function(e){e.preventDefault();drop.classList.add("on")});
drop.addEventListener("dragleave",function(){drop.classList.remove("on")});
drop.addEventListener("drop",function(e){e.preventDefault();drop.classList.remove("on");uploadFiles(e.dataTransfer.files)});
function compressImage(file,maxDim,quality,wm){
  return new Promise(function(resolve){
    if(String(file.type).indexOf("image/")!==0||file.type==="image/gif"){resolve(file);return}
    var url=URL.createObjectURL(file),img=new Image();
    img.onload=function(){
      URL.revokeObjectURL(url);
      var w=img.width,h=img.height,scale=Math.min(1,maxDim/Math.max(w,h));
      var cw=Math.max(1,Math.round(w*scale)),ch=Math.max(1,Math.round(h*scale));
      var cv=document.createElement("canvas");cv.width=cw;cv.height=ch;
      var ctx=cv.getContext("2d");ctx.drawImage(img,0,0,cw,ch);
      if(wm){var fs=Math.max(14,Math.round(cw/26));ctx.font=fs+"px sans-serif";ctx.textAlign="right";ctx.textBaseline="bottom";ctx.lineWidth=Math.max(2,fs/8);ctx.strokeStyle="rgba(0,0,0,.45)";ctx.fillStyle="rgba(255,255,255,.82)";ctx.strokeText(wm,cw-12,ch-10);ctx.fillText(wm,cw-12,ch-10)}
      cv.toBlob(function(b){
        if(!b||(b.size>=file.size&&!wm)){resolve(file);return}
        var nm=file.name,dot=nm.lastIndexOf(".");nm=(dot>0?nm.slice(0,dot):nm)+".jpg";
        resolve(new File([b],nm,{type:"image/jpeg"}));
      },"image/jpeg",quality);
    };
    img.onerror=function(){URL.revokeObjectURL(url);resolve(file)};
    img.src=url;
  });
}
function xhrUpload(file,albumId,onprog){
  return new Promise(function(resolve,reject){
    var fd=new FormData();fd.append("file",file);if(albumId)fd.append("album_id",albumId);
    var x=new XMLHttpRequest();x.open("POST","/api/upload");x.setRequestHeader("authorization","Bearer "+TOKEN);
    x.upload.onprogress=function(e){if(e.lengthComputable&&onprog)onprog(e.loaded/e.total)};
    x.onload=function(){var d={};try{d=JSON.parse(x.responseText)}catch(e){}if(x.status>=200&&x.status<300)resolve(d);else{if(x.status===401)logout();reject(new Error(d.error||("HTTP "+x.status)))}};
    x.onerror=function(){reject(new Error("网络错误"))};
    x.send(fd);
  });
}
function fileSig(file){return "tuku_mpu_"+encodeURIComponent(file.name)+"_"+file.size+"_"+(file.lastModified||0)}
function mpuSave(sig,st){try{localStorage.setItem(sig,JSON.stringify(st))}catch(e){}}
function mpuLoad(sig){try{var v=localStorage.getItem(sig);return v?JSON.parse(v):null}catch(e){return null}}
function mpuClear(sig){try{localStorage.removeItem(sig)}catch(e){}}
// 大文件分片上传，带断点续传(localStorage 记 uploadId+已传分片)+ 每片自动重试
function multipartUpload(file,albumId,onprog){
  var CHUNK=40*1024*1024;
  var sig=fileSig(file);
  var st=mpuLoad(sig),resumed=false;
  function ensure(){
    if(st&&st.uploadId&&st.key&&st.chunk===CHUNK&&Array.isArray(st.parts)){resumed=true;return Promise.resolve()}
    return api("/api/mpu/create",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({filename:file.name,mime:file.type||"application/octet-stream",size:file.size,album_id:albumId})}).then(function(init){st={key:init.key,uploadId:init.uploadId,chunk:CHUNK,parts:[]};mpuSave(sig,st)});
  }
  return ensure().then(function(){
    if(resumed&&st.parts.length&&onprog)toast("继续未完成的上传…");
    var total=Math.ceil(file.size/CHUNK),done={};
    st.parts.forEach(function(p){done[p.part]=true});
    function reportBase(){if(onprog)onprog(Math.min(1,(st.parts.length*CHUNK)/file.size))}
    reportBase();
    function uploadPart(n,attempt){
      return new Promise(function(resolve,reject){
        var start=(n-1)*CHUNK,chunk=file.slice(start,Math.min(file.size,start+CHUNK));
        var x=new XMLHttpRequest();x.open("POST","/api/mpu/part?key="+encodeURIComponent(st.key)+"&uploadId="+encodeURIComponent(st.uploadId)+"&part="+n);x.setRequestHeader("authorization","Bearer "+TOKEN);
        x.upload.onprogress=function(e){if(e.lengthComputable&&onprog){var base=st.parts.length*CHUNK;onprog(Math.min(1,(base+e.loaded)/file.size))}};
        x.onload=function(){var d={};try{d=JSON.parse(x.responseText)}catch(e){}if(x.status>=200&&x.status<300){st.parts.push({part:d.part,etag:d.etag});mpuSave(sig,st);reportBase();resolve()}else{if(x.status===401)logout();reject(new Error(d.error||("分片"+n+"失败")))}};
        x.onerror=function(){reject(new Error("网络中断"))};
        x.send(chunk);
      }).catch(function(e){
        if(attempt<3)return new Promise(function(r){setTimeout(r,900*attempt)}).then(function(){return uploadPart(n,attempt+1)});
        throw e;
      });
    }
    function loop(n){if(n>total)return Promise.resolve();if(done[n])return loop(n+1);return uploadPart(n,1).then(function(){return loop(n+1)})}
    return loop(1).catch(function(e){if(resumed)mpuClear(sig);throw e});
  }).then(function(){
    return api("/api/mpu/complete",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({key:st.key,uploadId:st.uploadId,parts:st.parts,filename:file.name,mime:file.type||"application/octet-stream",size:file.size,album_id:albumId})});
  }).then(function(r){mpuClear(sig);return r});
}
function uploadFiles(files){
  files=Array.prototype.slice.call(files||[]);if(!files.length)return;
  navTo({view:"upload"});
  var pc=$("progress");pc.classList.remove("hide");pc.innerHTML="";
  var doCompress=$("cmp").checked,wm=$("wm").value.trim();
  var albumId=(NAV.album!=null&&NAV.type==null)?NAV.album:null;
  var done=0,fail=0;
  var runOne=function(i){
    if(i>=files.length){toast("完成 "+done+" 个"+(fail?("，失败 "+fail):""));reloadFiles();setTimeout(function(){if(!fail)pc.classList.add("hide")},1600);return}
    var f=files[i];
    var item=document.createElement("div");item.className="pitem";
    item.innerHTML="<div class='pn'><span>"+esc(f.name)+"</span><span class='pct'>0%</span></div><div class='pbar'><i></i></div>";
    pc.appendChild(item);
    var bar=item.querySelector("i"),pct=item.querySelector(".pct");
    (doCompress?compressImage(f,2560,0.85,wm):Promise.resolve(f)).then(function(uf){
      var prog=function(p){var v=Math.round(p*100);bar.style.width=v+"%";pct.textContent=v+"%"};
      return uf.size>90*1024*1024 ? multipartUpload(uf,albumId,prog) : xhrUpload(uf,albumId,prog);
    }).then(function(){done++;item.classList.add("done");pct.textContent="完成"}).catch(function(e){fail++;item.classList.add("err");pct.textContent=e.message}).then(function(){runOne(i+1)});
  };
  toast("上传中…");runOne(0);
}
function openLightbox(im){var imgs=currentList().filter(function(x){return x.kind==="image"});LB=imgs;LBI=0;for(var k=0;k<LB.length;k++){if(LB[k].id===im.id){LBI=k;break}}if(!LB.length)return;$("lbImg").src=LB[LBI].link;show("lightbox")}
function lbNav(d){if(!LB.length)return;LBI=(LBI+d+LB.length)%LB.length;$("lbImg").src=LB[LBI].link}
$("lbClose").onclick=function(){hide("lightbox")};
$("lbPrev").onclick=function(){lbNav(-1)};
$("lbNext").onclick=function(){lbNav(1)};
$("lightbox").addEventListener("click",function(e){if(e.target.id==="lightbox")hide("lightbox")});
function closeOverlays(){var ov=document.querySelectorAll(".overlay");for(var i=0;i<ov.length;i++)ov[i].classList.remove("show")}
["menuOverlay","copyOverlay","detailOverlay","renameOverlay","moveOverlay","setOverlay"].forEach(function(id){$(id).addEventListener("click",function(e){if(e.target===this)this.classList.remove("show")})});
$("cmClose").onclick=function(){hide("copyOverlay")};
$("dClose").onclick=function(){hide("detailOverlay")};
$("renCancel").onclick=function(){hide("renameOverlay")};
$("renSave").onclick=doRename;
$("renameInput").addEventListener("keydown",function(e){if(e.key==="Enter")doRename()});
$("moveCancel").onclick=function(){hide("moveOverlay")};
$("setClose").onclick=function(){hide("setOverlay")};
$("setLogout").onclick=function(){hide("setOverlay");logout()};
$("goUpload").addEventListener("click",function(){navTo({view:"upload"})});
$("recMore").addEventListener("click",function(){navTo({type:"all"})});
$("logoutBtn").addEventListener("click",logout);
$("delAlbumBtn").addEventListener("click",function(){if(NAV.album!=null)delAlbum(NAV.album)});
$("q").addEventListener("input",function(){Q=this.value;renderFiles()});
$("sort").addEventListener("change",function(){SORT=this.value;renderFiles()});
$("bMove").onclick=function(){openMove(selIds())};
$("bDown").onclick=downloadSel;
$("bDel").onclick=function(){delImgs(selIds())};
$("bCancel").onclick=clearSel;
$("burger").addEventListener("click",openDrawer);
$("sideClose").addEventListener("click",closeDrawer);
$("scrim").addEventListener("click",closeDrawer);
function openDrawer(){$("side").classList.add("open");$("scrim").classList.add("show")}
function closeDrawer(){$("side").classList.remove("open");$("scrim").classList.remove("show")}
document.addEventListener("keydown",function(e){
  if($("lightbox").classList.contains("show")){if(e.key==="Escape")hide("lightbox");else if(e.key==="ArrowLeft")lbNav(-1);else if(e.key==="ArrowRight")lbNav(1);return}
  if($("appShell").classList.contains("hide"))return;
  var inField=/INPUT|TEXTAREA|SELECT/.test((document.activeElement||{}).tagName||"");
  if(e.key==="Escape"){clearSel();closeOverlays();closeDrawer();return}
  if(VIEW!=="files"||inField)return;
  if(e.key==="Delete"&&selIds().length){delImgs(selIds())}
  else if((e.ctrlKey||e.metaKey)&&(e.key==="a"||e.key==="A")){e.preventDefault();currentList().forEach(function(x){SEL[x.id]=true});updateSelUI()}
});
document.addEventListener("paste",function(e){
  if($("appShell").classList.contains("hide"))return;
  var items=(e.clipboardData||{}).items||[],fs=[];
  for(var i=0;i<items.length;i++){if(items[i].kind==="file"){var f=items[i].getAsFile();if(f)fs.push(f)}}
  if(fs.length)uploadFiles(fs);
});
if(TOKEN)enterApp();
</script></body></html>`;

/* ---------- 运营台页面 /scfw ---------- */
const ADMIN_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>存链 · 运营台</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='24' fill='%236d5efc'/><text x='50' y='73' font-size='58' text-anchor='middle' fill='%23ffffff' font-family='sans-serif' font-weight='bold'>存</text></svg>"><style>
:root{--bg:#080910;--bg2:#0b0d15;--card:#10131c;--ink:#EEF1F7;--mut:#8A93A6;--line:rgba(255,255,255,.08);--g1:#a855f7;--g2:#6d5efc;--ok:#34D39A;--amber:#F3B44C;--bad:#F2726F}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);min-height:100vh;line-height:1.5;-webkit-font-smoothing:antialiased}
.bg{position:fixed;inset:0;z-index:-1;background:radial-gradient(900px 500px at 12% -5%,rgba(124,92,255,.20),transparent 60%),radial-gradient(800px 500px at 100% 110%,rgba(243,180,76,.10),transparent 55%)}
input,button,select{font:inherit}
input,select{width:100%;border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.05);color:var(--ink);padding:11px 12px;outline:0}
input:focus,select:focus{border-color:rgba(124,108,255,.55)}
button{border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.06);color:var(--ink);font-weight:700;cursor:pointer;padding:10px 15px;transition:.15s}
button:hover{background:rgba(255,255,255,.11)}
button.pri{border:0;background:linear-gradient(135deg,var(--g2),var(--g1));color:#fff}
button.pri:hover{filter:brightness(1.1)}
button.sm{padding:5px 10px;font-size:.76rem;font-weight:600}
button.danger{color:var(--bad);border-color:rgba(242,114,111,.35)}
.muted{color:var(--mut);font-size:.85rem}
.hide{display:none!important}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--g2),var(--g1));display:flex;align-items:center;justify-content:center;font-weight:900;color:#fff;flex-shrink:0}
.shell{display:flex;min-height:100vh}
.side{width:230px;flex-shrink:0;background:var(--bg2);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:16px 12px;position:sticky;top:0;height:100vh;overflow-y:auto}
.side .brand{display:flex;align-items:center;gap:10px;font-size:1.15rem;font-weight:800;padding:6px 8px 14px}
.side .brand .x{margin-left:auto;font-size:1.3rem;color:var(--mut);cursor:pointer;display:none}
.navgrp{font-size:.68rem;color:var(--mut);letter-spacing:.08em;padding:12px 10px 5px}
.navitem{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:10px;color:var(--mut);font-weight:600;cursor:pointer;font-size:.9rem;transition:.14s}
.navitem:hover{background:rgba(255,255,255,.05);color:var(--ink)}
.navitem.on{background:linear-gradient(135deg,rgba(109,94,252,.22),rgba(168,85,247,.16));color:#fff;box-shadow:inset 0 0 0 1px rgba(124,108,255,.3)}
.navitem .ni{font-size:1.05rem;width:20px;text-align:center}
.navitem .cnt{margin-left:auto;font-size:.75rem;color:var(--mut);font-variant-numeric:tabular-nums}
.navitem.on .cnt{color:#c9beff}
.sidefoot{margin-top:auto;padding-top:10px;border-top:1px solid var(--line)}
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:30;display:none}
.scrim.show{display:block}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;gap:12px;padding:14px 24px;border-bottom:1px solid var(--line);background:rgba(10,12,18,.6);backdrop-filter:blur(8px);position:sticky;top:0;z-index:6}
.topbar .burger{font-size:1.4rem;cursor:pointer;display:none;line-height:1}
.topbar .pt{font-size:1.15rem;font-weight:700}
.topbar .sp{margin-left:auto}
.uchip{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:999px;padding:6px 14px;font-size:.85rem;color:var(--mut)}
.uchip .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok)}
.content{padding:24px 32px;width:100%}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px}
.scard{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px 20px;display:flex;align-items:center;gap:15px;box-shadow:0 12px 40px rgba(0,0,0,.32)}
.scard .ico{width:52px;height:52px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;flex-shrink:0}
.scard .ico.i1{background:rgba(109,94,252,.16)}
.scard .ico.i2{background:rgba(52,211,154,.16)}
.scard .ico.i3{background:rgba(243,180,76,.16)}
.scard .ico.i4{background:rgba(168,85,247,.16)}
.scard .k{font-size:.8rem;color:var(--mut);margin-bottom:3px}
.scard .v{font-size:1.5rem;font-weight:800;font-variant-numeric:tabular-nums;line-height:1.1}
.panels{display:grid;grid-template-columns:1.618fr 1fr;gap:16px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px;box-shadow:0 12px 40px rgba(0,0,0,.32)}
.panel .ph{font-size:.95rem;font-weight:700;margin-bottom:16px}
.usebar{height:8px;background:rgba(255,255,255,.08);border-radius:5px;overflow:hidden}
.usebar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--g2),var(--g1));border-radius:5px}
.usebar>i.full{background:linear-gradient(90deg,#fb7185,#ef4444)}
.toprow{display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--line)}
.toprow:last-child{border-bottom:0}
.toprow .mono{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.toprow .tb{width:90px;flex-shrink:0}
.toprow .tv{width:74px;text-align:right;font-size:.8rem;color:var(--mut);font-variant-numeric:tabular-nums;flex-shrink:0}
.info{display:flex;justify-content:space-between;gap:12px;padding:9px 0;border-bottom:1px solid var(--line);font-size:.9rem}
.info:last-child{border-bottom:0}
.info .il{color:var(--mut)}
.ftool{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.ftitle{font-size:1.05rem;font-weight:700;margin-right:auto}
.srch{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.05);border:1px solid var(--line);border-radius:10px;padding:0 12px;min-width:170px}
.srch .si{color:var(--mut)}
.srch input{border:0;background:transparent;padding:9px 0}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{border:1px solid var(--line);border-radius:999px;padding:6px 12px;font-size:.8rem;background:rgba(255,255,255,.04);cursor:pointer;color:var(--mut)}
.chip.on{border-color:rgba(124,108,255,.55);background:rgba(124,108,255,.14);color:#c9beff}
.tblwrap{overflow-x:auto;border:1px solid var(--line);border-radius:14px}
table{width:100%;border-collapse:collapse;background:var(--card)}
th,td{padding:11px 12px;text-align:left;font-size:.84rem;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
th{color:var(--mut);font-weight:600;font-size:.76rem}
tr:last-child td{border-bottom:0}
tr:hover td{background:rgba(255,255,255,.02)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;color:#c9b8ff}
.badge{display:inline-block;font-size:.72rem;padding:2px 8px;border-radius:999px;border:1px solid var(--line)}
.badge.on{color:var(--ok);background:rgba(52,211,153,.1);border-color:rgba(52,211,153,.3)}
.badge.off{color:var(--bad);background:rgba(242,114,111,.1);border-color:rgba(242,114,111,.3)}
.badge.exp{color:var(--amber);background:rgba(243,180,76,.1);border-color:rgba(243,180,76,.3)}
.badge.tier{color:#a78bfa;background:rgba(124,92,255,.12);border-color:rgba(124,92,255,.35)}
.pbar{height:6px;border-radius:3px;background:rgba(255,255,255,.08);overflow:hidden;min-width:110px;margin-top:4px}
.pbar>i{display:block;height:100%;background:linear-gradient(90deg,var(--g2),var(--g1))}
.pbar>i.full{background:linear-gradient(90deg,#fb7185,#ef4444)}
.tacts{display:flex;gap:5px}
.empty{text-align:center;padding:50px 20px;color:var(--mut)}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:35;padding:16px}
.overlay.show{display:flex}
.modal{background:#0d0f16;border:1px solid var(--line);border-radius:16px;padding:22px;width:100%;max-width:420px;box-shadow:0 30px 80px rgba(0,0,0,.6)}
.modal h2{font-size:1.1rem;margin-bottom:12px}
.modal label{display:block;color:var(--mut);font-size:.8rem;margin:10px 0 5px}
.foot{display:flex;gap:10px;justify-content:flex-end;margin-top:18px}
.note{color:var(--mut);font-size:.82rem;white-space:pre-line}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);opacity:0;background:rgba(14,16,26,.95);border:1px solid var(--line);border-radius:12px;padding:12px 16px;transition:.2s;pointer-events:none;z-index:50}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(max-width:820px){
.cards{grid-template-columns:repeat(2,1fr)}
.panels{grid-template-columns:1fr}
.side{position:fixed;left:0;top:0;height:100vh;z-index:31;transform:translateX(-100%);transition:transform .22s;box-shadow:0 0 60px rgba(0,0,0,.6)}
.side.open{transform:translateX(0)}
.side .brand .x{display:block}
.topbar .burger{display:block}
.content{padding:16px}
.topbar{padding:12px 16px}
}
</style></head><body><div class="bg"></div>

<div id="appShell" class="shell">
  <div class="scrim" id="scrim"></div>
  <aside class="side" id="side">
    <div class="brand"><span class="logo">存</span>运营台<span class="x" id="sideClose">✕</span></div>
    <nav>
      <div class="navgrp">管理</div>
      <div class="navitem on" data-view="dash"><span class="ni">📊</span>概览</div>
      <div class="navitem" data-view="cust"><span class="ni">👥</span>客户管理<span class="cnt" id="navCnt"></span></div>
    </nav>
    <div class="sidefoot"><div class="navitem" id="refreshBtn"><span class="ni">🔄</span>刷新数据</div><div class="navitem" id="logoutBtn"><span class="ni">↩</span>退出</div></div>
  </aside>
  <div class="main">
    <header class="topbar"><span class="burger" id="burger">☰</span><div class="pt" id="pageTitle">概览</div><span class="sp"></span><div class="uchip"><span class="dot"></span>超级管理员</div></header>
    <div class="content">

      <div id="view-dash" class="view">
        <div class="cards">
          <div class="scard"><div class="ico i1">👥</div><div><div class="k">客户数</div><div class="v" id="sTotal">0</div></div></div>
          <div class="scard"><div class="ico i2">✅</div><div><div class="k">活跃</div><div class="v" id="sActive">0</div></div></div>
          <div class="scard"><div class="ico i3">🗂️</div><div><div class="k">文件总数</div><div class="v" id="sFiles">0</div></div></div>
          <div class="scard"><div class="ico i4">💾</div><div><div class="k">总用量</div><div class="v" id="sGB">0</div></div></div>
        </div>
        <div class="panels">
          <div class="panel"><div class="ph">存储占用 Top 5</div><div id="topBox"></div></div>
          <div class="panel"><div class="ph">套餐分布</div><div id="distBox"></div></div>
        </div>
      </div>

      <div id="view-cust" class="view hide">
        <div class="ftool">
          <span class="ftitle">客户管理</span>
          <div class="srch"><span class="si">🔍</span><input id="q" placeholder="搜索卡号"></div>
          <div class="chips" id="chips"></div>
        </div>
        <div class="tblwrap"><table><thead><tr><th>#</th><th>卡号</th><th>档位</th><th>用量 / 容量</th><th>文件</th><th>到期</th><th>状态</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table></div>
        <div id="empty" class="empty hide">没有匹配的客户</div>
      </div>

    </div>
  </div>
</div>

<div class="overlay" id="loginOverlay"><div class="modal">
  <h2>运营台登录</h2><label>管理密钥（ADMIN_KEY）</label><input id="akey" type="password" placeholder="输入管理密钥">
  <div class="foot"><button class="pri" id="loginBtn" style="width:100%">进入</button></div>
  <div class="note" id="loginErr" style="color:var(--bad);min-height:18px;margin-top:8px"></div>
</div></div>
<div class="overlay" id="editOverlay"><div class="modal">
  <h2>改客户</h2><div class="note" id="editWho" style="margin-bottom:6px"></div>
  <label>套餐（改档位会套用该档默认容量）</label><select id="eTier"><option value="">不改</option><option value="basic">存链-基础</option><option value="pro">存链-专业</option></select>
  <label>容量上限（GB，留空=不改）</label><input id="eGB" type="number" placeholder="如 5 / 50 / 100">
  <label>到期日（留空=不改）</label><input id="eDate" type="date">
  <div class="foot"><button id="editCancel">取消</button><button class="pri" id="editSave">保存</button></div>
</div></div>
<div class="overlay" id="confirmOverlay"><div class="modal">
  <h2>请确认</h2><div class="note" id="confirmMsg" style="margin-bottom:14px"></div>
  <div class="foot"><button id="confirmNo">取消</button><button class="pri danger" id="confirmYes">确认</button></div>
</div></div>
<div class="toast" id="toast"></div>
<script>
var AK=sessionStorage.getItem("tuku_ak")||"",LIST=[],STATS=null,VIEW="dash",editId=null,_cf=null,Q="",FILT="all";
function $(id){return document.getElementById(id)}
function show(id){$(id).classList.add("show")}
function hide(id){$(id).classList.remove("show")}
function toast(m){var t=$("toast");t.textContent=m;t.classList.add("show");setTimeout(function(){t.classList.remove("show")},2200)}
function esc(s){return String(s==null?"":s).replace(/[<>&]/g,function(c){return c==="<"?"&lt;":c===">"?"&gt;":"&amp;"})}
function fmtSize(b){b=Number(b)||0;if(b<1024)return b+" B";if(b<1048576)return (b/1024).toFixed(1)+" KB";if(b<1073741824)return (b/1048576).toFixed(1)+" MB";return (b/1073741824).toFixed(2)+" GB"}
function api(p,o){o=o||{};o.headers=Object.assign({"x-admin-key":AK},o.headers||{});return fetch("/api/admin"+p,o).then(function(r){return r.json().then(function(d){if(r.status===401){sessionStorage.removeItem("tuku_ak");AK="";show("loginOverlay");throw new Error(d.error||"未授权")}if(!r.ok)throw new Error(d.error||("HTTP "+r.status));return d})})}
function uiConfirm(m){return new Promise(function(res){$("confirmMsg").textContent=m;_cf=res;show("confirmOverlay")})}
function byId(id){for(var i=0;i<LIST.length;i++)if(String(LIST[i].id)===String(id))return LIST[i];return null}
function statusOf(c){if(c.status!=="active")return"disabled";if(c.expiresAt&&new Date(c.expiresAt)<new Date())return"expired";return"active"}
$("confirmYes").onclick=function(){hide("confirmOverlay");var r=_cf;_cf=null;if(r)r(true)};
$("confirmNo").onclick=function(){hide("confirmOverlay");var r=_cf;_cf=null;if(r)r(false)};
$("loginBtn").onclick=function(){AK=$("akey").value.trim();sessionStorage.setItem("tuku_ak",AK);hide("loginOverlay");$("loginErr").textContent="";load()};
$("akey").addEventListener("keydown",function(e){if(e.key==="Enter")$("loginBtn").click()});
$("logoutBtn").onclick=function(){sessionStorage.removeItem("tuku_ak");AK="";show("loginOverlay")};
$("refreshBtn").onclick=function(){load();toast("已刷新")};
$("editCancel").onclick=function(){hide("editOverlay")};
$("editSave").onclick=doEdit;
$("q").addEventListener("input",function(){Q=this.value;renderCust()});
var navItems=document.querySelectorAll(".navitem[data-view]");
for(var ni=0;ni<navItems.length;ni++){navItems[ni].addEventListener("click",function(){showView(this.getAttribute("data-view"))})}
function showView(v){
  VIEW=v;closeDrawer();
  $("view-dash").classList.toggle("hide",v!=="dash");
  $("view-cust").classList.toggle("hide",v!=="cust");
  $("pageTitle").textContent=v==="dash"?"概览":"客户管理";
  var it=document.querySelectorAll(".navitem[data-view]");for(var i=0;i<it.length;i++)it[i].classList.toggle("on",it[i].getAttribute("data-view")===v);
  if(v==="cust")renderCust();
}
function load(){api("/customers").then(function(d){LIST=d.customers||[];STATS=d.stats;renderDash();renderChips();renderCust();$("navCnt").textContent=d.stats.total}).catch(function(e){var msg=e.message||"";if(msg.indexOf("授权")>=0||msg.indexOf("密钥")>=0){show("loginOverlay");$("loginErr").textContent=AK?"密钥不正确":""}else toast(msg)})}
function renderDash(){
  var s=STATS;$("sTotal").textContent=s.total;$("sActive").textContent=s.active;$("sFiles").textContent=s.totalFiles;$("sGB").textContent=s.totalGB;
  var top=LIST.slice().sort(function(a,b){return (b.usedBytes||0)-(a.usedBytes||0)}).slice(0,5);
  var tb=$("topBox");tb.innerHTML="";
  if(!top.length||!top[0].usedBytes){tb.innerHTML="<div class='muted'>还没有用量数据</div>"}
  else{top.forEach(function(c){var pct=c.byteLimit?Math.min(100,Math.round(c.usedBytes/c.byteLimit*100)):0;var d=document.createElement("div");d.className="toprow";d.innerHTML="<span class='mono'>"+esc(c.card)+"</span><span class='tb'><span class='pbar'><i class='"+(pct>=100?"full":"")+"' style='width:"+pct+"%'></i></span></span><span class='tv'>"+fmtSize(c.usedBytes)+"</span>";tb.appendChild(d)})}
  var basic=LIST.filter(function(c){return c.tier==="basic"}).length,pro=LIST.filter(function(c){return c.tier==="pro"}).length,tot=basic+pro||1;
  var db=$("distBox");db.innerHTML="";
  var mk=function(label,n,color){var pc=Math.round(n/tot*100);var d=document.createElement("div");d.style.marginBottom="14px";d.innerHTML="<div style='display:flex;justify-content:space-between;font-size:.85rem;margin-bottom:6px'><span>"+label+"</span><span class='muted'>"+n+" 个 · "+pc+"%</span></div><div class='usebar'><i style='width:"+pc+"%;background:"+color+"'></i></div>";db.appendChild(d)};
  mk("存链-基础",basic,"linear-gradient(90deg,#6d5efc,#a855f7)");
  mk("存链-专业",pro,"linear-gradient(90deg,#34D39A,#5DCAA5)");
}
function renderChips(){
  var defs=[["all","全部"],["active","正常"],["disabled","停服"],["expired","到期"]];
  var box=$("chips");box.innerHTML="";
  defs.forEach(function(df){var n=df[0]==="all"?LIST.length:LIST.filter(function(c){return statusOf(c)===df[0]}).length;var s=document.createElement("span");s.className="chip"+(FILT===df[0]?" on":"");s.textContent=df[1]+" "+n;s.onclick=function(){FILT=df[0];renderChips();renderCust()};box.appendChild(s)});
}
function renderCust(){
  var q=Q.toLowerCase();
  var arr=LIST.filter(function(c){
    if(FILT!=="all"&&statusOf(c)!==FILT)return false;
    if(q&&String(c.card||"").toLowerCase().indexOf(q)<0)return false;
    return true;
  });
  $("empty").classList.toggle("hide",arr.length>0);
  $("rows").innerHTML=arr.map(function(c){
    var pct=c.byteLimit?Math.min(100,Math.round(c.usedBytes/c.byteLimit*100)):0;
    var stt=statusOf(c);
    var st=stt==="disabled"?"<span class='badge off'>已停服</span>":stt==="expired"?"<span class='badge exp'>已到期</span>":"<span class='badge on'>正常</span>";
    return "<tr><td>"+c.id+"</td><td class='mono'>"+esc(c.card)+"</td>"+
      "<td><span class='badge tier'>"+esc(c.tierLabel)+"</span></td>"+
      "<td>"+c.usedGB+" / "+c.limitGB+"<div class='pbar'><i class='"+(pct>=100?"full":"")+"' style='width:"+pct+"%'></i></div></td>"+
      "<td>"+c.files+"</td><td>"+(c.expiresAt?c.expiresAt.slice(0,10):"永久")+"</td><td>"+st+"</td>"+
      "<td><div class='tacts'><button class='sm' data-a='edit' data-id='"+c.id+"'>改</button>"+
      (c.status==="active"?"<button class='sm danger' data-a='off' data-id='"+c.id+"'>停服</button>":"<button class='sm' data-a='on' data-id='"+c.id+"'>恢复</button>")+
      "<button class='sm danger' data-a='del' data-id='"+c.id+"'>删除</button></div></td></tr>";
  }).join("");
}
$("rows").addEventListener("click",function(e){
  var b=e.target.closest?e.target.closest("button[data-a]"):null;if(!b)return;
  var c=byId(b.getAttribute("data-id")),a=b.getAttribute("data-a");if(!c)return;
  if(a==="edit")openEdit(c);else if(a==="off")toggle(c,"disabled");else if(a==="on")toggle(c,"active");else if(a==="del")del(c);
});
function toggle(c,st){api("/customers/"+c.id,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({status:st})}).then(function(){toast(st==="active"?"已恢复":"已停服");load()}).catch(function(e){toast(e.message)})}
function del(c){uiConfirm("确认删除客户 "+c.card+"？\\n他的所有文件("+c.files+"个)和记录都会被清除，不可恢复。").then(function(ok){if(!ok)return;api("/customers/"+c.id,{method:"DELETE"}).then(function(){toast("已删除");load()}).catch(function(e){toast(e.message)})})}
function openEdit(c){editId=c.id;$("editWho").textContent=c.card+"（"+c.tierLabel+"）";$("eTier").value="";$("eGB").value="";$("eDate").value=c.expiresAt?c.expiresAt.slice(0,10):"";show("editOverlay")}
function doEdit(){
  var body={},t=$("eTier").value,gb=$("eGB").value.trim(),dt=$("eDate").value;
  if(t)body.tier=t;if(gb)body.byteLimit=Math.round(Number(gb)*1073741824);if(dt)body.expiresAt=dt+"T23:59:59";
  if(!Object.keys(body).length){toast("没改动");return}
  api("/customers/"+editId,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)}).then(function(){hide("editOverlay");toast("已保存");load()}).catch(function(e){toast(e.message)});
}
$("burger").addEventListener("click",openDrawer);
$("sideClose").addEventListener("click",closeDrawer);
$("scrim").addEventListener("click",closeDrawer);
function openDrawer(){$("side").classList.add("open");$("scrim").classList.add("show")}
function closeDrawer(){$("side").classList.remove("open");$("scrim").classList.remove("show")}
["loginOverlay","editOverlay","confirmOverlay"].forEach(function(id){$(id).addEventListener("click",function(e){if(e.target===this&&id!=="loginOverlay")this.classList.remove("show")})});
document.addEventListener("keydown",function(e){if(e.key==="Escape"){hide("editOverlay");hide("confirmOverlay");closeDrawer()}});
if(AK)load();else show("loginOverlay");
</script></body></html>`;
