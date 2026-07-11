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
  basic: { byteLimit: 5 * GB, label: "图床-基础" },
  pro: { byteLimit: 50 * GB, label: "图床-专业" },
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

      // 以下都要登录
      const auth = await requireCustomer(request, env);
      if (auth.error) return auth.error;
      const customer = auth.customer;

      if (request.method === "GET" && path === "/api/me") return handleMe(request, env, customer);
      if (request.method === "POST" && path === "/api/upload") return await handleUpload(request, env, customer);
      if (request.method === "GET" && path === "/api/list") return handleList(request, env, customer, url);
      if (request.method === "GET" && path === "/api/albums") return handleAlbums(request, env, customer);
      if (request.method === "POST" && path === "/api/albums") return handleCreateAlbum(request, env, customer);

      let m;
      if ((m = path.match(/^\/api\/img\/(\d+)$/)) && request.method === "DELETE") return handleDeleteImg(request, env, customer, Number(m[1]));
      if ((m = path.match(/^\/api\/img\/(\d+)\/album$/)) && request.method === "POST") return handleMoveImg(request, env, customer, Number(m[1]));
      if ((m = path.match(/^\/api\/albums\/(\d+)$/)) && request.method === "DELETE") return handleDeleteAlbum(request, env, customer, Number(m[1]));

      return json({ error: "not_found" }, 404);
    } catch (err) {
      console.log("tuku error: " + (err && err.message ? err.message : err));
      return json({ error: "服务器繁忙，请稍后重试" }, 500);
    }
  },
};

/* ---------- 前端页面 ---------- */
const PAGE_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>图床</title><style>
:root{--bg:#090a0f;--card:#0e1017;--ink:#EEF1F7;--mut:#99A2B4;--line:rgba(255,255,255,.09);--g1:#a855f7;--g2:#6d5efc;--ok:#34D39A;--bad:#F2726F}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);min-height:100vh;line-height:1.5}
.bg{position:fixed;inset:0;z-index:-1;background:radial-gradient(circle at 0% 0%,rgba(124,92,255,.28),transparent 34%),radial-gradient(circle at 100% 100%,rgba(45,212,191,.16),transparent 34%)}
.wrap{max-width:1040px;margin:0 auto;padding:24px}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:20px;flex-wrap:wrap}
h1{font-size:1.4rem;display:flex;align-items:center;gap:10px}
.logo{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,var(--g2),var(--g1));display:flex;align-items:center;justify-content:center;font-weight:900;color:#fff}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px;box-shadow:inset 0 1px 0 rgba(255,255,255,.04),0 20px 60px rgba(0,0,0,.5)}
input,button,select{font:inherit}
input,select{width:100%;border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.05);color:var(--ink);padding:12px 13px;outline:0}
input:focus,select:focus{border-color:rgba(124,108,255,.55)}
button{border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.06);color:var(--ink);font-weight:700;cursor:pointer;padding:11px 16px;transition:.15s}
button:hover{background:rgba(255,255,255,.11)}
button.pri{border:0;background:linear-gradient(135deg,var(--g2),var(--g1));color:#fff}
button.pri:hover{filter:brightness(1.12)}
button.sm{padding:6px 10px;font-size:.8rem}
button.danger{color:var(--bad);border-color:rgba(242,114,111,.35)}
.muted{color:var(--mut);font-size:.85rem}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.hide{display:none!important}
.login{max-width:400px;margin:8vh auto}
.login .card>*+*{margin-top:12px}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
.pill{border:1px solid var(--line);border-radius:999px;padding:6px 12px;font-size:.82rem;background:rgba(255,255,255,.04);cursor:pointer}
.pill.on{border-color:rgba(124,108,255,.55);background:rgba(124,108,255,.12)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.tile img{width:100%;height:120px;object-fit:cover;display:block;background:#000}
.filebox{height:120px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;padding:8px;background:#0a0b10}
.ficon{font-size:2.4rem;line-height:1}
.fname{font-size:.72rem;color:var(--mut);text-align:center;word-break:break-all;max-height:2.3em;overflow:hidden}
.dlbtn{text-decoration:none;text-align:center;line-height:1.9;display:inline-block}
.tile .act{display:flex;gap:6px;padding:8px;flex-wrap:wrap}
.drop{border:2px dashed var(--line);border-radius:14px;padding:26px;text-align:center;color:var(--mut);cursor:pointer;margin-bottom:16px}
.drop.on{border-color:var(--g2);background:rgba(124,108,255,.06)}
.setbar{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:12px;color:var(--mut);font-size:.85rem}
.setbar .chk{display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none}
.setbar input[type=text],.setbar input:not([type]){padding:8px 10px}
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
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);opacity:0;background:rgba(14,16,26,.95);border:1px solid var(--line);border-radius:12px;padding:12px 16px;transition:.2s;pointer-events:none;z-index:9}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
</style></head><body><div class="bg"></div>
<div class="wrap">
  <div class="top"><h1><span class="logo">图</span>图床</h1><div id="who" class="muted"></div></div>

  <div id="loginView" class="login"><div class="card">
    <h2 style="font-size:1.1rem">登录 / 开通</h2>
    <div class="muted">第一次用：输入卡号 + 给自己设个密码，即完成开通。以后凭卡号+密码登录。</div>
    <input id="card" placeholder="卡号 CM-XXXX-XXXX-XXXX" autocomplete="off">
    <input id="pw" type="password" placeholder="访问密码（至少4位）">
    <button class="pri" id="loginBtn" style="width:100%">进入</button>
    <div id="loginErr" class="muted" style="color:var(--bad);min-height:20px"></div>
  </div></div>

  <div id="appView" class="hide">
    <div class="setbar">
      <label class="chk"><input type="checkbox" id="cmp" checked> 图片上传前压缩（省空间/更快）</label>
      <input id="wm" placeholder="水印文字（留空=无，仅加在图片上）" style="max-width:240px">
    </div>
    <div class="drop" id="drop">拖文件到这里，或点击选择（图片/视频/音频/PDF/压缩包… 可多选）<input id="file" type="file" multiple class="hide"></div>
    <div id="progress" class="prog hide"></div>
    <div class="bar" id="albumBar"></div>
    <div class="grid" id="grid"></div>
    <div id="empty" class="muted hide" style="text-align:center;padding:40px">这个相册还没有图片</div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
var TOKEN=sessionStorage.getItem("tuku_token")||"";
var CUR_ALBUM="all";
var ALBUMS=[];
function $(id){return document.getElementById(id)}
function toast(m){var t=$("toast");t.textContent=m;t.classList.add("show");setTimeout(function(){t.classList.remove("show")},2200)}
function esc(s){return String(s==null?"":s).replace(/[<>&]/g,function(c){return c==="<"?"&lt;":c===">"?"&gt;":"&amp;"})}
function fileIcon(im){var m=String(im.mime||"");if(m.indexOf("video")===0)return"🎬";if(m.indexOf("audio")===0)return"🎵";if(m.indexOf("pdf")>=0)return"📄";if(/zip|rar|7z|compress|tar/.test(m))return"🗜️";return"📎"}
function api(path,opts){opts=opts||{};opts.headers=Object.assign({authorization:"Bearer "+TOKEN},opts.headers||{});return fetch(path,opts).then(function(r){return r.json().then(function(d){if(r.status===401){logout();throw new Error(d.error||"未登录")}if(!r.ok)throw new Error(d.error||("HTTP "+r.status));return d})})}
function logout(){sessionStorage.removeItem("tuku_token");TOKEN="";$("appView").classList.add("hide");$("loginView").classList.remove("hide");$("who").textContent=""}
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
function enterApp(){$("loginView").classList.add("hide");$("appView").classList.remove("hide");loadMe();loadAlbums().then(loadImages)}
function loadMe(){api("/api/me").then(function(d){$("who").textContent=d.tierLabel+" · 已用 "+d.usedGB+"/"+d.limitGB+"（"+d.count+" 个）"+(d.expiresAt?" · 到期 "+d.expiresAt.slice(0,10):"")}).catch(function(){})}
function loadAlbums(){return api("/api/albums").then(function(d){ALBUMS=d.albums||[];renderAlbumBar()})}
function renderAlbumBar(){
  var bar=$("albumBar");bar.innerHTML="";
  var mk=function(key,label){var p=document.createElement("span");p.className="pill"+(CUR_ALBUM==key?" on":"");p.textContent=label;p.onclick=function(){CUR_ALBUM=key;renderAlbumBar();loadImages()};return p};
  bar.appendChild(mk("all","全部"));
  bar.appendChild(mk("none","未分组"));
  ALBUMS.forEach(function(a){var p=mk(String(a.id),a.name+"("+a.count+")");bar.appendChild(p)});
  var add=document.createElement("button");add.className="sm";add.textContent="+ 新建相册";add.onclick=newAlbum;bar.appendChild(add);
  if(CUR_ALBUM!=="all"&&CUR_ALBUM!=="none"){var del=document.createElement("button");del.className="sm danger";del.textContent="删除本相册";del.onclick=function(){delAlbum(CUR_ALBUM)};bar.appendChild(del)}
}
function newAlbum(){var name=prompt("相册名字");if(!name)return;api("/api/albums",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:name})}).then(function(){loadAlbums()}).catch(function(e){toast(e.message,true)})}
function delAlbum(id){if(!confirm("删除相册？里面的图会变成未分组，不会删图。"))return;api("/api/albums/"+id,{method:"DELETE"}).then(function(){CUR_ALBUM="all";loadAlbums().then(loadImages)}).catch(function(e){toast(e.message)})}
function loadImages(){
  var q=CUR_ALBUM==="all"?"":(CUR_ALBUM==="none"?"?album_id=none":"?album_id="+CUR_ALBUM);
  api("/api/list"+q).then(function(d){
    var g=$("grid");g.innerHTML="";
    if(!d.images.length){$("empty").classList.remove("hide")}else{$("empty").classList.add("hide")}
    d.images.forEach(function(im){
      var t=document.createElement("div");t.className="tile";
      if(im.kind==="image"){var img=document.createElement("img");img.src=im.thumb;img.loading="lazy";t.appendChild(img);}
      else{var fb=document.createElement("div");fb.className="filebox";fb.innerHTML="<div class='ficon'>"+fileIcon(im)+"</div><div class='fname'>"+esc(im.filename||"文件")+"</div>";t.appendChild(fb);}
      var act=document.createElement("div");act.className="act";
      var copy=document.createElement("button");copy.className="sm";copy.textContent="复制链接";copy.onclick=function(){navigator.clipboard.writeText(im.link).then(function(){toast("链接已复制")})};
      act.appendChild(copy);
      if(im.kind==="file"){var dl=document.createElement("a");dl.className="sm dlbtn";dl.textContent="下载";dl.href=im.link+"?dl=1";act.appendChild(dl);}
      var mv=document.createElement("button");mv.className="sm";mv.textContent="移动";mv.onclick=function(){moveImg(im.id)};act.appendChild(mv);
      var del=document.createElement("button");del.className="sm danger";del.textContent="删除";del.onclick=function(){delImg(im.id)};act.appendChild(del);
      t.appendChild(act);g.appendChild(t);
    });
  }).catch(function(e){toast(e.message)});
}
function delImg(id){if(!confirm("删除这张图？不可恢复。"))return;api("/api/img/"+id,{method:"DELETE"}).then(function(){toast("已删除");loadAlbums().then(loadImages)}).catch(function(e){toast(e.message)})}
function moveImg(id){
  var names=["未分组"].concat(ALBUMS.map(function(a){return a.name}));
  var pick=prompt("移到哪个相册？输入序号：\\n0=未分组"+ALBUMS.map(function(a,i){return "\\n"+(i+1)+"="+a.name}).join(""));
  if(pick===null)return;var idx=Number(pick);
  var albumId=idx===0?null:(ALBUMS[idx-1]?ALBUMS[idx-1].id:undefined);
  if(albumId===undefined)return toast("序号不对");
  api("/api/img/"+id+"/album",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({album_id:albumId})}).then(function(){toast("已移动");loadAlbums().then(loadImages)}).catch(function(e){toast(e.message)});
}
var drop=$("drop"),fileInput=$("file");
drop.addEventListener("click",function(){fileInput.click()});
fileInput.addEventListener("change",function(){uploadFiles(fileInput.files);fileInput.value=""});
drop.addEventListener("dragover",function(e){e.preventDefault();drop.classList.add("on")});
drop.addEventListener("dragleave",function(){drop.classList.remove("on")});
drop.addEventListener("drop",function(e){e.preventDefault();drop.classList.remove("on");uploadFiles(e.dataTransfer.files)});
// 客户端压缩图片（canvas 缩放 + 可选水印）。非图片/GIF 原样返回。
function compressImage(file,maxDim,quality,wm){
  return new Promise(function(resolve){
    if(!/^image\//.test(file.type)||file.type==="image/gif"){resolve(file);return}
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
        resolve(new File([b],file.name.replace(/\.(png|webp|bmp|jpeg)$/i,".jpg"),{type:"image/jpeg"}));
      },"image/jpeg",quality);
    };
    img.onerror=function(){URL.revokeObjectURL(url);resolve(file)};
    img.src=url;
  });
}
// 带进度的上传（XHR）
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
function uploadFiles(files){
  files=Array.prototype.slice.call(files||[]);if(!files.length)return;
  var pc=$("progress");pc.classList.remove("hide");pc.innerHTML="";
  var doCompress=$("cmp").checked,wm=$("wm").value.trim();
  var albumId=(CUR_ALBUM!=="all"&&CUR_ALBUM!=="none")?CUR_ALBUM:null;
  var done=0,fail=0;
  var runOne=function(i){
    if(i>=files.length){toast("完成 "+done+" 个"+(fail?("，失败 "+fail):""));loadMe();loadAlbums().then(loadImages);setTimeout(function(){if(!fail)pc.classList.add("hide")},1600);return}
    var f=files[i];
    var item=document.createElement("div");item.className="pitem";
    item.innerHTML="<div class='pn'><span>"+esc(f.name)+"</span><span class='pct'>0%</span></div><div class='pbar'><i></i></div>";
    pc.appendChild(item);
    var bar=item.querySelector("i"),pct=item.querySelector(".pct");
    (doCompress?compressImage(f,2560,0.85,wm):Promise.resolve(f)).then(function(uf){
      return xhrUpload(uf,albumId,function(p){var v=Math.round(p*100);bar.style.width=v+"%";pct.textContent=v+"%"});
    }).then(function(){done++;item.classList.add("done");pct.textContent="完成"}).catch(function(e){fail++;item.classList.add("err");pct.textContent=e.message}).then(function(){runOne(i+1)});
  };
  toast("上传中…");runOne(0);
}
if(TOKEN)enterApp();
</script></body></html>`;
