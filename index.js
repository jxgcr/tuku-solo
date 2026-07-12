// 存链 tuku Worker — 多租户文件/图片托管 SaaS
// 账号 Hannah；图片存 Cloudflare Images；非图片存 R2；元数据存 D1(DB)；卡密来自畅密(changmi)
// 获客：/ 落地页 + 免费档(无卡密,500MB,限注册) + 开发者 API(/api/v1/upload, PicGo/Lsky 兼容, 付费档)
// 机密(wrangler secret)：CF_IMAGES_TOKEN、SESSION_SECRET、APP_KEY_TU_BASIC、APP_KEY_TU_PRO
// 配置(wrangler vars)：BUY_URL(购买入口)、FREE_SIGNUP_MAX/WINDOW(免费限注册)
const VERSION = "tuku-v1-20260712";
const MAX_SIZE = 10 * 1024 * 1024; // CF Images 图片单张上限 10MB
const MAX_FILE = 100 * 1024 * 1024; // 非图片单文件上限 100MB（更大走直传，二期再说）
const GB = 1073741824;
const DEFAULT_SESSION_TTL = 7 * 24 * 3600;
// 档位：容量上限（字节）。价格是运营侧的事，这里只管容量闸。改档位改这里重新部署。
// free = 获客免费档：无需卡密，填密码即生成账号；容量小、图片强制品牌水印、按 IP 限注册防薅。
const TIERS = {
  free: { byteLimit: 500 * 1024 * 1024, label: "存链-免费" },
  basic: { byteLimit: 5 * GB, label: "存链-基础" },
  pro: { byteLimit: 50 * GB, label: "存链-专业" },
};
// 对外购买/续费/升级入口。对外一律走 aistela.com 子域，绝不暴露内部 .5209696.xyz 域。
// 可配置：改 wrangler.jsonc 的 vars.BUY_URL 即可，不用动代码。子域的反代/发卡页在门面侧另配。
function buyUrl(env) { return (env && env.BUY_URL) || "https://pay.aistela.com"; }
function imgThumb(env, cfId) { return "https://imagedelivery.net/" + env.IMAGES_HASH + "/" + cfId + "/public"; }
function fmtGB(b) { const g = Number(b) / GB; return (g >= 10 || g === Math.floor(g) ? g.toFixed(0) : g.toFixed(1)) + "GB"; }
function safeName(n) { return String(n || "file").replace(/[^\w.\-]/g, "_").slice(-80) || "file"; }

/* ---------- 基础工具 ---------- */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}
function htmlResponse(body, env) {
  // 每次请求生成随机 nonce，注入 <script nonce> 并写进 CSP，从而去掉 script-src 的 'unsafe-inline'
  // （脚本仍内联，不拆文件、无缓存坑；页面 no-store 不缓存，nonce 逐请求刷新）。
  const nonce = btoa(String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(16)))).replace(/[+/=]/g, "");
  const html = String(body).split("__CSP_NONCE__").join(nonce).split("__BUY_URL__").join(buyUrl(env)).split("__TURNSTILE_SITE__").join(env.TURNSTILE_SITE_KEY || "");
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      // 放行 Cloudflare Turnstile（人机验证）的脚本/iframe/连接
      "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-" + nonce + "' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://imagedelivery.net; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; base-uri 'none'; form-action 'self'; object-src 'none'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
    },
  });
}
function clientIp(request) {
  return request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "0.0.0.0";
}
// 购买页 /buy：手动收款(自己的微信/支付宝码)。收款码/价格/联系方式全走 wrangler vars，改配置不动代码。
// 单独的响应构造：CSP 放开 img-src 到 https:，好让收款码图片(不管你传哪)都能显示。
function payVar(env, k, d) { return (env && env[k]) ? String(env[k]) : d; }
function buyPageResponse(env) {
  const nonce = btoa(String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(16)))).replace(/[+/=]/g, "");
  const rep = {
    "__CSP_NONCE__": nonce,
    "__PAY_WX_QR__": payVar(env, "PAY_WX_QR", ""),
    "__PAY_ALI_QR__": payVar(env, "PAY_ALI_QR", ""),
    "__PAY_CONTACT__": payVar(env, "PAY_CONTACT", "（运营者未设置联系方式）"),
    "__PRICE_BASIC__": payVar(env, "PRICE_BASIC", "联系客服"),
    "__PRICE_PRO__": payVar(env, "PRICE_PRO", "联系客服"),
    "__PUBLIC_BASE__": env.PUBLIC_BASE || "",
  };
  let html = BUY_HTML;
  for (const k in rep) html = html.split(k).join(rep[k]);
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; connect-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none'",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
    },
  });
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
// 文件直链防枚举：/f/<id> 用数字主键会被人 1,2,3… 遍历下载所有客户文件。
// 给每个 id 派生一个 HMAC 短令牌，直链写成 /f/<id>~<token>，无令牌或不匹配一律 404。现算，不改库。
async function fileToken(env, id) {
  return b64u(await hmac(env.SESSION_SECRET, "file:" + id)).slice(0, 24);
}
async function fileLink(env, id) {
  return (env.PUBLIC_BASE || "") + "/f/" + id + "~" + (await fileToken(env, id));
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
// 带超时的 fetch：上游(畅密/CF Images)慢响应时不拖垮整个请求到 Worker 上限
async function fetchT(url, init, ms) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms || 8000);
  try { return await fetch(url, { ...(init || {}), signal: ctl.signal }); }
  finally { clearTimeout(t); }
}
function imagesBase(env) {
  return "https://api.cloudflare.com/client/v4/accounts/" + (env.ACCOUNT_ID) + "/images/v1";
}
async function imagesApi(env, path, init = {}) {
  const headers = { authorization: "Bearer " + env.CF_IMAGES_TOKEN, ...(init.headers || {}) };
  let res;
  try { res = await fetchT(imagesBase(env) + path, { ...init, headers }, 20000); }
  catch (e) { return { success: false, errors: [{ message: "图片服务超时，请重试" }] }; }
  const data = await res.json().catch(() => ({ success: false, errors: [{ message: "Images API invalid JSON" }] }));
  if (!res.ok && data.success !== false) data.success = false;
  return data;
}
// 调畅密验卡：返回 { valid, status, expires_at?, duration_days? }
async function changmiVerify(env, card, appKey) {
  if (!appKey) return { valid: false, status: 0 };
  try {
    const res = await fetchT(env.CHANGMI_URL.replace(/\/+$/, "") + "/api/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: card, app_key: appKey }),
    }, 8000);
    const data = await res.json().catch(() => ({}));
    return { valid: res.ok && data.valid === true, status: res.status, expires_at: data.expires_at, duration_days: data.duration_days };
  } catch (e) {
    return { valid: false, status: 0 };
  }
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

  const existing = await getCustomerByCard(env, card);
  if (existing) {
    // 先验密码再看账号状态：停用/到期只对“知道密码的本人”暴露，不给枚举者辨识
    if (!(await verifyPassword(password, existing.password_hash))) return json({ error: "卡号或密码不正确" }, 401);
    if (!customerActive(existing)) return json({ error: "账号已停用或到期" }, 403);
    const token = await signSession(env, existing.id, card);
    return json({ ok: true, token, tier: existing.tier });
  }

  // 弱口令统一按 401 前置返回：不区分“无效卡 / 有效未开通卡”，杜绝用短密码枚举有效卡（提示交前端）
  if (password.length < 8) return json({ error: "卡号或密码不正确" }, 401);

  // 首次：验卡开通（逐档试，畅密对不匹配的 app_key 返回 404）
  let tier = null, expiresAt = null;
  const basic = await changmiVerify(env, card, env.APP_KEY_TU_BASIC);
  if (basic.valid) { tier = "basic"; expiresAt = basic.expires_at || null; }
  else if (basic.status !== 404 && basic.status !== 0) return json({ error: "卡号或密码不正确" }, 401);
  else {
    const pro = await changmiVerify(env, card, env.APP_KEY_TU_PRO);
    if (pro.valid) { tier = "pro"; expiresAt = pro.expires_at || null; }
    else return json({ error: "卡号或密码不正确" }, 401);
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
// 上传核心：图片→CF Images、其它→R2，含大小闸/配额闸/并发 TOCTOU 复核回滚/写库失败回滚。
// web 端与开发者 API 共用同一套逻辑。返回 { record } 或 { error, status }。
async function storeUpload(env, customer, file, albumId) {
  const isImage = String(file.type || "").startsWith("image/");
  if (isImage && file.size > MAX_SIZE) return { error: "图片单张超过 10MB", status: 413 };
  if (!isImage && file.size > MAX_FILE) return { error: "单个文件超过 100MB 上限", status: 413 };
  const usedBytes = await usedBytesOf(env, customer.id);
  if (usedBytes + file.size > customer.byte_limit) {
    return { error: "容量不足（上限 " + fmtGB(customer.byte_limit) + "，已用 " + fmtGB(usedBytes) + "），请删文件或升级", status: 402 };
  }
  const now = Math.floor(Date.now() / 1000);
  if (isImage) {
    const fd = new FormData();
    fd.append("file", file, file.name || "upload.png");
    fd.append("requireSignedURLs", "false");
    fd.append("metadata", JSON.stringify({ owner: String(customer.id) }));
    const data = await imagesApi(env, "", { method: "POST", body: fd });
    if (!data.success) return { error: (data.errors && data.errors[0] && data.errors[0].message) || "图片上传失败", status: 502 };
    const cfId = data.result.id;
    try {
      const ins = await env.DB.prepare(
        "INSERT INTO images (customer_id, album_id, kind, cf_id, filename, mime, bytes, uploaded_at) VALUES (?,?,'image',?,?,?,?,?)"
      ).bind(customer.id, albumId, cfId, file.name || "", file.type || "image/*", file.size, now).run();
      if ((await usedBytesOf(env, customer.id)) > customer.byte_limit) {
        try { await imagesApi(env, "/" + encodeURIComponent(cfId), { method: "DELETE" }); } catch (e2) { await recordPending(env, "image", cfId); }
        await env.DB.prepare("DELETE FROM images WHERE id=? AND customer_id=?").bind(ins.meta.last_row_id, customer.id).run();
        return { error: "容量不足（上限 " + fmtGB(customer.byte_limit) + "），请删文件或升级", status: 402 };
      }
      return { record: { id: ins.meta.last_row_id, kind: "image", cf_id: cfId, r2_key: null, filename: file.name || "", mime: file.type || "image/*", bytes: file.size } };
    } catch (e) {
      try { await imagesApi(env, "/" + encodeURIComponent(cfId), { method: "DELETE" }); } catch (e2) { await recordPending(env, "image", cfId); }
      console.log("image insert fail, rolled back: " + (e && e.message ? e.message : e));
      return { error: "上传失败，请重试", status: 502 };
    }
  }
  // 非图片 → R2
  const key = customer.id + "/" + crypto.randomUUID() + "-" + safeName(file.name);
  try {
    const buf = await file.arrayBuffer();
    await env.R2.put(key, buf, { httpMetadata: { contentType: file.type || "application/octet-stream" } });
    const ins = await env.DB.prepare(
      "INSERT INTO images (customer_id, album_id, kind, cf_id, r2_key, filename, mime, bytes, uploaded_at) VALUES (?,?,'file','',?,?,?,?,?)"
    ).bind(customer.id, albumId, key, file.name || "file", file.type || "application/octet-stream", file.size, now).run();
    if ((await usedBytesOf(env, customer.id)) > customer.byte_limit) {
      try { await env.R2.delete(key); } catch (e) {}
      await env.DB.prepare("DELETE FROM images WHERE id=? AND customer_id=?").bind(ins.meta.last_row_id, customer.id).run();
      return { error: "容量不足（上限 " + fmtGB(customer.byte_limit) + "），请删文件或升级", status: 402 };
    }
    return { record: { id: ins.meta.last_row_id, kind: "file", cf_id: "", r2_key: key, filename: file.name || "file", mime: file.type || "application/octet-stream", bytes: file.size } };
  } catch (e) {
    try { await env.R2.delete(key); } catch (e2) { await recordPending(env, "r2", key); }
    console.log("file upload fail, rolled back: " + (e && e.message ? e.message : e));
    return { error: "文件上传失败，请稍后重试", status: 502 };
  }
}
async function handleUpload(request, env, customer) {
  const form = await request.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") return json({ error: "缺少文件" }, 400);
  let albumId = Number(form.get("album_id")) || null;
  if (albumId) {
    const a = await env.DB.prepare("SELECT id FROM albums WHERE id=? AND customer_id=?").bind(albumId, customer.id).first();
    if (!a) albumId = null;
  }
  const r = await storeUpload(env, customer, file, albumId);
  if (r.error) return json({ error: r.error }, r.status || 400);
  const rec = r.record;
  if (rec.kind === "image") {
    return json({ ok: true, id: rec.id, kind: "image", link: (env.PUBLIC_BASE || "") + "/i/" + rec.cf_id, thumb: imgThumb(env, rec.cf_id) });
  }
  return json({ ok: true, id: rec.id, kind: "file", filename: rec.filename, link: await fileLink(env, rec.id) });
}

/* ---------- 开发者 API：PicGo「兰空图床(Lsky)」/ Typora 兼容上传 ---------- */
// 用 api_key（Authorization: Bearer tuku_...）鉴权，不走会话；multipart 字段名 file。
// 返回兰空/Lsky 风格结构，PicGo「兰空图床」插件把 server 填 https://link.aistela.com 即可直传。
async function handleApiUpload(request, env) {
  const key = bearer(request);
  if (!key || key.indexOf("tuku_") !== 0) return json({ status: false, message: "缺少或无效的 API 密钥（请在设置里生成）" }, 401);
  const customer = await env.DB.prepare("SELECT * FROM customers WHERE api_key=?").bind(key).first();
  if (!customerActive(customer)) return json({ status: false, message: "密钥无效或账号已停用/到期" }, 401);
  if (customer.tier === "free") return json({ status: false, message: "开发者 API 为付费功能，请升级后使用" }, 403);
  let form;
  try { form = await request.formData(); } catch (e) { return json({ status: false, message: "请用 multipart/form-data 上传，字段名 file" }, 400); }
  const file = form.get("file");
  if (!file || typeof file === "string") return json({ status: false, message: "缺少文件（字段名 file）" }, 400);
  const r = await storeUpload(env, customer, file, null);
  if (r.error) return json({ status: false, message: r.error }, r.status || 400);
  const rec = r.record;
  const url = rec.kind === "image" ? (env.PUBLIC_BASE || "") + "/i/" + rec.cf_id : await fileLink(env, rec.id);
  const name = rec.filename || "file";
  const ext = name.lastIndexOf(".") > 0 ? name.slice(name.lastIndexOf(".") + 1).toLowerCase() : "";
  return json({
    status: true, message: "上传成功",
    data: {
      key: String(rec.id), name: name, origin_name: name, size: rec.bytes, mimetype: rec.mime, extension: ext,
      links: {
        url: url,
        html: rec.kind === "image" ? '<img src="' + url + '" alt="' + name + '">' : '<a href="' + url + '">' + name + '</a>',
        markdown: rec.kind === "image" ? "![" + name + "](" + url + ")" : "[" + name + "](" + url + ")",
        bbcode: rec.kind === "image" ? "[img]" + url + "[/img]" : "[url]" + url + "[/url]",
        thumbnail_url: rec.kind === "image" ? imgThumb(env, rec.cf_id) : null,
      },
    },
  });
}
function genApiKey() { return "tuku_" + b64u(crypto.getRandomValues(new Uint8Array(24))); }
async function handleGetApiKey(env, customer) {
  if (customer.tier === "free") return json({ locked: true, endpoint: (env.PUBLIC_BASE || "") + "/api/v1/upload" });
  return json({ apiKey: customer.api_key || null, endpoint: (env.PUBLIC_BASE || "") + "/api/v1/upload" });
}
async function handleRotateApiKey(env, customer) {
  if (customer.tier === "free") return json({ error: "开发者 API 为付费功能，请升级后使用" }, 403);
  const key = genApiKey();
  await env.DB.prepare("UPDATE customers SET api_key=? WHERE id=?").bind(key, customer.id).run();
  return json({ ok: true, apiKey: key, endpoint: (env.PUBLIC_BASE || "") + "/api/v1/upload" });
}

// Cloudflare Turnstile 人机验证：未配 TURNSTILE_SECRET 则跳过（部署后在 CF 建好验证码、填 key 才生效）
async function verifyTurnstile(env, token, ip) {
  if (!env.TURNSTILE_SECRET) return true;
  if (!token) return false;
  try {
    const r = await fetchT("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip }),
    }, 8000);
    const d = await r.json().catch(() => ({}));
    return d.success === true;
  } catch (e) { return false; }
}
/* ---------- 免费试用开通（无卡密，按 IP 限注册 + 人机验证 防薅） ---------- */
async function handleFreeSignup(request, env) {
  const body = await request.json().catch(() => ({}));
  const password = String(body.password || "");
  if (password.length < 8) return json({ error: "请设至少 8 位密码" }, 400);
  const ip = clientIp(request);
  if (!(await verifyTurnstile(env, body.cfToken, ip))) return json({ error: "请完成人机验证后再试" }, 403);
  const max = envNumber(env, "FREE_SIGNUP_MAX", 3), win = envNumber(env, "FREE_SIGNUP_WINDOW", 86400);
  const lim = limiter(env, "freesignup:" + ip);
  if (lim) {
    const c = await (await lim.fetch("https://do/check?max=" + max + "&lock=" + win)).json();
    if (c.locked) return json({ error: "试用注册太频繁，请 " + Math.ceil(c.retryIn / 3600) + " 小时后再试，或直接购买正式卡" }, 429);
  }
  let card = "";
  for (let i = 0; i < 5; i++) {
    const hex = Array.from(crypto.getRandomValues(new Uint8Array(6))).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    const cand = "FREE-" + hex.slice(0, 4) + "-" + hex.slice(4, 8) + "-" + hex.slice(8, 12);
    const dup = await env.DB.prepare("SELECT 1 FROM customers WHERE card=?").bind(cand).first();
    if (!dup) { card = cand; break; }
  }
  if (!card) return json({ error: "注册繁忙，请重试" }, 503);
  const now = Math.floor(Date.now() / 1000);
  const pwHash = await hashPassword(password);
  const ins = await env.DB.prepare(
    "INSERT INTO customers (card, tier, password_hash, img_limit, byte_limit, expires_at, status, created_at) VALUES (?,?,?,?,?,NULL,'active',?)"
  ).bind(card, "free", pwHash, 9999999, TIERS.free.byteLimit, now).run();
  if (lim) await lim.fetch("https://do/fail?max=" + max + "&lock=" + win); // 每次成功注册计一次，达上限即锁该 IP
  const token = await signSession(env, ins.meta.last_row_id, card);
  return json({ ok: true, token, tier: "free", card, firstTime: true });
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
  // 安全：只认 R2 实际大小（绝不回退客户端申报的 size，杜绝造假绕配额）；拿不到就判失败回滚
  let realSize = null;
  try { const head = await env.R2.head(key); if (head && Number.isFinite(head.size)) realSize = head.size; } catch (e) { /* 下面统一处理 */ }
  if (realSize == null) {
    try { await env.R2.delete(key); } catch (e) { console.log("mpu head-fail rollback fail: " + key); }
    return json({ error: "文件校验失败，请重试" }, 502);
  }
  const usedBytes = await usedBytesOf(env, customer.id);
  if (usedBytes + realSize > customer.byte_limit) {
    try { await env.R2.delete(key); } catch (e) { console.log("mpu over-quota rollback fail: " + key); }
    return json({ error: "容量不足（上限 " + fmtGB(customer.byte_limit) + "，已用 " + fmtGB(usedBytes) + "）" }, 402);
  }
  const now = Math.floor(Date.now() / 1000);
  const ins = await env.DB.prepare(
    "INSERT INTO images (customer_id, album_id, kind, cf_id, r2_key, filename, mime, bytes, uploaded_at) VALUES (?,?,'file','',?,?,?,?,?)"
  ).bind(customer.id, albumId, key, String(body.filename || "file"), String(body.mime || "application/octet-stream"), realSize, now).run();
  return json({ ok: true, id: ins.meta.last_row_id, kind: "file", link: await fileLink(env, ins.meta.last_row_id) });
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
  const images = await Promise.all((rows.results || []).map(async (im) => {
    const isImage = im.kind !== "file";
    return {
      id: im.id, kind: isImage ? "image" : "file", filename: im.filename, mime: im.mime, bytes: im.bytes,
      album_id: im.album_id, uploaded_at: im.uploaded_at,
      link: isImage ? (env.PUBLIC_BASE || "") + "/i/" + im.cf_id : await fileLink(env, im.id),
      thumb: isImage ? "https://imagedelivery.net/" + env.IMAGES_HASH + "/" + im.cf_id + "/public" : null,
    };
  }));
  return json({ images });
}
// 删除失败时把待删对象登记到 pending_deletes，交给 scheduled 对账补删，避免存储孤儿静默泄漏
async function recordPending(env, kind, ref) {
  try { await env.DB.prepare("INSERT INTO pending_deletes (kind, ref, attempts, created_at) VALUES (?,?,0,?)").bind(kind, ref, Math.floor(Date.now() / 1000)).run(); }
  catch (e) { console.log("recordPending fail(表可能未建): " + kind + " " + ref); }
}
async function handleDeleteImg(request, env, customer, id) {
  const row = await env.DB.prepare("SELECT * FROM images WHERE id=? AND customer_id=?").bind(id, customer.id).first();
  if (!row) return json({ error: "文件不存在" }, 404);
  if (row.kind === "file" && row.r2_key) { try { await env.R2.delete(row.r2_key); } catch (e) { await recordPending(env, "r2", row.r2_key); } }
  else if (row.cf_id) { const r = await imagesApi(env, "/" + encodeURIComponent(row.cf_id), { method: "DELETE" }); if (!r.success) await recordPending(env, "image", row.cf_id); }
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
  const variant = "public";
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
async function serveFile(request, env, id, token) {
  if (!token || !ctEqual(token, await fileToken(env, id))) return new Response("Not Found", { status: 404 });
  const row = await env.DB.prepare("SELECT r2_key, filename, mime FROM images WHERE id=? AND kind='file'").bind(id).first();
  if (!row || !row.r2_key) return new Response("Not Found", { status: 404 });
  const hasRange = !!request.headers.get("range");
  const obj = await env.R2.get(row.r2_key, hasRange ? { range: request.headers } : undefined);
  if (!obj) return new Response("Not Found", { status: 404 });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  if (obj.httpEtag) headers.set("etag", obj.httpEtag);
  const mime = row.mime || headers.get("content-type") || "application/octet-stream";
  headers.set("content-type", mime);
  headers.set("cache-control", "public, max-age=3600");
  headers.set("accept-ranges", "bytes");
  // 安全：禁止 MIME 嗅探(防 .txt 被当 html 渲染)；对可执行脚本的文档类型(html/svg/xml)强制下载+沙箱，
  // 杜绝"上传恶意 HTML/SVG → 直链在本域内联执行 → 偷 token"这类存储型 XSS。视频/音频/PDF 等安全类型保留内联预览。
  headers.set("x-content-type-options", "nosniff");
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
  const nowSec = Math.floor(Date.now() / 1000);
  const rawRows = rows.results || [];
  const since = (days) => rawRows.filter((c) => Number(c.created_at || 0) >= nowSec - days * 86400).length;
  const tierCount = (t) => customers.filter((c) => c.tier === t).length;
  const paid = tierCount("basic") + tierCount("pro");
  const free = tierCount("free");
  // 快到期（7 天内、且还没过期）——续费召回的目标名单
  const expiringSoon = rawRows.filter((c) => c.expires_at && Number(c.expires_at) > nowSec && Number(c.expires_at) <= nowSec + 7 * 86400).length;
  const stats = {
    total: customers.length,
    active: customers.filter((c) => c.status === "active").length,
    totalFiles: customers.reduce((s, c) => s + Number(c.files || 0), 0),
    totalGB: fmtGB(totalBytes),
    // 获客漏斗指标
    free, paid, basic: tierCount("basic"), pro: tierCount("pro"),
    new7: since(7), new30: since(30),
    convRate: (free + paid) > 0 ? Math.round(paid / (free + paid) * 100) : 0, // 付费占比(粗略转化率)
    expiringSoon,
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
      else if (f.cf_id) { const r = await imagesApi(env, "/" + encodeURIComponent(f.cf_id), { method: "DELETE" }); if (!r.success) await recordPending(env, "image", f.cf_id); }
    } catch (e) { if (f.kind === "file" && f.r2_key) await recordPending(env, "r2", f.r2_key); }
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
  // 定时对账：补删之前删除失败留下的孤儿存储对象（DB 行已删、存储没删干净的）
  async scheduled(event, env, ctx) {
    try {
      const rows = await env.DB.prepare("SELECT id, kind, ref, attempts FROM pending_deletes ORDER BY id LIMIT 200").all();
      for (const r of (rows.results || [])) {
        let done = false;
        try {
          if (r.kind === "r2") { await env.R2.delete(r.ref); done = true; }
          else { const d = await imagesApi(env, "/" + encodeURIComponent(r.ref), { method: "DELETE" }); done = !!d.success; }
        } catch (e) { done = false; }
        if (done || r.attempts >= 10) await env.DB.prepare("DELETE FROM pending_deletes WHERE id=?").bind(r.id).run();
        else await env.DB.prepare("UPDATE pending_deletes SET attempts=attempts+1 WHERE id=?").bind(r.id).run();
      }
    } catch (e) { console.log("scheduled cleanup fail(表可能未建): " + (e && e.message ? e.message : e)); }
  },
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    request.__ctx = ctx;

    if (path === "/health") return json({ ok: true, service: "tuku", version: VERSION });
    if (path === "/" || path === "/index.html") return htmlResponse(PAGE_HTML, env);
    if (path === "/scfw") return htmlResponse(ADMIN_HTML, env);
    if (path === "/privacy") return htmlResponse(PRIVACY_HTML, env);
    if (path === "/terms") return htmlResponse(TERMS_HTML, env);
    if (path === "/buy") return buyPageResponse(env);

    // 图片直链（公开）
    const im = path.match(/^\/i\/([A-Za-z0-9_-]+)$/);
    if (im) return serveImage(request, env, im[1]);
    // 文件直链（公开，R2）
    const fm = path.match(/^\/f\/(\d+)~([A-Za-z0-9_-]+)$/);
    if (fm) return serveFile(request, env, Number(fm[1]), fm[2]);

    try {
      // 开发者 API：PicGo / 兰空(Lsky) 兼容上传，用 api_key（Bearer tuku_...）鉴权，不走会话
      if (request.method === "POST" && path === "/api/v1/upload") {
        return await handleApiUpload(request, env);
      }
      // 免费试用开通：无需卡密，按 IP 限注册防薅
      if (request.method === "POST" && path === "/api/free-signup") {
        return await handleFreeSignup(request, env);
      }
      // 登录/开通：带暴破锁
      if (request.method === "POST" && path === "/api/login") {
        const ip = clientIp(request);
        let card = "";
        try { card = normCard((await request.clone().json()).card); } catch (e) { /* ignore */ }
        const max = envNumber(env, "AUTH_MAX_FAILURES", 8), lock = envNumber(env, "AUTH_LOCK_SECONDS", 900);
        // 双维度暴破锁：按 IP（挡代理池外的暴破）+ 按卡号（挡分布式 IP 撞单张卡）
        const lims = [limiter(env, "login:" + ip), card ? limiter(env, "logincard:" + card) : null].filter(Boolean);
        for (const lim of lims) {
          const c = await (await lim.fetch("https://do/check?max=" + max + "&lock=" + lock)).json();
          if (c.locked) return json({ error: "尝试过于频繁，请 " + Math.ceil(c.retryIn / 60) + " 分钟后再试" }, 429);
        }
        const resp = await handleLogin(request, env);
        for (const lim of lims) {
          if (resp.status === 401 || resp.status === 400) await lim.fetch("https://do/fail?max=" + max + "&lock=" + lock);
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
      if (request.method === "GET" && path === "/api/apikey") return await handleGetApiKey(env, customer);
      if (request.method === "POST" && path === "/api/apikey") return await handleRotateApiKey(env, customer);
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
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:20px}
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
.pitem.paused .pbar>i{background:var(--amber)}
.pitem.paused .pct{color:var(--amber)}
.pitem.canceled{opacity:.55}
.pitem.canceled .pbar>i{background:var(--mut)}
.pitem.canceled .pct{color:var(--mut)}
.pacts{display:flex;justify-content:flex-end;gap:8px;margin-top:8px}
.pacts:empty{margin-top:0}
.pbtn{padding:4px 10px;font-size:.74rem;font-weight:600;border-radius:8px}
.pbtn.del{color:var(--bad);border-color:rgba(242,114,111,.35)}
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
/* ---- 落地页 ---- */
.lp{max-width:1080px;margin:0 auto;padding:22px}
.lpnav{display:flex;align-items:center;gap:12px;padding:8px 2px 0}
.lpnav .brand{display:flex;align-items:center;gap:10px;font-size:1.25rem;font-weight:800}
.lpnav .sp{margin-left:auto}
.lpnav a.nl{color:var(--mut);font-weight:600;padding:8px 12px;border-radius:9px;cursor:pointer}
.lpnav a.nl:hover{color:var(--ink);background:rgba(255,255,255,.05)}
.hero{text-align:center;padding:64px 16px 30px}
.hero .tagline{display:inline-block;font-size:.8rem;color:#c9beff;border:1px solid rgba(124,108,255,.4);background:rgba(124,108,255,.12);border-radius:999px;padding:5px 14px;margin-bottom:20px}
.hero h1{font-size:2.6rem;line-height:1.18;font-weight:900;letter-spacing:-.5px;margin-bottom:16px}
.hero h1 .grad{background:linear-gradient(120deg,#a78bfa,#6d5efc 60%,#34D39A);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.hero p.sub{max-width:600px;margin:0 auto 26px;color:#aeb6c6;font-size:1.08rem}
.hero .cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.hero .cta button,.hero .cta a{font-size:1rem;padding:13px 24px;border-radius:12px}
.hero .hint{margin-top:14px;color:var(--mut);font-size:.85rem}
.sect{padding:34px 0}
.sect h2{text-align:center;font-size:1.5rem;font-weight:800;margin-bottom:6px}
.sect .lead{text-align:center;color:var(--mut);margin-bottom:26px}
.feat{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.fcard{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 12px 40px rgba(0,0,0,.28)}
.fcard .fi{font-size:1.7rem;margin-bottom:10px}
.fcard h3{font-size:1.02rem;margin-bottom:6px}
.fcard p{color:#aeb6c6;font-size:.9rem}
.plans{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;align-items:stretch}
.plan{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:24px 22px;display:flex;flex-direction:column;position:relative}
.plan.hot{border-color:rgba(124,108,255,.55);box-shadow:0 0 0 1px rgba(124,108,255,.35),0 18px 50px rgba(109,94,252,.18)}
.plan .pop{position:absolute;top:-11px;left:50%;transform:translateX(-50%);font-size:.72rem;font-weight:700;color:#fff;background:linear-gradient(135deg,var(--g2),var(--g1));padding:3px 12px;border-radius:999px}
.plan .pname{font-size:1.05rem;font-weight:800;margin-bottom:4px}
.plan .pcap{font-size:2rem;font-weight:900;font-variant-numeric:tabular-nums;margin:6px 0}
.plan .pcap small{font-size:.9rem;color:var(--mut);font-weight:600}
.plan ul{list-style:none;margin:14px 0 20px;display:grid;gap:9px}
.plan li{color:#c3cad6;font-size:.9rem;padding-left:22px;position:relative}
.plan li:before{content:"✓";position:absolute;left:0;color:var(--ok);font-weight:800}
.plan .pf{margin-top:auto}
.plan .pf button,.plan .pf a{width:100%;justify-content:center;display:inline-flex;padding:12px}
.devbox{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:26px;display:grid;grid-template-columns:1.2fr 1fr;gap:24px;align-items:center}
.devbox h2{text-align:left;margin-bottom:10px}
.devbox p{color:#aeb6c6;font-size:.95rem;margin-bottom:8px}
.devbox .code{background:#0a0b10;border:1px solid var(--line);border-radius:12px;padding:14px 16px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.82rem;color:#c9beff;overflow-x:auto;white-space:pre;line-height:1.7}
.lpfoot{border-top:1px solid var(--line);margin-top:30px;padding:24px 2px;display:flex;gap:18px;flex-wrap:wrap;align-items:center;color:var(--mut);font-size:.85rem}
.lpfoot a{color:var(--mut);cursor:pointer}
.lpfoot a:hover{color:var(--ink)}
.lpfoot .sp{margin-left:auto}
.cardbox{background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.35);border-radius:12px;padding:14px;margin:10px 0;text-align:center}
.cardbox .cn{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:1.1rem;font-weight:800;color:#7ee7b8;letter-spacing:1px;word-break:break-all}
.banner{display:flex;align-items:center;gap:10px;background:rgba(124,108,255,.08);border:1px solid rgba(124,108,255,.28);border-radius:10px;padding:8px 12px;margin-bottom:16px;font-size:.82rem;color:var(--mut)}
.banner.free{background:rgba(124,108,255,.08);border-color:rgba(124,108,255,.28)}
.banner b{color:var(--ink);font-weight:600}
.banner .bx{margin-left:auto;flex-shrink:0;display:flex;align-items:center;gap:6px}
.banner .bx a{color:#c9beff;font-weight:600;text-decoration:none;white-space:nowrap}
.banner .bx .close{width:22px;height:22px;border-radius:6px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--mut);font-size:1rem}
.banner .bx .close:hover{background:rgba(255,255,255,.08);color:var(--ink)}
.space .spacefoot{margin-top:14px;border-top:1px solid var(--line);padding-top:4px}
.space .spacefoot .info{padding:7px 0}
@media(max-width:820px){
.hero h1{font-size:2rem}
.feat{grid-template-columns:1fr}
.plans{grid-template-columns:1fr}
.devbox{grid-template-columns:1fr}
.lpnav a.nl.hideM{display:none}
}
</style></head><body><div class="bg"></div>

<div id="loginView">
  <div class="lp">
    <nav class="lpnav">
      <div class="brand"><span class="logo">存</span>存链</div>
      <span class="sp"></span>
      <a class="nl hideM" id="navFeat">功能</a>
      <a class="nl hideM" id="navPrice">价格</a>
      <a class="nl hideM" id="navDev">开发者</a>
      <a class="nl" id="navLogin">登录</a>
    </nav>
    <header class="hero">
      <span class="tagline">图床 · 网盘 · 开发者直传，一站搞定</span>
      <h1>把文件与图片，<span class="grad">安心托管</span>在一条链接里</h1>
      <p class="sub">拖拽即传、粘贴即传，自动生成直链 / Markdown / HTML；大文件断点续传，视频音频在线预览。支持 PicGo / Typora 一键直传，写博客配图从此不折腾。</p>
      <div class="cta">
        <button class="pri" id="heroFree">🚀 免费试用 · 500MB</button>
        <a href="__BUY_URL__" target="_blank" rel="noopener"><button>购买正式版</button></a>
      </div>
      <div class="hint">免费档无需卡密，设个密码即可开始 · 已有卡号？<a class="nl" id="heroLogin" style="display:inline;color:#a78bfa;padding:2px 4px">点此登录 / 开通</a></div>
    </header>

    <section class="sect" id="secFeat">
      <h2>为什么选存链</h2>
      <div class="lead">省心、够快、好看——把自建图床该有的都做到位</div>
      <div class="feat">
        <div class="fcard"><div class="fi">⚡</div><h3>拖拽 / 粘贴即传</h3><p>拖进来、Ctrl+V 粘贴截图就上传，自动压缩、可加水印，秒出直链。</p></div>
        <div class="fcard"><div class="fi">🎬</div><h3>不止图片</h3><p>视频、音频、PDF、压缩包任意文件；视频音频支持在线拖动预览。</p></div>
        <div class="fcard"><div class="fi">🧩</div><h3>大文件断点续传</h3><p>大文件自动分片直传，断网重拖从断点继续，不用从头再来。</p></div>
        <div class="fcard"><div class="fi">🔗</div><h3>多格式链接</h3><p>一键复制直链 / Markdown / HTML / BBCode / 缩略图，配博客论坛都顺手。</p></div>
        <div class="fcard"><div class="fi">🗂️</div><h3>相册与批量管理</h3><p>相册归类、多选批量删除移动、搜索排序、灯箱看大图，文件不再乱。</p></div>
        <div class="fcard"><div class="fi">🔒</div><h3>私密可靠</h3><p>文件不公开、直链带签名令牌防枚举；删除真删，存储对账兜底不留孤儿。</p></div>
      </div>
    </section>

    <section class="sect" id="secPrice">
      <h2>简单透明的价格</h2>
      <div class="lead">先免费试用，用顺手了再升级；容量不够随时扩</div>
      <div class="plans">
        <div class="plan">
          <div class="pname">存链-免费</div>
          <div class="pcap">500<small> MB</small></div>
          <ul><li>无需卡密，设密码即用</li><li>图片 / 文件通用托管</li><li>图片带品牌水印</li><li>体验全部核心功能</li></ul>
          <div class="pf"><button id="planFree">免费开始</button></div>
        </div>
        <div class="plan hot">
          <div class="pop">最受欢迎</div>
          <div class="pname">存链-基础</div>
          <div class="pcap">5<small> GB</small></div>
          <ul><li>无水印</li><li>大文件分片直传</li><li>开发者 API / PicGo 直传</li><li>相册与批量管理</li></ul>
          <div class="pf"><a href="__BUY_URL__" target="_blank" rel="noopener"><button class="pri">购买基础版</button></a></div>
        </div>
        <div class="plan">
          <div class="pname">存链-专业</div>
          <div class="pcap">50<small> GB</small></div>
          <ul><li>基础版全部能力</li><li>10 倍容量</li><li>适合团队 / 重度使用</li><li>优先支持</li></ul>
          <div class="pf"><a href="__BUY_URL__" target="_blank" rel="noopener"><button>购买专业版</button></a></div>
        </div>
      </div>
    </section>

    <section class="sect" id="secDev">
      <div class="devbox">
        <div>
          <h2>开发者 &amp; 博主友好</h2>
          <p>生成 API 密钥，配到 PicGo「兰空图床」或 Typora，写作时截图即传、自动回填直链，工作流零打断。</p>
          <p class="muted">登录后在「设置 → 开发者 API」一键获取密钥与配置说明。</p>
        </div>
        <div class="code">POST https://link.aistela.com/api/v1/upload
Authorization: Bearer tuku_****
form-data:  file=@shot.png

→ { "data": { "links": {
     "url": "https://link.aistela.com/i/xxxx"
   } } }</div>
      </div>
    </section>

    <footer class="lpfoot">
      <span>© 存链 · link.aistela.com</span>
      <a href="/privacy">隐私政策</a>
      <a href="/terms">服务条款</a>
      <span class="sp"></span>
      <a href="__BUY_URL__" target="_blank" rel="noopener">购买 / 续费</a>
    </footer>
  </div>

  <div class="overlay" id="loginOverlay"><div class="modal">
    <div class="brand" style="display:flex;align-items:center;gap:10px;font-size:1.2rem;font-weight:800;margin-bottom:6px"><span class="logo">存</span>登录 / 开通</div>
    <div class="muted" style="margin-bottom:12px">已有卡号：输入卡号+密码登录；首次用该卡：输入卡号并设 ≥8 位密码即完成开通。</div>
    <input id="card" placeholder="卡号 CM-XXXX-XXXX-XXXX" autocomplete="off" style="margin-bottom:10px">
    <input id="pw" type="password" placeholder="访问密码（首次开通请设 ≥8 位）" style="margin-bottom:12px">
    <button class="pri" id="loginBtn" style="width:100%">进入</button>
    <div id="loginErr" class="muted" style="color:var(--bad);min-height:20px;margin-top:6px"></div>
    <div class="muted" style="margin-top:8px;text-align:center">没有卡号？<a class="nl" id="toFree" style="display:inline;color:#a78bfa;padding:2px">免费试用 ›</a> · <a href="__BUY_URL__" target="_blank" rel="noopener" style="color:#a78bfa">购买 ›</a></div>
  </div></div>

  <div class="overlay" id="freeOverlay"><div class="modal">
    <div class="brand" style="display:flex;align-items:center;gap:10px;font-size:1.2rem;font-weight:800;margin-bottom:6px"><span class="logo">存</span>免费试用</div>
    <div class="muted" style="margin-bottom:12px" id="freeIntro">无需卡密。设一个密码，我们当场给你生成一个账号（500MB，图片带水印）。请记好卡号，下次凭它+密码登录。</div>
    <div id="freeForm">
      <input id="fpw" type="password" placeholder="给账号设个密码（≥8 位）" style="margin-bottom:12px">
      <div id="cfTurnstile" style="margin-bottom:12px"></div>
      <button class="pri" id="freeBtn" style="width:100%">生成我的账号并进入</button>
      <div id="freeErr" class="muted" style="color:var(--bad);min-height:20px;margin-top:6px"></div>
    </div>
    <div id="freeDone" class="hide">
      <div class="muted">这是你的登录账号，请截图或抄下来保存：</div>
      <div class="cardbox"><div class="cn" id="freeCard">—</div></div>
      <button class="pri" id="freeEnter" style="width:100%">我已保存，进入</button>
    </div>
  </div></div>
</div>

<div id="appShell" class="shell hide">
  <div class="scrim" id="scrim"></div>
  <aside class="side" id="side">
    <div class="brand"><span class="logo">存</span>存链<span class="x" id="sideClose">✕</span></div>
    <div id="nav"></div>
    <div class="sidefoot"><div class="navitem" id="logoutBtn"><span class="ni">↩</span>退出登录</div></div>
  </aside>
  <div class="main">
    <header class="topbar"><span class="burger" id="burger">☰</span><div class="pt" id="pageTitle">我的云盘</div><span class="sp"></span><div class="uchip"><span class="dot"></span><span id="who">—</span></div></header>
    <div class="content">

      <div id="view-dash" class="view">
        <div id="upBanner" class="banner hide"></div>
        <div class="panel space">
          <div class="ph" style="display:flex;justify-content:space-between;align-items:center">我的空间<span class="muted" style="font-weight:400"><span id="sCount">0</span> 个文件</span></div>
          <div class="usetxt" style="margin-bottom:9px"><span id="dUseTxt" style="font-size:1.5rem;font-weight:800">0 / 0</span><span id="dPct" class="muted">0%</span></div>
          <div class="usebar"><i id="dBar"></i></div>
          <div id="catBars" style="margin-top:16px"></div>
          <div class="spacefoot">
            <div class="info"><span class="il">到期</span><span id="iExp">—</span></div>
            <div class="info"><span class="il">隐私</span><span>🔒 文件仅你可见，不公开</span></div>
          </div>
          <button class="pri" id="goUpload" style="margin-top:16px">☁️ 上传文件</button>
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
<div class="overlay" id="upgradeOverlay"><div class="modal"><h3>容量不够啦</h3><div class="muted" id="upgradeMsg" style="margin:8px 0 4px"></div><div class="muted" style="margin-bottom:6px">升级到 5GB / 50GB：去水印、扩容，并解锁开发者 API 直传。</div><div class="foot"><button id="upgradeClose">以后再说</button><a href="__BUY_URL__" target="_blank" rel="noopener"><button class="pri">去升级</button></a></div></div></div>
<div class="toast" id="toast"></div>
<script nonce="__CSP_NONCE__">
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
function esc(s){return String(s==null?"":s).replace(/[<>&"']/g,function(c){return c==="<"?"&lt;":c===">"?"&gt;":c==="&"?"&amp;":c==='"'?"&quot;":"&#39;"})}
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
function openLogin(){show("loginOverlay");setTimeout(function(){$("card").focus()},60)}
var TURNSTILE_SITE="__TURNSTILE_SITE__",TS_ID=null;
function tsActive(){return TURNSTILE_SITE&&TURNSTILE_SITE.indexOf("__")!==0}
function loadTurnstile(){
  if(!tsActive())return;
  function render(){if(!window.turnstile)return;if(TS_ID===null){TS_ID=window.turnstile.render("#cfTurnstile",{sitekey:TURNSTILE_SITE})}else{window.turnstile.reset(TS_ID)}}
  if(window.turnstile){render();return}
  if(!window.__tsLoading){window.__tsLoading=true;var s=document.createElement("script");s.src="https://challenges.cloudflare.com/turnstile/v0/api.js";s.async=true;s.defer=true;s.onload=render;document.head.appendChild(s)}else{setTimeout(render,800)}
}
function openFree(){$("freeForm").classList.remove("hide");$("freeDone").classList.add("hide");$("fpw").value="";$("freeErr").textContent="";show("freeOverlay");setTimeout(function(){$("fpw").focus()},60);loadTurnstile()}
$("navLogin").addEventListener("click",openLogin);
$("heroLogin").addEventListener("click",openLogin);
$("heroFree").addEventListener("click",openFree);
$("planFree").addEventListener("click",openFree);
$("toFree").addEventListener("click",function(){hide("loginOverlay");openFree()});
[["navFeat","secFeat"],["navPrice","secPrice"],["navDev","secDev"]].forEach(function(p){$(p[0]).addEventListener("click",function(){var el=$(p[1]);if(el)el.scrollIntoView({behavior:"smooth"})})});
["loginOverlay","freeOverlay"].forEach(function(id){$(id).addEventListener("click",function(e){if(e.target===this)hide(id)})});
$("fpw").addEventListener("keydown",function(e){if(e.key==="Enter")doFree()});
$("freeBtn").addEventListener("click",doFree);
$("freeEnter").addEventListener("click",function(){hide("freeOverlay");enterApp()});
function doFree(){
  var pw=$("fpw").value;$("freeErr").textContent="";
  if(pw.length<8){$("freeErr").textContent="密码至少 8 位";return}
  var cfToken="";
  if(tsActive()){cfToken=(window.turnstile&&TS_ID!==null)?window.turnstile.getResponse(TS_ID):"";if(!cfToken){$("freeErr").textContent="请先完成上方人机验证";return}}
  $("freeBtn").disabled=true;
  fetch("/api/free-signup",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:pw,cfToken:cfToken})}).then(function(r){return r.json().then(function(d){
    $("freeBtn").disabled=false;
    if(!r.ok){$("freeErr").textContent=d.error||"注册失败";if(tsActive()&&window.turnstile&&TS_ID!==null)window.turnstile.reset(TS_ID);return}
    TOKEN=d.token;sessionStorage.setItem("tuku_token",TOKEN);
    $("freeCard").textContent=d.card;$("freeForm").classList.add("hide");$("freeDone").classList.remove("hide");
  })}).catch(function(){$("freeBtn").disabled=false;$("freeErr").textContent="网络错误";if(tsActive()&&window.turnstile&&TS_ID!==null)window.turnstile.reset(TS_ID)});
}
function doLogin(){
  var card=$("card").value.trim(),pw=$("pw").value;
  $("loginErr").textContent="";
  fetch("/api/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({card:card,password:pw})}).then(function(r){return r.json().then(function(d){
    if(!r.ok){$("loginErr").textContent=d.error||"登录失败";return}
    TOKEN=d.token;sessionStorage.setItem("tuku_token",TOKEN);
    hide("loginOverlay");
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
  $("iExp").textContent=d.expiresAt?d.expiresAt.slice(0,10):"永久";
  var pct=d.byteLimit>0?Math.min(100,d.usedBytes/d.byteLimit*100):0;
  var bar=$("dBar");bar.style.width=(pct<1.5&&pct>0?1.5:pct).toFixed(1)+"%";bar.className=pct>=95?"full":pct>=80?"warn":"";
  $("dUseTxt").textContent=fmtSize(d.usedBytes)+" / "+fmtSize(d.byteLimit);
  $("dPct").textContent=pct.toFixed(pct<10?1:0)+"%";
  renderUpBanner(d);applyTierUI();
}).catch(function(){})}
function renderUpBanner(d){
  var el=$("upBanner");if(!el)return;
  if(sessionStorage.getItem("tuku_banner_off")==="1"){el.classList.add("hide");return}
  var days=null;if(d.expiresAt){days=Math.ceil((new Date(d.expiresAt).getTime()-Date.now())/86400000)}
  var pct=d.byteLimit>0?d.usedBytes/d.byteLimit*100:0,msg="",cta="升级 ›";
  if(d.tier==="free"){msg="<b>免费档</b> · 500MB，图片带水印。需要更多空间?";}
  else if(days!=null&&days<=7){msg="账号将在 <b>"+(days<0?0:days)+" 天</b>后到期。";cta="续费 ›";}
  else if(pct>=90){msg="容量已用 <b>"+Math.round(pct)+"%</b>，快满了。";cta="扩容 ›";}
  if(msg){
    el.className="banner free";
    el.innerHTML="<span>"+msg+"</span><span class='bx'><a href='__BUY_URL__' target='_blank' rel='noopener'>"+cta+"</a><span class='close' id='bannerClose'>×</span></span>";
    var c=$("bannerClose");if(c)c.onclick=function(){sessionStorage.setItem("tuku_banner_off","1");el.classList.add("hide")};
    el.classList.remove("hide");
  }else el.classList.add("hide");
}
function applyTierUI(){
  var free=ME&&ME.tier==="free",cmp=$("cmp"),wm=$("wm");if(!cmp||!wm)return;
  if(free){cmp.checked=true;cmp.disabled=true;if(!wm.value)wm.value="存链 link.aistela.com";wm.readOnly=true;wm.title="免费档图片带品牌水印，升级后可去除";}
  else{cmp.disabled=false;wm.readOnly=false;wm.title="";}
}
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
  $("pageTitle").textContent=VIEW==="dash"?"我的云盘":VIEW==="upload"?"上传文件":"我的文件";
  renderNav();
  if(VIEW==="dash"){loadMe();renderRecent();renderCatBars()}
  if(VIEW==="files")renderFiles();
}
function renderCatBars(){
  var box=$("catBars");if(!box)return;box.innerHTML="";
  var tot=0,sums={};
  ALLFILES.forEach(function(x){var t=typeOf(x),b=Number(x.bytes)||0;sums[t]=(sums[t]||0)+b;tot+=b});
  if(!tot){box.innerHTML="<div class='muted' style='font-size:.8rem'>上传后这里会显示空间构成</div>";return}
  var colors={image:"#a855f7",video:"#2dd4bf",audio:"#f3b44c",doc:"#6d5efc",zip:"#fb7185",other:"#8A93A6"};
  CATS.forEach(function(c){
    if(c[0]==="all")return;
    var b=sums[c[0]]||0;if(!b)return;
    var pc=Math.max(1,Math.round(b/tot*100));
    var d=document.createElement("div");d.style.marginBottom="9px";
    d.innerHTML="<div style='display:flex;justify-content:space-between;font-size:.78rem;color:var(--mut);margin-bottom:3px'><span>"+c[2]+" "+c[1]+"</span><span>"+fmtSize(b)+" · "+pc+"%</span></div><div class='pbar'><i style='width:"+pc+"%;background:"+colors[c[0]]+"'></i></div>";
    box.appendChild(d);
  });
}
function renderNav(){
  var nav=$("nav");nav.innerHTML="";
  var grp=function(t){var g=document.createElement("div");g.className="navgrp";g.textContent=t;nav.appendChild(g)};
  var item=function(icon,label,active,cnt,fn){var a=document.createElement("div");a.className="navitem"+(active?" on":"");a.innerHTML="<span class='ni'>"+icon+"</span>"+esc(label);if(cnt!=null){var c=document.createElement("span");c.className="cnt";c.textContent=cnt;a.appendChild(c)}a.onclick=fn;nav.appendChild(a)};
  grp("常规");
  item("🏠","我的云盘",VIEW==="dash",null,function(){navTo({view:"dash"})});
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
var API_KEY=null;
function openSettings(){var b=$("setBody");b.innerHTML="";closeDrawer();
  var row=function(k,v){var d=document.createElement("div");d.className="info";d.innerHTML="<span class='il'>"+k+"</span><span>"+esc(v)+"</span>";b.appendChild(d)};
  if(ME){row("档位",ME.tierLabel);row("卡号",ME.card);row("到期",ME.expiresAt?ME.expiresAt.slice(0,10):"永久");row("已用",fmtSize(ME.usedBytes)+" / "+fmtSize(ME.byteLimit))}
  var up=document.createElement("div");up.style.margin="12px 0 4px";
  up.innerHTML="<a href='__BUY_URL__' target='_blank' rel='noopener'><button class='pri' style='width:100%'>"+(ME&&ME.tier==="free"?"升级去水印 / 扩容":"续费 / 升级")+"</button></a>";b.appendChild(up);
  var h=document.createElement("div");h.style.cssText="font-weight:700;margin:16px 0 8px";h.textContent="开发者 API（PicGo / Typora 直传）";b.appendChild(h);
  var apiBox=document.createElement("div");apiBox.id="apiBox";apiBox.innerHTML="<div class='muted'>加载中…</div>";b.appendChild(apiBox);
  var links=document.createElement("div");links.className="muted";links.style.marginTop="16px";links.style.textAlign="center";
  links.innerHTML="<a href='/privacy' target='_blank' style='color:var(--mut)'>隐私政策</a> · <a href='/terms' target='_blank' style='color:var(--mut)'>服务条款</a>";b.appendChild(links);
  loadApiKey();show("setOverlay");
}
function loadApiKey(){api("/api/apikey").then(function(d){if(d.locked){var x=$("apiBox");if(x)x.innerHTML="<div class='muted' style='line-height:1.7'>🔒 开发者 API 为付费功能。升级到基础版即可用 PicGo / Typora 直传。</div><a href='__BUY_URL__' target='_blank' rel='noopener'><button class='pri sm' style='margin-top:8px'>升级解锁</button></a>";return}API_KEY=d.apiKey;renderApiBox(d.apiKey,d.endpoint)}).catch(function(e){var x=$("apiBox");if(x)x.innerHTML="<div class='muted'>获取失败："+esc(e.message)+"</div>"})}
function renderApiBox(key,endpoint){
  var box=$("apiBox");if(!box)return;box.innerHTML="";API_KEY=key;
  var ep=document.createElement("div");ep.className="info";ep.innerHTML="<span class='il'>上传地址</span><span class='mono' style='word-break:break-all'>"+esc(endpoint)+"</span>";box.appendChild(ep);
  var kv=document.createElement("div");kv.className="cval";var inp=document.createElement("input");inp.readOnly=true;inp.className="mono";inp.value=key||"（尚未生成）";
  var cp=document.createElement("button");cp.className="sm";cp.textContent=key?"复制":"生成";cp.onclick=function(){if(key){navigator.clipboard.writeText(key).then(function(){toast("密钥已复制")})}else{rotateApiKey(false)}};
  kv.appendChild(inp);kv.appendChild(cp);box.appendChild(kv);
  if(key){var acts=document.createElement("div");acts.style.marginTop="8px";var rot=document.createElement("button");rot.className="sm";rot.textContent="重置密钥";rot.onclick=function(){rotateApiKey(true)};acts.appendChild(rot);box.appendChild(acts)}
  var hint=document.createElement("div");hint.className="muted";hint.style.cssText="margin-top:10px;line-height:1.7";
  hint.innerHTML="PicGo →「兰空图床(Lsky)」：服务地址填 <b class='mono'>"+esc(endpoint.replace("/api/v1/upload",""))+"</b>，Token 填上面的密钥，其余默认即可。<br>Typora → 偏好设置 → 图像 → 上传服务选 PicGo。";box.appendChild(hint);
}
function rotateApiKey(hasOld){
  if(hasOld&&!confirm("重置后旧密钥立即失效，需在 PicGo 等处更新。继续？"))return;
  api("/api/apikey",{method:"POST"}).then(function(d){API_KEY=d.apiKey;renderApiBox(d.apiKey,d.endpoint);toast("已生成新密钥")}).catch(function(e){toast(e.message)});
}
function openUpgrade(msg){$("upgradeMsg").textContent=msg||"当前容量已满。";show("upgradeOverlay")}
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
function ctrlGate(ctrl){
  return new Promise(function(res,rej){
    (function chk(){
      if(ctrl&&ctrl.canceled)return rej(new Error("已取消"));
      if(!ctrl||!ctrl.paused)return res();
      setTimeout(chk,300);
    })();
  });
}
function xhrUpload(file,albumId,onprog,ctrl){
  return new Promise(function(resolve,reject){
    if(ctrl&&ctrl.canceled)return reject(new Error("已取消"));
    var fd=new FormData();fd.append("file",file);if(albumId)fd.append("album_id",albumId);
    var x=new XMLHttpRequest();x.open("POST","/api/upload");x.setRequestHeader("authorization","Bearer "+TOKEN);
    if(ctrl){ctrl.xhr=x;ctrl.abort=function(){try{x.abort()}catch(e){}}}
    x.upload.onprogress=function(e){if(e.lengthComputable&&onprog)onprog(e.loaded/e.total)};
    x.onload=function(){var d={};try{d=JSON.parse(x.responseText)}catch(e){}if(x.status>=200&&x.status<300)resolve(d);else{if(x.status===401)logout();reject(new Error(d.error||("HTTP "+x.status)))}};
    x.onerror=function(){reject(new Error("网络错误"))};
    x.onabort=function(){reject(new Error("已取消"))};
    x.send(fd);
  });
}
function fileSig(file){return "tuku_mpu_"+encodeURIComponent(file.name)+"_"+file.size+"_"+(file.lastModified||0)}
function mpuSave(sig,st){try{localStorage.setItem(sig,JSON.stringify(st))}catch(e){}}
function mpuLoad(sig){try{var v=localStorage.getItem(sig);return v?JSON.parse(v):null}catch(e){return null}}
function mpuClear(sig){try{localStorage.removeItem(sig)}catch(e){}}
// 大文件分片上传，带断点续传(localStorage 记 uploadId+已传分片)+ 每片自动重试
function multipartUpload(file,albumId,onprog,ctrl){
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
        if(ctrl){ctrl.xhr=x;ctrl.abort=function(){try{x.abort()}catch(e){}}}
        x.upload.onprogress=function(e){if(e.lengthComputable&&onprog){var base=st.parts.length*CHUNK;onprog(Math.min(1,(base+e.loaded)/file.size))}};
        x.onload=function(){var d={};try{d=JSON.parse(x.responseText)}catch(e){}if(x.status>=200&&x.status<300){st.parts.push({part:d.part,etag:d.etag});mpuSave(sig,st);reportBase();resolve()}else{if(x.status===401)logout();reject(new Error(d.error||("分片"+n+"失败")))}};
        x.onerror=function(){reject(new Error("网络中断"))};
        x.onabort=function(){reject(new Error("已取消"))};
        x.send(chunk);
      }).catch(function(e){
        if(ctrl&&ctrl.canceled)throw new Error("已取消");
        if(attempt<3)return new Promise(function(r){setTimeout(r,900*attempt)}).then(function(){return uploadPart(n,attempt+1)});
        throw e;
      });
    }
    function loop(n){if(n>total)return Promise.resolve();if(done[n])return loop(n+1);return ctrlGate(ctrl).then(function(){return uploadPart(n,1)}).then(function(){return loop(n+1)})}
    return loop(1).catch(function(e){if(resumed&&!(ctrl&&ctrl.canceled))mpuClear(sig);if(ctrl&&ctrl.canceled)mpuClear(sig);throw e});
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
  var done=0,fail=0,canceled=0,quotaHit=false;
  var runOne=function(i){
    if(i>=files.length){var msg="完成 "+done+" 个"+(fail?("，失败 "+fail):"")+(canceled?("，取消 "+canceled):"");toast(msg);reloadFiles();setTimeout(function(){if(!fail&&!canceled)pc.classList.add("hide")},1600);if(quotaHit)openUpgrade("容量不足，剩余空间放不下这次上传。");return}
    var f=files[i];
    var ctrl={canceled:false,paused:false,xhr:null,abort:null};
    var item=document.createElement("div");item.className="pitem";
    item.innerHTML="<div class='pn'><span>"+esc(f.name)+"</span><span class='pct'>0%</span></div><div class='pbar'><i></i></div><div class='pacts'></div>";
    pc.appendChild(item);
    var bar=item.querySelector("i"),pct=item.querySelector(".pct"),acts=item.querySelector(".pacts");
    var cancelBtn=document.createElement("button");cancelBtn.className="pbtn del";cancelBtn.textContent="✕ 取消";
    cancelBtn.onclick=function(){ctrl.canceled=true;if(ctrl.abort)ctrl.abort();};
    acts.appendChild(cancelBtn);
    (doCompress?compressImage(f,2560,0.85,wm):Promise.resolve(f)).then(function(uf){
      if(ctrl.canceled)throw new Error("已取消");
      var prog=function(p){if(ctrl.paused)return;var v=Math.round(p*100);bar.style.width=v+"%";pct.textContent=v+"%"};
      var big=uf.size>90*1024*1024;
      if(big){
        var pauseBtn=document.createElement("button");pauseBtn.className="pbtn";pauseBtn.textContent="⏸ 暂停";
        pauseBtn.onclick=function(){ctrl.paused=!ctrl.paused;pauseBtn.textContent=ctrl.paused?"▶ 继续":"⏸ 暂停";item.classList.toggle("paused",ctrl.paused);if(ctrl.paused)pct.textContent="已暂停"};
        acts.insertBefore(pauseBtn,cancelBtn);
      }
      return big?multipartUpload(uf,albumId,prog,ctrl):xhrUpload(uf,albumId,prog,ctrl);
    }).then(function(){done++;item.classList.add("done");pct.textContent="完成";acts.innerHTML=""})
    .catch(function(e){
      if(ctrl.canceled||/已取消/.test(e.message||"")){canceled++;item.classList.add("canceled");pct.textContent="已取消";acts.innerHTML="";}
      else{fail++;item.classList.add("err");pct.textContent=e.message;acts.innerHTML="";if(/容量不足|升级|扩容/.test(e.message||""))quotaHit=true;}
    }).then(function(){runOne(i+1)});
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
["menuOverlay","copyOverlay","detailOverlay","renameOverlay","moveOverlay","setOverlay","upgradeOverlay"].forEach(function(id){$(id).addEventListener("click",function(e){if(e.target===this)this.classList.remove("show")})});
$("upgradeClose").onclick=function(){hide("upgradeOverlay")};
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
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:20px}
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
        <div class="cards">
          <div class="scard"><div class="ico i1">🆕</div><div><div class="k">近 7 天新增</div><div class="v" id="sNew7">0</div></div></div>
          <div class="scard"><div class="ico i2">💳</div><div><div class="k">付费 / 免费</div><div class="v" id="sPaidFree">0 / 0</div></div></div>
          <div class="scard"><div class="ico i4">📈</div><div><div class="k">付费转化</div><div class="v" id="sConv">0%</div></div></div>
          <div class="scard"><div class="ico i3">⏰</div><div><div class="k">7 天内到期</div><div class="v" id="sExp">0</div></div></div>
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
  <label>套餐（改档位会套用该档默认容量）</label><select id="eTier"><option value="">不改</option><option value="free">存链-免费</option><option value="basic">存链-基础</option><option value="pro">存链-专业</option></select>
  <label>容量上限（GB，留空=不改）</label><input id="eGB" type="number" placeholder="如 5 / 50 / 100">
  <label>到期日（留空=不改）</label><input id="eDate" type="date">
  <div class="foot"><button id="editCancel">取消</button><button class="pri" id="editSave">保存</button></div>
</div></div>
<div class="overlay" id="confirmOverlay"><div class="modal">
  <h2>请确认</h2><div class="note" id="confirmMsg" style="margin-bottom:14px"></div>
  <div class="foot"><button id="confirmNo">取消</button><button class="pri danger" id="confirmYes">确认</button></div>
</div></div>
<div class="toast" id="toast"></div>
<script nonce="__CSP_NONCE__">
var AK=sessionStorage.getItem("tuku_ak")||"",LIST=[],STATS=null,VIEW="dash",editId=null,_cf=null,Q="",FILT="all";
function $(id){return document.getElementById(id)}
function show(id){$(id).classList.add("show")}
function hide(id){$(id).classList.remove("show")}
function toast(m){var t=$("toast");t.textContent=m;t.classList.add("show");setTimeout(function(){t.classList.remove("show")},2200)}
function esc(s){return String(s==null?"":s).replace(/[<>&"']/g,function(c){return c==="<"?"&lt;":c===">"?"&gt;":c==="&"?"&amp;":c==='"'?"&quot;":"&#39;"})}
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
  $("sNew7").textContent=s.new7!=null?s.new7:0;
  $("sPaidFree").textContent=(s.paid!=null?s.paid:0)+" / "+(s.free!=null?s.free:0);
  $("sConv").textContent=(s.convRate!=null?s.convRate:0)+"%";
  $("sExp").textContent=s.expiringSoon!=null?s.expiringSoon:0;
  var top=LIST.slice().sort(function(a,b){return (b.usedBytes||0)-(a.usedBytes||0)}).slice(0,5);
  var tb=$("topBox");tb.innerHTML="";
  if(!top.length||!top[0].usedBytes){tb.innerHTML="<div class='muted'>还没有用量数据</div>"}
  else{top.forEach(function(c){var pct=c.byteLimit?Math.min(100,Math.round(c.usedBytes/c.byteLimit*100)):0;var d=document.createElement("div");d.className="toprow";d.innerHTML="<span class='mono'>"+esc(c.card)+"</span><span class='tb'><span class='pbar'><i class='"+(pct>=100?"full":"")+"' style='width:"+pct+"%'></i></span></span><span class='tv'>"+fmtSize(c.usedBytes)+"</span>";tb.appendChild(d)})}
  var free=LIST.filter(function(c){return c.tier==="free"}).length,basic=LIST.filter(function(c){return c.tier==="basic"}).length,pro=LIST.filter(function(c){return c.tier==="pro"}).length,tot=free+basic+pro||1;
  var db=$("distBox");db.innerHTML="";
  var mk=function(label,n,color){var pc=Math.round(n/tot*100);var d=document.createElement("div");d.style.marginBottom="14px";d.innerHTML="<div style='display:flex;justify-content:space-between;font-size:.85rem;margin-bottom:6px'><span>"+label+"</span><span class='muted'>"+n+" 个 · "+pc+"%</span></div><div class='usebar'><i style='width:"+pc+"%;background:"+color+"'></i></div>";db.appendChild(d)};
  mk("存链-免费",free,"linear-gradient(90deg,#8A93A6,#aeb6c6)");
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

/* ---------- 信任页：隐私政策 / 服务条款（静态，落地页与运营台页脚引用） ---------- */
function legalDoc(title, bodyHtml) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} · 存链</title><style>
:root{--bg:#080910;--card:#10131c;--ink:#EEF1F7;--mut:#8A93A6;--line:rgba(255,255,255,.08);--g1:#a855f7;--g2:#6d5efc}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);line-height:1.75;-webkit-font-smoothing:antialiased}
.wrap{max-width:760px;margin:0 auto;padding:40px 22px 80px}
.brand{display:flex;align-items:center;gap:10px;font-size:1.2rem;font-weight:800;margin-bottom:8px}
.logo{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,var(--g2),var(--g1));display:flex;align-items:center;justify-content:center;font-weight:900;color:#fff}
h1{font-size:1.5rem;margin:18px 0 6px}
h2{font-size:1.05rem;margin:26px 0 8px;color:#c9beff}
p,li{color:#c3cad6;font-size:.95rem}
ul{margin:6px 0 6px 20px}
.upd{color:var(--mut);font-size:.85rem;margin-bottom:8px}
a{color:#a78bfa;text-decoration:none}
a:hover{text-decoration:underline}
.foot{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);color:var(--mut);font-size:.85rem;display:flex;gap:16px;flex-wrap:wrap}
</style></head><body><div class="wrap">
<div class="brand"><span class="logo">存</span>存链</div>
<h1>${title}</h1><div class="upd">最近更新：2026-07-12</div>
${bodyHtml}
<div class="foot"><a href="/">← 返回首页</a><a href="/privacy">隐私政策</a><a href="/terms">服务条款</a><span>© 存链 · link.aistela.com</span></div>
</div></body></html>`;
}
const PRIVACY_HTML = legalDoc("隐私政策", `
<p>我们把你托管文件的隐私放在第一位。这页用大白话说清楚我们存什么、怎么用、你有什么权利。</p>
<h2>我们存什么</h2>
<ul>
<li><b>你上传的文件与图片本体</b>：图片存于 Cloudflare Images、其它文件存于 Cloudflare R2。</li>
<li><b>元数据</b>：文件名、大小、类型、上传时间、所属相册，以及你的卡号与<b>密码的哈希值</b>（PBKDF2，明文密码我们不保存、也无法还原）。</li>
</ul>
<h2>你的文件是否公开</h2>
<ul>
<li>文件<b>不会</b>被列入任何公开目录，也不会被搜索到。</li>
<li>只有持有你主动复制出去的直链的人才能访问；非图片直链带有不可枚举的签名令牌，改数字猜不到别人的文件。</li>
<li>我们<b>不浏览、不分析、不倒卖</b>你的文件内容，也不会用于训练任何模型。</li>
</ul>
<h2>删除</h2>
<p>你在后台删除文件时，我们会真实删除存储对象；万一某次存储侧删除失败，会进入对账队列，由定时任务（每 6 小时）补删，不做“只删记录、留着占空间”的假删除。</p>
<h2>Cookie 与本地存储</h2>
<p>我们不使用第三方追踪 Cookie。登录令牌仅保存在你浏览器的 sessionStorage 里，关闭标签即失效。</p>
<h2>联系</h2>
<p>对隐私有疑问，可通过你的购买/续费渠道联系我们：<a href="__BUY_URL__">__BUY_URL__</a>。</p>
`);
const TERMS_HTML = legalDoc("服务条款", `
<p>使用「存链」即表示你已阅读并同意以下条款。</p>
<h2>账号与开通</h2>
<ul>
<li>正式账号通过卡密（卡号）开通，首次开通时你自行设置访问密码；请妥善保管，密码遗失我们无法找回。</li>
<li>免费试用账号无需卡密，容量受限、图片带品牌水印，仅供体验，我们保留调整或回收长期不活跃免费账号的权利。</li>
</ul>
<h2>可接受使用</h2>
<ul>
<li>不得上传、存储或分发违反所在地法律法规的内容，不得侵犯他人知识产权、隐私或合法权益。</li>
<li>不得上传恶意程序，不得利用本服务实施攻击、滥发或其它危害网络安全的行为。</li>
<li>对滥用、异常占用资源或危害服务稳定的账号，我们可暂停或终止服务。</li>
</ul>
<h2>容量、到期与续费</h2>
<p>各档位的容量上限以产品页与后台显示为准。付费账号到期后将停用，续费后恢复。请通过官方购买入口 <a href="__BUY_URL__">__BUY_URL__</a> 购买与续费。</p>
<h2>服务与责任</h2>
<p>本服务按“现状”提供。我们尽力保障可用性与数据安全，并提供数据库时间点恢复能力，但对不可抗力或第三方基础设施故障导致的损失不承担超出你已付费用范围的责任。请对重要文件自行保留额外备份。</p>
<h2>条款变更</h2>
<p>我们可能不时更新本条款，重大变更会在产品内提示。继续使用即视为接受更新后的条款。</p>
`);

/* ---------- 购买页 /buy（手动收款：自己的微信/支付宝码；配置全走 wrangler vars） ---------- */
const BUY_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>开通存链 · 购买</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='24' fill='%236d5efc'/><text x='50' y='73' font-size='58' text-anchor='middle' fill='%23ffffff' font-family='sans-serif' font-weight='bold'>存</text></svg>"><style>
:root{--bg:#080910;--card:#10131c;--ink:#EEF1F7;--mut:#8A93A6;--line:rgba(255,255,255,.08);--g1:#a855f7;--g2:#6d5efc;--ok:#34D39A;--amber:#F3B44C}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:var(--bg);color:var(--ink);line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh}
.bg{position:fixed;inset:0;z-index:-1;background:radial-gradient(900px 500px at 12% -5%,rgba(124,92,255,.20),transparent 60%),radial-gradient(800px 500px at 100% 110%,rgba(52,211,153,.12),transparent 55%)}
a{color:#a78bfa;text-decoration:none}a:hover{text-decoration:underline}
button{border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.06);color:var(--ink);font-weight:700;cursor:pointer;padding:10px 15px;font:inherit;transition:.15s}
button:hover{background:rgba(255,255,255,.11)}
button.pri{border:0;background:linear-gradient(135deg,var(--g2),var(--g1));color:#fff}
button.pri:hover{filter:brightness(1.1)}
button.sm{padding:6px 11px;font-size:.8rem;font-weight:600}
.wrap{max-width:1000px;margin:0 auto;padding:22px}
.nav{display:flex;align-items:center;gap:12px;padding:6px 2px}
.brand{display:flex;align-items:center;gap:10px;font-size:1.2rem;font-weight:800}
.logo{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,var(--g2),var(--g1));display:flex;align-items:center;justify-content:center;font-weight:900;color:#fff}
.nav .sp{margin-left:auto}
.hero{text-align:center;padding:40px 10px 22px}
.hero h1{font-size:2rem;font-weight:900;letter-spacing:-.5px;margin-bottom:10px}
.hero h1 .grad{background:linear-gradient(120deg,#a78bfa,#6d5efc 60%,#34D39A);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.hero p{color:#aeb6c6}
.tiers{display:grid;grid-template-columns:1fr 1fr;gap:14px;max-width:620px;margin:22px auto 8px}
.tier{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px;cursor:pointer;transition:.15s;position:relative;text-align:left}
.tier:hover{border-color:rgba(124,108,255,.4)}
.tier.on{border-color:rgba(124,108,255,.7);box-shadow:0 0 0 1px rgba(124,108,255,.5),0 16px 44px rgba(109,94,252,.18)}
.tier .pop{position:absolute;top:-11px;right:16px;font-size:.7rem;font-weight:700;color:#fff;background:linear-gradient(135deg,var(--g2),var(--g1));padding:3px 11px;border-radius:999px}
.tier .tn{font-size:1.05rem;font-weight:800}
.tier .tc{font-size:1.9rem;font-weight:900;margin:4px 0}
.tier .tc small{font-size:.85rem;color:var(--mut);font-weight:600}
.tier .tp{color:var(--ok);font-weight:800;font-size:1.05rem}
.tier .rd{position:absolute;top:16px;left:16px;width:18px;height:18px;border-radius:50%;border:2px solid var(--line)}
.tier.on .rd{border-color:var(--g2);background:radial-gradient(circle,var(--g2) 40%,transparent 46%)}
.tier .tn,.tier .tc,.tier .tp{padding-left:26px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:24px;margin-top:16px;box-shadow:0 12px 40px rgba(0,0,0,.3)}
.ph{font-size:1.05rem;font-weight:800;margin-bottom:4px}
.psub{color:var(--mut);font-size:.88rem;margin-bottom:18px}
.pays{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.pay{text-align:center;border:1px solid var(--line);border-radius:14px;padding:18px;background:rgba(255,255,255,.02)}
.pay .pt{font-weight:800;margin-bottom:12px;display:flex;align-items:center;justify-content:center;gap:8px}
.pay .pt .d{width:9px;height:9px;border-radius:50%}
.qr{width:190px;height:190px;margin:0 auto;border-radius:12px;background:#fff;display:flex;align-items:center;justify-content:center;overflow:hidden}
.qr img{width:100%;height:100%;object-fit:contain}
.qr.empty{background:rgba(255,255,255,.04);border:2px dashed var(--line);color:var(--mut);font-size:.82rem;padding:14px;text-align:center}
.remark{display:flex;align-items:center;gap:10px;background:#0a0b10;border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin-top:16px;flex-wrap:wrap}
.remark .lab{color:var(--mut);font-size:.85rem}
.remark .val{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:800;color:#c9beff;font-size:1rem}
.remark .sp{margin-left:auto}
.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:18px}
.step{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.step .n{width:26px;height:26px;border-radius:8px;background:linear-gradient(135deg,var(--g2),var(--g1));color:#fff;font-weight:800;display:flex;align-items:center;justify-content:center;font-size:.82rem;margin-bottom:10px}
.step h4{font-size:.92rem;margin-bottom:4px}
.step p{color:#aeb6c6;font-size:.82rem}
.contact{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:16px;background:linear-gradient(135deg,rgba(109,94,252,.14),rgba(168,85,247,.08));border:1px solid rgba(124,108,255,.35);border-radius:14px;padding:16px 18px}
.contact .ci{font-size:1.5rem}
.contact .cv{font-weight:700}
.contact .sp{margin-left:auto}
.cta{text-align:center;margin-top:24px}
.cta a button{padding:13px 26px;font-size:1rem}
.foot{border-top:1px solid var(--line);margin-top:30px;padding:22px 2px;display:flex;gap:16px;flex-wrap:wrap;color:var(--mut);font-size:.85rem}
.foot .sp{margin-left:auto}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);opacity:0;background:rgba(14,16,26,.95);border:1px solid var(--line);border-radius:12px;padding:12px 16px;transition:.2s;pointer-events:none;z-index:50}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(max-width:760px){.tiers{grid-template-columns:1fr}.pays{grid-template-columns:1fr}.steps{grid-template-columns:1fr 1fr}.hero h1{font-size:1.6rem}}
</style></head><body><div class="bg"></div>
<div class="wrap">
  <nav class="nav"><div class="brand"><span class="logo">存</span>存链</div><span class="sp"></span><a href="/">← 返回首页</a> · <a href="/">登录 / 开通</a></nav>
  <header class="hero">
    <h1>开通<span class="grad">存链</span>正式版</h1>
    <p>扫码付款 → 加客服发截图 → 收到卡号 → 回首页输入卡号并设密码，即刻开通。</p>
  </header>

  <div class="tiers" id="tiers">
    <div class="tier on" data-tier="basic" data-label="存链-基础" data-price="__PRICE_BASIC__"><span class="rd"></span><div class="tn">存链-基础</div><div class="tc">5<small> GB</small></div><div class="tp">__PRICE_BASIC__</div></div>
    <div class="tier" data-tier="pro" data-label="存链-专业" data-price="__PRICE_PRO__"><span class="pop">大容量</span><span class="rd"></span><div class="tn">存链-专业</div><div class="tc">50<small> GB</small></div><div class="tp">__PRICE_PRO__</div></div>
  </div>

  <div class="panel">
    <div class="ph">扫码付款</div>
    <div class="psub">用微信或支付宝任一扫码支付；<b>付款时请在备注里填下面这行</b>，方便核对你买的套餐。</div>
    <div class="pays">
      <div class="pay wx"><div class="pt"><span class="d" style="background:#22c55e"></span>微信支付</div><div class="qr" id="qrWx"></div></div>
      <div class="pay ali"><div class="pt"><span class="d" style="background:#1677ff"></span>支付宝</div><div class="qr" id="qrAli"></div></div>
    </div>
    <div class="remark"><span class="lab">付款备注</span><span class="val" id="remarkVal">存链-基础</span><span class="sp"></span><button class="sm" id="copyRemark">复制备注</button></div>
  </div>

  <div class="steps">
    <div class="step"><div class="n">1</div><h4>选套餐</h4><p>上面选基础 / 专业，备注会自动对应。</p></div>
    <div class="step"><div class="n">2</div><h4>扫码付款</h4><p>微信或支付宝扫码，付款时填上"付款备注"。</p></div>
    <div class="step"><div class="n">3</div><h4>发截图给客服</h4><p>加下方联系方式，把付款截图发过来。</p></div>
    <div class="step"><div class="n">4</div><h4>收卡开通</h4><p>收到卡号后，回首页输入卡号+设密码即开通。</p></div>
  </div>

  <div class="contact"><span class="ci">💬</span><div><div class="cv" id="contactVal">__PAY_CONTACT__</div><div style="color:var(--mut);font-size:.82rem">付款后联系客服发卡（人工发卡，通常很快）</div></div><span class="sp"></span><button class="sm" id="copyContact">复制联系方式</button></div>

  <div class="cta"><a href="/"><button class="pri">已有卡号？去开通 →</button></a></div>

  <footer class="foot"><span>© 存链 · link.aistela.com</span><a href="/privacy">隐私政策</a><a href="/terms">服务条款</a><span class="sp"></span><a href="/">返回首页</a></footer>
</div>
<div class="toast" id="toast"></div>
<script nonce="__CSP_NONCE__">
function $(id){return document.getElementById(id)}
function toast(m){var t=$("toast");t.textContent=m;t.classList.add("show");setTimeout(function(){t.classList.remove("show")},2000)}
function setQr(boxId,url,name){var box=$(boxId);if(!box)return;if(url){var img=document.createElement("img");img.src=url;img.alt=name;img.onerror=function(){box.className="qr empty";box.textContent=name+"收款码加载失败，请联系客服"};box.appendChild(img)}else{box.className="qr empty";box.textContent="未设置"+name+"收款码"}}
setQr("qrWx","__PAY_WX_QR__","微信");
setQr("qrAli","__PAY_ALI_QR__","支付宝");
var tiers=document.querySelectorAll("#tiers .tier");
for(var i=0;i<tiers.length;i++){tiers[i].addEventListener("click",function(){for(var j=0;j<tiers.length;j++)tiers[j].classList.remove("on");this.classList.add("on");$("remarkVal").textContent=this.getAttribute("data-label")})}
$("copyRemark").addEventListener("click",function(){navigator.clipboard.writeText($("remarkVal").textContent).then(function(){toast("备注已复制")})});
$("copyContact").addEventListener("click",function(){navigator.clipboard.writeText($("contactVal").textContent).then(function(){toast("联系方式已复制")})});
</script>
</body></html>`;
