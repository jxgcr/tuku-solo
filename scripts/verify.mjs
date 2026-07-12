#!/usr/bin/env node
// 存链-私有版 部署前验证闸：文件存在 + 语法 + 前端求值 + 无 A 版残留。纯本地，无网络。
import { execSync } from "node:child_process";
import { readFileSync, existsSync, statSync, writeFileSync, unlinkSync } from "node:fs";

const A_ACCOUNT = "2e7307f9e8cd602d0396fc1f4ef532c9"; // A 版(Hannah)账号，私有版里不该出现
let failed = 0;
const fail = (m) => { console.error("X " + m); failed++; };
const ok = (m) => console.log("OK " + m);

for (const f of ["index.js", "wrangler.jsonc", "schema.sql"]) {
  if (!existsSync(f)) fail("缺文件 " + f); else ok("存在 " + f);
}

try { execSync("node --check index.js", { stdio: "pipe" }); ok("index.js 语法通过"); }
catch (e) { fail("index.js 语法错误:\n" + (e.stderr ? e.stderr.toString() : e.message)); }

if (existsSync("index.js")) {
  const kb = statSync("index.js").size / 1024;
  if (kb < 3) fail("index.js 疑似被截断 (" + kb.toFixed(1) + "KB)"); else ok("index.js 体积正常 (" + kb.toFixed(1) + "KB)");
}

// 前端模板求值检查：解析出「实际下发」的 <script> 再 node --check（模板转义坑 node --check 查不出）
try {
  const src = readFileSync("index.js", "utf8");
  // 取出共用 CSS 常量，供模板里的 ${BASE_CSS} 替换后再求值
  let baseCss = "";
  const bm = src.indexOf("const BASE_CSS = `");
  if (bm >= 0) { const s = bm + "const BASE_CSS = `".length; baseCss = src.slice(s, src.indexOf("`", s)); }
  for (const name of ["SETUP_HTML", "PAGE_HTML"]) {
    const marker = "const " + name + " = `";
    const m = src.indexOf(marker);
    if (m < 0) continue;
    const s = m + marker.length;
    const e = src.indexOf("`;", s);
    let content = src.slice(s, e).split("${BASE_CSS}").join(baseCss);
    if (content.includes("${") || content.includes("`")) { console.warn("⚠ 跳过 " + name + "(仍含 ${ 或反引号，无法安全求值)"); continue; }
    const html = eval("`" + content + "`");
    const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map((x) => x[1]).join("\n;\n");
    if (!scripts.trim()) continue;
    const tmp = ".verify_" + name + ".js";
    writeFileSync(tmp, scripts);
    try { execSync("node --check " + tmp, { stdio: "pipe" }); ok(name + " 前端下发脚本语法通过"); }
    catch (err) { fail(name + " 前端下发脚本语法错误(求值后):\n" + (err.stderr ? err.stderr.toString() : err.message)); }
    finally { try { unlinkSync(tmp); } catch (e) {} }
  }
} catch (e) { console.warn("⚠ 前端求值检查未执行: " + e.message); }

if (existsSync("wrangler.jsonc")) {
  const t = readFileSync("wrangler.jsonc", "utf8");
  if (t.includes(A_ACCOUNT)) fail("wrangler.jsonc 残留 A 版账号 ID，私有版不该有——请清掉");
  else ok("无 A 版账号残留");
  if (t.includes("changmi") || t.includes("aistela") || t.includes("CF_IMAGES")) fail("wrangler.jsonc 残留 A 版依赖(畅密/aistela/CF_IMAGES)");
  else ok("无 A 版依赖残留");
  if (t.includes('"binding": "R2"') && t.includes('"binding": "DB"')) ok("R2 + D1 绑定就位");
  else fail("缺 R2 或 D1 绑定");
}

if (failed) { console.error("\n验证失败：" + failed + " 项"); process.exit(1); }
console.log("\n验证全部通过");
