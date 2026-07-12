#!/usr/bin/env node
// 图床 tuku 部署前验证闸：文件存在 + 语法 + 账号绑定。纯本地，无网络。
import { execSync } from "node:child_process";
import { readFileSync, existsSync, statSync, writeFileSync, unlinkSync } from "node:fs";

const EXPECT_ACCOUNT = "2e7307f9e8cd602d0396fc1f4ef532c9"; // Hannah
let failed = 0;
const fail = (m) => { console.error("X " + m); failed++; };
const ok = (m) => console.log("OK " + m);

for (const f of ["index.js", "wrangler.jsonc", "schema.sql"]) {
  if (!existsSync(f)) fail("缺文件 " + f); else ok("存在 " + f);
}

try {
  execSync("node --check index.js", { stdio: "pipe" });
  ok("index.js 语法通过");
} catch (e) {
  fail("index.js 语法错误:\n" + (e.stderr ? e.stderr.toString() : e.message));
}

if (existsSync("index.js")) {
  const kb = statSync("index.js").size / 1024;
  if (kb < 3) fail("index.js 疑似被截断 (" + kb.toFixed(1) + "KB)");
  else ok("index.js 体积正常 (" + kb.toFixed(1) + "KB)");
}

// 前端模板转义坑：PAGE_HTML/ADMIN_HTML 是反引号模板，下发时才求值(\/ \n \" 等会被处理)。
// 直接 node --check index.js 查不出前端 JS 的语法错，必须求值出“实际下发”的 <script> 再检查。
try {
  const src = readFileSync("index.js", "utf8");
  for (const name of ["PAGE_HTML", "ADMIN_HTML"]) {
    const marker = "const " + name + " = `";
    const m = src.indexOf(marker);
    if (m < 0) continue;
    const s = m + marker.length;
    const e = src.indexOf("`", s);
    const content = src.slice(s, e);
    if (content.includes("${") || content.includes("`")) { console.warn("⚠ 跳过 " + name + " 前端求值检查(含 ${ 或反引号，无法安全求值)"); continue; }
    const html = eval("`" + content + "`"); // 复现下发时的转义处理
    const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((x) => x[1]).join("\n;\n");
    if (!scripts.trim()) continue;
    const tmp = ".verify_" + name + ".js";
    writeFileSync(tmp, scripts);
    try { execSync("node --check " + tmp, { stdio: "pipe" }); ok(name + " 前端下发脚本语法通过"); }
    catch (err) { fail(name + " 前端下发脚本语法错误(求值后):\n" + (err.stderr ? err.stderr.toString() : err.message)); }
    finally { try { unlinkSync(tmp); } catch (e) {} }
  }
} catch (e) {
  console.warn("⚠ 前端求值检查未执行: " + e.message);
}

if (existsSync("wrangler.jsonc")) {
  const t = readFileSync("wrangler.jsonc", "utf8");
  if (t.includes(EXPECT_ACCOUNT)) ok("wrangler.jsonc 账号=Hannah(" + EXPECT_ACCOUNT + ")");
  else fail("wrangler.jsonc 的 account_id 不是 Hannah，拒绝部署");
  if (t.includes("TODO_运行")) console.warn("⚠ 提醒：wrangler.jsonc 里 D1 database_id 还没填——部署前先建 tuku-db 并填 id");
}

if (failed) { console.error("\n验证失败：" + failed + " 项"); process.exit(1); }
console.log("\n验证全部通过");
