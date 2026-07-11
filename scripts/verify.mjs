#!/usr/bin/env node
// 图床 tuku 部署前验证闸：文件存在 + 语法 + 账号绑定。纯本地，无网络。
import { execSync } from "node:child_process";
import { readFileSync, existsSync, statSync } from "node:fs";

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

if (existsSync("wrangler.jsonc")) {
  const t = readFileSync("wrangler.jsonc", "utf8");
  if (t.includes(EXPECT_ACCOUNT)) ok("wrangler.jsonc 账号=Hannah(" + EXPECT_ACCOUNT + ")");
  else fail("wrangler.jsonc 的 account_id 不是 Hannah，拒绝部署");
  if (t.includes("TODO_运行")) console.warn("⚠ 提醒：wrangler.jsonc 里 D1 database_id 还没填——部署前先建 tuku-db 并填 id");
}

if (failed) { console.error("\n验证失败：" + failed + " 项"); process.exit(1); }
console.log("\n验证全部通过");
