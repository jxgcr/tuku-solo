# tuku-solo 构建进度（私有版）

从 A 版（多租户 SaaS）fork 而来，改造成「单人自持、纯 R2、可部署到买家自己 CF 账号」的私有云盘。

## 已完成 ✅
- fork 出独立仓库，已断开与 A 版本地仓库的 origin（不会误推 A 版线上）
- `wrangler.jsonc`：去掉 CF Images / 畅密 / Turnstile / 购买 相关配置；改纯 R2 + D1 + DO；
  加 `BRAND_NAME`/`BRAND_LOGO`/`BYTE_LIMIT` 配置；`database_id` 留空待部署自动回填
- `schema.sql`：去掉多租户 `customers`，改单账户 `config` 表（owner 密码/会话串/品牌）；
  `images`→`files`（纯 R2，加 `has_thumb`）；`albums` 去 `customer_id`；`pending_deletes` 简化

## 已完成 ✅（index.js 全量改造，已验证）
1. ✅ 删 SaaS 后端：运营台/购买/免费/畅密/CF Images/Turnstile 全清（index.js 从头重写为 solo）
2. ✅ 单 owner 鉴权：`config` 表存 owner 密码哈希 + 会话串（`secretOf` 首次自动生成）；
   `/setup` 首启页 + `/api/setup`（建表+设密码）；`handleLogin` 只验密码；`requireOwner` 校验会话
3. ✅ 纯 R2：`storeUpload` 图片也走 R2 + 前端 canvas 缩略图存 `<key>.thumb`；`serveFile ?thumb`；
   `files` 表；`/f/<id>~<token>` 带签名令牌；图片 link/thumb 都走 `/f/`
4. ✅ 品牌配置化：`BRAND_NAME`/`BRAND_LOGO`/`PUBLIC_BASE` 占位替换（htmlResponse）
5. ✅ 前端：登录只密码；`/setup` 首启页；「我的云盘」App（我的空间+空间构成+上传取消/暂停+
   相册+灯箱+设置），全部改品牌；隐私/条款页
6. ✅ verify.mjs 改 solo（去 Hannah 账号检查，加"无 A 版残留"检查，前端求值解析 ${BASE_CSS}）
7. ✅ 清掉 A 版残留文件（部署/迁移脚本、A 版 docs）；package.json 改名

**验证**：`node scripts/verify.mjs` 全绿（含两个模板的前端脚本求值检查）；
浏览器渲染 setup/app 两页零 console 报错，仪表盘/构成条/相册/画廊/上传件均正常。

## 待做（部署与文档，下一轮）
- **「Deploy to Cloudflare」按钮**：需要 GitHub 公开仓库 + 部署描述，让买家点按钮自动建 D1/R2 并回填 id
- **买家部署文档**：README 重写成"如何部署到你自己的 CF"（含绑卡说明、设密码、填域名）
- **本地/CI 部署**：`.github/workflows/deploy.yml` 目前沿用 A 版(npx wrangler deploy)，买家版应改为按钮为主
- 真机联调：建一个真 D1/R2 跑一遍 setup→登录→上传→看图→删（沙箱连不到 CF，需在本机/CI）

## 关键决策（已定）
- fork 独立仓库（非一套代码加开关）
- 缩略图：前端 canvas 生成，随原图一起存 R2
- 运营台：删

## 注意
- A 版（jxgcr/tuku, link.aistela.com）是线上真用户，**本仓库任何改动都不影响它**
- 本仓库暂无 GitHub 远端；等 index.js 改完、买家部署流程自测通过，再建 jxgcr/tuku-solo
