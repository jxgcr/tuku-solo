# tuku-solo 构建进度（私有版）

从 A 版（多租户 SaaS）fork 而来，改造成「单人自持、纯 R2、可部署到买家自己 CF 账号」的私有云盘。

## 已完成 ✅
- fork 出独立仓库，已断开与 A 版本地仓库的 origin（不会误推 A 版线上）
- `wrangler.jsonc`：去掉 CF Images / 畅密 / Turnstile / 购买 相关配置；改纯 R2 + D1 + DO；
  加 `BRAND_NAME`/`BRAND_LOGO`/`BYTE_LIMIT` 配置；`database_id` 留空待部署自动回填
- `schema.sql`：去掉多租户 `customers`，改单账户 `config` 表（owner 密码/会话串/品牌）；
  `images`→`files`（纯 R2，加 `has_thumb`）；`albums` 去 `customer_id`；`pending_deletes` 简化

## 待做（index.js 改造，按顺序）
1. **删 SaaS 后端**：`ADMIN_HTML`/`BUY_HTML` 两个大模板常量、`/scfw`/`/api/admin/*`/`/buy` 路由、
   `requireAdmin`/`adminGate`/`handleAdmin*`/`buyPageResponse`/`handleFreeSignup`/Turnstile；
   `changmiVerify`/`APP_KEY`；`imagesApi`/`imgThumb`/`serveImage`（CF Images 相关全删）
2. **单 owner 鉴权**：`config` 表存 owner 密码哈希 + 会话串（首次自动生成）。
   `handleLogin` 改为「只验密码」；新增 `/setup` 首启页 + `/api/setup`（建表 + 设 owner 密码）；
   `requireCustomer` 从 config 合成一个 owner 身份（byte_limit 取 env.BYTE_LIMIT）
3. **纯 R2**：`storeUpload` 图片也走 R2；接收前端 canvas 生成的缩略图存 `<key>.thumb`；
   `serveFile` 支持 `?thumb` 读缩略图；`files` 表替代 `images`；`/i/` 路由删除，图片 link 走 `/f/`
4. **品牌配置化**：`存链`/LOGO/域名写死处 → 读 `BRAND_NAME`/`BRAND_LOGO`/`PUBLIC_BASE`（`htmlResponse` 里做占位替换）
5. **前端 PAGE_HTML**：登录卡号+密码 → 只密码；删升级横幅/免费试用/购买/档位；
   落地页简化成「你的私人云盘」+ 登录/首启；上传时前端生成缩略图一起传
6. **部署件**：`deploy to cloudflare` 按钮配置 + 买家部署文档（README 重写）；删 A 版的 `一键部署.cmd`/`应用迁移*.cmd`/`/buy` 相关 docs

## 关键决策（已定）
- fork 独立仓库（非一套代码加开关）
- 缩略图：前端 canvas 生成，随原图一起存 R2
- 运营台：删

## 注意
- A 版（jxgcr/tuku, link.aistela.com）是线上真用户，**本仓库任何改动都不影响它**
- 本仓库暂无 GitHub 远端；等 index.js 改完、买家部署流程自测通过，再建 jxgcr/tuku-solo
