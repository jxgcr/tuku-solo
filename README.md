# 存链（tuku）· 文件/图片托管 SaaS

多租户文件托管产品，要卖的。图片存 Cloudflare Images、其它文件存 R2、元数据存 D1，算力在 Hannah 号。卡密来自畅密（changmi），另有免费档。
> 品牌名「存链」；代号/仓库/worker/D1/R2 内部仍叫 `tuku`（省级联）。

## 访问入口
| 用途 | 地址 |
|---|---|
| 客户端（落地页+应用） | `https://link.aistela.com`（`tu.aistela.com` 旧别名仍可用） |
| worker 直连 | `https://tuku.5209696.xyz` |
| 运营台 | `link.aistela.com/scfw`（`/admin` 已废，防猜） |
| 开发者上传 API | `link.aistela.com/api/v1/upload`（PicGo/Typora/兰空兼容） |
| 信任页 | `/privacy`、`/terms` |
| 图片直链 | `/i/<cf_id>`（随机 id，不可枚举） |
| 文件直链 | `/f/<id>~<HMAC令牌>`（带令牌，不可枚举；html/svg 强制下载） |

## 档位（按容量）
| 档 | 容量 | 卡前缀 | 来源 |
|---|---|---|---|
| 免费 | 500MB + 图片水印 + 按IP限注册 | `FREE-` | 网页「免费试用」自助开通，无需卡 |
| 存链-基础 | 5GB | `CM-` | 畅密卡（app_key `APP_KEY_TU_BASIC`） |
| 存链-专业 | 50GB | `CM-` | 畅密卡（app_key `APP_KEY_TU_PRO`） |

档位定义在 `index.js` 的 `TIERS`；改容量改这里。

## 客户能做什么
落地页 → 免费试用 / 贴卡开通 → 登录（卡号+密码，PBKDF2+HMAC会话）→ 仪表盘（用量/最近上传）、上传（拖拽/粘贴Ctrl+V/多选/进度/压缩水印/大文件断点续传）、我的文件（干净缩略图+选择+批量+⋯菜单：多格式复制/下载/重命名/详情/移动/删除、灯箱、搜索排序、相册）、设置（账户信息+升级+开发者API密钥）。手机端侧栏收成抽屉、网格2列。

## 开发者 API
- 生成密钥：设置页（付费档专属，免费档显示「升级解锁」）。密钥 `tuku_...`，存 `customers.api_key`。
- 上传：`POST /api/v1/upload`，头 `Authorization: Bearer tuku_...`，字段 `file`；返回兰空(Lsky)兼容结构 `{status,message,data:{url,...}}`。

## 运营台 /scfw
`ADMIN_KEY` 登录（≠客户密码，≠云枢）。概览（客户数/活跃/文件/用量 + 获客指标：近7天新增、付费/免费、转化率、7天内到期 + 套餐分布）、客户管理（搜索/状态筛选/改档/停服/删除，删除连带清存储）。

## 部署 / 配置
- **部署走 CI**：双击 `一键部署.cmd` 或 `gh workflow run deploy.yml --repo jxgcr/tuku`。严禁本机 `wrangler deploy`。
- **账号**：Hannah `2e7307f9e8cd602d0396fc1f4ef532c9`（部署前 `npx wrangler whoami` 核对）。
- **机密（wrangler secret，不进 git）**：`CF_IMAGES_TOKEN`、`SESSION_SECRET`、`APP_KEY_TU_BASIC`、`APP_KEY_TU_PRO`、`ADMIN_KEY`。
- **非机密配置（wrangler.jsonc vars，改完重部）**：`BUY_URL`（购买/续费入口）、`FREE_SIGNUP_MAX`/`FREE_SIGNUP_WINDOW`（免费限注册）、`PUBLIC_BASE`、会话/暴破参数。
- **建库/迁移**：新库 `schema.sql`（权威、含全部列）；老库按序 `migration-v2/v3/v4.sql`（双击 `应用迁移v3.cmd`/`应用迁移v4.cmd`）。**新代码依赖 `api_key` 列，部署前必须先跑 v4。**

## 安全现状（已加固并实测）
会话 HMAC+过期+常量时间比较；租户隔离（读写删全按会话 customer.id 作用域，mpu key 前缀 customer.id）；密码 PBKDF2-SHA256 10万次+独立盐；登录暴破锁按 IP+卡号双维度；运营台 ADMIN_KEY+暴破锁+隐蔽路径；SQL 全参数化；文件直链 HMAC 令牌防枚举；上传 html/svg 强制下载+CSP sandbox（防存储型 XSS）；CSP 用逐请求 nonce（无 unsafe-inline）；分片上传只认 R2 真实大小防配额造假；上传写库失败回滚存储、删除失败入 `pending_deletes` 由每6h `scheduled` 对账补删；上游调用带超时。详见 `docs/`。

## ⚠️ 待办（上线前需处理，非代码能覆盖）
- **购买/续费入口未通**：`BUY_URL` 现指 `pay.aistela.com`，但该发卡页未建、changmi 发卡站也未开卖 → 落地页「购买正式版」目前是死链。发卡渠道定了再改 `BUY_URL`（一行）。
- **免费档水印是网页端强制**：真正不可绕过需在 CF Images 配服务端水印变体（账号侧）；已把开发者 API 挡在付费档外堵一条绕过路。
- **续费/升级无自助流**：现模型是「一卡一账号」，买新卡=开新账号，暂无「登录后输新卡续期/升级同一账号」的接口（如需，要加后端 redeem 流程）。

## 文档
- 运维恢复：`docs/运维恢复手册.md`（回滚/D1 time-travel/备份/迁移/密钥）
- 变更日志：`docs/变更日志.md`
- 第三方审查/验收提示词：`docs/第三方审查提示词.md`、`docs/整改验收提示词.md`
- 全套系统说明（存链+云枢共用畅密+aistela 门面）：`D:\系统默认\桌面\畅密\yunshu\云枢-系统总说明-交接必读.md`
