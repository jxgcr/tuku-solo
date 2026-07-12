# 存链 · 私有云盘（自持版）

一套**只属于你自己的**文件 / 图片云盘，部署在**你自己的 Cloudflare 账号**里——
数据全在你手上，运营方碰不到；用的是 Cloudflare 的免费额度，正常用**不花钱**。

- 📦 图片、视频、音频、PDF、压缩包，任意文件统一收纳
- 🔒 文件默认私密、不公开；分享链接带签名令牌，别人猜不到
- ⚡ 拖拽 / 粘贴即传，自动压缩缩略图；大文件断点续传、可暂停/取消
- 🗂️ 相册归类、批量管理、灯箱看图、搜索排序
- 🎨 名字和 LOGO 可自定义

---

## 一键部署（推荐）

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/jxgcr/tuku-solo)

点上面的按钮，Cloudflare 会**自动**在你账号里创建好 D1 数据库和 R2 存储桶并部署，你只需：

1. 用你的 Cloudflare 账号登录、授权；
2. 按提示确认（会让你**绑一张卡**——这是 Cloudflare 开通 R2 的要求，免费额度内不会扣费，虚拟卡/借记卡都行）；
3. 等它部署完，给你一个网址（形如 `https://my-cloud.xxx.workers.dev`）。

> 没有 GitHub 账号也没关系，按钮流程会引导你 fork 一份到你自己的 GitHub。

## 首次使用

1. 打开部署好的网址 → 自动进入 **首次设置** 页；
2. 给你的云盘**设一个登录密码**（≥8 位，记牢，找不回）；
3. 进去就能用了。以后凭这个密码登录。

**就这样，不用敲任何命令、不用建表、不用配密钥。** 数据库表首次打开自动建好，会话密钥自动生成。

## 自定义（可选）

在 Cloudflare 后台 → 你的 Worker → Settings → Variables，改这几个 `vars` 再重新部署即可：

| 变量 | 作用 | 默认 |
|---|---|---|
| `BRAND_NAME` | 云盘显示的名字 | `我的云盘` |
| `BRAND_LOGO` | LOGO 里的字（一个字或 emoji） | `云` |
| `BYTE_LIMIT` | 容量上限（字节）。默认 9GB，压在 R2 免费额度(10GB)内**永不产生账单** | `9663676416` |
| `PUBLIC_BASE` | 你的自定义域名（留空则用 workers.dev 地址，直链也能用） | 空 |

**想用自己的域名**：在 Cloudflare 后台把域名加到这个 Worker（Custom Domain），再把 `PUBLIC_BASE` 填成 `https://你的域名`。
> 注意：`*.workers.dev` 在中国大陆常被墙，面向国内使用建议绑自己的域名。

**想要更大容量**：把 `BYTE_LIMIT` 调大。超过 10GB 的部分会按 Cloudflare R2 的价格从你卡里扣费，自行承担。

## 限制与说明

- 单个文件网页直传上限 100MB；更大的文件自动走分片，最大 5GB。
- 免费额度：R2 存储 10GB、每月足量读写；单人自用一般碰不到上限。
- 这是**你自己的**部署：可用性、账单、数据备份都由你的 Cloudflare 账号决定，重要文件请自行另存一份。
- 隐私 / 服务条款见站内 `/privacy`、`/terms`。

## 给动手能力强的（可选：命令行部署）

```bash
npm i -g wrangler
wrangler login
wrangler d1 create cloud-db          # 把返回的 database_id 填进 wrangler.jsonc
wrangler r2 bucket create cloud-files
npm run deploy
```

首次打开网址走 `/setup` 设密码即可（表由代码自动创建，无需手动 `d1 execute`）。
