# tuku · 图床 SaaS

多租户图片托管产品。算力在 Hannah，图片存 Cloudflare Images，元数据存 D1，卡密来自畅密（changmi）。对外走 `tu.aistela.com`。

- 部署：双击 `一键部署.cmd`（走 CI，仓库 `jxgcr/tuku`），或 `gh workflow run deploy.yml --repo jxgcr/tuku`
- 账号：Hannah `2e7307f9e8cd602d0396fc1f4ef532c9`
- 机密（wrangler secret）：`CF_IMAGES_TOKEN`、`SESSION_SECRET`、`APP_KEY_TU_BASIC`、`APP_KEY_TU_PRO`
- 档位：图床-基础 / 图床-专业（张数上限见 `index.js` 的 `TIERS`）

完整系统说明见 `D:\系统默认\桌面\畅密\yunshu\云枢-系统总说明-交接必读.md`（图床与云枢共用畅密发卡 + aistela 门面）。
