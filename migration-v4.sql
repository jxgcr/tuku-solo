-- 第四期：开发者 API。customers 加 api_key（PicGo/Typora 直传用的长期密钥）。
-- 应用（老库升级；新库直接用 schema.sql 已含此列与索引）：
--   wrangler d1 execute tuku-db --remote --file=migration-v4.sql
-- （ALTER ADD COLUMN 幂等性弱：只跑一次；已跑过再跑会报 duplicate column，忽略即可。）

ALTER TABLE customers ADD COLUMN api_key TEXT;   -- 开发者 API 密钥(tuku_...)，null=未生成

-- 唯一部分索引：按 api_key 查客户（登录直传时用），并防重复；NULL 行不入索引可多条
CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_apikey ON customers(api_key) WHERE api_key IS NOT NULL;

-- 说明：免费档(tier='free')不需要建表改动，沿用 customers/images 现有结构，
--       byte_limit=500MB、expires_at=NULL、card 以 FREE- 前缀区分。
