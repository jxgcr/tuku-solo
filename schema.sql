-- 存链（tuku）元数据库（tuku-db）——权威建表脚本，已合并第二期(文件床)所有列。
-- 图片本体在 CF Images、非图片文件在 R2，这里只记"哪个文件属于谁、在哪个相册、多大"。
-- 新建库一步到位：
--   wrangler d1 create tuku-db          # 把返回的 id 填进 wrangler.jsonc
--   wrangler d1 execute tuku-db --remote --file=schema.sql
-- 说明：老库(第一期建的)请改用 migration-v2.sql 增量升级；本文件是“从零重建”的权威版，
--       与运行时代码(index.js)保持一致，灾备/迁移以此为准。

CREATE TABLE IF NOT EXISTS customers (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  card          TEXT UNIQUE NOT NULL,           -- 卡号（登录账号）
  tier          TEXT NOT NULL,                  -- basic / pro
  password_hash TEXT,                           -- 首次开通时设的访问密码（PBKDF2）
  img_limit     INTEGER NOT NULL DEFAULT 9999999, -- 遗留列(第一期按张数)，现按容量，保留仅为兼容 INSERT
  byte_limit    INTEGER,                        -- 容量上限（字节），按档位：basic=5GB, pro=50GB
  expires_at    INTEGER,                        -- 到期时间戳（秒），null=不限
  status        TEXT NOT NULL DEFAULT 'active', -- active / disabled
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS albums (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  name        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS images (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  album_id    INTEGER,                          -- null=未分组
  kind        TEXT NOT NULL DEFAULT 'image',    -- image | file
  cf_id       TEXT NOT NULL,                    -- CF Images 里的图片 id；非图片文件存空串 ''
  r2_key      TEXT,                             -- 非图片文件在 R2 的 key（图片为 null）
  mime        TEXT,                             -- 文件 MIME
  filename    TEXT,
  bytes       INTEGER,
  uploaded_at INTEGER NOT NULL
);

-- 待清理队列：删除时存储对象删失败就登记这里，scheduled(每6h) 补删，防孤儿静默泄漏
CREATE TABLE IF NOT EXISTS pending_deletes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,     -- r2 | image
  ref        TEXT NOT NULL,     -- r2 的 key 或 CF Images 的 cf_id
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_images_customer ON images(customer_id);
CREATE INDEX IF NOT EXISTS idx_images_album ON images(album_id);
CREATE INDEX IF NOT EXISTS idx_albums_customer ON albums(customer_id);
CREATE INDEX IF NOT EXISTS idx_images_cf ON images(cf_id);
