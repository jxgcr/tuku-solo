-- 图床 SaaS 元数据库（tuku-db）。CF Images 只存图本身，这里记"哪张图属于谁、在哪个相册"。
-- 建库：wrangler d1 create tuku-db  → 把 id 填进 wrangler.jsonc
-- 建表：wrangler d1 execute tuku-db --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS customers (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  card          TEXT UNIQUE NOT NULL,        -- 卡号（登录账号）
  tier          TEXT NOT NULL,               -- basic / pro
  password_hash TEXT,                        -- 首次开通时设的访问密码（PBKDF2）
  img_limit     INTEGER NOT NULL,            -- 图片张数上限（按档位）
  expires_at    INTEGER,                     -- 到期时间戳（秒），null=不限
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
  album_id    INTEGER,                       -- null=未分组
  cf_id       TEXT NOT NULL,                 -- Cloudflare Images 里的图片 id
  filename    TEXT,
  bytes       INTEGER,
  uploaded_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_images_customer ON images(customer_id);
CREATE INDEX IF NOT EXISTS idx_images_album ON images(album_id);
CREATE INDEX IF NOT EXISTS idx_albums_customer ON albums(customer_id);
CREATE INDEX IF NOT EXISTS idx_images_cf ON images(cf_id);
