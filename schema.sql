-- 存链-私有版（solo）元数据库。单人自持，纯 R2（图片也存 R2，不用 CF Images）。
-- 买家一般不用手动建表：首次打开 /setup 时代码会自动 CREATE TABLE IF NOT EXISTS。
-- 这份仅作参考 / 灾备重建用：
--   wrangler d1 execute cloud-db --remote --file=schema.sql

-- 单账户配置：owner 密码哈希、会话签名串、品牌等，都存这里（无多租户 customers 表）
CREATE TABLE IF NOT EXISTS config (
  key   TEXT PRIMARY KEY,   -- owner_hash | session_secret | brand_name | brand_logo | initialized
  value TEXT
);

CREATE TABLE IF NOT EXISTS albums (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

-- 所有文件（图片和其它一视同仁，都存 R2）
CREATE TABLE IF NOT EXISTS files (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  album_id    INTEGER,                          -- null=未分组
  kind        TEXT NOT NULL DEFAULT 'file',     -- image | file（仅用于前端分类展示）
  r2_key      TEXT NOT NULL,                    -- R2 对象 key（缩略图为 r2_key + '.thumb'）
  has_thumb   INTEGER NOT NULL DEFAULT 0,       -- 1=有缩略图（图片上传时前端生成）
  mime        TEXT,
  filename    TEXT,
  bytes       INTEGER,
  uploaded_at INTEGER NOT NULL
);

-- 待清理队列：删除时 R2 对象删失败就登记这里，scheduled(每6h) 补删，防孤儿
CREATE TABLE IF NOT EXISTS pending_deletes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ref        TEXT NOT NULL,     -- R2 的 key
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_files_album ON files(album_id);
CREATE INDEX IF NOT EXISTS idx_files_uploaded ON files(uploaded_at);
