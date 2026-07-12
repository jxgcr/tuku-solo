-- 第三期：孤儿对象对账。删除时存储对象删失败 → 登记这里，scheduled(每6h) 补删。
-- 应用（老库升级用；新库直接用 schema.sql 已含此表）：
--   wrangler d1 execute tuku-db --remote --file=migration-v3.sql
CREATE TABLE IF NOT EXISTS pending_deletes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,     -- r2 | image
  ref        TEXT NOT NULL,     -- r2 的 key 或 CF Images 的 cf_id
  attempts   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
