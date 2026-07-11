-- 第二期：图床 → 文件床。存储改按容量算，images 表升级成通用 files（加 kind/r2_key/mime）。
-- 应用：wrangler d1 execute tuku-db --remote --file=migration-v2.sql
-- （ALTER ADD COLUMN 幂等性弱：只跑一次；已跑过再跑会报 duplicate column，忽略即可。）

ALTER TABLE customers ADD COLUMN byte_limit INTEGER;         -- 容量上限（字节），按档位
ALTER TABLE images    ADD COLUMN kind TEXT NOT NULL DEFAULT 'image'; -- image | file
ALTER TABLE images    ADD COLUMN r2_key TEXT;               -- 非图片文件在 R2 的 key（图片为 null）
ALTER TABLE images    ADD COLUMN mime TEXT;                 -- 文件 MIME

-- 给已有客户按档位补容量上限（basic=5GB, pro=50GB）
UPDATE customers SET byte_limit = 5368709120  WHERE tier='basic' AND byte_limit IS NULL;
UPDATE customers SET byte_limit = 53687091200 WHERE tier='pro'   AND byte_limit IS NULL;
