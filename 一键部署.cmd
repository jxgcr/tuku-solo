@echo off
chcp 65001 >nul
echo 正在部署 图床 tuku ...
gh workflow run deploy.yml --repo jxgcr/tuku
if errorlevel 1 ( echo. ^& echo 触发失败:确认 gh 已登录且已设 CLOUDFLARE_API_TOKEN。 ^& pause ^& exit /b 1 )
echo 已触发,等几秒查结果...
timeout /t 8 >nul
gh run list --repo jxgcr/tuku --limit 1
echo.
echo 最上面一行 success = 部署成功。
pause
