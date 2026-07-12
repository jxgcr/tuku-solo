@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ========================================
echo   Apply migration-v4 (api_key column + unique index)
echo   For developer API (PicGo/Typora direct upload)
echo ========================================
echo.
echo [Step 1] Check current Cloudflare account (must be Hannah)
echo.
call npx wrangler whoami
echo.
echo ----------------------------------------
echo Account should be Hannah. Press any key to apply, or close window if not Hannah.
echo ----------------------------------------
pause
echo.
echo [Step 2] Adding column api_key + unique index to tuku-db ...
call npx wrangler d1 execute tuku-db --remote --file=migration-v4.sql
if errorlevel 1 ( echo. & echo ERROR - screenshot this window and send to AI. & pause & exit /b 1 )
echo.
echo Done. Now the new code (free tier / landing page / developer API) is safe to deploy.
echo.
pause
