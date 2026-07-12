@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ========================================
echo   Apply migration-v3 (pending_deletes table)
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
echo [Step 2] Creating table pending_deletes in tuku-db ...
call npx wrangler d1 execute tuku-db --remote --file=migration-v3.sql
if errorlevel 1 ( echo. & echo ERROR - screenshot this window and send to AI. & pause & exit /b 1 )
echo.
echo Done. The 6-hourly cleanup cron can now purge orphaned storage objects.
echo.
pause
