@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ========================================
echo   Set TURNSTILE_SECRET (free-signup captcha)
echo ========================================
echo.
echo [Step 1] Check account (must be Hannah)
call npx wrangler whoami
echo.
echo ----------------------------------------
echo Account should be Hannah.
echo Next: paste the Turnstile SECRET KEY when it asks "Enter a secret value".
echo (the secret is sent straight to Cloudflare, not saved in any file)
echo ----------------------------------------
pause
echo.
echo [Step 2] Setting secret ...
call npx wrangler secret put TURNSTILE_SECRET
if errorlevel 1 ( echo. & echo ERROR - screenshot this window and send to AI. & pause & exit /b 1 )
echo.
echo Done. Free-signup captcha is now fully active.
echo.
pause
