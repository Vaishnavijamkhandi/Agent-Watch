@echo off
cd /d "%~dp0\..\frontend"
npm ci && npm run build
