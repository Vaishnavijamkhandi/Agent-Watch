@echo off
cd /d "%~dp0\.."
python -m pytest backend\tests -q
