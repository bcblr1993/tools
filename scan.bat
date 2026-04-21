@echo off
chcp 65001 >nul
echo ========================================
echo   软件资产扫描工具 - 正在扫描...
echo ========================================
python "%~dp0software_scanner.py"
if errorlevel 1 (
    echo [错误] 未找到 Python，请先安装 Python 3.6+
    pause
    exit /b 1
)
echo.
echo 扫描完成！报告已保存到当前目录。
pause
