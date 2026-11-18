@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "DEST=%APPDATA%\Wireshark"
if not exist "%DEST%\plugins" mkdir "%DEST%\plugins"

copy /Y "lab1a.lua" "%DEST%\plugins\lab1a.lua" >nul
if errorlevel 1 (
    echo 复制 lab1a.lua 失败，请检查 Wireshark 配置目录。
    pause
    exit /b 1
)

echo 已安装: %DEST%\plugins\lab1a.lua
echo 请重启 Wireshark。抓包中端口 9999 的 TCP/UDP 载荷会显示为 LAB1A。
echo.
echo 着色规则需要手动导入:
echo   Wireshark -> 视图(View) -> 着色规则(Coloring Rules...) -> 导入(Import)
echo   选择: %~dp0lab1a_colorfilters
echo.
echo 流统计: 工具(Tools) -> LAB1A -> 流统计
echo.
pause
