#!/bin/bash
echo "========================================"
echo "  软件资产扫描工具 - 正在扫描..."
echo "========================================"

# 检查 python3 是否存在
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
else
    echo "[错误] 未找到 Python，请先安装 Python 3.6+"
    read -p "按回车键退出..."
    exit 1
fi

$PYTHON_CMD "$(dirname "$0")/software_scanner.py"

echo ""
echo "扫描完成！报告已保存到当前目录。"
read -p "按回车键退出..."
