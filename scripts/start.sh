#!/usr/bin/env bash
# ==============================================================================
# 出海易审 (CrossBorder SafeGuard)
# 竞赛现场一键启动脚本 (scripts/start.sh)
#
# 功能特性：
# 1. 自动定位 Python 虚拟环境与工作区根目录
# 2. 自动检测可用网络端口（默认 8092，遇占用自动递增）
# 3. 自动初始化 SQLite 数据库与 ChromaDB 16项欧盟法规知识库
# 4. 强制执行 10 秒冒烟自检 (scripts/smoke.py)
# 5. 零跨域单端口极速拉起 FastAPI 工业级合规工作台并自动唤起浏览器
# ==============================================================================

set -e

# 定位工程根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "=================================================================="
echo "  出海易审 (CrossBorder SafeGuard) 一键安全启动程序"
echo "  工作目录: ${PROJECT_ROOT}"
echo "=================================================================="

# 1. 寻找可用 Python 解释器
if [ -f "${PROJECT_ROOT}/.venv/bin/python" ]; then
    PYTHON_EXEC="${PROJECT_ROOT}/.venv/bin/python"
elif [ -f "${PROJECT_ROOT}/venv/bin/python" ]; then
    PYTHON_EXEC="${PROJECT_ROOT}/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_EXEC="$(command -v python3)"
else
    echo "[ERROR] 未检测到 Python 3 运行环境，请先初始化虚拟环境！"
    exit 1
fi
echo "[1/4] 使用 Python 解释器: ${PYTHON_EXEC}"

# 导出环境变量
export PYTHONPATH="${PROJECT_ROOT}/backend:${PROJECT_ROOT}/scripts:${PROJECT_ROOT}:${PYTHONPATH:-}"

# 2. 自动探测空闲端口 (从 8092 开始)
PORT=8092
while "${PYTHON_EXEC}" -c "import socket; s = socket.socket(); s.bind(('127.0.0.1', ${PORT})); s.close()" 2>/dev/null; [ $? -ne 0 ]; do
    echo "[INFO] 端口 ${PORT} 已被占用，尝试探测下一个可用端口..."
    PORT=$((PORT + 1))
    if [ ${PORT} -ge 8110 ]; then
        echo "[ERROR] 探测未找到 8092-8110 范围内的可用端口！"
        exit 1
    fi
done
echo "[2/4] 确定系统服务绑定端口: ${PORT}"

# 3. 检查并初始化 ChromaDB 知识库 (如果 data/chroma 不存在或为空)
if [ ! -d "${PROJECT_ROOT}/data/chroma" ] || [ -z "$(ls -A "${PROJECT_ROOT}/data/chroma" 2>/dev/null)" ]; then
    echo "[3/4] 正在初次载入欧盟 GPSR / CE / RoHS 权威法规库..."
    "${PYTHON_EXEC}" "${PROJECT_ROOT}/scripts/seed_regulations.py"
else
    echo "[3/4] ChromaDB 向量知识库缓存已存在，跳过冷启动初始化"
fi

# 4. 执行路演前 10 秒冒烟自检
echo "[4/4] 正在执行路演前 10 秒自动化冒烟自检..."
"${PYTHON_EXEC}" "${PROJECT_ROOT}/scripts/smoke.py"
SMOKE_STATUS=$?

if [ ${SMOKE_STATUS} -ne 0 ]; then
    echo "[CRITICAL] 冒烟自检未通过，终止启动！请先根据上述红字提示排查异常。"
    exit 1
fi

echo ""
echo "=================================================================="
echo "  >> 出海易审 (CrossBorder SafeGuard) 服务已成功就绪！"
echo "  >> 本地工作台访问地址: http://127.0.0.1:${PORT}"
echo "  >> OpenAPI 交互式文档: http://127.0.0.1:${PORT}/docs"
echo "  >> 现场答辩提示: 如遇现场无网络，系统已内置离线研判应急保障。"
echo "=================================================================="
echo ""

# 尝试自动唤起浏览器 (Mac 或 Linux 桌面环境)
if [ -z "${CI}" ] && [ -z "${NO_BROWSER}" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        (sleep 1.2 && open "http://127.0.0.1:${PORT}") &
    elif command -v xdg-open >/dev/null 2>&1; then
        (sleep 1.2 && xdg-open "http://127.0.0.1:${PORT}") &
    fi
fi

# 启动 Uvicorn ASGI 服务
exec "${PYTHON_EXEC}" -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT}"
