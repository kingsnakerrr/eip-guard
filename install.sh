#!/usr/bin/env bash
#
# EIP Guard 一键安装脚本
#
#   主程序（墙内机器人所在机器）：
#       sudo ./install.sh
#   探针（一台国内 + 一台国外，各跑一次）：
#       sudo ./install.sh --probe --zone cn
#       sudo ./install.sh --probe --zone overseas
#
# 参数：
#   --probe            安装成探针，不装主程序
#   --zone cn|overseas 探针所在位置（决定它代表哪一侧）
#   --dir PATH         安装目录（默认 /opt/eipguard 或 /opt/eip-probe）
#   --token TOKEN      探针共享 token（不填则生成一个并打印）
#   --port PORT        探针监听端口（默认 8787）
#   --no-service       只装文件，不注册 systemd
#   --uninstall        卸载
#
set -euo pipefail

MODE="main"
ZONE=""
APP_DIR=""
PROBE_TOKEN="${PROBE_TOKEN:-}"
PROBE_PORT="${PROBE_PORT:-8787}"
NO_SERVICE=0
UNINSTALL=0
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_END=$'\033[0m'
info() { printf '%s==>%s %s\n' "$C_OK" "$C_END" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_END" "$*"; }
die()  { printf '%s[x]%s %s\n' "$C_ERR" "$C_END" "$*" >&2; exit 1; }
dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$C_END"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --probe) MODE="probe"; shift ;;
    --zone) ZONE="${2:-}"; shift 2 ;;
    --dir) APP_DIR="${2:-}"; shift 2 ;;
    --token) PROBE_TOKEN="${2:-}"; shift 2 ;;
    --port) PROBE_PORT="${2:-}"; shift 2 ;;
    --no-service) NO_SERVICE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "未知参数：$1（--help 查看用法）" ;;
  esac
done

need_root() { [ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo ./install.sh）"; }

# ---------------------------------------------------------------- 卸载
if [ "$UNINSTALL" -eq 1 ]; then
  need_root
  if [ "$MODE" = "probe" ]; then
    systemctl disable --now eip-probe 2>/dev/null || true
    rm -f /etc/systemd/system/eip-probe.service
    rm -rf "${APP_DIR:-/opt/eip-probe}"
    systemctl daemon-reload || true
    info "探针已卸载"
  else
    systemctl disable --now eipguard 2>/dev/null || true
    rm -f /etc/systemd/system/eipguard.service
    warn "保留 ${APP_DIR:-/opt/eipguard}（含 config.yaml/.env/data），确认后手动 rm -rf"
    systemctl daemon-reload || true
    info "主程序已卸载"
  fi
  exit 0
fi

# ---------------------------------------------------------------- 探针安装
install_probe() {
  need_root
  [ -n "$ZONE" ] || die "探针需要 --zone cn 或 --zone overseas"
  case "$ZONE" in cn|overseas) ;; *) die "--zone 只能是 cn 或 overseas" ;; esac
  APP_DIR="${APP_DIR:-/opt/eip-probe}"

  info "安装探针到 $APP_DIR（zone=$ZONE）"
  mkdir -p "$APP_DIR"
  cp "$SRC_DIR/probe_agent/server.py" "$APP_DIR/"

  command -v python3 >/dev/null || die "需要 python3"
  if ! python3 -c "import aiohttp" 2>/dev/null; then
    info "安装 aiohttp"
    python3 -m pip install -q aiohttp 2>/dev/null \
      || (apt-get update -qq && apt-get install -y -qq python3-aiohttp) \
      || die "aiohttp 安装失败，请手动 pip3 install aiohttp"
  fi
  if ! command -v ping >/dev/null; then
    warn "没有 ping 命令，ICMP 层会被跳过：apt install -y iputils-ping"
  fi

  if [ -z "$PROBE_TOKEN" ]; then
    PROBE_TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    info "已生成探针 token（两台探针必须一致，并填进主程序的 PROBE_AGENT_TOKEN）："
    printf '\n    %s%s%s\n\n' "$C_OK" "$PROBE_TOKEN" "$C_END"
  fi
  printf 'PROBE_TOKEN=%s\nPROBE_PORT=%s\n' "$PROBE_TOKEN" "$PROBE_PORT" > "$APP_DIR/probe.env"
  chmod 600 "$APP_DIR/probe.env"

  if [ "$NO_SERVICE" -eq 0 ]; then
    cat > /etc/systemd/system/eip-probe.service <<UNIT
[Unit]
Description=EIP Guard probe agent (${ZONE})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/probe.env
Environment=ZONE=${ZONE}
ExecStart=/usr/bin/python3 ${APP_DIR}/server.py --port ${PROBE_PORT}
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now eip-probe
    sleep 1
    systemctl --no-pager --lines=0 status eip-probe || true
  fi

  IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
  echo
  info "探针已就绪"
  echo "  地址：http://${IP}:${PROBE_PORT}"
  echo "  位置：${ZONE}   ← 这台机器在网络上的实际位置，别填错"
  echo "  token：${PROBE_TOKEN}"
  echo
  dim "自测： curl -s http://127.0.0.1:${PROBE_PORT}/health"
  if [ "$ZONE" = "cn" ]; then
    dim "填进主程序 .env： PROBE_CN_URL=http://${IP}:${PROBE_PORT}"
  else
    dim "填进主程序 .env： PROBE_OS_URL=http://${IP}:${PROBE_PORT}"
  fi
  echo
  dim "⚠ 防火墙需放行 ${PROBE_PORT}，并只允许主程序那台机器的 IP 访问，否则别人能拿它当探测服务"
}

# ---------------------------------------------------------------- 主程序安装
install_main() {
  need_root
  APP_DIR="${APP_DIR:-/opt/eipguard}"
  command -v python3 >/dev/null || die "需要 python3"

  info "检查 Python 版本"
  python3 - <<'PY' || die "需要 Python 3.10+"
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY

  info "安装到 $APP_DIR"
  mkdir -p "$APP_DIR/data"
  cp -r "$SRC_DIR/src" "$SRC_DIR/pyproject.toml" "$SRC_DIR/requirements.txt" \
        "$SRC_DIR/config.example.yaml" "$APP_DIR/"

  if [ ! -d "$APP_DIR/.venv" ]; then
    info "创建虚拟环境"
    python3 -m venv "$APP_DIR/.venv" || {
      warn "python3-venv 缺失，尝试安装"
      apt-get update -qq && apt-get install -y -qq python3-venv
      python3 -m venv "$APP_DIR/.venv"
    }
  fi
  info "安装依赖"
  "$APP_DIR/.venv/bin/pip" install -q --upgrade pip
  "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
  "$APP_DIR/.venv/bin/pip" install -q --no-deps -e "$APP_DIR"

  if [ ! -f "$APP_DIR/config.yaml" ]; then
    cp "$APP_DIR/config.example.yaml" "$APP_DIR/config.yaml"
    warn "已生成 $APP_DIR/config.yaml，请填写 targets（账号、实例 ID、域名、端口）"
  else
    dim "保留已有 config.yaml"
  fi
  if [ ! -f "$APP_DIR/.env" ]; then
    cp "$SRC_DIR/.env.example" "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    warn "已生成 $APP_DIR/.env，请填：TG token、2 组阿里云 AK、CF token、两台北探针地址"
  else
    dim "保留已有 .env"
  fi

  if ! id eipguard >/dev/null 2>&1; then
    useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin eipguard || true
  fi
  chown -R eipguard:eipguard "$APP_DIR" 2>/dev/null || true
  chmod 600 "$APP_DIR/.env" 2>/dev/null || true
  chmod 700 "$APP_DIR/data" 2>/dev/null || true

  if [ "$NO_SERVICE" -eq 0 ]; then
    sed "s#/opt/eipguard#${APP_DIR}#g" "$SRC_DIR/deploy/eipguard.service" \
      > /etc/systemd/system/eipguard.service
    systemctl daemon-reload
    systemctl enable eipguard >/dev/null 2>&1 || true
    dim "服务已注册（未启动）。填好配置后：systemctl start eipguard"
  fi

  echo
  info "下一步"
  cat <<EOF
  1. 编辑配置： ${APP_DIR}/.env
       必填：TG_BOT_TOKEN、ALIYUN_AK_ID/SECRET、ALIYUN_AK_ID_2/SECRET_2、
            CF_API_TOKEN、PROBE_CN_URL、PROBE_OS_URL、PROBE_AGENT_TOKEN
  2. 编辑实例： ${APP_DIR}/config.yaml
       每个 target 填 account / instance_id / dns_records / aux_ports
  3. 校验配置：
       ${APP_DIR}/.venv/bin/python -m eipguard -c ${APP_DIR}/config.yaml --check-config
  4. 试跑一次（不改任何东西，只探测）：
       su -s /bin/sh eipguard -c "${APP_DIR}/.venv/bin/python -m eipguard -c ${APP_DIR}/config.yaml --once"
  5. 启动：
       systemctl start eipguard && journalctl -u eipguard -f
  6. 在 Telegram 私聊机器人发 /bind 你的口令 完成绑定
EOF
  echo
  dim "提示：首次上线建议 /set release off，观察一轮确认流程无误再打开释放旧 EIP"
}

case "$MODE" in
  probe) install_probe ;;
  main)  install_main ;;
esac
