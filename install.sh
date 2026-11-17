#!/usr/bin/env bash
# 一键安装到 /opt/eipguard（systemd 服务）。在墙内的机器上运行。
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/eipguard}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '\033[32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }

command -v python3 >/dev/null || { echo "需要 python3"; exit 1; }
python3 - <<'PY' || { echo "需要 Python 3.10+"; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY

info "安装目录 $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/src" "$SRC_DIR/pyproject.toml" "$SRC_DIR/requirements.txt" "$SRC_DIR/config.example.yaml" "$APP_DIR/"
mkdir -p "$APP_DIR/data"

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
  warn "已生成 $APP_DIR/config.yaml，请填写 targets / 地域"
fi
if [ ! -f "$APP_DIR/.env" ]; then
  cp "$SRC_DIR/.env.example" "$APP_DIR/.env"
  chmod 600 "$APP_DIR/.env"
  warn "已生成 $APP_DIR/.env，请填入阿里云 AK、CF token、TG token"
fi

info "安装 systemd 服务"
if ! id eipguard >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin eipguard || true
fi
sed "s#/opt/eipguard#$APP_DIR#g" "$SRC_DIR/deploy/eipguard.service" > /etc/systemd/system/eipguard.service
chown -R eipguard:eipguard "$APP_DIR"
chmod 600 "$APP_DIR/.env" 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now eipguard

info "完成。查看状态："
echo "  systemctl status eipguard -l"
echo "  journalctl -u eipguard -f"
echo "校验配置： $APP_DIR/.venv/bin/python -m eipguard -c $APP_DIR/config.yaml --check-config"
