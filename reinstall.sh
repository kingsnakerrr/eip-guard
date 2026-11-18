#!/usr/bin/env bash
#
#  EIP Guard 卸载 / 重装脚本
#
#  彻底重装（保留不了任何东西，密钥要重新填）：
#      bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/reinstall.sh) --fresh
#
#  只清理旧版本、不装新版：
#      bash <(curl -Ls .../reinstall.sh) --clean
#
set -o pipefail

APP_DIR="${APP_DIR:-/opt/eipguard}"
SERVICE="eipguard"
REPO="${REPO:-kingsnakerrr/eip-guard}"
BRANCH="${BRANCH:-main}"

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; BLD=""; DIM=""; RST=""
fi
msg()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$GRN" "$RST" "$*"; }
info() { printf '%s→%s %s\n' "$YEL" "$RST" "$*"; }
warn() { printf '%s!%s %s\n' "$YEL" "$RST" "$*"; }
err()  { printf '%s✗%s %s\n' "$RED" "$RST" "$*" >&2; }
dim()  { printf '%s%s%s\n' "$DIM" "$*" "$RST"; }
die()  { err "$*"; exit 1; }
hr()   { printf '%s\n' "────────────────────────────────────────────────────────"; }

[ "$(id -u)" -eq 0 ] || die "需要 root"

MODE="${1:-}"

# ---------------------------------------------------------------- 备份密钥
backup_keys() {
  local out
  out="/root/eipguard-backup-$(date +%Y%m%d-%H%M%S).txt"
  local found=0
  {
    echo "# EIP Guard 卸载前备份 $(date)"
    echo "# 这些是你原来配置里的密钥，重装后可以照着填"
    echo
    if [ -f "$APP_DIR/.env" ]; then
      echo "=== .env ==="
      grep -E '^[A-Z_]+=' "$APP_DIR/.env" || true
      echo
    fi
    if [ -f "$APP_DIR/config.yaml" ]; then
      echo "=== config.yaml（账号和 CF 部分）==="
      sed -n '/^aliyun:/,/^targets:/p' "$APP_DIR/config.yaml" 2>/dev/null | grep -vE '^\s*#' | grep -E 'name:|access_key|region|api_token|zone' || true
      echo
      echo "=== 实例 ==="
      sed -n '/^targets:/,$p' "$APP_DIR/config.yaml" 2>/dev/null | grep -E 'name:|instance_id|dns_records|- ' | head -40 || true
    fi
  } >"$out" 2>/dev/null
  chmod 600 "$out"
  # 只要能找到非占位符的 AK 就算有内容
  if grep -qE 'ALIYUN_AK_ID=.+|access_key_id: *"?[A-Za-z0-9]{8,}' "$out" 2>/dev/null; then
    found=1
  fi
  if [ "$found" = "1" ]; then
    ok "已备份原密钥到 $out"
    dim "   （重装后照着这个文件填，填完把它删掉：rm $out）"
  else
    rm -f "$out"
    warn "没找到可备份的密钥（原来可能就没配）"
  fi
}

# ---------------------------------------------------------------- 清理
cleanup() {
  hr
  msg "${BLD}清理旧版本${RST}"
  hr

  if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE}.service"; then
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    systemctl disable "$SERVICE" >/dev/null 2>&1 || true
    ok "已停止并禁用服务"
  fi
  rm -f "/etc/systemd/system/${SERVICE}.service"
  systemctl daemon-reload >/dev/null 2>&1 || true

  # 第一版遗留的探针服务
  for old in eip-probe eip-probe-client; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${old}.service"; then
      systemctl stop "$old" >/dev/null 2>&1 || true
      systemctl disable "$old" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/${old}.service"
      ok "已清理旧探针服务 $old"
    fi
  done
  systemctl daemon-reload >/dev/null 2>&1 || true

  rm -f /usr/local/bin/eipguard
  ok "已删除 eipguard 命令"

  # 试运行残留
  rm -rf /tmp/opencode/eipguard-test /tmp/opencode/upg /tmp/opencode/upg2 2>/dev/null || true

  if [ -d "$APP_DIR" ]; then
    rm -rf "$APP_DIR"
    ok "已删除 $APP_DIR（含配置、虚拟环境、数据）"
  fi

  if [ -d /opt/eip-probe ]; then
    rm -rf /opt/eip-probe
    ok "已删除 /opt/eip-probe"
  fi

  if id eipguard >/dev/null 2>&1; then
    userdel eipguard 2>/dev/null || true
    ok "已删除 eipguard 用户"
  fi

  msg ""
  ok "清理完成，现在是干净状态"
  msg ""
  dim "确认一下没有任何残留："
  dim "  systemctl status eipguard     # 应该提示 not found"
  dim "  ls /opt/eipguard              # 应该不存在"
  dim "  which eipguard                # 应该没有输出"
}

# ---------------------------------------------------------------- 主流程
case "$MODE" in
  --clean)
    backup_keys
    echo
    cleanup
    echo
    msg "重新安装："
    msg "  ${BLD}bash <(curl -Ls https://raw.githubusercontent.com/${REPO}/${BRANCH}/install.sh)${RST}"
    ;;

  --fresh)
    backup_keys
    echo
    cleanup
    echo
    hr
    msg "${BLD}开始全新安装${RST}"
    hr
    msg ""
    msg "接下来会问 3 件事：Bot Token、你的 chat id、绑定口令"
    msg "阿里云 AK 和 Cloudflare 装完再填（会更简单）"
    msg ""
    # 直接复用 install.sh
    exec bash <(curl -Ls "https://raw.githubusercontent.com/${REPO}/${BRANCH}/install.sh")
    ;;

  ""|--help|-h)
    cat <<EOF
${BLD}EIP Guard 重装助手${RST}

  彻底重装（先备份密钥，删干净，再装新版）：
      bash <(curl -Ls https://raw.githubusercontent.com/${REPO}/${BRANCH}/reinstall.sh) --fresh

  只清理，不装：
      bash <(curl -Ls .../reinstall.sh) --clean

说明：
  · 会先尝试把原密钥备份到 /root/eipguard-backup-*.txt
  · 会删掉 $APP_DIR、systemd 服务、eipguard 命令、eipguard 用户
  · 顺带清理第一版遗留的 eip-probe 服务
EOF
    ;;

  *)
    die "未知参数：$MODE（用 --fresh 或 --clean）"
    ;;
esac
