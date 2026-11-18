#!/usr/bin/env bash
#
#  EIP Guard · 阿里云 EIP 手动换 IP + Cloudflare 解析 + Telegram 机器人
#
#  安装（交互，推荐）：
#      bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh)
#
#  装完可以在 Telegram 里做剩下的配置（加账号、加实例、设 CF），
#  也可以随时在这台机器上用命令行补：
#      eipguard account add main AK SK cn-hongkong
#      eipguard target add hk main i-xxxx hk.example.com
#      eipguard cf TOKEN example.com
#      eipguard bind 你的chatid
#
set -o pipefail

REPO="${REPO:-kingsnakerrr/eip-guard}"
BRANCH="${BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/eipguard}"
SERVICE="eipguard"
PIP_INDEX="${PIP_INDEX:-}"

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLU=$'\033[36m'
  BLD=$'\033[1m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; BLU=""; BLD=""; DIM=""; RST=""
fi

msg()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$GRN" "$RST" "$*"; }
info() { printf '%s→%s %s\n' "$BLU" "$RST" "$*"; }
warn() { printf '%s!%s %s\n' "$YEL" "$RST" "$*"; }
err()  { printf '%s✗%s %s\n' "$RED" "$RST" "$*" >&2; }
dim()  { printf '%s%s%s\n' "$DIM" "$*" "$RST"; }
die()  { err "$*"; exit 1; }
hr()   { printf '%s\n' "────────────────────────────────────────────────────────"; }
title(){ hr; printf '%s%s%s\n' "$BLD" "$*" "$RST"; hr; }

TTY=""
for cand in /dev/tty /dev/stdin; do
  [ -r "$cand" ] && { TTY="$cand"; break; }
done

ask() {
  local prompt="$1" def="${2:-}" ans=""
  if [ "$NON_INTERACTIVE" = "1" ] || [ -z "$TTY" ]; then printf '%s' "$def"; return; fi
  if [ -n "$def" ]; then
    printf '%s%s%s [%s%s%s]: ' "$BLD" "$prompt" "$RST" "$GRN" "$def" "$RST" >&2
  else
    printf '%s%s%s: ' "$BLD" "$prompt" "$RST" >&2
  fi
  IFS= read -r ans <"$TTY" || ans=""
  [ -z "$ans" ] && ans="$def"
  printf '%s' "$ans"
}

ask_secret() {
  local prompt="$1" ans=""
  if [ "$NON_INTERACTIVE" = "1" ] || [ -z "$TTY" ]; then printf ''; return; fi
  printf '%s%s%s: ' "$BLD" "$prompt" "$RST" >&2
  if command -v stty >/dev/null && [ -t 0 ] 2>/dev/null; then
    stty -echo <"$TTY" 2>/dev/null || true
    IFS= read -r ans <"$TTY" || ans=""
    stty echo <"$TTY" 2>/dev/null || true
    printf '\n' >&2
  else
    IFS= read -r ans <"$TTY" || ans=""
  fi
  printf '%s' "$ans"
}

confirm() {
  local prompt="$1" def="${2:-n}" ans=""
  [ "$NON_INTERACTIVE" = "1" ] && { [ "$def" = "y" ]; return; }
  [ -z "$TTY" ] && { [ "$def" = "y" ]; return; }
  local hint="[y/N]"; [ "$def" = "y" ] && hint="[Y/n]"
  printf '%s%s%s %s ' "$BLD" "$prompt" "$RST" "$hint" >&2
  IFS= read -r ans <"$TTY" || ans=""
  [ -z "$ans" ] && ans="$def"
  case "$ans" in y|Y|yes|是) return 0 ;; *) return 1 ;; esac
}

need_root() { [ "$(id -u)" -eq 0 ] || die "需要 root：sudo 再运行"; }

detect_pm() {
  if command -v apt-get >/dev/null; then echo apt
  elif command -v dnf >/dev/null; then echo dnf
  elif command -v yum >/dev/null; then echo yum
  elif command -v apk >/dev/null; then echo apk
  else echo none; fi
}

pm_install() {
  local pm; pm="$(detect_pm)"
  case "$pm" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf) dnf install -y -q "$@" ;;
    yum) yum install -y -q "$@" ;;
    apk) apk add --no-cache "$@" ;;
    *) return 1 ;;
  esac
}

py_ok() {
  command -v python3 >/dev/null || return 1
  python3 - <<'PY' 2>/dev/null
import sys
sys.exit(0 if sys.version_info >= (3, 10) else 1)
PY
}

ensure_python() {
  if py_ok; then ok "Python $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"; return 0; fi
  warn "Python 3.10+ 缺失，尝试安装"
  pm_install python3 python3-venv python3-pip || true
  py_ok || die "需要 Python 3.10+"
  ok "Python $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
}

ensure_venv() {
  python3 -m venv "$1" 2>/dev/null && { rm -rf "$1"; return 0; }
  warn "python3-venv 缺失，安装"
  pm_install python3-venv python3-pip || true
  python3 -m venv "$1" 2>/dev/null && { rm -rf "$1"; return 0; }
  die "无法创建虚拟环境"
}

has_systemd() { command -v systemctl >/dev/null && [ -d /run/systemd/system ]; }

SRC_TMP=""
cleanup() { [ -n "$SRC_TMP" ] && rm -rf "$SRC_TMP"; }
trap cleanup EXIT

local_source() {
  local self="${BASH_SOURCE[0]}"
  case "$self" in /dev/*|/proc/*) return 1 ;; esac
  local d; d="$(cd "$(dirname "$self")" 2>/dev/null && pwd)" || return 1
  [ -f "$d/src/eipguard/__init__.py" ] || return 1
  printf '%s' "$d"
}

fetch_source() {
  local dir
  if dir="$(local_source)"; then
    info "使用本地源码：$dir" >&2
    printf '%s' "$dir"
    return 0
  fi

  SRC_TMP="$(mktemp -d)"
  local out="$SRC_TMP/src.tgz" ok=0 url
  local -a urls=(
    "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
    "https://ghproxy.net/https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
    "https://gh-proxy.com/https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
    "https://ghfast.top/https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
  )
  for url in "${urls[@]}"; do
    info "下载源码：${url}" >&2
    rm -f "$out"
    if curl -fsSL --http1.1 --connect-timeout 15 --max-time 300 \
         --retry 2 --retry-delay 2 --retry-all-errors "$url" -o "$out" 2>/dev/null; then
      if tar tzf "$out" >/dev/null 2>&1; then ok=1; break; fi
      warn "压缩包损坏，换下一个镜像" >&2
    fi
  done
  if [ "$ok" != "1" ]; then
    err "下载失败（网络问题）" >&2
    {
      msg ""
      msg "办法："
      msg "  1) 浏览器下载后上传到本机，解压后运行 ./install.sh"
      msg "     ${DIM}https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz${RST}"
      msg "  2) 有代理时：${DIM}export https_proxy=http://127.0.0.1:7890${RST}"
      msg "  3) git clone https://github.com/${REPO}.git && cd eip-guard && sudo ./install.sh"
    } >&2
    return 1
  fi
  tar xzf "$out" -C "$SRC_TMP" || die "解压失败"
  local root
  root="$(find "$SRC_TMP" -maxdepth 1 -type d -name '*-*' | head -1)"
  [ -n "$root" ] || die "压缩包结构异常"
  printf '%s' "$root"
}

svc_state() {
  local name="$1"
  if ! has_systemd; then echo "无 systemd"; return; fi
  if systemctl is-active --quiet "$name" 2>/dev/null; then echo "${GRN}运行中${RST}"
  elif systemctl is-enabled --quiet "$name" 2>/dev/null; then echo "${YEL}已停止${RST}"
  else echo "${DIM}未安装${RST}"; fi
}

svc_start() { systemctl restart "$1" && ok "$1 已启动" || err "$1 启动失败：journalctl -u $1 -n 50"; }

# =====================================================================
# 写配置：最小可用（token + 管理员），其余留给 TG
# =====================================================================
write_config() {
  local dir="$1"
  local env_file="$dir/.env" cfg_file="$dir/config.yaml"

  if [ -f "$cfg_file" ]; then
    info "保留已有 config.yaml"
    return 0
  fi

  title "基础配置（共 3 项，其余之后在 Telegram 里加）"

  msg ""
  msg "${BLD}① Telegram Bot${RST} ${DIM}（@BotFather 发 /newbot）${RST}"
  local tg_token="${TG_BOT_TOKEN:-}"
  [ -z "$tg_token" ] && tg_token="$(ask 'Bot Token' '')"
  [ -z "$tg_token" ] && die "Bot Token 必填（或用环境变量 TG_BOT_TOKEN）"

  local tg_admin="${TG_ADMIN_IDS:-}"
  [ -z "$tg_admin" ] && tg_admin="$(ask '你的数字 chat id（可空，之后 /bind 口令）' '')"

  msg ""
  msg "${BLD}② 管理员口令${RST} ${DIM}（防止别人抢先绑定，可空）${RST}"
  local bind_token="${TG_BIND_TOKEN:-}"
  [ -z "$bind_token" ] && bind_token="$(ask '绑定口令' '')"

  msg ""
  msg "${BLD}③ Telegram 代理${RST} ${DIM}（服务器在国内才需要，国外直接回车）${RST}"
  local tg_proxy="${TG_PROXY:-}"
  [ -z "$tg_proxy" ] && tg_proxy="$(ask 'socks5://127.0.0.1:1080（可空）' '')"

  umask 077
  {
    echo "# 由 install.sh 生成 $(date '+%Y-%m-%d %H:%M:%S')"
    echo "TG_BOT_TOKEN=$tg_token"
    echo "TG_ADMIN_IDS=$tg_admin"
    echo "TG_BIND_TOKEN=$bind_token"
    echo "TG_PROXY=$tg_proxy"
  } >"$env_file"
  chmod 600 "$env_file"

  cat >"$cfg_file" <<YAML
# 由 install.sh 生成 $(date '+%Y-%m-%d %H:%M:%S')
# 阿里云账号、Cloudflare、实例都可以之后在 Telegram 里添加：
#   /account add  → 填 AK/SK/地域
#   /cf           → 填 CF Token + 域名
#   /target add   → 填实例 ID + 域名
# 也可以在这台机器上用命令行：
#   eipguard account add main AK SK cn-hongkong
#   eipguard cf TOKEN example.com
#   eipguard target add hk main i-xxxx hk.example.com

telegram:
  token: "\${TG_BOT_TOKEN}"
  admin_chat_ids: "\${TG_ADMIN_IDS:-}"
  bind_token: "\${TG_BIND_TOKEN:-}"
  channel_id: ""
  proxy: "\${TG_PROXY:-}"

aliyun:
  accounts: []

cloudflare:
  api_token: ""
  zone_name: ""
  ttl: 60
  proxied: false
  create_missing: true
  multi_record_policy: replace

switch:
  release_old: true
  max_attempts: 3
  internet_charge_type: ""
  bandwidth_mbps: null
  isp: ""

targets: []

timezone: "Asia/Shanghai"
data_dir: "./data"
log_level: "INFO"
YAML
  chmod 600 "$cfg_file"
  ok "已生成 $env_file 和 $cfg_file"
}

# =====================================================================
# 安装主程序
# =====================================================================
install_main() {
  need_root
  title "安装 / 更新 EIP Guard"

  has_systemd || warn "没有 systemd，只能手动运行"

  ensure_python
  ensure_venv "$APP_DIR/.venv.$$"

  local src; src="$(fetch_source)" || die "获取源码失败"

  local update=0
  [ -f "$APP_DIR/config.yaml" ] && update=1

  info "部署到 $APP_DIR"
  mkdir -p "$APP_DIR/data"
  rm -rf "$APP_DIR/src"
  cp -r "$src/src" "$src/pyproject.toml" "$src/requirements.txt" "$APP_DIR/"
  [ -f "$APP_DIR/config.example.yaml" ] && cp "$src/config.example.yaml" "$APP_DIR/" || true

  if [ ! -d "$APP_DIR/.venv" ]; then
    python3 -m venv "$APP_DIR/.venv" || die "创建虚拟环境失败"
  fi
  local mirror=()
  [ -n "$PIP_INDEX" ] && mirror=(-i "$PIP_INDEX")
  info "安装依赖（首次约 1-2 分钟）"
  "$APP_DIR/.venv/bin/pip" install -q --upgrade pip "${mirror[@]}" >/dev/null 2>&1 || true
  "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt" "${mirror[@]}" \
    || die "依赖安装失败（可加 --pip-index https://pypi.tuna.tsinghua.edu.cn/simple）"
  "$APP_DIR/.venv/bin/pip" install -q --no-deps -e "$APP_DIR" || die "安装失败"

  write_config "$APP_DIR"

  if ! id eipguard >/dev/null 2>&1; then
    useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin eipguard 2>/dev/null || true
  fi
  chown -R eipguard:eipguard "$APP_DIR" 2>/dev/null || true
  chmod 600 "$APP_DIR/.env" "$APP_DIR/config.yaml"
  chmod 700 "$APP_DIR/data"

  # 老版本配置自动迁移（先备份）
  if [ -f "$APP_DIR/config.yaml" ] && ( cd "$APP_DIR" && "$APP_DIR/.venv/bin/python" -m eipguard -c config.yaml --check-config 2>&1 | grep -q "第一版配置" ); then
    info "检测到第一版配置，正在迁移（会先备份）"
    ( cd "$APP_DIR" && "$APP_DIR/.venv/bin/python" -m eipguard -c config.yaml --migrate ) || warn "迁移失败，原配置已备份为 config.yaml.bak"
  fi

  info "校验配置"
  if ! ( cd "$APP_DIR" && "$APP_DIR/.venv/bin/python" -m eipguard -c config.yaml --check-config ); then
    warn "配置校验未通过，修好后手动启动"
    return 1
  fi

  # 装命令行工具
  cat >/usr/local/bin/eipguard <<SH
#!/bin/sh
exec $APP_DIR/.venv/bin/python -m eipguard -c $APP_DIR/config.yaml "\$@"
SH
  chmod +x /usr/local/bin/eipguard

  if has_systemd; then
    cat >/etc/systemd/system/${SERVICE}.service <<UNIT
[Unit]
Description=EIP Guard (Aliyun EIP switch + Cloudflare + Telegram)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
User=eipguard
Group=eipguard
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/.venv/bin/python -m eipguard -c ${APP_DIR}/config.yaml
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    svc_start "$SERVICE"
    sleep 2
    if systemctl is-active --quiet "$SERVICE"; then
      ok "服务运行中"
    else
      err "服务没起来："
      journalctl -u "$SERVICE" -n 20 --no-pager -o cat 2>/dev/null | tail -20
    fi
  else
    warn "手动启动：cd $APP_DIR && .venv/bin/python -m eipguard -c config.yaml"
  fi

  echo
  ok "安装完成${update:+（这是更新，配置已保留）}"
  echo
  msg "  ${BLD}下一步（任选其一）${RST}"
  msg ""
  msg "  ${BLD}方式 A：在 Telegram 里配置${RST}"
  msg "    1. 私聊机器人发 /start"
  msg "    2. /account add  → 填阿里云 AK/SK、选地域"
  msg "    3. /cf           → 填 Cloudflare Token + 域名"
  msg "    4. /target add   → 填实例 ID + 域名"
  msg "    5. /switch 实例名 → 换 IP"
  msg ""
  msg "  ${BLD}方式 B：在这台机器用命令行${RST}"
  msg "    eipguard account add main 你的AK 你的SK cn-hongkong"
  msg "    eipguard cf 你的CF_TOKEN example.com"
  msg "    eipguard target add hk main i-xxxxxxxx hk.example.com"
  msg "    eipguard --check-config"
  msg ""
  msg "  ${BLD}管理员绑定${RST}（不知道 chat id 时）"
  msg "    私聊机器人随便发一句，它会告诉你 chat id，然后："
  msg "    ${DIM}eipguard --bind 你的chatid${RST}"
  msg ""
  msg "  日志：${BLD}journalctl -u eipguard -f${RST}"
}

show_status() {
  title "运行状态"
  printf '  服务 %-12s %b\n' "$SERVICE" "$(svc_state "$SERVICE")"
  echo
  if [ -x /usr/local/bin/eipguard ]; then
    eipguard --check-config 2>/dev/null | sed 's/^/  /'
  else
    dim "  未安装（$APP_DIR 不存在）"
  fi
}

show_log() {
  has_systemd || die "无 systemd"
  msg "${DIM}Ctrl+C 退出$RST"
  journalctl -u "$SERVICE" -f -n 50 --no-pager -o cat
}

do_update() {
  [ -f "$APP_DIR/src/eipguard/__init__.py" ] || { warn "还没安装，走完整安装"; install_main; return; }
  need_root
  title "升级（代码更新 + 配置迁移，密钥保留）"

  local src; src="$(fetch_source)" || die "获取源码失败"
  info "更新代码"
  rm -rf "$APP_DIR/src"
  cp -r "$src/src" "$APP_DIR/"
  "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt" >/dev/null 2>&1 || true
  "$APP_DIR/.venv/bin/pip" install -q --no-deps -e "$APP_DIR" >/dev/null || die "安装失败"
  chown -R eipguard:eipguard "$APP_DIR" 2>/dev/null || true

  # 旧配置自动迁移
  if ( cd "$APP_DIR" && "$APP_DIR/.venv/bin/python" -m eipguard -c config.yaml --check-config 2>&1 | grep -q "第一版配置" ); then
    info "迁移旧配置（备份为 config.yaml.bak）"
    ( cd "$APP_DIR" && "$APP_DIR/.venv/bin/python" -m eipguard -c config.yaml --migrate ) || warn "迁移失败，看 config.yaml.bak"
  fi

  # 配置是新的但 .env 里还有第一版的 AK/CF —— 提示可以一键导入
  local imported=0
  if [ -f "$APP_DIR/.env" ]; then
    local ak cf
    ak="$(grep -E '^ALIYUN_AK_ID=' "$APP_DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r\"')"
    cf="$(grep -E '^CF_API_TOKEN=' "$APP_DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r\"')"
    if [ -n "$ak" ] && ! grep -q "access_key_id" "$APP_DIR/config.yaml" 2>/dev/null; then
      info ".env 里还有第一版的阿里云 AK，可以一键导入"
      imported=1
    fi
    if [ -n "$cf" ] && ! grep -q 'api_token: "' "$APP_DIR/config.yaml" 2>/dev/null; then
      info ".env 里还有 Cloudflare Token，可以一键导入"
      imported=1
    fi
  fi

  info "校验"
  ( cd "$APP_DIR" && "$APP_DIR/.venv/bin/python" -m eipguard -c config.yaml --check-config ) || {
    warn "配置有问题，服务未重启。修好后 systemctl restart $SERVICE"
    return 1
  }

  # 命令行包装也刷新一下
  cat >/usr/local/bin/eipguard <<SH
#!/bin/sh
exec $APP_DIR/.venv/bin/python -m eipguard -c $APP_DIR/config.yaml "\$@"
SH
  chmod +x /usr/local/bin/eipguard

  if has_systemd; then svc_start "$SERVICE"; fi
  ok "升级完成"

  # 如实统计现在有什么
  local n_acc n_target n_cf
  n_acc="$(grep -c '^  - name:' "$APP_DIR/config.yaml" 2>/dev/null | head -1)"
  n_acc="${n_acc:-0}"
  n_target="$(awk '/^targets:/{f=1;next} f&&/^  - name:/{c++} END{print c+0}' "$APP_DIR/config.yaml" 2>/dev/null)"
  if grep -q 'api_token: ""' "$APP_DIR/config.yaml" 2>/dev/null; then n_cf=0; else n_cf=1; fi

  echo
  if [ "${n_acc:-0}" -eq 0 ] || [ "${n_target:-0}" -eq 0 ] || [ "$n_cf" -eq 0 ]; then
    msg "  ${BLD}还缺这些配置，需要补一下：${RST}"
    [ "${n_acc:-0}" -eq 0 ] && msg "    · 阿里云账号：${DIM}eipguard account add main AK SK cn-hongkong${RST}"
    if [ "$n_cf" -eq 0 ]; then
      msg "    · Cloudflare：${DIM}eipguard cf CF_TOKEN 你的域名.com${RST}"
    fi
    [ "${n_target:-0}" -eq 0 ] && msg "    · 实例：${DIM}eipguard target add hk-main main i-xxxx hk.example.com${RST}"
    echo
    msg "  也可以在 Telegram 里：/account add → /cf → /target add"
    if [ "$imported" = "1" ]; then
      msg "  ${BLD}或者一条命令自动导入 .env 里的旧密钥：${RST}"
      msg "    ${DIM}eipguard --import-env${RST}"
    fi
  else
    ok "账号 ${n_acc} 个 · 实例 ${n_target} 台 · Cloudflare 已配置"
    msg "  备份：${APP_DIR}/config.yaml.bak"
  fi
  echo
  msg "  校验：${BLD}eipguard --check-config${RST}"
}

do_uninstall() {
  need_root
  title "卸载"
  if has_systemd; then
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    systemctl disable "$SERVICE" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${SERVICE}.service"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f /usr/local/bin/eipguard
  if confirm "同时删除 $APP_DIR（含配置和密钥）？" n; then
    rm -rf "$APP_DIR"
    ok "已完全删除"
  else
    ok "服务已卸载，$APP_DIR 保留"
  fi
}

menu() {
  while :; do
    clear 2>/dev/null || true
    echo
    printf '%s╭──────────────────────────────────────────────╮%s\n' "$BLU" "$RST"
    printf '%s│%s  %sEIP Guard%s · 阿里云 EIP 手动换 IP           %s│%s\n' "$BLU" "$RST" "$BLD" "$RST" "$BLU" "$RST"
    printf '%s╰──────────────────────────────────────────────╯%s\n' "$BLU" "$RST"
    printf '  服务 %b\n\n' "$(svc_state "$SERVICE")"
    msg "  ${BLD}1${RST}) 安装 / 更新"
    msg "  ${BLD}2${RST}) 查看状态"
    msg "  ${BLD}3${RST}) 查看日志"
    msg "  ${BLD}4${RST}) 命令行添加账号 / 实例 / CF"
    msg "  ${BLD}5${RST}) 绑定管理员 chat id"
    msg "  ${BLD}6${RST}) 重启服务"
    msg "  ${BLD}7${RST}) 卸载"
    msg "  ${BLD}0${RST}) 退出"
    msg ""
    local c; c="$(ask '选择' '0')"
    case "$c" in
      1) install_main ;;
      2) show_status ;;
      3) show_log ;;
      4) cmdline_wizard ;;
      5) bind_wizard ;;
      6) if has_systemd; then svc_start "$SERVICE"; else warn "无 systemd"; fi ;;
      7) do_uninstall ;;
      0|q|Q) exit 0 ;;
      *) warn "无效选择"; sleep 1 ;;
    esac
    echo
    ask '按回车继续' '' >/dev/null
  done
}

cmdline_wizard() {
  need_root
  title "命令行添加"
  [ -x /usr/local/bin/eipguard ] || die "还没安装"
  msg "  1) 添加阿里云账号"
  msg "  2) 添加实例"
  msg "  3) 设置 Cloudflare"
  msg "  4) 查看当前配置"
  local c; c="$(ask '选择' '1')"
  case "$c" in
    1)
      local n ak sk reg
      n="$(ask '账号代号（英文）' 'main')"
      ak="$(ask 'AccessKey ID' '')"
      sk="$(ask_secret 'AccessKey Secret')"
      reg="$(ask '地域' 'cn-hongkong')"
      eipguard account add "$n" "$ak" "$sk" "$reg"
      ;;
    2)
      local tn ta ti td
      tn="$(ask '实例代号' 'hk-main')"
      ta="$(ask '用哪个账号代号' 'main')"
      ti="$(ask '实例 ID（i-xxxxxxxx）' '')"
      td="$(ask '域名（空格分隔，可空）' '')"
      # shellcheck disable=SC2086
      eipguard target add "$tn" "$ta" "$ti" $td
      ;;
    3)
      local tok zone
      tok="$(ask_secret 'Cloudflare API Token')"
      zone="$(ask '域名' 'example.com')"
      eipguard cf "$tok" "$zone"
      ;;
    4) eipguard --check-config ;;
  esac
}

bind_wizard() {
  need_root
  title "绑定管理员"
  msg "在 Telegram 里私聊机器人发任意消息，它会回复你的 chat id。"
  local cid; cid="$(ask '你的 chat id' '')"
  [ -z "$cid" ] && return
  eipguard --bind "$cid"
}

usage() {
  cat <<EOF
${BLD}EIP Guard${RST} · 阿里云 EIP 手动换 IP + Cloudflare 解析 + Telegram

  ${BLD}bash <(curl -Ls https://raw.githubusercontent.com/${REPO}/${BRANCH}/install.sh)${RST}
      交互菜单（推荐）

  install.sh --install     安装 / 更新
  install.sh --status      查看状态
  install.sh --log         查看日志
  install.sh --update      升级（更新代码 + 自动迁移旧配置，保留密钥）
  install.sh --uninstall   卸载

选项：
  --dir PATH          安装目录（默认 $APP_DIR）
  --pip-index URL     pip 镜像
  --non-interactive   不提问，全部用环境变量

环境变量：
  TG_BOT_TOKEN TG_ADMIN_IDS TG_BIND_TOKEN TG_PROXY

装完后也可以直接用命令行管理（不用 Telegram）：
  eipguard account add main AK SK cn-hongkong
  eipguard cf TOKEN example.com
  eipguard target add hk main i-xxxx hk.example.com
  eipguard --bind 你的chatid
  eipguard --check-config
  eipguard --status
EOF
}

ACTION=""
NON_INTERACTIVE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --install|--main) ACTION="install" ;;
    --status) ACTION="status" ;;
    --log) ACTION="log" ;;
    --update|--upgrade) ACTION="update" ;;
    --uninstall) ACTION="uninstall" ;;
    --dir) APP_DIR="${2:-}"; shift ;;
    --pip-index) PIP_INDEX="${2:-}"; shift ;;
    --repo) REPO="${2:-}"; shift ;;
    --non-interactive) NON_INTERACTIVE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) err "未知参数：$1"; usage; exit 1 ;;
  esac
  shift
done

case "$ACTION" in
  install) install_main ;;
  status) show_status ;;
  log) show_log ;;
  update) do_update ;;
  uninstall) do_uninstall ;;
  "") menu ;;
esac
