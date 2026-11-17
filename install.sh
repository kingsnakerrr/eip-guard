#!/usr/bin/env bash
#
#  EIP Guard 一键安装 / 管理脚本
#
#  主程序（推荐，跑在一台长期在线的机器上）：
#      bash <(curl -Ls https://raw.githubusercontent.com/USER/eip-guard/main/install.sh)
#
#  探针（国内、国外各跑一次，直接用对应机器的命令行）：
#      bash <(curl -Ls .../install.sh) --probe --zone cn
#      bash <(curl -Ls .../install.sh) --probe --zone overseas
#
#  非交互（CI / 批量部署）：
#      TG_BOT_TOKEN=... ALIYUN_AK_ID=... ./install.sh --install --non-interactive
#
#  环境变量可覆盖：REPO BRANCH APP_DIR PIP_INDEX TG_BOT_TOKEN ...
#
set -o pipefail

# =====================================================================
# 可修改的默认值
# =====================================================================
# ★ 源码仓库（已填好，换仓库时改这里）★
REPO="${REPO:-kingsnakerrr/eip-guard}"
BRANCH="${BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/eipguard}"
PROBE_DIR="${PROBE_DIR:-/opt/eip-probe}"
SERVICE_MAIN="eipguard"
SERVICE_PROBE="eip-probe"
PIP_INDEX="${PIP_INDEX:-}"                  # 例：https://pypi.tuna.tsinghua.edu.cn/simple

# =====================================================================
# 颜色 / 输出
# =====================================================================
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

hr() { printf '%s\n' "────────────────────────────────────────────────────────"; }
title() { hr; printf '%s%s%s\n' "$BLD" "$*" "$RST"; hr; }

# =====================================================================
# 交互（支持 bash <(curl ...)，stdin 不一定是终端）
# =====================================================================
TTY=""
for cand in /dev/tty /dev/stdin; do
  [ -r "$cand" ] && { TTY="$cand"; break; }
done

ask() {  # ask <提示> [默认值]
  local prompt="$1" def="${2:-}" ans=""
  if [ "$NON_INTERACTIVE" = "1" ] || [ -z "$TTY" ]; then
    printf '%s' "$def"; return
  fi
  if [ -n "$def" ]; then
    printf '%s%s%s [%s%s%s]: ' "$BLD" "$prompt" "$RST" "$GRN" "$def" "$RST" >&2
  else
    printf '%s%s%s: ' "$BLD" "$prompt" "$RST" >&2
  fi
  IFS= read -r ans <"$TTY" || ans=""
  [ -z "$ans" ] && ans="$def"
  printf '%s' "$ans"
}

ask_secret() {  # 不回显
  local prompt="$1" ans=""
  if [ "$NON_INTERACTIVE" = "1" ] || [ -z "$TTY" ]; then
    printf ''
    return
  fi
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

confirm() {  # confirm <提示> [默认 y/n]
  local prompt="$1" def="${2:-n}" ans=""
  [ "$NON_INTERACTIVE" = "1" ] && { [ "$def" = "y" ]; return; }
  [ -z "$TTY" ] && { [ "$def" = "y" ]; return; }
  local hint="[y/N]"; [ "$def" = "y" ] && hint="[Y/n]"
  printf '%s%s%s %s ' "$BLD" "$prompt" "$RST" "$hint" >&2
  IFS= read -r ans <"$TTY" || ans=""
  [ -z "$ans" ] && ans="$def"
  case "$ans" in y|Y|yes|YES|是) return 0 ;; *) return 1 ;; esac
}

# =====================================================================
# 系统
# =====================================================================
need_root() { [ "$(id -u)" -eq 0 ] || die "需要 root：请用 sudo 运行"; }

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
  if py_ok; then
    ok "Python $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
    return 0
  fi
  warn "Python 3.10+ 缺失，尝试安装"
  pm_install python3 python3-venv python3-pip || true
  if ! py_ok; then
    for v in 3.13 3.12 3.11 3.10; do
      if command -v "python$v" >/dev/null; then
        ln -sf "$(command -v python$v)" /usr/local/bin/python3
        break
      fi
    done
  fi
  py_ok || die "需要 Python 3.10+。Debian/Ubuntu 请先 apt install python3.11 python3.11-venv"
  ok "Python $(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
}

ensure_venv_support() {
  python3 -m venv "$1" 2>/dev/null && { rm -rf "$1"; return 0; }
  warn "python3-venv 缺失，安装"
  pm_install python3-venv python3-pip || true
  python3 -m venv "$1" 2>/dev/null && { rm -rf "$1"; return 0; }
  die "无法创建虚拟环境，请安装 python3-venv"
}

ensure_ping() {
  command -v ping >/dev/null && return 0
  pm_install iputils-ping >/dev/null 2>&1 || pm_install iputils >/dev/null 2>&1 || true
}

has_systemd() { command -v systemctl >/dev/null && [ -d /run/systemd/system ]; }

# =====================================================================
# 源码获取：本地目录优先，否则从 GitHub 下载
# =====================================================================
SRC_TMP=""

cleanup() { [ -n "$SRC_TMP" ] && rm -rf "$SRC_TMP"; }
trap cleanup EXIT

local_source() {
  local self="${BASH_SOURCE[0]}"
  # bash <(curl ...) 时路径是 /dev/fd/63，不能用
  case "$self" in /dev/*|/proc/*) return 1 ;; esac
  local d; d="$(cd "$(dirname "$self")" 2>/dev/null && pwd)" || return 1
  [ -f "$d/src/eipguard/__init__.py" ] || return 1
  printf '%s' "$d"
}

# 注意：本函数只把"路径"写到 stdout，所有日志必须去 stderr
fetch_source() {
  local dir
  if dir="$(local_source)"; then
    info "使用本地源码：$dir" >&2
    printf '%s' "$dir"
    return 0
  fi

  local url="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
  info "下载源码：$url" >&2
  SRC_TMP="$(mktemp -d)"
  if ! curl -fsSL --connect-timeout 15 --retry 2 "$url" -o "$SRC_TMP/src.tgz"; then
    err "下载失败。仓库可能还没上传，或 REPO 变量不对。" >&2
    {
      msg ""
      msg "当前 REPO = ${BLD}${REPO}${RST}"
      msg "先上传项目到 GitHub，然后这样运行："
      msg "  ${DIM}REPO=kingsnakerrr/eip-guard bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh)${RST}"
    } >&2
    return 1
  fi
  tar xzf "$SRC_TMP/src.tgz" -C "$SRC_TMP" || die "解压失败"
  local root
  root="$(find "$SRC_TMP" -maxdepth 1 -type d -name '*-*' | head -1)"
  [ -n "$root" ] || die "压缩包结构异常"
  printf '%s' "$root"
}

# =====================================================================
# 服务管理
# =====================================================================
svc_write() {  # svc_write <名称> <目录> <启动命令> <用户> [额外环境行]
  local name="$1" dir="$2" exec_cmd="$3" user="$4" extra="${5:-}"
  local file="/etc/systemd/system/${name}.service"
  local user_lines=""
  [ -n "$user" ] && [ "$user" != "root" ] && user_lines="User=${user}
Group=${user}"
  cat >"$file" <<UNIT
[Unit]
Description=${name} (EIP Guard)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${dir}
${user_lines}
${extra}
ExecStart=${exec_cmd}
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable "$name" >/dev/null 2>&1 || true
}

svc_start() { systemctl restart "$1" && ok "$1 已启动" || err "$1 启动失败，看日志：journalctl -u $1 -n 50"; }

svc_stop_rm() {
  local name="$1"
  systemctl stop "$name" >/dev/null 2>&1 || true
  systemctl disable "$name" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${name}.service"
  systemctl daemon-reload >/dev/null 2>&1 || true
}

svc_state() {
  local name="$1"
  if ! has_systemd; then echo "无 systemd"; return; fi
  if systemctl is-active --quiet "$name" 2>/dev/null; then echo "${GRN}运行中${RST}"
  elif systemctl is-enabled --quiet "$name" 2>/dev/null; then echo "${YEL}已停止${RST}"
  else echo "${DIM}未安装${RST}"; fi
}

# =====================================================================
# 配置文件生成（交互向导）
# =====================================================================
yaml_q() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

gen_env_and_config() {
  local dir="$1"
  local env_file="$dir/.env" cfg_file="$dir/config.yaml"
  local fresh=0
  [ -f "$env_file" ] || fresh=1

  if [ "$fresh" = "1" ]; then
    title "配置向导（共 5 步，直接回车用默认值）"

    # ---------- Telegram ----------
    msg ""
    msg "${BLD}① Telegram${RST} (${DIM}找 @BotFather 发 /newbot 拿 token${RST})"
    local tg_token="${TG_BOT_TOKEN:-}"
    [ -z "$tg_token" ] && tg_token="$(ask 'Bot Token' '')"
    [ -z "$tg_token" ] && die "Bot Token 不能为空（也可用环境变量 TG_BOT_TOKEN）"
    local tg_admins="${TG_ADMIN_IDS:-}"
    [ -z "$tg_admins" ] && tg_admins="$(ask '你的数字 chat id（可空，之后私聊机器人 /bind）' '')"
    local tg_channel="${TG_CHANNEL_ID:-}"
    [ -z "$tg_channel" ] && tg_channel="$(ask '通知频道 id（可空，形如 -1001234567890）' '')"
    local tg_bind="${TG_BIND_TOKEN:-}"
    [ -z "$tg_bind" ] && tg_bind="$(ask '首次绑定口令（可空）' '')"

    # ---------- 阿里云 ----------
    msg ""
    msg "${BLD}② 阿里云${RST} (${DIM}每个账号建一个 RAM 子账号，只给 EIP 权限${RST})"
    local ak1="${ALIYUN_AK_ID:-}" sk1="${ALIYUN_AK_SECRET:-}"
    [ -z "$ak1" ] && ak1="$(ask '账号 1 AccessKey ID' '')"
    [ -z "$sk1" ] && sk1="$(ask_secret '账号 1 AccessKey Secret')"
    [ -z "$ak1" ] || [ -z "$sk1" ] && die "账号 1 的 AK/SK 不能为空"
    local region1="${ALIYUN_REGION:-}"
    [ -z "$region1" ] && region1="$(ask '账号 1 默认地域' 'cn-hongkong')"
    local name1="${ALIYUN_NAME:-}"
    [ -z "$name1" ] && name1="$(ask '账号 1 代号（脚本内部用）' 'main')"

    local ak2="${ALIYUN_AK_ID_2:-}" sk2="${ALIYUN_AK_SECRET_2:-}" region2="${ALIYUN_REGION_2:-cn-hongkong}" name2="second"
    if [ -n "$ak2" ] || confirm '添加第二个阿里云账号？' n; then
      [ -z "$ak2" ] && ak2="$(ask '账号 2 AccessKey ID' '')"
      [ -z "$sk2" ] && sk2="$(ask_secret '账号 2 AccessKey Secret')"
      [ -z "$region2" ] && region2="$(ask '账号 2 默认地域' 'cn-hongkong')"
      name2="$(ask '账号 2 代号' 'second')"
    fi

    # ---------- Cloudflare ----------
    msg ""
    msg "${BLD}③ Cloudflare${RST} (${DIM}Token 权限：Zone.DNS:Edit + Zone:Read${RST})"
    local cf_token="${CF_API_TOKEN:-}"
    [ -z "$cf_token" ] && cf_token="$(ask_secret 'Cloudflare API Token')"
    [ -z "$cf_token" ] && die "Cloudflare Token 不能为空"
    local cf_zone="${CF_ZONE_NAME:-}"
    [ -z "$cf_zone" ] && cf_zone="$(ask '域名（zone）' 'example.com')"

    # ---------- 探针 ----------
    msg ""
    msg "${BLD}④ 探针${RST} (${DIM}必须国内 + 国外各一台，判定靠对比${RST})"
    msg "${DIM}   还没装？先在另外两台机器上跑：${RST}"
    msg "${DIM}   bash <(curl -Ls .../install.sh) --probe --zone cn${RST}"
    msg "${DIM}   bash <(curl -Ls .../install.sh) --probe --zone overseas${RST}"
    local probe_cn="${PROBE_CN_URL:-}"
    [ -z "$probe_cn" ] && probe_cn="$(ask '国内探针地址（http://IP:8787）' '')"
    local probe_os="${PROBE_OS_URL:-}"
    [ -z "$probe_os" ] && probe_os="$(ask '国外探针地址（http://IP:8787）' '')"
    local probe_token="${PROBE_AGENT_TOKEN:-}"
    [ -z "$probe_token" ] && probe_token="$(ask '探针 token（两台一致）' '')"
    if [ -z "$probe_cn" ] || [ -z "$probe_os" ]; then
      warn "探针地址没填全，程序能启动但会一直「无法判定」。之后可改 $env_file"
    fi

    # ---------- 实例 ----------
    msg ""
    msg "${BLD}⑤ 要换 IP 的实例${RST} (${DIM}控制台里的 i-xxxx，以及要跟着换的域名${RST})"
    local inst_list=()

    # 非交互模式：从 TARGETS 读，格式 name|account|instance|port|aux|dns，多条换行或分号
    if [ "$NON_INTERACTIVE" = "1" ] && [ -n "${TARGETS:-}" ]; then
      local record
      while IFS= read -r record; do
        record="$(printf '%s' "$record" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -z "$record" ] && continue
        inst_list+=("$record")
      done < <(printf '%s\n' "$TARGETS" | tr ';' '\n')
    else
      local i=0
      while :; do
        i=$((i+1))
        local tname taccount tinst tport taux tdns
        if [ -z "$TTY" ] && [ "$NON_INTERACTIVE" != "1" ]; then
          die "没有交互终端。请用 --non-interactive 并设置 TARGETS 环境变量"
        fi
        tname="$(ask "实例 $i 代号" "")"
        [ -z "$tname" ] && { [ "$i" -eq 1 ] && die "至少填一个实例"; break; }
        taccount="$(ask "  用哪个账号代号" "$name1")"
        tinst="$(ask "  实例 ID（i-xxxxxxxx）" "")"
        [ -z "$tinst" ] && die "实例 ID 不能为空"
        tport="$(ask "  业务端口" "443")"
        taux="$(ask "  这台机器上其它真实开放的端口（空格分隔，用来区分整机/单端口）" "22 80")"
        tdns="$(ask "  要跟随的域名（空格分隔）" "")"
        inst_list+=("${tname}|${taccount}|${tinst}|${tport}|${taux}|${tdns}")
        confirm '再添加一个实例？' n || break
      done
    fi
    if [ "${#inst_list[@]}" -eq 0 ]; then
      err "没有实例配置。"
      msg ""
      msg "非交互模式需要 TARGETS 环境变量，格式："
      msg "  ${DIM}name|account|instance_id|port|aux_ports|dns_records${RST}"
      msg ""
      msg "示例："
      msg "  ${DIM}TARGETS='hk-main|main|i-j6cxxx|443|22 80|hk.example.com api.example.com'${RST}"
      msg "  ${DIM}TG_BOT_TOKEN=... ALIYUN_AK_ID=... bash install.sh --install --non-interactive${RST}"
      die "已中止"
    fi

    # ---------- 写 .env ----------
    umask 077
    {
      echo "# 由 install.sh 生成于 $(date '+%Y-%m-%d %H:%M:%S')"
      echo "TG_BOT_TOKEN=$tg_token"
      echo "TG_ADMIN_IDS=$tg_admins"
      echo "TG_BIND_TOKEN=$tg_bind"
      echo "TG_CHANNEL_ID=$tg_channel"
      echo ""
      echo "ALIYUN_AK_ID=$ak1"
      echo "ALIYUN_AK_SECRET=$sk1"
      echo "ALIYUN_AK_ID_2=$ak2"
      echo "ALIYUN_AK_SECRET_2=$sk2"
      echo ""
      echo "CF_API_TOKEN=$cf_token"
      echo ""
      echo "PROBE_CN_URL=$probe_cn"
      echo "PROBE_OS_URL=$probe_os"
      echo "PROBE_AGENT_TOKEN=$probe_token"
    } >"$env_file"
    chmod 600 "$env_file"

    # ---------- 写 config.yaml ----------
    exec 3>"$cfg_file"
    cat >&3 <<YAML
# 由 install.sh 生成于 $(date '+%Y-%m-%d %H:%M:%S')
# 改完执行：systemctl restart eipguard

telegram:
  token: "\${TG_BOT_TOKEN}"
  admin_chat_ids: "\${TG_ADMIN_IDS:-}"
  bind_token: "\${TG_BIND_TOKEN:-}"
  channel_id: "\${TG_CHANNEL_ID:-}"

aliyun:
  accounts:
    - name: $(yaml_q "$name1")
      access_key_id: "\${ALIYUN_AK_ID}"
      access_key_secret: "\${ALIYUN_AK_SECRET}"
      default_region: $(yaml_q "$region1")
YAML
    if [ -n "$ak2" ]; then
      cat >&3 <<YAML
    - name: $(yaml_q "${name2:-second}")
      access_key_id: "\${ALIYUN_AK_ID_2}"
      access_key_secret: "\${ALIYUN_AK_SECRET_2}"
      default_region: $(yaml_q "$region2")
YAML
    fi
    cat >&3 <<'YAML'

timezone: "Asia/Shanghai"
data_dir: "./data"
log_level: "INFO"

cloudflare:
  api_token: "${CF_API_TOKEN}"
  zone_name: "PLACEHOLDER_ZONE"
  ttl: 60
  proxied: false
  create_missing: true

detect:
  provider: "probe_agent"
  port: 443
  interval: 60
  failure_threshold: 3
  fail_ratio: 0.6
  timeout: 6.0
  attempts: 2
  # icmp 只做参考展示，不参与判定；tls 用来查 SNI 阻断
  layers: ["icmp", "tls"]
  # 全局默认辅助端口，target 可覆盖
  aux_ports: [22, 80]
  http_path: "/"
  verify_delay: 20
  verify_attempts: 3
  probe_agent:
    agents:
YAML
    if [ -n "$probe_cn" ]; then
      cat >&3 <<YAML
      - url: "\${PROBE_CN_URL}"
        token: "\${PROBE_AGENT_TOKEN}"
        zone: "cn"
        name: "cn-probe"
YAML
    fi
    if [ -n "$probe_os" ]; then
      cat >&3 <<YAML
      - url: "\${PROBE_OS_URL}"
        token: "\${PROBE_AGENT_TOKEN}"
        zone: "overseas"
        name: "os-probe"
YAML
    fi
    cat >&3 <<'YAML'
  checkhost:
    max_nodes: 6
    timeout: 20

switch:
  auto: true
  # 只有「IP 被墙」自动换；端口被墙/服务故障换 IP 无效
  auto_switch_on: ["ip_blocked"]
  max_attempts: 3
  cooldown: 900
  release_old: true
  restore_old_on_failure: true
  internet_charge_type: ""
  bandwidth_mbps: null
  isp: ""

targets:
YAML
    for entry in "${inst_list[@]}"; do
      IFS='|' read -r tname taccount tinst tport taux tdns <<<"$entry"
      {
        printf '  - name: %s\n' "$(yaml_q "$tname")"
        printf '    account: %s\n' "$(yaml_q "$taccount")"
        printf '    instance_id: %s\n' "$(yaml_q "$tinst")"
        printf '    probe_port: %s\n' "$tport"
        if [ -n "$taux" ]; then
          printf '    aux_ports: [%s]\n' "$(printf '%s' "$taux" | tr ' ' ',')"
        fi
        if [ -n "$tdns" ]; then
          printf '    dns_records:\n'
          for d in $tdns; do printf '      - %s\n' "$(yaml_q "$d")"; done
        fi
        printf '    notes: ""\n'
      } >&3
    done
    exec 3>&-

    # 填 zone（避免 heredoc 转义问题）
    sed -i "s|zone_name: \"PLACEHOLDER_ZONE\"|zone_name: \"${cf_zone}\"|" "$cfg_file"

    chmod 640 "$cfg_file"
    ok "已生成 $env_file 和 $cfg_file"
  else
    info "保留已有配置（$env_file）"
  fi
}

# =====================================================================
# 主程序
# =====================================================================
install_main() {
  need_root
  title "安装 / 更新 EIP Guard 主程序"

  has_systemd || warn "没有 systemd，将只安装文件，需手动启动"

  ensure_python
  ensure_venv_support "$APP_DIR/.venv.$$"
  ensure_ping

  local src; src="$(fetch_source)" || die "获取源码失败"

  local update=0
  [ -f "$APP_DIR/config.yaml" ] && update=1

  info "部署到 $APP_DIR"
  mkdir -p "$APP_DIR/data"
  rm -rf "$APP_DIR/src"
  cp -r "$src/src" "$src/pyproject.toml" "$src/requirements.txt" "$APP_DIR/"
  [ -f "$APP_DIR/config.example.yaml" ] || cp "$src/config.example.yaml" "$APP_DIR/" 2>/dev/null || true
  mkdir -p "$APP_DIR/probe_agent"
  cp "$src/probe_agent/server.py" "$APP_DIR/probe_agent/" 2>/dev/null || true

  if [ ! -d "$APP_DIR/.venv" ]; then
    python3 -m venv "$APP_DIR/.venv" || die "创建虚拟环境失败"
  fi
  local mirror=()
  [ -n "$PIP_INDEX" ] && mirror=(-i "$PIP_INDEX")
  info "安装依赖（首次约 1-2 分钟）"
  "$APP_DIR/.venv/bin/pip" install -q --upgrade pip "${mirror[@]}" >/dev/null 2>&1 || true
  "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt" "${mirror[@]}" \
    || die "依赖安装失败（国内可加 --pip-index https://pypi.tuna.tsinghua.edu.cn/simple）"
  "$APP_DIR/.venv/bin/pip" install -q --no-deps -e "$APP_DIR" || die "安装本体失败"

  gen_env_and_config "$APP_DIR"

  if ! id eipguard >/dev/null 2>&1; then
    useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin eipguard 2>/dev/null || true
  fi
  chown -R eipguard:eipguard "$APP_DIR" 2>/dev/null || true
  chmod 600 "$APP_DIR/.env"
  chmod 640 "$APP_DIR/config.yaml"
  chmod 700 "$APP_DIR/data"

  # 配置校验
  info "校验配置"
  if ! ( cd "$APP_DIR" && set -a && . ./.env && set +a && \
         "$APP_DIR/.venv/bin/python" -m eipguard -c "$APP_DIR/config.yaml" --check-config ); then
    warn "配置校验未通过，请检查后手动启动"
    [ -n "$SRC_TMP" ] && rm -rf "$SRC_TMP"
    return 1
  fi

  if has_systemd; then
    svc_write "$SERVICE_MAIN" "$APP_DIR" \
      "$APP_DIR/.venv/bin/python -m eipguard -c $APP_DIR/config.yaml" "eipguard"
    svc_start "$SERVICE_MAIN"
  else
    warn "手动启动：cd $APP_DIR && .venv/bin/python -m eipguard -c config.yaml"
  fi

  echo
  ok "主程序已就绪${update:+（更新完成）}"
  msg ""
  msg "  状态：${BLD}eipguard status${RST}   |   日志：${BLD}eipguard log${RST}"
  msg "  改配置：${BLD}${APP_DIR}/.env${RST} 和 ${BLD}${APP_DIR}/config.yaml${RST}"
  msg "  首次使用：Telegram 私聊机器人发 ${BLD}/bind${RST} 或 ${BLD}/start${RST}"
  [ -n "$SRC_TMP" ] && rm -rf "$SRC_TMP"
  return 0
}

# =====================================================================
# 探针
# =====================================================================
install_probe() {
  need_root
  title "安装 / 更新 EIP Guard 探针"

  local zone="$ZONE"
  if [ -z "$zone" ]; then
    msg "这台机器在哪一侧？判定靠「国内不通 + 国外通」对比，两侧都要有。"
    msg "  1) cn        国内（中国大陆）"
    msg "  2) overseas  国外（境外）"
    local pick; pick="$(ask '选择' '2')"
    case "$pick" in 1|cn|CN|国内) zone="cn" ;; *) zone="overseas" ;; esac
  fi
  case "$zone" in cn|overseas) ;; *) die "--zone 只能是 cn 或 overseas" ;; esac
  ZONE="$zone"

  ensure_python
  ensure_ping

  local token="$PROBE_TOKEN"
  if [ -z "$token" ]; then
    token="$(openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    info "生成探针 token（两台必须一致）：${BLD}${token}${RST}"
  fi

  local src; src="$(fetch_source)" || die "获取源码失败"

  info "部署到 $PROBE_DIR"
  mkdir -p "$PROBE_DIR"
  cp "$src/probe_agent/server.py" "$PROBE_DIR/"

  # 依赖：优先系统包 aiohttp
  if ! python3 -c 'import aiohttp' 2>/dev/null; then
    info "安装 aiohttp"
    if ! pm_install python3-aiohttp >/dev/null 2>&1 && \
       ! python3 -m pip install -q aiohttp >/dev/null 2>&1; then
      python3 -m pip install -q --break-system-packages aiohttp || die "aiohttp 安装失败"
    fi
  fi

  printf 'PROBE_TOKEN=%s\nPROBE_PORT=%s\nZONE=%s\n' "$token" "$PROBE_PORT" "$ZONE" >"$PROBE_DIR/probe.env"
  chmod 600 "$PROBE_DIR/probe.env"

  if has_systemd; then
    svc_write "$SERVICE_PROBE" "$PROBE_DIR" \
      "/usr/bin/python3 $PROBE_DIR/server.py --port $PROBE_PORT" "" \
      "EnvironmentFile=$PROBE_DIR/probe.env"
    if ! port_free "$PROBE_PORT"; then
      warn "端口 $PROBE_PORT 已被占用（可能是别的程序），探针可能起不来"
    fi
    svc_start "$SERVICE_PROBE"
    sleep 2
    if ! systemctl is-active --quiet "$SERVICE_PROBE"; then
      err "服务没起来，日志如下："
      journalctl -u "$SERVICE_PROBE" -n 20 --no-pager -o cat 2>/dev/null | tail -20
    elif probe_healthy; then
      ok "健康检查通过（zone=$ZONE）"
    else
      warn "端口 $PROBE_PORT 有响应但不是本探针，检查是否被占用：ss -lntp | grep $PROBE_PORT"
    fi
  else
    warn "手动启动：cd $PROBE_DIR && PROBE_TOKEN=$token ZONE=$zone python3 server.py --port $PROBE_PORT"
  fi

  ensure_firewall "$PROBE_PORT"

  local ip; ip="$(curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
  echo
  ok "探针已就绪（zone=${ZONE}）"
  msg ""
  msg "  地址：${BLD}http://${ip}:${PROBE_PORT}${RST}"
  msg "  token：${BLD}${token}${RST}"
  [ -n "$SRC_TMP" ] && rm -rf "$SRC_TMP"
  msg ""
  if [ "$ZONE" = "cn" ]; then
    dim "填进主程序 .env：PROBE_CN_URL=http://${ip}:${PROBE_PORT}"
  else
    dim "填进主程序 .env：PROBE_OS_URL=http://${ip}:${PROBE_PORT}"
  fi
  dim "别忘了把上面的 token 填进主程序的 PROBE_AGENT_TOKEN"
  return 0
}

port_free() {
  local port="$1"
  if command -v ss >/dev/null; then
    ! ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"
  else
    ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
  fi
}

probe_healthy() {
  local body
  body="$(curl -fsS --max-time 3 "http://127.0.0.1:${PROBE_PORT}/health" 2>/dev/null)" || return 1
  case "$body" in
    *'"ok":true'*|*'"ok": true'*) return 0 ;;
    *) return 1 ;;
  esac
}

ensure_firewall() {
  local port="$1"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$port"/tcp >/dev/null 2>&1 && dim "已放行 ufw $port/tcp"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state 2>/dev/null | grep -q running; then
    firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
    dim "已放行 firewalld $port/tcp"
  fi
  dim "云厂商安全组需另外放行 $port/tcp，建议只允许主程序那台机器的 IP"
}

# =====================================================================
# 状态 / 日志 / 卸载
# =====================================================================
show_status() {
  title "运行状态"
  printf '  主程序 %-14s %b\n' "$SERVICE_MAIN" "$(svc_state "$SERVICE_MAIN")"
  printf '  探针   %-14s %b\n' "$SERVICE_PROBE" "$(svc_state "$SERVICE_PROBE")"
  echo
  if has_systemd && systemctl is-active --quiet "$SERVICE_MAIN" 2>/dev/null; then
    local since; since="$(systemctl show -p ActiveEnterTimestamp --value "$SERVICE_MAIN" 2>/dev/null)"
    [ -n "$since" ] && msg "  主程序启动于：$since"
  fi
  if [ -f "$APP_DIR/config.yaml" ]; then
    echo
    msg "  配置：$APP_DIR/config.yaml"
    local n; n="$(grep -c '^  - name:' "$APP_DIR/config.yaml" 2>/dev/null || echo 0)"
    msg "  实例数：$n"
    if [ -f "$APP_DIR/data/state.json" ]; then
      msg "  最近事件："
      python3 - "$APP_DIR/data/state.json" <<'PY' 2>/dev/null || true
import json, sys, time
d = json.load(open(sys.argv[1]))
for e in (d.get("history") or [])[-5:]:
    ts = time.strftime("%m-%d %H:%M", time.localtime(e.get("ts", 0)))
    print(f"    {ts} {e.get('type','?'):16s} {e.get('target','')}")
PY
    fi
  fi
}

show_log() {
  local svc="$SERVICE_MAIN"
  [ "${1:-}" = "probe" ] && svc="$SERVICE_PROBE"
  has_systemd || die "无 systemd"
  msg "${DIM}Ctrl+C 退出$RST"
  journalctl -u "$svc" -f -n 50 --no-pager -o cat
}

do_uninstall() {
  need_root
  title "卸载"
  local which; which="$(ask '卸载哪个？1) 主程序 2) 探针 3) 两个都卸' '1')"
  case "$which" in
    1) svc_stop_rm "$SERVICE_MAIN"
       if confirm "同时删除 $APP_DIR（含配置和密钥）？" n; then rm -rf "$APP_DIR"; fi
       ok "主程序已卸载" ;;
    2) svc_stop_rm "$SERVICE_PROBE"
       if confirm "同时删除 $PROBE_DIR？" n; then rm -rf "$PROBE_DIR"; fi
       ok "探针已卸载" ;;
    3) svc_stop_rm "$SERVICE_MAIN"; svc_stop_rm "$SERVICE_PROBE"
       if confirm "同时删除所有数据？" n; then rm -rf "$APP_DIR" "$PROBE_DIR"; fi
       ok "已卸载" ;;
    *) warn "取消" ;;
  esac
}

do_update() {
  local src; src="$(fetch_source)" || die "获取源码失败"
  if [ -f "$APP_DIR/src/eipguard/__init__.py" ]; then
    rm -rf "$APP_DIR/src"; cp -r "$src/src" "$APP_DIR/"
    "$APP_DIR/.venv/bin/pip" install -q --no-deps -e "$APP_DIR" >/dev/null
    chown -R eipguard:eipguard "$APP_DIR" 2>/dev/null || true
    svc_start "$SERVICE_MAIN"
    ok "代码已更新（配置未动）"
  else
    warn "主程序未安装，走完整安装流程"
    install_main
  fi
  [ -n "$SRC_TMP" ] && rm -rf "$SRC_TMP"
}

# =====================================================================
# 菜单
# =====================================================================
menu() {
  while :; do
    clear 2>/dev/null || true
    msg ""
    printf '%s╭──────────────────────────────────────────╮%s\n' "$BLU" "$RST"
    printf '%s│%s  %sEIP Guard%s · 阿里云 EIP 被墙自动更换       %s│%s\n' "$BLU" "$RST" "$BLD" "$RST" "$BLU" "$RST"
    printf '%s╰──────────────────────────────────────────╯%s\n' "$BLU" "$RST"
    printf '  主程序 %b    探针 %b\n\n' "$(svc_state "$SERVICE_MAIN")" "$(svc_state "$SERVICE_PROBE")"
    msg "  ${BLD}1${RST}) 安装 / 更新主程序"
    msg "  ${BLD}2${RST}) 安装 / 更新探针（国内或国外）"
    msg "  ${BLD}3${RST}) 查看状态"
    msg "  ${BLD}4${RST}) 查看日志"
    msg "  ${BLD}5${RST}) 编辑配置 / 重启"
    msg "  ${BLD}6${RST}) 更新代码（保留配置）"
    msg "  ${BLD}7${RST}) 卸载"
    msg "  ${BLD}0${RST}) 退出"
    msg ""
    local c; c="$(ask '请选择' '0')"
    case "$c" in
      1) install_main ;;
      2) ZONE=""; install_probe ;;
      3) show_status ;;
      4) local w; w="$(ask '看哪个日志？1) 主程序 2) 探针' '1')"
         [ "$w" = "2" ] && show_log probe || show_log ;;
      5) ${EDITOR:-vi} "$APP_DIR/config.yaml" 2>/dev/null || vi "$APP_DIR/config.yaml"
         if confirm '重启主程序使配置生效？' y; then svc_start "$SERVICE_MAIN"; fi ;;
      6) do_update ;;
      7) do_uninstall ;;
      0|q|Q) exit 0 ;;
      *) warn "无效选择" ; sleep 1 ;;
    esac
    echo
    ask '按回车继续' '' >/dev/null
  done
}

# =====================================================================
# 参数解析
# =====================================================================
ACTION=""
ZONE=""
PROBE_TOKEN="${PROBE_TOKEN:-}"
PROBE_PORT="${PROBE_PORT:-8787}"
NON_INTERACTIVE=0

usage() {
  cat <<EOF
${BLD}EIP Guard 安装脚本${RST}

  ${BLD}bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh)${RST}
      交互菜单（推荐）

  install.sh --probe --zone cn        装国内探针
  install.sh --probe --zone overseas  装国外探针

  install.sh --install              安装 / 更新主程序
  install.sh --probe --zone cn      安装探针（国内）
  install.sh --probe --zone overseas 安装探针（国外）
  install.sh --status | --log | --update | --uninstall

选项：
  --zone cn|overseas    探针所在位置
  --token TOKEN         探针共享 token（不填则生成）
  --port PORT           探针端口（默认 8787）
  --dir PATH            主程序目录（默认 $APP_DIR）
  --probe-dir PATH      探针目录（默认 $PROBE_DIR）
  --pip-index URL       pip 镜像
  --non-interactive     不做任何提问，全部从环境变量读
  -h, --help            显示本帮助

环境变量：
  REPO BRANCH APP_DIR PROBE_DIR PIP_INDEX
  TG_BOT_TOKEN TG_ADMIN_IDS TG_CHANNEL_ID TG_BIND_TOKEN
  ALIYUN_AK_ID ALIYUN_AK_SECRET ALIYUN_REGION ALIYUN_NAME
  ALIYUN_AK_ID_2 ALIYUN_AK_SECRET_2
  CF_API_TOKEN CF_ZONE_NAME
  PROBE_CN_URL PROBE_OS_URL PROBE_AGENT_TOKEN
  TARGETS   非交互模式的实例列表，每行：
            name|account|instance_id|port|aux_ports|dns_records
            例：hk-main|main|i-j6cxxx|443|22 80|hk.example.com api.example.com

非交互示例：
  TARGETS='hk-main|main|i-j6cxxx|443|22 80|hk.example.com' \
  TG_BOT_TOKEN=... ALIYUN_AK_ID=... ./install.sh --install --non-interactive
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --install|--main) ACTION="install" ;;
    --probe) ACTION="probe" ;;
    --status) ACTION="status" ;;
    --log) ACTION="log" ;;
    --update) ACTION="update" ;;
    --uninstall) ACTION="uninstall" ;;
    --zone) ZONE="${2:-}"; shift ;;
    --token) PROBE_TOKEN="${2:-}"; shift ;;
    --port) PROBE_PORT="${2:-}"; shift ;;
    --dir) APP_DIR="${2:-}"; shift ;;
    --probe-dir) PROBE_DIR="${2:-}"; shift ;;
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
  probe) install_probe ;;
  status) show_status ;;
  log) show_log ;;
  update) do_update ;;
  uninstall) do_uninstall ;;
  "") menu ;;
esac
