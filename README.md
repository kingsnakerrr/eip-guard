# EIP Guard

阿里云 ECS 的 **EIP 被墙 → 自动换新 IP → 自动改 Cloudflare 解析**，全过程由 **Telegram 机器人** 通知、查看和手动控制。

```
         墙内探测节点 ──┐
                        ├─→ 判定被墙（墙内不通 + 墙外通）
     境外探针 VPS ──────┘            │
                                     ▼
      分配新 EIP → 解绑旧 → 绑定新 → 验证新 IP → 改 CF 解析 → 释放旧
                                     │
                          ┌──────────┴──────────┐
                     管理员私聊              频道（广播）
```

## 一、需要准备什么

| 项目 | 用途 | 在哪拿 |
|---|---|---|
| **阿里云 AccessKey ID / Secret** ×N | 换 EIP 的 API 调用（有几个号就几组） | 每个号建一个 **RAM 子账号**，只给 EIP 权限 |
| **Cloudflare API Token** | 改域名 A 记录 | CF 面板 → My Profile → API Tokens |
| **Cloudflare Zone**（域名） | 要跟着换的域名 | 例：`example.com` |
| **ECS 实例 ID** | 要换 IP 的机器 | 控制台，形如 `i-j6cxxxxxxxx` |
| **Telegram Bot Token** | 机器人本体 | 找 [@BotFather](https://t.me/BotFather) `/newbot` |
| **Telegram 你的 chat id** | 谁能控制机器人 | 私聊 [@userinfobot](https://t.me/userinfobot)，或用 `/bind` |
| **Telegram 频道 id**（可选） | 把告警广播出去 | 频道加机器人当管理员，id 形如 `-1001234567890` |
| **国内 VPS** | 提供"国内视角" | 最便宜国内小鸡即可 |
| **境外 VPS** | 提供"国外视角" | 最便宜海外小鸡即可 |

> **必须两台探针**：一台在国内（`--zone cn`）、一台在国外（`--zone overseas`）。
> 判定的核心是「同一端口，国内不通 + 国外通」，缺任何一侧都无法下结论。
> 没有国内机器时可临时用 `provider: checkhost`（公共 API，节点里常有中国的，免费但限流）。

### 多账号

两个阿里云账号各自建一个 RAM 子账号，`config.yaml` 里：

```yaml
aliyun:
  accounts:
    - name: "main"
      access_key_id: "${ALIYUN_AK_ID}"
      access_key_secret: "${ALIYUN_AK_SECRET}"
      default_region: "cn-hongkong"
    - name: "second"
      access_key_id: "${ALIYUN_AK_ID_2}"
      access_key_secret: "${ALIYUN_AK_SECRET_2}"
      default_region: "ap-southeast-1"

targets:
  - name: "hk-main"
    account: "main"          # 用哪个账号
    instance_id: "i-j6c..."
  - name: "sg-second"
    account: "second"
    instance_id: "i-t4n..."
```

每个账号的 AK 只对该账号下的 EIP 有权限，互不影响；地域默认取账号的 `default_region`（target 里可覆盖）。

### 阿里云最小权限（每个账号都要建）

新建 RAM 用户 → 编程访问 → 只附加这份自定义策略（[`docs/aliyun-ram-policy.json`](docs/aliyun-ram-policy.json)）：

```json
{
  "Version": "1",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "vpc:DescribeEipAddresses",
      "vpc:AllocateEipAddress",
      "vpc:AssociateEipAddress",
      "vpc:UnassociateEipAddress",
      "vpc:ReleaseEipAddress"
    ],
    "Resource": "*"
  }]
}
```

不用给 ECS 权限，也不用给 `AliyunECSFullAccess`。

### Cloudflare Token 权限

自定义 Token，两项：

- **Zone → DNS → Edit**
- **Zone → Zone → Read**（用 `zone_name` 自动查 zone id 时要）

Zone Resources 只选你那一个域名。**用 Token，不要用 Global API Key。** 如果换 IP 是为了让流量直连（不走 CF 中转），`proxied` 必须设 `false`，否则解析到哪都无所谓。

---

## 二、一键安装

仓库地址：https://github.com/kingsnakerrr/eip-guard

### 装探针（国内、国外各一台）

判定靠「同一端口，国内不通 + 国外通」对比，**两台都要有**。

```bash
# 国外机器
bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh) --probe --zone overseas

# 国内机器（token 用上面打印的那个）
bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh) --probe --zone cn --token <上面的token>
```

脚本自动：装 Python 依赖 → 生成 token → 写 systemd → 启动 → 健康检查 → 放行防火墙 → 打印地址和该填的配置行。

### 装主程序

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh)
```

出现菜单：

```
╭──────────────────────────────────────────╮
│  EIP Guard · 阿里云 EIP 被墙自动更换       │
╰──────────────────────────────────────────╯
  主程序 未安装    探针 未安装

  1) 安装 / 更新主程序
  2) 安装 / 更新探针（国内或国外）
  3) 查看状态
  4) 查看日志
  5) 编辑配置 / 重启
  6) 更新代码（保留配置）
  7) 卸载
  0) 退出
```

选 `1`，按提示填 5 步（都有默认值，直接回车即可）：

1. **Telegram** — Bot Token、你的 chat id、频道 id（可空）
2. **阿里云** — 账号 1 的 AK/SK + 地域；问你要不要加账号 2
3. **Cloudflare** — API Token、域名
4. **探针** — 国内、国外两个地址 + 共享 token
5. **实例** — 代号、用哪个账号、实例 ID、业务端口、其它端口、域名

填完自动生成 `.env` + `config.yaml`，做一次配置校验，然后启动服务。密码类输入不回显。

### 日常操作

```bash
# 同一条命令进菜单
bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh)

# 或直接用参数
... --status      # 运行状态 + 最近事件
... --log         # 跟踪日志
... --update      # 只更新代码，保留配置
... --uninstall   # 卸载
```

### 非交互安装（批量 / CI）

```bash
TARGETS='hk-main|main|i-j6cxxx|443|22 80|hk.example.com api.example.com
sg-second|second|i-t4nxxx|443|22|sg.example.com' \
TG_BOT_TOKEN='123:abc' \
TG_ADMIN_IDS='12345678' \
ALIYUN_AK_ID='LTAI...' ALIYUN_AK_SECRET='...' \
ALIYUN_AK_ID_2='LTAI...' ALIYUN_AK_SECRET_2='...' \
CF_API_TOKEN='...' CF_ZONE_NAME='example.com' \
PROBE_CN_URL='http://1.1.1.1:8787' PROBE_OS_URL='http://2.2.2.2:8787' \
PROBE_AGENT_TOKEN='xxx' \
bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh) --install --non-interactive
```

`TARGETS` 每行：`代号|账号|实例ID|业务端口|其它端口|域名(空格分隔)`，多行用换行或 `;` 分隔。

### 国内 pip 慢

```bash
bash <(curl -Ls .../install.sh) --pip-index https://pypi.tuna.tsinghua.edu.cn/simple
```

### 装完检查

```bash
cd /opt/eipguard
.venv/bin/python -m eipguard -c config.yaml --check-config   # 配置对不对
.venv/bin/python -m eipguard -c config.yaml --once           # 判定对不对（不改任何东西）
```

`--once` 会打印每个目标的国内外端口对照和结论，确认判对了再放心用。

### 绑定管理员

`.env` 里填了 `TG_ADMIN_IDS` 就直接能用。没填：私聊机器人发 `/bind 你的口令`（口令在 `.env` 的 `TG_BIND_TOKEN`）。

频道：机器人拉进频道 → 设为管理员 → 配置里填 `TG_CHANNEL_ID`，或私聊机器人 `/channel -100xxxxxxxxxx`。

### Docker

```bash
git clone https://github.com/kingsnakerrr/eip-guard.git
cd eip-guard && docker compose up -d --build
```

### raw 链接显示旧内容？

`raw.githubusercontent.com` 有约 5 分钟 CDN 缓存。刚推完代码时可能还是旧的，等几分钟或改用：

```bash
bash <(curl -Ls https://cdn.jsdelivr.net/gh/kingsnakerrr/eip-guard@main/install.sh)
```

---

## 三、Telegram 命令

| 命令 | 作用 |
|---|---|
| `/status` | 所有目标实时状态（IP、判定结论、国内外端口对照） |
| `/status hk-main` | 单个目标详情 |
| `/ip` | 快速看当前 IP 和域名 |
| `/probe [目标]` | 只探测，不改任何东西（显示国内外端口对照 + ping.pe 链接） |
| `/verdict` | 各种判定类型的定义，以及该不该换 IP |
| `/switch 目标` | 手动换 IP（有确认按钮） |
| `/switch all` | 自动挑出异常的目标依次换 |
| `/dns 目标 [ip]` | 重新同步 CF 解析（不填 ip 用当前 EIP） |
| `/settings` | 看当前设置 |
| `/set interval 60` | 检查间隔（秒，≥15） |
| `/set threshold 3` | 连续异常几次才动作 |
| `/set cooldown 900` | 两次更换最小间隔（秒） |
| `/set release on\|off` | 成功后是否释放旧 EIP |
| `/autoswitch` | 全局自动换 IP 开关 |
| `/auto 目标 on\|off` | 单目标自动开关 |
| `/channel -100xxx` / `/channel off` | 设置/关闭频道通知 |
| `/history` | 最近 15 条事件 |
| `/health` | 自检：阿里云、CF、探针、频道是否都通 |

启动时、被墙时、开始更换时、更换成功/失败时，消息都会同时发给**所有管理员**，并广播到**频道**（未达阈值的"疑似"只发管理员，避免刷屏）。

示例通知：

```
🔴 IP 被墙，已确认，准备更换 IP

🎯 目标：hk-main
📤 IP：47.243.1.25
📉 连续异常 3/3 次
🔎 端口 443 国内不通、国外正常，同 IP 其它端口也没有国内可达的 → 判定 IP 被墙
端口对照（国内 / 国外）
  443: 国内 ✗(timeout) / 国外 ✓ ← 节点端口
  22: 国内 ✗(timeout) / 国外 ✓
  ICMP 国内 通 / 国外 通
💡 建议：换 IP 有效。
🔄 正在自动更换 IP…
🔗 自查：https://ping.pe/47.243.1.25:443?host=hk.example.com
```

```
✅ EIP 更换成功

🎯 目标：hk-main
📤 旧 IP：47.243.1.25
📥 新 IP：47.243.9.88
🌐 Cloudflare：2/2 条已更新
   ✓ hk.example.com → 47.243.9.88
   ✓ api.example.com → 47.243.9.88
🔎 验证：正常
⏱ 耗时 43.2s
```

如果是服务挂了，则是：

```
⚫ 服务不可用（不是被墙）

🎯 目标：hk-main
📤 IP：47.243.1.25
🔎 端口 443 在国内和国外都连不上 → 不是墙，是服务没起/安全组没放行/防火墙挡住（refused）
端口对照（国内 / 国外）
  443: 国内 ✗(refused) / 国外 ✗(refused) ← 节点端口
💡 这个端口国内外都连不上，换 IP 解决不了。依次检查：① 服务进程在监听吗（ss -lntp）
   ② 阿里云安全组放行了吗 ③ 系统防火墙 ④ 云盾/黑洞
```

---

## 四、判定逻辑

**核心：同一个端口，国内测一次、国外测一次。** 这是唯一可靠的判据（也是 ping.pe 的做法）。

> 常见误区：以为"22 端口能连"就说明 IP 没被封。错。22 通只证明 22 的服务活着，
> 和 443 是否被墙是两件独立的事。反过来 22 不通也不能证明 IP 被封（可能是 sshd 挂了）。
> 详见 [docs/判定规则.md](docs/判定规则.md)。

### 判定表

| 业务端口 国内 | 业务端口 国外 | 同 IP 其它端口 国内 | 结论 | 该做什么 | 自动换 IP |
|---|---|---|---|---|---|
| ✗ | ✓ | 都不通 | **IP 被墙** | 换 IP | ✅ |
| ✗ | ✓ | 有能通的 | **端口被墙** | 换端口 | ❌ |
| ✗ | ✗ | — | **服务不可用** | 查进程/安全组/防火墙 | ❌ |
| ✓ | — | — | 正常（再看 TLS/HTTP） | — | ❌ |
| ✓ | ✓ | — | TLS 或数据面被阻断 | 换域名/协议/端口 | ❌ |
| 缺国内或国外探针 | | | **无法判定** | 补探针 | ❌ |

- `icmp`（ping）只作为参考信息展示，**不参与判定** —— ping 通不代表可用，ping 不通也不一定是墙。
- "其它端口"（`aux_ports`）用来区分「整台 IP 被封」和「只封了业务端口」：
  - 443 国内不通、22 国内能连 → 只有 443 被针对，**换 IP 无效**，该换端口。
  - 443 和 22 国内都不通、国外都通 → 整台 IP 被墙，**换 IP 有效**。

### 其他保护

- `failure_threshold`（默认 3）连续多次才动作，避免抖动误换。
- **只有 `ip_blocked` 会自动换 IP**；其它结论只告警不花钱（`switch.auto_switch_on` 可扩展）。
- 新 IP 绑定后**先验证、再改解析**：新 IP 也被墙就释放重试，域名始终指向能用的地址。
- 任何一步失败都会**回滚**：释放新 EIP、把已改的解析改回、旧 EIP 绑回。
- 只有部分域名更新失败时不整体回滚（IP 已可用），但会 ⚠️ 指出哪几条没改成功。
- 告警里附带 **ping.pe 自查链接**，可人工复核同一套结论。

### 通知示例

```
🔴 IP 被墙，已确认，准备更换 IP

🎯 目标：hk-main
📤 IP：47.243.1.25
📉 连续异常 3/3 次
🔎 端口 443 国内不通、国外正常，同 IP 其它端口也没有国内可达的 → 判定 IP 被墙
端口对照（国内 / 国外）
  443: 国内 ✗(timeout) / 国外 ✓ ← 节点端口
  22: 国内 ✗(timeout) / 国外 ✓
  ICMP 国内 通 / 国外 通
💡 建议：换 IP 有效。
🔄 正在自动更换 IP…
🔗 自查：https://ping.pe/47.243.1.25:443?host=hk.example.com
```

端口封锁时：

```
🟠 端口被墙（换 IP 无效，不自动更换）

🔎 端口 443 国内不通、国外正常，但同 IP 的 22 国内能连 → 只封了这一个端口
端口对照（国内 / 国外）
  443: 国内 ✗(timeout) / 国外 ✓ ← 节点端口
  22: 国内 ✓ / 国外 ✓
💡 建议：只有这一个端口被墙，同 IP 其它端口国内能连 → 换端口（如 443→8443）最有效
```

## 五、配置说明

`config.yaml` 关键项（完整见 [`config.example.yaml`](config.example.yaml)）：

```yaml
aliyun:
  region_id: "cn-hongkong"      # EIP 所在地域，香港/新加坡/日本最常见
cloudflare:
  zone_name: "example.com"      # 或 zone_id
  ttl: 60                       # 60 秒，被墙后能较快生效
  proxied: false                # 换 IP 直连就要 false
detect:
  provider: "probe_agent"       # probe_agent | hybrid | checkhost | tcp_self
  interval: 60
  failure_threshold: 3
  # 分层探测：icmp + tcp + tls 是推荐组合；http 用来查数据面；aux 用来区分整机/单端口
  layers: ["icmp", "tcp", "tls"]
  # 强烈建议填机器上真实开放的其它端口（SSH/面板/备用 Web）
  aux_ports: [22, 80]
  probe_agent:
    urls: "http://1.2.3.4:8787"
    token: "${PROBE_AGENT_TOKEN}"
switch:
  auto_switch_on: ["ip_blocked"]  # 只有 IP 被墙才自动换
  max_attempts: 3
  cooldown: 900
  release_old: true             # false 会保留旧 EIP 继续计费
targets:
  - name: "hk-main"
    instance_id: "i-j6cxxxxxxxxxxxxxxxx"
    dns_records: ["hk.example.com", "api.example.com"]
```

多个实例就写多个 target，可以跨地域（`region_id` 写在 target 里覆盖全局）。多个探针可以写成：

```yaml
detect:
  probe_agent:
    agents:
      - {url: "http://1.2.3.4:8787", token: "t1", zone: "overseas", name: "us-la"}
      - {url: "http://5.6.7.8:8787", token: "t2", zone: "cn", name: "sh"}   # 墙内节点
```

`zone: cn` 的探针是墙内的（比如另一台国内小鸡），`overseas` 是墙外的。**有墙内节点判定才准**。

---

## 六、费用与安全

- 换 IP 期间会短暂出现**两个 EIP 同时在计费**（几十秒），之后释放旧的。保留旧 EIP（`release_old: false`）会持续收未绑定 EIP 的费用。
- `data/state.json` 存冷却和统计，删掉只影响历史统计，不会误换 IP。
- `.env` 是明文密钥：`chmod 600 .env`，不要把 `config.yaml` / `.env` 提交进 git（`.gitignore` 已排除）。
- 建议每个账号的 AK 只开上面那份最小策略；某个 AK 泄露，别人最多能操作**那个账号**的 EIP。
- 探针端口 8787 要限制来源 IP，只允许主程序那台机器访问，否则等于给别人开了个探测服务。
- 本程序会**自动花钱**（分配新 EIP、可能保留旧 EIP）。第一次上线建议 `/set release off` 观察一轮，确认流程没问题再打开。

## 七、开发

```bash
.venv/bin/python -m pytest -q     # 83 个测试：国内外对比判定 / CF 客户端 / 换 IP 全流程 / 多账号 / 机器人 / 探针
```

结构：

```
src/eipguard/
  __main__.py    # 启动、信号处理；Telegram 挂了不影响监控
  config.py      # YAML + ${ENV} 解析、校验、多账号
  cloud/aliyun.py    # EIP 分配/绑定/解绑/释放（异步包装、重试）
  cloud/cloudflare.py # A 记录查询/更新/创建
  detect/probe.py    # 探针客户端、check-host、判定逻辑（国内外同端口对比）
  engine.py      # 状态机：inspect / monitor / switch / rollback / verify
  bot.py         # Telegram 命令与通知
  state.py       # 状态与动态设置持久化
  fmt.py         # 消息渲染
probe_agent/server.py   # 探针（国内/国外各一台，仅需 aiohttp）
install.sh              # 一键安装 / 菜单 / 卸载
docs/判定规则.md        # 为什么不能靠 22 端口判断
```

## 八、排错

| 现象 | 检查 |
|---|---|
| 换 IP 报 `InvalidAccessKeyId` | AK 写错或子账号被禁用 |
| 报 `Forbidden.RAM` | 权限策略少了某个 vpc: 动作 |
| CF 报 `Unable to authenticate` | Token 少了 `Zone:Read` / 没选对 zone |
| 一直"无法判定：没有国内探针" | 只装了国外探针，或 `zone` 写成 overseas 了 |
| 一直"无法判定：没有国外探针" | 缺境外探针 |
| 判成"端口被墙"但你觉得整机都废了 | `aux_ports` 里有个端口恰好国内能连；确认那个端口真的该通，否则从 `aux_ports` 去掉 |
| 判成"服务不可用" | 国外也连不上业务端口。查：`ss -lntp` 看进程、安全组、firewalld/ufw |
| 探针显示 `icmp –` | 探针机没有 ping 命令：`apt install iputils-ping`（不影响判定） |
| 探针连接超时 | 8787 端口没放行，或安全组没开；`curl` 探针 /health 试 |
| 机器人不回话 | `journalctl -u eipguard -f`，检查 token 和 chat id |
| 频道收不到 | 机器人不是频道管理员；或 `/channel` 没设 |
| 新 IP 一换就被墙 | 该地域 IP 段被重点照顾，多设 `max_attempts`，或换地域 |
| 想人工复核结论 | 告警里有 ping.pe 链接，点开对比国内外结果 |
| 装完服务起不来 | `journalctl -u eipguard -n 50`；配置错会直接报在哪一行 |
| 提示 `REPO 还没配置` | 改 `install.sh` 里的 `REPO=`，或运行时加 `REPO=用户名/仓库` |
| 探针 8787 起不来 | 端口被占：`ss -lntp | grep 8787`，换 `--port 18787` |
| Telegram token 无效 | 服务仍会运行（监控不停），只是收不到消息；修 `.env` 后重启 |
