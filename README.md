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
| **阿里云 AccessKey ID / Secret** | 换 EIP 的 API 调用 | 建议新建 **RAM 子账号**，只给 EIP 相关权限 |
| **Cloudflare API Token** | 改域名 A 记录 | CF 面板 → My Profile → API Tokens |
| **Cloudflare Zone**（域名） | 要跟着换的域名 | 例：`example.com` |
| **ECS 实例 ID** | 要换 IP 的机器 | 控制台，形如 `i-j6cxxxxxxxx` |
| **Telegram Bot Token** | 机器人本体 | 找 [@BotFather](https://t.me/BotFather) `/newbot` |
| **Telegram 你的 chat id** | 谁能控制机器人 | 私聊 [@userinfobot](https://t.me/userinfobot)，或用 `/bind` |
| **Telegram 频道 id**（可选） | 把告警广播出去 | 频道加机器人当管理员，id 形如 `-1001234567890` |
| **境外 VPS**（推荐） | 判断"被墙"还是"机器挂了" | 一台最便宜的海外小鸡即可 |

> 只靠墙内探测无法区分"被墙"和"服务器宕机"，本项目**要求墙内不通 + 墙外通**才判定为被墙，所以需要至少一个墙外探针。没有墙外 VPS 时可临时用 `provider: checkhost`（公共 API，别人家的海外节点，免费但会限流）。

### 阿里云最小权限

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

## 二、快速开始

### 1. 墙外探针（一台海外 VPS，1 分钟）

```bash
apt install -y python3-aiohttp     # 或 pip install aiohttp
mkdir -p /opt/eip-probe && cp probe_agent/server.py /opt/eip-probe/

echo 'PROBE_TOKEN=一串很长的随机字符' > /opt/eip-probe/probe.env

cp deploy/probe-agent.service /etc/systemd/system/
systemctl enable --now probe-agent
curl 'http://127.0.0.1:8787/health'   # {"ok": true, "zone": "overseas"}
```

记住 `http://这台机器IP:8787` 和 token，下一步要填。

### 2. 安装主程序（墙内那台要跑机器人的机器）

```bash
git clone <你的仓库> eip-guard && cd eip-guard
cp .env.example .env && chmod 600 .env
cp config.example.yaml config.yaml
$EDITOR .env config.yaml          # 填密钥、实例 ID、域名
./install.sh                      # 装到 /opt/eipguard 并注册 systemd
```

不想用脚本就手动：

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .
.venv/bin/python -m eipguard -c config.yaml --check-config   # 校验配置
.venv/bin/python -m eipguard -c config.yaml                  # 启动
```

也可以 Docker：

```bash
docker compose up -d --build
```

### 3. 绑定管理员

`.env` 里先填 `TG_ADMIN_IDS`（你的数字 id）最省事。若留空：

1. 在 `config.yaml` 的 `telegram.bind_token` 设一个口令
2. 私聊机器人发送 `/bind 你的口令`
3. 机器人回复 chat id，把它写进 `TG_ADMIN_IDS` 更稳妥

设置频道：把机器人拉进频道 → 设为管理员 → 要么在 `.env` 填 `TG_CHANNEL_ID`，要么私聊机器人 `/channel -100xxxxxxxxxx`。

---

## 三、Telegram 命令

| 命令 | 作用 |
|---|---|
| `/status` | 所有目标实时状态（IP、EIP、失败次数、每个探针的结果） |
| `/status hk-main` | 单个目标详情 |
| `/ip` | 快速看当前 IP 和域名 |
| `/probe [目标]` | 只探测，不改任何东西 |
| `/switch 目标` | 手动换 IP（有确认按钮） |
| `/switch all` | 自动挑出异常的目标依次换 |
| `/dns 目标 [ip]` | 重新同步 CF 解析（不填 ip 用当前 EIP） |
| `/settings` | 看当前设置 |
| `/set interval 60` | 检查间隔（秒，≥15） |
| `/set threshold 3` | 连续失败几次才换 |
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
🚨 检测到 IP 被墙，开始更换（自动）

🎯 目标：hk-main
📤 当前 IP：47.243.1.25
🧭 原因：自动：连续探测判定被墙
🔎 墙内不通、墙外正常 → 判定被墙：hk-cn(cn) 不通(timeout) | us-1(overseas) 通 182ms
```

```
✅ EIP 更换成功

🎯 目标：hk-main
📤 旧 IP：47.243.1.25
📥 新 IP：47.243.9.88
🌐 Cloudflare：2/2 条已更新
   ✓ hk.example.com hk.example.com → 47.243.9.88
   ✓ api.example.com api.example.com → 47.243.9.88
🔎 验证：墙内通 210ms
⏱ 耗时 43.2s
```

---

## 四、判定逻辑（为什么不会乱换 IP）

每轮探测对所有节点发起 TCP 连接（可选 TLS 握手），然后：

| 墙内节点 | 墙外节点 | 结论 | 动作 |
|---|---|---|---|
| 大面积失败 | 正常 | **被墙** | 计一次失败，达阈值就换 |
| 正常 | — | 正常 | 失败计数清零 |
| 失败 | 也失败 | 实例/服务故障 | **只告警，不换 IP** |
| 没有墙内节点 | — | 无法确认 | 只告警，不换 IP |

- `failure_threshold`（默认 3）连续多次才动作，避免网络抖动误换。
- 新 IP 绑定后**先验证、再改解析**：如果新 IP 也被墙，就释放它并试下一个（`max_attempts`），域名始终指向能用的地址。
- 任何一步失败都会**回滚**：释放新 EIP、必要时把已改的解析改回、把旧 EIP 绑回去，保证机器至少还能通过控制台操作。
- 只有部分域名更新失败时不会整体回滚（IP 已经可用），但通知里会有 ⚠️ 提示具体哪几条没改成功。
- `cooldown` 防止短时间内反复换 IP 烧钱。

---

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
  probe_agent:
    urls: "http://1.2.3.4:8787"
    token: "${PROBE_AGENT_TOKEN}"
switch:
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
- 建议 AK 只开上面那份最小策略；如果 AK 泄露，别人最多能操作你的 EIP。
- 本程序会**自动花钱**（分配新 EIP、可能保留旧 EIP）。第一次上线建议 `/set release off` 观察一轮，确认流程没问题再打开。

## 七、开发

```bash
.venv/bin/python -m pytest -q     # 52 个测试：探测判定 / CF 客户端 / 换 IP 全流程 / 机器人命令 / 探针
```

结构：

```
src/eipguard/
  config.py      # YAML + ${ENV} 解析、校验
  cloud/aliyun.py    # EIP 分配/绑定/解绑/释放（异步包装、重试）
  cloud/cloudflare.py # A 记录查询/更新/创建
  detect/probe.py    # 探针客户端、check-host、判定逻辑
  engine.py      # 状态机：inspect / monitor / switch / rollback / verify
  bot.py         # Telegram 命令与通知
  state.py       # 状态与动态设置持久化
  fmt.py         # 消息渲染
probe_agent/server.py   # 墙外探针（独立部署，仅需 aiohttp）
```

## 八、排错

| 现象 | 检查 |
|---|---|
| 换 IP 报 `InvalidAccessKeyId` | AK 写错或子账号被禁用 |
| 报 `Forbidden.RAM` | 权限策略少了某个 vpc: 动作 |
| CF 报 `Unable to authenticate` | Token 少了 `Zone:Read` / 没选对 zone |
| 一直"缺少墙外节点确认" | 探针没通，`/health` 看探针那行；或 `zone` 填错 |
| 一直"墙内外都不通" | 是服务挂了不是被墙，先查实例 |
| 机器人不回话 | `journalctl -u eipguard -f`，检查 token 和 chat id |
| 频道收不到 | 机器人不是频道管理员；或 `/channel` 没设 |
| 新 IP 一换就被墙 | 该地域 IP 段被重点照顾，可以多设 `max_attempts`，或换地域 |
