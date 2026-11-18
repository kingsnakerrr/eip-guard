# EIP Guard

阿里云 EIP **手动换 IP** + Cloudflare **自动改解析** + **Telegram 机器人**，支持**多阿里云账号**。

你发现 IP 被墙了，在 Telegram 发一条 `/switch hk-main`，程序就：

```
释放旧 IP（立刻停止计费） → 分配新 IP → 绑定到实例 → 改 CF 解析
```

每一步都推送给你和频道。

> 不做自动检测、不自动换 IP。判定交给你（或用 ping.pe 看）。

---

## 一、安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh)
```

脚本会装好程序、systemd 服务和 `eipguard` 命令行工具，**只问 3 件事**：

| 问题 | 说明 |
|---|---|
| Telegram Bot Token | @BotFather → `/newbot` 拿 |
| 你的 chat id | 可空，之后 `eipguard --bind 你的id` |
| 绑定口令 | 防止别人抢先绑定，可空 |
| Telegram 代理 | 服务器在国内才需要，国外直接回车 |

阿里云 AK、Cloudflare Token、实例**都不在这一步填**——之后在 Telegram 里加，或者用命令行加。

装完自动启动。日志：`journalctl -u eipguard -f`

---

## 一.五、从第一版升级

**不用删，直接升级**，配置会自动迁移（先备份 `config.yaml.bak`）：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kingsnakerrr/eip-guard/main/install.sh) --update
```

升级过程：

```
→ 更新代码
→ 迁移旧配置（备份为 config.yaml.bak）
    · aliyun.access_key_id → aliyun.accounts[default]
    · targets[hk-main].probe_port/aux_ports 已忽略
    · cloudflare.zone_name 取自 .env 的 CF_ZONE_NAME（realdomain.com）
✅ 配置校验通过
  管理员：555666
  阿里云账号：1 个
    - default · akRE… · cn-hongkong · 1 台实例
  实例（1 台）：
    - hk-main · default · i-j6cxxx · hk.example.com
✓ eipguard 已启动
```

**会保留的**：阿里云 AK/SK、Cloudflare Token 和域名、实例 ID、域名列表、管理员、频道。
**会丢的**：探针配置（新版不需要了，直接忽略）。

升级后自己确认一眼：

```bash
eipguard --check-config
```

### 第一版的两个坑，升级时要注意

1. **`zone_name` 写死成 `example.com`**
   第一版的 `config.example.yaml` 把域名硬编码了，你的真实域名其实在 `.env` 的 `CF_ZONE_NAME`。
   升级时会自动纠正，但如果你的 `.env` 里也没填，需要手动补：
   ```bash
   eipguard cf 你的CF_TOKEN 你的真实域名.com
   ```

2. **`.env` 可能还是模板占位符**
   如果你当初是用 `--non-interactive` 装的而且没手动改 `.env`，里面还是 `your_bot_token` 这种。
   升级后先 `eipguard --check-config`，看到账号/AK 是占位符就重新填：
   ```bash
   eipguard account add main 真实AK 真实SK cn-hongkong
   ```

### 想彻底重装

```bash
# 卸载（保留数据）
bash <(curl -Ls .../install.sh) --uninstall
# 或连配置一起删
rm -rf /opt/eipguard

# 重新装
bash <(curl -Ls .../install.sh)
```

只有当你第一版的配置本来就是错的、或者想换安装目录时才需要这样。否则 `--update` 更省事。

---

## 二、配置（两种方式，随时切换）

### 方式 A：在 Telegram 里配置（推荐）

私聊机器人，按顺序：

```
/start                  → 它会提示你还缺什么
/account add            → 对话式：代号 → AK → SK → 选地域
/cf                     → 对话式：CF Token → 域名
/target add             → 对话式：代号 → 选账号 → 实例ID → 域名
```

每一步都会验证：AK 会真调一次阿里云接口，CF Token 会真查一次 zone。错了当场告诉你原因，不会存坏配置。

**含密钥的消息会自动删除**（机器人收到后 `delete` 掉那条）。

### 方式 B：在 SSH 里用命令行

```bash
# 添加阿里云账号（会验证 AK）
eipguard account add main LTAI5t... xxxxxxx cn-hongkong
eipguard account add second LTAI5t... yyyyyyy ap-southeast-1

# 设置 Cloudflare（会验证 Token 和 zone）
eipguard cf 你的CF_TOKEN example.com

# 添加实例
eipguard target add hk-main main i-j6cxxxxxxxx hk.example.com api.example.com
eipguard target add sg-second second i-t4nxxxxxxxx sg.example.com

# 查看
eipguard account list
eipguard target list
eipguard --check-config
eipguard --status
```

命令可以重复执行，直接覆盖同名项。

### 方式 C：直接改 config.yaml

```bash
sudo -e /opt/eipguard/config.yaml
sudo systemctl restart eipguard
```

---

## 三、Telegram 命令

### 换 IP

| 命令 | 说明 |
|---|---|
| `/switch hk-main` | 换某台实例的 IP（先弹确认按钮） |
| `/switch all` | 全部实例依次换 |
| `/dns hk-main` | 只重同步解析，不换 IP |

### 查看

| 命令 | 说明 |
|---|---|
| `/status` | 所有实例 + 当前 IP + EIP 状态 |
| `/status hk-main` | 单个实例 + 当前解析记录 + ping.pe 链接 |
| `/accounts` | 阿里云账号列表（AK 只显示前 8 位） |
| `/targets` | 实例列表 |
| `/settings` | 当前设置 |
| `/history` | 最近操作记录 |
| `/health` | 依赖自检（每个账号、CF、频道） |

### 管理

| 命令 | 说明 |
|---|---|
| `/account add` / `del 名字` / `region 名字 地域` | 账号增删改 |
| `/target add` / `del 名字` / `dns 名字 a.com b.com` | 实例增删改 |
| `/cf` | 重设 Cloudflare |
| `/set release on\|off` | 换完是否释放旧 IP（默认 on） |
| `/set proxied on\|off` | CF 小黄云 |
| `/set ttl 60` | 解析 TTL |
| `/set retries 3` | 分配新 IP 失败时重试几次 |
| `/channel -100xxxx` | 通知频道（机器人需是管理员） |
| `/bind 口令` | 绑定自己为管理员 |
| `/help` | 完整说明 |

---

## 四、换 IP 的推送

发 `/switch` 后你会依次收到 5 条消息：

```
🔁 开始更换 IP
   当前 IP：47.243.1.25
   待更新域名：hk.example.com, api.example.com

✅ 已分配新 IP
   新 IP：47.243.9.88

✅ 旧 IP 已释放（停止计费）
   旧 IP：47.243.1.25

✅ 新 IP 已绑定到实例
   新 IP：47.243.9.88

✅ Cloudflare 解析已更新（2/2）
   ✓ hk.example.com → 47.243.9.88
   ✓ api.example.com → 47.243.9.88

🎉 换 IP 全部完成
   旧 IP：47.243.1.25（已释放）
   新 IP：47.243.9.88
   解析：2/2 条已指向新 IP
   耗时 43.2s
```

失败时也会说清是哪一步失败、旧 IP 有没有释放、新 IP 现在什么状态。

---

## 四.五、域名从哪来？

换 IP 时程序按这个顺序确定要改哪些域名：

```
1. 你在 /target add 或 config.yaml 里写的 dns_records   ← 优先
2. 没写？用 CF Token 反查「哪些 A 记录指向旧 IP」        ← 自动发现
3. 都没有 → 只换 IP，并明确告警告诉你域名没动
```

### 情况一：什么都没配（没填 CF）

```
🔁 开始更换 IP
📤 当前 IP：47.243.1.25
⚠️ 本次只换 IP，不改域名（原因见下）
⚠️ 没有配置 Cloudflare（缺 API Token 或域名），这次只换 IP，域名不会更新
   （已配置的域名 hk.example.com 没能更新）。发 /cf 设置后再 /dns 目标名 可以补上。
```

**旧 IP 照样释放（停止计费），新 IP 照样绑定**，只是域名还指着旧 IP。配好 CF 后发 `/dns hk-main` 就能补上。

### 情况二：配了 CF，没写域名 → 自动发现

程序会问 Cloudflare：这个 zone 里哪些 A 记录指向旧 IP？

```
🔁 开始更换 IP
📤 当前 IP：47.243.1.25
🌐 待更新域名（自动发现）：hk.example.com, api.example.com, www.example.com
```

查到的域名会**自动写回配置**，以后不用再查。

### 情况三：CF 里也没记录指向旧 IP

```
⚠️ 这个 zone 下没有指向 47.243.1.25 的 A 记录，这次只换 IP。
   请发 /target dns 目标名 你的域名 指定要改哪条。
```

这时候要明确告诉它域名：`/target dns hk-main hk.example.com`

### 随时查看当前对应关系

```
/cf check
```

```
Cloudflare · example.com

• hk-main 47.243.1.25
   指向它的域名：hk.example.com, api.example.com
   ✅ 换 IP 时会自动更新这些域名
```

这个命令会告诉你：**换 IP 时到底会改哪些域名**，而不是靠猜。

---

## 五、需要准备什么

| 项目 | 用途 | 在哪拿 |
|---|---|---|
| 阿里云 AccessKey ID / Secret | 换 EIP（有几个号就几组） | 每个号建 RAM 子账号，只给 EIP 权限 |
| Cloudflare API Token | 改 A 记录 | CF → My Profile → API Tokens |
| Cloudflare 域名 | 要跟着换的域名 | 例 `example.com` |
| ECS 实例 ID | 要换 IP 的机器 | 控制台，形如 `i-j6cxxxxxxxx` |
| Telegram Bot Token | 机器人 | @BotFather |
| Telegram chat id | 谁能操作 | @userinfobot，或机器人会告诉你 |

### 阿里云最小权限（每个账号都建一份）

RAM 用户 → 编程访问 → 自定义策略（[`docs/aliyun-ram-policy.json`](docs/aliyun-ram-policy.json)）：

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

不用给 ECS 权限。

### Cloudflare Token 权限

- **Zone → DNS → Edit**
- **Zone → Zone → Read**

Zone Resources 只选你那一个域名。用 Token，不要用 Global API Key。

如果换 IP 是为了流量直连，`proxied` 必须是 `false`（默认就是）。

---

## 六、安装脚本的其他参数

```bash
bash <(curl -Ls .../install.sh)              # 交互菜单
bash <(curl -Ls .../install.sh) --install    # 直接安装
bash <(curl -Ls .../install.sh) --status     # 查看状态
bash <(curl -Ls .../install.sh) --log        # 看日志
bash <(curl -Ls .../install.sh) --update     # 只更新代码，保留配置
bash <(curl -Ls .../install.sh) --uninstall  # 卸载
```

国内 pip 慢：

```bash
bash <(curl -Ls .../install.sh) --pip-index https://pypi.tuna.tsinghua.edu.cn/simple
```

GitHub 拉不动会自动换镜像（ghproxy.net / gh-proxy.com / ghfast.top）。

---

## 七、费用与安全

- **旧 IP 默认会释放**，`/set release off` 可保留（会继续收未绑定 EIP 的费用）。
- 换 IP 期间会短暂存在两个 EIP（几十秒）。
- `config.yaml` 权限是 **600**，里面有 AK/SK 明文；`.env` 也是 600。
- 建议每个账号只用最小权限的 RAM 子账号。
- 机器人只有 `admin_chat_ids` 里的人能用；别人私聊会被回一个"未授权"和它自己的 chat id。
- 含密钥的 Telegram 消息会被自动删除，但 Telegram 服务器上可能仍有备份——敏感环境建议只用 SSH 命令行添加账号。

---

## 八、开发

```bash
.venv/bin/python -m pytest -q     # 63 个测试
.venv/bin/python -m mypy src/eipguard
```

结构：

```
src/eipguard/
  config.py    # 配置加载/校验/回写（多账号）
  cloud/aliyun.py     # EIP 分配/绑定/解绑/释放
  cloud/cloudflare.py # A 记录查询/更新/创建
  engine.py    # 换 IP 流程：释放旧 → 分配新 → 绑定 → 改解析
  bot.py       # Telegram 命令、对话式配置、通知
  fmt.py       # 消息渲染
  __main__.py  # 启动 + 命令行（--status/--switch/--bind/account/target/cf）
install.sh     # 一键安装
```

---

## 九、排错

| 现象 | 检查 |
|---|---|
| 装完没反应 | `journalctl -u eipguard -n 50` |
| 机器人不回话 | token 对不对；国内机器要设 `TG_PROXY` |
| `/account add` 验证失败 | AK/SK 错、子账号没 EIP 权限、或该地域不支持 |
| `/cf` 验证失败 | Token 少了 Zone:Read，或域名不在这个账号下 |
| `/switch` 报"没有绑定 EIP" | 实例 ID 错，或该实例本来就没绑 EIP |
| 换完解析没变 | 检查域名是否在同一个 zone；`/dns hk-main` 单独重试 |
| 旧 IP 还是被扣费 | `/set release off` 会导致这样，改回 on |
| 想看当前 IP | `eipguard --status` 或 TG `/status` |
| 想手工确认是不是被墙 | `/status 目标名` 里有 ping.pe 链接 |
