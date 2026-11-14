# tp-rotate

轮换 tinyproxy 的 BasicAuth 密码，并把新密码推送到企业微信群。

手动触发，不带定时任务。密码在青龙容器里生成、经 SSH 交给路由器写入，
路由器本地验证新密码真的能用之后才返回成功 —— 所以群里收到的密码一定
是当前生效的那个。

## 结构

```
青龙容器 (manual task)
  └── tp_rotate.py
        ├── 生成 8 位密码，只留在内存里
        ├── ssh -T ────────────────►  路由器 /usr/sbin/tp-setpw
        │                              （forced command，只有这一条路）
        │                                 ├── 校验密码格式
        │                                 ├── 重建 uci 里的 BasicAuth 列表
        │                                 ├── 重启 tinyproxy
        │                                 ├── 本地自检 4 项
        │                                 ├── 任一步失败 → 恢复原列表
        │                                 └── 返回 OK <account> <port> / ERR <reason>
        └── 企业微信群机器人（webhook）
```

## 为什么走 SSH 而不是 HTTP 回调

- 路由器 **不用开新端口**，一行 firewall 规则都不用加（SSH 本来就在跑）
- 密码走加密信道，不在内网明文
- 认证靠公钥，不可爆破；再配 forced command，这把 key 即使泄露也只能改
  一个指定账号的密码，拿不到 shell、做不了端口转发
- 青龙官方的 Alpine 镜像自带 `ssh` / `curl` / `python3`，零安装

## 青龙到路由器走的什么路径

```
青龙容器 172.17.0.5/16
  └── 默认网关 172.17.0.1 (docker0)
        └── iptables MASQUERADE  源地址改写为宿主机 LAN 地址
              └── 宿主机 eth  →  路由器:22
```

关键是 **MASQUERADE**：路由器上看到的连接来源是宿主机的 LAN 地址，不是
`172.17.0.x`。所以想靠"只放行容器网段"来收紧权限是做不到的，只能按宿主机
地址放行。验证方法：

```sh
# 路由器上
grep 'dport=22' /proc/net/nf_conntrack
```

## 密码规则

- 8 位
- 只含 `[A-Za-z0-9]`
- 大写、小写、数字各至少一位
- 排除 `0 O 1 l I`，避免从手机屏幕上抄错

## 部署

### 1. 路由器端

把 `openwrt/tp-setpw` 放到 `/usr/sbin/`，加执行位：

```sh
scp openwrt/tp-setpw root@ROUTER:/usr/sbin/tp-setpw
ssh root@ROUTER 'chmod 755 /usr/sbin/tp-setpw'
```

在路由器上生成一把专用密钥（或者把已有的公钥拿来用），然后把公钥写进
`/etc/dropbear/authorized_keys`，**必须带 `command=` 前缀**：

```
command="/usr/sbin/tp-setpw",no-pty,no-port-forwarding,no-agent-forwarding,no-x11-forwarding ssh-ed25519 AAAA... comment
```

改之前先备份：

```sh
cp -a /etc/dropbear/authorized_keys /etc/dropbear/authorized_keys.bak-$(date +%Y%m%d)
```

验证锁定生效（应该返回 `ERR empty-password`，而不是文件内容）：

```sh
ssh -i KEY root@ROUTER 'cat /etc/shadow' </dev/null
```

前提：路由器上 tinyproxy 的 `BasicAuth` 至少有一条 `root ...` 和一条
`user ...`，且 `root` 在第一条 —— 状态页依赖这个顺序。

### 2. 青龙端：代码从仓库拉，不手工拷

青龙面板 → 订阅管理 → 新建订阅：

| 字段 | 值 |
|---|---|
| 名称 | `tp-rotate` |
| 链接 | `https://github.com/USER/tp-rotate.git` |
| 分支 | `main` |
| 白名单 | 留空 |
| 黑名单 | 留空 |
| 依赖文件 | 留空 |
| 定时规则 | 留空（只手动拉取，不自动同步） |

保存后点「运行」，代码落到 `/ql/data/scripts/<owner>_tp-rotate/`。

**不要手工把脚本拷进容器。** 手工副本和仓库会分叉，下次拉取是覆盖
还是并存取决于青龙版本，迟早会跑到一份过期代码上。

### 2.1 两样东西必须手工放（含环境信息，不进仓库）

**密钥**，在青龙容器里生成：

```sh
mkdir -p /ql/data/keys
ssh-keygen -t ed25519 -N "" -C "ql-tp-rotate" -f /ql/data/keys/tp-ROUTER
chmod 600 /ql/data/keys/tp-ROUTER
ssh-keyscan -t ed25519,rsa ROUTER > /ql/data/keys/known_hosts.tp-ROUTER
```

把 `tp-ROUTER.pub` 贴到路由器的 `authorized_keys`（见上一步）。

**配置**，复制 `config.example.json` 到 `/ql/data/config/tp-rotate.json`
并按实际环境填写：

```json
{
  "targets": [
    {
      "label": "router-a",
      "host": "10.0.0.1",
      "port": 22,
      "user": "root",
      "account": "user",
      "key_path": "/ql/data/keys/tp-router-a",
      "known_hosts": "/ql/data/keys/known_hosts.tp-router-a"
    }
  ]
}
```

| 字段 | 含义 |
|---|---|
| `label` | 显示名字，也用于默认推导 known_hosts 文件名 |
| `host` / `port` | 路由器地址和 SSH 端口 |
| `user` | SSH 登录名，通常 `root` |
| `account` | 要改密码的 tinyproxy 账号，**只能是 `user`**，helper 会硬拒绝 `root` |
| `key_path` | 私钥路径 |
| `known_hosts` | 可选，缺省为私钥同目录下 `known_hosts.<label>` |

`tp-rotate.json` 里有内网地址，**不要提交到任何仓库**，权限设 `600`。
配置路径可以用环境变量 `TP_CONFIG` 覆盖，方便一份代码挂多个环境。

### 3. 环境变量

在青龙「环境变量」里加：

| 名称 | 说明 |
|---|---|
| `WECOM_WEBHOOK_KEY` | 企业微信群机器人的 key（`.../send?key=` 后面那串） |

没设这个变量时脚本照常轮换，只是不推送。

### 4. 建任务

青龙面板 → 定时任务 → 新建：

| 项 | 值 |
|---|---|
| 名称 | tinyproxy 密码轮换 |
| 命令 | `python3 /ql/data/scripts/<owner>_tp-rotate/tp_rotate.py` |
| 定时规则 | 留空（只手动触发，不要填 cron） |

`<owner>` 是拉取后实际生成的目录前缀，`ls /ql/data/scripts/ | grep tp-rotate`
确认一下再填。

保存后点「运行」即可。要空跑看效果，命令后面加 `--dry-run`。


## 输出

```
[OK] router-a  user / Kx7mPq3T
[WECOM] ok
```

群消息：

```
【tinyproxy 密码轮换】
router-a  user / Kx7mPq3T
```

失败时对应目标是 `失败：<原因>（原密码保持不变）`，脚本退出码非 0。

## 路由器本地自检

`tp-setpw` 写完配置后依次验证：

| 检查 | 期望 |
|---|---|
| 无凭据 GET 到代理端口 | `401` |
| 错误密码 | `401` |
| 新密码 | `200` |
| 新密码走真实代理模式（`curl -x`） | `200` |
| `root` 那一条仍是第一条且字节未变 | — |

任何一项不过就恢复原 `BasicAuth` 列表、重启 tinyproxy，然后返回 `ERR`。
注意直连代理端口时 tinyproxy 返回的是 **401**，`407` 只在 `-x` 代理模式下
出现，两者别混。

## 回滚

路由器端：

```sh
cp -a /etc/dropbear/authorized_keys.bak-YYYYMMDD /etc/dropbear/authorized_keys
rm -f /usr/sbin/tp-setpw
```

密码本身用 `uci` 改回即可：

```sh
uci get tinyproxy.@tinyproxy[0].BasicAuth
```

## 约定

这个仓库里不出现任何真实凭据、主机地址、域名、webhook key。所有环境相关
的东西都在 `/ql/data` 下的配置文件和环境变量里。
