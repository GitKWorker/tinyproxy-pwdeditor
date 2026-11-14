# tp-rotate

轮换 tinyproxy 的 BasicAuth 密码，并把新密码推送到企业微信群。

手动触发，不带定时任务。密码在青龙容器里生成、经 SSH 交给路由器写入，
路由器本地验证新密码真的能用之后才返回成功 —— 所以群里收到的密码一定
是当前生效的那个。

## 结构

```
青龙容器 (manual task)
  └── tp_rotate.py
        ├── 读 TINYPROXY_PWDEDITOR → 目标列表 / 私钥路径 / 主机公钥 / 企微 key
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

## 密钥分工（先看这节）

SSH 公钥认证的方向是固定的：**私钥留在发起连接的一方，公钥交给被连接的一方。**
这里发起连接的是青龙，被连接的是路由器。

| 文件 | 在哪生成 | 放哪 | 权限 | 进仓库 |
|---|---|---|---|---|
| `tp-ROUTER`（**私钥**，无扩展名） | 青龙容器 | `/ql/data/keys/tp-ROUTER` | `600` | **绝对不行** |
| `tp-ROUTER.pub`（**公钥**） | 青龙容器 | 路由器 `/etc/dropbear/authorized_keys` 里的**一行** | 该文件 `600` | 不敏感，但没必要 |
| `known_hosts.tp-ROUTER` | 青龙容器 | `/ql/data/keys/` | `644` | 不要，绑死了具体主机 |

一句话：**青龙拿私钥，路由器只拿公钥。** 反过来是错的 —— 把私钥放到路由器
上，等于把"我是青龙"这个身份交出去，任何拿到它的进程都能冒充青龙。

私钥泄露的后果被 `command=` 限制压到了"能改一个账号的密码"，但压不到零，
所以私钥按密码对待：`600`、不进仓库、不进聊天记录、不贴群里。

## 部署

### 1. 青龙端：生成密钥对（只做一次）

在青龙容器的终端里执行（面板右上角「终端」，或者 `docker exec -it qinglong sh`）：

```sh
mkdir -p /ql/data/keys
chmod 700 /ql/data/keys
ssh-keygen -t ed25519 -N "" -C "ql-tp-rotate" -f /ql/data/keys/tp-ROUTER
chmod 600 /ql/data/keys/tp-ROUTER
ssh-keyscan -t ed25519,rsa ROUTER > /ql/data/keys/known_hosts.tp-ROUTER
cat /ql/data/keys/tp-ROUTER.pub
```

- `-N ""` 是空口令：任务无人值守，必须免密。代价是私钥文件本身就是凭据，
  所以 `600` 不能省。
- 最后一行输出的**整行**就是要贴到路由器上的公钥，从 `ssh-ed25519` 开始到
  `ql-tp-rotate` 结束，复制它。

### 2. 路由器端：装 helper、写公钥

先把 `openwrt/tp-setpw` 放进去：

```sh
scp openwrt/tp-setpw root@ROUTER:/usr/sbin/tp-setpw
ssh root@ROUTER 'chmod 755 /usr/sbin/tp-setpw'
```

备份 `authorized_keys`，**这一步不能省**，写坏了就再也进不去：

```sh
cp -a /etc/dropbear/authorized_keys /etc/dropbear/authorized_keys.bak-$(date +%Y%m%d)
```

然后手工追加公钥。**不要用 `ssh-copy-id`** —— 它只会写一条裸公钥，不会带
`command=` 前缀，那样这把 key 就等同于一个完整的 root shell。

把下面这一行整行单引号包住，`ssh-ed25519` 后面对着换成上一步复制的内容：

```sh
echo 'command="/usr/sbin/tp-setpw",no-pty,no-port-forwarding,no-agent-forwarding,no-x11-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...replace-with-yours ql-tp-rotate' >> /etc/dropbear/authorized_keys
```

几个必须注意的点：

- 整行要用**单引号**包住，因为里面有双引号，用双引号包会被 shell 解释
- `command=` 和公钥在**同一行**，逗号分隔各个选项，选项和 `ssh-ed25519`
  之间是空格
- 行尾不能有多余空格或换行错位
- 文件权限必须是 `600`、属主 `root`，否则 dropbear 直接忽略这个文件

```sh
chmod 600 /etc/dropbear/authorized_keys
chown root:root /etc/dropbear/authorized_keys
```

dropbear **不需要重启**，每次认证都会重读这个文件。

验证追加成功（行数应该比原来多 1）：

```sh
wc -l /etc/dropbear/authorized_keys
tail -n 1 /etc/dropbear/authorized_keys | cut -c1-70
```

再回到青龙容器验证锁定真的生效 —— 期望返回 `ERR empty-password`，
而不是 `/etc/shadow` 的内容：

```sh
ssh -T -i /ql/data/keys/tp-ROUTER \
    -o UserKnownHostsFile=/ql/data/keys/known_hosts.tp-ROUTER \
    -o StrictHostKeyChecking=yes -o BatchMode=yes -o IdentitiesOnly=yes \
    root@ROUTER 'cat /etc/shadow' </dev/null
```

如果报 `Permission denied (publickey)`，多半是某个 option 拼错导致 dropbear
整行丢弃。排查办法：临时把 `command=` 和所有 `no-*` 全去掉，只留裸公钥
`ssh-ed25519 AAAA...` 试一次，能连说明是 option 的问题，逐个加回来定位。

前提：路由器上 tinyproxy 的 `BasicAuth` 至少有一条 `root ...` 和一条
`user ...`，且 `root` 在第一条 —— 状态页依赖这个顺序。


### 3. 青龙端：代码从仓库拉，不手工拷

青龙面板 → 订阅管理 → 新建订阅：

| 字段 | 值 |
|---|---|
| 名称 | `tp-rotate` |
| 链接 | `https://github.com/GitKWorker/tinyproxy-pwdeditor.git` |
| 分支 | `main` |
| 白名单 | 留空 |
| 黑名单 | 留空 |
| 依赖文件 | 留空 |
| 定时规则 | 留空（只手动拉取，不自动同步） |

保存后点「运行」，代码落到 `/ql/data/scripts/GitKWorker_tinyproxy-pwdeditor_main/`。

注意目录名末尾那个 `_main` 是**分支名后缀**：青龙在订阅里指定了分支时，
落地目录会拼成 `<owner>_<repo>_<branch>`。不是 `-main`，也不省略，填路径时
容易少一段。拉完 `ls /ql/data/scripts/ | grep tinyproxy` 对一下再继续。

**不要手工把脚本拷进容器。** 手工副本和仓库会分叉，下次拉取是覆盖
还是并存取决于青龙版本，迟早会跑到一份过期代码上。

### 4. 配置：一个环境变量

青龙面板 → 环境变量 → 只加 `TINYPROXY_PWDEDITOR` 这一条。路由器参数、
私钥路径、主机公钥、企业微信 webhook key 全在里面，不用配置文件。

#### TINYPROXY_PWDEDITOR（必填）

一行写完全部参数：

```
wecom=693a91f6-xxxx-xxxx-xxxx-xxxxxxxxxxxx|label=router-a,host=10.0.0.1,port=22,user=root,account=user,key=/ql/data/keys/tp-router-a,hostkey=ssh-ed25519:AAAAC3NzaC1lZDI1NTE5AAAA...
```

第一段 `wecom=...` 是**全局设置**，不属于任何一台路由器，所以单独用 `|`
隔开放在最前面。放最后、或者直接塞进某个目标分片里也一样生效。

| 字段 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `host` | **是** | — | 路由器地址 |
| `key` | **是** | — | 私钥路径。私钥**只能**是文件，不能内联 |
| `label` | 否 | 取 `host` | 显示名。不给 `hostkey`/`known_hosts` 时也用它拼文件名 |
| `port` | 否 | `22` | SSH 端口 |
| `proxy_port` | 否 | `38888` | tinyproxy 监听端口，只影响群消息里的 `地址` 那一行 |
| `user` | 否 | `root` | SSH 登录用户 |
| `account` | 否 | `user` | 要改密码的 tinyproxy 账号，**只能是 `user`**，helper 硬拒绝 `root` |
| `hostkey` | 二选一 | — | 内联主机公钥，格式 `ssh-ed25519:AAAAC3...` |
| `known_hosts` | 二选一 | — | 现成的 known_hosts 文件路径 |
| `wecom` | 否 | — | 企业微信群机器人 key，**全局字段**，不属于某台路由器。不给就只轮换不推送 |

**`hostkey` 怎么来（推荐，省掉一个文件）**

在青龙容器里跑：

```sh
ssh-keyscan -t ed25519 10.0.0.1 2>/dev/null | awk '/ssh-ed25519/{print "ssh-ed25519:"$3; exit}'
```

输出就是 `ssh-ed25519:AAAAC3...`，整串粘到 `hostkey=` 后面。

那个**冒号不是笔误**。标准 known_hosts 一行是三列 `host keytype base64`，
这里 `host` 已经单独给了，只剩后两列；用空格连接会在这条环境变量里断词，
所以改用冒号。脚本收到后会重新拼成合法的一行写进临时文件，用完立刻删掉。

**三种主机公钥校验方式的优先级**：

```
hostkey=内联公钥   >   known_hosts=文件路径   >   私钥同目录的 known_hosts.<label>
```

都不给就走第三个。文件不存在时 ssh 直接失败，不会退化到"信任所有"——
这是故意的，宁可报错也不要静默降低安全性。

**多台路由器 + 全局企微 key** 用 `|` 隔开：

```
wecom=693a91f6-xxxx-xxxx-xxxx-xxxxxxxxxxxx|label=a,host=10.0.0.1,key=/ql/data/keys/tp-a,hostkey=ssh-ed25519:AAAA...|label=b,host=10.0.0.2,port=2222,key=/ql/data/keys/tp-b,hostkey=ssh-ed25519:BBBB...
```

**这条值的写法限制**（很重要，踩了会静默断掉）：

- 不要有空格。`key = /a` 这种带空格的写法不行
- 不要有单引号、双引号
- 不要有 `$` 和反引号
- 字段之间用 `,`，字段内部 `=` 只用于分隔键和值

密码本身不进这个变量，它只在运行时生成、经 SSH stdin 传给路由器。

#### 全局字段 `wecom`

`wecom` 不属于任何一台路由器，是所有目标共用的一条推送通道。两种写法等价：

```
# 单独一个分片（推荐，读起来清楚）
wecom=KEY|label=a,host=10.0.0.1,key=/k1

# 塞在某个目标分片里（会被提出来，仍然作用于全体）
label=a,host=10.0.0.1,key=/k1,wecom=KEY
```

只写 `wecom=` 而没有任何目标时，脚本报 `no target configured` 退出 2，
不会静默地什么都不做。

**值可以整段粘 URL**，脚本会自动截出 `key=` 后面那截：

```
wecom=https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=693a91f6-xxxx-...
```

企业微信后台的 key 形如 `693a91f6-7bcd-4f2a-9c31-0ec2sifa5aaa`，
只含字母、数字和 `-`，不带空格逗号竖线，正好满足上面的写法限制。

**优先级**：`TINYPROXY_PWDEDITOR` 里的 `wecom` > 环境变量
`WECOM_WEBHOOK_KEY`。后者是给老部署留的兜底，两边都设时以配置里为准。
`--dry-run` 会打印来源，便于确认到底读到了哪个。

#### 老方式：单独设 WECOM_WEBHOOK_KEY（可选，已不推荐）

如果不想把 key 和路由器参数放一起，仍然可以只设环境变量
`WECOM_WEBHOOK_KEY`，脚本会拿它当兜底。没设就只轮换不推送。

#### 验证配置对不对

建任务之前先空跑一次，配置错误会在这时候暴露，不会真的改密码：

```sh
python3 /ql/data/scripts/GitKWorker_tinyproxy-pwdeditor_main/tp_rotate.py --dry-run
```

正常输出（`kh=inline hostkey` 说明走的是内联公钥，第二行说明企微 key 读到了
以及从哪读的）：

```
[DRY_RUN] router-a -> root@10.0.0.1:22 account=user key=/ql/data/keys/tp-router-a kh=inline hostkey
[DRY_RUN] wecom key set (36 chars, from TINYPROXY_PWDEDITOR)
DRY_RUN, nothing pushed
```

没配 key 时对应那行是 `wecom key not set, push would be skipped`。

配置有问题的典型报错：

| 输出 | 原因 |
|---|---|
| `malformed: missing required field: host` | 没写 `host` |
| `malformed: missing required field: key` | 没写私钥路径 |
| `malformed: unknown field 'xxx'` | 字段名拼错，会列出所有可用字段 |
| `hostkey must be 'ssh-ed25519:AAAAC3...'` | 用了空格分隔，或者冒号后面是空的 |
| `Permission denied (publickey)` | 公钥没写进路由器的 `authorized_keys`，或权限不是 600 |
| `Host key verification failed` | `hostkey` 填的和路由器实际的不一致（换过固件/恢复过出厂） |
| `no target configured` | 只写了 `wecom=` 之类的全局字段，没有任何带 `host`+`key` 的目标 |

> 旧版本用 `/ql/data/config/tp-rotate.json` 存配置的方式仍然兼容，
> 没设 `TINYPROXY_PWDEDITOR` 时会回退去读它；那个 JSON 里也支持顶层加
> `"wecom": "..."`。新装直接用环境变量就行。

### 5. 建任务

青龙面板 → 定时任务 → 新建：

| 项 | 值 |
|---|---|
| 名称 | tinyproxy 密码轮换 |
| 命令 | `python3 /ql/data/scripts/GitKWorker_tinyproxy-pwdeditor_main/tp_rotate.py` |
| 定时规则 | 留空（只手动触发，不要填 cron） |

从订阅拉取时青龙会自动建一条任务，名字和命令都已经对上，一般不用重建；
但**自动建的定时规则会带上一个默认 cron**（形如 `30 20 10 * * *`），
必须手动清空，否则它每天自己跑一次、每天换一个密码。

命令里的目录名以实际落地的为准，`ls /ql/data/scripts/ | grep tinyproxy` 确认。

保存后点「运行」即可。要空跑看效果，命令后面加 `--dry-run`。



## 输出

```
[OK] router-a  user / Kx7mPq3T
[WECOM] ok
```

群消息：

```
【tinyproxy 密码轮换】
时间：2026-11-14 19:45

设备：router-a
地址：10.0.0.1:38888
账号：user
密码：Kx7mPq3T
```

一台路由器一块，块与块之间空一行。**设备名、地址（IP + tinyproxy 端口）、
账号、新密码四样齐全** —— 群消息是给人照着填客户端用的，不该再让人回头翻
配置文件对 IP。端口取 `proxy_port`，默认 `38888`。

失败的目标也占一块，`密码` 那行变成 `密码：未变更（<原因>）`，脚本退出码非 0。
这样群里能一眼看出哪台没换成，而不是整条消息只有一句笼统的报错。

`--dry-run` 不发消息，但会打印 `--- message preview ---` 让你先看排版：

```
--- message preview ---
【tinyproxy 密码轮换】（DRY_RUN 预演，未改动）
时间：2026-11-14 19:45

设备：router-a
地址：10.0.0.1:38888
账号：user
密码：Ab3dEf6h（预演，未下发）
--- end preview ---
```

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

## 配套的客户端包

密码轮换的目的是让客户端始终连得上，真正拿去用的客户端在 Releases 里，
不塞进仓库正文（两个包加起来快 40 MB，进 git 历史没有意义）：

| 平台 | 文件 | 内容 |
|---|---|---|
| Windows | `cloudflare-tunnel-proxy-surfing-windows.zip` | `开代理.bat` / `关代理.bat` / `检测.bat` + `cloudflared.exe` |
| Linux | `cloudflare-tunnel-proxy-surfing-linux.tar.gz` | `start.sh` / `stop.sh` / `check.sh` + `cloudflared` |

```
https://github.com/GitKWorker/tinyproxy-pwdeditor/releases/latest
```

用法：解压 → 首次运行填 Cloudflare 隧道域名（写进 `config.txt` 的 `HOSTNAME`）
→ 系统代理指向 `127.0.0.1:18888` → 浏览器弹认证框时填群消息里的 `账号` 和 `密码`。

**包里不含任何凭据**，所以可以公开分发：`config.txt` 只有 `HOSTNAME` 和
`LOCAL_PORT` 两项，账号密码由人在浏览器认证框里当场输入，不写盘、不进配置。
密码每次轮换后，重新看一眼群消息即可。

## 约定

这个仓库里不出现任何真实凭据、主机地址、域名、webhook key。所有环境相关
的东西都在 `/ql/data` 下的配置文件和环境变量里。
