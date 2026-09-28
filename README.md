# brutal-ip-link

从 Xray 认证日志识别客户端公网 IP，自动加入
[TCP Brutal v2](https://github.com/HyNetworks/tcp-brutal) 规则。秘密 HTTPS 链接作为
手动兜底。适合客户端公网 IP 经常变化的服务器，默认保留最近识别的 5 个 IP，
支持过期清理、命令行管理、诊断和 TCP Brutal 每日自动更新。

识别到新 IP 时，程序会：

1. 先将 IP、识别时间和路由表原子保存到 `/var/lib/brutal-ip-link/state.json`；
2. 执行 `brutalctl add <IP>/32 <速率>`（IPv6 使用 `/128`），使用策略表时带 `noroute`；
3. 验证规则和路由，成功后按配置上限淘汰最久未识别的 IP；
4. 为每个 IP 独立保留失败和清理进度，每 30 秒重试。一条规则失败不会阻塞其他规则恢复。

新 IP 添加失败并回滚后仍保留重试意图，不会立即淘汰正常地址。待添加队列也按
`BRUTAL_LINK_MAX_PREFIXES` 限制数量；删除失败的条目继续保留，直至清理成功。
修改策略表后，会先建立新表路由，再清理记录中的旧表路由。

程序只接受同一条 Xray 认证成功日志中的公网来源 IP 和非空 `email:`，不关联
不同连接的日志。未认证接入和本机来源日志不会触发更新。只使用 Python 标准库，
不信任 `X-Forwarded-For`，也不会把秘密 URL 写入日志。

## 要求

- Linux 5.10+；
- 已安装并加载 TCP Brutal v2，`brutalctl` 支持 `noroute`；
- `/usr/local/bin/brutalctl` 可用；
- Python 3.12+、systemd、iproute2；启用 HTTPS 时需要 OpenSSL；
- 自动更新需要 kmod（`modinfo` / `modprobe`）和到 GitHub、`tcp.hy2.sh` 的 HTTPS 访问；
  上游安装脚本会检查 DKMS、内核头文件和编译工具。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/joyiok/brutal-ip-link/main/install.sh | sudo bash
```

脚本会自动生成 token、自签名 HTTPS 证书和 systemd 服务，检测源地址策略路由表；
存在 `xray.service` 时自动启用日志监听，最后输出备用专属链接。重复执行保留
已有 token，以及显式清空的监听和策略表配置。脚本不会修改 Xray 配置。
默认启用每日 TCP Brutal 自动更新；未设置此开关的旧版安装升级后也会启用。
仅使用日志识别时，可安装为不开放 HTTPS 端口：

```bash
sudo env BRUTAL_LINK_HTTPS=0 bash install.sh
```

指定发送速率或服务器公网 IPv4：

```bash
curl -fsSL https://raw.githubusercontent.com/joyiok/brutal-ip-link/main/install.sh | \
  sudo env BRUTAL_LINK_RATE=200 SERVER_IP=203.0.113.10 bash
```

如自动检测不正确，可显式指定策略路由表：

```bash
curl -fsSL https://raw.githubusercontent.com/joyiok/brutal-ip-link/main/install.sh | \
  sudo env BRUTAL_LINK_TABLE=10001 bash
```

也可以克隆后运行：

```bash
git clone https://github.com/joyiok/brutal-ip-link.git
cd brutal-ip-link
sudo bash install.sh
```

如果服务器启用了防火墙，还需允许 TCP `8443` 端口。

### 升级已有安装

重新执行上述安装命令即可升级；未显式覆盖的 token、速率、策略表和 Xray 设置会保留，
当前 IP 记录也会保留；旧版 `current-prefix` 和 `pending-prefix` 会自动迁入 `state.json`。
旧文件保留为备份，迁移后以 `state.json` 为准。安装脚本会在替换配置前记录旧策略表，
因此升级时同时修改表号也可以清理旧路由。克隆安装的用户先执行
`git pull --ff-only`，再运行 `sudo bash install.sh`。

旧版本通过两条日志之间的时间间隔推测 IP，新版本已删除该逻辑。使用本机转发的部署，
升级前应按下文配置 PROXY protocol，确认认证日志含真实公网 IP；否则自动识别会跳过
本机来源日志，备用 HTTPS 链接仍可使用。

## 配置

运行配置保存在 `/etc/brutal-ip-link/env`；修改后执行 `sudo systemctl restart brutal-ip-link`。

| 配置项 | 默认或安装行为 | 说明 |
| --- | --- | --- |
| `BRUTAL_LINK_TOKEN` | 首次安装生成，重装保留 | 至少 32 位，仅含字母、数字、`_`、`-` |
| `BRUTAL_LINK_RATE` | `100` | Mbps，整数范围 `1`–`1000000` |
| `BRUTAL_LINK_TABLE` | 检测源地址策略表 | 数字表号；空值表示使用主路由表 |
| `BRUTAL_LINK_XRAY_UNIT` | 检测到时使用 `xray.service` | 监听的 systemd 单元；空值关闭自动识别 |
| `BRUTAL_LINK_XRAY_EMAIL` | 空 | 非空时仅接受该用户的认证日志，值须与 Xray 中的 email 完全一致 |
| `BRUTAL_LINK_MAX_PREFIXES` | `5` | 同时保留的 IP 数，范围 `1`–`1000` |
| `BRUTAL_LINK_TTL` | `0` | 距离最后一次识别的过期秒数；`0` 关闭，最大 `31536000`（365 天） |
| `BRUTAL_LINK_HTTPS` | `1` | `0` 关闭备用 HTTPS 入口，无需证书或服务器公网地址 |
| `BRUTAL_LINK_HOST` | `0.0.0.0` | 监听 IP；设为 `::` 可在 Linux 上同时接收 IPv4 和 IPv6 |
| `BRUTAL_LINK_PORT` | `8443` | HTTPS 端口，范围 `1`–`65535` |
| `BRUTAL_LINK_AUTO_UPDATE` | `1` | `0` 跳过定时更新；手动 `update-brutal` 仍可用 |

配置使用不带引号的 `KEY=value`，命令行也会自动读取此文件；同名进程环境变量优先。
`SERVER_IP` 仅用于安装时指定服务器公网 IPv4 / IPv6 和证书地址。自动识别支持
公网 IPv4 和 IPv6；使用策略表处理 IPv6 时，该表也必须有 IPv6 默认路由。

例如保留 10 个 IP，24 小时未识别则清理：

```ini
BRUTAL_LINK_MAX_PREFIXES=10
BRUTAL_LINK_TTL=86400
```

IPv6 备用入口可这样安装（替换成服务器实际公网 IPv6）：

```bash
sudo env BRUTAL_LINK_HOST=:: SERVER_IP=YOUR_PUBLIC_IPV6 bash install.sh
```

输出的 IPv6 链接形如 `https://[IPv6地址]:8443/TOKEN`。

## 使用

### Xray 自动识别的前提

认证成功的访问日志必须输出到 journal，包含真实公网来源和非空用户 email，例如：

```text
from 8.8.8.8:12345 accepted tcp:example.com:443 [auth -> direct] email: owner
```

可在 `/etc/brutal-ip-link/env` 设置 `BRUTAL_LINK_XRAY_EMAIL=owner`，只接受该用户；
未设置时接受任意非空 email，适用于只有一个用户的 Xray。将
`BRUTAL_LINK_XRAY_UNIT=` 设为空可关闭自动识别。

如果公网入口经 dokodemo-door 转发到本机 VLESS/REALITY，必须保留真实来源：

- 为这条本机转发路径使用专用 freedom 出站，设置 `settings.proxyProtocol: 1`；
- 路由规则按公网入口的准确 `inboundTag` 选择该出站；不要给普通互联网出站添加该设置；
- 本机认证入口保持监听 `127.0.0.1`，设置 `streamSettings.sockopt.acceptProxyProtocol: true`。

例如，将下面的专用出站追加到现有 `outbounds`，将对应路由放在现有 `routing.rules`
中会匹配此入口的其他规则之前。入口 tag 和本机端口须按实际配置调整；保留原有默认出站顺序。
这只是配置片段，需合并到已有配置中：

```json
{
  "outbounds": [
    {
      "tag": "brutal-proxy-forward",
      "protocol": "freedom",
      "settings": {
        "proxyProtocol": 1,
        "redirect": "127.0.0.1:45987"
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["dokodemo-in-VLESSReality"],
        "outboundTag": "brutal-proxy-forward"
      }
    ]
  }
}
```

PROXY protocol 接收端必须只对可信转发端开放，不能直接暴露公网。使用多个配置文件时，
后续文件的 `routing` 会覆盖前面的配置；使用 `xray run -dump -confdir <目录>` 核对合并结果
（输出含凭据，请勿公开）。修改后先运行 `xray run -test -confdir <目录>` 验证。
若认证日志仍显示 `127.0.0.1`，程序会跳过该日志，请使用备用链接或修正转发配置。

### 生效与恢复

正常使用无需访问链接：Xray 用户认证后，后续新连接会自动使用 Brutal。程序同时保留
默认最多 5 个不同 IP，第 6 个新 IP 成功添加后会替换最久未识别的一个。首次识别新 IP 的那条连接已经建立，
不受新规则影响。

程序每 30 秒核对规则、重试操作和清理过期 IP。已知 IP 使用 5 秒检查缓存，最近识别时间
和日志游标最多每 30 秒合并保存；突然掉电可能损失这一小段时间的最近使用顺序，
新 IP 和增删操作会立即持久化。重启后从保存的 journal 游标继续；游标不可用时回看最近
5 分钟，TTL 按日志实际时间计算，已过期的旧日志不会重新激活 IP。

HTTPS 握手和请求读写超时为 5 秒，最多同时处理 32 个连接。升级期间若无法在
5 秒内取得更新锁，备用入口返回 `503`，稍后重试即可。

自动识别失败时可打开备用链接；首次打开时浏览器会提示自签名证书不受信任：

```text
https://SERVER_IP:8443/YOUR_RANDOM_TOKEN
```

成功响应示例：

```text
TCP Brutal enabled for 198.51.100.20/32 at 100 Mbps
```

该规则只影响访问链接后建立的新 TCP 连接。不要分享秘密链接。

## 命令行管理

```bash
sudo brutal-ip-link status           # IP、路由表、最近识别时间、内核版本、更新结果
sudo brutal-ip-link list             # 仅列出 IP
sudo brutal-ip-link doctor           # 检查模块、规则、服务、日志识别和证书
sudo brutal-ip-link status --json     # status / list / doctor 均支持 JSON
sudo brutal-ip-link add 8.8.8.8       # 也接受 IPv6 或 /32、/128 主机前缀
sudo brutal-ip-link remove 8.8.8.8
sudo brutal-ip-link clear            # 清理本工具记录的所有 IP 和路由
sudo brutal-ip-link reconcile        # 立即重试规则恢复和清理
sudo brutal-ip-link check-config
```

`doctor` 全部检查通过返回 `0`，发现问题返回 `1`；安装后尚无匹配日志时会提示检查来源 IP
和 email。诊断不输出 token。`remove` / `clear` 删除当前记录，之后新的认证日志仍可重新加入。
清理失败时保留记录并返回错误，避免遗失未清理的路由。

## TCP Brutal 自动更新

安装后，`brutal-ip-link-update.timer` 每天按**服务器本地时间 04:00–05:00** 随机检查一次。
关机错过的检查在下次启动后补做。程序查询 GitHub 的最新正式发布；当前仅自动接受 v2
正式版本，不安装预览版本，也不自动跨大版本升级。已安装最新版本时跳过编译。

发现更新时，下载[上游官方安装脚本](https://github.com/HyNetworks/tcp-brutal/blob/master/scripts/install_dkms.sh)，
指定版本执行升级，随后立即恢复本工具管理的规则。更新与 IP 修改共用进程锁，
状态查询仍然可用。如果内核中存在本工具没有记录的 Brutal 规则，会跳过自动安装并记录错误，
由管理员手动升级，避免模块重载后丢失其他规则。

上游尝试重载模块时，正在使用 Brutal 的连接可能使卸载失败。此时显示
`reboot_required`，表示新版本已安装、当前仍运行旧版本；本工具不会主动重启服务器或停止 Xray。
升级失败会记录错误并尝试恢复规则，详情保存在 `update.json` 和 systemd 日志中。

```bash
sudo brutal-ip-link update-brutal                 # 立即手动检查并升级
systemctl list-timers brutal-ip-link-update.timer
sudo journalctl -u brutal-ip-link-update.service -n 100
sudo brutal-ip-link status
```

关闭自动更新：在配置文件中设置 `BRUTAL_LINK_AUTO_UPDATE=0`，并执行：

```bash
sudo systemctl disable --now brutal-ip-link-update.timer
sudo systemctl restart brutal-ip-link
```

重新启用时将开关改为 `1`，执行 `sudo systemctl enable --now brutal-ip-link-update.timer`，
并重启主服务。自定义更新时间可通过 `sudo systemctl edit brutal-ip-link-update.timer`：

```ini
[Timer]
OnCalendar=
OnCalendar=*-*-* 05:00:00
RandomizedDelaySec=15min
```

保存后执行 `sudo systemctl daemon-reload` 和 `sudo systemctl restart brutal-ip-link-update.timer`。
brutal-ip-link 自身的升级仍通过重新运行安装脚本完成。

## 检查与排错

```bash
sudo systemctl status brutal-ip-link
sudo journalctl -u brutal-ip-link -n 50
sudo brutalctl list
ip route show table 10001 proto 233
```

自动识别 IP 并成功更新规则时，服务日志包含：

```text
Xray authenticated; updated 198.51.100.20/32
```

使用策略路由时，`brutalctl list` 的 `MEMBERS` 应大于 `0`，`SENT(MB)` 应随新连接
流量增长。规则只影响添加后建立的新连接。

使用 `noroute` 后，`brutalctl list` 的 `ROUTE` 可能显示 `no`：它只检查主路由表。
此时应结合 `ip route show table 10001 proto 233` 和实际连接、流量计数判断是否生效。

修改 `/etc/brutal-ip-link/env` 后重启服务：

```bash
sudo systemctl restart brutal-ip-link
```

## 卸载

```bash
sudo brutal-ip-link uninstall
```

此命令先停止自动更新和主服务，再清理记录中的规则、主表及新旧策略表中的 `proto 233`
路由，最后删除本工具的配置、状态和 systemd 单元。清理失败会保留文件并退出，修复错误后
可以重新执行。TCP Brutal 内核模块和未由本工具管理的其他前缀规则会保留。

## 测试

```bash
python3 brutal-ip-link.py --self-test
python3 test_brutal_ip_link.py --tls
bash -n install.sh
```

回归测试使用临时文件和模拟内核状态；TLS 测试只监听本机随机端口，不修改系统路由。
覆盖日志交错、用户过滤、伪造转发头、独立重试、回滚、原子写入失败、旧状态迁移、
策略表迁移、TTL、重复日志缓存、CLI、安装脚本流程、更新失败恢复、进程锁、卸载清理，
以及 IPv4 / IPv6 TLS 和连接超时。安装脚本测试使用临时目录和模拟系统命令；
自动更新测试模拟下载与编译，不会实际安装或卸载内核模块。

本次新增功能在 Python 3.14 上执行回归测试；真实 DKMS 升级仍需在目标服务器验证。
原有版本曾在 Python 3.13、Xray 26.3.27 和 TCP Brutal v2 环境验证 REALITY / PROXY protocol
转发链路、同一 IP 重复更新，以及公网 IP 变化后的自动切换和旧规则清理。
