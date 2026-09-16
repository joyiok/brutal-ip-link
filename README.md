# brutal-ip-link

从 Xray 认证日志识别客户端公网 IP，自动加入
[TCP Brutal v2](https://github.com/HyNetworks/tcp-brutal) 规则。秘密 HTTPS 链接作为
手动兜底。适合客户端公网 IP 经常变化的服务器，最多保留最近识别的 5 个 IP。

识别到新 IP 时，程序会：

1. 先将待更新 IP 原子保存到 `/var/lib/brutal-ip-link/pending-prefix`；
2. 执行 `brutalctl add <当前IP>/32 <速率>`，使用策略表时带 `noroute`；
3. 将 Brutal 路由写入对应策略表，超过 5 个时删除最久未识别的 IP 规则和路由；
4. 将 IP 列表原子保存到 `current-prefix` 并清除待处理记录。失败时回滚或保留记录重试。

程序只接受同一条 Xray 认证成功日志中的公网来源 IP 和非空 `email:`，不关联
不同连接的日志。未认证接入和本机来源日志不会触发更新。只使用 Python 标准库，
不信任 `X-Forwarded-For`，也不会把秘密 URL 写入日志。

## 要求

- Linux 5.10+；
- 已安装并加载 TCP Brutal v2，`brutalctl` 支持 `noroute`；
- `/usr/local/bin/brutalctl` 可用；
- Python 3（已验证 3.12 / 3.13）、systemd、iproute2 和 OpenSSL。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/joyiok/brutal-ip-link/main/install.sh | sudo bash
```

脚本会自动生成 token、自签名 HTTPS 证书和 systemd 服务，检测源地址策略路由表；
存在 `xray.service` 时自动启用日志监听，最后输出备用专属链接。重复执行保留
已有 token，以及显式清空的监听和策略表配置。脚本不会修改 Xray 配置。

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
当前 IP 记录也会保留；旧版的单行记录会自动兼容。克隆安装的用户先执行
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

`SERVER_IP` 仅用于安装时指定服务器公网 IPv4 和证书地址，不是服务运行配置。
HTTPS 备用入口固定监听 IPv4 的 `8443` 端口。自动识别支持公网 IPv4 和 IPv6；
使用策略表处理 IPv6 时，该表也必须有 IPv6 默认路由。

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
最多 5 个不同 IP，第 6 个新 IP 会替换最久未识别的一个。首次识别新 IP 的那条连接已经建立，
不受新规则影响。

程序每 30 秒核对已记录的规则和路由，重试未完成操作。HTTPS 握手和请求读写超时
为 5 秒，最多同时处理 32 个连接。

自动识别失败时可打开备用链接；首次打开时浏览器会提示自签名证书不受信任：

```text
https://SERVER_IP:8443/YOUR_RANDOM_TOKEN
```

成功响应示例：

```text
TCP Brutal enabled for 198.51.100.20/32 at 100 Mbps
```

该规则只影响访问链接后建立的新 TCP 连接。不要分享秘密链接。

## 检查与排错

```bash
sudo systemctl status brutal-ip-link
sudo journalctl -u brutal-ip-link -n 50
sudo brutalctl list
ip route show table 10001 proto 233
```

自动更新成功时，服务日志包含：

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

先停止服务。若需清理规则，删除文件前记录 `current-prefix` 和可能存在的
`pending-prefix`，逐一执行 `sudo brutalctl del <前缀>`；设置了策略表时还需执行
`sudo ip -4 route del <前缀> table <表号> proto 233`（IPv6 使用 `-6`）。
`brutalctl` 不会清理本程序额外写入的策略表路由。

```bash
sudo systemctl disable --now brutal-ip-link
sudo rm /etc/systemd/system/brutal-ip-link.service
sudo rm /usr/local/sbin/brutal-ip-link
sudo rm -r /etc/brutal-ip-link /var/lib/brutal-ip-link
sudo systemctl daemon-reload
```

以上文件卸载命令不会卸载 TCP Brutal，也不会自动删除规则。

## 测试

```bash
python3 brutal-ip-link.py --self-test
python3 test_brutal_ip_link.py --tls
bash -n install.sh
```

回归测试使用临时文件和模拟内核状态；TLS 测试只监听本机随机端口，不修改系统路由。
覆盖日志交错、用户过滤、伪造转发头、重复更新、删除失败、更新中断、规则恢复及连接超时。

另已在 Python 3.13、Xray 26.3.27 和 TCP Brutal v2 的实机环境验证 REALITY / PROXY protocol
转发链路、同一 IP 重复更新，以及公网 IP 实际变化后的自动切换和旧规则清理。
