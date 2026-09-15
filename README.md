# brutal-ip-link

通过访问一个秘密 HTTPS 链接，把访问者当前的公网 IP 自动加入
[TCP Brutal v2](https://github.com/HyNetworks/tcp-brutal) 规则。适合客户端公网 IP
经常变化、但只需要维护一个使用者的服务器。

访问成功时，程序会：

1. 执行 `brutalctl add <当前IP>/32 <速率>`；
2. 如果服务器使用策略路由，同时把 Brutal 路由写入对应路由表；
3. 删除上一次记录的 IP 规则；
4. 将当前 IP 保存到 `/var/lib/brutal-ip-link/current-prefix`。

只使用 Python 标准库，不信任可伪造的 `X-Forwarded-For`，也不会把秘密 URL
写入日志。

## 要求

- Linux 5.10+；
- 已安装并加载 TCP Brutal v2；
- `/usr/local/bin/brutalctl` 可用；
- Python 3、systemd 和 OpenSSL。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/joyiok/brutal-ip-link/main/install.sh | sudo bash
```

脚本会自动生成 token、自签名 HTTPS 证书和 systemd 服务，并检测源地址策略路由表，
最后输出专属链接。重复执行不会更换已有 token。

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

## 使用

首次打开时，浏览器会提示自签名证书不受信任，确认服务器地址后继续：

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

使用策略路由时，`brutalctl list` 的 `MEMBERS` 应大于 `0`，`SENT(MB)` 应随新连接
流量增长。规则只影响添加后建立的新连接。

修改 `/etc/brutal-ip-link/env` 后重启服务：

```bash
sudo systemctl restart brutal-ip-link
```

## 卸载

```bash
sudo systemctl disable --now brutal-ip-link
sudo rm /etc/systemd/system/brutal-ip-link.service
sudo rm /usr/local/sbin/brutal-ip-link
sudo rm -r /etc/brutal-ip-link /var/lib/brutal-ip-link
sudo systemctl daemon-reload
```

本项目不会卸载 TCP Brutal，也不会自动删除最后添加的规则；需要时执行
`sudo brutalctl flush`。
