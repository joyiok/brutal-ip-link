# brutal-ip-link

通过访问一个秘密 HTTPS 链接，把访问者当前的公网 IP 自动加入
[TCP Brutal v2](https://github.com/HyNetworks/tcp-brutal) 规则。适合客户端公网 IP
经常变化、但只需要维护一个使用者的服务器。

访问成功时，程序会：

1. 执行 `brutalctl add <当前IP>/32 <速率>`；
2. 删除上一次记录的 IP 规则；
3. 将当前 IP 保存到 `/var/lib/brutal-ip-link/current-prefix`。

只使用 Python 标准库，不信任可伪造的 `X-Forwarded-For`，也不会把秘密 URL
写入日志。

## 要求

- Linux 5.10+；
- 已安装并加载 TCP Brutal v2；
- `/usr/local/bin/brutalctl` 可用；
- Python 3、systemd 和 OpenSSL。

## 安装

```bash
sudo install -m 755 brutal-ip-link.py /usr/local/sbin/brutal-ip-link
sudo install -m 644 brutal-ip-link.service /etc/systemd/system/
sudo install -d -m 700 /etc/brutal-ip-link

# 生成至少 32 字符的秘密 token，保存输出
openssl rand -hex 24

sudo editor /etc/brutal-ip-link/env
```

写入以下配置，把占位符替换为刚生成的 token：

```ini
BRUTAL_LINK_TOKEN=YOUR_RANDOM_TOKEN
BRUTAL_LINK_RATE=100
```

保护配置并生成自签名证书；将 `SERVER_IP` 换成服务器公网 IPv4：

```bash
sudo chmod 600 /etc/brutal-ip-link/env
SERVER_IP=203.0.113.10
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout /etc/brutal-ip-link/key.pem \
  -out /etc/brutal-ip-link/cert.pem \
  -subj "/CN=$SERVER_IP" \
  -addext "subjectAltName=IP:$SERVER_IP"
sudo chmod 600 /etc/brutal-ip-link/key.pem

sudo systemctl daemon-reload
sudo systemctl enable --now brutal-ip-link
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
```

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
