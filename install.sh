#!/usr/bin/env bash
set -euo pipefail

if (( EUID != 0 )); then
  echo "Run as root: sudo bash install.sh" >&2
  exit 1
fi
for command in python3 systemctl ip; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
[[ -x /usr/local/bin/brutalctl ]] || {
  echo "Install TCP Brutal v2 and /usr/local/bin/brutalctl first." >&2
  exit 1
}

script_dir=""
if [[ -n ${BASH_SOURCE[0]:-} ]]; then
  script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fi
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
files=(brutal-ip-link.py brutal-ip-link.service brutal-ip-link-update.service brutal-ip-link-update.timer)
for file in "${files[@]}"; do
  if [[ -n "$script_dir" && -f "$script_dir/$file" ]]; then
    cp "$script_dir/$file" "$tmp_dir/$file"
  else
    command -v curl >/dev/null || { echo "Missing command: curl" >&2; exit 1; }
    curl -fsSL --connect-timeout 10 --max-time 60 \
      "https://raw.githubusercontent.com/joyiok/brutal-ip-link/main/$file" -o "$tmp_dir/$file"
  fi
done
app="$tmp_dir/brutal-ip-link.py"
python3 "$app" --self-test

server_ip=${SERVER_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -1 || true)}
if [[ -z "$server_ip" ]]; then
  server_ip=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -1 || true)
fi
family=-4
destination=1.1.1.1
if [[ "$server_ip" == *:* ]]; then
  family=-6
  destination=2606:4700:4700::1111
fi
detected_table=$(ip "$family" route get "$destination" from "$server_ip" 2>/dev/null | sed -n 's/.* table \([^ ]*\).*/\1/p' | head -1 || true)
detected_xray=$(systemctl cat xray.service >/dev/null 2>&1 && printf xray.service || true)

# Parse data as data: never source an EnvironmentFile as root shell code.
python3 - "$tmp_dir/env" "$detected_table" "$detected_xray" <<'PY'
import os
import secrets
import sys
from pathlib import Path

values = {
    'BRUTAL_LINK_TOKEN': secrets.token_hex(24),
    'BRUTAL_LINK_RATE': '100',
    'BRUTAL_LINK_TABLE': sys.argv[2],
    'BRUTAL_LINK_XRAY_UNIT': sys.argv[3],
    'BRUTAL_LINK_XRAY_EMAIL': '',
    'BRUTAL_LINK_MAX_PREFIXES': '5',
    'BRUTAL_LINK_TTL': '0',
    'BRUTAL_LINK_HTTPS': '1',
    'BRUTAL_LINK_HOST': '0.0.0.0',
    'BRUTAL_LINK_PORT': '8443',
    'BRUTAL_LINK_AUTO_UPDATE': '1',
}
old = Path('/etc/brutal-ip-link/env')
if old.exists():
    for line in old.read_text().splitlines():
        key, _, value = line.partition('=')
        if key in values:
            values[key] = value
for key in values:
    if key in os.environ:
        values[key] = os.environ[key]
Path(sys.argv[1]).write_text(''.join(f'{key}={value}\n' for key, value in values.items()))
PY
python3 "$app" --config "$tmp_dir/env" check-config

declare -A settings
while IFS='=' read -r key value; do settings["$key"]=$value; done < "$tmp_dir/env"
if [[ -n ${settings[BRUTAL_LINK_XRAY_UNIT]} ]]; then
  command -v journalctl >/dev/null || { echo "Missing command: journalctl" >&2; exit 1; }
fi
if [[ ${settings[BRUTAL_LINK_HTTPS]} == 1 ]]; then
  command -v openssl >/dev/null || { echo "Missing command: openssl" >&2; exit 1; }
  python3 -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); assert a.is_global and not a.is_multicast' "$server_ip" || {
    echo "Set SERVER_IP to the public IPv4 or IPv6 address used for the HTTPS link." >&2
    exit 1
  }
  if [[ "$server_ip" == *:* && ${settings[BRUTAL_LINK_HOST]} != *:* ]]; then
    echo "For an IPv6 link, also set BRUTAL_LINK_HOST=:: or a local IPv6 address." >&2
    exit 1
  fi
  cert_ip=$(cat /etc/brutal-ip-link/cert-ip 2>/dev/null || true)
  if [[ ! -f /etc/brutal-ip-link/key.pem || ! -f /etc/brutal-ip-link/cert.pem || "$cert_ip" != "$server_ip" ]] || \
     ! openssl x509 -checkend 86400 -noout -in /etc/brutal-ip-link/cert.pem >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "$tmp_dir/key.pem" -out "$tmp_dir/cert.pem" \
      -subj "/CN=$server_ip" -addext "subjectAltName=IP:$server_ip" >/dev/null 2>&1
  fi
fi

# Stop the old daemon before importing files it doesn't yet know to lock.
was_active=0
if systemctl is-active --quiet brutal-ip-link.service; then
  was_active=1
  systemctl stop brutal-ip-link.service
fi
restart_on_error() {
  if (( was_active )); then systemctl start brutal-ip-link.service || true; fi
}
trap restart_on_error ERR
if [[ -f /etc/brutal-ip-link/env ]]; then
  old_table=$(sed -n 's/^BRUTAL_LINK_TABLE=//p' /etc/brutal-ip-link/env | head -1)
  BRUTAL_LINK_TABLE="$old_table" python3 "$app" --config /etc/brutal-ip-link/env migrate-state
fi

install -d -m 700 /etc/brutal-ip-link /var/lib/brutal-ip-link
install -m 755 "$app" /usr/local/sbin/brutal-ip-link.new
mv /usr/local/sbin/brutal-ip-link.new /usr/local/sbin/brutal-ip-link
for file in "${files[@]:1}"; do
  install -m 644 "$tmp_dir/$file" "/etc/systemd/system/$file"
done
install -m 600 "$tmp_dir/env" /etc/brutal-ip-link/env.new
mv /etc/brutal-ip-link/env.new /etc/brutal-ip-link/env
if [[ -f "$tmp_dir/key.pem" ]]; then
  install -m 600 "$tmp_dir/key.pem" /etc/brutal-ip-link/key.pem
  install -m 644 "$tmp_dir/cert.pem" /etc/brutal-ip-link/cert.pem
  printf '%s\n' "$server_ip" > /etc/brutal-ip-link/cert-ip
fi

systemctl daemon-reload
systemctl enable brutal-ip-link.service >/dev/null
systemctl restart brutal-ip-link.service
systemctl is-active --quiet brutal-ip-link.service
if [[ ${settings[BRUTAL_LINK_AUTO_UPDATE]} == 1 ]]; then
  systemctl enable --now brutal-ip-link-update.timer >/dev/null
else
  systemctl disable --now brutal-ip-link-update.timer >/dev/null
fi
trap - ERR

if [[ ${settings[BRUTAL_LINK_HTTPS]} == 1 ]]; then
  link_host=$server_ip
  [[ "$link_host" != *:* ]] || link_host="[$link_host]"
  echo "Installed: https://$link_host:${settings[BRUTAL_LINK_PORT]}/${settings[BRUTAL_LINK_TOKEN]}"
  echo "The certificate is self-signed; confirm the warning on first visit."
else
  echo "Installed with HTTPS disabled."
fi
echo "Automatic TCP Brutal updates: ${settings[BRUTAL_LINK_AUTO_UPDATE]} (daily, server local time 04:00-05:00)"
echo "Diagnostics: sudo brutal-ip-link doctor"
