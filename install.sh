#!/usr/bin/env bash
set -euo pipefail

if (( EUID != 0 )); then
  echo "Run as root: sudo bash install.sh" >&2
  exit 1
fi

for command in python3 openssl systemctl ip; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
[[ -x /usr/local/bin/brutalctl ]] || {
  echo "Install TCP Brutal v2 and /usr/local/bin/brutalctl first." >&2
  exit 1
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

if [[ -f "$script_dir/brutal-ip-link.py" && -f "$script_dir/brutal-ip-link.service" ]]; then
  app="$script_dir/brutal-ip-link.py"
  unit="$script_dir/brutal-ip-link.service"
else
  command -v curl >/dev/null || { echo "Missing command: curl" >&2; exit 1; }
  base=https://raw.githubusercontent.com/joyiok/brutal-ip-link/main
  curl -fsSL "$base/brutal-ip-link.py" -o "$tmp_dir/brutal-ip-link.py"
  curl -fsSL "$base/brutal-ip-link.service" -o "$tmp_dir/brutal-ip-link.service"
  app="$tmp_dir/brutal-ip-link.py"
  unit="$tmp_dir/brutal-ip-link.service"
fi

python3 "$app" --self-test

server_ip=${SERVER_IP:-$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -1)}
python3 -c 'import ipaddress, sys; a = ipaddress.ip_address(sys.argv[1]); assert a.version == 4 and a.is_global' "$server_ip" 2>/dev/null || {
  echo "Could not detect a public IPv4 address; rerun with SERVER_IP=x.x.x.x" >&2
  exit 1
}

install -d -m 700 /etc/brutal-ip-link
old_token=$(sed -n 's/^BRUTAL_LINK_TOKEN=//p' /etc/brutal-ip-link/env 2>/dev/null | head -1 || true)
old_rate=$(sed -n 's/^BRUTAL_LINK_RATE=//p' /etc/brutal-ip-link/env 2>/dev/null | head -1 || true)
old_table=$(sed -n 's/^BRUTAL_LINK_TABLE=//p' /etc/brutal-ip-link/env 2>/dev/null | head -1 || true)
old_xray=$(sed -n 's/^BRUTAL_LINK_XRAY_UNIT=//p' /etc/brutal-ip-link/env 2>/dev/null | head -1 || true)
detected_table=$(ip -4 route get 1.1.1.1 from "$server_ip" 2>/dev/null | sed -n 's/.* table \([^ ]*\).*/\1/p' | head -1 || true)
detected_xray=$(systemctl cat xray.service >/dev/null 2>&1 && printf xray.service || true)
token=${BRUTAL_LINK_TOKEN:-${old_token:-$(openssl rand -hex 24)}}
rate=${BRUTAL_LINK_RATE:-${old_rate:-100}}
table=${BRUTAL_LINK_TABLE-${old_table:-$detected_table}}
xray=${BRUTAL_LINK_XRAY_UNIT-${old_xray:-$detected_xray}}

[[ ${#token} -ge 32 && "$token" != *[!A-Za-z0-9_-]* ]] || {
  echo "BRUTAL_LINK_TOKEN must be at least 32 URL-safe characters." >&2
  exit 1
}
[[ "$rate" =~ ^[0-9]+$ ]] && (( rate >= 1 && rate <= 1000000 )) || {
  echo "BRUTAL_LINK_RATE must be an integer from 1 to 1000000." >&2
  exit 1
}
[[ -z "$table" || "$table" =~ ^[0-9]+$ ]] || {
  echo "BRUTAL_LINK_TABLE must be a numeric policy routing table." >&2
  exit 1
}
[[ -z "$xray" || "$xray" =~ ^[A-Za-z0-9_.@-]+$ ]] || {
  echo "BRUTAL_LINK_XRAY_UNIT is invalid." >&2
  exit 1
}

install -m 755 "$app" /usr/local/sbin/brutal-ip-link
install -m 644 "$unit" /etc/systemd/system/brutal-ip-link.service
printf 'BRUTAL_LINK_TOKEN=%s\nBRUTAL_LINK_RATE=%s\nBRUTAL_LINK_TABLE=%s\nBRUTAL_LINK_XRAY_UNIT=%s\n' \
  "$token" "$rate" "$table" "$xray" \
  > /etc/brutal-ip-link/env
chmod 600 /etc/brutal-ip-link/env

cert_ip=$(cat /etc/brutal-ip-link/cert-ip 2>/dev/null || true)
if [[ ! -f /etc/brutal-ip-link/key.pem || ! -f /etc/brutal-ip-link/cert.pem || "$cert_ip" != "$server_ip" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$tmp_dir/key.pem" \
    -out "$tmp_dir/cert.pem" \
    -subj "/CN=$server_ip" \
    -addext "subjectAltName=IP:$server_ip" >/dev/null 2>&1
  install -m 600 "$tmp_dir/key.pem" /etc/brutal-ip-link/key.pem
  install -m 644 "$tmp_dir/cert.pem" /etc/brutal-ip-link/cert.pem
  printf '%s\n' "$server_ip" > /etc/brutal-ip-link/cert-ip
fi

systemctl daemon-reload
systemctl enable brutal-ip-link.service >/dev/null
systemctl restart brutal-ip-link.service
systemctl is-active --quiet brutal-ip-link.service

echo
echo "Installed: https://$server_ip:8443/$token"
[[ -z "$table" ]] || echo "Policy routing table: $table"
[[ -z "$xray" ]] || echo "Automatic Xray detection: $xray"
echo "The certificate is self-signed; confirm the warning on first visit."
