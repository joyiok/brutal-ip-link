#!/usr/bin/env python3
import hmac
import ipaddress
import os
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

TOKEN = os.environ.get("BRUTAL_LINK_TOKEN", "")
RATE = int(os.environ.get("BRUTAL_LINK_RATE", "100"))
TABLE = os.environ.get("BRUTAL_LINK_TABLE", "")
STATE = Path("/var/lib/brutal-ip-link/current-prefix")
CTL = "/usr/local/bin/brutalctl"


def prefix_for(value):
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise ValueError("request did not come from a public IP")
    return f"{address}/{32 if address.version == 4 else 128}"


def policy_route_args(prefix, default):
    words = default.split()
    args = ["ip", "-6" if ":" in prefix else "-4", "route", "replace", prefix]
    for field in ("via", "dev"):
        if field in words:
            args += [field, words[words.index(field) + 1]]
    if "dev" not in words:
        raise ValueError(f"no device in table {TABLE} default route")
    return args + ["table", TABLE, "congctl", "lock", "brutal", "proto", "233"]


def policy_route(prefix, delete=False):
    if not TABLE:
        return
    family = "-6" if ":" in prefix else "-4"
    if delete:
        subprocess.run(
            ["ip", family, "route", "del", prefix, "table", TABLE, "proto", "233"],
            timeout=10,
        )
        return
    default = subprocess.run(
        ["ip", family, "route", "show", "table", TABLE, "default"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.splitlines()
    if not default:
        raise ValueError(f"no default route in table {TABLE}")
    subprocess.run(policy_route_args(prefix, default[0]), check=True, timeout=10)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not TOKEN or not hmac.compare_digest(self.path, "/" + TOKEN):
            self.send_error(404)
            return

        try:
            prefix = prefix_for(self.client_address[0])
            old = STATE.read_text().strip() if STATE.exists() else ""
            subprocess.run([CTL, "add", prefix, str(RATE)], check=True, timeout=10)
            policy_route(prefix)
            if old and old != prefix:
                subprocess.run([CTL, "del", old], timeout=10)
                policy_route(old, delete=True)
            STATE.write_text(prefix + "\n")
        except Exception as error:
            print(f"update failed: {error}", file=sys.stderr, flush=True)
            self.send_error(500, "failed to update TCP Brutal rule")
            return

        body = f"TCP Brutal enabled for {prefix} at {RATE} Mbps\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass  # Do not put the secret URL in logs.


def main():
    if sys.argv[1:] == ["--self-test"]:
        assert prefix_for("8.8.8.8") == "8.8.8.8/32"
        assert policy_route_args("8.8.8.8/32", "default via 192.0.2.1 dev eth0") == [
            "ip", "-4", "route", "replace", "8.8.8.8/32", "via", "192.0.2.1",
            "dev", "eth0", "table", TABLE, "congctl", "lock", "brutal", "proto", "233",
        ]
        try:
            prefix_for("127.0.0.1")
        except ValueError:
            return
        raise AssertionError("private address accepted")

    if len(TOKEN) < 32 or not 1 <= RATE <= 1_000_000 or (TABLE and not TABLE.isdigit()):
        raise SystemExit("invalid BRUTAL_LINK_TOKEN, BRUTAL_LINK_RATE or BRUTAL_LINK_TABLE")
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("/etc/brutal-ip-link/cert.pem", "/etc/brutal-ip-link/key.pem")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
