#!/usr/bin/env python3
import hmac
import ipaddress
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

TOKEN = os.environ.get("BRUTAL_LINK_TOKEN", "")
RATE = int(os.environ.get("BRUTAL_LINK_RATE", "100"))
TABLE = os.environ.get("BRUTAL_LINK_TABLE", "")
XRAY_UNIT = os.environ.get("BRUTAL_LINK_XRAY_UNIT", "")
STATE = Path("/var/lib/brutal-ip-link/current-prefix")
CTL = "/usr/local/bin/brutalctl"
UPDATE_LOCK = threading.Lock()
XRAY_SOURCE = re.compile(
    r"\bfrom (\[[0-9a-fA-F:]+\]|[0-9.]+):\d+ accepted .*\[dokodemo-in-"
)


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


def update_prefix(prefix, force=True):
    with UPDATE_LOCK:
        old = STATE.read_text().strip() if STATE.exists() else ""
        if not force and old == prefix:
            return False
        subprocess.run([CTL, "add", prefix, str(RATE)], check=True, timeout=10)
        policy_route(prefix)
        if old and old != prefix:
            subprocess.run([CTL, "del", old], timeout=10)
            policy_route(old, delete=True)
        STATE.write_text(prefix + "\n")
        return True


def xray_source(line):
    match = XRAY_SOURCE.search(line)
    if not match:
        return ""
    try:
        return prefix_for(match.group(1).strip("[]"))
    except ValueError:
        return ""


def watch_xray():
    while True:
        candidate = (0.0, "")
        process = subprocess.Popen(
            ["journalctl", "-fu", XRAY_UNIT, "-n", "0", "-o", "cat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in process.stdout:
            prefix = xray_source(line)
            if prefix:
                candidate = (time.monotonic(), prefix)
            elif " email: " in line and candidate[1] and time.monotonic() - candidate[0] <= 5:
                try:
                    if update_prefix(candidate[1], force=False):
                        print(f"Xray authenticated; updated {candidate[1]}", flush=True)
                except Exception as error:
                    print(f"Xray update failed: {error}", file=sys.stderr, flush=True)
                candidate = (0.0, "")
        process.wait()
        time.sleep(5)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not TOKEN or not hmac.compare_digest(self.path, "/" + TOKEN):
            self.send_error(404)
            return

        try:
            prefix = prefix_for(self.client_address[0])
            update_prefix(prefix)
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
        assert xray_source(
            "from 8.8.8.8:12345 accepted tcp:127.0.0.1:45987 [dokodemo-in-test]"
        ) == "8.8.8.8/32"
        assert not xray_source("from 127.0.0.1:12345 accepted tcp:example.com:443 [direct]")
        try:
            prefix_for("127.0.0.1")
        except ValueError:
            return
        raise AssertionError("private address accepted")

    if (
        len(TOKEN) < 32
        or not 1 <= RATE <= 1_000_000
        or (TABLE and not TABLE.isdigit())
        or (XRAY_UNIT and not re.fullmatch(r"[A-Za-z0-9_.@-]+", XRAY_UNIT))
    ):
        raise SystemExit("invalid configuration")
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("/etc/brutal-ip-link/cert.pem", "/etc/brutal-ip-link/key.pem")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    if STATE.exists():
        try:
            update_prefix(STATE.read_text().strip())
        except Exception as error:
            print(f"restore failed: {error}", file=sys.stderr, flush=True)
    if XRAY_UNIT:
        threading.Thread(target=watch_xray, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
