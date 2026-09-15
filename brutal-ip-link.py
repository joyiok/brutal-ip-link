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
STATE = Path("/var/lib/brutal-ip-link/current-prefix")
CTL = "/usr/local/bin/brutalctl"


def prefix_for(value):
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise ValueError("request did not come from a public IP")
    return f"{address}/{32 if address.version == 4 else 128}"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not TOKEN or not hmac.compare_digest(self.path, "/" + TOKEN):
            self.send_error(404)
            return

        try:
            prefix = prefix_for(self.client_address[0])
            old = STATE.read_text().strip() if STATE.exists() else ""
            subprocess.run([CTL, "add", prefix, str(RATE)], check=True, timeout=10)
            if old and old != prefix:
                subprocess.run([CTL, "del", old], check=True, timeout=10)
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
        try:
            prefix_for("127.0.0.1")
        except ValueError:
            return
        raise AssertionError("private address accepted")

    if len(TOKEN) < 32 or not 1 <= RATE <= 1_000_000:
        raise SystemExit("invalid BRUTAL_LINK_TOKEN or BRUTAL_LINK_RATE")
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("/etc/brutal-ip-link/cert.pem", "/etc/brutal-ip-link/key.pem")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
