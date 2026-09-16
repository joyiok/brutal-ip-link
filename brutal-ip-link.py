#!/usr/bin/env python3
import hmac
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = os.environ.get("BRUTAL_LINK_TOKEN", "")
RATE = int(os.environ.get("BRUTAL_LINK_RATE", "100"))
TABLE = os.environ.get("BRUTAL_LINK_TABLE", "")
XRAY_UNIT = os.environ.get("BRUTAL_LINK_XRAY_UNIT", "")
XRAY_EMAIL = os.environ.get("BRUTAL_LINK_XRAY_EMAIL", "")
STATE = Path("/var/lib/brutal-ip-link/current-prefix")
PENDING = STATE.with_name("pending-prefix")
RULES = Path("/proc/net/tcp_brutal/rules")
CTL = "/usr/local/bin/brutalctl"
MAX_PREFIXES = 5
UPDATE_LOCK = threading.Lock()
XRAY_SOURCE = re.compile(
    r"^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? )?"
    r"from (?:tcp:|udp:)?(\[[0-9a-fA-F:.]+\]|[0-9.]+):\d+ accepted "
    r"(?:tcp|udp):\S+(?: \[[^\]\r\n]+\])? email: (\S+)$"
)


def prefix_for(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast:
        raise ValueError("request did not come from a public IP")
    return f"{address}/{32 if address.version == 4 else 128}"


def policy_route_args(prefix, default):
    words = default.split()
    args = ["ip", "-6" if ":" in prefix else "-4", "route", "replace", prefix]
    if "nexthop" in words:
        raise ValueError("multipath policy routes are not supported")
    for field in ("via", "dev", "src"):
        if field in words:
            args += [field, words[words.index(field) + 1]]
    if "dev" not in words:
        raise ValueError(f"no device in table {TABLE} default route")
    if "onlink" in words:
        args.append("onlink")
    return args + ["table", TABLE, "congctl", "lock", "brutal", "proto", "233"]


def routes_for(prefix, table, owned=False):
    return subprocess.run(
        ["ip", "-6" if ":" in prefix else "-4", "route", "show", "table", table,
         "exact", prefix] + (["proto", "233"] if owned else []),
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout.strip()


def policy_route(prefix):
    if not TABLE:
        return
    family = "-6" if ":" in prefix else "-4"
    # ip omits the protocol field when filtering by it; compare matching route counts.
    if len(routes_for(prefix, TABLE).splitlines()) != len(routes_for(prefix, TABLE, owned=True).splitlines()):
        raise ValueError(f"refusing to replace an unmanaged route in table {TABLE}")
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


def read_prefixes(path):
    if not path.exists():
        return []
    prefixes = []
    for prefix in path.read_text().splitlines():
        network = ipaddress.ip_network(prefix, strict=True)
        if network.prefixlen != network.max_prefixlen:
            raise ValueError(f"invalid host prefix in {path}")
        prefix = prefix_for(str(network.network_address))
        if prefix in prefixes:
            raise ValueError(f"duplicate host prefix in {path}")
        prefixes.append(prefix)
    return prefixes


def read_prefix(path):
    prefixes = read_prefixes(path)
    if len(prefixes) > 1:
        raise ValueError(f"multiple host prefixes in {path}")
    return prefixes[0] if prefixes else ""


def write_prefix(path, prefix):
    write_prefixes(path, [prefix])


def write_prefixes(path, prefixes):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as output:
        output.writelines(prefix + "\n" for prefix in prefixes)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def rule_for(prefix):
    try:
        for line in RULES.read_text().splitlines():
            fields = dict(word.split("=", 1) for word in line.split() if "=" in word)
            if fields.get("dst") == prefix:
                return fields
    except FileNotFoundError:
        pass
    return {}


def remove_prefix(prefix):
    if rule_for(prefix):
        subprocess.run([CTL, "del", prefix], check=True, timeout=10)
    # brutalctl may silently fail to remove its main-table route.
    for table in dict.fromkeys(["main"] + ([TABLE] if TABLE else [])):
        if routes_for(prefix, table, owned=True):
            subprocess.run(
                ["ip", "-6" if ":" in prefix else "-4", "route", "del", prefix,
                 "table", table, "proto", "233"], check=True, timeout=10,
            )


def prefix_ready(prefix):
    rule = rule_for(prefix)
    return (rule.get("rate") == str(RATE * 125_000) and rule.get("lock") == "1"
            and "congctl lock brutal" in routes_for(prefix, TABLE or "main", owned=True))


def update_prefix(prefix=None, force=True):
    with UPDATE_LOCK:
        saved, pending = read_prefixes(STATE), read_prefix(PENDING)
        requested = prefix is not None
        if prefix is None and not pending:
            changed = False
            for current in saved:
                if prefix_ready(current):
                    continue
                write_prefix(PENDING, current)
                subprocess.run([CTL, "add", current, str(RATE)] + (["noroute"] if TABLE else []),
                               check=True, timeout=10)
                policy_route(current)
                PENDING.unlink()
                changed = True
            return changed
        prefix = prefix or pending
        if not prefix:
            return False
        network = ipaddress.ip_network(prefix, strict=True)
        if prefix_for(str(network.network_address)) != prefix:
            raise ValueError("only canonical public host prefixes are allowed")
        if pending and pending not in saved and pending != prefix:
            remove_prefix(pending)
            PENDING.unlink()
        if requested:
            updated = ([item for item in saved if item != prefix] + [prefix])[-MAX_PREFIXES:]
        else:
            updated = saved if prefix in saved else (saved + [prefix])[-MAX_PREFIXES:]
        if not force and prefix in saved and not pending and prefix_ready(prefix):
            if updated == saved:
                return False
            write_prefixes(STATE, updated)
            return True
        # Record ownership before any side effect so an interrupted update is recoverable.
        write_prefix(PENDING, prefix)
        try:
            subprocess.run([CTL, "add", prefix, str(RATE)] + (["noroute"] if TABLE else []),
                           check=True, timeout=10)
            policy_route(prefix)
        except Exception:
            if prefix not in saved:
                try:
                    remove_prefix(prefix)
                    PENDING.unlink()
                except Exception as error:
                    print(f"rollback pending: {error}", file=sys.stderr, flush=True)
            raise
        for old in saved:
            if old not in updated:
                remove_prefix(old)
        write_prefixes(STATE, updated)
        PENDING.unlink()
        return True


def xray_source(line):
    match = XRAY_SOURCE.fullmatch(line.rstrip("\n"))
    if not match or (XRAY_EMAIL and match.group(2) != XRAY_EMAIL):
        return ""
    try:
        return prefix_for(match.group(1).strip("[]"))
    except ValueError:
        return ""


def watch_xray():
    cursor = ""
    while True:
        try:
            with subprocess.Popen(
                ["journalctl", "-fu", XRAY_UNIT, "-o", "json"]
                + (["--after-cursor", cursor] if cursor else ["-n", "0"]),
                stdout=subprocess.PIPE, text=True, errors="replace",
            ) as process:
                for line in process.stdout:
                    try:
                        event = json.loads(line)
                        cursor = event.get("__CURSOR", cursor)
                        prefix = xray_source(event.get("MESSAGE", ""))
                        if prefix and update_prefix(prefix, force=False):
                            print(f"Xray authenticated; updated {prefix}", flush=True)
                    except Exception as error:
                        print(f"Xray update failed: {error}", file=sys.stderr, flush=True)
            print(f"journalctl exited: {process.returncode}; retrying", file=sys.stderr, flush=True)
            if process.returncode:
                cursor = ""
        except OSError as error:
            print(f"Xray watcher failed: {error}", file=sys.stderr, flush=True)
        time.sleep(5)


def maintain_rules():
    while True:
        try:
            if update_prefix(force=False):
                print("Saved TCP Brutal rule restored", flush=True)
        except Exception as error:
            print(f"restore failed; will retry: {error}", file=sys.stderr, flush=True)
        time.sleep(30)


class TLSServer(ThreadingHTTPServer):
    request_timeout = 5

    def __init__(self, address, handler, tls):
        self.tls = tls
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(self.request_timeout)
            request = self.tls.wrap_socket(request, server_side=True)
            self.finish_request(request, address)
        except (OSError, ssl.SSLError):
            pass  # Timeouts and peers closing a connection are normal on a public listener.
        except Exception:
            self.handle_error(request, address)
        finally:
            try:
                self.shutdown_request(request)
            finally:
                self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not TOKEN or not hmac.compare_digest(self.path.encode(), ("/" + TOKEN).encode()):
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
            "from 8.8.8.8:12345 accepted tcp:example.com:443 [direct] email: " + (XRAY_EMAIL or "owner")
        ) == "8.8.8.8/32"
        assert not xray_source("from 8.8.8.8:12345 accepted tcp:127.0.0.1:45987 [dokodemo-in-test]")
        assert not xray_source("from 127.0.0.1:12345 accepted tcp:example.com:443 [direct]")
        try:
            prefix_for("127.0.0.1")
        except ValueError:
            return
        raise AssertionError("private address accepted")

    if (
        not re.fullmatch(r"[A-Za-z0-9_-]{32,}", TOKEN)
        or not 1 <= RATE <= 1_000_000
        or (TABLE and not TABLE.isdigit())
        or (XRAY_UNIT and not re.fullmatch(r"[A-Za-z0-9_.@-]+", XRAY_UNIT))
        or (XRAY_EMAIL and not re.fullmatch(r"\S+", XRAY_EMAIL))
    ):
        raise SystemExit("invalid configuration")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("/etc/brutal-ip-link/cert.pem", "/etc/brutal-ip-link/key.pem")
    server = TLSServer(("0.0.0.0", 8443), Handler, tls)
    threading.Thread(target=maintain_rules, daemon=True).start()
    if XRAY_UNIT:
        threading.Thread(target=watch_xray, daemon=True).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
