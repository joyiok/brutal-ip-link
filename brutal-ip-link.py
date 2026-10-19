#!/usr/bin/env python3
import argparse
import copy
import fcntl
import hmac
import ipaddress
import json
import math
import os
import re
import signal
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = ""
RATE = 100
TABLE = ""
XRAY_UNIT = ""
XRAY_EMAIL = ""
STATE = Path("/var/lib/brutal-ip-link/current-prefix")
PENDING = STATE.with_name("pending-prefix")
RULES = Path("/proc/net/tcp_brutal/rules")
CTL = "/usr/local/bin/brutalctl"
MAX_PREFIXES = 5
TTL = 0
HTTPS = True
HOST = "0.0.0.0"
PORT = 8443
AUTO_UPDATE = True
CONFIG = Path("/etc/brutal-ip-link/env")
CERT_DIR = CONFIG.parent
MODULE_VERSION = Path("/sys/module/brutal/version")
CHECK_INTERVAL = 30
CACHE_SECONDS = 5
SEEN = {}
READY_CACHE = {}
XRAY_STATUS = {}
XRAY_PROCESS = None
STOP = threading.Event()
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
    # sync_entry has already checked that any existing route is ours.
    if not TABLE:
        return
    family = "-6" if ":" in prefix else "-4"
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


def assert_route_owned(prefix, table):
    # ip omits the protocol field when filtering by it; compare matching route counts.
    if len(routes_for(prefix, table).splitlines()) != len(routes_for(prefix, table, owned=True).splitlines()):
        raise ValueError(f"refusing to replace an unmanaged route in table {table}")


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


def atomic_write(path, text):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as output:
        output.write(text)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def rules_by_prefix():
    rules = {}
    try:
        for line in RULES.read_text().splitlines():
            fields = dict(word.split("=", 1) for word in line.split() if "=" in word)
            rules.setdefault(fields.get("dst"), fields)
    except FileNotFoundError:
        pass
    return rules


def rule_for(prefix):
    return rules_by_prefix().get(prefix, {})


def owned_routes(family):
    # One listing per family; ip prints host routes without their prefix length.
    output = subprocess.run(
        ["ip", family, "route", "show", "table", TABLE or "main", "proto", "233"],
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout
    routes = {}
    for line in output.splitlines():
        try:
            prefix = str(ipaddress.ip_network(line.split()[0]))
        except (IndexError, ValueError):
            continue  # Route types such as "unreachable" and multipath continuation lines.
        routes[prefix] = routes.get(prefix, "") + line + "\n"
    return routes


def kernel_snapshot(prefixes):
    # Lets a pass confirm healthy rules with one read and one ip call per family.
    try:
        routes = {}
        for family in {"-6" if ":" in prefix else "-4" for prefix in prefixes}:
            routes.update(owned_routes(family))
        return rules_by_prefix(), routes
    except Exception:
        return None  # The per-address checks still run and report the error.


def remove_route(prefix, table):
    if routes_for(prefix, table, owned=True):
        subprocess.run(
            ["ip", "-6" if ":" in prefix else "-4", "route", "del", prefix,
             "table", table, "proto", "233"], check=True, timeout=10,
        )


def remove_prefix(prefix, tables=None):
    if rule_for(prefix):
        subprocess.run([CTL, "del", prefix], check=True, timeout=10)
    # brutalctl may silently fail to remove its main-table route.
    for table in dict.fromkeys(["main"] + list(tables or [TABLE or "main"])):
        remove_route(prefix, table)


def rule_matches(rule):
    return rule.get("rate") == str(RATE * 125_000) and rule.get("lock") == "1"


def prefix_ready(prefix, snapshot=None):
    if snapshot:
        rules, routes = snapshot
        if rule_matches(rules.get(prefix, {})) and "congctl lock brutal" in routes.get(prefix, ""):
            return True  # A snapshot only confirms readiness; anything else is checked directly.
    return (rule_matches(rule_for(prefix))
            and "congctl lock brutal" in routes_for(prefix, TABLE or "main", owned=True))


def state_path(name="state.json"):
    return STATE.with_name(name)


@contextmanager
def state_lock(timeout=None):
    # The CLI, daemon and updater must use the same lock, including across rename().
    deadline = time.monotonic() + timeout if timeout is not None else None
    if not UPDATE_LOCK.acquire(timeout=timeout if timeout is not None else -1):
        raise TimeoutError("rule maintenance is busy")
    try:
        STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with state_path("state.lock").open("a") as lock:
            if deadline is None:
                fcntl.flock(lock, fcntl.LOCK_EX)
            else:
                while True:
                    try:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("rule maintenance is busy")
                        time.sleep(0.05)
            yield
    finally:
        UPDATE_LOCK.release()


def new_entry(seen):
    return {"last_seen": seen, "desired": True, "tables": [TABLE or "main"],
            "error": "", "last_success": 0}


def validate_prefix(prefix):
    network = ipaddress.ip_network(prefix, strict=True)
    if prefix_for(str(network.network_address)) != prefix:
        raise ValueError("only canonical public host prefixes are allowed")
    return prefix


def load_state():
    path = state_path()
    if not path.exists():
        data = {"version": 1, "entries": {}, "xray": {}}
        # Import both legacy files before the first new-format commit. Keep the
        # old files as a backup; state.json becomes the sole authority thereafter.
        for path in (STATE, PENDING):
            for index, prefix in enumerate(read_prefixes(path)):
                seen = path.stat().st_mtime + index * 0.000001
                entry = data["entries"].setdefault(prefix, new_entry(seen))
                entry["last_seen"] = max(entry["last_seen"], seen)
                if path == STATE:
                    entry["last_success"] = seen
        return data
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("entries"), dict):
        raise ValueError("unsupported or invalid state file")
    for prefix, entry in data["entries"].items():
        validate_prefix(prefix)
        if (not isinstance(entry, dict) or not isinstance(entry.get("desired"), bool)
                or not isinstance(entry.get("last_seen"), (float, int))
                or not math.isfinite(entry["last_seen"])
                or not isinstance(entry.get("tables"), list)
                or any(not isinstance(t, str) or not (t == "main" or re.fullmatch(r"[0-9]+", t))
                       for t in entry["tables"])):
            raise ValueError("invalid state entry")
    return data


def save_state(data):
    atomic_write(state_path(), json.dumps(data, sort_keys=True, indent=2) + "\n")


def merge_seen(data):
    for prefix, seen in list(SEEN.items()):
        entry = data["entries"].get(prefix)
        if entry and entry["desired"]:
            entry["last_seen"] = max(entry["last_seen"], seen)
        else:
            SEEN.pop(prefix, None)


def expire_entries(data):
    active = sorted((p for p, e in data["entries"].items() if e["desired"]),
                    key=lambda p: data["entries"][p]["last_seen"], reverse=True)
    now = time.time()
    applied = pending = 0
    for prefix in active:
        entry = data["entries"][prefix]
        if entry.get("last_success"):
            applied += 1
            excess = applied > MAX_PREFIXES
        else:
            pending += 1
            excess = pending > MAX_PREFIXES
        if excess or (TTL and now - entry["last_seen"] >= TTL):
            entry["desired"] = False
            READY_CACHE.pop(prefix, None)
            SEEN.pop(prefix, None)


def sync_entry(data, prefix, force=False, snapshot=None):
    entry = data["entries"][prefix]
    changed = False
    try:
        if not entry["desired"]:
            remove_prefix(prefix, entry["tables"])
            del data["entries"][prefix]
            READY_CACHE.pop(prefix, None)
            save_state(data)
            return True
        target = TABLE or "main"
        if target not in entry["tables"]:
            entry["tables"].append(target)
            save_state(data)  # Own the new table before writing any route to it.
        if force or not prefix_ready(prefix, snapshot):
            assert_route_owned(prefix, target)
            existed = bool(rule_for(prefix))
            try:
                subprocess.run([CTL, "add", prefix, str(RATE)] + (["noroute"] if TABLE else []),
                               check=True, timeout=10)
                policy_route(prefix)
                if not prefix_ready(prefix):
                    raise RuntimeError("rule or route is missing after update")
            except Exception:
                if not existed:
                    try:
                        remove_prefix(prefix, [target])
                    except Exception as error:
                        print(f"rollback pending for {prefix}: {error}", file=sys.stderr, flush=True)
                raise
            changed = True
        # Only remove old-table routes once the replacement works.
        for table in entry["tables"]:
            if table != target:
                remove_route(prefix, table)
                changed = True
        dirty = entry["tables"] != [target] or entry.get("error") or not entry.get("last_success") or changed
        entry["tables"] = [target]
        entry["error"] = ""
        if dirty:
            entry["last_success"] = time.time()
            save_state(data)
        READY_CACHE[prefix] = (time.monotonic(), TABLE, RATE)
        return bool(changed or dirty)
    except Exception as error:
        READY_CACHE.pop(prefix, None)
        # Persist the intent even when rollback succeeds; maintenance retries it.
        entry["error"] = str(error)
        save_state(data)
        raise


def reconcile(data):
    before = copy.deepcopy(data)
    merge_seen(data)
    if XRAY_STATUS:
        data["xray"] = dict(XRAY_STATUS)
    expire_entries(data)
    if data != before or not state_path().exists():
        save_state(data)
    errors = {}
    changed = False
    snapshot = kernel_snapshot(data["entries"])
    # One bad IP must never prevent the remaining rules or cleanups from running.
    for prefix in list(data["entries"]):
        try:
            changed = sync_entry(data, prefix, snapshot=snapshot) or changed
        except Exception as error:
            errors[prefix] = str(error)
            print(f"retry pending for {prefix}: {error}", file=sys.stderr, flush=True)
    before = copy.deepcopy(data)
    expire_entries(data)
    if data != before:
        save_state(data)
        for prefix, entry in list(data["entries"].items()):
            if not entry["desired"] and prefix not in errors:
                try:
                    changed = sync_entry(data, prefix) or changed
                except Exception as error:
                    errors[prefix] = str(error)
    return changed, errors


def update_prefix(prefix=None, force=True, seen_at=None, lock_timeout=None):
    if prefix is not None:
        validate_prefix(prefix)
        observed = time.time() if seen_at is None else seen_at
        cached = READY_CACHE.get(prefix)
        if (not force and cached and cached[1:] == (TABLE, RATE)
                and time.monotonic() - cached[0] < CACHE_SECONDS):
            # Repeated connection logs skip the lock and state file; maintenance merges SEEN.
            SEEN[prefix] = max(observed, SEEN.get(prefix, 0))
            return False
    with state_lock(lock_timeout):
        data = load_state()
        if prefix is None:
            return reconcile(data)[0]
        entry = data["entries"].get(prefix)
        seen = SEEN[prefix] = max(observed, SEEN.get(prefix, 0), entry["last_seen"] if entry else 0)
        # Batch last_seen/LRU writes for known addresses. New addresses and
        # explicit changes always commit before touching the kernel.
        if entry and entry["desired"] and not force:
            # Maintenance retries failures; retrying on every connection log only adds load.
            return False if entry.get("error") else sync_entry(data, prefix)
        merge_seen(data)
        if not entry:
            entry = data["entries"][prefix] = new_entry(seen)
        SEEN[prefix] = seen
        entry["last_seen"] = seen
        entry["desired"] = True
        save_state(data)
        result = sync_entry(data, prefix, force=force)
        # Do not evict healthy addresses until the new address has been applied.
        reconcile(data)
        return result


def delete_prefix(prefix=None):
    with state_lock():
        data = load_state()
        targets = list(data["entries"]) if prefix is None else [validate_prefix(prefix)]
        for target in targets:
            if target in data["entries"]:
                data["entries"][target]["desired"] = False
                SEEN.pop(target, None)
                READY_CACHE.pop(target, None)
        save_state(data)
        errors = {}
        for target in targets:
            if target in data["entries"]:
                try:
                    sync_entry(data, target)
                except Exception as error:
                    errors[target] = str(error)
        if errors:
            raise RuntimeError(f"cleanup pending: {errors}")


def xray_source(line):
    match = XRAY_SOURCE.fullmatch(line.rstrip("\n"))
    if not match or (XRAY_EMAIL and match.group(2) != XRAY_EMAIL):
        return ""
    try:
        return prefix_for(match.group(1).strip("[]"))
    except ValueError:
        return ""


def watch_xray():
    global XRAY_PROCESS
    cursor = None
    while not STOP.is_set():
        process = None
        try:
            if cursor is None:
                # Load inside the retry loop: a bad state file must not end detection.
                with state_lock():
                    previous = load_state().get("xray", {})
                if previous.get("unit") != XRAY_UNIT:
                    previous = {}
                XRAY_STATUS.update(previous, unit=XRAY_UNIT, connected=False)
                cursor = previous.get("cursor", "")
            process = subprocess.Popen(
                ["journalctl", "-fu", XRAY_UNIT, "-o", "json"]
                + (["--after-cursor", cursor] if cursor else ["--since", "-5 min"]),
                stdout=subprocess.PIPE, text=True, errors="replace",
            )
            XRAY_PROCESS = process
            if STOP.is_set():
                break
            XRAY_STATUS.update(connected=True, error="")
            for line in process.stdout:
                if STOP.is_set():
                    break
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        continue
                except ValueError:
                    continue
                message = event.get("MESSAGE", "")
                prefix = xray_source(message) if isinstance(message, str) else ""
                XRAY_STATUS["last_event"] = time.time()
                try:
                    seen = min(time.time(), int(event["__REALTIME_TIMESTAMP"]) / 1_000_000)
                except (KeyError, TypeError, ValueError):
                    seen = time.time()
                if TTL and time.time() - seen >= TTL:
                    prefix = ""
                if prefix:
                    try:
                        if update_prefix(prefix, force=False, seen_at=seen):
                            print(f"Xray authenticated; updated {prefix}", flush=True)
                    except Exception as error:
                        # Advance only if the failed operation has durable retry intent.
                        with state_lock():
                            entry = load_state()["entries"].get(prefix, {})
                        if not entry.get("desired"):
                            raise
                        print(f"Xray update queued for {prefix}: {error}", file=sys.stderr, flush=True)
                    XRAY_STATUS["last_match"] = max(XRAY_STATUS.get("last_match", 0), seen)
                cursor = event.get("__CURSOR", cursor)
                XRAY_STATUS["cursor"] = cursor
            if STOP.is_set():
                break
            process.wait()
            print(f"journalctl exited: {process.returncode}; retrying", file=sys.stderr, flush=True)
            if process.returncode:
                cursor = ""
                XRAY_STATUS["cursor"] = ""
            XRAY_STATUS["error"] = f"journalctl exited: {process.returncode}"
        except Exception as error:
            XRAY_STATUS["error"] = str(error)
            print(f"Xray watcher failed: {error}", file=sys.stderr, flush=True)
        finally:
            XRAY_STATUS["connected"] = False
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                process.stdout.close()
            XRAY_PROCESS = None
        STOP.wait(5)


def notify_ready():
    # With Type=notify, systemctl start/restart waits for this and reports early exits.
    address = os.environ.pop("NOTIFY_SOCKET", "")
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect("\0" + address[1:] if address.startswith("@") else address)
            sock.sendall(b"READY=1")


def maintain_rules():
    while not STOP.is_set():
        try:
            if update_prefix(force=False):
                print("Saved TCP Brutal rule restored", flush=True)
        except Exception as error:
            print(f"restore failed; will retry: {error}", file=sys.stderr, flush=True)
        STOP.wait(CHECK_INTERVAL)


class DeadlineSocket(ssl.SSLSocket):
    # Reads share one deadline, so a client trickling bytes cannot hold a slot.
    deadline = None

    def recv_into(self, *args, **kwargs):
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("request deadline exceeded")
            self.settimeout(remaining)
        return super().recv_into(*args, **kwargs)


class TLSServer(ThreadingHTTPServer):
    request_timeout = 5

    def __init__(self, address, handler, tls):
        self.tls = tls
        tls.sslsocket_class = DeadlineSocket
        self.slots = threading.BoundedSemaphore(32)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, handler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

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
            # The handshake already has a total deadline; give the request one too.
            request.deadline = time.monotonic() + self.request_timeout
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
            update_prefix(prefix, lock_timeout=5)
        except TimeoutError:
            self.send_error(503, "rule maintenance in progress; retry shortly")
            return
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


def configure(path=CONFIG):
    global TOKEN, RATE, TABLE, XRAY_UNIT, XRAY_EMAIL, MAX_PREFIXES, TTL, HTTPS, HOST, PORT, AUTO_UPDATE
    values = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip() and not line.lstrip().startswith("#"):
                key, sep, value = line.partition("=")
                if not sep:
                    raise ValueError(f"invalid configuration line in {path}")
                values[key.strip()] = value.strip()
    def setting(name, default):
        key = "BRUTAL_LINK_" + name
        return os.environ.get(key, values.get(key, str(default)))
    def number(name, default, low, high):
        value = setting(name, default)
        if not re.fullmatch(r"[0-9]+", value) or not low <= int(value) <= high:
            raise ValueError(f"BRUTAL_LINK_{name} must be between {low} and {high}")
        return int(value)
    def flag(name, default):
        value = setting(name, default)
        if value not in ("0", "1"):
            raise ValueError(f"BRUTAL_LINK_{name} must be 0 or 1")
        return value == "1"
    TOKEN = setting("TOKEN", "")
    RATE = number("RATE", 100, 1, 1_000_000)
    TABLE = setting("TABLE", "")
    if TABLE:
        if not re.fullmatch(r"[0-9]+", TABLE) or not 1 <= int(TABLE) <= 4294967295:
            raise ValueError("BRUTAL_LINK_TABLE must be a nonzero numeric routing table")
        TABLE = "" if int(TABLE) == 254 else str(int(TABLE))
    XRAY_UNIT = setting("XRAY_UNIT", "")
    XRAY_EMAIL = setting("XRAY_EMAIL", "")
    MAX_PREFIXES = number("MAX_PREFIXES", 5, 1, 1000)
    TTL = number("TTL", 0, 0, 31536000)
    HTTPS = flag("HTTPS", 1)
    HOST = setting("HOST", "0.0.0.0")
    ipaddress.ip_address(HOST)
    PORT = number("PORT", 8443, 1, 65535)
    AUTO_UPDATE = flag("AUTO_UPDATE", 1)
    if ((HTTPS and not re.fullmatch(r"[A-Za-z0-9_-]{32,}", TOKEN))
            or (XRAY_UNIT and not re.fullmatch(r"[A-Za-z0-9_.@-]+", XRAY_UNIT))
            or (XRAY_EMAIL and not re.fullmatch(r"[A-Za-z0-9_.@+-]+", XRAY_EMAIL))):
        raise ValueError("invalid token, Xray unit or email configuration")


def command_output(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout.strip()


def module_versions():
    loaded = MODULE_VERSION.read_text().strip() if MODULE_VERSION.exists() else ""
    try:
        installed = command_output(["modinfo", "-F", "version", "brutal"])
    except (OSError, subprocess.SubprocessError):
        installed = ""
    return installed, loaded


def status_report():
    # Atomic replacement lets read-only diagnostics run during a long DKMS build.
    data = load_state()
    installed, loaded = module_versions()
    snapshot = kernel_snapshot(data["entries"])
    rows = []
    for prefix, entry in sorted(data["entries"].items(), key=lambda item: item[1]["last_seen"], reverse=True):
        row = dict(entry, prefix=prefix, ready=False)
        try:
            row["ready"] = prefix_ready(prefix, snapshot)
        except Exception as error:
            row["error"] = str(error)
        rows.append(row)
    update_file = state_path("update.json")
    update = json.loads(update_file.read_text()) if update_file.exists() else {}
    return {"entries": rows, "xray": data.get("xray", {}), "update": update,
            "module": {"installed": installed, "loaded": loaded,
                       "reboot_required": bool(installed and loaded and installed != loaded)},
            "config": {"rate_mbps": RATE, "table": TABLE or "main", "max_prefixes": MAX_PREFIXES,
                       "ttl_seconds": TTL, "https": HTTPS, "host": HOST, "port": PORT,
                       "xray_unit": XRAY_UNIT, "auto_update": AUTO_UPDATE}}


def doctor_report(report):
    checks = []
    def check(name, ok, detail):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
    check("brutalctl", os.access(CTL, os.X_OK), CTL)
    check("kernel_rules", RULES.exists(), str(RULES))
    check("module_version", report["module"]["loaded"] and not report["module"]["reboot_required"],
          str(report["module"]))
    for name in ("brutal-ip-link.service", XRAY_UNIT):
        if name:
            try:
                active = command_output(["systemctl", "is-active", name]) == "active"
            except (OSError, subprocess.SubprocessError):
                active = False
            check(name, active, "active" if active else "not active")
    for row in report["entries"]:
        check(row["prefix"], row["desired"] and row["ready"] and not row.get("error")
              and row["tables"] == [TABLE or "main"],
              row.get("error") or ("ready" if row["desired"] and row["ready"] else "pending"))
    if XRAY_UNIT:
        watcher = report["xray"]
        check("xray_watcher", watcher.get("unit") == XRAY_UNIT and watcher.get("connected") and not watcher.get("error"),
              watcher.get("error") or "watcher status is saved every 30 seconds")
        check("xray_detection", watcher.get("unit") == XRAY_UNIT and watcher.get("last_match"),
              f"last authenticated source: {watcher.get('last_match', 'never')}; check public source IP and email in journal")
    if HTTPS:
        try:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(CERT_DIR / "cert.pem", CERT_DIR / "key.pem")
            command_output(["openssl", "x509", "-checkend", "0", "-noout", "-in", str(CERT_DIR / "cert.pem")])
            check("certificate", True, "certificate and private key load successfully")
        except Exception as error:
            check("certificate", False, str(error))
    if AUTO_UPDATE:
        try:
            active = command_output(["systemctl", "is-active", "brutal-ip-link-update.timer"]) == "active"
        except (OSError, subprocess.SubprocessError):
            active = False
        check("update_timer", active, "active" if active else "not active")
        if report["update"].get("status") == "failed":
            check("last_update", False, report["update"].get("error", "update failed"))
    report["checks"] = checks
    return all(item["ok"] for item in checks)


def print_status(report, as_json=False, listing=False):
    if as_json:
        print(json.dumps(report["entries"] if listing else report, indent=2))
        return
    if not listing:
        print(f"TCP Brutal: installed={report['module']['installed'] or 'unknown'} loaded={report['module']['loaded'] or 'unloaded'}")
        print(f"Rate: {RATE} Mbps; table: {TABLE or 'main'}; limit: {MAX_PREFIXES}; TTL: {TTL}s")
        print(f"HTTPS: {HOST}:{PORT}" if HTTPS else "HTTPS: disabled")
        print(f"Xray: {XRAY_UNIT or 'disabled'}; last match: {report['xray'].get('last_match', 'never')}")
        print(f"Automatic update: {'enabled' if AUTO_UPDATE else 'disabled'}; last result: {report['update'].get('status', 'never')}")
        if report["module"]["reboot_required"]:
            print("A newer module is installed; reboot is required to activate it.")
    print("PREFIX\tSTATUS\tLAST SEEN\tTABLES")
    for row in report["entries"]:
        status = "ready" if row["ready"] and not row.get("error") else "retry"
        if not row["desired"]:
            status = "removing"
        seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["last_seen"]))
        print(f"{row['prefix']}\t{status}\t{seen}\t{','.join(row['tables'])}")
        if row.get("error"):
            print(f"  {row['error']}")
    if not report["entries"]:
        print("No tracked IPs.")
    for check in report.get("checks", []):
        print(f"{'OK' if check['ok'] else 'CHECK'} {check['name']}: {check['detail']}")


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "brutal-ip-link"})
    with urllib.request.urlopen(request, timeout=30) as response:
        content = response.read(2_000_001)
    if len(content) > 2_000_000:
        raise ValueError("upstream response exceeds size limit")
    return content


def version_tuple(version):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError(f"unsupported module version: {version!r}")
    return tuple(map(int, match.groups()))


def run_installer(path, version):
    environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive", TERM="dumb")
    with subprocess.Popen(["bash", str(path), "install", "--version", version],
                          env=environment, stdin=subprocess.DEVNULL, start_new_session=True) as process:
        try:
            if process.wait(timeout=1800):
                raise RuntimeError(f"upstream installer exited with {process.returncode}")
        except BaseException:
            # Kill the entire build process group before releasing the state lock.
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            raise


def update_brutal(scheduled=False):
    if scheduled and not AUTO_UPDATE:
        print("Automatic updates disabled.")
        return
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with state_path("update.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = {"checked_at": time.time(), "status": "checking"}
        atomic_write(state_path("update.json"), json.dumps(result, indent=2) + "\n")
        try:
            release = json.loads(fetch("https://api.github.com/repos/HyNetworks/tcp-brutal/releases/latest"))
            if not isinstance(release, dict) or not isinstance(release.get("tag_name"), str):
                raise ValueError("upstream did not return a release version")
            target = release["tag_name"]
            target_version = version_tuple(target)
            if release.get("prerelease") or release.get("draft") or target_version[0] != 2:
                raise ValueError("automatic updates require a stable TCP Brutal v2 release")
            result["target"] = target
            installed, loaded = module_versions()
            needed = not installed or version_tuple(installed) < target_version
            with tempfile.TemporaryDirectory(prefix="brutal-update-") as directory:
                script = Path(directory) / "install.sh"
                if needed:
                    script.write_bytes(fetch("https://tcp.hy2.sh/"))
                    subprocess.run(["bash", "-n", str(script)], check=True, timeout=10)
                with state_lock():
                    data = load_state()
                    save_state(data)  # Migrate legacy ownership before a module reload.
                    if needed and RULES.exists():
                        existing = {field[4:] for line in RULES.read_text().splitlines()
                                    for field in line.split() if field.startswith("dst=")}
                        if existing - data["entries"].keys():
                            raise RuntimeError("unmanaged Brutal rules exist; update manually to preserve those rules")
                    try:
                        if needed:
                            result["status"] = "updating"
                            atomic_write(state_path("update.json"), json.dumps(result, indent=2) + "\n")
                            run_installer(script, target)
                        elif not loaded:
                            subprocess.run(["modprobe", "brutal"], check=True, timeout=30)
                    finally:
                        READY_CACHE.clear()
                        _, errors = reconcile(data)
                    installed, loaded = module_versions()
                    result.update(installed=installed, loaded=loaded)
                    if not installed or version_tuple(installed) < target_version:
                        raise RuntimeError("the new module was not installed for the running kernel")
                    if not loaded or not RULES.exists() or not os.access(CTL, os.X_OK):
                        raise RuntimeError("TCP Brutal v2 or brutalctl is unavailable after update")
                    if errors:
                        raise RuntimeError(f"rule recovery pending: {errors}")
                    result["status"] = ("reboot_required" if version_tuple(loaded) != version_tuple(installed)
                                        else "updated" if needed else "up_to_date")
        except BaseException as error:
            result["status"] = "failed"
            result["error"] = str(error)
            raise
        finally:
            atomic_write(state_path("update.json"), json.dumps(result, indent=2) + "\n")
        print(f"TCP Brutal: {result['status']} (installed={installed}, loaded={loaded})")


def uninstall():
    subprocess.run(["systemctl", "disable", "--now", "brutal-ip-link-update.timer"], check=True)
    subprocess.run(["systemctl", "stop", "brutal-ip-link-update.service"], check=True)
    subprocess.run(["systemctl", "disable", "--now", "brutal-ip-link.service"], check=True)
    delete_prefix()  # On cleanup failure, retain files and retry state for the operator.
    for name in ("brutal-ip-link.service", "brutal-ip-link-update.service", "brutal-ip-link-update.timer"):
        (Path("/etc/systemd/system") / name).unlink(missing_ok=True)
    Path("/usr/local/sbin/brutal-ip-link").unlink(missing_ok=True)
    shutil.rmtree(CERT_DIR)
    shutil.rmtree(STATE.parent)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("brutal-ip-link and its tracked rules were removed. TCP Brutal remains installed.")


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

    parser = argparse.ArgumentParser(description="Manage authenticated client IPs for TCP Brutal")
    parser.add_argument("--config", type=Path, default=CONFIG)
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("serve", help="run the daemon (default)")
    commands.add_parser("check-config", help="validate configuration without changing rules")
    for name in ("status", "list", "doctor"):
        commands.add_parser(name).add_argument("--json", action="store_true")
    for name in ("add", "remove"):
        commands.add_parser(name).add_argument("ip", help="public IP or /32 or /128 host prefix")
    commands.add_parser("clear", help="remove all tracked IPs")
    commands.add_parser("reconcile", help="restore rules and retry outstanding cleanup")
    commands.add_parser("migrate-state", help="import legacy state without changing kernel rules")
    commands.add_parser("uninstall", help="remove this service and its tracked rules")
    commands.add_parser("update-brutal", help="update TCP Brutal to the latest stable v2 release").add_argument("--scheduled", action="store_true")
    args = parser.parse_args()
    configure(args.config)
    if args.command == "check-config":
        print("Configuration OK")
        return
    if args.command in ("status", "list", "doctor"):
        report = status_report()
        healthy = doctor_report(report) if args.command == "doctor" else True
        print_status(report, args.json, args.command == "list")
        if not healthy:
            raise SystemExit(1)
        return
    if os.geteuid() != 0:
        raise ValueError("run this command as root")
    os.umask(0o077)
    if args.command in ("add", "remove"):
        prefix = validate_prefix(args.ip) if "/" in args.ip else prefix_for(args.ip)
        update_prefix(prefix) if args.command == "add" else delete_prefix(prefix)
        print(f"{args.command}: {prefix}")
        return
    if args.command == "clear":
        delete_prefix()
        return
    if args.command == "reconcile":
        with state_lock():
            _, errors = reconcile(load_state())
        if errors:
            raise RuntimeError(f"recovery pending: {errors}")
        return
    if args.command == "migrate-state":
        with state_lock():
            save_state(load_state())
        return
    if args.command == "update-brutal":
        def interrupted(*_):
            raise InterruptedError("update interrupted")
        signal.signal(signal.SIGTERM, interrupted)
        update_brutal(args.scheduled)
        return
    if args.command == "uninstall":
        uninstall()
        return
    server = None
    if HTTPS:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(CERT_DIR / "cert.pem", CERT_DIR / "key.pem")
        server = TLSServer((HOST, PORT), Handler, tls)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    workers = [threading.Thread(target=maintain_rules, daemon=True)]
    if XRAY_UNIT:
        workers.append(threading.Thread(target=watch_xray, daemon=True))
    for worker in workers:
        worker.start()
    notify_ready()
    STOP.wait()
    process = XRAY_PROCESS
    if process is not None and process.poll() is None:
        process.terminate()
    if server:
        server.shutdown()
        server.server_close()
    for worker in workers:
        worker.join(timeout=15)
    with state_lock():
        data = load_state()
        merge_seen(data)
        if XRAY_STATUS:
            data["xray"] = dict(XRAY_STATUS, connected=False)
        save_state(data)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
