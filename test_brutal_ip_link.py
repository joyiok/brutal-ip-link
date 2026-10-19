"""Run with python3 test_brutal_ip_link.py; add --tls for local socket checks."""
import importlib.util
import fcntl
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

spec = importlib.util.spec_from_file_location("app", Path(__file__).with_name("brutal-ip-link.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def fails(function):
    try:
        function()
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        return
    raise AssertionError("expected failure")


def check_logs():
    with patch.object(app, "XRAY_EMAIL", "owner"):
        lines = [
            "from 8.8.8.8:1 accepted tcp:127.0.0.1:45987 [dokodemo-in-test]",
            "from 1.1.1.1:2 accepted tcp:127.0.0.1:45987 [dokodemo-in-test]",
            "from 127.0.0.1:3 accepted tcp:example.com:443 [direct] email: owner",
            "2026/09/15 17:41:00.742476 from 8.8.8.8:1 accepted tcp:example.com:443 [auth -> direct] email: owner",
        ]
        assert [app.xray_source(line) for line in lines] == ["", "", "", "8.8.8.8/32"]
        for line in (
            "from 1.1.1.1:1 rejected tcp:example.com:443 [direct] email: owner",
            "from 1.1.1.1:1 accepted tcp:example.com:443 [direct] email: stranger",
            "from 1.1.1.1:1 accepted tcp:example.com:443 [direct] email: ",
            "error: from 1.1.1.1:1 accepted tcp:example.com:443 [direct] email: owner",
            "from 1.1.1.1:1 accepted tcp:fake email: owner [dokodemo-in]",
            "from 999.1.1.1:1 accepted tcp:example.com:443 [direct] email: owner",
        ):
            assert not app.xray_source(line), line
        assert app.xray_source("from tcp:[2606:4700:4700::1111]:1 accepted udp:example.com:53 [direct] email: owner") == "2606:4700:4700::1111/128"
        assert app.xray_source("from [::ffff:8.8.8.8]:1 accepted tcp:example.com:443 email: owner") == "8.8.8.8/32"
    for address in ("127.0.0.1", "10.0.0.1", "::1", "224.0.0.1", "ff02::1", "::ffff:127.0.0.1"):
        fails(lambda: app.prefix_for(address))


class Kernel:
    """Model the external CLI's rules and routes, including partial failures."""
    def __init__(self):
        self.rules = {}
        self.routes = {}
        self.failures = set()
        self.fail_listing = False
        self.calls = []

    def save(self):
        app.RULES.write_text("".join(f"dst={prefix} rate={rate} lock=1\n" for prefix, rate in self.rules.items()))

    def run(self, args, **kwargs):
        self.calls.append(args)
        output = ""
        if args[0] == "bash":
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == app.CTL:
            operation, prefix = args[1:3]
            if (operation, prefix) in self.failures:
                raise subprocess.CalledProcessError(1, args)
            if operation == "add":
                self.rules[prefix] = int(args[3]) * 125_000
                if "noroute" in args:
                    self.routes.pop(("main", prefix), None)
                else:
                    self.routes["main", prefix] = "proto 233 congctl lock brutal"
            else:
                self.rules.pop(prefix, None)
                self.routes.pop(("main", prefix), None)
            self.save()
        else:
            operation = args[3]
            table = args[args.index("table") + 1]
            if operation == "show":
                if args[-1] == "default":
                    output = "default via 192.0.2.1 dev eth0 src 192.0.2.2 onlink"
                elif "exact" not in args:
                    if self.fail_listing:
                        raise subprocess.CalledProcessError(1, args)
                    # A whole-table listing prints host routes without their prefix length.
                    output = "".join(
                        f"{prefix.split('/')[0]} {route.replace('proto 233 ', '')}\n"
                        for (name, prefix), route in self.routes.items()
                        if name == table and "proto 233" in route and (":" in prefix) == (args[1] == "-6"))
                else:
                    prefix = args[args.index("exact") + 1]
                    output = self.routes.get((table, prefix), "")
                    if "proto" in args and "proto 233" not in output:
                        output = ""
                    elif "proto" in args:
                        output = output.replace("proto 233 ", "")  # ip suppresses fields used as filters.
            else:
                prefix = args[4]
                if (operation, prefix) in self.failures:
                    raise subprocess.CalledProcessError(1, args)
                if operation == "replace":
                    assert "onlink" in args and "src" in args
                    self.routes[table, prefix] = "proto 233 congctl lock brutal"
                else:
                    self.routes.pop((table, prefix), None)
        return subprocess.CompletedProcess(args, 0, output, "")


A, B, C, D, E, F = (
    "8.8.8.8/32", "1.1.1.1/32", "9.9.9.9/32", "208.67.222.222/32",
    "8.8.4.4/32", "1.0.0.1/32",
)


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
        for name, filename in (("STATE", "current-prefix"), ("PENDING", "pending-prefix"), ("RULES", "rules")):
            stack.enter_context(patch.object(app, name, Path(directory) / filename))
        for name, value in (("TABLE", "10001"), ("RATE", 100), ("MAX_PREFIXES", 5),
                            ("TTL", 0), ("CACHE_SECONDS", 0), ("SEEN", {}),
                            ("READY_CACHE", {}), ("XRAY_STATUS", {})):
            stack.enter_context(patch.object(app, name, value))
        kernel = Kernel()
        kernel.save()
        stack.enter_context(patch.object(app.subprocess, "run", side_effect=kernel.run))
        stack.enter_context(redirect_stderr(io.StringIO()))
        yield kernel


def entries():
    return app.load_state()["entries"]


def desired():
    return {p for p, e in entries().items() if e["desired"]}


def check_updates():
    with fixture() as kernel:
        assert app.update_prefix(A)
        assert desired() == {A}
        assert not app.update_prefix(A, force=False)
        assert app.update_prefix(A)
        assert not any(key[0] == "main" for key in kernel.routes)
        kernel.rules.clear()
        kernel.routes.clear()
        kernel.save()
        assert app.update_prefix(A, force=False)
        kernel.routes.clear()
        assert app.update_prefix(A, force=False)
        for prefix in (B, C, D, E):
            app.update_prefix(prefix)
        app.update_prefix(A, force=False)  # Refresh LRU in memory before eviction.
        kernel.failures.add(("del", B))
        app.update_prefix(F)
        assert desired() == {A, C, D, E, F}
        assert not entries()[B]["desired"] and entries()[B]["error"]
        assert B in kernel.rules
        kernel.failures.clear()
        app.update_prefix(force=False)
        assert set(kernel.rules) == {A, C, D, E, F}
        assert B not in entries()
        before = len(kernel.calls)
        for invalid in ("0.0.0.0/0", "8.8.8.0/24", "127.0.0.1/32", "8.8.8.8/32\nflush"):
            fails(lambda: app.update_prefix(invalid))
        assert len(kernel.calls) == before


def check_retry_isolation():
    with fixture() as kernel:
        kernel.failures.add(("add", A))
        fails(lambda: app.update_prefix(A))
        assert entries()[A]["desired"] and entries()[A]["error"]
        assert A not in kernel.rules  # Rollback did not discard retry intent.
        kernel.failures.clear()
        app.update_prefix(force=False)
        assert A in kernel.rules and not entries()[A]["error"]
        app.update_prefix(B)
        app.update_prefix(C)
        kernel.rules.clear()
        kernel.routes.clear()
        kernel.save()
        kernel.failures.add(("add", A))
        app.update_prefix(force=False)
        assert set(kernel.rules) == {B, C}
        assert entries()[A]["error"]
        kernel.failures.clear()
        app.update_prefix(force=False)
        assert set(kernel.rules) == {A, B, C}
    with fixture() as kernel:
        kernel.failures.add(("replace", A))
        kernel.failures.add(("del", A))
        fails(lambda: app.update_prefix(A))
        assert A in kernel.rules and entries()[A]["error"]
        app.update_prefix(B)  # A failed rollback doesn't block another address.
        assert B in kernel.rules
        kernel.failures.clear()
        app.update_prefix(force=False)
        assert all(not e["error"] for e in entries().values())
    with fixture() as kernel:
        kernel.failures.add(("add", A))
        fails(lambda: app.update_prefix(A, force=False))
        before = len(kernel.calls)
        latest = app.time.time() + 100
        with patch.object(app.os, "fsync", wraps=app.os.fsync) as fsync:
            for offset in range(10):
                assert not app.update_prefix(A, force=False, seen_at=latest - offset)
            assert len(kernel.calls) == before and fsync.call_count == 0  # No retry per connection log.
        kernel.failures.clear()
        app.update_prefix(force=False)
        assert A in kernel.rules and not entries()[A]["error"]
        assert entries()[A]["last_seen"] == latest  # Skipped logs still refresh LRU order.


def check_state_recovery():
    with fixture() as kernel:
        app.STATE.write_text(A + "\n" + B + "\n")
        app.PENDING.write_text(C + "\n")
        app.update_prefix(force=False)
        assert desired() == {A, B, C} and set(kernel.rules) == {A, B, C}
        # Retained legacy files must never resurrect a removed address.
        app.delete_prefix(A)
        assert A not in entries()
        assert app.STATE.exists()
    with fixture() as kernel, patch.object(app, "MAX_PREFIXES", 2):
        app.STATE.write_text(A + "\n" + B + "\n")
        app.PENDING.write_text(C + "\n")
        kernel.failures.add(("add", C))
        app.update_prefix(force=False)
        assert set(kernel.rules) == {A, B}  # A legacy pending failure cannot evict saved IPs.
    with fixture() as kernel:
        replace = Path.replace
        def fail_commit(path, target):
            if target == app.state_path():
                raise OSError("simulated failed state commit")
            return replace(path, target)
        with patch.object(Path, "replace", fail_commit):
            fails(lambda: app.update_prefix(A))
        assert not kernel.calls and not kernel.rules
        app.update_prefix(A)
        kernel.rules.clear()
        kernel.routes.clear()
        kernel.save()
        with patch.object(Path, "replace", fail_commit):
            fails(lambda: app.update_prefix(A))
        assert desired() == {A}  # An interrupted post-kernel commit is recoverable.
        app.update_prefix(force=False)
        assert kernel.rules and not entries()[A]["error"]


def check_table_migration():
    with fixture() as kernel:
        app.update_prefix(A)
        with patch.object(app, "TABLE", "10002"):
            kernel.failures.add(("replace", A))
            app.update_prefix(force=False)
            assert ("10001", A) in kernel.routes
            assert set(entries()[A]["tables"]) == {"10001", "10002"}
            kernel.failures.clear()
            app.update_prefix(force=False)
            assert ("10001", A) not in kernel.routes and ("10002", A) in kernel.routes
            assert entries()[A]["tables"] == ["10002"]
            app.delete_prefix(A)
            assert not kernel.rules and not kernel.routes
    with fixture() as kernel:
        kernel.routes["10001", A] = "proto static via 192.0.2.9 dev eth1"
        fails(lambda: app.update_prefix(A))
        assert "proto static" in kernel.routes["10001", A]
        assert A not in kernel.rules
        app.delete_prefix(A)
        assert "proto static" in kernel.routes["10001", A]
    with fixture() as kernel, patch.object(app, "TABLE", ""):
        kernel.routes["main", A] = "proto static via 192.0.2.9 dev eth1"
        fails(lambda: app.update_prefix(A))
        assert A not in kernel.rules  # Main-table routes receive the same protection.


def check_ttl_and_cache():
    with fixture() as kernel, patch.object(app, "CACHE_SECONDS", 5):
        app.update_prefix(A)
        app.update_prefix(B)
        before = len(kernel.calls)
        latest = app.time.time() + 100
        with patch.object(app.os, "fsync", wraps=app.os.fsync) as fsync, \
                patch.object(app, "load_state", wraps=app.load_state) as load:
            for prefix in [A, B] * 10:
                app.update_prefix(prefix, force=False, seen_at=latest)
            assert len(kernel.calls) == before and fsync.call_count == 0 and load.call_count == 0
        kernel.rules.clear()
        kernel.routes.clear()
        kernel.save()
        app.update_prefix(force=False)  # Maintenance must bypass the cache.
        assert set(kernel.rules) == {A, B}
        assert entries()[A]["last_seen"] == latest  # Cached logs still refresh LRU order.
    with fixture() as kernel, patch.object(app, "TTL", 60):
        with patch.object(app.time, "time", return_value=100):
            app.update_prefix(A)
        with patch.object(app.time, "time", return_value=130):
            app.update_prefix(B)
        with patch.object(app.time, "time", return_value=161):
            app.update_prefix(force=False)
        assert desired() == {B} and set(kernel.rules) == {B}
        app.delete_prefix()
        assert not entries() and not kernel.rules and not kernel.routes
    with fixture() as kernel, patch.object(app, "MAX_PREFIXES", 2):
        app.update_prefix(A)
        app.update_prefix(B)
        kernel.failures.add(("add", C))
        fails(lambda: app.update_prefix(C))
        app.update_prefix(force=False)
        assert set(kernel.rules) == {A, B}  # Failed newcomers do not evict working IPs.
        kernel.failures.clear()
        app.update_prefix(force=False)
        assert set(kernel.rules) == {B, C}


def check_batched_checks():
    with fixture() as kernel, patch.object(app, "MAX_PREFIXES", 100), \
            patch.object(app, "module_versions", return_value=("2.0.1", "2.0.1")):
        prefixes = [f"8.8.0.{i}/32" for i in range(1, 61)] + ["2606:4700:4700::1111/128"]
        for prefix in prefixes:
            app.update_prefix(prefix)
        before = len(kernel.calls)
        app.update_prefix(force=False)
        assert len(kernel.calls) - before == 2  # One route listing per family, not one ip call per address.
        assert all(row["ready"] for row in app.status_report()["entries"])
        del kernel.routes["10001", prefixes[0]]
        app.update_prefix(force=False)
        assert ("10001", prefixes[0]) in kernel.routes  # Missing from the listing, so checked and repaired.
        kernel.fail_listing = True
        del kernel.routes["10001", prefixes[1]]
        app.update_prefix(force=False)
        assert ("10001", prefixes[1]) in kernel.routes  # Without a listing, addresses are checked one by one.


def check_installer():
    source = Path(__file__).with_name("install.sh").read_text()
    selection = source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    with tempfile.TemporaryDirectory() as directory:
        old = Path(directory) / "old-env"
        target = Path(directory) / "new-env"
        old.write_text("BRUTAL_LINK_TABLE=\nBRUTAL_LINK_XRAY_UNIT=\nBRUTAL_LINK_XRAY_EMAIL=owner\n"
                       "BRUTAL_LINK_TOKEN=" + "t" * 48 + "\nBRUTAL_LINK_HTTPS=0\nBRUTAL_LINK_AUTO_UPDATE=0\n")
        selection = selection.replace("/etc/brutal-ip-link/env", str(old))
        environment = {k: v for k, v in os.environ.items() if not k.startswith("BRUTAL_LINK_")}
        subprocess.run([sys.executable, "-", str(target), "10001", "xray.service"],
                       input=selection, text=True, check=True, env=environment)
        values = dict(line.split("=", 1) for line in target.read_text().splitlines())
        assert values["BRUTAL_LINK_TABLE"] == values["BRUTAL_LINK_XRAY_UNIT"] == ""
        assert values["BRUTAL_LINK_HTTPS"] == values["BRUTAL_LINK_AUTO_UPDATE"] == "0"
        assert values["BRUTAL_LINK_TOKEN"] == "t" * 48
        assert values["BRUTAL_LINK_MAX_PREFIXES"] == "5"
        environment["BRUTAL_LINK_MAX_PREFIXES"] = "10"
        subprocess.run([sys.executable, "-", str(target), "10001", "xray.service"],
                       input=selection, text=True, check=True, env=environment)
        assert "BRUTAL_LINK_MAX_PREFIXES=10" in target.read_text()


def check_config_and_cli():
    with fixture() as kernel, ExitStack() as stack:
        names = ("TOKEN", "RATE", "TABLE", "XRAY_UNIT", "XRAY_EMAIL", "MAX_PREFIXES", "TTL", "HTTPS", "HOST", "PORT", "AUTO_UPDATE")
        for name in names:
            stack.enter_context(patch.object(app, name, getattr(app, name)))
        stack.enter_context(patch.dict(os.environ, {}, clear=True))
        config = app.STATE.parent / "env"
        config.write_text("BRUTAL_LINK_HTTPS=0\nBRUTAL_LINK_TABLE=10001\nBRUTAL_LINK_AUTO_UPDATE=0\nBRUTAL_LINK_HOST=::\nBRUTAL_LINK_PORT=9443\n")
        app.configure(config)
        assert not app.HTTPS and app.HOST == "::" and app.PORT == 9443
        with patch.dict(os.environ, {"BRUTAL_LINK_TTL": "-1"}):
            fails(lambda: app.configure(config))
        with patch.dict(os.environ, {"BRUTAL_LINK_HTTPS": "01"}):
            fails(lambda: app.configure(config))
        with patch.dict(os.environ, {"BRUTAL_LINK_TABLE": "0254"}):
            app.configure(config)
            assert app.TABLE == ""
        stack.enter_context(patch.object(app.os, "geteuid", return_value=0))
        def cli(*args):
            output = io.StringIO()
            with patch.object(sys, "argv", ["brutal-ip-link", "--config", str(config), *args]), redirect_stdout(output):
                app.main()
            return output.getvalue()
        cli("add", "8.8.8.8")
        assert A in kernel.rules
        with patch.object(app, "module_versions", return_value=("2.0.1", "2.0.1")):
            report = json.loads(cli("status", "--json"))
            assert report["entries"][0]["ready"] and "token" not in report["config"]
            assert json.loads(cli("list", "--json"))[0]["prefix"] == A
            with patch.object(app, "command_output", return_value="active"), patch.object(app.os, "access", return_value=True):
                assert all(c["ok"] for c in json.loads(cli("doctor", "--json"))["checks"])
        cli("remove", "8.8.8.8")
        assert not entries() and not kernel.routes


def check_installer_flow():
    # Execute the whole installer with all installation paths redirected into a
    # temporary tree and systemctl/ip replaced; no root or real routing required.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        fake_bin = root / "bin"
        fake_bin.mkdir()
        paths = ("/etc/brutal-ip-link", "/var/lib/brutal-ip-link", "/usr/local/sbin",
                 "/usr/local/bin", "/etc/systemd/system")
        for path in paths:
            (root / path.lstrip("/")).mkdir(parents=True, exist_ok=True)
        for filename in ("install.sh", "brutal-ip-link.py", "brutal-ip-link.service",
                         "brutal-ip-link-update.service", "brutal-ip-link-update.timer"):
            text = Path(__file__).with_name(filename).read_text()
            for path in paths:
                text = text.replace(path, str(root / path.lstrip("/")))
            text = text.replace("if (( EUID != 0 )); then", "if false; then")
            text = text.replace("if os.geteuid() != 0:", "if False:")
            (source / filename).write_text(text)
        ctl = root / "usr/local/bin/brutalctl"
        ctl.write_text("#!/bin/sh\nexit 0\n")
        ctl.chmod(0o755)
        systemctl = fake_bin / "systemctl"
        systemctl.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$INSTALL_TEST_LOG\"\nexit 0\n")
        systemctl.chmod(0o755)
        ip = fake_bin / "ip"
        ip.write_text("#!/bin/sh\necho '1.1.1.1 via 192.0.2.1 dev eth0 table 10001 src 8.8.8.8'\n")
        ip.chmod(0o755)
        config = root / "etc/brutal-ip-link/env"
        config.write_text("BRUTAL_LINK_TOKEN=" + "t" * 48 + "\nBRUTAL_LINK_TABLE=10001\n"
                          "BRUTAL_LINK_XRAY_UNIT=\nBRUTAL_LINK_HTTPS=0\nBRUTAL_LINK_AUTO_UPDATE=0\n")
        (root / "var/lib/brutal-ip-link/current-prefix").write_text(A + "\n")
        log = root / "commands"
        environment = {k: v for k, v in os.environ.items() if not k.startswith("BRUTAL_LINK_")}
        environment.update(PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                           INSTALL_TEST_LOG=str(log), BRUTAL_LINK_TABLE="10002")
        result = subprocess.run(["bash", str(source / "install.sh")], env=environment,
                                text=True, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert "HTTPS disabled" in result.stdout
        assert "BRUTAL_LINK_TABLE=10002" in config.read_text()
        state = json.loads((root / "var/lib/brutal-ip-link/state.json").read_text())
        assert state["entries"][A]["tables"] == ["10001"]
        assert "disable --now brutal-ip-link-update.timer" in log.read_text()
        assert (root / "usr/local/sbin/brutal-ip-link").stat().st_mode & 0o777 == 0o755
        assert config.stat().st_mode & 0o777 == 0o600
        environment["BRUTAL_LINK_AUTO_UPDATE"] = "1"
        subprocess.run(["bash", str(source / "install.sh")], env=environment,
                       check=True, capture_output=True, timeout=20)
        assert "enable --now brutal-ip-link-update.timer" in log.read_text()
        assert "BRUTAL_LINK_TOKEN=" + "t" * 48 in config.read_text()


def check_journal_recovery():
    for seen, expected in ((190, True), (100, False)):
        with fixture() as kernel, patch.object(app, "TTL", 60), patch.object(app, "XRAY_UNIT", "xray.service"), \
                patch.object(app.time, "time", return_value=200), patch.object(app, "STOP", threading.Event()):
            event = {"MESSAGE": "from 8.8.8.8:1 accepted tcp:example.com:443 email: owner",
                     "__CURSOR": "cursor-1", "__REALTIME_TIMESTAMP": str(seen * 1_000_000)}
            process = Mock(returncode=0)
            process.stdout = io.StringIO(json.dumps(event) + "\n")
            process.poll.return_value = 0
            kernel.failures.add(("add", A))
            with patch.object(app.subprocess, "Popen", return_value=process), \
                    patch.object(app.STOP, "wait", side_effect=lambda _: app.STOP.set()):
                app.watch_xray()
            assert app.XRAY_STATUS["cursor"] == "cursor-1"
            assert (A in entries()) == expected
            if expected:
                assert entries()[A]["last_seen"] == seen
                assert entries()[A]["error"]
                kernel.failures.clear()
                app.update_prefix(force=False)
                assert A in kernel.rules
                assert app.load_state()["xray"]["cursor"] == "cursor-1"
    with fixture() as kernel, patch.object(app, "XRAY_UNIT", "xray.service"), \
            patch.object(app, "STOP", threading.Event()):
        app.state_path().write_text("{")
        event = {"MESSAGE": "from 8.8.8.8:1 accepted tcp:example.com:443 email: owner", "__CURSOR": "cursor-2"}
        process = Mock(returncode=0)
        process.stdout = io.StringIO(json.dumps(event) + "\n")
        process.poll.return_value = 0
        def wait(_):
            if app.state_path().read_text() == "{":
                app.state_path().unlink()  # The operator repairs the state file.
            else:
                app.STOP.set()
        with patch.object(app.subprocess, "Popen", return_value=process), \
                patch.object(app.STOP, "wait", side_effect=wait), redirect_stdout(io.StringIO()):
            app.watch_xray()
        assert A in kernel.rules  # Detection resumes without restarting the daemon.


def check_ready_notification():
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / "notify")
        name = f"brutal-ip-link-test-{os.getpid()}"
        for address, bound in ((path, path), ("@" + name, "\0" + name)):
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver, \
                    patch.dict(os.environ, {"NOTIFY_SOCKET": address}):
                receiver.bind(bound)
                receiver.settimeout(2)
                app.notify_ready()
                assert receiver.recv(64) == b"READY=1"
                assert "NOTIFY_SOCKET" not in os.environ  # Child commands must not inherit it.
    with patch.dict(os.environ, {}, clear=True):
        app.notify_ready()  # Not started by systemd.


def check_locking_and_uninstall():
    with fixture() as kernel, patch.object(app, "module_versions", return_value=("2.0.1", "2.0.1")):
        app.update_prefix(A)
        with app.state_path("state.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            fails(lambda: app.update_prefix(B, lock_timeout=0.01))
            assert app.status_report()["entries"][0]["ready"]
        app.update_prefix(B, lock_timeout=0.01)
        assert B in kernel.rules
        original_run = kernel.run
        def command(args, **kwargs):
            if args[0] == "systemctl":
                return subprocess.CompletedProcess(args, 0)
            return original_run(args, **kwargs)
        kernel.failures.add(("del", A))
        with patch.object(app.subprocess, "run", side_effect=command), patch.object(app.shutil, "rmtree") as remove:
            fails(app.uninstall)
            remove.assert_not_called()
        assert entries()[A]["error"] and app.state_path().exists()
        kernel.failures.clear()
        with patch.object(app.subprocess, "run", side_effect=command), patch.object(app.shutil, "rmtree") as remove, \
                patch.object(Path, "unlink") as unlink, redirect_stdout(io.StringIO()):
            app.uninstall()
            assert remove.call_count == 2 and unlink.call_count == 4
        assert not kernel.rules and not kernel.routes


def check_updater():
    for outcome in ("updated", "reboot_required", "up_to_date", "failed"):
        with fixture() as kernel, ExitStack() as stack:
            app.update_prefix(A)
            needed = outcome != "up_to_date"
            before = ("2.0.0", "2.0.0") if needed else ("2.0.1", "2.0.1")
            after = ("2.0.1", "2.0.0" if outcome == "reboot_required" else "2.0.1")
            stack.enter_context(patch.object(app, "module_versions", side_effect=[before, after]))
            fetch = stack.enter_context(patch.object(app, "fetch", side_effect=[
                json.dumps({"tag_name": "v2.0.1", "prerelease": False}).encode(), b"#!/bin/bash\nexit 0\n"]))
            stack.enter_context(patch.object(app.os, "access", return_value=True))
            def install(*_):
                kernel.rules.clear()
                kernel.save()
                if outcome == "failed":
                    raise RuntimeError("build failed")
            installer = stack.enter_context(patch.object(app, "run_installer", side_effect=install))
            with redirect_stdout(io.StringIO()):
                if outcome == "failed":
                    fails(app.update_brutal)
                else:
                    app.update_brutal()
            result = json.loads(app.state_path("update.json").read_text())
            assert result["status"] == outcome
            assert A in kernel.rules  # Also restored after an installer failure.
            assert installer.call_count == int(needed)
            assert fetch.call_count == (2 if needed else 1)
    with fixture() as kernel, patch.object(app, "AUTO_UPDATE", False), patch.object(app, "fetch") as fetch:
        with redirect_stdout(io.StringIO()):
            app.update_brutal(scheduled=True)
        fetch.assert_not_called()
    with fixture() as kernel, ExitStack() as stack:
        kernel.rules[A] = 12500000  # Not tracked by this tool.
        kernel.save()
        stack.enter_context(patch.object(app, "module_versions", return_value=("2.0.0", "2.0.0")))
        stack.enter_context(patch.object(app, "fetch", side_effect=[b'{"tag_name":"v2.0.1"}', b"exit 0"]))
        installer = stack.enter_context(patch.object(app, "run_installer"))
        fails(app.update_brutal)
        installer.assert_not_called()
        assert A in kernel.rules
    process = MagicMock()
    process.__enter__.return_value = process
    process.pid = 12345
    process.poll.return_value = None
    process.wait.side_effect = [subprocess.TimeoutExpired("installer", 1800), 0]
    with patch.object(app.subprocess, "Popen", return_value=process), patch.object(app.os, "killpg") as kill:
        fails(lambda: app.run_installer(Path("/unused/installer"), "v2.0.1"))
        kill.assert_called_once_with(process.pid, app.signal.SIGTERM)


def check_http_auth():
    token = "t" * 48

    def request(path, address, headers=""):
        peer = Mock()
        peer.makefile.return_value = io.BytesIO(
            f"GET {path} HTTP/1.0\r\n{headers}\r\n".encode("latin-1"))
        output = io.BytesIO()
        peer.sendall.side_effect = output.write
        app.Handler(peer, (address, 12345), Mock())
        return output.getvalue()

    with patch.object(app, "TOKEN", token), patch.object(app, "update_prefix") as update:
        response = request("/" + token, "8.8.8.8")
        assert b"200 OK" in response and b"8.8.8.8/32" in response
        update.assert_called_once_with("8.8.8.8/32", lock_timeout=5)
        update.reset_mock()
        for path in ("/", "/wrong", "/" + token + "?extra=1", "/\xff"):
            assert b"404 Not Found" in request(path, "8.8.8.8")
        with redirect_stderr(io.StringIO()):
            assert b"500" in request("/" + token, "127.0.0.1", "X-Forwarded-For: 8.8.8.8\r\n")
        update.assert_not_called()
        update.side_effect = TimeoutError("busy")
        assert b"503 " in request("/" + token, "8.8.8.8")


def check_tls():
    with tempfile.TemporaryDirectory() as directory:
        key, cert = Path(directory) / "key.pem", Path(directory) / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost"],
                       check=True, capture_output=True, timeout=15)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        server = app.TLSServer(("127.0.0.1", 0), app.Handler, tls)
        server.request_timeout = 0.5
        serving = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        serving.start()
        client_tls = ssl._create_unverified_context()

        def request(path=b"/"):
            with socket.create_connection(server.server_address, timeout=2) as raw:
                with client_tls.wrap_socket(raw, server_hostname="localhost") as client:
                    client.sendall(b"GET " + path + b" HTTP/1.0\r\n\r\n")
                    assert b"404" in client.recv(4096)

        try:
            with socket.create_connection(server.server_address, timeout=2) as idle:
                request()  # A stalled TLS handshake cannot block another client.
                assert idle.recv(1) == b""  # The handshake expires.
            with socket.create_connection(server.server_address, timeout=2) as raw:
                with client_tls.wrap_socket(raw, server_hostname="localhost") as idle:
                    idle.sendall(b"GET /")
                    request()  # An incomplete HTTP request cannot block another client.
                    assert idle.recv(1) == b""
            request(b"/\xff")  # Non-ASCII paths do not crash compare_digest.
            with patch.object(server, "tls") as context, patch.object(
                server, "finish_request", side_effect=ConnectionResetError
            ), patch.object(server, "handle_error") as error:
                peer = Mock()
                context.wrap_socket.return_value = peer
                assert server.slots.acquire(blocking=False)
                server.process_request_thread(peer, ("127.0.0.1", 1))
                error.assert_not_called()
                peer.close.assert_called_once()
        finally:
            server.shutdown()
            server.server_close()
            serving.join(timeout=2)
        if socket.has_ipv6:
            server6 = app.TLSServer(("::1", 0), app.Handler, tls)
            serving6 = threading.Thread(target=server6.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            serving6.start()
            try:
                with socket.create_connection(("::1", server6.server_address[1]), timeout=2) as raw:
                    with client_tls.wrap_socket(raw, server_hostname="localhost") as client:
                        client.sendall(b"GET / HTTP/1.0\r\n\r\n")
                        assert b"404" in client.recv(4096)
            finally:
                server6.shutdown()
                server6.server_close()
                serving6.join(timeout=2)


if __name__ == "__main__":
    for check in (check_logs, check_updates, check_retry_isolation, check_state_recovery,
                  check_table_migration, check_ttl_and_cache, check_batched_checks, check_installer,
                  check_config_and_cli, check_installer_flow, check_journal_recovery,
                  check_ready_notification, check_locking_and_uninstall, check_updater,
                  check_http_auth):
        check()
        print(check.__name__ + ": PASS")
    if "--tls" in sys.argv:
        check_tls()
        print("check_tls: PASS")
