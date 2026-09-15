"""Run with python3 test_brutal_ip_link.py; add --tls for local socket checks."""
import importlib.util
import io
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from contextlib import ExitStack, redirect_stderr
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("app", Path(__file__).with_name("brutal-ip-link.py"))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def fails(function):
    try:
        function()
    except (ValueError, OSError, subprocess.CalledProcessError):
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
        self.calls = []

    def save(self):
        app.RULES.write_text("".join(f"dst={prefix} rate={rate} lock=1\n" for prefix, rate in self.rules.items()))

    def run(self, args, **kwargs):
        self.calls.append(args)
        output = ""
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


def check_updates():
    a, b, c = "8.8.8.8/32", "1.1.1.1/32", "9.9.9.9/32"
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
        for name, filename in (("STATE", "current-prefix"), ("PENDING", "pending-prefix"), ("RULES", "rules")):
            stack.enter_context(patch.object(app, name, Path(directory) / filename))
        stack.enter_context(patch.object(app, "TABLE", "10001"))
        kernel = Kernel()
        kernel.save()
        stack.enter_context(patch.object(app.subprocess, "run", side_effect=kernel.run))
        stack.enter_context(redirect_stderr(io.StringIO()))

        assert app.update_prefix(a)
        assert app.read_prefix(app.STATE) == a and not app.PENDING.exists()
        assert not app.update_prefix(a, force=False)
        assert app.update_prefix(a)  # Repeated manual updates must accept our existing policy route.
        assert not any(key[0] == "main" for key in kernel.routes)
        kernel.rules.clear()
        kernel.routes.clear()
        kernel.save()
        assert app.update_prefix(a, force=False)  # A saved file cannot hide missing live rules.
        kernel.routes.clear()
        assert app.update_prefix(a, force=False)  # Restore a missing route independently.

        kernel.failures.add(("del", a))
        fails(lambda: app.update_prefix(b))
        assert app.read_prefix(app.STATE) == a and app.read_prefix(app.PENDING) == b
        assert set(kernel.rules) == {a, b}
        kernel.failures.clear()
        assert app.update_prefix(force=False)
        assert set(kernel.rules) == {b} and app.read_prefix(app.STATE) == b
        assert not app.PENDING.exists()

        kernel.failures.add(("replace", c))
        fails(lambda: app.update_prefix(c))
        assert set(kernel.rules) == {b} and not app.PENDING.exists()  # Rollback succeeded.
        kernel.failures.add(("del", c))
        fails(lambda: app.update_prefix(c))
        assert app.read_prefix(app.PENDING) == c and set(kernel.rules) == {b, c}
        fails(lambda: app.update_prefix(a))  # Do not lose track of failed rollback.
        assert a not in kernel.rules and app.read_prefix(app.PENDING) == c
        kernel.failures.clear()
        assert app.update_prefix(a)
        assert set(kernel.rules) == {a} and app.read_prefix(app.STATE) == a

        replace = Path.replace

        def interrupted_commit(path, target):
            if target == app.STATE:
                raise OSError("simulated failed commit")
            return replace(path, target)

        with patch.object(Path, "replace", interrupted_commit):
            fails(lambda: app.update_prefix(b))
        assert app.read_prefix(app.STATE) == a  # The previous file was not truncated.
        assert app.read_prefix(app.PENDING) == b and set(kernel.rules) == {b}
        assert app.update_prefix(force=False)
        assert app.read_prefix(app.STATE) == b and not app.PENDING.exists()

        kernel.rules.clear()
        kernel.save()
        kernel.failures.add(("add", b))
        fails(lambda: app.update_prefix(force=False))
        assert app.read_prefix(app.PENDING) == b
        kernel.failures.clear()
        assert app.update_prefix(force=False)  # Startup recovery retries even for the same IP.

        kernel.routes["10001", c] = "proto static via 192.0.2.9 dev eth1"
        fails(lambda: app.update_prefix(c))
        assert kernel.routes["10001", c] == "proto static via 192.0.2.9 dev eth1"
        assert set(kernel.rules) == {b}
        before = len(kernel.calls)
        for invalid in ("0.0.0.0/0", "8.8.8.0/24", "127.0.0.1/32", "8.8.8.8/32\nflush"):
            fails(lambda: app.update_prefix(invalid))
        assert len(kernel.calls) == before


def check_installer():
    source = Path(__file__).with_name("install.sh").read_text()
    selection = source[source.index("old_table=$detected_table"):source.index("[[ ${#token}")]
    with tempfile.TemporaryDirectory() as directory:
        env = Path(directory) / "env"
        env.write_text("BRUTAL_LINK_TABLE=\nBRUTAL_LINK_XRAY_UNIT=\nBRUTAL_LINK_XRAY_EMAIL=owner\n")
        selection = selection.replace("/etc/brutal-ip-link/env", str(env))
        code = ('unset BRUTAL_LINK_TABLE BRUTAL_LINK_XRAY_UNIT BRUTAL_LINK_XRAY_EMAIL\n'
                'BRUTAL_LINK_TOKEN=not-used; detected_table=10001; detected_xray=xray.service\n'
                + selection + '\nprintf "%s|%s|%s" "$table" "$xray" "$email"\n')
        result = subprocess.run(["bash", "-eu"], input=code, text=True, capture_output=True, check=True)
        assert result.stdout == "||owner"


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
        update.assert_called_once_with("8.8.8.8/32")
        update.reset_mock()
        for path in ("/", "/wrong", "/" + token + "?extra=1", "/\xff"):
            assert b"404 Not Found" in request(path, "8.8.8.8")
        with redirect_stderr(io.StringIO()):
            assert b"500" in request("/" + token, "127.0.0.1", "X-Forwarded-For: 8.8.8.8\r\n")
        update.assert_not_called()


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


if __name__ == "__main__":
    for check in (check_logs, check_updates, check_installer, check_http_auth):
        check()
        print(check.__name__ + ": PASS")
    if "--tls" in sys.argv:
        check_tls()
        print("check_tls: PASS")
