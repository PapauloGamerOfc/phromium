#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Real-browser HTTPPS/cookie tests; no OS trust or certificate bypass changes.

Requires Python 3.11+, cryptography and the pinned tls20-server source. See
browser_e2e_README.md for the exact coverage and build/test commands.
"""

import argparse
import asyncio
import base64
from collections import deque
from contextlib import suppress
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import ssl
import struct
import subprocess
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit


SERVER_REVISION = "219f0a15a6c9d253feec78a6fc6010219aacc7b5"
HOST = "cookie.test"
MAX_MESSAGE = 4 * 1024 * 1024


class OwnedProcess:
    """Bounded subprocess operations also work with Windows' selector loop."""

    def __init__(self, process):
        self.process = process

    @classmethod
    async def start(cls, *arguments, **options):
        if sys.platform == "win32":
            options.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
        return cls(await asyncio.to_thread(subprocess.Popen, arguments, **options))

    @property
    def returncode(self):
        return self.process.poll()

    async def wait(self):
        try:
            return await asyncio.to_thread(self.process.wait, timeout=15)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Owned subprocess did not exit within 15 seconds") from error

    async def communicate(self):
        try:
            return await asyncio.to_thread(self.process.communicate, timeout=20)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Owned subprocess did not finish within 20 seconds") from error

    def kill(self):
        self.process.kill()


async def close_writer(writer):
    writer.close()
    with suppress(OSError, TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), 2)


class CDP:
    """Minimal loopback-only RFC6455 client; one command in flight at a time."""

    def __init__(self, reader, writer):
        self.reader, self.writer, self.sequence = reader, writer, 0
        self.events = deque(maxlen=64)

    @classmethod
    async def connect(cls, url):
        parts = urlsplit(url)
        if parts.scheme != "ws" or parts.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("CDP must remain on loopback")
        reader, writer = await asyncio.open_connection(parts.hostname, parts.port)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        writer.write((f"GET {parts.path} HTTP/1.1\r\nHost: {parts.netloc}\r\n"
                      f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        await writer.drain()
        response = await reader.readuntil(b"\r\n\r\n")
        expected = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        headers = dict(line.split(b":", 1) for line in response.split(b"\r\n")[1:] if b":" in line)
        headers = {name.lower(): value.strip() for name, value in headers.items()}
        if not response.startswith(b"HTTP/1.1 101 ") or headers.get(b"sec-websocket-accept") != expected:
            await close_writer(writer)
            raise RuntimeError("CDP WebSocket upgrade failed")
        return cls(reader, writer)

    async def send_frame(self, payload, opcode=1):
        mask = os.urandom(4)
        size = len(payload)
        header = bytes([0x80 | opcode])
        if size < 126:
            header += bytes([0x80 | size])
        elif size < 65536:
            header += bytes([0x80 | 126]) + struct.pack("!H", size)
        else:
            header += bytes([0x80 | 127]) + struct.pack("!Q", size)
        self.writer.write(header + mask + bytes(value ^ mask[index % 4]
                                               for index, value in enumerate(payload)))
        await self.writer.drain()

    async def receive(self):
        message = bytearray()
        started = False
        while True:
            first, second = await self.reader.readexactly(2)
            if first & 0x70 or second & 0x80:
                raise RuntimeError("Unexpected CDP frame flags")
            opcode, size = first & 15, second & 127
            if size == 126:
                size = struct.unpack("!H", await self.reader.readexactly(2))[0]
            elif size == 127:
                size = struct.unpack("!Q", await self.reader.readexactly(8))[0]
            if size > MAX_MESSAGE or len(message) + size > MAX_MESSAGE:
                raise RuntimeError("CDP frame limit exceeded")
            payload = await self.reader.readexactly(size)
            if opcode == 8:
                raise EOFError("Browser closed CDP")
            if opcode == 9:
                await self.send_frame(payload, 10)
                continue
            if opcode == 10:
                continue
            if opcode not in (0, 1) or (opcode == 0) != started:
                raise RuntimeError("Unexpected CDP data frame")
            started = True
            message.extend(payload)
            if first & 0x80:
                return json.loads(message)

    async def command(self, method, **params):
        self.sequence += 1
        identifier = self.sequence
        async with asyncio.timeout(30):
            await self.send_frame(json.dumps({"id": identifier, "method": method,
                                             "params": params}).encode())
            while True:
                result = await self.receive()
                if "method" in result:
                    self.events.append(result)
                if result.get("id") == identifier:
                    if "error" in result:
                        raise RuntimeError(f"{method}: {result['error']}")
                    return result.get("result", {})

    async def evaluate(self, expression):
        result = await self.command("Runtime.evaluate", expression=expression,
                                    returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in result:
            raise RuntimeError(result["exceptionDetails"])
        return result["result"].get("value")

    async def navigate(self, url, success=True):
        result = await self.command("Page.navigate", url=url)
        if not success:
            if not result.get("errorText"):
                raise AssertionError(f"Unexpected accepted navigation: {url}")
            return result["errorText"]
        if result.get("errorText"):
            raise AssertionError(f"Navigation rejected: {url}: {result}")
        async with asyncio.timeout(15):
            while True:
                with suppress(RuntimeError):
                    state = await self.evaluate("[location.href, document.readyState]")
                    if state[0] == url and state[1] == "complete":
                        return
                await asyncio.sleep(0.025)


async def debug_targets(port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        # DevTools echoes Host into webSocketDebuggerUrl, including the port.
        writer.write((f"GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                      "Connection: close\r\n\r\n").encode("ascii"))
        async with asyncio.timeout(5):
            await writer.drain()
            header = await reader.readuntil(b"\r\n\r\n")
            if not header.startswith(b"HTTP/1.1 200 "):
                raise ValueError("DevTools target discovery did not return HTTP 200")
            headers = dict(line.split(b":", 1) for line in header.split(b"\r\n")[1:]
                           if b":" in line)
            headers = {name.lower(): value.strip() for name, value in headers.items()}
            size = int(headers.get(b"content-length", b"-1"))
            if not 0 <= size <= MAX_MESSAGE or b"transfer-encoding" in headers:
                raise ValueError("Invalid DevTools target response framing")
            # Chromium's debugging server may keep the connection open even
            # with Connection: close. Read the framed body, not until EOF.
            result = json.loads(await reader.readexactly(size))
            if not isinstance(result, list):
                raise ValueError("DevTools target discovery did not return a list")
            return result
    finally:
        await close_writer(writer)


class Browser:
    def __init__(self, executable, profile, root=None, profile_config=None,
                 enable_network_sandbox=False, fixture_host=HOST):
        self.executable, self.profile, self.root = executable, profile, root
        self.profile_config = profile_config
        self.enable_network_sandbox = enable_network_sandbox
        self.fixture_host = fixture_host
        self.process = self.cdp = self.log = None

    async def __aenter__(self):
        self.profile.mkdir(exist_ok=True)
        active_port = self.profile / "DevToolsActivePort"
        active_port.unlink(missing_ok=True)
        arguments = [str(self.executable), "--headless=new", "--remote-debugging-port=0",
                     f"--user-data-dir={self.profile}", "--no-first-run", "--no-default-browser-check",
                     "--disable-background-networking", "--disable-component-update", "--disable-sync",
                     "--disable-extensions", "--disable-domain-reliability", "--no-proxy-server",
                     "--disable-features=OptimizationHints,MediaRouter,AutofillServerCommunication,Translate,EnablePortBoundCookies,EnableSchemeBoundCookies",
                     f"--host-resolver-rules=MAP {self.fixture_host} 127.0.0.1, MAP * ~NOTFOUND", "about:blank"]
        if self.root is not None:
            arguments.append("--httpps-trust-anchor=" + base64.b64encode(self.root).decode())
        if self.profile_config is not None:
            arguments.append("--httpps-profile-file=" + str(self.profile_config.resolve()))
        if self.enable_network_sandbox:
            arguments.append("--enable-features=NetworkServiceSandbox")
        self.log = (self.profile.parent / (self.profile.name + ".browser.log")).open("ab")
        stage = "spawning owned browser"
        last_probe = "DevToolsActivePort not observed"
        try:
            self.process = await OwnedProcess.start(
                *arguments, stdout=self.log, stderr=self.log,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            stage = "discovering page debugger"
            async with asyncio.timeout(45):
                while True:
                    if self.process.returncode is not None:
                        raise RuntimeError(f"Browser exited early: {self.process.returncode}")
                    if active_port.exists():
                        try:
                            # Windows can observe the file while Chrome still
                            # holds its writer handle. Retry within the same
                            # startup deadline as an incomplete DevTools reply.
                            lines = active_port.read_text().splitlines()
                            if lines:
                                targets = await debug_targets(int(lines[0]))
                                pages = [target for target in targets if target.get("type") == "page"]
                                last_probe = f"DevTools responded with {len(targets)} targets, {len(pages)} pages"
                                if pages:
                                    stage = "connecting page debugger WebSocket"
                                    self.cdp = await CDP.connect(pages[0]["webSocketDebuggerUrl"])
                                    break
                        except (OSError, ValueError, IndexError) as probe_error:
                            last_probe = repr(probe_error)
                            stage = "discovering page debugger"
                    await asyncio.sleep(0.05)
            stage = "enabling Page domain"
            await self.cdp.command("Page.enable")
            stage = "enabling Network domain"
            await self.cdp.command("Network.enable")
            stage = "disabling test HTTP cache"
            await self.cdp.command("Network.setCacheDisabled", cacheDisabled=True)
            return self.cdp
        except BaseException as error:
            error.add_note(f"Browser startup stage: {stage}; last probe: {last_probe}")
            # __aenter__ failures do not invoke __aexit__ automatically. Preserve
            # the startup error even if teardown must kill a stalled browser;
            # otherwise the diagnostically useful failure gets hidden.
            await self.__aexit__(type(error), error, error.__traceback__)
            raise

    async def __aexit__(self, exc_type, error, traceback):
        try:
            if self.cdp:
                with suppress(Exception):
                    await asyncio.wait_for(self.cdp.command("Browser.close"), 5)
                with suppress(Exception):
                    await close_writer(self.cdp.writer)
            if self.process:
                try:
                    # OwnedProcess.wait already bounds the blocking worker.
                    # A second equal timeout races it and leaves the worker
                    # running after cancellation of asyncio.to_thread.
                    await self.process.wait()
                except TimeoutError:
                    self.process.kill()
                    await self.process.wait()
                    raise RuntimeError("Browser did not close normally; persistence result invalid")
        except BaseException as cleanup_error:
            if error is None:
                raise
            error.add_note(f"Browser cleanup also failed: {cleanup_error!r}")
        finally:
            if self.log:
                self.log.close()
        return False


class Fixtures:
    def __init__(self, folder):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        from tls20_server.lab import generate_lab_credentials
        from tls20_server.pki import Credentials
        from tls20_server.tickets import TicketStore

        self.listeners, self.tasks, self.errors = [], set(), []
        self.requests = []
        self.attempts = {}
        self.application_bytes = {}
        self.ticket_store = TicketStore()
        self.early_sessions = []
        self.h2_connections = 0
        self.h2_requests = []
        now = datetime.now(timezone.utc)
        issuer_key = ec.generate_private_key(ec.SECP256R1())
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Browser local test CA")])
        issuer = (x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
                  .public_key(issuer_key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=2))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                  .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                  .sign(issuer_key, hashes.SHA256()))
        self.root = issuer.public_bytes(serialization.Encoding.DER)
        self.credentials = {}
        for kind in ("valid", "wrong-host", "expired", "bad-proof", "https"):
            key = ec.generate_private_key(ec.SECP256R1()) if kind == "https" else x25519.X25519PrivateKey.generate()
            certificate = (x509.CertificateBuilder()
                           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
                           .issuer_name(issuer_name).public_key(key.public_key())
                           .serial_number(x509.random_serial_number())
                           .not_valid_before(now - timedelta(days=1))
                           .not_valid_after(now + timedelta(hours=-1 if kind == "expired" else 24))
                           .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                           .add_extension(x509.KeyUsage(kind == "https", False, False, False,
                                                        kind != "https", False, False, False, False), True)
                           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                           .add_extension(x509.SubjectAlternativeName([
                               x509.DNSName("wrong.test" if kind == "wrong-host" else HOST)]), False)
                           .sign(issuer_key, hashes.SHA256()))
            if kind == "https":
                cert_path, key_path = folder / "https.pem", folder / "https.key"
                cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
                key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.ssl_context.load_cert_chain(cert_path, key_path)
            else:
                if kind == "bad-proof":
                    key = x25519.X25519PrivateKey.generate()
                self.credentials[kind] = Credentials([certificate.public_bytes(serialization.Encoding.DER)], key)
        self.credentials["untrusted"], _ = generate_lab_credentials(HOST)

    async def listen(self, callback, **options):
        def completed(task):
            self.tasks.discard(task)
            if not task.cancelled() and task.exception() is not None:
                error = task.exception()
                self.errors.append(repr(error))
                asyncio.get_running_loop().call_exception_handler({
                    "message": "Fixture connection task failed", "exception": error,
                })
        def dispatch(reader, writer):
            task = asyncio.create_task(callback(reader, writer))
            self.tasks.add(task)
            task.add_done_callback(completed)
        server = await asyncio.start_server(dispatch, "127.0.0.1", 0, **options)
        self.listeners.append(server)
        return server.sockets[0].getsockname()[1]

    def response(self, request, protocol):
        header = request.decode("iso-8859-1").split("\r\n")
        _, target, _ = header[0].split(" ", 2)
        fields = {name.lower(): value.strip() for name, value in
                  (line.split(":", 1) for line in header[1:] if ":" in line)}
        self.requests.append((protocol, target, fields.get("cookie", "")))
        path = urlsplit(target)
        value = parse_qs(path.query).get("value", [protocol])[0]
        if value not in ("http", "https", "httpps", "changed"):
            raise AssertionError("Unexpected cookie fixture value")
        secure = "; Secure" if protocol != "http" else ""
        extra = []
        if path.path == "/set":
            extra = [f"Set-Cookie: session={value}; Path=/; Max-Age=3600{secure}",
                     f"Set-Cookie: secret={protocol}-secret; Path=/; Max-Age=3600; HttpOnly{secure}"]
            if protocol == "httpps":
                # Isolation must hold even when the Secure flag itself would
                # not stop this cookie being sent to ordinary HTTP.
                extra.append("Set-Cookie: plain=httpps-plain; Path=/; Max-Age=3600")
        elif path.path == "/delete":
            extra = [f"Set-Cookie: session=; Path=/; Max-Age=0{secure}"]
        if path.path == "/echo":
            body = json.dumps({"cookie": fields.get("cookie", ""), "protocol": protocol}).encode()
            mime = "application/json"
        else:
            body = (b"<!doctype html><title>HTTPPS browser fixture</title>"
                    b"<link rel=icon href='data:,'><p>cookie fixture</p>")
            mime = "text/html"
        headers = ["HTTP/1.1 200 OK", f"Content-Length: {len(body)}", f"Content-Type: {mime}",
                   "Cache-Control: no-store", "Connection: close", *extra, "", ""]
        return "\r\n".join(headers).encode() + body

    async def http(self, reader, writer, protocol="http"):
        try:
            async with asyncio.timeout(10):
                request = await reader.readuntil(b"\r\n\r\n")
                writer.write(self.response(request, protocol))
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
            pass
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            await close_writer(writer)

    def record_application(self, kind, data):
        if data:
            self.application_bytes[kind] = self.application_bytes.get(kind, 0) + len(data)
            if kind != "valid":
                self.errors.append("Application bytes reached rejected fixture " + kind)

    async def httpps(self, reader, writer, kind="valid"):
        from tls20_server.errors import ProtocolError
        from tls20_server.handshake import server_handshake
        channel = None
        self.attempts[kind] = self.attempts.get(kind, 0) + 1
        try:
            async with asyncio.timeout(12):
                channel = await server_handshake(reader, writer, self.credentials[kind], HOST)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    data = await channel.recv()
                    if data is None:
                        return
                    self.record_application(kind, data)
                    request.extend(data)
                    if len(request) > 65536:
                        raise AssertionError("Request too large")
                await channel.send(self.response(request, "httpps"))
        except (ProtocolError, ConnectionError, asyncio.IncompleteReadError, TimeoutError):
            pass  # Speculative sockets and rejected certificates may close here.
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            if channel:
                await channel.close()
            else:
                await close_writer(writer)

    async def start(self):
        http_port = await self.listen(self.http)
        https_port = await self.listen(lambda r, w: self.http(r, w, "https"), ssl=self.ssl_context)
        self.secure_port = await self.listen(self.httpps)
        self.early_port = await self.listen(self.early_httpps)
        h2_secure_port = await self.listen(self.h2_httpps)
        self.negative_ports = {}
        for kind in ("wrong-host", "expired", "bad-proof", "untrusted"):
            self.negative_ports[kind] = await self.listen(lambda r, w, kind=kind: self.httpps(r, w, kind))

        async def relay(reader, writer):
            upstream = None
            async def pump(source, destination):
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()
            try:
                async with asyncio.timeout(30):
                    first = await reader.readexactly(1)
                    port = {b"T": self.secure_port, b"\x16": https_port}.get(first, http_port)
                    incoming, upstream = await asyncio.open_connection("127.0.0.1", port)
                    upstream.write(first)
                    await upstream.drain()
                    tasks = [asyncio.create_task(pump(reader, upstream)), asyncio.create_task(pump(incoming, writer))]
                    try:
                        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    finally:
                        for task in tasks:
                            task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
            except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
                pass
            finally:
                if upstream:
                    await close_writer(upstream)
                await close_writer(writer)
        self.port = await self.listen(relay)

        async def h2_relay(reader, writer):
            upstream = None
            tasks = []
            async def pump(source, destination):
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()
            try:
                async with asyncio.timeout(30):
                    first = await reader.readexactly(1)
                    # Same authority for HTTPS/HTTPPS checks. A reused HTTPPS
                    # pool entry must never satisfy an ordinary HTTPS request.
                    port = h2_secure_port if first == b"T" else https_port
                    incoming, upstream = await asyncio.open_connection("127.0.0.1", port)
                    upstream.write(first)
                    tasks = [asyncio.create_task(pump(reader, upstream)),
                             asyncio.create_task(pump(incoming, writer))]
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
                pass
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                if upstream:
                    await close_writer(upstream)
                await close_writer(writer)
        self.h2_port = await self.listen(h2_relay)

    async def h2_httpps(self, reader, writer):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import DataReceived, RequestReceived
        from tls20_server.errors import ProtocolError
        from tls20_server.handshake import server_handshake
        channel = None
        try:
            async with asyncio.timeout(30):
                channel = await server_handshake(reader, writer, self.credentials["valid"], HOST,
                                                 application_protocols=(b"h2",))
                self.h2_connections += 1
                assert channel.protocol == b"h2" and not channel.peer_post_handshake_auth
                connection = H2Connection(H2Configuration(client_side=False, header_encoding="utf-8"))
                connection.initiate_connection()
                await channel.send(connection.data_to_send())
                while (data := await channel.recv()) is not None:
                    for event in connection.receive_data(data):
                        if isinstance(event, RequestReceived):
                            headers = dict(event.headers)
                            self.h2_requests.append(headers)
                            if headers[":path"] == "/":
                                body = b"<!doctype html><title>HTTPPS h2</title><link rel=icon href='data:,'>h2"
                                mime = "text/html"
                            else:
                                body = json.dumps({"scheme": headers[":scheme"], "path": headers[":path"],
                                                   "cookie": headers.get("cookie", "")}).encode()
                                mime = "application/json"
                            connection.send_headers(event.stream_id, [
                                (":status", "200"), ("content-type", mime),
                                ("content-length", str(len(body))), ("cache-control", "no-store")])
                            connection.send_data(event.stream_id, body, end_stream=True)
                        elif isinstance(event, DataReceived):
                            connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if outgoing := connection.data_to_send():
                        await channel.send(outgoing)
        except (ProtocolError, ConnectionError, asyncio.IncompleteReadError, TimeoutError):
            pass
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            if channel:
                await channel.close()
            else:
                await close_writer(writer)

    async def early_httpps(self, reader, writer):
        """Separate replay-aware fixture; never relax the cookie-test peers."""
        from tls20_server.early_http import EarlyRequestGate, TOO_EARLY_RESPONSE
        from tls20_server.errors import ProtocolError
        from tls20_server.handshake import server_handshake
        gate = EarlyRequestGate(("/early", "/early-reject"), HOST, self.early_port, 16384)
        early_request = None
        channel = None

        async def accept_early(data):
            nonlocal early_request
            request = gate.feed(data)
            if request is not None:
                # This callback runs while server_handshake is still waiting
                # for client Finished. Do not infer 0-RTT merely from a ticket.
                early_request = request

        try:
            async with asyncio.timeout(12):
                channel = await server_handshake(
                    reader, writer, self.credentials["valid"], HOST,
                    ticket_store=self.ticket_store, max_early_data=16384,
                    on_early_data=accept_early)
                request = bytearray(early_request or b"")
                if not gate.rejected:
                    while b"\r\n\r\n" not in request:
                        data = await channel.recv()
                        if data is None:
                            return
                        request.extend(data)
                        if len(request) > 65536:
                            raise AssertionError("Early fixture request too large")
                target = bytes(request).split(b" ", 2)[1].decode("ascii") if request else "refused"
                self.early_sessions.append({
                    "resumed": channel.resumed,
                    "accepted": channel.early_data_accepted,
                    "before_finished": early_request is not None,
                    "target": target,
                })
                if gate.rejected or (early_request is not None and target == "/early-reject"):
                    await channel.send(TOO_EARLY_RESPONSE)
                else:
                    await channel.send(self.response(request, "httpps"))
        except (ProtocolError, ConnectionError, asyncio.IncompleteReadError, TimeoutError):
            pass
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            if channel:
                await channel.close()
            else:
                await close_writer(writer)

    async def close(self):
        for listener in self.listeners:
            listener.close()
        # Close active clients first: wait_closed can otherwise wait for their
        # transports to detach from the server. Never allow teardown to hang.
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        async with asyncio.timeout(10):
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.gather(*(listener.wait_closed() for listener in self.listeners))


def cookie_map(value):
    # Every fixture uses one host-only cookie per name, at Path=/. Duplicate
    # names would therefore indicate leakage or a browser error, not a valid
    # path/domain override. Never discard a leaked cookie by dict overwriting.
    result = {}
    for part in value.split(";"):
        if not part.strip():
            continue
        if "=" not in part:
            raise AssertionError("Malformed fixture cookie: " + part)
        name, content = part.strip().split("=", 1)
        if name in result:
            raise AssertionError("Duplicate fixture cookie name: " + name)
        result[name] = content
    return result


async def run(args, report):
    actual = subprocess.check_output(["git", "-C", str(args.server_source), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(args.server_source), "status", "--porcelain", "--", "tls20_server"], text=True)
    if (actual != SERVER_REVISION or dirty.strip()) and not args.allow_server_worktree:
        raise RuntimeError("Reference server must match the clean pinned revision " + SERVER_REVISION)
    source_hash = hashlib.sha256()
    for source in sorted((args.server_source / "tls20_server").glob("*.py")):
        source_hash.update(source.name.encode("utf-8") + b"\x00")
        source_hash.update(hashlib.sha256(source.read_bytes()).digest())
    sys.path.insert(0, str(args.server_source.resolve()))
    report["reference_server"] = actual
    report["reference_server_dirty"] = bool(dirty.strip())
    report["reference_server_source_sha256"] = source_hash.hexdigest()
    report["explicit_worktree_validation"] = args.allow_server_worktree
    report["checks"] = []
    def check(condition, message):
        if not condition:
            raise AssertionError(message)
        report["checks"].append(message)
        print("PASS:", message, flush=True)

    with tempfile.TemporaryDirectory(prefix="phromium-browser-test-") as temporary:
        folder = Path(temporary)
        fixtures = Fixtures(folder)
        await fixtures.start()
        http = f"http://{HOST}:{fixtures.port}"
        https = f"https://{HOST}:{fixtures.port}"
        httpps = f"httpps://{HOST}:{fixtures.port}"
        profile = folder / "profile"
        try:
            if args.fixtures_only_native:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                root = folder / "root.der"
                root.write_bytes(fixtures.root)
                for kind, port in [("valid", fixtures.port), *fixtures.negative_ports.items()]:
                    process = await OwnedProcess.start(str(args.fixtures_only_native), "--get", HOST,
                        str(port), str(root), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    try:
                        output, error = await process.communicate()
                    finally:
                        if process.returncode is None:
                            process.kill()
                            await process.wait()
                    check((process.returncode == 0) == (kind == "valid"), "native fixture " + kind)
                for encrypted in (False, True):
                    options = {}
                    if encrypted:
                        context = ssl.create_default_context()
                        context.load_verify_locations(cadata=x509.load_der_x509_certificate(
                            fixtures.root).public_bytes(serialization.Encoding.PEM).decode())
                        options = {"ssl": context, "server_hostname": HOST}
                    reader, writer = await asyncio.open_connection("127.0.0.1", fixtures.port, **options)
                    try:
                        writer.write(f"GET /echo HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode())
                        await writer.drain()
                        response = await asyncio.wait_for(reader.read(), 5)
                        body = json.loads(response.split(b"\r\n\r\n", 1)[1])
                        expected = "https" if encrypted else "http"
                        check(body["protocol"] == expected, "same-port multiplexer " + expected)
                    finally:
                        await close_writer(writer)
                check(not fixtures.errors, "Fixture servers reported no unexpected errors")
                return

            h2_origin = f"httpps://{HOST}:{fixtures.h2_port}"
            async with Browser(args.browser.resolve(), folder / "h2-profile", fixtures.root) as cdp:
                await cdp.navigate(h2_origin + "/")
                await cdp.evaluate("document.cookie='h2_session=isolated; Path=/; Secure'")
                responses = await cdp.evaluate(
                    "Promise.all(Array.from({length:16}, (_,i) => fetch('/stream/'+i).then(r=>r.json())))")
                check(len(responses) == 16 and all(item["scheme"] == "httpps" and
                      item["path"] == "/stream/" + str(i) and item["cookie"] == "h2_session=isolated"
                      for i, item in enumerate(responses)), "HTTPPS HTTP/2 multiplexes sixteen real requests with its own cookies")
                check(fixtures.h2_connections == 1, "HTTPPS HTTP/2 reuses one authenticated connection")
                check(await cdp.evaluate("performance.getEntriesByType('navigation')[0].nextHopProtocol") == "h2",
                      "Browser reports actually negotiated h2")
                before = len(fixtures.h2_requests)
                error = await cdp.navigate(f"https://{HOST}:{fixtures.h2_port}/", success=False)
                check(error == "net::ERR_CERT_AUTHORITY_INVALID" and len(fixtures.h2_requests) == before,
                      "HTTPS cannot reuse the HTTPPS h2 pool at the same authority")

            early_origin = f"httpps://{HOST}:{fixtures.early_port}"
            async with Browser(args.browser.resolve(), folder / "early-profile", fixtures.root) as cdp:
                await cdp.navigate(early_origin + "/early")
                for _ in range(3):
                    status = await cdp.evaluate(
                        "fetch('/early').then(async r => { await r.arrayBuffer(); return r.status; })")
                    check(status == 200, "HTTPPS repeat request succeeds on a fresh connection")
                check(any(item["resumed"] for item in fixtures.early_sessions),
                      "Browser actually resumes an HTTPPS session")
                check(any(item["accepted"] and item["before_finished"] for item in fixtures.early_sessions),
                      "Browser HTTPPS 0-RTT reaches peer before client Finished")
                before = len(fixtures.early_sessions)
                status = await cdp.evaluate(
                    "fetch('/early-reject').then(async r => { await r.arrayBuffer(); return r.status; })")
                retries = fixtures.early_sessions[before:]
                check(status == 200 and any(item["before_finished"] and item["target"] == "/early-reject" for item in retries)
                      and any(not item["before_finished"] and item["target"] == "/early-reject" for item in retries),
                      "Browser retries HTTP 425 without early data")
                report["early_sessions"] = fixtures.early_sessions

            async with Browser(args.browser.resolve(), profile, fixtures.root) as cdp:
                report["browser"] = await cdp.command("Browser.getVersion")
                await cdp.navigate(http + "/set")
                check(cookie_map(await cdp.evaluate("document.cookie")) == {"session": "http"},
                      "HTTP document.cookie hides HttpOnly")
                await cdp.navigate(httpps + "/echo")
                first_echo = json.loads(await cdp.evaluate("document.body.innerText"))
                check(first_echo["cookie"] == "", "HTTPPS initial network request receives no HTTP cookies")
                await cdp.navigate(httpps + "/set")
                check(await cdp.evaluate("isSecureContext") is True,
                      "HTTPPS is a secure context in the renderer")
                check(cookie_map(await cdp.evaluate("document.cookie")) ==
                      {"session": "httpps", "plain": "httpps-plain"},
                      "HTTPPS document.cookie is isolated and hides HttpOnly")
                echo = await cdp.evaluate("fetch('/echo').then(r => r.json())")
                check(cookie_map(echo["cookie"]) == {"session": "httpps", "secret": "httpps-secret",
                                                      "plain": "httpps-plain"},
                      "HTTPPS network sends only its own Secure, HttpOnly and non-Secure cookies")
                await cdp.evaluate("document.cookie='secret=modified; Path=/; Secure'")
                echo = await cdp.evaluate("fetch('/echo').then(r => r.json())")
                check(cookie_map(echo["cookie"])["secret"] == "httpps-secret", "HTTPPS script cannot overwrite HttpOnly cookie")
                await cdp.navigate(http + "/echo")
                echo = json.loads(await cdp.evaluate("document.body.innerText"))
                check(cookie_map(echo["cookie"]) == {"session": "http", "secret": "http-secret"},
                      "HTTP network receives no HTTPPS cookies, including non-Secure")
                check(cookie_map(await cdp.evaluate("document.cookie")) == {"session": "http"},
                      "HTTP document.cookie receives no HTTPPS non-Secure cookie")
                # Same host, same port: namespace boundaries cannot be caused by port isolation.
                result = await cdp.command("Network.setCookie", url=https, name="https_only", value="https",
                                           secure=True, httpOnly=True, expires=datetime.now(timezone.utc).timestamp() + 3600)
                check(result["success"], "HTTPS control cookie created through CDP without bypassing TLS")
                await cdp.navigate(httpps + "/")
                echo = await cdp.evaluate("fetch('/echo').then(r => r.json())")
                check("https_only" not in cookie_map(echo["cookie"]), "HTTPS control cookie never reaches HTTPPS")
                await cdp.evaluate("document.cookie='script=httpps-script; Path=/; Max-Age=3600; Secure'")
                await cdp.evaluate("document.cookie='session=changed; Path=/; Max-Age=3600; Secure'")
                check(cookie_map(await cdp.evaluate("document.cookie")) ==
                      {"session": "changed", "script": "httpps-script", "plain": "httpps-plain"},
                      "HTTPPS script write and overwrite take effect within their namespace")
                echo = await cdp.evaluate("fetch('/echo').then(r => r.json())")
                check(cookie_map(echo["cookie"]) == {"session": "changed", "secret": "httpps-secret",
                                                      "script": "httpps-script", "plain": "httpps-plain"},
                      "HTTPPS network observes the script overwrite without duplicate cookies")
                https_cookies = (await cdp.command("Network.getCookies", urls=[https]))["cookies"]
                check(any(c["name"] == "session" and c["value"] == "http" for c in https_cookies),
                      "HTTPPS script overwrite preserves shared HTTP/HTTPS session")
                check(not any(c["name"] in ("script", "plain") for c in https_cookies),
                      "HTTPPS script and non-Secure cookies are absent from HTTPS")
                await cdp.navigate(httpps + "/delete")
                check("session" not in cookie_map(await cdp.evaluate("document.cookie")), "HTTPPS expiry deletes its session")
                await cdp.navigate(http + "/")
                check(cookie_map(await cdp.evaluate("document.cookie"))["session"] == "http", "HTTPPS expiry preserves HTTP session")
                await cdp.navigate(httpps + "/set")
                await cdp.navigate(http + "/delete")
                await cdp.navigate(httpps + "/")
                check(cookie_map(await cdp.evaluate("document.cookie"))["session"] == "httpps", "HTTP expiry preserves HTTPPS session")
                await cdp.navigate(http + "/set")

            async with Browser(args.browser.resolve(), profile, fixtures.root) as cdp:
                await cdp.navigate(httpps + "/")
                actual = cookie_map(await cdp.evaluate("document.cookie"))
                check(actual == {"session": "httpps", "script": "httpps-script", "plain": "httpps-plain"},
                      "HTTPPS cookie namespace survives browser restart")
                echo = await cdp.evaluate("fetch('/echo').then(r => r.json())")
                check(cookie_map(echo["cookie"]) == {"session": "httpps", "secret": "httpps-secret",
                                                      "script": "httpps-script", "plain": "httpps-plain"},
                      "Restart preserves HTTPPS HttpOnly cookie without mixing namespaces")
                await cdp.navigate(http + "/")
                check(cookie_map(await cdp.evaluate("document.cookie")) == {"session": "http"}, "HTTP namespace survives browser restart")
                https_cookies = (await cdp.command("Network.getCookies", urls=[https]))["cookies"]
                check(any(c["name"] == "https_only" and c["value"] == "https" for c in https_cookies),
                      "HTTPS control cookie survives restart in its original namespace")
                before = len(fixtures.requests)
                error = await cdp.navigate(https + "/", success=False)
                check(error == "net::ERR_CERT_AUTHORITY_INVALID" and len(fixtures.requests) == before,
                      "Private HTTPPS CA does not authorize ordinary HTTPS (" + error + ")")
                for kind, port in fixtures.negative_ports.items():
                    before = len(fixtures.requests)
                    attempts = fixtures.attempts.get(kind, 0)
                    error = await cdp.navigate(f"httpps://{HOST}:{port}/", success=False)
                    expected = ("net::ERR_SSL_PROTOCOL_ERROR" if kind == "bad-proof" else
                                "net::ERR_SSL_SERVER_CERT_BAD_FORMAT")
                    check(error == expected and fixtures.attempts.get(kind, 0) > attempts and
                          fixtures.application_bytes.get(kind, 0) == 0 and len(fixtures.requests) == before,
                          f"HTTPPS {kind} rejected before HTTP application data ({error})")

            async with Browser(args.browser.resolve(), folder / "no-extra-root") as cdp:
                before = len(fixtures.requests)
                attempts = fixtures.attempts.get("valid", 0)
                application_bytes = fixtures.application_bytes.get("valid", 0)
                error = await cdp.navigate(httpps + "/", success=False)
                check(error == "net::ERR_SSL_SERVER_CERT_BAD_FORMAT" and
                      fixtures.attempts.get("valid", 0) > attempts and len(fixtures.requests) == before and
                      fixtures.application_bytes.get("valid", 0) == application_bytes,
                      f"Default browser verifier rejects unknown private CA ({error})")
            check(not fixtures.errors, "Fixture servers reported no unexpected errors")
        except BaseException:
            # Temporary profiles and keys still disappear on exit; retain only
            # bounded diagnostic text, never fixture private-key files.
            report["browser_stderr_tail"] = {}
            report["fixture_attempts"] = fixtures.attempts
            report["fixture_requests"] = fixtures.requests[-64:]
            report["fixture_errors"] = fixtures.errors[-64:]
            report["fixture_application_bytes"] = fixtures.application_bytes
            report["early_sessions"] = fixtures.early_sessions
            if "cdp" in locals():
                report["browser_events_tail"] = list(cdp.events)
            for log_path in folder.glob("*.browser.log"):
                with log_path.open("rb") as log:
                    log.seek(0, os.SEEK_END)
                    log.seek(max(0, log.tell() - 16384))
                    report["browser_stderr_tail"][log_path.name] = log.read().decode("utf-8", errors="replace")
            raise
        finally:
            await fixtures.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", type=Path, help="The built Phromium chrome.exe")
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--allow-server-worktree", action="store_true",
                        help="explicitly test local server edits; record revision, dirty state and source hash")
    parser.add_argument("--report", type=Path, help="Optional JSON result, including failures")
    parser.add_argument("--fixtures-only-native", type=Path, help="Validate fixture peers with native engine, NOT a browser test")
    args = parser.parse_args()
    if not args.browser and not args.fixtures_only_native:
        parser.error("--browser is required unless validating fixtures only")
    report = {"status": "running", "browser_test": not bool(args.fixtures_only_native),
              "coverage_note": "Private-CA browser integration. Public/default shared-root acceptance is covered separately by CertVerifyProcBuiltin tests.",
              "event_loop_errors": []}
    try:
        # Python 3.12's Windows Proactor transport can throw on shutdown after a
        # deliberate peer reset, before detaching from its server; wait_closed
        # then never completes. Selector networking avoids that runtime defect,
        # and our bounded Popen wrapper does not need Proactor subprocess pipes.
        loop_factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
        with asyncio.Runner(loop_factory=loop_factory) as runner:
            def loop_error(loop, context):
                report["event_loop_errors"].append({
                    "message": context.get("message", ""),
                    "exception": repr(context.get("exception")),
                })
                loop.default_exception_handler(context)
            runner.get_loop().set_exception_handler(loop_error)
            runner.run(run(args, report))
        if report["event_loop_errors"]:
            raise RuntimeError("Unexpected event-loop errors: " + repr(report["event_loop_errors"]))
        report["status"] = "passed"
    except BaseException as error:
        report["status"], report["error"] = "failed", repr(error)
        report["error_notes"] = list(getattr(error, "__notes__", ()))
        raise
    finally:
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
