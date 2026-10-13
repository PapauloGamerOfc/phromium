#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Local tests of the test harness transport; these do not test the browser."""

import asyncio
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from browser_e2e_test import (Browser, CDP, Fixtures, MAX_MESSAGE, OwnedProcess,
                              close_writer, cookie_map, debug_targets)


class CDPTest(unittest.IsolatedAsyncioTestCase):
    async def test_owned_process_communicates_without_asyncio_subprocess_transport(self):
        process = await OwnedProcess.start(sys.executable, "-c", "print('fixture-child-ok')",
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            output, error = await process.communicate()
            self.assertEqual(output.strip(), b"fixture-child-ok")
            self.assertEqual(error, b"")
            self.assertEqual(await process.wait(), 0)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    async def test_owned_process_worker_operations_have_real_timeouts(self):
        child = Mock()
        child.wait.side_effect = subprocess.TimeoutExpired("fixture", 15)
        child.communicate.side_effect = subprocess.TimeoutExpired("fixture", 20)
        process = OwnedProcess(child)
        with self.assertRaises(TimeoutError):
            await process.wait()
        with self.assertRaises(TimeoutError):
            await process.communicate()
        child.wait.assert_called_once_with(timeout=15)
        child.communicate.assert_called_once_with(timeout=20)

    def test_partial_application_data_is_recorded_before_complete_http_header(self):
        fixtures = Fixtures.__new__(Fixtures)
        fixtures.application_bytes, fixtures.errors = {}, []
        fixtures.record_application("expired", b"G")
        self.assertEqual(fixtures.application_bytes, {"expired": 1})
        self.assertEqual(fixtures.errors, ["Application bytes reached rejected fixture expired"])
        fixtures.record_application("valid", b"GET ")
        fixtures.record_application("bad-proof", b"")
        self.assertEqual(fixtures.application_bytes, {"expired": 1, "valid": 4})
        self.assertEqual(len(fixtures.errors), 1)

    def test_httpps_fixture_includes_a_cookie_without_secure(self):
        fixtures = Fixtures.__new__(Fixtures)
        fixtures.requests = []
        response = fixtures.response(b"GET /set HTTP/1.1\r\nHost: cookie.test\r\n\r\n", "httpps")
        plain_headers = [line for line in response.decode().split("\r\n")
                         if line.startswith("Set-Cookie: plain=")]
        self.assertEqual(plain_headers, ["Set-Cookie: plain=httpps-plain; Path=/; Max-Age=3600"])

    async def test_target_discovery_preserves_port_and_does_not_wait_for_eof(self):
        errors = []
        finished = asyncio.Event()

        async def peer(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                host = next(line.split(b":", 1)[1].strip().decode("ascii")
                            for line in request.split(b"\r\n") if line.startswith(b"Host:"))
                self.assertEqual(host, f"127.0.0.1:{port}")
                body = json.dumps([{"type": "page", "webSocketDebuggerUrl":
                                    f"ws://{host}/devtools/page/test"}]).encode()
                writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
                await writer.drain()
                # Like Chromium, do not close the server side after responding.
                self.assertEqual(await asyncio.wait_for(reader.read(), 3), b"")
            except Exception as error:
                errors.append(error)
            finally:
                await close_writer(writer)
                finished.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            targets = await asyncio.wait_for(debug_targets(port), 2)
            self.assertEqual(targets, [{"type": "page", "webSocketDebuggerUrl":
                                       f"ws://127.0.0.1:{port}/devtools/page/test"}])
            await asyncio.wait_for(finished.wait(), 3)
            self.assertEqual(errors, [])
        finally:
            server.close()
            await server.wait_closed()

    async def test_target_discovery_rejects_bad_response(self):
        for response in (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\n[]",
                         b"HTTP/1.1 200 OK\r\n\r\n[]",
                         f"HTTP/1.1 200 OK\r\nContent-Length: {MAX_MESSAGE + 1}\r\n\r\n".encode(),
                         b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"):
            with self.subTest(response=response):
                finished = asyncio.Event()

                async def peer(reader, writer):
                    try:
                        await reader.readuntil(b"\r\n\r\n")
                        writer.write(response)
                        await writer.drain()
                    finally:
                        await close_writer(writer)
                        finished.set()

                server = await asyncio.start_server(peer, "127.0.0.1", 0)
                try:
                    with self.assertRaises(ValueError):
                        await debug_targets(server.sockets[0].getsockname()[1])
                    await asyncio.wait_for(finished.wait(), 3)
                finally:
                    server.close()
                    await server.wait_closed()

    async def test_masking_fragmented_response_events_and_ping(self):
        errors = []
        finished = asyncio.Event()

        async def peer(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                key = next(line.split(b":", 1)[1].strip() for line in request.split(b"\r\n")
                           if line.startswith(b"Sec-WebSocket-Key:"))
                accept = base64.b64encode(hashlib.sha1(
                    key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                             b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
                await writer.drain()
                first, second = await reader.readexactly(2)
                self.assertEqual(first, 0x81)
                self.assertTrue(second & 0x80)
                size = second & 127
                if size == 126:
                    size = struct.unpack("!H", await reader.readexactly(2))[0]
                mask = await reader.readexactly(4)
                data = await reader.readexactly(size)
                command = json.loads(bytes(value ^ mask[index % 4] for index, value in enumerate(data)))
                self.assertEqual(command["method"], "Runtime.evaluate")
                self.assertEqual(command["params"]["expression"], "x" * 512)
                event = b'{"method":"test.event"}'
                writer.write(bytes([0x81, len(event)]) + event)
                result = json.dumps({"id": command["id"], "result": {"answer": 42}}).encode()
                writer.write(bytes([1, 10]) + result[:10])
                writer.write(b"\x89\x01x")
                writer.write(bytes([0x80, len(result) - 10]) + result[10:])
                await writer.drain()
                first, second = await reader.readexactly(2)
                self.assertEqual((first, second), (0x8a, 0x81))
                mask = await reader.readexactly(4)
                self.assertEqual((await reader.readexactly(1))[0] ^ mask[0], ord("x"))
            except Exception as error:
                errors.append(error)
            finally:
                await close_writer(writer)
                finished.set()

        server = await asyncio.start_server(peer, "127.0.0.1", 0)
        try:
            client = await CDP.connect(f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/devtools/page/test")
            try:
                result = await client.command("Runtime.evaluate", expression="x" * 512)
                self.assertEqual(result, {"answer": 42})
                await asyncio.wait_for(finished.wait(), 3)
                self.assertEqual(errors, [])
            finally:
                await close_writer(client.writer)
        finally:
            server.close()
            await server.wait_closed()

    async def test_nonlocal_debugger_is_rejected(self):
        with self.assertRaises(ValueError):
            await CDP.connect("ws://example.com:9222/debugger")

    def test_cookie_values_may_contain_equals(self):
        self.assertEqual(cookie_map("token=a=b; session=value"), {"token": "a=b", "session": "value"})

    def test_duplicate_cookie_names_cannot_hide_namespace_leak(self):
        with self.assertRaisesRegex(AssertionError, "Duplicate fixture cookie name"):
            cookie_map("session=http; session=httpps")
        with self.assertRaisesRegex(AssertionError, "Duplicate fixture cookie name"):
            cookie_map("session=httpps; session=http")

    def test_malformed_cookie_header_is_not_silently_ignored(self):
        with self.assertRaisesRegex(AssertionError, "Malformed fixture cookie"):
            cookie_map("session=value; unexpected")

    async def test_failed_browser_spawn_closes_log_and_profile(self):
        with tempfile.TemporaryDirectory(prefix="httpps-harness-selftest-") as temporary:
            folder = Path(temporary)
            browser = Browser(folder / "missing-browser.exe", folder / "profile")
            with self.assertRaises(FileNotFoundError):
                async with browser:
                    self.fail("Missing browser must not enter the test body")
            self.assertIsNone(browser.process)
            self.assertTrue(browser.log.closed)

    async def test_proxy_route_and_roots_are_explicit_and_separate(self):
        with tempfile.TemporaryDirectory(prefix="httpps-proxy-harness-") as temporary:
            folder = Path(temporary)
            for proxy in (None, "httpps://cookie.test:4343"):
                with self.subTest(proxy=proxy):
                    browser = Browser(folder / "fixture.exe", folder / "profile", b"origin-root",
                                      proxy=proxy, proxy_root=b"proxy-root" if proxy else None)
                    with patch("browser_e2e_test.OwnedProcess.start",
                               new=AsyncMock(side_effect=FileNotFoundError("fixture"))) as spawn:
                        with self.assertRaises(FileNotFoundError):
                            await browser.__aenter__()
                    arguments = spawn.call_args.args
                    self.assertIn("--httpps-trust-anchor=" + base64.b64encode(b"origin-root").decode(), arguments)
                    self.assertEqual("--no-proxy-server" in arguments, proxy is None)
                    if proxy:
                        self.assertIn("--proxy-server=" + proxy, arguments)
                        self.assertIn("--httpps-proxy-trust-anchor=" + base64.b64encode(b"proxy-root").decode(), arguments)
                    else:
                        self.assertFalse(any(item.startswith("--httpps-proxy-trust-anchor=") for item in arguments))
                    self.assertFalse(any(item.startswith("--ignore-certificate") for item in arguments))

    async def test_startup_retries_transient_active_port_file_lock(self):
        with tempfile.TemporaryDirectory(prefix="httpps-startup-file-lock-") as temporary:
            folder = Path(temporary)
            browser = Browser(folder / "fixture.exe", folder / "profile")
            process = Mock(returncode=None)
            process.wait = AsyncMock(return_value=0)
            cdp = Mock()
            cdp.command = AsyncMock()

            async def spawn(*args, **kwargs):
                (browser.profile / "DevToolsActivePort").write_text("12345\n/browser/test\n")
                return process

            with patch("browser_e2e_test.OwnedProcess.start", side_effect=spawn), \
                 patch.object(Path, "read_text", side_effect=[PermissionError("writer still open"),
                                                              "12345\n/browser/test\n"]) as read, \
                 patch("browser_e2e_test.debug_targets", new=AsyncMock(return_value=[
                     {"type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:12345/test"}])) as targets, \
                 patch("browser_e2e_test.CDP.connect", new=AsyncMock(return_value=cdp)), \
                 patch("browser_e2e_test.close_writer", new=AsyncMock()):
                async with browser as selected:
                    self.assertIs(selected, cdp)
                self.assertEqual(read.call_count, 2)
                targets.assert_awaited_once_with(12345)
            process.kill.assert_not_called()
            self.assertTrue(browser.log.closed)

    async def test_startup_failure_survives_forced_process_cleanup(self):
        for failure in (RuntimeError("original WebSocket failure"),
                        asyncio.CancelledError("startup cancelled")):
            with self.subTest(failure=type(failure).__name__):
                with tempfile.TemporaryDirectory(prefix="httpps-startup-failure-") as temporary:
                    folder = Path(temporary)
                    browser = Browser(folder / "fixture.exe", folder / "profile")
                    process = Mock(returncode=None)
                    process.wait = AsyncMock(side_effect=[TimeoutError("owned wait timeout"), 0])

                    async def spawn(*args, **kwargs):
                        (browser.profile / "DevToolsActivePort").write_text("12345\n/browser/test\n")
                        return process

                    with patch("browser_e2e_test.OwnedProcess.start", side_effect=spawn), \
                         patch("browser_e2e_test.debug_targets", new=AsyncMock(return_value=[
                             {"type": "page", "webSocketDebuggerUrl": "ws://127.0.0.1:12345/test"}])), \
                         patch("browser_e2e_test.CDP.connect", new=AsyncMock(side_effect=failure)):
                        with self.assertRaises(type(failure)) as caught:
                            await browser.__aenter__()
                    self.assertIs(caught.exception, failure)
                    self.assertIn("connecting page debugger WebSocket", failure.__notes__[0])
                    self.assertIn("Browser cleanup also failed", failure.__notes__[1])
                    process.kill.assert_called_once()
                    self.assertEqual(process.wait.await_count, 2)
                    self.assertTrue(browser.log.closed)

    async def test_cleanup_preserves_body_error_but_invalidates_successful_persistence(self):
        for failure in (ValueError("original assertion"), None):
            with self.subTest(prior_failure=failure is not None):
                with tempfile.TemporaryDirectory(prefix="httpps-cleanup-failure-") as temporary:
                    folder = Path(temporary)
                    browser = Browser(folder / "fixture.exe", folder / "profile")
                    browser.log = (folder / "fixture.log").open("ab")
                    browser.process = Mock()
                    browser.process.wait = AsyncMock(side_effect=[TimeoutError("timeout"), 0])
                    if failure:
                        self.assertFalse(await browser.__aexit__(type(failure), failure, None))
                        self.assertIn("persistence result invalid", failure.__notes__[0])
                    else:
                        with self.assertRaisesRegex(RuntimeError, "persistence result invalid"):
                            await browser.__aexit__(None, None, None)
                    browser.process.kill.assert_called_once()
                    self.assertTrue(browser.log.closed)


if __name__ == "__main__":
    unittest.main()
