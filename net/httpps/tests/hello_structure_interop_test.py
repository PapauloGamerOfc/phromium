#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Real SH/HRR vector syntax versus invalid selections, including optional PWD."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from interop_runtime import run, start_process


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives.serialization import Encoding
    from tls20_server import messages as m
    from tls20_server.errors import PeerClosed, ProtocolError
    from tls20_server.handshake import Wire, server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.psk import ExternalPSK
    from tls20_server.retry_cookie import RetryCookiePolicy
    credentials, ca = generate_lab_credentials("localhost")
    cases = [("SH", mode, None, b"", 0) for mode in ("none", "psk", "combined")]
    cases += [("HRR", "none", None, b"", 0)]
    cases += [("SH", "psk", 41, value, 50) for value in (b"", b"\0", b"\0\0\0")]
    cases += [("SH", "psk", 41, b"\0\x01", 47), ("SH", "combined", 33, b"\0", 50)]
    cases += [("SH", "none", 51, value, 50) for value in
              (b"", b"\0\x1d\0", b"\0\x1d\0\0", b"\0\x1d\0\x02\x07")]
    cases += [("SH", "none", 51, value, 47) for value in
              (b"\0\x17\0\x01\x07", b"\0\x1d\0\x01\x07")]
    cases += [("HRR", "none", 51, value, 50) for value in (b"", b"\0", b"\0\x17\0")]
    cases += [("HRR", "none", 51, b"\0\0", 47)]
    cases += [("HRR", "none", 44, value, 50) for value in (b"", b"\0", b"\0\0", b"\0\x02\x07")]
    provider = policy = None
    if args.provider:
        from tls20_server import pake_handshake
        from tls20_server.openssl_provider import OpenSSLProvider
        from tls20_server.pake import PasswordAccount, PasswordServer, password_base
        from tls20_server.pake_native import PakeProvider
        provider = OpenSSLProvider(args.provider.resolve())
        salt = bytes(range(32))
        policy = PasswordServer("localhost", PakeProvider(provider, args.helper.resolve()),
            [PasswordAccount(b"alice", password_base("alice", "correct horse", salt), salt)])
        cases += [("HRR", "pwd", None, b"", 0)]
        cases += [("HRR", "pwd", 31, value, 50) for value in (b"", b"\0", b"\0\x20\x07")]
        cases += [("HRR", "pwd", 31, m._vec(bytes(31), 2), 47)]
    encode, raw_record, parse = m.server_hello, Wire.raw_record, m.parse_client_hello
    try:
        with tempfile.TemporaryDirectory(prefix="httpps-hello-structure-") as folder:
            root = Path(folder)/"root.der"
            root.write_bytes(ca.public_bytes(Encoding.DER))
            for context, mode, code, value, expected in cases:
                name = (context, mode, code, value.hex(), expected)
                errors, requests, alerts, mutations, hellos, handlers = [], [], [], [], [], set()
                cleanup_errors = []
                completed = asyncio.Event()
                def parse_hello(*a, **kw):
                    hello = parse(*a, **kw)
                    hellos.append(hello)
                    assert (41 in hello.extensions) == (mode in ("psk", "combined"))
                    assert (33 in hello.extensions) == (mode == "combined")
                    if mode == "pwd": assert 29 in hello.extensions or 30 in hello.extensions
                    return hello
                def server_hello(*a, **kw):
                    frame = encode(*a, **kw)
                    if (context == "HRR") != kw.get("retry", False): return frame
                    mutations.append(frame)
                    if code is None: return frame
                    assert frame[38] == 0
                    extensions = m.extensions(frame[44:])
                    extensions[code] = value
                    return m.frame(2, frame[4:42] + m._vec(b"".join(m.extension(k, v) for k, v in extensions.items()), 2))
                async def observe_record(wire):
                    record = await raw_record(wire)
                    if record[0] == 21: alerts.append(record)
                    return record
                async def peer(reader, writer):
                    task = asyncio.current_task(); handlers.add(task)
                    channel = None
                    try:
                        async with asyncio.timeout(12):
                            if mode == "pwd":
                                channel = await pake_handshake.server(reader, writer, policy, cipher_suites=(0xc0b0,))
                            else:
                                psks = (ExternalPSK(b"\x01", bytes([7])*32, "localhost", combined=mode=="combined"),) if mode in ("psk", "combined") else ()
                                channel = await server_handshake(reader, writer, credentials, "localhost", external_psks=psks,
                                    retry_cookie_policy=RetryCookiePolicy(key=bytes(range(32))) if context == "HRR" else None)
                            request = await channel.recv()
                            assert request.startswith(b"GET / HTTP/1.1\r\n")
                            requests.append(request)
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                            await channel.close()
                    except Exception as error: errors.append(error)
                    finally:
                        if channel is not None: channel.abort()
                        writer.close()
                        try: await asyncio.wait_for(writer.wait_closed(), 2)
                        except OSError: pass
                        except TimeoutError as error:
                            cleanup_errors.append(error)
                            writer.transport.abort()
                        finally: handlers.discard(task); completed.set()
                listener = await asyncio.start_server(peer, "127.0.0.1", 0)
                process = None
                try:
                    command = [str(args.native.resolve()), "--hello-structure-alert", "localhost",
                        str(listener.sockets[0].getsockname()[1]), str(root), mode, str(expected)]
                    if mode == "pwd": command += [str(args.provider.resolve()), str(args.helper.resolve())]
                    with patch.object(m, "server_hello", server_hello), patch.object(m, "parse_client_hello", parse_hello), patch.object(Wire, "raw_record", observe_record):
                        process = await start_process(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                        stdout, stderr = await asyncio.wait_for(process.communicate(), 16)
                        await asyncio.wait_for(completed.wait(), 12)
                        if handlers: await asyncio.wait_for(asyncio.gather(*handlers), 12)
                    assert not cleanup_errors, (name, cleanup_errors)
                    assert process.returncode == 0 and len(mutations) == 1 and hellos, (name, stdout, stderr, errors)
                    if expected:
                        assert not requests and len(hellos) == 1, name
                        assert alerts == [b"\x15\x03\x03\0\x02\x02" + bytes((expected,))], (name, alerts)
                        assert len(errors) == 1 and isinstance(errors[0], (PeerClosed, ProtocolError)), (name, errors)
                        assert f"fatal alert {expected} generated".encode() in stdout, (name, stdout)
                    else:
                        assert not errors and len(requests) == 1 and stdout.endswith(b"\r\n\r\nOK"), (name, errors, stdout)
                finally:
                    if process is not None and process.returncode is None: process.kill(); await process.wait()
                    listener.close()
                    for task in tuple(handlers): task.cancel()
                    if handlers: await asyncio.wait_for(asyncio.gather(*tuple(handlers), return_exceptions=True), 4)
                    await listener.wait_closed()
        print(f"{len(cases)} Hello structure cases passed; PWD={policy is not None}")
    finally:
        if provider is not None: provider.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "server-source"): parser.add_argument("--"+name, type=Path, required=True)
    for name in ("provider", "helper"): parser.add_argument("--"+name, type=Path)
    args = parser.parse_args()
    if bool(args.provider) != bool(args.helper): parser.error("provider and helper must be supplied together")
    run(main(args))
