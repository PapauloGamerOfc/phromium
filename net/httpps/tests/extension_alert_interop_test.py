#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Encrypted EE alerts: absent offer versus wrong context or malformed content."""
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
    from tls20_server.errors import PeerClosed
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials

    credentials, ca = generate_lab_credentials("localhost")
    cases = [("valid", None, b"", False, None),
             ("unknown", 0xfafa, b"", False, 110),
             ("heartbeat-unoffered", 15, b"\x01", False, 110),
             ("rsl-unoffered", 28, b"\x00\x40", False, 110),
             ("heartbeat-invalid-mode", 15, b"\x00", True, 47),
             ("heartbeat-empty", 15, b"", True, 47),
             ("heartbeat-long", 15, b"\x01\x01", True, 47),
             ("truncated", None, b"\xfa\xfa\x00", False, 50),
             ("duplicate", 0, b"", False, 50)]
    cases += [(f"misplaced-{code}", code, b"", False, 47) for code in
              (2, 3, 4, 5, 13, 17, 18, 21, 27, 29, 30, 31, 33, 34, 41,
               43, 44, 45, 47, 48, 49, 50, 51, 52, 59, 0xff02, 0xff03, 0xff04)]
    with tempfile.TemporaryDirectory(prefix="httpps-ee-alert-") as folder:
        root = Path(folder) / "root.der"
        root.write_bytes(ca.public_bytes(Encoding.DER))
        for name, code, value, offered, expected in cases:
            errors, requests, hellos, handlers, cleanup_errors = [], [], [], set(), []
            parse, encode = m.parse_client_hello, m.encrypted_extensions
            def parse_hello(*args, **kwargs):
                hello = parse(*args, **kwargs)
                hellos.append(hello)
                if code in (15, 28, 0xfafa):
                    assert (code in hello.extensions) == offered
                return hello
            def encrypted_extensions(*args, **kwargs):
                frame = encode(*args, **kwargs)
                extra = value if code is None else m.extension(code, value)
                return m.frame(8, m._vec(frame[6:] + extra, 2))
            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                channel = None
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, "localhost")
                        request = await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1")
                        requests.append(request)
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                        await channel.close()
                except Exception as error:
                    errors.append(error)
                finally:
                    if channel is not None: channel.abort()
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), 2)
                    except TimeoutError as error:
                        cleanup_errors.append(error)
                        writer.transport.abort()
                    except OSError:
                        pass
                    finally:
                        handlers.discard(task)
            listener = await asyncio.start_server(peer, "127.0.0.1", 0)
            process = None
            try:
                with patch.object(m, "parse_client_hello", parse_hello), patch.object(m, "encrypted_extensions", encrypted_extensions):
                    command = [str(args.native.resolve()), "--get" if expected is None else "--reject-ee-alert",
                               "localhost", str(listener.sockets[0].getsockname()[1]), str(root)]
                    if expected is not None: command += ["heartbeat" if offered else "none", str(expected)]
                    process = await start_process(*command,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await asyncio.wait_for(process.communicate(), 12)
                    if handlers: await asyncio.wait_for(asyncio.gather(*handlers), 12)
                assert not cleanup_errors, (name, cleanup_errors)
                assert process.returncode == 0 and len(hellos) == 1, (name, stdout, stderr, errors)
                if expected is None:
                    assert stdout.endswith(b"\r\n\r\nOK") and len(requests) == 1 and not errors, (name, errors)
                else:
                    # Native verifies the generated encrypted alert locally;
                    # FIN/drain then separately confirms delivery to this peer.
                    assert f"fatal alert {expected} generated".encode() in stdout, (name, stdout)
                    assert not requests and len(errors) == 1 and isinstance(errors[0], PeerClosed), (name, errors)
                    assert errors[0].alert == expected, (name, errors)
                print("PASS", name, expected, flush=True)
            finally:
                if process is not None and process.returncode is None:
                    process.kill()
                    await process.wait()
                listener.close()
                for task in tuple(handlers): task.cancel()
                if handlers:
                    await asyncio.wait_for(asyncio.gather(*tuple(handlers), return_exceptions=True), 4)
                await listener.wait_closed()
    print(f"{len(cases)} encrypted-extension alert cases passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    run(main(parser.parse_args()))
