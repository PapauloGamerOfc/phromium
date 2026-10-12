#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Encrypted RFC8879 alert selection, independent of TCP alert delivery races."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tls20_server import credential_cache, handshake
    from tls20_server.errors import PeerClosed
    from tls20_server.lab import generate_lab_credentials

    credentials, ca = generate_lab_credentials("localhost")
    checks = 0
    with tempfile.TemporaryDirectory(prefix="httpps-codec-alert-") as temporary:
        root = Path(temporary) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        for algorithm in (1, 2, 3):
            for variant, expected in (("valid", None), ("garbage", 42), ("short", 42),
                                      ("long", 42), ("envelope", 50), ("trailing", 50),
                                      ("empty-vector", 50), ("truncated-header", 50),
                                      ("truncated-algorithm", 50), ("empty", 50),
                                      ("unoffered", 47), ("unsupported", 47),
                                      ("unoffered-malformed", 50),
                                      ("zero-mismatch", 42), ("zero-output", 50)):
                errors, requests, generated, handlers = [], [], [], set()
                complete = asyncio.Event()

                def compress(body, selected):
                    assert selected == algorithm
                    generated.append(body)
                    packed = credential_cache.compress_certificate(body, selected)
                    if variant == "garbage":
                        data = b"invalid compressed bytes"
                        return packed[:5] + len(data).to_bytes(3, "big") + data
                    if variant in ("short", "long"):
                        declared = len(body) + (-1 if variant == "short" else 1)
                        return packed[:2] + declared.to_bytes(3, "big") + packed[5:]
                    if variant == "envelope":
                        return packed[:5] + (len(packed) - 7).to_bytes(3, "big") + packed[8:]
                    if variant == "trailing":
                        return packed + b"\x00"
                    if variant == "empty-vector":
                        return packed[:5] + bytes(3)
                    if variant == "truncated-header":
                        return packed[:7]
                    if variant == "truncated-algorithm":
                        return packed[:1]
                    if variant == "empty":
                        return b""
                    if variant == "unoffered":
                        return credential_cache.compress_certificate(body, 2 if selected == 1 else 1)
                    if variant == "unsupported":
                        return b"\xff\xfe" + packed[2:]
                    if variant == "unoffered-malformed":
                        return (2 if selected == 1 else 1).to_bytes(2, "big") + packed[2:-1]
                    if variant == "zero-mismatch":
                        return packed[:2] + bytes(3) + packed[5:]
                    if variant == "zero-output":
                        # A syntactically valid envelope and successful empty
                        # decompression still cannot encode a Certificate body.
                        if selected == 1:
                            import zlib
                            data = zlib.compress(b"")
                        elif selected == 2:
                            import brotli
                            data = brotli.compress(b"")
                        else:
                            import zstandard
                            data = zstandard.ZstdCompressor().compress(b"")
                        return packed[:2] + bytes(3) + len(data).to_bytes(3, "big") + data
                    return packed

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    handlers.add(task)
                    try:
                        async with asyncio.timeout(10):
                            channel = await handshake.server_handshake(reader, writer, credentials, "localhost")
                            request = await channel.recv()
                            assert request.startswith(b"GET / HTTP/1.1\r\n"), request
                            requests.append(request)
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                            await channel.close()
                    except Exception as error:
                        errors.append(error)
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except OSError:
                            pass
                        handlers.discard(task)
                        complete.set()

                listener = await asyncio.start_server(peer, "127.0.0.1", 0)
                process = None
                try:
                    port = str(listener.sockets[0].getsockname()[1])
                    command = ([str(args.native.resolve()), "--get-compression", "localhost", port,
                                str(root), str(algorithm), "-", "-"] if expected is None else
                               [str(args.native.resolve()), "--reject-compression-alert", "localhost", port,
                                str(root), str(algorithm), str(expected)])
                    with patch.object(handshake, "compress_certificate", compress):
                        process = await asyncio.create_subprocess_exec(*command,
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                        output, error = await asyncio.wait_for(process.communicate(), 20)
                        # A failed native assertion can exit without sending
                        # the alert. Surface that regression before waiting for
                        # the peer's close path (which may otherwise time out).
                        assert process.returncode == 0, (algorithm, variant, output, error)
                        await asyncio.wait_for(complete.wait(), 12)
                        if handlers:
                            await asyncio.gather(*handlers)
                    assert process.returncode == 0 and len(generated) == 1, (algorithm, variant, output, error, errors)
                    if expected is None:
                        assert not errors and len(requests) == 1 and output.endswith(b"\r\n\r\nOK"), (variant, errors, output)
                    else:
                        # Native mode decrypts its own generated fatal alert
                        # and fails the process if the code differs or the
                        # invalid certificate reaches an established state.
                        assert output == f"certificate parser: authenticated fatal alert {expected} generated\n".encode(), output
                        assert not requests and len(errors) == 1 and isinstance(errors[0], PeerClosed), (variant, errors)
                        assert errors[0].alert == expected, (variant, errors)
                    checks += 1
                finally:
                    if process is not None and process.returncode is None:
                        process.kill()
                        await process.wait()
                    listener.close()
                    await listener.wait_closed()
                    for task in list(handlers):
                        task.cancel()
                    await asyncio.gather(*handlers, return_exceptions=True)
    print(f"{checks} encrypted codec cases passed: algorithms 1/2/3, exact bad_certificate alerts, "
          "valid controls, decode_error envelopes and illegal_parameter algorithm selections")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
