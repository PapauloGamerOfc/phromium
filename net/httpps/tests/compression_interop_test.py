#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""RFC8478 multi-frame certificates, exact decoding, cache and wire transcripts."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tls20_server import handshake
    from tls20_server.lab import generate_lab_credentials
    import zstandard

    credentials, ca = generate_lab_credentials("localhost")
    checks = 0

    def encode(body, variant):
        compressor = zstandard.ZstdCompressor(write_checksum=True)
        single = compressor.compress(body)
        halves = (compressor.compress(body[:len(body) // 2]) +
                  compressor.compress(body[len(body) // 2:]))
        skips = b"".join((0x184d2a50 + i).to_bytes(4, "little") +
                         (i % 3).to_bytes(4, "little") + bytes(i % 3)
                         for i in range(16))
        empty = compressor.compress(b"")
        data, declared = single, len(body)
        if variant == "multiple":
            data = halves
        elif variant == "skippable":
            data = skips + halves + skips
        elif variant == "empty-frames":
            data = empty + halves + empty
        elif variant == "unknown-size":
            data = zstandard.ZstdCompressor(write_content_size=False).compress(body)
        elif variant == "mixed-sizes":
            data = (zstandard.ZstdCompressor(write_content_size=False).compress(body[:20]) +
                    skips + compressor.compress(body[20:]))
        elif variant == "truncated":
            data = halves[:-1]
        elif variant == "truncated-skippable":
            data = single + skips[:-1]
        elif variant == "trailing-junk":
            data = single + b"junk"
        elif variant == "bad-checksum":
            data = single[:-1] + bytes((single[-1] ^ 1,))
        elif variant == "declared-short":
            data, declared = halves, len(body) - 1
        elif variant == "declared-long":
            data, declared = halves, len(body) + 1
        elif variant == "extra-output":
            data = single + compressor.compress(b"extra")
        elif variant == "output-bomb":
            data = single + compressor.compress(bytes(2 * 1024 * 1024))
        return b"\0\3" + declared.to_bytes(3, "big") + len(data).to_bytes(3, "big") + data

    positive = ("single", "multiple", "skippable", "empty-frames", "unknown-size", "mixed-sizes")
    negative = ("truncated", "truncated-skippable", "trailing-junk", "bad-checksum",
                "declared-short", "declared-long", "extra-output", "output-bomb")
    with tempfile.TemporaryDirectory(prefix="httpps-zstd-") as temporary:
        root = Path(temporary) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        for cached in (False, True):
            for variant in positive + negative:
                valid = variant in positive
                requests, encoded, errors, handlers = [], [], [], set()
                complete = asyncio.Event()

                def compress(body, algorithm):
                    assert algorithm == 3, algorithm
                    encoded.append(body)
                    # Establish and learn the cache before corrupting its
                    # compressed reference, not the initial full Certificate.
                    if cached and not valid and len(encoded) == 1:
                        return encode(body, "single")
                    return encode(body, variant)

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    handlers.add(task)
                    try:
                        async with asyncio.timeout(10):
                            channel = await handshake.server_handshake(reader, writer, credentials, "localhost")
                            request = await channel.recv()
                            assert request.startswith(b"GET / HTTP/1.1\r\n"), request
                            requests.append(tuple(channel.cache_types))
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                            await channel.close()
                    except Exception as exc:
                        errors.append(exc)
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except (OSError, ConnectionError):
                            pass
                        handlers.discard(task)
                        complete.set()

                listener = await asyncio.start_server(peer, "127.0.0.1", 0)
                process = None
                try:
                    with patch.object(handshake, "compress_certificate", compress):
                        command = [str(args.native.resolve()), "--get-cache" if cached else "--get-compression",
                                   "localhost", str(listener.sockets[0].getsockname()[1]), str(root), "3", "-", "-"]
                        process = await asyncio.create_subprocess_exec(*command,
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                        output, error = await asyncio.wait_for(process.communicate(), 20)
                        await asyncio.wait_for(complete.wait(), 12)
                        if handlers:
                            await asyncio.gather(*handlers)
                    assert encoded, (cached, variant, "did not reach compression")
                    assert (process.returncode == 0) == valid, (cached, variant, error, errors)
                    if valid:
                        assert not errors and output.endswith(b"\r\n\r\nOK"), (variant, error, errors)
                        assert requests == ([(), (1,), (1,)] if cached else [()]), requests
                        assert len(encoded) == len(requests), (variant, len(encoded), requests)
                    else:
                        assert requests == ([()] if cached else []) and errors, (variant, requests, errors)
                        assert len(encoded) == (2 if cached else 1), (variant, len(encoded))
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
    print(f"{checks} Zstandard full/cached cases passed: concatenated/skippable/unknown-size frames, "
          "authenticated transcripts, truncation/checksum/trailing input and bounded output rejection")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
