#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""SH/HRR/EE alerts: absent offer versus wrong context or malformed content."""
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
    from tls20_server.retry_cookie import RetryCookiePolicy

    credentials, ca = generate_lab_credentials("localhost")
    cases = [("valid", None, b"", False, None),
             ("unknown", 0xfafa, b"", False, 110),
             ("heartbeat-unoffered", 15, b"\x01", False, 110),
             ("rsl-unoffered", 28, b"\x00\x40", False, 110),
             ("heartbeat-invalid-mode", 15, b"\x00", True, 47),
             ("heartbeat-empty", 15, b"", True, 50),
             ("heartbeat-long", 15, b"\x01\x01", True, 50),
             ("truncated", None, b"\xfa\xfa\x00", False, 50),
             # Both extension encodings are complete: repetition is a
             # semantic violation (RFC9846 Sections 4.3 and 6), not framing.
             ("duplicate", 0, b"", False, 47)]
    for code, fields in (
        (28, (("valid", b"\x40\x01", None), ("empty", b"", 50),
              ("short", b"\x40", 50), ("long", b"\x40\x01\x00", 50),
              ("too-small", b"\x00\x3f", 47), ("too-large", b"\x40\x02", 47))),
        (1, (("valid", b"\x01", None), ("empty", b"", 50),
             ("long", b"\x01\x00", 50), ("invalid", b"\x05", 47),
             ("changed", b"\x02", 47))),
        (15, (("valid", b"\x01", None),)),
        (20, (("valid", b"\x00", None), ("empty", b"", 50),
              ("long", b"\x00\x00", 50), ("unoffered-value", b"\x03", 47))),
        (58, (("valid-zero", b"\x00", None), ("valid-max", b"\xff", None),
              ("empty", b"", 50), ("long", b"\x01\x00", 50))),
        (0, (("nonempty", b"\x00", 50),)),
    ):
        cases += [(f"field-{code}-{label}", code, value, True, expected)
                  for label, value, expected in fields]
    cases += [(f"misplaced-{code}", code, b"", False, 47) for code in
              (2, 3, 4, 5, 13, 17, 18, 21, 27, 29, 30, 31, 33, 34, 41,
               43, 44, 45, 47, 48, 49, 50, 51, 52, 59, 0xff02, 0xff03, 0xff04)]
    cases = [("EE", *case) for case in cases]
    for context in ("SH", "HRR"):
        cases += [(context, "valid", None, b"", False, None),
                  (context, "unknown", 0xfafa, b"", False, 110),
                  (context, "heartbeat-wrong-context", 15, b"\x01", False, 47),
                  (context, "psk-unoffered", 41, b"\x00\x00", False, 47 if context == "HRR" else 110),
                  (context, "combined-unoffered", 33, b"", False, 47 if context == "HRR" else 110),
                  (context, "auth-share-wrong-context", 0xff02, bytes(32), False, 47),
                  (context, "truncated", None, b"\xfa\xfa\x00", False, 50)]
    with tempfile.TemporaryDirectory(prefix="httpps-ee-alert-") as folder:
        root = Path(folder) / "root.der"
        root.write_bytes(ca.public_bytes(Encoding.DER))
        for context, label, code, value, offered, expected in cases:
            name = f"{context}-{label}"
            errors, requests, hellos, handlers, cleanup_errors = [], [], [], set(), []
            plaintext_alerts = []
            raw_record = Wire.raw_record
            parse, encode, encode_hello = m.parse_client_hello, m.encrypted_extensions, m.server_hello
            async def observe_record(wire):
                record = await raw_record(wire)
                if record[0] == 21:
                    plaintext_alerts.append(record)
                return record
            def parse_hello(*args, **kwargs):
                hello = parse(*args, **kwargs)
                hellos.append(hello)
                if code in (1, 15, 20, 28, 33, 41, 58, 0xfafa):
                    assert (code in hello.extensions) == offered
                return hello
            def encrypted_extensions(*args, **kwargs):
                frame = encode(*args, **kwargs)
                if context != "EE": return frame
                extra = value if code is None else m.extension(code, value)
                original = frame[6:]
                if code is not None and label != "duplicate":
                    original = b"".join(m.extension(kind, data) for kind, data in
                        m.extensions(original).items() if kind != code)
                return m.frame(8, m._vec(original + extra, 2))
            def server_hello(*args, **kwargs):
                frame = encode_hello(*args, **kwargs)
                if context == "EE" or (context == "HRR") != kwargs.get("retry", False): return frame
                # These clients emit an empty legacy session ID; preserve every
                # valid Hello field and only mutate its extension block.
                assert frame[38] == 0
                extra = value if code is None else m.extension(code, value)
                return m.frame(2, frame[4:42] + m._vec(frame[44:] + extra, 2))
            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                channel = None
                try:
                    async with asyncio.timeout(8):
                        channel = await server_handshake(reader, writer, credentials, "localhost",
                            retry_cookie_policy=RetryCookiePolicy(key=bytes(range(32))) if context == "HRR" else None)
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
                with patch.object(m, "parse_client_hello", parse_hello), patch.object(m, "encrypted_extensions", encrypted_extensions), patch.object(m, "server_hello", server_hello), patch.object(Wire, "raw_record", observe_record):
                    command = [str(args.native.resolve()), "--reject-ee-alert" if context == "EE" else
                               "--get" if expected is None else "--reject-hello-alert",
                               "localhost", str(listener.sockets[0].getsockname()[1]), str(root)]
                    if context == "EE":
                        mode = {1: "mfl", 15: "heartbeat", 20: "server-type", 28: "rsl", 58: "ticket"}.get(code, "none") if offered else "none"
                        command += [mode, str(expected or 0)]
                    elif expected is not None:
                        command += [str(expected)]
                    process = await start_process(*command,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await asyncio.wait_for(process.communicate(), 12)
                    if handlers: await asyncio.wait_for(asyncio.gather(*handlers), 12)
                assert not cleanup_errors, (name, cleanup_errors)
                assert process.returncode == 0 and len(hellos) == (2 if context == "HRR" and expected is None else 1), (name, stdout, stderr, errors)
                if expected is None:
                    assert stdout.endswith(b"\r\n\r\nOK") and len(requests) == 1 and not errors, (name, errors)
                else:
                    # Native verifies its generated alert locally; FIN/drain
                    # then separately confirms delivery to this peer.
                    assert f"fatal alert {expected} generated".encode() in stdout, (name, stdout)
                    assert not requests and len(errors) == 1, (name, errors)
                    if context == "EE":
                        assert isinstance(errors[0], PeerClosed) and errors[0].alert == expected, (name, errors)
                        assert not plaintext_alerts, (name, plaintext_alerts)
                    else:
                        # A rejected Hello has not installed handshake keys.
                        # The server may already be reading protected records
                        # after SH, so inspect the exact plaintext alert before
                        # that read epoch attempts to decode it.
                        assert plaintext_alerts == [b"\x15\x03\x03\x00\x02\x02" + bytes((expected,))], (name, plaintext_alerts)
                        assert isinstance(errors[0], (PeerClosed, ProtocolError)), (name, errors)
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
    print(f"{len(cases)} Hello/encrypted-extension alert cases passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    run(main(parser.parse_args()))
