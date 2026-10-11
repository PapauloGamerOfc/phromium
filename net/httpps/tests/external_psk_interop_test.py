#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""External/imported PSK modes, selected identity and optional combined PKI."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tls20_server.handshake import server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.psk import ExternalPSK, import_psk
    from tls20_server.tickets import TicketStore

    credentials, ca = generate_lab_credentials("localhost")
    with tempfile.TemporaryDirectory(prefix="httpps-external-") as directory:
        root = Path(directory) / "root.der"
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        cases = [(suite, kind, mode, combined, extra)
                 for suite in (0x1301, 0x1302, 0x1303)
                 for kind in ("ext", "imp")
                 for mode, combined, extra in ((0, False, "plain"), (1, False, "multiple"),
                                                (1, True, "plain"), (1, False, "early"),
                                                (1, False, "resume"), (1, True, "resume"))]
        cases += [(0x1301, "ext", 1, combined, "lost-ticket") for combined in (False, True)]
        for suite, kind, mode, combined, extra in cases:
            if kind == "imp":
                key = import_psk(bytes(range(48)), b"native identity", b"native fixture scope",
                                 "localhost", base_hash="sha384", target_hash="sha384" if suite == 0x1302 else "sha256",
                                 combined=combined, cipher_suite=suite,
                                 max_early_data=16384 if extra == "early" else 0)
            else:
                key = ExternalPSK(b"native identity", bytes(range(32)), "localhost",
                                  hash_name="sha384" if suite == 0x1302 else "sha256", combined=combined,
                                  cipher_suite=suite, max_early_data=16384 if extra == "early" else 0)
            errors, results, handlers = [], [], set()
            store = TicketStore()

            async def peer(reader, writer):
                task = asyncio.current_task()
                handlers.add(task)
                early = []

                async def on_early(data):
                    early.append(data)

                try:
                    async with asyncio.timeout(8):
                        lost_ticket = extra == "lost-ticket" and bool(results)
                        channel = await server_handshake(
                            reader, writer, credentials, "localhost", external_psks=() if lost_ticket else (key,),
                            cipher_suites=(suite,), psk_modes=(mode,), max_early_data=16384,
                            external_early_replay=lambda key, digest: True, on_early_data=on_early,
                            ticket_store=TicketStore() if lost_ticket else store)
                        request = b"".join(early) or await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n")
                        results.append(channel.early_data_accepted)
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                        await channel.close()
                except BaseException as error:
                    errors.append(repr(error))
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except ConnectionError:
                        pass
                    handlers.discard(task)

            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                process = await asyncio.create_subprocess_exec(
                    str(args.native.resolve()), "--get-psk", "localhost", str(server.sockets[0].getsockname()[1]),
                    str(root), key.identity.hex(), key.psk.hex(), f"{suite:x}", str(mode), kind,
                    "combined" if combined else "plain", "resume" if extra == "lost-ticket" else extra,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                output, error = await asyncio.wait_for(process.communicate(), 15)
                if handlers:
                    await asyncio.gather(*handlers)
                if extra == "lost-ticket":
                    assert process.returncode != 0 and errors, (error, errors)
                    assert results == [False], results  # No certificate-only application exchange.
                    continue
                assert process.returncode == 0 and not errors, ((suite, kind, mode, combined, extra), error, errors)
                assert b"HTTP/1.1 200 OK" in output
                assert results == ([False, False, True] if extra == "resume" else [extra == "early"]), results
            finally:
                server.close()
                await server.wait_closed()
    print(f"{len(cases)} native external/imported PSK cases passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
