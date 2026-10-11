#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Full OCSP request metadata and CA preferences, with independent DER fixtures.

The metadata matcher is not a signature/trust validator. Browser CertVerifier
continues to validate responder authority, signature, CertID, status and time.
"""
import argparse
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import NameOID
    from tests.test_pki import der, issue
    from tests.test_signature_profiles import tlv
    from tls20_server import messages
    from tls20_server.handshake import server_handshake
    from tls20_server.pki import Credentials
    from tls20_server.tickets import TicketStore

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP metadata fixture")])
    issuer, key = ec.generate_private_key(ec.SECP256R1()), x25519.X25519PrivateKey.generate()
    root = issue(issuer, issuer, name, name, ca=True)
    leaf = issue(key, issuer, name, name)
    nonce = bytes(range(32))  # Public deterministic test vector, not production.
    nonce_oid = tlv(6, bytes.fromhex("2b0601050507300102"))
    request_extension = tlv(0x30, nonce_oid + tlv(4, tlv(4, nonce)))
    request = tlv(0x30, request_extension)
    now = datetime.now(timezone.utc)
    def response(selected_nonce=nonce, by_name=False):
        builder = (ocsp.OCSPResponseBuilder().add_response(leaf, root, hashes.SHA1(),
            ocsp.OCSPCertStatus.GOOD, now-timedelta(minutes=1), now+timedelta(hours=1), None, None)
            .responder_id(ocsp.OCSPResponderEncoding.NAME if by_name else ocsp.OCSPResponderEncoding.HASH, root))
        if selected_nonce is not None:
            builder = builder.add_extension(x509.OCSPNonce(selected_nonce), False)
        result = builder.sign(issuer, hashes.SHA256())
        responder = tlv(0xa1, name.public_bytes()) if by_name else tlv(0xa2, tlv(4, result.responder_key_hash))
        return result.public_bytes(serialization.Encoding.DER), responder
    valid, responder = response()
    checks = 0
    with tempfile.TemporaryDirectory(prefix="httpps-requests-") as directory:
        directory = Path(directory)
        root_path, name_path, id_path, request_path, response_path = [directory/item for item in (
            "root.der", "name.der", "responder.der", "request.der", "response.der")]
        root_path.write_bytes(der(root))
        async def check(expected, id_value=responder, request_value=request, response_value=valid, name_value=name.public_bytes()):
            nonlocal checks
            for path, data in ((name_path, name_value), (id_path, id_value), (request_path, request_value), (response_path, response_value)):
                path.write_bytes(data)
            process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--check-ocsp-request",
                str(id_path), str(request_path), str(response_path), str(name_path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                output, error = await asyncio.wait_for(process.communicate(), 10)
            except BaseException:
                if process.returncode is None:
                    process.kill()
                await process.wait()
                raise
            assert (process.returncode == 0) == expected, (checks, process.returncode, output, error,
                id_value.hex(), request_value.hex(), name_value.hex(), response_value.hex())
            checks += 1
        await check(True)
        await check(False, response_value=response(b"different nonce")[0])
        await check(False, response_value=response(None)[0])
        await check(False, id_value=responder[:-1] + bytes([responder[-1] ^ 1]))
        named, named_id = response(by_name=True)
        await check(True, id_value=named_id, response_value=named)
        await check(False, response_value=named)
        await check(False, request_value=tlv(0x30, request_extension * 2))
        await check(False, request_value=tlv(0x30, tlv(0x30, nonce_oid + tlv(4, tlv(4, bytes(129))))))
        await check(False, request_value=b"\x30\x00")
        await check(False, name_value=name.public_bytes()+b"\0")
        await check(False, id_value=b"\xa2\x02\x04\x00")
        await check(True, response_value=b"")  # Optional absence isn't evidence.
        for size in range(len(valid)):
            if size:
                await check(False, response_value=valid[:size])
        await check(True)  # Restore the valid fixture files for the real peer.

        metadata = b"\x01" + len(valid).to_bytes(3, "big") + valid
        credentials = Credentials([der(leaf)], key, entry_extensions=(((5, metadata),),))
        store, tasks, seen, errors, offers = TicketStore(), set(), [], [], []
        original = messages.parse_client_hello
        def inspect(data, **options):
            hello = original(data, **options)
            extensions = dict(hello.extension_values)
            expected = b"\x01" + (len(responder)+2).to_bytes(2, "big") + len(responder).to_bytes(2, "big") + responder + len(request).to_bytes(2, "big") + request
            assert extensions[5] == expected, ("status_request", extensions[5], expected)
            names = len(name.public_bytes()).to_bytes(2, "big") + name.public_bytes()
            assert extensions[47] == len(names).to_bytes(2, "big") + names, ("authorities", extensions[47], names)
            offers.append(hello)
            return hello
        async def peer(reader, writer):
            task = asyncio.current_task()
            tasks.add(task)
            early_bytes = []
            async def early(value): early_bytes.append(value)
            try:
                async with asyncio.timeout(8):
                    channel = await server_handshake(reader, writer, credentials, "example.test",
                        ticket_store=store, max_early_data=16384, on_early_data=early)
                    data = b"".join(early_bytes) or await channel.recv()
                    assert data.startswith(b"GET / HTTP/1.1\r\n")
                    seen.append((channel.resumed, channel.early_data_accepted))
                    await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    await channel.close()
            except BaseException as error:
                errors.append(repr(error))
            finally:
                writer.close()
                try: await writer.wait_closed()
                except (ConnectionError, OSError): pass
                tasks.discard(task)
        listener = await asyncio.start_server(peer, "127.0.0.1", 0)
        try:
            with patch.object(messages, "parse_client_hello", inspect):
                process = await asyncio.create_subprocess_exec(str(args.native.resolve()), "--get-credential-request",
                    "example.test", str(listener.sockets[0].getsockname()[1]), str(root_path),
                    str(name_path), str(id_path), str(request_path),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try: output, error = await asyncio.wait_for(process.communicate(), 25)
                except BaseException:
                    if process.returncode is None: process.kill()
                    await process.wait()
                    raise
                if tasks: await asyncio.gather(*tasks)
                assert process.returncode == 0 and not errors, (output, error, errors)
                assert len(offers) == 3 and seen == [(False, False), (True, False), (True, True)], seen
        finally:
            listener.close()
            await listener.wait_closed()
            for task in tuple(tasks): task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    print(f"{checks} OCSP request/nonce/responder/DER checks and 3 full/resumed/early CA-preference connections passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    asyncio.run(main(parser.parse_args()))
