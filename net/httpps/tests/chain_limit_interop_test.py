#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Real signed long-chain, credential-budget and initial/PHA interoperability."""
import argparse
import asyncio
from contextlib import nullcontext
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from tls20_server import credential_cache, messages as m, pki
    from tls20_server.credential_profiles import CredentialPolicy
    from tls20_server.handshake import server_handshake
    from tests.test_pki import der, issue

    native = str(args.native.resolve())
    checks = connections = 0

    async def command(*arguments, success=True):
        nonlocal checks
        process = await asyncio.create_subprocess_exec(native, *map(str, arguments),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            output, error = await asyncio.wait_for(process.communicate(), 30)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        assert (process.returncode == 0) == success, (arguments[:3], process.returncode, output, error)
        checks += 1
        return output

    def material(count):
        name = lambda value: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
        root_key = ed25519.Ed25519PrivateKey.generate()
        root_name = name("Long-chain test root")
        root = issue(root_key, root_key, root_name, root_name, ca=True, path_length=count)
        issuer_key, issuer_name, intermediates = root_key, root_name, []
        for index in range(count - 1):
            key = ed25519.Ed25519PrivateKey.generate()
            subject = name(f"Intermediate {index}")
            intermediates.append(issue(key, issuer_key, subject, issuer_name, ca=True,
                path_length=count - index - 2,
                extra=[(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)]))
            issuer_key, issuer_name = key, subject
        key = x25519.X25519PrivateKey.generate()
        leaf = issue(key, issuer_key, name("localhost"), issuer_name, hostname="localhost", eku=False,
            extra=[(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False),
                   (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)])
        return pki.Credentials([der(leaf), *map(der, reversed(intermediates))], key), root

    with tempfile.TemporaryDirectory(prefix="httpps-chain-limits-") as temporary:
        directory = Path(temporary)

        def save(name, data):
            path = directory / name
            path.write_bytes(data)
            return path

        fixtures = {}
        for count in (9, 64):
            credential, root = material(count)
            paths = [save(f"chain{count}-{index}.der", value)
                     for index, value in enumerate(credential.chain_der)]
            root_path = save(f"root{count}.der", der(root))
            key_path = save(f"key{count}.raw", credential.private_key.private_bytes_raw())
            fixtures[count] = credential, root, paths, root_path, key_path
            await command("--verify", "localhost", root_path, *paths)
            await command("--check-client-chain", key_path, *paths)
            if args.native_provider:
                output = await command("--verify-native-chain", "localhost", root_path,
                                       args.native_provider.resolve(), *paths)
                assert output.strip() == f"verified path certificates: {count + 1}".encode(), output

        credential, root, paths, root_path, key_path = fixtures[64]
        # This is a real 65-certificate chain: include its already trusted root.
        await command("--verify", "localhost", root_path, *paths, root_path, success=False)
        await command("--check-client-chain", key_path, *paths, root_path, success=False)
        if args.native_provider:
            await command("--verify-native-chain", "localhost", root_path,
                          args.native_provider.resolve(), *paths, root_path, success=False)

        # Enlarging count budgets must not weaken ordinary trust or key checks.
        await command("--verify", "wrong.test", root_path, *paths, success=False)
        await command("--verify", "localhost", fixtures[9][3], *paths, success=False)
        await command("--verify", "localhost", root_path, paths[0], *reversed(paths[1:]), success=False)
        damaged = bytearray(credential.chain_der[0])
        damaged[-1] ^= 1
        damaged_path = save("bad-signature.der", damaged)
        await command("--verify", "localhost", root_path, damaged_path, *paths[1:], success=False)
        await command("--check-client-chain", fixtures[9][4], *paths, success=False)

        # Setter budgets remain 64 KiB per DER and 256 KiB of credential DER.
        # The additional certificates here are real DER, not oversized garbage.
        padding_key = ed25519.Ed25519PrivateKey.generate()
        padding_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Size fixture")])

        def sized_certificate(size):
            padding = size - 400
            for _ in range(5):
                encoded = der(issue(padding_key, padding_key, padding_name, padding_name,
                    ca=True, extra=[(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.99"),
                                                               bytes(padding)), False)]))
                if len(encoded) == size:
                    return encoded
                padding += size - len(encoded)
            raise AssertionError((size, len(encoded)))

        at_der = save("der-at-limit.der", sized_certificate(65536))
        over_der = save("der-over-limit.der", sized_certificate(65537))
        leaf_path = paths[0]
        await command("--check-client-chain", key_path, leaf_path, at_der)
        await command("--check-client-chain", key_path, leaf_path, over_der, success=False)
        remainder = 262144 - len(credential.chain_der[0]) - 3 * 65536
        at_total = save("der-at-total.der", sized_certificate(remainder))
        over_total = save("der-over-total.der", sized_certificate(remainder + 1))
        await command("--check-client-chain", key_path, leaf_path, at_der, at_der, at_der, at_total)
        await command("--check-client-chain", key_path, leaf_path, at_der, at_der, at_der, over_total,
                      success=False)

        async def connection(count, mode, *, client_auth=False, too_many=False):
            nonlocal connections
            credential, root, paths, root_path, key_path = fixtures[count]
            if too_many:
                credential = pki.Credentials([*credential.chain_der, der(root)], credential.private_key)
            errors, observations = [], []
            finished = asyncio.Event()

            async def peer(reader, writer):
                drive = None
                try:
                    async with asyncio.timeout(15):
                        policy = CredentialPolicy(trust_roots=(root,), revocation_policy="offline",
                            authorize_client=lambda material, evidence: tuple(material) == tuple(credential.chain_der))
                        channel = await server_handshake(reader, writer, credential, "localhost",
                            client_credential_policy=policy if client_auth else None,
                            require_client_auth=client_auth)
                        observations.append("established")
                        request = await channel.recv()
                        assert request.startswith(b"GET / HTTP/1.1\r\n"), request
                        if client_auth:
                            assert channel.authenticated_client == tuple(credential.chain_der)
                            pending = await channel.request_client_auth(required=True)
                            drive = asyncio.create_task(channel.recv())
                            identity = await pending
                            assert identity == tuple(credential.chain_der), identity
                            observations.append("PHA authenticated")
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                        if drive:
                            writer.write(channel.sender.seal(b"\x01\x00", 21))
                            await writer.drain()
                            assert await drive is None
                        await channel.close()
                except BaseException as error:
                    errors.append(error)
                finally:
                    if drive and not drive.done():
                        drive.cancel()
                        await asyncio.gather(drive, return_exceptions=True)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (ConnectionError, OSError):
                        pass
                    finished.set()

            listener = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                arguments = [mode, "localhost", listener.sockets[0].getsockname()[1], root_path]
                if client_auth:
                    arguments += [key_path, *paths]
                # Only the synthetic sending peer exceeds its local count budget,
                # so the negative case reaches the unmodified browser parser.
                with (patch.object(m, "MAX_CERTIFICATES", 65) if too_many else nullcontext(),
                      patch.object(credential_cache, "MAX_CERTIFICATES", 65) if too_many else nullcontext()):
                    try:
                        output = await command(*arguments)
                    except AssertionError as error:
                        await asyncio.wait_for(finished.wait(), 16)
                        raise AssertionError((str(error), observations, errors)) from error
                    await asyncio.wait_for(finished.wait(), 16)
                if too_many:
                    assert not observations and len(errors) == 1, (observations, errors)
                    # The native driver independently decrypts its generated
                    # fatal alert and checks decode_error before reporting this
                    # marker. TCP may reset when a rejecting client closes with
                    # unread server-flight bytes; alert delivery is best effort.
                    assert output == b"oversized chain: authenticated fatal decode_error generated\n", output
                    if mode == "--reject-long-chain-reset":
                        assert isinstance(errors[0], ConnectionResetError), errors
                    else:
                        assert getattr(errors[0], "alert", None) == 50 or isinstance(errors[0], ConnectionResetError), errors
                else:
                    assert not errors, errors
                    assert output.endswith(b"\r\n\r\nOK"), output
                    assert observations == (["established", "PHA authenticated"] if client_auth else ["established"])
                connections += 1
            finally:
                listener.close()
                await listener.wait_closed()

        for count in (9, 64):
            for mode in ("--get", "--get-external"):
                await connection(count, mode)
            await connection(count, "--get-client-chain", client_auth=True)
        await connection(64, "--reject-long-chain", too_many=True)
        await connection(64, "--reject-long-chain-reset", too_many=True)

    print(f"{checks} native chain checks passed, including {connections} real connections: "
          "9/64 certificates, 65 rejected, separate anchor, initial/PHA, trust/key and byte budgets")
    if not args.native_provider:
        print("3 native-provider checks skipped: pass --native-provider for explicit OpenSSL validation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--native-provider", type=Path)
    asyncio.run(main(parser.parse_args()))
