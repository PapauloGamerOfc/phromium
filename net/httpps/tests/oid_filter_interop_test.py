#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Validate CR/PHA OID filters before identity selection, including empty replies."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from interop_runtime import run, start_process


def vector(value, width=2):
    return len(value).to_bytes(width, 'big') + value


def filters(oid, values=b'', duplicate=False):
    entry = vector(oid, 1) + vector(values)
    return vector(entry * (2 if duplicate else 1))


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from tls20_server import handshake as h, messages as m
    from tls20_server.errors import PeerClosed
    from tls20_server.lab import generate_lab_credentials
    from tests.test_client_auth import client_credentials

    credentials, ca = generate_lab_credentials('localhost')
    credential = client_credentials(ed25519.Ed25519PrivateKey.generate())
    unknown, ku, eku = (bytes.fromhex(value) for value in ('06022a03', '0603551d0f', '0603551d25'))
    cases = (
        ('empty-list', b'\0\0', 0),
        ('unknown', filters(unknown), 0),
        ('unknown-opaque-value', filters(unknown, b'\xff\0\x80'), 0),
        ('key-usage-presence', filters(ku), 0),
        ('key-usage-empty-bits', filters(ku, bytes.fromhex('030100')), 0),
        ('key-usage-agreement', filters(ku, bytes.fromhex('03020308')), 0),
        ('extended-key-usage-client', filters(eku, bytes.fromhex('300a06082b06010505070302')), 0),
        ('duplicate-oid', filters(unknown, duplicate=True), 47),
        ('missing-vector', b'', 50),
        ('truncated-vector', b'\0\x01\0', 50),
        ('trailing-vector', b'\0\0\0', 50),
        ('empty-oid', filters(b''), 50),
        ('empty-oid-content', filters(b'\x06\0'), 50),
        ('incomplete-oid-component', filters(bytes.fromhex('060180')), 50),
        ('trailing-oid', filters(unknown+b'\0'), 50),
        ('nonminimal-oid-length', filters(bytes.fromhex('0681022a03')), 50),
        ('bad-ku-unused-bits', filters(ku, bytes.fromhex('03020880')), 50),
        ('nonminimal-ku', filters(ku, bytes.fromhex('03020080')), 50),
        ('undefined-ku-bit', filters(ku, bytes.fromhex('0303060040')), 47),
        ('empty-eku', filters(eku, bytes.fromhex('3000')), 50),
        ('incomplete-eku-oid', filters(eku, bytes.fromhex('3003060180')), 50),
        ('forbidden-any-eku', filters(eku, bytes.fromhex('30060604551d2500')), 47),
    )
    checks = 0
    with tempfile.TemporaryDirectory(prefix='httpps-oid-filter-') as directory:
        root, leaf, key = (Path(directory)/name for name in ('root.der', 'client.der', 'client.raw'))
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        leaf.write_bytes(credential.chain_der[0])
        key.write_bytes(credential.private_key.private_bytes_raw())
        for selected in (False, True):
            for pha in (False, True):
                for label, encoded, expected in cases:
                    case = (selected, pha, label)
                    errors, requests, identities, channels, generated = [], [], [], [], []
                    futures, handlers, cleanup_errors = [], set(), []
                    completed = asyncio.Event()
                    original = m.certificate_request

                    def inject(context, share, algorithms=m.CERT_ALGORITHMS, *, extra_extensions=()):
                        if bool(context) == pha:
                            extra_extensions = tuple(pair for pair in extra_extensions if pair[0] != 48)
                            extra_extensions += ((48, encoded),)
                            generated.append(context)
                        return original(context, share, algorithms, extra_extensions=extra_extensions)

                    def validate(chain):
                        assert chain == credential.chain_der, (case, chain)
                        return credential.private_key.public_key()

                    async def peer(reader, writer):
                        task = asyncio.current_task()
                        handlers.add(task)
                        channel = driver = None
                        try:
                            async with asyncio.timeout(8):
                                channel = await h.server_handshake(reader, writer, credentials, 'localhost',
                                    client_auth_validator=validate, require_client_auth=selected)
                                channels.append(channel)
                                identities.append(channel.authenticated_client)
                                request = await channel.recv()
                                assert request.startswith(b'GET / HTTP/1.1\r\n'), (case, request)
                                requests.append(request)
                                if pha:
                                    if expected:
                                        # An intentionally malformed peer must bypass its own local
                                        # request API validation, not the receiver's wire parser.
                                        share = x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()
                                        await channel.send_handshake(m.certificate_request(b'oid-filter-context', share))
                                        await channel.recv()
                                        raise AssertionError('invalid PHA filter returned data')
                                    future = await channel.request_client_auth(required=selected)
                                    futures.append(future)
                                    driver = asyncio.create_task(channel.recv())
                                    identities.append(await asyncio.wait_for(future, 3))
                                await channel.send(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
                                if driver is not None:
                                    if not driver.done():
                                        driver.cancel()
                                    outcome = (await asyncio.gather(driver, return_exceptions=True))[0]
                                    assert isinstance(outcome, asyncio.CancelledError), (case, outcome)
                                    driver = None
                                await channel.close()
                        except Exception as error:
                            errors.append(error)
                        finally:
                            if driver is not None:
                                if not driver.done():
                                    driver.cancel()
                                await asyncio.gather(driver, return_exceptions=True)
                            if channel is not None:
                                channel.abort()
                            writer.close()
                            try:
                                await asyncio.wait_for(writer.wait_closed(), 2)
                            except TimeoutError as error:
                                cleanup_errors.append(error)
                                writer.transport.abort()
                            except OSError:
                                pass
                            handlers.discard(task)
                            completed.set()

                    listener = await asyncio.start_server(peer, '127.0.0.1', 0)
                    process = None
                    try:
                        port = str(listener.sockets[0].getsockname()[1])
                        command = [str(args.native.resolve()), '--oid-filter-alert', 'localhost', port,
                                   str(root), str(leaf) if selected else '-', str(key) if selected else '-',
                                   'pha' if pha else 'initial', str(expected)]
                        with patch.object(m, 'certificate_request', inject):
                            process = await start_process(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                            output, error = await asyncio.wait_for(process.communicate(), 12)
                            await asyncio.wait_for(completed.wait(), 10)
                            if handlers:
                                await asyncio.wait_for(asyncio.gather(*tuple(handlers)), 10)
                        assert not cleanup_errors, (case, cleanup_errors)
                        assert process.returncode == 0 and generated, (case, output, error, errors)
                        if expected:
                            assert len(errors) == 1 and isinstance(errors[0], PeerClosed), (case, errors)
                            assert errors[0].alert == expected, (case, errors)
                            assert f'fatal alert {expected}'.encode() in output, (case, output)
                            assert len(channels) == len(requests) == int(pha), (case, channels, requests)
                            assert not futures
                        else:
                            assert not errors and len(requests) == 1 and output.endswith(b'\r\n\r\nOK'), (case, output, errors)
                            identity = tuple(credential.chain_der) if selected else None
                            assert identities == [identity] * (2 if pha else 1), (case, identities)
                            assert all(future.done() and not future.cancelled() for future in futures)
                        checks += 1
                    finally:
                        if process is not None and process.returncode is None:
                            process.kill()
                            await process.wait()
                        listener.close()
                        for task in tuple(handlers):
                            task.cancel()
                        if handlers:
                            await asyncio.wait_for(asyncio.gather(*tuple(handlers), return_exceptions=True), 4)
                        await listener.wait_closed()
                print('PASS OID filters selected', selected, 'PHA', pha, flush=True)
    print(f'{checks} initial/PHA OID-filter wire cases passed with selected credentials and ordinary refusals')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--server-source', type=Path, required=True)
    run(main(parser.parse_args()))
