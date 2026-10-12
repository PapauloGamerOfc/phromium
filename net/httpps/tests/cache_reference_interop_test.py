#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Wire alerts for cached certificates, compressed references and initial/PHA CR."""
import argparse
import asyncio
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from interop_runtime import run, start_process


def metadata(body, value):
    return body[:33] + len(value).to_bytes(3, 'big') + value


def unknown_hash(body):
    cursor = 1 + body[0]
    return body[:cursor] + bytes([body[cursor] ^ 1]) + body[cursor + 1:]


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from tls20_server import handshake as h
    from tls20_server.credential_profiles import CredentialPolicy, RawPublicKeyBinding
    from tls20_server.errors import PeerClosed
    from tls20_server.lab import generate_lab_credentials
    from tls20_server.pki import Credentials

    credentials, ca = generate_lab_credentials('localhost')
    credentials = Credentials(credentials.chain_der[:1], credentials.private_key)
    private = x25519.X25519PrivateKey.generate()
    client_der = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    client_policy = CredentialPolicy(peer_name='device', raw_public_keys=(RawPublicKeyBinding('client', 'device', client_der),))
    certificate_cases = (
        ('valid', lambda b: b, 0),
        ('missing-context', lambda b: b'', 50),
        ('truncated-context', lambda b: b'\x02x', 50),
        ('truncated-hash', lambda b: b[:17], 50),
        ('truncated-metadata-length', lambda b: b[:35], 50),
        ('truncated-metadata', lambda b: b[:-1], 50),
        ('trailing-data', lambda b: b+b'x', 50),
        ('truncated-entry-length', lambda b: metadata(b, b'\0'), 50),
        ('truncated-entry', lambda b: metadata(b, b'\0\x02x'), 50),
        ('truncated-extra-entry', lambda b: metadata(b, b[36:]+b'\0'), 50),
        ('missing-entry', lambda b: metadata(b, b''), 47),
        ('extra-entry', lambda b: metadata(b, b[36:]+b'\0\0'), 47),
        ('unknown-hash', unknown_hash, 47),
        ('nonempty-context', lambda b: b'\x01x'+b[1:], 47),
    )
    request_cases = (
        ('valid', lambda b: b, 0),
        ('missing-context', lambda b: b'', 50),
        ('truncated-context', lambda b: b'\x02x', 50),
        ('truncated-hash', lambda b: b[:1+b[0]+17], 50),
        ('truncated-share', lambda b: b[:-1], 50),
        ('trailing-data', lambda b: b+b'x', 50),
        ('unknown-hash', unknown_hash, 47),
    )
    checks = 0
    with tempfile.TemporaryDirectory(prefix='httpps-cache-alert-') as directory:
        directory = Path(directory)
        root, leaf, client_leaf, client_key, template = (directory/name for name in
            ('root.der', 'leaf.der', 'client.der', 'client.raw', 'request-template.bin'))
        root.write_bytes(ca.public_bytes(serialization.Encoding.DER))
        leaf.write_bytes(credentials.chain_der[0])
        client_leaf.write_bytes(client_der)
        client_key.write_bytes(private.private_bytes_raw())
        # RPK authentication, no compression/evidence request: removing the
        # fresh ff03 leaves an empty, length-prefixed extension template.
        template.write_bytes(b'\0\0')
        modes = [('certificate', algorithm, False) for algorithm in (0, 1, 2, 3)]
        modes += [('request', 0, pha) for pha in (False, True)]
        for kind, algorithm, pha in modes:
            for label, transform, expected in certificate_cases if kind == 'certificate' else request_cases:
                # The compression encoder rejects an empty decoded body before
                # transmission; this is not evidence about the receiver.
                if algorithm and label == 'missing-context':
                    continue
                case = (kind, algorithm, pha, label)
                name = 'cached_certificate_body' if kind == 'certificate' else 'cached_request_body'
                original = getattr(h, name)
                generated, errors, requests, identities, completed_phas = [], [], [], [], []
                channels, futures, handlers, cleanup_errors = [], [], set(), []
                completed = asyncio.Event()

                def inject(*a, **kw):
                    body = original(*a, **kw)
                    if kind == 'request' and bool(a[0]) != pha:
                        return body
                    generated.append(body)
                    return transform(body)

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    handlers.add(task)
                    channel = driver = None
                    try:
                        async with asyncio.timeout(8):
                            options = dict(certificate_compression=(algorithm,) if algorithm else ())
                            if kind == 'request':
                                options.update(client_certificate_types=(2,), client_credential_policy=client_policy,
                                               require_client_auth=True)
                            channel = await h.server_handshake(reader, writer, credentials, 'localhost', **options)
                            channels.append(channel)
                            assert tuple(channel.cache_types) == ((1,) if kind == 'certificate' else (2,)), case
                            if kind == 'request':
                                assert channel.authenticated_client == (client_der,)
                                identities.append(channel.authenticated_client)
                            request = await channel.recv()
                            assert request.startswith(b'GET / HTTP/1.1\r\n'), (case, request)
                            requests.append(request)
                            if pha:
                                future = await channel.request_client_auth(required=True)
                                futures.append(future)
                                if expected:
                                    await channel.recv()  # Must receive the native fatal alert, not a proof.
                                    raise AssertionError('invalid PHA reference returned data')
                                driver = asyncio.create_task(channel.recv())
                                completed_phas.append(await asyncio.wait_for(future, 3))
                                assert completed_phas == [(client_der,)], (case, completed_phas)
                            await channel.send(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
                            if driver is not None:
                                # The response is flushed and PHA is complete.
                                # End the owned reader before close() clears its
                                # receive epoch; cancellation permits only the
                                # remaining close_notify, not new application data.
                                if not driver.done():
                                    driver.cancel()
                                outcome = (await asyncio.gather(driver, return_exceptions=True))[0]
                                assert isinstance(outcome, asyncio.CancelledError), (case, outcome)
                                driver = None
                            await channel.close()
                    except Exception as error:
                        errors.append(error)
                    finally:
                        if driver is not None and not driver.done():
                            driver.cancel()
                        if driver is not None:
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
                        finally:
                            handlers.discard(task)
                            completed.set()

                listener = await asyncio.start_server(peer, '127.0.0.1', 0)
                process = None
                try:
                    port = str(listener.sockets[0].getsockname()[1])
                    if kind == 'certificate':
                        command = [str(args.native.resolve()), '--certificate-alert', 'localhost', port,
                                   str(root), str(leaf), str(algorithm), '1', 'none', str(expected)]
                    else:
                        command = [str(args.native.resolve()), '--cached-request-alert', 'localhost', port,
                                   str(root), str(template), str(client_leaf), str(client_key),
                                   'pha' if pha else 'initial', str(expected)]
                    with patch.object(h, name, inject):
                        process = await start_process(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                        stdout, stderr = await asyncio.wait_for(process.communicate(), 12)
                        await asyncio.wait_for(completed.wait(), 10)
                        if handlers:
                            await asyncio.wait_for(asyncio.gather(*tuple(handlers)), 10)
                    assert not cleanup_errors, (case, cleanup_errors)
                    assert process.returncode == 0 and len(generated) == 1, (case, stdout, stderr, errors)
                    if not expected:
                        assert not errors and len(requests) == 1 and stdout.endswith(b'\r\n\r\nOK'), (case, stdout, errors)
                        if pha:
                            assert completed_phas == [(client_der,)]
                    else:
                        assert len(errors) == 1 and isinstance(errors[0], PeerClosed), (case, errors)
                        assert errors[0].alert == expected, (case, errors)
                        assert f'fatal alert {expected}'.encode() in stdout, (case, stdout)
                        assert not completed_phas
                        if pha:
                            assert len(channels) == len(requests) == len(identities) == 1
                            assert len(futures) == 1 and futures[0].cancelled()
                            assert channels[0].closed and not channels[0].pending_client_auth
                        else:
                            assert not channels and not requests
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
            print('PASS cached reference', kind, 'compression', algorithm, 'PHA', pha, flush=True)
    print(f'{checks} cached-reference wire alert and authenticated positive-control cases passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--server-source', type=Path, required=True)
    run(main(parser.parse_args()))
