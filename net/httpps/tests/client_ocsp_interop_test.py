#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Real client OCSP evidence, current initial/PHA/EA offers, and peer policy."""
import argparse
import asyncio
import base64
from datetime import timedelta
from pathlib import Path
import json
import sys
import tempfile
from unittest.mock import patch


async def main(args):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography import x509
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from tls20_server import messages as m
    from tls20_server.application_auth import credential_validator, parse_request, _parse_certificate
    from tls20_server.credential_evidence import CredentialEvidencePolicy
    from tls20_server.credential_profiles import CredentialPolicy
    from tls20_server.errors import ProtocolError
    from tls20_server.handshake import Wire, server_handshake
    from tls20_server.lab import generate_lab_credentials
    from tests.test_credential_profiles import CredentialProfileTests
    from tests.test_pki import issue, der

    if args.browser:
        from browser_e2e_test import Browser, HOST
        hostname = HOST
    else:
        hostname = "localhost"
    server_credentials, server_root = generate_lab_credentials(hostname)
    fixture = CredentialProfileTests()
    fixture.setUp()
    fixture.leaf = issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name, eku=False,
        extra=[(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
               # OCSP plus unilateral certificate algorithms and the actual
               # client MAC share. EA must derive satisfaction from its request.
               (x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24"),
                    bytes.fromhex("300b020105020132020300ff03")), False)])
    chain = [der(fixture.leaf), der(fixture.root)]
    good = fixture.make_ocsp()
    responses = {"good": good, "missing": b"", "bad-signature": good[:-1] + bytes((good[-1] ^ 1,)),
        "revoked": fixture.make_ocsp(status=ocsp.OCSPCertStatus.REVOKED),
        "unknown": fixture.make_ocsp(status=ocsp.OCSPCertStatus.UNKNOWN)}
    previous = fixture.now
    fixture.now -= timedelta(days=2)
    responses["expired"] = fixture.make_ocsp()
    fixture.now = previous
    previous_leaf = fixture.leaf
    fixture.leaf = issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name)
    responses["wrong-certid"] = fixture.make_ocsp()
    fixture.leaf = previous_leaf
    with tempfile.TemporaryDirectory(prefix="httpps-client-ocsp-") as directory:
        folder = Path(directory)
        root, leaf, issuer, key, response_file = (folder / name for name in
            ("server.der", "client.der", "issuer.der", "client.raw", "ocsp.der"))
        root.write_bytes(der(server_root))
        leaf.write_bytes(chain[0])
        issuer.write_bytes(chain[1])
        key.write_bytes(fixture.key.private_bytes_raw())
        phases = ("initial", "pha") if args.browser else ("initial", "pha", "ea")
        for phase in phases:
            for kind, response in responses.items():
                response_file.write_bytes(response)
                errors, requests, identities, crs, certificates = [], [], [], [], []
                handlers = set()
                policy = CredentialPolicy(trust_roots=(fixture.root,),
                    authorize_client=lambda material, evidence: tuple(material) == tuple(chain),
                    evidence_validator=CredentialEvidencePolicy())
                original_send, original_parse = Wire.send_frame, m.parse_certificate

                async def send(wire, frame, state=None):
                    if frame[0] == 13:
                        parsed = m.parse_certificate_request(frame[4:], details=True)
                        crs.append((parsed[0], parsed[3]))
                    return await original_send(wire, frame, state)

                def parse(body, *args, **kwargs):
                    result = original_parse(body, *args, **kwargs)
                    if kwargs.get("details"):
                        certificates.append((m._Reader(body).vector(1), result[1]))
                    return result

                async def peer(reader, writer):
                    task = asyncio.current_task()
                    handlers.add(task)
                    channel = drive = None
                    try:
                        async with asyncio.timeout(10):
                            channel = await server_handshake(reader, writer, server_credentials, hostname,
                                client_credential_policy=policy if phase != "ea" else None, require_client_auth=phase != "ea",
                                client_certificate_evidence_extensions=((5, b""),) if phase == "initial" else (),
                                certificate_compression=(), enable_authenticators=phase == "ea",
                                require_alpn=not args.browser)
                            if phase == "ea":
                                manager = channel.authenticators()
                                validator = credential_validator(policy, role="client", authorize=lambda resolved: True)
                                buffered = bytearray()
                                for offered in (True, False):
                                    request = manager.request(context=b"ocsp-request" + bytes((offered,)),
                                        extra_extensions=((5, b""),) if offered else ())
                                    parsed = parse_request(request)
                                    crs.append((parsed.context, dict(parsed.extensions)))
                                    await channel.send(len(request).to_bytes(4, "big") + request)
                                    while len(buffered) < 4 or len(buffered) < 4 + int.from_bytes(buffered[:4], "big"):
                                        value = await channel.recv()
                                        assert value is not None
                                        buffered.extend(value)
                                    size = int.from_bytes(buffered[:4], "big")
                                    assert size <= 1048576
                                    authenticator = bytes(buffered[4:4 + size])
                                    del buffered[:4 + size]
                                    certificate_size = int.from_bytes(authenticator[1:4], "big")
                                    identity = _parse_certificate(authenticator[4:4 + certificate_size])
                                    certificates.append((identity.context, identity.extensions))
                                    result = await manager.validate(authenticator, validator, request=request)
                                    assert result.authenticated and result.certificate.chain == tuple(chain)
                                    identities.append(result.certificate.chain)
                                assert not buffered
                            else:
                                identities.append(channel.authenticated_client)
                            request = await channel.recv()
                            assert request.startswith(b"GET / HTTP/1.1\r\n")
                            requests.append(request)
                            if phase == "pha":
                                first = await channel.request_client_auth(required=True,
                                    certificate_evidence_extensions=((5, b""),))
                                await channel.key_update(request_peer=True)
                                # Deliberately omit OCSP on the next request. Configured
                                # bytes must not leak into a later unoffered response.
                                second = await channel.request_client_auth(required=True,
                                    certificate_evidence_extensions=()) if kind == "good" else None
                                drive = asyncio.create_task(channel.recv())
                                # recv drives authentication and must itself be observed
                                # on failure: cancellation of the request is not proof.
                                done, _ = await asyncio.wait((first, drive), return_when=asyncio.FIRST_COMPLETED)
                                if drive in done:
                                    await drive
                                identities.append(await first)
                                if second is not None:
                                    identities.append(await second)
                            await channel.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                            await channel.close()
                    except Exception as error:
                        errors.append(error)
                    finally:
                        if channel is not None:
                            channel.abort()
                        if drive is not None:
                            if not drive.done():
                                drive.cancel()
                            await asyncio.gather(drive, return_exceptions=True)
                        writer.close()
                        try:
                            await asyncio.wait_for(writer.wait_closed(), 2)
                        except (OSError, TimeoutError):
                            pass
                        handlers.discard(task)

                server = await asyncio.start_server(peer, "127.0.0.1", 0)
                try:
                    with patch.object(Wire, "send_frame", send), patch.object(m, "parse_certificate", parse):
                        port = server.sockets[0].getsockname()[1]
                        if args.browser:
                            b64 = lambda value: base64.b64encode(value).decode("ascii")
                            origin = f"httpps://{hostname}:{port}"
                            profile = folder / f"{phase}-{kind}.json"
                            profile.write_text(json.dumps({"format": 1, "profiles": [{"origin": origin,
                                "top_frame_site": f"httpps://{hostname}", "cross_site": False, "privacy_mode": 0,
                                "route": "direct", "options": {"trust_anchors": [b64(der(server_root))],
                                # The browser otherwise offers h2, on which PHA
                                # is forbidden. Explicitly select HTTP/1.1.
                                "post_handshake_auth": True, "no_alpn_http11": True,
                                "client_credential": {"certificates": [b64(value) for value in chain],
                                "private_key": b64(fixture.key.private_bytes_raw()), "ocsp_responses": [b64(response)]}}}]}))
                            async with Browser(args.browser.resolve(), folder / f"browser-{phase}-{kind}",
                                               profile_config=profile, enable_network_sandbox=args.enable_network_sandbox) as browser:
                                try:
                                    await browser.navigate(origin + "/", success=kind == "good")
                                except BaseException as error:
                                    error.add_note(f"client OCSP {phase}/{kind}: peer_errors={errors!r}; "
                                                   f"requests={len(requests)}; identities={len(identities)}; CRs={len(crs)}")
                                    raise
                                output = b"HTTP/1.1 200 OK" if kind == "good" and await browser.evaluate("document.body.innerText") == "OK" else b""
                            returncode, error = (0 if kind == "good" else 1), b""
                        else:
                            process = await asyncio.create_subprocess_exec(str(args.native.resolve()),
                                "--get-client-ocsp-ea" if phase == "ea" else "--get-client-ocsp",
                                hostname, str(port), str(root), str(key), str(response_file), str(leaf), str(issuer),
                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                            try:
                                output, error = await asyncio.wait_for(process.communicate(), 15)
                            except BaseException:
                                if process.returncode is None:
                                    process.kill()
                                await process.wait()
                                raise
                            returncode = process.returncode
                        if handlers:
                            await asyncio.gather(*handlers)
                    assert crs and certificates, (phase, kind, crs, certificates, error, errors)
                    by_context = {context: dict(metadata[0]) for context, metadata in certificates}
                    requested = [context for context, extensions in crs if 5 in extensions]
                    assert len(requested) == 1 and all(extensions[5] == b"" for _, extensions in crs if 5 in extensions)
                    actual = by_context[requested[0]].get(5)
                    expected = b"\x01" + len(response).to_bytes(3, "big") + response if response else None
                    assert actual == expected, (phase, kind, actual, expected)
                    for context, extensions in crs:
                        if 5 not in extensions:
                            assert 5 not in by_context[context], (phase, kind, crs, certificates)
                    if kind == "good":
                        assert returncode == 0 and b"HTTP/1.1 200 OK" in output and not errors, (phase, kind, error, errors)
                        assert identities == [tuple(chain)] * {"initial": 1, "pha": 3, "ea": 2}[phase], identities
                    else:
                        assert returncode != 0 and not output and len(errors) == 1 and isinstance(errors[0], ProtocolError), (phase, kind, error, errors)
                        assert len(requests) == (1 if phase == "pha" else 0), (phase, kind, requests)
                        assert identities == ([tuple(chain)] if phase == "pha" else []), (phase, kind, identities)
                    print("PASS", "browser" if args.browser else "native", "client OCSP", phase, kind, flush=True)
                finally:
                    server.close()
                    for task in tuple(handlers):
                        task.cancel()
                    if handlers:
                        await asyncio.gather(*tuple(handlers), return_exceptions=True)
                    await server.wait_closed()
    print(f"{len(phases) * len(responses)} client OCSP cases passed: {'/'.join(phases)} signed evidence, current-offer isolation, TLSFeature50/ff03, missing/signature/status/freshness/CertID failures")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--native", type=Path)
    mode.add_argument("--browser", type=Path)
    parser.add_argument("--enable-network-sandbox", action="store_true")
    parser.add_argument("--server-source", type=Path, required=True)
    args = parser.parse_args()
    # Native mode launches asyncio subprocesses, which need Proactor on Windows.
    # Browser's CDP runner instead uses sockets and the Selector loop.
    with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop if args.browser and sys.platform == "win32" else None) as runner:
        runner.run(main(args))
