#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Real-browser TLSFeature negotiation and private/DANE path evidence regression."""
import argparse
import asyncio
import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from browser_e2e_test import Browser, Fixtures, HOST, close_writer
from browser_profiles_test import ct_fixture, dane_fixture, provider_staging_directory, stage_library


def b64(value):
    return base64.b64encode(value).decode("ascii")


def material(feature):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from tls20_server.pki import Credentials
    now = datetime.now(timezone.utc)
    ca, key = ec.generate_private_key(ec.SECP256R1()), x25519.X25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Browser evidence CA")])
    common = (x509.CertificateBuilder().issuer_name(name).not_valid_before(now-timedelta(days=1))
              .not_valid_after(now+timedelta(days=1)))
    root = (common.subject_name(name).public_key(ca.public_key()).serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(True, 0), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca.public_key()), False)
            .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False), True)
            .sign(ca, hashes.SHA256()))
    leaf = (common.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(False, None), True)
            .add_extension(x509.KeyUsage(False,False,False,False,True,False,False,False,False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False))
    if feature is not None:
        integer = feature.to_bytes(max(1, (feature.bit_length() + 7) // 8), "big")
        if integer[0] & 0x80:
            integer = b"\x00" + integer
        leaf = leaf.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24"),
            bytes((0x30, len(integer) + 2, 2, len(integer))) + integer), False)
    leaf = leaf.sign(ca, hashes.SHA256())
    encoded = lambda cert: cert.public_bytes(serialization.Encoding.DER)
    return Credentials([encoded(leaf), encoded(root)], key), root, leaf, ca


def ocsp_fixture(leaf, root, ca, kind):
    if kind.startswith("rollover-"):
        return ocsp_rollover_fixture(leaf, root, ca, kind)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509 import ocsp
    from tls20_server.credential_profiles import validate_ocsp_response
    now = datetime.now(timezone.utc)
    signer, responder = ca, root
    if kind == "unauthorized":
        signer = ec.generate_private_key(ec.SECP256R1())
        responder = (x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(root.subject)
            .public_key(signer.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
            .add_extension(x509.BasicConstraints(False, None), True).sign(ca, hashes.SHA256()))
    target = material(None)[2] if kind == "wrong-certid" else leaf
    status = {"revoked": ocsp.OCSPCertStatus.REVOKED, "unknown": ocsp.OCSPCertStatus.UNKNOWN}.get(kind, ocsp.OCSPCertStatus.GOOD)
    this_update = now-timedelta(days=10) if kind == "stale" else now-timedelta(minutes=1)
    next_update = now-timedelta(days=1) if kind == "stale" else now+timedelta(seconds=8 if kind == "expires" else 3600)
    builder = (ocsp.OCSPResponseBuilder().add_response(target, root, hashes.SHA1(), status,
        this_update, next_update, now-timedelta(hours=1) if kind == "revoked" else None, None)
        .responder_id(ocsp.OCSPResponderEncoding.HASH, responder))
    if kind == "unauthorized":
        builder = builder.certificates([responder])
    if kind.startswith("nonce"):
        builder = builder.add_extension(x509.OCSPNonce(b"wrong" if kind == "nonce-mismatch" else b"expected"), False)
    response = builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    if kind == "bad-signature":
        response = response[:-1] + bytes((response[-1] ^ 1,))
    if kind in ("good", "expires", "nonce-good"):
        validate_ocsp_response(response, leaf, root)
    return b"\x01" + len(response).to_bytes(3, "big") + response, next_update


def ocsp_rollover_fixture(leaf, issuer, ca, kind):
    """Same responder DN, distinct keys: only an authorized actual signer counts."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP responder rollover")])
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
    certs = []
    for index, key in enumerate(keys):
        unauthorized = ((index == 0 and kind == "rollover-unauthorized-first") or
                        (index == 1 and kind == "rollover-signer-unauthorized"))
        expired = ((index == 0 and kind == "rollover-expired-first") or
                   (index == 1 and kind == "rollover-signer-stale"))
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(days=2))
            .not_valid_after(now+timedelta(days=-1 if expired else 1))
            .add_extension(x509.BasicConstraints(False, None), True)
            .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False), True))
        if not unauthorized:
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False)
        certs.append(builder.sign(ca, hashes.SHA256()))
    assert certs[0].subject == certs[1].subject
    assert certs[0].public_key().public_numbers() != certs[1].public_key().public_numbers()
    next_update = now+timedelta(hours=1)
    response = (ocsp.OCSPResponseBuilder().add_response(leaf, issuer, hashes.SHA256(),
        ocsp.OCSPCertStatus.GOOD, now-timedelta(minutes=1), next_update, None, None)
        .responder_id(ocsp.OCSPResponderEncoding.HASH if kind == "rollover-by-key" else
                      ocsp.OCSPResponderEncoding.NAME, certs[1])
        .certificates(certs[::-1] if kind == "rollover-new-first" else certs)
        .sign(keys[1], hashes.SHA256()))
    # Check fixture integrity independently of the Python verifier under test:
    # both are issuer-signed, but only the second key signed this OCSP response.
    for cert in certs:
        cert.verify_directly_issued_by(issuer)
    certs[1].public_key().verify(response.signature, response.tbs_response_bytes,
                               ec.ECDSA(response.signature_hash_algorithm))
    encoded = response.public_bytes(serialization.Encoding.DER)
    if kind == "rollover-bad-signature":
        # Embedded certificates follow the OCSP signature. Mutate the response
        # signature itself, not an unrelated trailing certificate signature.
        assert encoded.count(response.signature) == 1
        offset = encoded.index(response.signature) + len(response.signature) - 1
        encoded = encoded[:offset] + bytes((encoded[offset] ^ 1,)) + encoded[offset+1:]
    return b"\x01" + len(encoded).to_bytes(3, "big") + encoded, next_update


async def run(args, provider_directory):
    sys.path.insert(0, str(args.server_source.resolve()))
    from cryptography.hazmat.primitives import serialization
    from tls20_server import handshake
    from tls20_server.tickets import TicketStore
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    crypto = stage_library(manifest["environment"]["TLS20_TEST_OPENSSL"], provider_directory)
    getdns = stage_library(manifest["getdns"], provider_directory)
    if sys.platform == "win32":
        stage_library(Path(manifest["openssl_prefix"]) / "bin/libssl-3-x64.dll", provider_directory)
    cases = ["feature-absent", "feature-unoffered", "feature-negotiated", "feature-missing",
             "feature-resumed-missing", "feature-cert-algorithms", "feature-compression", "feature-compression-missing",
             "feature-mac", "feature-mac-missing"]
    cases += [f"{trust}-ct-{kind}" for trust in ("private", "dane") for kind in ("good", "tampered")]
    cases += [f"{trust}-ocsp-{kind}" for trust in ("private", "dane") for kind in
              ("good", "missing", "bad-signature", "wrong-certid", "stale", "revoked", "unknown",
               "unauthorized", "nonce-good", "nonce-mismatch", "expires")]
    cases += [f"{trust}-ocsp-rollover-{kind}" for trust in ("private", "dane") for kind in
              ("old-first", "new-first", "by-key", "expired-first", "unauthorized-first",
               "bad-signature", "signer-unauthorized", "signer-stale")]
    cases += ["dane-ct-omitted-issuer", "private-sct-required"]
    if args.case:
        assert set(args.case) <= set(cases), "Unknown evidence case"
        cases = [case for case in cases if case in args.case]
    with tempfile.TemporaryDirectory(prefix="httpps-browser-evidence-") as temporary:
        folder = Path(temporary)
        fixtures = Fixtures(folder)
        try:
            for case in cases:
                feature = (None if case == "feature-absent" or "-ct-" in case else
                           50 if case == "feature-cert-algorithms" else
                           27 if case.startswith("feature-compression") else
                           0xff02 if case.startswith("feature-mac") else
                           15 if case.startswith("feature-") else 18 if case == "private-sct-required" else 5)
                credentials, root, leaf, ca = material(feature)
                encoded_root = root.public_bytes(serialization.Encoding.DER)
                dane = case.startswith("dane-")
                options = {"native_library": str(crypto), "trust_anchors": [] if dane else [b64(encoded_root)]}
                metadata = ((), ())
                expiration = None
                if case.startswith("feature-") and case != "feature-unoffered":
                    options["heartbeat_mode"] = 1
                if case.startswith("feature-compression"):
                    options["certificate_compression"] = [3]
                if "-ct-" in case:
                    credentials, options["ct_v2"], _ = ct_fixture(credentials, encoded_root, case.endswith("tampered"))
                    metadata = credentials.entry_extensions + ((),)
                elif "-ocsp-" in case and not case.endswith("missing"):
                    kind = case.split("-ocsp-", 1)[1]
                    # Start the short expiry clock only after browser startup,
                    # when the peer is about to perform its first handshake.
                    staple, expiration = ocsp_fixture(leaf, root, ca, "good" if kind == "expires" else kind)
                    metadata = (((5, staple),), ())
                    if kind.startswith("nonce"):
                        # DER Extensions containing the supported OCSP nonce request.
                        options["ocsp_request_extensions"] = b64(bytes.fromhex("3019301706092b0601050507300102040a0408") + b"expected")
                omit_issuer = case == "dane-ct-omitted-issuer"
                if omit_issuer:
                    credentials = replace(credentials, chain_der=credentials.chain_der[:1])
                    metadata = metadata[:1]
                selected = replace(credentials, entry_extensions=metadata)
                requests, sessions, errors, hellos, sent_frames = [], [], [], [], []
                ticket_store = TicketStore()
                async def peer(reader, writer):
                    nonlocal expiration
                    try:
                        async with asyncio.timeout(15):
                            active = selected
                            if case.endswith("expires") and not requests:
                                staple, expiration = ocsp_fixture(leaf, root, ca, "expires")
                                current = tuple((kind, value) for kind, value in active.entry_extensions[0] if kind != 5)
                                active = replace(active, entry_extensions=(current + ((5, staple),),) + active.entry_extensions[1:])
                            heartbeat = case in ("feature-negotiated", "feature-resumed-missing") and not (
                                case == "feature-resumed-missing" and requests)
                            channel = await handshake.server_handshake(reader, writer, active, HOST,
                                heartbeat_mode=1 if heartbeat else None, ticket_store=ticket_store,
                                certificate_compression=() if case == "feature-compression-missing" else (1, 2, 3))
                            sessions.append(channel.resumed)
                            request = await channel.recv()
                            if request:
                                requests.append(request)
                                await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                            await channel.close()
                    except Exception as error:
                        errors.append(error)
                    finally:
                        await close_writer(writer)
                port = await fixtures.listen(peer)
                if dane:
                    selected, anchors = dane_fixture(selected, HOST, port, False, usage=2, root=encoded_root,
                                                     full_anchor=omit_issuer)
                    selected = replace(selected, entry_extensions=(selected.entry_extensions[0] + metadata[0],) + metadata[1:])
                    options["dane"] = {"library": str(getdns), "trust_anchors": b64(anchors),
                                       "application_policy_context": b64(b"browser-evidence-regression")}
                origin = f"httpps://{HOST}:{port}"
                config = {"format": 1, "profiles": [{"origin": origin, "top_frame_site": f"httpps://{HOST}",
                    "cross_site": False, "privacy_mode": 0, "route": "direct", "options": options}]}
                profile = folder / (case + ".json")
                profile.write_text(json.dumps(config), encoding="utf-8")
                failure = (case == "feature-missing" or case == "private-sct-required" or
                           case.endswith(("tampered", "missing", "bad-signature", "wrong-certid", "stale", "revoked",
                                          "unknown", "unauthorized", "nonce-mismatch")))
                resumed_failure = case == "feature-resumed-missing"
                failure = failure and not resumed_failure
                original_controls = handshake.server_controls
                def controls(extensions, *args, **kwargs):
                    hellos.append((extensions.get(15), 41 in extensions, 42 in extensions))
                    return original_controls(extensions, *args, **kwargs)
                original_send = handshake.Wire.send_frame
                async def send_frame(wire, message, state=None):
                    if case == "feature-mac-missing" and message[0] == 15:
                        return  # Negative control: omit the mandatory fresh proof.
                    await original_send(wire, message, state)
                    sent_frames.append(message[0])
                with patch.object(handshake, "server_controls", controls), patch.object(handshake.Wire, "send_frame", send_frame):
                    async with Browser(args.browser.resolve(), folder / case, profile_config=profile,
                                       enable_network_sandbox=args.enable_network_sandbox) as browser:
                        await browser.navigate(origin + "/", success=not failure)
                        if not failure:
                            assert await browser.evaluate("document.body.innerText") == "OK", case
                            if case.endswith("expires"):
                                # A stale saved staple must discard the PSK before CH;
                                # only a new flight carrying fresh evidence may succeed.
                                await asyncio.sleep(max(0, (expiration-datetime.now(timezone.utc)).total_seconds()) + 1)
                                staple, _ = ocsp_fixture(leaf, root, ca, "good")
                                new_metadata = tuple((kind, value) for kind, value in selected.entry_extensions[0] if kind != 5)
                                selected = replace(selected, entry_extensions=(new_metadata + ((5, staple),),) + selected.entry_extensions[1:])
                            await browser.navigate(origin + "/second", success=not resumed_failure)
                if fixtures.tasks:
                    async with asyncio.timeout(17):
                        await asyncio.gather(*fixtures.tasks)
                if failure:
                    # A fixture/provider/configuration failure must not pass as
                    # certificate rejection: require an observed CH, a complete
                    # credential flight, and an actual peer alert/connection close.
                    from tls20_server.errors import PeerClosed
                    assert not requests and hellos and any(kind in sent_frames for kind in (11, 25)) and 20 in sent_frames, (case, requests, hellos, sent_frames, errors)
                    assert errors and all(isinstance(error, (PeerClosed, ConnectionError)) for error in errors), (case, errors)
                elif resumed_failure:
                    assert len(requests) == 1 and errors and any(psk for _, psk, _ in hellos), (case, requests, errors, hellos)
                else:
                    assert len(requests) == 2 and not errors, (case, requests, errors)
                    assert sessions == ([False, False] if case.endswith("expires") else [False, True]), (case, sessions)
                if case.startswith("feature-"):
                    assert all(value == (None if case == "feature-unoffered" else b"\x01") for value, _, _ in hellos), (case, hellos)
                print("PASS", case, "sessions", sessions, flush=True)
        finally:
            await fixtures.close()
    print(f"{len(cases)} browser evidence and TLSFeature cases passed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--server-source", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--enable-network-sandbox", action="store_true")
    parser.add_argument("--case", action="append")
    args = parser.parse_args()
    with provider_staging_directory(args.browser.resolve()) as directory:
        with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop if sys.platform == "win32" else None) as runner:
            runner.run(run(args, directory))
