# Local HTTPPS profiles

Phromium accepts an explicit local configuration file:

```text
chrome.exe --httpps-profile-file=C:\private\httpps-profiles.json
```

Use an absolute path. The browser reads at most 4 MiB before normal startup,
then sends configuration over private browser-to-network-service IPC. Do not
put credentials directly on the command line. Restrict the file's filesystem
permissions to its owner; it can contain passwords, private scalars and PSKs.
Do not commit it or attach it to diagnostics. This file is not a website API,
OS trust-store installation, or graphical credential-import interface.

Configuration applies only to the regular profile named by `--profile-directory`
(the `Default` profile when omitted), and only its default storage partition.
It does not apply to incognito, guest profiles, other browser profiles, system
network fetches, HTTPS, or a connection authenticating a proxy. Restart after
editing the file. An unreadable or structurally invalid document refuses HTTPPS
in that browser profile. Invalid options refuse connections to the configured
origin rather than silently removing restrictions; unrelated origins retain
normal validation. Unknown fields and duplicate object keys (including
equivalent Unicode escapes) are rejected.

## Scope and basic example

```json
{
  "format": 1,
  "profiles": [
    {
      "origin": "httpps://example.test",
      "top_frame_site": "httpps://example.test",
      "cross_site": false,
      "privacy_mode": 0,
      "route": "direct",
      "options": {
        "continuity_pinning": true,
        "record_size_limit": 16385
      }
    }
  ]
}
```

Origins must be canonical serialized origins without a trailing slash; include
a port only when not the default 343. `top_frame_site` is a canonical schemeful
site, not an arbitrary URL or origin: subdomains collapse to the registrable
domain and ports are omitted. `cross_site` and `privacy_mode` are explicit
partition choices. Privacy values match Chromium: 0 includes credentials,
1 restricts cookies/HTTP authentication, 2 is Fetch `credentials: "omit"`, and
3 allows partitioned state. Mode 2 cannot carry client/account credentials.
Opaque/nonced/transient partitions cannot receive a configured profile.
Only the general network-isolation partition is eligible: FedCM, advertising
worklets, DNS-over-HTTPS and restricted SharedWorker partitions never inherit
these configured credentials or trust roots.

`route` is `direct` or an explicit opt-in `proxied`. It authorizes an end-to-end
origin connection through a proxy, not disclosure of origin credentials to
the proxy. Live credentials, tickets and continuity pins are further isolated
by the exact proxy chain and network/privacy partition. A configured origin
with a mismatched scope fails closed. An unrelated origin keeps ordinary
HTTPPS certificate validation. Maximum: 64 distinct profile scopes.

## Encoding

Binary fields use canonical padded base64. Arrays preserve preference order.
Integers are nonnegative JSON integers; values beyond signed 31-bit range can
use decimal strings to avoid floating-point loss. Do not encode JSON hex values.
Native libraries must have explicit absolute paths without parent traversal.
They are not downloaded or discovered through PATH, certificates or websites.
The network sandbox is never disabled to make a provider load; an unavailable
or sandbox-blocked provider makes that selected profile fail closed.
On Windows, existing modules explicitly listed in this immutable startup
snapshot are preloaded through Chromium's utility-process pre-lockdown hook.
The paths travel in private process-bootstrap data, not child command lines.
This preserves the normal post-lockdown restrictions and also applies when the
network service restarts. A missing module is not preloaded and its profile
still fails closed on use. Native module code is process-wide, although its
credentials, policies and connection state remain partition-scoped. Only name
libraries whose executable code you trust; keep them and their dependencies
protected against modification by other users. This is not permission for a
website to load a module, nor a change to the Windows trust store or sandbox.

On Windows the network service already has an AppContainer token during this
preload hook. Install the public provider DLLs and their explicit dependencies
in a location with the same sandbox read/execute access as the browser's
installed modules. Preloading does not bypass file permissions. Keep credential
files separate and private: they do **not** need AppContainer access because the
browser passes their parsed configuration over private IPC. The browser does
not change ACLs, copy arbitrary modules into its installation, or grant write
access. Invalid/unloadable optional modules reject their selected HTTPPS
profile without taking down normal HTTP/HTTPS networking.

## Authentication and trust options

- `trust_anchors`: array of public DER certificate base64 strings for this
  HTTPPS origin only. These are additional private trust, not HTTPS/proxy roots.
- `server_certificate_types`: numeric preference list, e.g. `[2]` for raw keys.
  `server_raw_public_keys`: out-of-band DER SPKI pins, never a key learned from
  the first untrusted connection.
- `client_credential`: object containing `certificates` (DER/SPKI/grant array),
  `private_key` (32 raw X25519 scalar bytes), optional `certificate_type`
  (0 certificate, 2 raw key, 3 ITS), `delegation`, and client-role `its` policy.
  Selection is local authorization to disclose this identity in the scope.
- `external_psks`: at most 16 objects with `identity`, `secret`, optional
  `alpn` (default `http/1.1`), `cipher_suite` (default 4865), `combined` and
  `max_early_data`. An `import_context` field selects the standard importer;
  `base_suite` selects its input hash and `cipher_suite` its target suite.
  Secrets are never constructed from public identities. Early data retains
  the browser's replay-safe request policy and server's replay protection.
- `password`: explicitly selected TLS-PWD `service`, `username`, `password`,
  absolute `helper_library`, and optional provisioned `protection_spki`.
  `service` must equal the origin hostname. The profile also needs
  `native_library`, password cipher suites and compatible groups. OpaqueString
  preparation is applied before use. No certificate/PSK fallback is implied.
- `native_library`: selected OpenSSL 3 library; optional `gost_module` selects
  its separately installed GOST provider. Ownership/provenance/updates remain
  the administrator's responsibility. These never replace HTTPS BoringSSL.
- `bootstrap`: authenticated bootstrap metadata with `spki`, `service`,
  `scope`, and optional `expires_unix_seconds`, paired with the separately
  selected `client_credential` for compatibility with singular profiles.
- `bootstraps`: an array of those records, each with its own base64 raw X25519
  `private_key`. The browser offers each provisioned BSK for the compatible
  hashes in `cipher_suites`; the authenticated server selection determines the
  exact client RPK and possession key. Unknown identities, duplicate BSK offers
  and mismatched private keys are rejected. Resumption remains bound to the
  selected current BSK, scope, trust policy and lifetime, not inventory order.
  Both forms are identifying credentials: they are unavailable when client
  credentials are omitted by privacy policy or for proxy authentication.
  Provisioning-trust bootstrap is deliberately unavailable to normal browser
  HTTPPS. The separate library API can explicitly select that trust model; it
  still verifies the PSK-bound server MAC and Finished, but is not Web PKI trust.

## Certificate evidence policies

`ct_v2` contains `minimum_logs`, `require_inclusion`,
`require_inclusion_after_mmd`, and `logs`. Each log supplies `id` (DER OID value
octets), `public_key_spki`, optional `signature_scheme`, `hash`
(`sha256`/`sha384`/`sha512`), `valid_from_ms`, `valid_until_ms` and
`maximum_merge_delay_seconds`. An optional `trusted_tree_head` supplies `size`,
`timestamp_ms`, and `root`. These are trusted local log choices, not server
suggestions. CT does not replace certificate path/name validation.

`dane` contains absolute getdns `library`, DNSKEY/DS `trust_anchors`, a stable
`application_policy_context`, and optional `allow_authenticated_denial`.
The origin port is used automatically. Native certificate path callbacks use
the explicit profile roots; the browser adapter also supplies its validated
path where applicable. DNSSEC denial never itself authenticates a server.
Change `application_policy_context` whenever independently managed DANE trust
policy changes. The profile requires `native_library` for path validation.

`its` supplies absolute `library`, `identity`, `role` (server 0/client 1),
`psid`, `application_scope`, `ssp_coer`, `trust_roots`, `authorized_leaves`,
optional `revoked`, `allowed_regions`, and `geographic_containment` pairs of
exact COER `parent`/`child` encodings. Such pairs assert containment verified by
an independently trusted local geographic authority, never by the peer.
Also required: `inventory_valid_until` (IEEE Time64),
`max_grant_lifetime_microseconds`, and explicit `tai_utc_offset`. Inventory
and grant expiry remain enforced. The policy does not turn ITS pseudonyms into
arbitrary Web PKI identities.

## Negotiation controls

These optional fields map to the same validated transport options used by the
native engine. Incompatible combinations fail before a ClientHello is sent:

- Lists: `cipher_suites`, `groups`, `psk_modes`,
  `certificate_signature_algorithms`, `grant_signature_algorithms`,
  `certificate_compression`.
- Booleans: `continuity_pinning`, `no_alpn_http11`, `post_handshake_auth`,
  `spontaneous_authenticators`, `delegated_credentials`, `grease`,
  `request_ocsp`, `request_scts`.
- Bounds/options: `record_size_limit`, `max_fragment_length`, `heartbeat_mode`,
  `record_padding_multiple`, `client_hello_padding`,
  `authenticator_context_budget`, `authenticator_message_budget`.
- Evidence: `certificate_authorities`, `ocsp_responder_ids` (binary arrays),
  `ocsp_request_extensions` (binary).
- `ticket_request`: `new_session_count` and `resumption_count` (0..255).
- `signaling`: independently authenticated `local_hash`, `peer_hash`,
  `local_session_id`, `peer_session_id` and optional `required`.

ALPN otherwise comes from the browser HTTP stack. `no_alpn_http11` explicitly
agrees on HTTP/1.1 without ALPN, never HTTP/2. PHA remains forbidden on HTTP/2.
Pinning uses a fresh attempt per connection and disables resumption/0-RTT for
that profile; state is partitioned and in-memory, not durable pin storage.
Application authenticators/exporters are trusted internal socket APIs, not
JavaScript APIs or invented HTTP authentication exchanges.

## Tests

`HttppsProfileConfigTest.*` checks strict decoding and partition isolation.
`net/httpps/tests/browser_profiles_test.py` exercises the production file/IPC
path with fresh local browser profiles and ephemeral credentials:

```text
python net/httpps/tests/browser_profiles_test.py --browser out/Phromium/chrome.exe --server-source ../tls20-server
```

This is distinct from standalone engine interoperability and the broader
cookie/certificate/HTTP2/0-RTT browser suite. Optional native provider tests must
also run on each target platform; a parser/unit-test pass is not evidence that
every operating system's sandbox can load a given administrator-selected file.
