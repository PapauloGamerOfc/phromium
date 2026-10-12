# Full-browser HTTPPS and cookie verification

`browser_e2e_test.py` uses the **built Phromium `chrome.exe`**, not a replacement
browser or a model of Chromium. It creates fresh credentials, a temporary user
profile and loopback-only servers. It makes no changes to OS roots, the normal
browser profile, or external services. It never passes `--ignore-certificate-*`,
disables the sandbox, or bypasses a browser certificate error through CDP.

Prerequisites: Python 3.11+, the reference server's `requirements-dev.txt`
(including the `h2` fixture dependency), and a clean checkout of
`tls20-server` at `da399bb040e24120fc4f303c746291a4a9088a1e`. The revision is
checked before importing its protocol implementation. No dependencies are
downloaded by the script.

For future protocol development, matching server changes may need testing before
they are committed or before this pin is updated. Pass `--allow-server-worktree`
explicitly only for that development case. The report records the server HEAD,
dirty state and SHA-256 of its Python source; it does not represent such a run
as validation of the pinned revision. This option changes only the test-source
provenance check, never certificate validation. Historical clean-revision
results do not validate a subsequent optional-profile expansion.
Use the server and browser from the same migration; the old numbered prototype
is not wire-compatible with the current spec.

## Empty CT requests and ClientHello extension pairing

Known CT18/52 request extensions require empty `extension_data`. Nonempty
requests fail with `decode_error` (50) in initial/PHA CertificateRequest,
including reconstructed cached requests. Application-authenticator requests
fail locally without closing TLS or consuming the context. This does not
change CT response encodings: SCT/TransItem lists and the permitted empty CT52
CertificateEntry remain valid under the existing evidence policy. Unknown
request extensions remain ignorable. The wire harness now covers 124 combined
OID/CT cases with and without client credentials; the authenticator peer sends
42 malformed requests alongside successful identity/refusal controls.

The reference server also rejects unpaired `supported_groups`/`key_share`
ClientHello extensions with `missing_extension` (109), including PSK-only
offers. PSK-ke without either extension is still valid. Twelve native initial
and retry ClientHello controls check that Phromium keeps the pair together
across PSK modes and early-data offers.

Local Windows validation for this correction passed a full browser/network-test
build, all 34,794 network tests without retries, seven CTests, 28 ordinary and
22 provider interoperability commands. The real browser passed 38 end-to-end
checks and the 40-profile, 54-evidence and 14-client-OCSP matrices under each of
the default and explicitly enabled network-service sandbox policies. The
matching server passed 847 tests on both Python 3.11 and 3.12 with all native
providers and only two Windows-specific skips. An older PSK fixture was updated
to send the required empty key_share alongside its advisory group list; the
production validation was not relaxed. Logs use the `ct-pair` prefix under
`out/Phromium`, `out/httpps-native` and the server's `build` directory. These
local results do not imply completed cross-platform CI or a formal security proof.

## Credential request filters, Finished framing and retired secrets

`oid_filter_interop_test.py` exercises actual encrypted initial and
post-handshake CertificateRequest messages, both with a provisioned X.509 client
identity and without one. Malformed OID/KeyUsage/ExtendedKeyUsage encodings must
produce `decode_error` (50); duplicate OIDs and prohibited `anyExtendedKeyUsage`
produce `illegal_parameter` (47). Empty filters and unknown OIDs, including
opaque values, remain valid. Positive controls complete authentication and HTTP
traffic. The record-layer client and application authenticators share the
filter parser, so refusing an identity does not bypass syntax validation.

The matching server also checks Finished against the negotiated hash size before
verifying its MAC. Its wire regressions preserve the password server's
authentication-failure mask for correctly sized invalid proofs. Additional
regressions cover compressed-certificate framing and codec alerts, duplicate
extensions, invalid DH shares, and retiring handshake secrets at epoch changes.

Earlier OID-only validation included a complete browser build, seven native CTests,
28 ordinary and 22 provider interoperability commands, and 88 OID-filter wire
cases. The actual browser passed 38 cookie/certificate/resumption checks and,
under both default and explicitly enabled network-service sandbox policies,
40 profile, 54 evidence and 14 client-OCSP cases per policy. Of 34,794 network
tests, 34,793 passed on the first run; the Python runtime test passed separately
after adding the required depot_tools runtime to the test process's PATH. This
was an environment correction, not a test exclusion or production-code change.
These are local results; platform CI results must be checked for the actual
committed revisions separately.

## HTTP 425, handshake-stage alerts and SM3 parameter erasure

HTTP 425 recovery also covers explicitly provisioned non-X.509 HTTPPS
identities. Accepted early requests are retried only under the existing safe
request policy, after handshake confirmation and without early data. The
browser profile tests exercise X.509, RPK, external/imported/combined PSKs and
password sessions, and reject unsafe or repeated retry loops. This does not
change certificate validity or authorize a new trust path.

Handshake-stage tests distinguish malformed ServerHello/HelloRetryRequest
session-id vectors (`decode_error`, 50) from well-formed nonmatching echoes
(`illegal_parameter`, 47). The optional SM3 provider regression observes owned
parameter allocations before release, checking that the copied HKDF secret is
cleared on successful derivation, failure and exception unwinding. It runs in
an isolated executable with the explicitly selected provider, never by
installing allocation hooks in the browser. Seventeen expansion cases and
three observer controls check actual pre-free storage; the old engine fails
the success, error and exception controls. Twelve framing cases cover both
ServerHello and HelloRetryRequest.

Local Windows validation rebuilt the full browser and network-test executable:
34,794 network tests passed with retries disabled, together with seven CTests,
27 ordinary interoperability commands and 22 provider commands. The actual
browser passed 38 end-to-end assertions and the 40-profile, 54-evidence and
14-client-OCSP matrices under each of the default and explicitly enabled
network-sandbox policies. Harness/runtime regressions (21) and branding tests
(nine) also passed. Logs use `out/Phromium/stage-sm3-425-*`,
`out/httpps-native/stage-sm3-425-*` and `out/stage-sm3-425-*`. These local results
do not claim a Linux/macOS full-browser build, a future CI result or a formal
security proof.

## Ticket and delegated-credential alert regressions

Secret-lifecycle regressions cover both KeyUpdate directions, rejected hybrid
key agreements and HelloRetryRequest changes of key-share size or family.
They check that replaced traffic keys and abandoned shared secrets are cleared
before their allocations are released, including the tail of a shortened
scalar. Pinning-proof transcripts and GOST HKDF expansion reserve their final
capacity before inserting derived secrets, so vector growth cannot release an
uncleansed copy. The GOST checks require an explicitly configured provider.
Positive controls retain valid traffic, retry and pinning-proof behavior.
These checks concern native buffers owned by the engine, not erasure of copies
retained by applications, diagnostic logs or external providers.

Cached credential-reference regressions check encrypted `decode_error` (50)
for truncated fields and trailing bytes, while well-framed unknown hashes,
wrong contexts and metadata-count mismatches retain `illegal_parameter` (47).
They cover plain/compressed CachedCertificate messages and initial/PHA
CachedCertificateRequest messages without weakening trust or local budgets.

The portable protocol regressions verify that malformed NewSessionTicket
vectors and early-data limits produce `decode_error` (50), never enter the
ticket cache, and erase connection-owned secrets. Valid tickets and unknown
well-formed ticket extensions remain accepted.

`delegation_interop_test.py` checks actual encrypted alerts for malformed grants
(50), invalid signatures or direction (47), and independent parent-trust
failure (42), including compressed flights and the explicitly selected
unauthenticated profile. The local certificate-error classification is retained
when a delegated-grant alert differs from `bad_certificate`. The certificate
extension matrix checks the RFC 9345-specific unsolicited-delegation alert (10)
without changing the generic unsupported-extension alert (110).

## Negotiated features and private/DANE evidence regressions

`browser_evidence_test.py` uses the actual browser with temporary profiles and
loopback peers. It covers offered/selected/omitted TLS Features, fresh and
resumed connections, compression, private-CA and DANE-TA CT v2, and OCSP
signature, responder authorization, CertID, freshness, status and nonce checks.
An omitted DANE trust anchor is recovered from the validated TLSA path; it is
not added to ordinary PKIX roots. Required SCT v1 still follows the browser's
existing CT/log policy and cannot be satisfied by parsing a blob.

```sh
python net/httpps/tests/browser_evidence_test.py --browser out/Default/chrome.exe --server-source ../tls20-server --manifest ../tls20-server/build/repro-providers/providers.json
python net/httpps/tests/browser_evidence_test.py --browser out/Default/chrome.exe --server-source ../tls20-server --manifest ../tls20-server/build/repro-providers/providers.json --enable-network-sandbox
```

Like the profile harness, this stages only public test libraries into an owned
temporary directory on Windows. It does not modify OS trust, existing browser
profiles or production services. `compression_alert_interop_test.py` separately
checks encrypted native-client alerts against a wire peer for all three codecs:
invalid payload/length yields `bad_certificate` (42), while malformed envelopes
and unoffered algorithms keep their distinct errors. Positive controls require
an established connection and exchanged application data.

## EncryptedExtensions offers and OCSP responder rollover: 2026-10-12

`extension_alert_interop_test.py` checks the actual encrypted fatal alert:
an unoffered response in EncryptedExtensions is `unsupported_extension` (110),
while recognized extensions in a prohibited message remain
`illegal_parameter` (47). Offered but invalid content and malformed framing
keep their distinct errors. Positive controls complete the handshake and HTTP
exchange; negative controls must not produce Finished or application data.

The browser evidence suite includes private-CA and DANE-TA OCSP responses with
multiple authorized responder certificates sharing a subject name during key
rollover. It covers both auxiliary-list orders, responder-name/key identifiers,
irrelevant expired/unauthorized candidates and invalid actual signers. Successful
cases must also resume; name equality alone never authorizes a response.

The Windows browser and integrated network-test binaries were rebuilt. All
34,789 integrated network tests passed with retries disabled, as did six portable
CTest targets, 24 ordinary interoperability commands and 19 optional-provider
commands. Actual-browser checks passed: 38 end-to-end assertions, plus 54
evidence cases, 40 profile cases and 14 client-OCSP cases under each of the
default and explicitly enabled network-sandbox policies. The 15 browser-harness
and nine branding tests passed.

The suite, signature-profile and extension-alert interop harnesses use selector
networking on Windows to avoid a Proactor shutdown race; other platforms retain
their asyncio subprocess implementation. Six helper regressions cover subprocess
output, deadlines, cleanup and fatal callback errors, and passed on Python 3.11
and 3.12. Cleanup timeouts and unexpected event-loop exceptions fail the tests.
Reports are retained under `out/httpps-native/audit-fixes-*`,
`out/Phromium/audit-fixes-*` and `out/ee-alert-evidence-all-*`. These are local
Windows results, not a claim that remote Linux/macOS CI or all Chromium tests
have run locally.

## Requested authenticator OCSP semantics: 2026-10-12

Both requested authenticator directions use CertificateRequest extension
semantics: `status_request` must be empty. Malformed nonempty requests are
rejected before consuming their context. Unsolicited server authenticators
still inherit the full ClientHello OCSP request. Public API and real-wire tests
exercise valid empty requests, malformed requests, context reuse after rejected
input, authenticated refusals and spontaneous identities under certificate and
password authentication.

`client_ocsp_interop_test.py` exercises configured client evidence against the
reference server's real PKIX/OCSP policy. Native mode covers initial, PHA and
exported-authenticator requests; browser mode covers initial/PHA through the
profile loader and network service. Each path includes signed GOOD evidence
and missing, bad-signature, revoked, unknown, expired and wrong-CertID failures.
The leaf also requires TLSFeature 50 and client MAC share 0xff03. Subsequent
PHA/EA requests without extension 5 must not receive previously requested OCSP.
Browser fixtures explicitly select HTTP/1.1 without ALPN, since a browser offer
containing HTTP/2 must not advertise PHA.

```sh
python net/httpps/tests/client_ocsp_interop_test.py --browser out/Default/chrome.exe --server-source ../tls20-server
python net/httpps/tests/client_ocsp_interop_test.py --browser out/Default/chrome.exe --server-source ../tls20-server --enable-network-sandbox
```

The production Windows browser and test binaries were incrementally rebuilt.
Local validation passed six portable CTest targets, 22 interoperability
invocations, 19 optional-provider commands, 15,803 selected integrated network
tests with retries disabled, 30 service tests, eight component tests, 38
real-browser checks and 34 provisioned-profile cases under each of the default
and explicitly enabled network-sandbox policies. The 15 harness tests and nine
branding tests passed. Reports are under `out/httpps-native/request-conformance-*`
and `out/Phromium/request-conformance-*`. This is local Windows evidence, not a
claim that the entire Chromium test suite or remote Linux/macOS CI ran locally.

## Certificate budgets, requests and retry alerts: 2026-10-11

Wire parsing, local client credentials, cached material and both certificate
verifiers now accept up to 64 presented certificates. A separately configured
anchor may extend the verified path to 65 entries. Per-certificate, aggregate
byte, identity, role and trust checks remain independent and mandatory.

CertificateRequest validates known extension syntax even when no client
credential is configured: authority vectors must be nonempty and contain valid
DER Names, and the OCSP-request extension must be empty in this direction.
The same checks apply to post-handshake and both requested authenticator
directions. Only spontaneous server authenticators retain the full ClientHello
OCSP structure (corrected on 2026-10-12).
A repeated HelloRetryRequest returns `unexpected_message`, including with
unknown or changed suite/group fields, while invalid first selections remain
`illegal_parameter` failures.

Exact-alert socket tests allow a complete fatal-record write. Separate tests
limit writes to three bytes and verify immediate closure, no credential or
application-data response and no late callbacks. Fatal-alert delivery remains
best effort; these tests do not require a closed transport to finish writing an
alert or retain protocol secrets while waiting for it.

`chain_limit_interop_test.py` exercises real chains of 9 and 64 certificates,
initial/PHA client credentials, a separate anchor, and rejected 65-entry,
wrong-key, untrusted and oversized inputs. Pass `--native-provider` with an
explicit OpenSSL library to run the additional native-verifier boundary cases.
Both forms are included in CI; the unconfigured form reports its three
optional-provider skips explicitly.

Final local Windows validation passed six portable CTest targets, 22
interoperability invocations, 19 optional-provider commands, 12,108 selected
integrated network tests, 30 service tests, eight component tests, 38 real-browser
assertions and 34 provisioned-profile cases under each of the default and
explicit network-sandbox policies. The network rerun had no retries or runtime
skips; six pre-existing disabled tests matching that selection were not enabled.
An initial run exposed the fixture's incorrect complete-alert expectation under
short writes; the tests were separated as described above and the entire
selection rerun, not just the failed test. The 15 harness self-checks and nine
branding checks passed. Logs/reports are under `out/httpps-native/cert-conformance-*`
and `out/Phromium/cert-conformance-*`. These are local Windows results, not
completed remote Linux/macOS CI or a formal security audit.

## Failure metadata and directional delegation: 2026-10-11

Fatal socket I/O now destroys the protocol object and its secrets while retaining
only public SSL connection metadata for error reporting. Regression tests cover
write failure, EOF, authenticated fatal alerts, malformed encrypted records and
an early-connect timeout; explicit Disconnect invalidates the metadata. The new
post-failure query test reproduced the null-dereference crash before the fix.

Installing an outgoing client delegated credential no longer applies the
ClientHello's independent server-grant offer. Local signature, role, lifetime,
authorization and key-matching checks remain mandatory. Actual initial/PHA and
application-authenticator requests still enforce their own grant offers.
Interop tests exercise disjoint ECDSA server/Ed25519 client grants, per-request
changes, authenticated refusals and nine local valid/invalid credential cases.

Local Windows validation passed six portable CTest targets, 21 interoperability
invocations, all 18 optional-provider commands, 11,705 selected integrated network
tests with retries disabled, 30 service tests, eight component tests,
38 actual-browser assertions, and 34 profile cases
under each of the default and explicitly enabled network-sandbox policies.
All executed network tests passed on the first attempt, with no runtime skips;
six pre-existing disabled tests matching the selection were not enabled.
The 15 harness self-checks and nine branding checks also passed. Logs/reports are
under `out/httpps-native/four-fixes-*` and `out/Phromium/four-fixes-*`.
These are local Windows results, not completed remote Linux/macOS CI or a
formal security audit.

## OCSP, authenticator and alert conformance: 2026-10-11

The portable engine and complete Windows browser were rebuilt after fixing
unsupported critical OCSP request requirements, unsupported delegation offers
in application authenticators, and fatal-alert classification. Regressions cover
fresh and cached OCSP evidence before resumption/0-RTT, direct identities and
authenticated refusals in both authenticator directions, selected-grant policy,
and exact authenticated alert codes with valid-message controls.

Local validation passed all six portable CTest targets, 20 interoperability
invocations, all 18 optional-provider commands, 11,702 selected integrated network
tests with retries disabled, 30 service tests, eight component tests, 38 actual
browser assertions and 34 provisioned-profile cases under each of the default
and explicitly enabled network-sandbox policies. Harness self-checks (15) and
branding checks (nine) also passed. The matching reference-server suite ran
637 tests with only two Windows-specific skips when all native providers were
enabled; its package and isolated-installation checks passed. Logs are under
`out/httpps-native/three-fixes-*` and `out/Phromium/three-fixes-*`.
These are local Windows results, not completed remote Linux/macOS CI or a
formal security audit.

## Retry-conformance validation: 2026-10-11

The rebuilt Windows browser and portable engine reject an explicit HRR group
zero and unencodable retry extension vectors. Regressions retain valid
cookie-only/group retries and the 65,535-byte extension-vector boundary, with
and without PSKs, including an independently recomputed retry binder.

Local validation passed: six portable CTest targets, all 19 interoperability
invocations and all 18 optional-provider commands; 11,552 selected integrated
network tests, 30 service tests and eight component tests; 38 actual-browser
end-to-end assertions; and 34 browser-profile cases under each of the default
and explicitly enabled network-sandbox policies. The harness self-checks (15)
and branding checks (nine) also passed. Certificate checks and browser
mitigations were not disabled. Logs/reports are under
`out/httpps-native/retry-conformance-*` and `out/Phromium/retry-conformance-*`.

The broader PAC tests exposed Windows checkout newline conversion, not a
protocol failure. `.gitattributes` now preserves LF for the byte-compared PAC
payloads and UTF-8 BOM fixture. Their bytes match the existing repository blobs;
the test expectations were not relaxed. The entire selected network suite was
rerun successfully with retries disabled. These results cover local Windows,
not an already completed remote Linux/macOS CI run or a formal security audit.

## Running on Windows

After a complete Chromium dependency sync and GN generation, build the browser
and the relevant integrated tests:

```powershell
autoninja -C out/Default chrome net_unittests services_unittests components_unittests content_unittests content_browsertests extensions_unittests blink_tests
```

Run the real-browser harness with the Python environment containing the
reference server's dependencies:

```powershell
python net/httpps/tests/browser_e2e_test.py --browser out/Default/chrome.exe --server-source ../tls20-server --report out/Default/httpps-browser-results.json
```

The script rejects an unknown private CA with no HTTPPS trust argument, then
uses `--httpps-trust-anchor` **only in its separate test profile** to exercise
successful encrypted HTTPPS. It uses the same hostname and port for HTTP,
HTTPS, and HTTPPS through a small local protocol demultiplexer. Port-bound and
scheme-bound cookie experiments are explicitly disabled, so they cannot mask a
failure of the mandatory HTTPPS namespace boundary.

Coverage:

- Real browser session resumption and 0-RTT over separate TCP connections,
  with server-side confirmation that early HTTP arrived before client Finished.
- HTTP 425 refusal followed by a browser retry without early application data.
  These tests use a separate temporary profile and replay-aware fixture, not the
  cookie-validation peers.
- Actual HTTP/2 negotiation with 16 parallel streams on one authenticated
  HTTPPS connection, correct `:scheme`/path/cookie fields, and rejection of
  ordinary HTTPS under that HTTPPS-only private CA on the same authority.

- Actual HTTP and HTTPPS requests, `Set-Cookie`, `document.cookie`, and `fetch`.
- Independent same-name cookies on the same host and port.
- A non-`Secure` HTTPPS cookie stays out of HTTP/HTTPS too, so the ordinary
  `Secure` restriction cannot conceal a broken namespace boundary.
- `Secure` and `HttpOnly` handling, script writes, overwrite, expiry, and restart
  persistence without cross-protocol cookie disclosure.
- HTTPPS is recognized as a secure context by the actual renderer.
- An HTTPS cookie seeded through CDP is absent from HTTPPS requests and script
  writes. This is **not** a successful HTTPS page navigation: the temporary CA
  is intentionally not installed as a normal HTTPS root.
- A real ordinary HTTPS listener under that private CA is rejected; the extra
  HTTPPS root must not leak into HTTPS trust.
- Bad hostname, expired certificate, bad server proof and untrusted CA fail
  before the server receives any HTTP application data, including an incomplete
  request header. The exact expected
  certificate/proof error code is required; timeout, DNS failure or an unrelated
  navigation error is not counted as successful rejection.
- Duplicate same-name cookies are rejected by the assertion helper, so a leaked
  cookie cannot be hidden by converting a cookie header to a dictionary.

The harness does **not** claim to test successful public-root HTTPPS issuance:
that requires an appropriate X25519 server certificate, not an ordinary HTTPS
leaf. Shared browser path-builder acceptance and normal chain-policy regressions are
tested with the real `CertVerifyProcBuiltin` below. No trust-policy bypass is
used to pretend otherwise.

Initial client-certificate authentication has a separate scope: the portable
engine accepts an explicitly supplied `ClientCredential` and produces the
client's X25519 MAC proof (`0xfe01`). With no selected credential it answers an
initial CertificateRequest with an empty Certificate, which may be accepted or
rejected by the server's optional/required-client policy. The browser does not
automatically discover or prompt for a client identity. Its default is that empty
response; the production-profile tests below cover an explicitly provisioned
identity, not selection through a GUI. Embedders can explicitly provision an identity through
`SSLClientContext::SetHttppsClientCredential`, scoped to the exact origin,
network/privacy context and proxy role. That route supports initial/PHA MAC
authentication; HTTP/2 never advertises or permits TLS PHA. The default remains
no selected identity, and there is no automatic reuse of an HTTPS client key.

## Portable session and authentication checks

The CI workflow separately compiles the actual native engine on Windows, Linux
and macOS and runs the following scripts. For the specification oracle, use a
checkout of `tls20-spec` at
`dee31da9826e10bd590f58acc0f9f46143505fd1`; CI checks out that exact revision
under `out/reference-spec` rather than importing the moving default branch.

```powershell
python net/httpps/tests/session_interop_test.py --native out/httpps-native/Release/httpps_native_test.exe --server-source ../tls20-server
python net/httpps/tests/client_auth_interop_test.py --native out/httpps-native/Release/httpps_native_test.exe --server-source ../tls20-server
python net/httpps/tests/client_ocsp_interop_test.py --native out/httpps-native/Release/httpps_native_test.exe --server-source ../tls20-server
python net/httpps/tests/chain_limit_interop_test.py --native out/httpps-native/Release/httpps_native_test.exe --server-source ../tls20-server
python net/httpps/tests/spec_oracle_test.py --native out/httpps-native/Release/httpps_native_test.exe --server-source ../tls20-server --spec-source ../tls20-spec
```

Use `out/httpps-native/httpps_native_test` for a single-configuration Linux/macOS
build. Session tests exercise full and resumed connections, early acceptance
and rejection, and KeyUpdate. Client-auth tests exercise optional/required
refusal, selected MAC credentials, rejected authorization, and resumed client
identity. The independent specification oracle uses the spec's derivation
helpers with its own peer framing/state machine for transcript/KDF, HRR, binder,
exporter, ticket, early-data and KeyUpdate checks; its only reference-server
import generates temporary certificate fixtures. These are interoperability
regressions, not a proof of protocol security or full browser coverage.

## Integrated C++ and DevTools tests

```powershell
out/Default/net_unittests.exe --gtest_filter="*Httpps*:*HTTPPS*:CookieMonsterTest.HttpAndHttpsStillShareNonSecureCookies:CertVerifierTest.*:MultiThreadedCertVerifierTest.*"
out/Default/services_unittests.exe --gtest_filter="*Httpps*:*HTTPPS*:CookieManagerTraitsTest.*"
out/Default/components_unittests.exe --gtest_filter="*Httpps*"
out/Default/content_unittests.exe --gtest_filter="*Httpps*:BrowsingDataFilterBuilderImplTest.CookieNamespaceSurvivesDeletionPipeline"
out/Default/content_browsertests.exe --gtest_filter="ClearSiteDataHandlerBrowserTest.CookieDeletionKeepsOtherProtocolNamespace"
out/Default/extensions_unittests.exe --gtest_filter="*Httpps*"
python third_party/blink/tools/run_web_tests.py -t Default http/tests/inspector-protocol/network/cookies-httpps-isolation.js
```

`net_unittests` includes real chain validation under an explicitly trusted test
root, rejection of that leaf for ordinary TLS, incorrect key usages, unknown
roots, hostname/expiry/name constraints/distrust, CT policy, async certificate
verification, cancellation and deadlines. Cookie tests cover feature-on/off and
legacy scope, database reload/encryption binding, isolation during notifications
and deletion, and HTTP/HTTPS compatibility. `services_unittests` covers Mojo,
renderer cookie writes, private-session cleanup, and forbidden certificate
exceptions. A full run of these binaries is recommended after the targeted pass.

List tests with `--gtest_list_tests` before interpreting a filtered run: an empty
matching set is not a passing validation. The build may require separate test
data targets depending on the GN configuration.

## Production profile provisioning tests

`browser_profiles_test.py` launches the actual browser with temporary,
origin/partition-scoped `--httpps-profile-file` files. Only the file path appears
on the command line; fixture passwords and private keys stay in the temporary
file. These tests do not disable the browser sandbox or certificate validation,
and do not change the OS trust store.

```powershell
python net/httpps/tests/browser_profiles_test.py --browser out/Default/chrome.exe --server-source ../tls20-server
python net/httpps/tests/browser_profiles_test.py --browser out/Default/chrome.exe --server-source ../tls20-server --manifest ../tls20-server/build/repro-providers/providers.json
python net/httpps/tests/browser_profiles_test.py --browser out/Default/chrome.exe --server-source ../tls20-server --manifest ../tls20-server/build/repro-providers/providers.json --enable-network-sandbox
```

On Windows, providers loaded by the network service also need read/execute
access under its sandbox identity. An arbitrary sibling build directory need
not have the browser output's AppContainer ACL. For these public test libraries,
add `--stage-native-libraries` to copy exactly the five manifest-selected DLLs
and the existing `openssl_prefix/bin/libssl-3-x64.dll` dependency into a fresh
UUID-named subdirectory of the browser output. It inherits the output ACL,
prints only a boolean diagnostic for restricted-AppContainer inherited access,
and is removed after the test. No existing ACL is changed; no PATH search is
used. Profile files, passwords and private keys remain in a separate private
temporary directory and are never staged alongside the libraries. A normal
Windows `TemporaryDirectory` has a deliberately private DACL, so it is unsuitable
for this public-library staging even when placed under the browser output.
Run both the default-policy and explicit-sandbox commands with the same staging
option when comparing results. Use `--case native-x448` for a focused load check.

The base cases cover private roots, explicit no-ALPN HTTP/1.1, client MAC
credentials, raw keys, direct/imported/combined PSKs, HRR cookies, hybrid key
exchange, signed/tampered CT v2 evidence, and invalid
credentials/configuration/partition scope. Bootstrap cases offer two BSKs and
two KDFs, require selection of the second BSK with SHA-384, repeat the test with
HRR, and verify selected-identity resumption on a new browser connection.
Unknown BSKs and mismatched possession keys must fail before application data.
Missing or invalid DLL profiles must
reject HTTPPS without crashing the network service; normal HTTP navigation is
checked before and after each rejection. The provider
manifest additionally exercises actual network-service DLL loading for X448,
SM, GOST, password/mixed authentication, DNSSEC/DANE and IEEE ITS, including
wrong-password, wrong-TLSA-association and revoked-ITS-grant negatives.
DANE PKIX-TA, PKIX-EE and DANE-TA cases also preserve an intermediate CA's
TLS Feature constraints through full handshakes and resumption, and reject a
leaf which drops those constraints. The DANE-TA cases deliberately have no
ordinary CA anchors; `--case dane-ta-missing-features` isolates that regression.
ITS requires freshly generated fixtures: the live grants deliberately expire
after 25 minutes, so regenerate them after a long browser build rather than
weakening expiry checks. A portable-engine provider test is not a substitute for these
browser navigation checks.

Record the default-policy and explicit `NetworkServiceSandbox` runs separately:
absence of `--no-sandbox` alone does not prove the network-service sandbox is
enabled on a platform whose upstream feature default is disabled. The last
command explicitly enables it without disabling other mitigations.

## Test-harness self-checks

These commands do **not** validate a browser build; they only validate the local
WebSocket harness, certificate fixtures and protocol multiplexer:

```powershell
python net/httpps/tests/browser_e2e_unittest.py
python net/httpps/tests/browser_e2e_test.py --server-source ../tls20-server --fixtures-only-native out/httpps-native/Release/httpps_native_test.exe
```

Browser startup, navigation and shutdown have bounded deadlines. Profiles and
generated test keys are temporary and removed after the owned browser closes.
Use `--report` to retain the pass/fail JSON. The JSON distinguishes a real-browser
run from a fixture-only check; a fixture pass must never be reported as a browser
pass. On a browser failure it also retains the last 16 KiB of each browser stderr
log and bounded fixture/CDP diagnostics, not the generated credentials or user
profile. Unexpected event-loop errors fail the run. Windows uses selector-based
networking with bounded subprocess operations to avoid a Python 3.12 Proactor
shutdown defect after intentionally rejected peer connections.
