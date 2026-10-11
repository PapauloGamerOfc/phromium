# Full-browser HTTPPS and cookie verification

`browser_e2e_test.py` uses the **built Phromium `chrome.exe`**, not a replacement
browser or a model of Chromium. It creates fresh credentials, a temporary user
profile and loopback-only servers. It makes no changes to OS roots, the normal
browser profile, or external services. It never passes `--ignore-certificate-*`,
disables the sandbox, or bypasses a browser certificate error through CDP.

Prerequisites: Python 3.11+, the reference server's `requirements-dev.txt`
(including the `h2` fixture dependency), and a clean checkout of
`tls20-server` at `18e04497259e21549c996dfb8ad45ea4ce590760`. The revision is
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
rejected by the server's optional/required-client policy. The browser currently
does not select or prompt for a client identity. Its default is that empty
response; the real-browser harness does not test successful client identity
selection through a GUI. Embedders can explicitly provision an identity through
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
