// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTPPS_DRAFT01_H_
#define NET_HTTPPS_DRAFT01_H_

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

#include "net/httpps/portable.h"
#include "net/httpps/control_profiles.h"

#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_EXPORT
#else
#include "net/base/net_export.h"
#define HTTPPS_EXPORT NET_EXPORT_PRIVATE
#endif

namespace net::httpps {

using Bytes = std::vector<uint8_t>;
using Secret = std::array<uint8_t, 32>;
enum class RequestExtensionContext {
  kCertificateRequest, kServerAuthenticator, kClientAuthenticator, kNewSessionTicket
};
HTTPPS_EXPORT bool RequestExtensionAllowed(uint16_t code, RequestExtensionContext context);
class PinAttempt;
class NativeProvider;
class NativeTrafficKey;
class NativePasswordState;
class NativeGostRecord;
struct CTv2Policy;
struct DANEPolicy;
struct ITSPolicy;
inline constexpr std::string_view kPreface = "TLS20-EXPERIMENT\r\n";
inline constexpr size_t kMaxRecordContent = 16384;
inline constexpr size_t kMaxRecord = 16645;

enum class Authentication {
  kCertificate,
  kRawPublicKey,
  kExternalPsk,
  kCertificateAndPsk,
  kRawPublicKeyAndPsk,
  kProvisioning,
  kDaneCertificate,
  kDaneRawPublicKey,
  kDaneCertificateAndPsk,
  kDaneRawPublicKeyAndPsk,
  kPassword,
  kITS,
  kITSAndPsk,
  kUnauthenticated,
};

// A credential, not a public cache entry. The owner MUST partition tickets by
// origin/port, route, privacy context and trust configuration. Do not serialize
// them or send early data without the application's explicit replay policy.
struct HTTPPS_EXPORT SessionTicket {
  Bytes identity;
  Bytes psk = Bytes(32);
  uint16_t cipher_suite = 0x1301;
  std::string alpn = "http/1.1";
  uint16_t peer_record_limit = 16385;
  uint8_t server_certificate_type = 0;
  uint8_t client_certificate_type = 0;
  Authentication authentication = Authentication::kCertificate;
  // Local ticket metadata, not an NST wire field. Successors may narrow, never
  // broaden, the key-exchange modes offered by their originating handshake.
  std::vector<uint8_t> allowed_psk_modes{1};
  Secret external_psk_binding{};
  Secret selected_client_identity{};
  Secret bootstrap_policy{};
  Secret signaling_context{};
  Secret password_context{};
  Bytes ct_policy_context;
  Bytes dane_policy_context;
  int64_t dane_expires_unix_seconds = 0;
  Bytes its_policy_context;
  int64_t its_expires_unix_milliseconds = 0;
  Bytes delegation;
  uint32_t lifetime = 0;
  uint32_t age_add = 0;
  uint32_t max_early_data = 0;
  int64_t received_milliseconds = 0;
  std::string hostname;
  std::vector<std::string> certificates;
  // Evidence remains bound to these exact certificate entries. Cached bytes
  // must be revalidated under current trust/revocation policy before 0-RTT.
  std::vector<std::map<uint16_t, Bytes>> certificate_extensions;
  // Zero means no client identity. A ticket cannot silently retain an old
  // authenticated client when the caller selects another (or no) credential.
  Secret client_identity{};
  ~SessionTicket();
};

// Explicitly selected for this authenticated server by the application. Never
// reuse an HTTPS signing credential or automatically send a user's identity.
// The server remains responsible for trust and authorization of this chain.
struct HTTPPS_EXPORT ClientCredential {
  std::vector<std::string> certificates;
  Secret private_key{};
  uint8_t certificate_type = 0;
  Bytes delegation;
  // Local authorization of this client-role ITS grant; not a Web PKI chain.
  std::shared_ptr<const ITSPolicy> its_policy;
  ~ClientCredential();
};

// Out-of-band provisioning is the trust decision. Never construct this from
// an identity received on the wire. Scope binds the peer and application.
struct HTTPPS_EXPORT ExternalPSK {
  Bytes identity;
  Bytes secret;
  std::string hostname;
  std::string alpn = "http/1.1";
  uint16_t cipher_suite = 0x1301;
  bool imported = false;
  bool combined = false;
  uint32_t max_early_data = 0;
  ~ExternalPSK();
};

// Explicit account/service selection. Text must be prepared with RFC8265
// OpaqueString before construction; this credential is never an external PSK.
struct HTTPPS_EXPORT PasswordCredential {
  std::string service;
  std::string username;
  std::string password;
  std::string helper_path;
  // Optional separately provisioned RFC8492 username-encryption EC SPKI.
  // Never populate from a key learned in this unauthenticated exchange.
  Bytes protection_spki;
  // Browser provisioning installs the RFC8265/ICU preparation implementation.
  // Without a provider, only printable ASCII (already OpaqueString) is usable.
  std::function<std::optional<std::string>(std::string_view)> prepare_text;
  ~PasswordCredential();
};
HTTPPS_EXPORT std::optional<ExternalPSK> ImportPSK(
    ByteSpan base_key, ByteSpan identity, ByteSpan context, std::string hostname,
    std::string alpn = "http/1.1", uint16_t base_suite = 0x1301,
    uint16_t target_suite = 0x1301, bool combined = false);

struct HTTPPS_EXPORT BootstrapBinding {
  Bytes spki;
  std::string service;
  std::string scope;
  bool provisioning_trust = false;
  int64_t expires_unix_seconds = 0;
  // Each offered BSK may have its own explicitly selected possession key.
  // The legacy singular binding can use Client::SetClientCredential instead.
  std::optional<ClientCredential> credential;
};
HTTPPS_EXPORT std::optional<ExternalPSK> BootstrapPSK(
    const BootstrapBinding& binding, uint16_t suite, std::string alpn);

struct HTTPPS_EXPORT ClientOptions {
  std::shared_ptr<NativeProvider> native_provider;
  std::shared_ptr<const PasswordCredential> password;
  std::shared_ptr<const CTv2Policy> ct_v2_policy;
  std::shared_ptr<const DANEPolicy> dane_policy;
  std::shared_ptr<const ITSPolicy> its_policy;
  std::shared_ptr<PinAttempt> pinning;
  std::optional<BootstrapBinding> bootstrap;
  std::vector<BootstrapBinding> bootstraps;
  // Generic provisioning applications must opt out explicitly. Browser HTTPPS
  // must never change this to turn a failed website certificate into success.
  bool ordinary_httpps = true;
  // Library-only, explicitly chosen before the handshake. MAC and Finished
  // still verify; no authenticated identity is reported or inherited by tickets.
  bool allow_unauthenticated = false;
  // Explicit application agreement to HTTP/1.1 with no ALPN extension.
  bool no_alpn_http11 = false;
  // Browser context creates a fresh attempt in its partitioned continuity cache.
  bool continuity_pinning = false;
  // Explicit non-confidential applications only; forbidden by browser HTTPPS.
  bool allow_integrity_only = false;
  std::optional<TicketRequest> ticket_request;
  std::optional<SignalingBinding> signaling;
  std::vector<uint16_t> cipher_suites{0x1301, 0x1302, 0x1303};
  std::vector<uint16_t> groups{29, 23, 24, 25};
  bool grease = false;
  size_t client_hello_padding = 0;
  std::vector<std::string> alpn_protocols{"http/1.1"};
  // Opt in only with application permission to disclose the selected identity.
  // HTTP/2 connections never advertise or process post-handshake client auth.
  bool post_handshake_auth = false;
  // Advertise only when an external credential policy consumes the evidence.
  bool request_ocsp = false;
  // Complete RFC6066 OCSPStatusRequest. IDs are DER ResponderID values and
  // request_extensions is a DER Extensions sequence (or empty). Matching
  // response metadata never replaces responder/signature/status validation.
  // An application generating a new nonce must use >=32 fresh random bytes
  // (RFC9654); this API also accepts historical 1..128-byte nonce encodings.
  std::vector<Bytes> ocsp_responder_ids;
  Bytes ocsp_request_extensions;
  // DER distinguished names expressing issuer preference, not trust anchors.
  std::vector<Bytes> certificate_authorities;
  bool request_scts = false;
  // Application negotiation/framing remains the caller's responsibility.
  // Only spontaneous server authenticators retain the original auth scalar.
  bool spontaneous_authenticators = false;
  size_t authenticator_context_budget = 65536;
  size_t authenticator_message_budget = 1 << 20;
#if defined(PHROMIUM_HTTPPS_TEST_DIAGNOSTICS)
  // Test-only compilation. The local owner must authorize and protect this
  // whole-entry sink; failure disables it, never redirects to ordinary logs.
  bool authorize_test_diagnostics = false;
  bool authorize_exporter_diagnostics = false;
  std::function<bool(std::string_view)> diagnostic_sink;
#endif
  std::vector<ExternalPSK> external_psks;
  std::vector<uint8_t> psk_modes{1};
  std::optional<uint16_t> record_size_limit;
  std::optional<uint8_t> max_fragment_length;
  std::optional<uint8_t> heartbeat_mode;
  size_t record_padding_multiple = 1;
  std::vector<uint8_t> server_certificate_types{0};
  // These pins are provisioned out of band for this Client's exact origin.
  std::vector<Bytes> server_raw_public_keys;
  std::vector<uint16_t> certificate_compression;
  std::vector<uint16_t> certificate_signature_algorithms{
      0x0807, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
      0x0401, 0x0501, 0x0601};
  bool delegated_credentials = false;
  std::vector<uint16_t> grant_signature_algorithms{0x0807, 0x0403, 0x0503, 0x0603,
                                                 0x0804, 0x0805, 0x0806};
  // Snapshots from authenticated connections in the SAME origin/policy scope.
  // They cache bytes only; every reference receives fresh validation.
  std::vector<std::pair<uint8_t, std::vector<std::string>>> cached_certificates;
  std::vector<Bytes> cached_request_templates;
};

struct HTTPPS_EXPORT AuthenticatorIdentity {
  std::vector<std::string> certificates;
  std::vector<std::map<uint16_t, Bytes>> extensions;
  Bytes context;
};
// Checks only negotiation compatibility, not signatures, trust or authorization.
HTTPPS_EXPORT bool CertificateAlgorithmsAllowed(
    const std::vector<std::string>& chain,
    const std::vector<uint16_t>& offered);
HTTPPS_EXPORT uint16_t GostPublicKeyGroup(ByteSpan spki);
HTTPPS_EXPORT bool CredentialRequestOptionsValid(const ClientOptions& options);
HTTPPS_EXPORT bool OCSPRequestMatchesResponse(const ClientOptions& options,
                                              ByteSpan response);
// Additional opt-in CT v2 policy, never a substitute for current path/name
// validation. The issuer is from that validated path, not unchecked peer data.
HTTPPS_EXPORT bool VerifyCertificateTransparency(
    const CTv2Policy* policy, const std::vector<std::string>& chain,
    const std::vector<std::map<uint16_t, Bytes>>& extensions,
    std::string_view validated_issuer);
HTTPPS_EXPORT std::string ValidatedPrivateIssuer(
    const std::vector<std::string>& chain, const std::vector<std::string>& anchors,
    std::string_view hostname, bool signing_parent = false, const NativeProvider* provider = nullptr);
HTTPPS_EXPORT std::vector<std::string> ValidatedPrivatePath(
    const std::vector<std::string>& chain, const std::vector<std::string>& anchors,
    std::string_view hostname, bool signing_parent = false, const NativeProvider* provider = nullptr);
// A value of -1 is authenticated DNSSEC absence and still requires PKIX.
// nullopt is failure, including an absent requested extension, never fallback.
HTTPPS_EXPORT std::optional<int> VerifyDNSSECPolicy(
    const DANEPolicy* policy, std::string_view hostname,
    const std::vector<std::string>& chain, uint8_t certificate_type,
    const std::vector<std::map<uint16_t, Bytes>>& extensions,
    const std::vector<std::string>& validated_path = {},
    int64_t* expires_unix_seconds = nullptr,
    std::vector<std::string>* authenticated_path = nullptr);
// Must validate the independent X.509 path, current request algorithms,
// evidence, expected identity AND application authorization. Returning a key
// alone is not completed authentication: the MAC/Finished are checked next.
using AuthenticatorValidator = std::function<bool(
    const AuthenticatorIdentity&, const std::map<uint16_t, Bytes>&, Secret*)>;

// The additional private-anchor path deliberately accepts only the ordered,
// offline lab PKI profile documented by tls20-server. Browser clients can also
// delegate trust to the HTTPS verifier using Client's pending-decision API.
// This helper performs no network fetching, TOFU or certificate exceptions.
HTTPPS_EXPORT bool VerifyLabChain(const std::vector<std::string>& chain,
                                  const std::vector<std::string>& anchors,
                                  std::string_view hostname,
                                  Secret* server_public_key,
                                  bool signing_parent = false,
                                  const NativeProvider* provider = nullptr);
HTTPPS_EXPORT bool ValidateDelegation(std::string_view parent, ByteSpan grant,
                                      bool server, const std::vector<uint16_t>& algorithms,
                                      Secret* public_key, const NativeProvider* provider = nullptr);
HTTPPS_EXPORT bool ValidServerName(std::string_view name);
// Check an explicitly configured outgoing client grant before any peer request.
// Remote credentials must use ValidateDelegation with the applicable offers.
HTTPPS_EXPORT bool ValidateLocalClientDelegation(std::string_view parent, ByteSpan grant,
                                                Secret* public_key,
                                                const NativeProvider* provider = nullptr);
// Reference identity may be an IP SAN. SNI host_name remains DNS-only.
HTTPPS_EXPORT bool IsIpIdentity(std::string_view name);
HTTPPS_EXPORT bool ValidServiceIdentity(std::string_view name);
// nullopt means malformed TLSFeature policy. Unknown/unoffered features impose
// no new client requirement (RFC 7633 section 4.3.3). A true
// result requires independently verified fresh OCSP, not just staple presence.
HTTPPS_EXPORT std::optional<bool> CertificateRequiresOCSP(std::string_view der);
// Issuer TLSFeature constraints apply along an independently validated path.
HTTPPS_EXPORT bool CertificateTLSFeaturesAllowed(
    const std::vector<std::string>& validated_path);
// Extracts the exact X25519 SPKI, not a trust decision. The caller must
// authenticate the certificate chain and its server identity separately.
HTTPPS_EXPORT bool ExtractServerPublicKey(std::string_view leaf_der,
                                          Secret* server_public_key);
HTTPPS_EXPORT bool ExtractRawPublicKey(ByteSpan spki, Secret* public_key);
HTTPPS_EXPORT Secret Hash(ByteSpan input);
HTTPPS_EXPORT Secret Mac(ByteSpan key, ByteSpan input);
HTTPPS_EXPORT Bytes Label(ByteSpan secret,
                          std::string_view label,
                          ByteSpan context,
                          size_t length);
HTTPPS_EXPORT size_t SuiteHashLength(uint16_t suite);
HTTPPS_EXPORT uint16_t SuiteHashId(uint16_t suite);
HTTPPS_EXPORT Bytes SuiteHash(uint16_t suite, ByteSpan input, const NativeProvider* provider = nullptr);
HTTPPS_EXPORT Bytes SuiteMac(uint16_t suite, ByteSpan key, ByteSpan input, const NativeProvider* provider = nullptr);
HTTPPS_EXPORT Bytes SuiteLabel(uint16_t suite, ByteSpan secret,
                               std::string_view label, ByteSpan context,
                               size_t length, const NativeProvider* provider = nullptr);

// One direction, one key epoch. Any authentication/format/quota failure latches
// permanently. Cipher states cannot be copied, reset or reused across epochs.
class HTTPPS_EXPORT RecordCipher {
 public:
  explicit RecordCipher(ByteSpan secret, uint16_t suite = 0x1301,
                        std::shared_ptr<NativeProvider> provider = {});
  ~RecordCipher();
  RecordCipher(const RecordCipher&) = delete;
  RecordCipher& operator=(const RecordCipher&) = delete;
  bool Seal(ByteSpan content, uint8_t type, Bytes* record, size_t padding = 0);
  bool Open(ByteSpan record, uint8_t* type, Bytes* content);
  uint8_t alert() const { return alert_; }
  // EE can negotiate a limit after its first protected record was opened.
  bool OpenedRecordsWithinLimits() const {
    return max_opened_inner_ <= inner_limit_ &&
           max_opened_content_ <= content_limit_;
  }
  bool needs_update() const;
  void SetLimit(uint16_t limit) {
    inner_limit_ = limit ? limit : 16385;
  }
  void SetContentLimit(uint16_t limit) { content_limit_ = limit; }

 private:
  friend class ProtocolRegressionPeer;
  bool Account(size_t content_length, bool sending);
  Bytes key_;
  std::shared_ptr<NativeProvider> native_provider_;
  std::unique_ptr<NativeGostRecord> gost_record_;
  uint16_t suite_ = 0x1301;
  Bytes iv_;
  uint64_t sequence_ = 0;
  uint64_t content_bytes_ = 0;
  bool failed_ = false;
  uint8_t alert_ = 20;
  size_t max_opened_inner_ = 0;
  size_t max_opened_content_ = 0;
  uint16_t inner_limit_ = 16385;
  uint16_t content_limit_ = 16384;
};

// I/O-independent client state machine. Give it exactly one complete record at
// a time. Start() emits preface + CH; TakeOutput() then exposes only encrypted
// CF or close_notify. CF must be fully written before OutputFlushed()
// establishes the channel. No received application bytes are available before
// that point.
class HTTPPS_EXPORT Client {
 public:
  enum class Error { kNone, kProtocol, kCertificate, kTimeout };
  Client(std::string hostname,
         std::vector<std::string> trust_anchors,
         bool use_external_verifier = false,
         ClientOptions options = {});
  ~Client();
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  bool Start(const SessionTicket* ticket = nullptr, ByteSpan early_data = {},
             bool enable_early_data = false);
  bool SetClientCredential(const ClientCredential& credential);
  bool SendEarlyData(ByteSpan data, Bytes* record);
  bool early_data_available() const {
    return state_ == State::kHello && early_offered_;
  }
  bool Receive(ByteSpan record, Bytes* application_data);
  bool Send(ByteSpan application_data, Bytes* record);
  bool Close(Bytes* record);
  Bytes TakeOutput();
  Bytes TakeFatalAlert() { return std::exchange(fatal_alert_, {}); }
  bool OutputFlushed();
  bool certificate_verification_pending() const;
  // Resume only after the external verifier has authenticated the unchanged
  // certificates() for this hostname. No proof/Finished or application traffic
  // is accepted while the decision is pending. A negative decision is fatal.
  bool CompleteCertificateVerification(bool trusted,
                                       std::string_view validated_issuer = {},
                                       const std::vector<std::string>& validated_path = {});
  bool established() const;
  bool closed() const;
  bool resumed() const { return resumed_; }
  bool server_mac_authenticated() const {
    return authentication_ != Authentication::kExternalPsk && authentication_ != Authentication::kPassword;
  }
  Authentication authentication() const { return authentication_; }
  bool delegated() const { return !server_delegation_.empty(); }
  bool bootstrap_authenticated() const { return established() && options_.bootstrap.has_value(); }
  bool client_identity_authenticated() const {
    return authenticated_client_identity_ != Secret{};
  }
  uint16_t traffic_group() const { return traffic_group_; }
  uint16_t cipher_suite() const { return suite_; }
  uint8_t server_certificate_type() const { return server_certificate_type_; }
  const std::string& negotiated_alpn() const { return alpn_; }
  bool early_data_accepted() const { return early_accepted_; }
  std::optional<uint8_t> expected_ticket_count() const { return expected_ticket_count_; }
  std::vector<SessionTicket> TakeTickets();
  bool Export(std::string_view label, ByteSpan context, size_t length,
              Bytes* output) const;
  bool ExportEarly(std::string_view label, ByteSpan context, size_t length,
                   Bytes* output) const;
  bool ChannelBinding(Bytes* output) const;
  bool RequestServerAuthenticator(ByteSpan context,
      const std::map<uint16_t, Bytes>& extra_extensions, Bytes* request);
  bool CancelAuthenticator(ByteSpan request);
  bool AuthenticateClient(ByteSpan request, const ClientCredential* credential,
                          Bytes* authenticator);
  bool ValidateServerAuthenticator(ByteSpan authenticator,
      const AuthenticatorValidator& validator, bool* authenticated,
      ByteSpan exact_request = {});
  void DisableAuthenticators();
  bool RequestKeyUpdate(bool request_peer, Bytes* record);
  bool RequestHeartbeat(ByteSpan payload, Bytes* record);
  std::optional<Bytes> TakeHeartbeatResponse();
  size_t max_send_content() const { return peer_record_limit_ - 1; }
  Error error() const { return error_; }
  // Meaningful for the negotiated connection after ServerHello. Early data
  // reports its own PSK suite, not a prospective later confidential handshake.
  bool confidential() const { return suite_ != 0xc0b4 && suite_ != 0xc0b5; }
  bool early_data_confidential() const {
    return offered_psks_.empty() || (offered_psks_[0].cipher_suite != 0xc0b4 &&
                                    offered_psks_[0].cipher_suite != 0xc0b5);
  }
#if defined(PHROMIUM_HTTPPS_TEST_DIAGNOSTICS)
  // Non-secret local status. Sink failure never falls back to ordinary logging.
  bool diagnostic_failed() const { return diagnostic_failed_; }
#endif
  const std::vector<std::string>& certificates() const { return certificates_; }
  const std::vector<std::string>& validated_certificate_path() const {
    return validated_certificate_path_;
  }
  const std::vector<std::map<uint16_t, Bytes>>& certificate_extensions() const {
    return certificate_extensions_;
  }
  std::vector<Bytes> authenticated_request_templates() const {
    return established() ? learned_request_templates_ : std::vector<Bytes>{};
  }

 private:
  friend class ProtocolRegressionPeer;
  enum class State {
    kNew,
    kHello,
    kExtensions,
    kCertificate,
    kVerifyingCertificate,
    kProof,
    kFinished,
    kFlushing,
    kEstablished,
    kClosed,
    kFailed
  };
  bool Fail(Error error = Error::kProtocol, uint8_t alert = 47);
  bool AcceptFrame(ByteSpan frame);
  bool DrainHandshakeFrames();
  bool PrepareServerProof();
  bool AppendClientAuthentication();
  bool AcceptCertificateRequest(ByteSpan frame, bool post_handshake);
  bool ClientCredentialMatchesRequest() const;
  void SelectBootstrap(size_t index);
  bool AddPskExtension(Bytes* extensions) const;
  bool BindClientHello(Bytes* hello, ByteSpan prefix) const;
  bool SealHandshake(ByteSpan frame);
  bool GenerateTrafficShare(uint16_t group, Bytes* public_key);
  bool TrafficAgreement(uint16_t group, ByteSpan public_key, Bytes* shared);
  bool RetryHello(ByteSpan frame, ByteSpan cookie, uint16_t group);
  bool AcceptPostHandshake(ByteSpan frame);
  bool AppendTranscript(ByteSpan frame);
  bool Deadline();
  void Diagnostic(std::string_view label, ByteSpan secret, bool exporter = false);
  bool AuthenticatorReady() const;
  bool ClaimAuthenticatorContext(const Bytes& context);
  bool AuthenticatorKeys(bool server, Bytes* context, Bytes* finished) const;
  void EraseHandshakeSecrets();
  void EraseConnectionSecrets();
  Bytes Hash(ByteSpan input) const;
  Bytes Mac(ByteSpan key, ByteSpan input) const;
  Bytes Label(ByteSpan secret, std::string_view label, ByteSpan context,
              size_t length = static_cast<size_t>(-1)) const;
  bool DeriveSecret(ByteSpan secret, std::string_view label, ByteSpan context,
                     Bytes* output) const;
  Bytes Finished(ByteSpan secret, ByteSpan transcript) const;
  State state_ = State::kNew;
  Error error_ = Error::kNone;
  std::string hostname_;
  std::vector<std::string> anchors_;
  std::vector<std::string> certificates_;
  std::vector<std::string> validated_certificate_path_;
  std::vector<std::map<uint16_t, Bytes>> certificate_extensions_;
  int64_t dane_expires_unix_seconds_ = 0;
  int64_t its_expires_unix_milliseconds_ = 0;
  ClientOptions options_;
  uint16_t suite_ = 0x1301;
  std::string alpn_;
  Secret a_{}, b_{}, A_{}, B_{}, E_{}, S_{};
  std::unique_ptr<NativeTrafficKey> native_traffic_key_;
  std::unique_ptr<NativePasswordState> password_state_;
  Bytes password_salt_;
  Secret password_context_{};
  // A password-only policy must not become certificate fallback merely because
  // its resumption ticket uses an ordinary successor traffic suite.
  bool password_only_ = false;
#if defined(PHROMIUM_HTTPPS_TEST_DIAGNOSTICS)
  Secret diagnostic_random_{};
  bool diagnostic_failed_ = false;
#endif
  Secret authenticator_a_{};
  struct PendingAuthenticator {
    Bytes request;
    Secret private_key{};
    ~PendingAuthenticator();
  };
  std::map<Bytes, PendingAuthenticator> pending_authenticators_;
  std::set<Bytes> used_authenticator_contexts_;
  std::map<uint16_t, Bytes> authenticator_capabilities_;
  bool authenticators_disabled_ = false;
  Bytes root_, c_hs_, s_hs_, expected_proof_;
  Bytes pinning_transcript_;
  std::optional<Bytes> pinning_response_;
  Bytes ec_private_;
  Bytes kem_seed_;
  Bytes client_hello_, hello_prefix_;
  std::set<uint16_t> offered_features_, negotiated_features_;
  bool retried_ = false;
  uint16_t traffic_group_ = 0x001d;
  Bytes master_, c_app_, s_app_, exporter_, resumption_;
  Bytes early_exporter_;
  std::optional<SessionTicket> offered_ticket_;
  std::vector<ExternalPSK> offered_psks_;
  std::vector<uint32_t> offered_psk_ages_;
  size_t selected_psk_ = 0;
  bool psk_selected_ = false;
  bool combined_psk_ = false;
  Authentication authentication_ = Authentication::kCertificate;
  Secret external_psk_binding_{};
  Secret selected_client_identity_{};
  Secret bootstrap_policy_{};
  std::map<Bytes, size_t> bootstrap_offers_;
  uint16_t early_suite_ = 0x1301;
  std::optional<ClientCredential> client_credential_;
  Secret client_verifier_share_{};
  Secret authenticated_client_identity_{};
  bool client_auth_requested_ = false;
  Bytes client_auth_context_;
  std::vector<uint16_t> client_signature_algorithms_;
  std::vector<uint16_t> client_compression_algorithms_;
  std::vector<uint16_t> client_grant_algorithms_;
  bool client_delegation_offered_ = false;
  Bytes server_delegation_;
  std::vector<Bytes> learned_request_templates_;
  bool cached_certificate_selected_ = false;
  bool cached_request_selected_ = false;
  std::vector<Bytes> client_authorities_;
  std::vector<std::pair<Bytes, Bytes>> client_oid_filters_;
  Bytes initial_transcript_;
  std::set<Bytes> client_auth_contexts_;
  std::vector<SessionTicket> tickets_;
  bool resumed_ = false;
  bool early_offered_ = false;
  bool early_accepted_ = false;
  bool resume_verification_ = false;
  bool update_response_pending_ = false;
  bool update_requested_pending_ = false;
  uint64_t sending_epoch_ = 0;
  bool post_handshake_auth_offered_ = false;
  uint32_t early_bytes_ = 0;
  std::unique_ptr<RecordCipher> early_sender_;
  std::unique_ptr<RecordCipher> sender_, receiver_;
  Bytes transcript_, reassembly_, output_;
  Bytes fatal_alert_;
  uint32_t handshake_records_ = 0;
  int64_t deadline_milliseconds_ = 0;
  bool close_sent_ = false;
  std::optional<uint8_t> expected_ticket_count_;
  uint16_t peer_record_limit_ = 16385;
  uint16_t local_record_limit_ = 0;
  uint16_t fragment_limit_ = 16384;
  std::optional<uint8_t> peer_heartbeat_mode_;
  std::optional<Bytes> heartbeat_request_, heartbeat_response_;
  bool use_external_verifier_ = false;
  uint8_t server_certificate_type_ = 0;
  uint8_t client_certificate_type_ = 0;
};

}  // namespace net::httpps

#undef HTTPPS_EXPORT
#endif  // NET_HTTPPS_DRAFT01_H_
