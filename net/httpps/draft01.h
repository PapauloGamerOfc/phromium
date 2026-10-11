// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTPPS_DRAFT01_H_
#define NET_HTTPPS_DRAFT01_H_

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "net/httpps/portable.h"

#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_EXPORT
#else
#include "net/base/net_export.h"
#define HTTPPS_EXPORT NET_EXPORT_PRIVATE
#endif

namespace net::httpps {

using Bytes = std::vector<uint8_t>;
using Secret = std::array<uint8_t, 32>;
inline constexpr std::string_view kPreface = "TLS20-EXPERIMENT\r\n";
inline constexpr size_t kMaxRecordContent = 16384;
inline constexpr size_t kMaxRecord = 16645;

// A credential, not a public cache entry. The owner MUST partition tickets by
// origin/port, route, privacy context and trust configuration. Do not serialize
// them or send early data without the application's explicit replay policy.
struct HTTPPS_EXPORT SessionTicket {
  Bytes identity;
  Secret psk{};
  uint32_t lifetime = 0;
  uint32_t age_add = 0;
  uint32_t max_early_data = 0;
  int64_t received_milliseconds = 0;
  std::string hostname;
  std::vector<std::string> certificates;
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
  ~ClientCredential();
};

// The additional private-anchor path deliberately accepts only the ordered,
// offline lab PKI profile documented by tls20-server. Browser clients can also
// delegate trust to the HTTPS verifier using Client's pending-decision API.
// This helper performs no network fetching, TOFU or certificate exceptions.
HTTPPS_EXPORT bool VerifyLabChain(const std::vector<std::string>& chain,
                                  const std::vector<std::string>& anchors,
                                  std::string_view hostname,
                                  Secret* server_public_key);
HTTPPS_EXPORT bool ValidServerName(std::string_view name);
// Extracts the exact X25519 SPKI, not a trust decision. The caller must
// authenticate the certificate chain and its server identity separately.
HTTPPS_EXPORT bool ExtractServerPublicKey(std::string_view leaf_der,
                                          Secret* server_public_key);
HTTPPS_EXPORT Secret Hash(ByteSpan input);
HTTPPS_EXPORT Secret Mac(ByteSpan key, ByteSpan input);
HTTPPS_EXPORT Bytes Label(ByteSpan secret,
                          std::string_view label,
                          ByteSpan context,
                          size_t length);

// One direction, one key epoch. Any authentication/format/quota failure latches
// permanently. Cipher states cannot be copied, reset or reused across epochs.
class HTTPPS_EXPORT RecordCipher {
 public:
  explicit RecordCipher(ByteSpan secret);
  ~RecordCipher();
  RecordCipher(const RecordCipher&) = delete;
  RecordCipher& operator=(const RecordCipher&) = delete;
  bool Seal(ByteSpan content, uint8_t type, Bytes* record, size_t padding = 0);
  bool Open(ByteSpan record, uint8_t* type, Bytes* content);
  bool needs_update() const { return sequence_ >= 23725542; }

 private:
  bool Account(size_t content_length);
  std::array<uint8_t, 16> key_{};
  std::array<uint8_t, 12> iv_{};
  uint64_t sequence_ = 0;
  uint64_t content_bytes_ = 0;
  bool failed_ = false;
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
         bool use_external_verifier = false);
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
  bool OutputFlushed();
  bool certificate_verification_pending() const;
  // Resume only after the external verifier has authenticated the unchanged
  // certificates() for this hostname. No proof/Finished or application traffic
  // is accepted while the decision is pending. A negative decision is fatal.
  bool CompleteCertificateVerification(bool trusted);
  bool established() const;
  bool closed() const;
  bool resumed() const { return resumed_; }
  uint16_t traffic_group() const { return traffic_group_; }
  bool early_data_accepted() const { return early_accepted_; }
  std::vector<SessionTicket> TakeTickets();
  bool Export(std::string_view label, ByteSpan context, size_t length,
              Bytes* output) const;
  bool RequestKeyUpdate(bool request_peer, Bytes* record);
  Error error() const { return error_; }
  const std::vector<std::string>& certificates() const { return certificates_; }

 private:
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
  bool Fail(Error error = Error::kProtocol);
  bool AcceptFrame(ByteSpan frame);
  bool DrainHandshakeFrames();
  bool PrepareServerProof();
  bool AppendClientAuthentication();
  bool RetryHello(ByteSpan frame, ByteSpan cookie, uint16_t group);
  bool AcceptPostHandshake(ByteSpan frame);
  bool AppendTranscript(ByteSpan frame);
  bool Deadline();
  void EraseHandshakeSecrets();
  State state_ = State::kNew;
  Error error_ = Error::kNone;
  std::string hostname_;
  std::vector<std::string> anchors_;
  std::vector<std::string> certificates_;
  Secret a_{}, b_{}, A_{}, B_{}, E_{}, S_{};
  Secret root_{}, c_hs_{}, s_hs_{}, expected_proof_{};
  Secret p256_private_{};
  Bytes client_hello_;
  bool retried_ = false;
  uint16_t traffic_group_ = 0x001d;
  Secret master_{}, c_app_{}, s_app_{}, exporter_{}, resumption_{};
  std::optional<SessionTicket> offered_ticket_;
  std::optional<ClientCredential> client_credential_;
  Secret client_verifier_share_{};
  Secret authenticated_client_identity_{};
  bool client_auth_requested_ = false;
  std::vector<SessionTicket> tickets_;
  bool resumed_ = false;
  bool early_offered_ = false;
  bool early_accepted_ = false;
  bool resume_verification_ = false;
  bool update_response_pending_ = false;
  uint32_t early_bytes_ = 0;
  std::unique_ptr<RecordCipher> early_sender_;
  std::unique_ptr<RecordCipher> sender_, receiver_;
  Bytes transcript_, reassembly_, output_;
  uint32_t handshake_records_ = 0;
  int64_t deadline_milliseconds_ = 0;
  bool close_sent_ = false;
  bool use_external_verifier_ = false;
};

}  // namespace net::httpps

#undef HTTPPS_EXPORT
#endif  // NET_HTTPPS_DRAFT01_H_
