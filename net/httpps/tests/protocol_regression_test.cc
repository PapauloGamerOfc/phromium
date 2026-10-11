// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Deterministic state/record tests for boundaries that successful connections
// do not exercise. Secrets below are public test-only traffic-key fixtures.
#include "net/httpps/draft01.h"

#include <cstdlib>
#include <iostream>
#include <limits>

#include "third_party/boringssl/src/include/openssl/aead.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"

namespace net::httpps {
class ProtocolRegressionPeer {
 public:
  static Bytes SendingSecret() { return Bytes(32, 0x31); }
  static Bytes ReceivingSecret() { return Bytes(32, 0x73); }
  static void Prepare(Client& client, bool extensions = false) {
    client.state_ = extensions ? Client::State::kExtensions
                               : Client::State::kEstablished;
    client.deadline_milliseconds_ = std::numeric_limits<int64_t>::max();
    client.c_app_ = SendingSecret();
    client.s_app_ = ReceivingSecret();
    client.exporter_ = Bytes(32, 0x45);
    client.sender_ = std::make_unique<RecordCipher>(client.c_app_);
    client.receiver_ = std::make_unique<RecordCipher>(client.s_app_);
    client.alpn_ = "http/1.1";
    client.initial_transcript_ = Bytes{1, 0, 0, 0};
    client.output_.clear();
  }
  static void SendingEpoch(Client& client, uint64_t epoch) {
    client.sending_epoch_ = epoch;
  }
  static void AuthenticationMode(Client& client, Authentication mode,
                                 bool resumed = false) {
    client.authentication_ = mode;
    client.resumed_ = resumed;
    client.client_certificate_type_ = 2;
  }
  static bool OfferedPha(const Client& client) {
    return client.post_handshake_auth_offered_;
  }
  static void HeartbeatLimits(Client& client, uint16_t local, uint16_t peer,
                              uint16_t fragment = 16384) {
    client.local_record_limit_ = local;
    client.peer_record_limit_ = peer;
    client.fragment_limit_ = fragment;
    client.peer_heartbeat_mode_ = 1;
    client.sender_->SetLimit(peer);
    client.sender_->SetContentLimit(fragment);
    client.receiver_->SetLimit(local);
    client.receiver_->SetContentLimit(fragment);
  }
  static void Sequence(RecordCipher& cipher, uint64_t sequence) {
    cipher.sequence_ = sequence;
  }
};
}  // namespace net::httpps

namespace {
using namespace net::httpps;

void Check(bool value, const char* description) {
  if (!value) {
    std::cerr << "Protocol regression failure: " << description << '\n';
    std::exit(1);
  }
}

void Append(Bytes* out, ByteSpan value) {
  out->insert(out->end(), value.begin(), value.end());
}

void U16(Bytes* out, size_t value) {
  out->push_back(static_cast<uint8_t>(value >> 8));
  out->push_back(static_cast<uint8_t>(value));
}

Bytes Frame(uint8_t type, ByteSpan body) {
  Bytes result{type, static_cast<uint8_t>(body.size() >> 16),
               static_cast<uint8_t>(body.size() >> 8),
               static_cast<uint8_t>(body.size())};
  Append(&result, body);
  return result;
}

void Extension(Bytes* out, uint16_t type, ByteSpan value) {
  U16(out, type);
  U16(out, value.size());
  Append(out, value);
}

Bytes Vector16(ByteSpan content) {
  Bytes result;
  U16(&result, content.size());
  Append(&result, content);
  return result;
}

// Encrypt independently of RecordCipher::Seal, which intentionally refuses
// invalid inner types and empty handshake payloads before creating ciphertext.
Bytes Protect(ByteSpan plaintext, uint64_t sequence = 0) {
  const auto secret = ProtocolRegressionPeer::ReceivingSecret();
  const auto key = SuiteLabel(0x1301, secret, "key", {}, 16);
  auto nonce = SuiteLabel(0x1301, secret, "iv", {}, 12);
  for (size_t i = 0; i < 8; ++i)
    nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>(sequence >> (8 * i));
  Bytes record{23, 3, 3};
  U16(&record, plaintext.size() + 16);
  record.resize(5 + plaintext.size() + 16);
  bssl::ScopedEVP_AEAD_CTX context;
  size_t written = 0;
  Check(EVP_AEAD_CTX_init(context.get(), EVP_aead_aes_128_gcm(), key.data(),
                          key.size(), 16, nullptr) &&
            EVP_AEAD_CTX_seal(context.get(), record.data() + 5, &written,
                              record.size() - 5, nonce.data(), nonce.size(),
                              plaintext.data(), plaintext.size(), record.data(),
                              5) && written == record.size() - 5,
        "independent test record encryption");
  return record;
}

void CheckAlert(Client& client, uint8_t expected, bool encrypted = true) {
  const auto alert = client.TakeFatalAlert();
  if (!encrypted) {
    Check(alert == Bytes({21, 3, 3, 0, 2, 2, expected}),
          "exact plaintext fatal alert");
    return;
  }
  RecordCipher peer(ProtocolRegressionPeer::SendingSecret());
  Bytes content;
  uint8_t type = 0;
  Check(peer.Open(alert, &type, &content) && type == 21 &&
            content == Bytes({2, expected}),
        "exact authenticated fatal alert");
}

void RecordAlerts() {
  const std::pair<Bytes, uint8_t> invalid[] = {
      {{}, 10}, {Bytes{1, 99}, 10}, {Bytes(4, 0), 10},
      {Bytes{22}, 10}, {Bytes{21}, 10}, {Bytes{1, 21}, 50},
      {Bytes(16386, 23), 22}, {Bytes(16625, 23), 22}};
  for (const auto& [plaintext, alert] : invalid) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    Bytes application;
    Check(!client.Receive(Protect(plaintext), &application) && application.empty(),
          "authenticated malformed record is rejected without application data");
    CheckAlert(client, alert);
  }
  Client client("example.test", {}, true);
  ProtocolRegressionPeer::Prepare(client);
  auto corrupted = Protect(Bytes{1, 23});
  corrupted.back() ^= 1;
  Bytes application;
  Check(!client.Receive(corrupted, &application), "bad authentication tag rejected");
  CheckAlert(client, 20);

  RecordCipher receiver(ProtocolRegressionPeer::ReceivingSecret());
  constexpr uint64_t kConservativeSendLimit = 23726566;
  ProtocolRegressionPeer::Sequence(receiver, kConservativeSendLimit);
  uint8_t type = 0;
  Check(receiver.Open(Protect(Bytes{7, 23}, kConservativeSendLimit), &type,
                      &application) && type == 23 && application == Bytes{7},
        "receiving does not impose the conservative sending-record limit");
}

void RecordFramingAlerts() {
  const std::pair<Bytes, uint8_t> protected_cases[] = {
      {{}, 50}, {{23, 3, 3, 0}, 50},
      {{22, 3, 3, 0, 0}, 10}, {{23, 3, 1, 0, 0}, 47},
      {{23, 3, 3, 0, 1}, 50}, {{23, 3, 3, 0, 0, 1}, 50},
      // A header alone must suffice to reject oversized ciphertext safely.
      {{23, 3, 3, 0x41, 1}, 22},
      {{23, 3, 3, 0, 0}, 20}, {{23, 3, 3, 0, 1, 0}, 20}};
  for (const auto& [record, alert] : protected_cases) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    Bytes application;
    Check(!client.Receive(record, &application) && application.empty(),
          "protected record framing is rejected without unsafe fragment access");
    CheckAlert(client, alert);
  }
  for (uint8_t outer_type : {0, 20, 21, 22, 24, 255}) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    auto record = Protect(Bytes{1, 23});
    record[0] = outer_type;
    Bytes application;
    Check(!client.Receive(record, &application), "unexpected outer content type rejected");
    CheckAlert(client, 10);
  }
  const std::pair<Bytes, uint8_t> plaintext_cases[] = {
      {{}, 50}, {{22, 3, 3, 0}, 50},
      {{22, 0, 255, 0, 0}, 10}, {{21, 0, 255, 0, 0}, 10},
      {{21, 0, 255, 0, 1, 90}, 50}, {{21, 0, 255, 0, 3, 1, 90, 0}, 50},
      {{21, 3, 3, 0, 2}, 50}, {{22, 3, 3, 0, 1}, 50},
      {{22, 3, 3, 0, 0, 1}, 50}, {{22, 3, 3, 0x40, 1}, 22},
      {{21, 3, 3, 0x40, 1}, 22},
      {{20, 3, 3, 0, 0}, 10}, {{23, 3, 3, 0, 0}, 10}, {{255, 3, 3, 0, 0}, 10}};
  for (const auto& [record, alert] : plaintext_cases) {
    Client client("example.test", {}, true);
    Check(client.Start(), "plaintext framing-test ClientHello");
    client.TakeOutput();
    Bytes application;
    Check(!client.Receive(record, &application) && application.empty(),
          "plaintext record framing is rejected without unsafe fragment access");
    CheckAlert(client, alert, false);
  }
}

Bytes ServerHello(ByteSpan extensions) {
  Bytes body(38, 0);
  body[0] = body[1] = 3;
  // Deliberately unsupported suite: version diagnostics must take precedence.
  body[35] = body[36] = 0xee;
  Append(&body, Vector16(extensions));
  return Frame(2, body);
}

Bytes Plaintext(ByteSpan frame, uint8_t major = 3, uint8_t minor = 3) {
  Bytes result{22, major, minor};
  U16(&result, frame.size());
  Append(&result, frame);
  return result;
}

void VersionAlerts() {
  Bytes duplicate, malformed, wrong;
  Extension(&duplicate, 43, Bytes{4, 0});
  Extension(&duplicate, 43, Bytes{4, 0});
  Extension(&malformed, 43, Bytes{4});
  Extension(&wrong, 43, Bytes{3, 4});
  const std::pair<Bytes, uint8_t> cases[] = {
      {{}, 109}, {malformed, 50}, {duplicate, 47}, {wrong, 47}};
  for (const auto& [extensions, alert] : cases) {
    for (const auto legacy : {std::pair<uint8_t, uint8_t>{3, 3}, {0, 255}}) {
      Client client("example.test", {}, true);
      Check(client.Start(), "version-test ClientHello");
      client.TakeOutput();
      Bytes application;
      Check(!client.Receive(Plaintext(ServerHello(extensions), legacy.first,
                                    legacy.second), &application),
            "invalid ServerHello rejected independently of record legacy version");
      CheckAlert(client, alert, false);
    }
  }
  Client client("example.test", {}, true);
  Check(client.Start(), "plaintext compatibility ClientHello");
  client.TakeOutput();
  Bytes application;
  Check(client.Receive(Bytes{20, 0, 255, 0, 1, 1}, &application),
        "compatibility CCS ignores record legacy version");
  Check(client.Receive(Bytes{21, 0, 255, 0, 2, 1, 90}, &application),
        "plaintext user_canceled ignores record legacy version");
}

void KeyUpdates() {
  for (uint8_t response : {0, 1}) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    Bytes record, application;
    Check(client.RequestKeyUpdate(true, &record), "first requested key update");
    Check(!client.RequestKeyUpdate(true, &record), "second requested update waits");
    Check(client.RequestKeyUpdate(false, &record), "nonrequested update remains legal");
    Check(!client.RequestKeyUpdate(true, &record), "nonrequested send does not clear request latch");
    auto update = Frame(24, Bytes{response});
    update.push_back(22);
    Check(client.Receive(Protect(update), &application), "peer key update accepted");
    Check(client.RequestKeyUpdate(true, &record), "either peer update clears request latch");
  }
  constexpr uint64_t kLastEpoch = (uint64_t{1} << 48) - 1;
  Client client("example.test", {}, true);
  ProtocolRegressionPeer::Prepare(client);
  ProtocolRegressionPeer::SendingEpoch(client, kLastEpoch - 1);
  Bytes record, application;
  Check(client.RequestKeyUpdate(false, &record), "last permitted sending epoch");
  auto update = Frame(24, Bytes{1});
  update.push_back(22);
  Check(client.Receive(Protect(update), &application),
        "receiving updates remains legal at local sending epoch maximum");
  Check(client.Send(Bytes{7}, &record),
        "final sending epoch ignores peer update request while key quota permits");
  Check(!client.RequestKeyUpdate(false, &record), "sending epoch cannot wrap");
}

Bytes CertificateRequest() {
  Secret private_key{}, public_key{};
  private_key.fill(0x29);
  X25519_public_from_private(public_key.data(), private_key.data());
  Bytes extensions;
  Extension(&extensions, 0xff03, public_key);
  Bytes body{1, 7};
  Append(&body, Vector16(extensions));
  return Frame(13, body);
}

void PostHandshakeAuthentication() {
  for (const auto mode : {Authentication::kCertificate,
                          Authentication::kExternalPsk,
                          Authentication::kPassword,
                          Authentication::kCertificateAndPsk}) {
    for (bool offer_h2 : {false, true}) {
      ClientOptions options;
      options.post_handshake_auth = true;
      if (offer_h2)
        options.alpn_protocols = {"h2", "http/1.1"};
      Client client("example.test", {}, true, options);
      Check(client.Start(), "PHA-test ClientHello");
      Check(ProtocolRegressionPeer::OfferedPha(client) == !offer_h2,
            "actual PHA offer follows offered ALPN list");
      ProtocolRegressionPeer::Prepare(client);
      ProtocolRegressionPeer::AuthenticationMode(client, mode);
      auto request = CertificateRequest();
      request.push_back(22);
      Bytes application;
      const bool allowed = !offer_h2 &&
          mode != Authentication::kExternalPsk && mode != Authentication::kPassword;
      Check(client.Receive(Protect(request), &application) == allowed,
            "PHA requires actual offer and eligible selected authentication");
      if (!allowed)
        CheckAlert(client, 10);
      else
        Check(!client.TakeOutput().empty(), "eligible PHA produces a response");
    }
  }
}

void RetrospectiveLimits() {
  for (bool mfl : {false, true}) {
    const size_t limit = mfl ? 513 : 64;
    for (bool overflow : {false, true}) {
      for (bool fragmented : {false, true}) {
        ClientOptions options;
        options.no_alpn_http11 = true;
        if (mfl)
          options.max_fragment_length = 1;
        else
          options.record_size_limit = 64;
        Client client("example.test", {}, true, options);
        ProtocolRegressionPeer::Prepare(client, true);
        Bytes extensions;
        Extension(&extensions, mfl ? 1 : 28, mfl ? Bytes{1} : Bytes{0, 64});
        const auto frame = Frame(8, Vector16(extensions));
        Bytes first(frame.begin(), fragmented ? frame.begin() + 4 : frame.end());
        first.push_back(22);
        first.resize(limit + (overflow ? 1 : 0), 0);
        Bytes application;
        bool accepted = client.Receive(Protect(first), &application);
        if (fragmented) {
          Check(accepted, "partial EE retained before limits can be negotiated");
          Bytes rest(frame.begin() + 4, frame.end());
          rest.push_back(22);
          accepted = client.Receive(Protect(rest, 1), &application);
        }
        Check(accepted == !overflow,
              "new EE limits include earlier protected plaintext and padding");
        if (overflow)
          CheckAlert(client, 22);
      }
    }
  }
}

void HeartbeatLimits() {
  const std::pair<uint16_t, uint16_t> limits[] = {{64, 16385}, {16385, 64}};
  for (const auto [local, peer] : limits) {
    ClientOptions options;
    options.heartbeat_mode = 1;
    Client client("example.test", {}, true, options);
    ProtocolRegressionPeer::Prepare(client);
    ProtocolRegressionPeer::HeartbeatLimits(client, local, peer);
    Bytes record;
    Check(!client.RequestHeartbeat(Bytes(45, 1), &record),
          "heartbeat request must leave room for response in both directions");
    Check(client.RequestHeartbeat(Bytes(44, 1), &record),
          "heartbeat exact shared bound is legal");
    Bytes response{2, 0, 44};
    response.resize(47, 1);
    response.resize(63, 0);
    response.push_back(24);
    Bytes application;
    Check(client.Receive(Protect(response), &application), "bounded heartbeat response opens");
    Check(client.TakeHeartbeatResponse() == std::optional<Bytes>(Bytes(44, 1)),
          "bounded heartbeat response matches request");
  }
}
}  // namespace

void RunProtocolRegressionTests() {
  RecordAlerts();
  RecordFramingAlerts();
  VersionAlerts();
  KeyUpdates();
  PostHandshakeAuthentication();
  RetrospectiveLimits();
  HeartbeatLimits();
  std::cout << "Protocol alert, key-update, PHA, record-limit and heartbeat regressions passed\n";
}
