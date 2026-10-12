// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Deterministic state/record tests for boundaries that successful connections
// do not exercise. Secrets below are public test-only traffic-key fixtures.
#include "net/httpps/draft01.h"
#include "net/httpps/native_provider.h"

#include <algorithm>
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
  static bool WritingSecretsErased(const Client& client) {
    return !client.sender_ && client.c_app_.empty() && !client.client_credential_ &&
        !client.update_response_pending_ && !client.update_requested_pending_;
  }
  static bool UpdateResponsePending(const Client& client) {
    return client.update_response_pending_;
  }
  static void RetainTicket(Client& client) {
    SessionTicket ticket;
    ticket.identity = Bytes{0x54};
    ticket.psk = Bytes(32, 0x70);
    client.tickets_.push_back(std::move(ticket));
  }
  static void PrepareTicket(Client& client) {
    Prepare(client);
    client.resumption_ = Bytes(32, 0x52);
  }
  static bool CertificateFailure(Client& client, bool explicit_alert) {
    return explicit_alert ? client.Fail(Client::Error::kCertificate, 47)
                          : client.Fail(Client::Error::kCertificate);
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
  static void AgeTicket(Client& client, int64_t milliseconds) {
    client.offered_ticket_->received_milliseconds -= milliseconds;
  }
  static uint32_t TicketAge(const Client& client) {
    return static_cast<uint32_t>(MonotonicMilliseconds() -
        client.offered_ticket_->received_milliseconds) + client.offered_ticket_->age_add;
  }
  static bool HasHandshakeSecrets(const Client& client) {
    for (const auto* secret : {&client.root_, &client.c_hs_, &client.s_hs_})
      if (secret->size() != 32 ||
          std::all_of(secret->begin(), secret->end(), [](uint8_t value) { return value == 0; }))
        return false;
    return true;
  }
  static Bytes HandshakeSendingSecret(const Client& client) { return client.c_hs_; }
  static bool HasNativeTrafficKey(const Client& client) {
    return client.native_traffic_key_ != nullptr;
  }
  static void AwaitVerification(Client& client) {
    client.state_ = Client::State::kVerifyingCertificate;
  }
  static void AwaitServerFinished(Client& client) {
    client.state_ = Client::State::kFinished;
  }
  static void InitialCertificateRequested(Client& client) {
    client.state_ = Client::State::kCertificate;
    client.client_auth_requested_ = true;
  }
  static void SelectFirstExternalPsk(Client& client) {
    client.psk_selected_ = true;
    client.selected_psk_ = 0;
    client.authentication_ = Authentication::kExternalPsk;
  }
  static void AwaitInitialCertificateRequest(Client& client) {
    client.state_ = Client::State::kCertificate;
  }
  static void SelectCachedRequest(Client& client) {
    client.cached_request_selected_ = true;
  }
  static void PopulateSecrets(Client& client) {
    for (auto* secret : {&client.a_, &client.b_, &client.authenticator_a_,
                         &client.client_verifier_share_, &client.password_context_,
                         &client.external_psk_binding_})
      secret->fill(0x52);
    for (auto* secret : {&client.ec_private_, &client.kem_seed_, &client.root_,
                         &client.c_hs_, &client.s_hs_, &client.expected_proof_,
                         &client.master_, &client.resumption_, &client.early_exporter_})
      *secret = Bytes(32, 0x52);
    client.early_sender_ = std::make_unique<RecordCipher>(client.early_exporter_);
    client.offered_ticket_.emplace();
    client.offered_ticket_->psk = Bytes(32, 0x54);
    client.tickets_.push_back(*client.offered_ticket_);
    ExternalPSK psk;
    psk.secret = Bytes(32, 0x50);
    client.offered_psks_.push_back(psk);
    client.options_.external_psks.push_back(psk);
    client.client_credential_.emplace();
    client.client_credential_->private_key.fill(0x43);
    client.options_.bootstrap.emplace();
    client.options_.bootstrap->credential = client.client_credential_;
    client.options_.bootstraps.push_back(*client.options_.bootstrap);
    client.pending_authenticators_[Bytes{1}].private_key.fill(0x41);
  }
  static bool SecretsErased(const Client& client) {
    const auto zero = [](const auto& bytes) {
      return std::all_of(bytes.begin(), bytes.end(), [](uint8_t value) { return value == 0; });
    };
    for (const auto* secret : {&client.a_, &client.b_, &client.authenticator_a_,
                               &client.client_verifier_share_, &client.password_context_,
                               &client.external_psk_binding_})
      if (!zero(*secret)) return false;
    for (const auto* secret : {&client.ec_private_, &client.kem_seed_, &client.root_,
                               &client.c_hs_, &client.s_hs_, &client.expected_proof_,
                               &client.master_, &client.c_app_, &client.s_app_,
                               &client.exporter_, &client.resumption_, &client.early_exporter_})
      if (!zero(*secret)) return false;
    return !client.sender_ && !client.receiver_ && !client.early_sender_ &&
        !client.client_credential_ && !client.offered_ticket_ && client.tickets_.empty() &&
        client.offered_psks_.empty() && client.options_.external_psks.empty() &&
        !client.options_.password && client.pending_authenticators_.empty() &&
        (!client.options_.bootstrap || !client.options_.bootstrap->credential) &&
        std::all_of(client.options_.bootstraps.begin(), client.options_.bootstraps.end(),
            [](const auto& binding) { return !binding.credential; });
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

void UnexpectedMessageAlerts() {
  // Authenticated records with valid framing can still be illegal in the
  // current protocol state. Keep these distinct from malformed encodings.
  const Bytes heartbeat{1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 24};
  for (bool initial : {false, true}) {
    for (const auto& plaintext : {Bytes{'O', 'K', 23}, heartbeat}) {
      Client client("example.test", {}, true);
      ProtocolRegressionPeer::Prepare(client, initial);
      Bytes application;
      const bool allowed = !initial && plaintext.back() == 23;
      Check(client.Receive(Protect(plaintext), &application) == allowed,
            "application records require completed handshake; heartbeat requires negotiation");
      if (allowed) {
        Check(application == Bytes({'O', 'K'}) && client.TakeFatalAlert().empty(),
              "established application record remains accepted without alert");
      } else {
        Check(application.empty(), "unexpected record releases no application data");
        CheckAlert(client, 10);
      }
    }
  }
  for (uint8_t following_type : {uint8_t{4}, uint8_t{24}}) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    auto plaintext = Frame(24, Bytes{0});
    Append(&plaintext, Frame(following_type, Bytes{0}));
    plaintext.push_back(22);
    Bytes application;
    Check(!client.Receive(Protect(plaintext), &application) && application.empty(),
          "KeyUpdate must end the old record epoch before any following message");
    CheckAlert(client, 10);
  }
  for (bool initial_hello : {false, true}) {
    Client client("example.test", {}, true);
    if (initial_hello) {
      Check(client.Start(), "boundary-test ClientHello");
      client.TakeOutput();
    } else {
      ProtocolRegressionPeer::Prepare(client);
      ProtocolRegressionPeer::AwaitServerFinished(client);
    }
    auto frames = Frame(initial_hello ? 2 : 20, Bytes(40));
    Append(&frames, Frame(4, Bytes{0}));
    Bytes record = initial_hello ? Plaintext(frames) : Bytes{};
    if (!initial_hello) {
      frames.push_back(22);
      record = Protect(frames);
    }
    Bytes application;
    Check(!client.Receive(record, &application) && application.empty(),
          "ServerHello and Finished must align with the record boundary");
    CheckAlert(client, 10, !initial_hello);
  }
  for (uint8_t request_type : {uint8_t{13}, uint8_t{252}}) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    ProtocolRegressionPeer::InitialCertificateRequested(client);
    auto plaintext = Frame(request_type, Bytes{0});
    plaintext.push_back(22);
    Bytes application;
    Check(!client.Receive(Protect(plaintext), &application) && application.empty(),
          "second initial CertificateRequest is an unexpected message");
    CheckAlert(client, 10);
  }
  const std::pair<Bytes, uint8_t> key_updates[] = {
      {{0}, 0}, {{1}, 0}, {{2}, 47}, {{}, 50}, {{0, 0}, 50}};
  for (const auto& [body, alert] : key_updates) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    auto plaintext = Frame(24, body);
    plaintext.push_back(22);
    Bytes application;
    Check(client.Receive(Protect(plaintext), &application) == (alert == 0) &&
              application.empty(), "KeyUpdate value and framing have distinct alerts");
    if (alert)
      CheckAlert(client, alert);
    else
      Check(client.TakeFatalAlert().empty(), "valid aligned KeyUpdate emits no alert");
  }
}

Bytes CookieRetry(size_t cookie_size = 1,
                  std::optional<uint16_t> group = std::nullopt) {
  Bytes body{3, 3};
  Append(&body, Bytes{0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,
      0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
      0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,
      0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c});
  Append(&body, Bytes{0, 0x13, 1, 0});
  Bytes extensions;
  Extension(&extensions, 43, Bytes{4, 0});
  if (cookie_size)
    Extension(&extensions, 44, Vector16(Bytes(cookie_size, 7)));
  if (group) {
    Bytes selected;
    U16(&selected, *group);
    Extension(&extensions, 51, selected);
  }
  Check(extensions.size() <= 65535, "test HRR extensions fit their uint16 vector");
  Append(&body, Vector16(extensions));
  return Frame(2, body);
}

Bytes JoinPlaintextRecords(ByteSpan records) {
  Bytes frame;
  while (!records.empty()) {
    Check(records.size() >= 5 && records[0] == 22 && records[1] == 3 &&
              records[2] == 3, "serialized plaintext handshake record header");
    const size_t length = (size_t{records[3]} << 8) | records[4];
    Check(length && length <= 16384 && length <= records.size() - 5,
          "serialized plaintext handshake record length");
    Append(&frame, records.subspan(5u, length));
    records = records.subspan(5 + length);
  }
  return frame;
}

bool ReceivePlaintextHandshake(Client& client, ByteSpan frame) {
  while (!frame.empty()) {
    const size_t length = std::min<size_t>(frame.size(), 16384);
    Bytes application;
    const bool accepted = client.Receive(Plaintext(frame.first(length)), &application);
    Check(application.empty(), "HRR never releases application data");
    if (!accepted)
      return false;
    frame = frame.subspan(length);
  }
  return true;
}

std::map<uint16_t, Bytes> HelloExtensions(ByteSpan hello) {
  Check(hello.size() >= 4 && hello[0] == 1 &&
            ((size_t{hello[1]} << 16) | (size_t{hello[2]} << 8) | hello[3]) ==
                hello.size() - 4, "serialized ClientHello handshake length");
  const auto read16 = [&](size_t offset) {
    Check(offset + 2 <= hello.size(), "ClientHello uint16 framing");
    return (size_t{hello[offset]} << 8) | hello[offset + 1];
  };
  size_t cursor = 4 + 34;
  Check(cursor < hello.size(), "ClientHello fixed header");
  cursor += 1 + hello[cursor];
  cursor += 2 + read16(cursor);
  Check(cursor < hello.size(), "ClientHello compression framing");
  cursor += 1 + hello[cursor];
  Check(cursor + 2 + read16(cursor) == hello.size(), "ClientHello extension vector");
  cursor += 2;
  std::map<uint16_t, Bytes> extensions;
  while (cursor + 4 <= hello.size()) {
    const auto type = read16(cursor), length = read16(cursor + 2);
    cursor += 4;
    Check(cursor + length <= hello.size(), "ClientHello extension length");
    if (type == 41) {
      Check(cursor + length == hello.size(), "PSK is last after retry cookie");
    }
    Check(extensions.emplace(static_cast<uint16_t>(type),
              Bytes(hello.begin() + cursor, hello.begin() + cursor + length)).second,
          "ClientHello has no duplicate extensions");
    cursor += length;
  }
  Check(cursor == hello.size(), "ClientHello has no trailing extension bytes");
  return extensions;
}

void HelloResponseOffers() {
  for (bool retry : {false, true}) {
    for (bool grease : {false, true}) {
      for (int fault = 0; fault < 6; ++fault) {
        ClientOptions options;
        options.grease = grease;
        Client client("example.test", {}, true, options);
        Check(client.Start(), "Hello response fixture starts");
        auto records = client.TakeOutput();
        auto offers = HelloExtensions(JoinPlaintextRecords(ByteSpan(records).subspan(kPreface.size())));
        uint16_t unknown = 0x1234;
        Check(!offers.count(unknown) && !offers.count(41), "negative response types were not offered");
        Bytes response = CookieRetry();
        Bytes body(response.begin() + 4, response.begin() + 42);
        Bytes extensions;
        Extension(&extensions, 43, Bytes{4, 0});
        if (retry) {
          Extension(&extensions, 44, Bytes{0, 1, 7});
        } else {
          std::fill(body.begin() + 2, body.begin() + 34, 0x12);
          Secret key, private_key;
          X25519_keypair(key.data(), private_key.data());
          Bytes share{0, 29};
          Append(&share, Vector16(key));
          Extension(&extensions, 51, share);
        }
        if (fault == 1) Extension(&extensions, unknown, {});
        if (fault == 2) Extension(&extensions, 15, Bytes{1});
        if (fault == 3) Extension(&extensions, 41, Bytes{0, 0});
        if (fault == 4) Append(&extensions, Bytes{0x12, 0x34, 0});
        if (fault == 5) {
          // An offered GREASE response is still not a negotiated capability.
          if (!grease) continue;
          for (const auto& [type, unused] : offers)
            if ((type & 0x0f0f) == 0x0a0a) unknown = type;
          Check(offers.count(unknown), "GREASE response uses the actual CH offer");
          Extension(&extensions, unknown, {});
        }
        Append(&body, Vector16(extensions));
        const bool accepted = ReceivePlaintextHandshake(client, Frame(2, body));
        Check(accepted == (fault == 0), "Hello responses enforce offer and context separately");
        if (fault) CheckAlert(client, fault == 1 || (fault == 3 && !retry) ? 110 : fault == 4 ? 50 : 47, false);
        else if (retry) {
          const auto second = HelloExtensions(JoinPlaintextRecords(client.TakeOutput()));
          Check(second.at(44) == Bytes({0, 1, 7}) && second.at(51) == offers.at(51),
                "unsolicited valid cookie is echoed without changing traffic share");
        }
      }
    }
  }
}

void HelloResponseSyntax() {
  struct Case { bool retry; uint16_t type; Bytes value; uint8_t alert; };
  const Case cases[] = {
      {false, 41, {}, 50}, {false, 41, {0}, 50}, {false, 41, {0, 0, 0}, 50},
      {false, 41, {0, 1}, 47}, {false, 33, {0}, 50},
      {false, 51, {}, 50}, {false, 51, {0, 29, 0}, 50},
      {false, 51, {0, 29, 0, 0}, 50}, {false, 51, {0, 29, 0, 2, 7}, 50},
      {false, 51, {0, 23, 0, 1, 7}, 47}, {false, 51, {0, 29, 0, 1, 7}, 47},
      {true, 51, {}, 50}, {true, 51, {0}, 50}, {true, 51, {0, 23, 0}, 50},
      {true, 51, {0, 0}, 47}, {true, 44, {}, 50}, {true, 44, {0}, 50},
      {true, 44, {0, 0}, 50}, {true, 44, {0, 2, 7}, 50}};
  for (const auto& test : cases) {
    ClientOptions options;
    if (test.type == 41 || test.type == 33) {
      ExternalPSK psk;
      psk.identity = Bytes{1}; psk.secret = Bytes(32, 7); psk.hostname = "example.test";
      psk.combined = test.type == 33;
      options.external_psks = {psk};
    }
    Client client("example.test", {}, true, options);
    Check(client.Start(), "Hello syntax fixture starts with actual offers");
    client.TakeOutput();
    auto retry = CookieRetry();
    Bytes body(retry.begin() + 4, retry.begin() + 42), extensions;
    Extension(&extensions, 43, Bytes{4, 0});
    if (!test.retry) {
      std::fill(body.begin() + 2, body.begin() + 34, 0x12);
      if (test.type != 51) {
        Secret key, private_key;
        X25519_keypair(key.data(), private_key.data());
        Bytes share{0, 29}; Append(&share, Vector16(key));
        Extension(&extensions, 51, share);
      }
      if (test.type == 33) Extension(&extensions, 41, Bytes{0, 0});
    } else if (test.type != 44) {
      Extension(&extensions, 44, Bytes{0, 1, 7});
    }
    Extension(&extensions, test.type, test.value);
    Append(&body, Vector16(extensions));
    Check(!ReceivePlaintextHandshake(client, Frame(2, body)), "invalid Hello structure rejected");
    CheckAlert(client, test.alert, false);
  }
}

void HelloSessionSyntax() {
  struct Case { uint8_t declared; size_t present; uint8_t alert; };
  const Case cases[] = {
      {0, 0, 0}, {1, 1, 47}, {32, 32, 47},
      {33, 33, 50}, {255, 0, 50}, {32, 0, 50}};
  for (bool retry : {false, true}) {
    for (const auto& test : cases) {
      Client client("example.test", {}, true);
      Check(client.Start(), "session-vector fixture starts with empty session ID");
      client.TakeOutput();
      const auto baseline = CookieRetry();
      Bytes body(baseline.begin() + 4, baseline.begin() + 42), extensions;
      Extension(&extensions, 43, Bytes{4, 0});
      if (retry) {
        Extension(&extensions, 44, Bytes{0, 1, 7});
      } else {
        std::fill(body.begin() + 2, body.begin() + 34, 0x12);
        Secret key, private_key;
        X25519_keypair(key.data(), private_key.data());
        Bytes share{0, 29};
        Append(&share, Vector16(key));
        Extension(&extensions, 51, share);
      }
      Append(&body, Vector16(extensions));
      body[34] = test.declared;
      body.insert(body.begin() + 35, test.present, 0x17);
      // Keep the length byte but truncate the vector even if a normal SH
      // would have enough extension bytes to be mistaken for its contents.
      if (test.declared == 32 && test.present == 0)
        body.resize(40);
      Check(ReceivePlaintextHandshake(client, Frame(2, body)) == (test.alert == 0),
            "SH and HRR distinguish session-vector framing from echo mismatch");
      if (test.alert)
        CheckAlert(client, test.alert, false);
      else
        Check(client.TakeFatalAlert().empty(), "empty session echo remains valid");
    }
  }
}

Bytes HelloPsk(ByteSpan hello) {
  const auto extensions = HelloExtensions(hello);
  Check(extensions.count(41), "ClientHello offers PSK");
  return extensions.at(41);
}

void RetryGroups() {
  const std::optional<uint16_t> groups[] = {
      std::nullopt, uint16_t{0}, uint16_t{23}, uint16_t{29}, uint16_t{0xffff}};
  for (const auto group : groups) {
    Client client("example.test", {}, true);
    Check(client.Start(), "HRR selected-group ClientHello");
    const auto initial_records = client.TakeOutput();
    const auto initial = HelloExtensions(
        JoinPlaintextRecords(ByteSpan(initial_records).subspan(kPreface.size())));
    const bool allowed = !group || *group == 23;
    Check(ReceivePlaintextHandshake(client, CookieRetry(1, group)) == allowed,
          "HRR accepts omitted or offered-new groups, not zero/reused/unknown selections");
    const auto output = client.TakeOutput();
    if (!allowed) {
      Check(output.empty(), "invalid HRR group cannot emit CH2");
      CheckAlert(client, 47, false);
      continue;
    }
    const auto second = HelloExtensions(JoinPlaintextRecords(output));
    Check(second.at(44) == Bytes({0, 1, 7}), "valid HRR cookie is echoed exactly");
    if (!group) {
      Check(second.at(51) == initial.at(51),
            "cookie-only HRR preserves the original key_share");
    } else {
      const auto& share = second.at(51);
      Check(share.size() >= 6 && share[2] == 0 && share[3] == *group &&
                share != initial.at(51), "valid group HRR replaces the traffic share");
    }
    Check(!ReceivePlaintextHandshake(client, CookieRetry(1, group)) &&
              client.TakeOutput().empty(), "second HRR cannot emit another ClientHello");
    CheckAlert(client, 10, false);
  }
  for (int changed = 0; changed < 4; ++changed) {
    Client client("example.test", {}, true);
    Check(client.Start(), "second HRR parameter fixture starts");
    client.TakeOutput();
    Check(ReceivePlaintextHandshake(client, CookieRetry()), "first cookie retry is legal");
    client.TakeOutput();
    auto second = CookieRetry(1, changed == 0 ? uint16_t{23} : uint16_t{0xffff});
    if (changed >= 2) {
      second[39] = changed == 2 ? 0x13 : 0xaa;
      second[40] = changed == 2 ? 2 : 0xaa;
    }
    Check(!ReceivePlaintextHandshake(client, second) && client.TakeOutput().empty(),
          "second HRR is unexpected even with changed group or suite");
    CheckAlert(client, 10, false);
  }
}

void RetryCookieBounds() {
  for (bool with_psk : {false, true}) {
    for (int difference : {-1, 0, 1}) {
      ClientOptions options;
      ExternalPSK psk;
      if (with_psk) {
        psk.identity = Bytes{0x45};
        psk.secret = Bytes(32, 0x65);
        psk.hostname = "example.test";
        options.external_psks.push_back(psk);
      }
      Client client("example.test", {}, true, options);
      Check(client.Start(), "large-cookie initial ClientHello");
      const auto initial_records = client.TakeOutput();
      const auto first = JoinPlaintextRecords(
          ByteSpan(initial_records).subspan(kPreface.size()));
      const auto first_extensions = HelloExtensions(first);
      size_t first_size = 0;
      for (const auto& [type, value] : first_extensions)
        first_size += 4 + value.size();
      // The cookie adds its extension header, uint16 length and cookie bytes.
      const size_t cookie_size = 65535 - first_size - 6 + difference;
      const auto retry = CookieRetry(cookie_size);
      Check(ReceivePlaintextHandshake(client, retry) == (difference <= 0),
            "CH2 obeys the uint16 extension bound after a valid fragmented HRR");
      const auto output = client.TakeOutput();
      if (difference > 0) {
        Check(output.empty(), "unencodable CH2 does not emit truncated output");
        // AddPskExtension already rejects an overflowing PSK offer.
        CheckAlert(client, with_psk ? 47 : 80, false);
        continue;
      }
      const auto second = JoinPlaintextRecords(output);
      const auto second_extensions = HelloExtensions(second);
      size_t second_size = 0;
      for (const auto& [type, value] : second_extensions)
        second_size += 4 + value.size();
      Check(second_size == 65535 + difference &&
                second_extensions.at(44) == Vector16(Bytes(cookie_size, 7)),
            "boundary-size CH2 preserves the complete cookie and extension lengths");
      if (!with_psk)
        continue;
      const auto second_psk = HelloPsk(second);
      Bytes transcript(StringBytes(kPreface).begin(), StringBytes(kPreface).end());
      Append(&transcript, Frame(254, SuiteHash(0x1301, first)));
      Append(&transcript, retry);
      Append(&transcript, ByteSpan(second).first(second.size() - 35));
      const auto early = SuiteMac(0x1301, Bytes(32), psk.secret);
      const auto binder = SuiteLabel(0x1301, early, "ext binder", SuiteHash(0x1301, {}), 32);
      const auto finished = SuiteLabel(0x1301, binder, "finished", {}, 32);
      const auto expected = SuiteMac(0x1301, finished, SuiteHash(0x1301, transcript));
      Check(second_psk.size() >= expected.size() &&
                std::equal(expected.begin(), expected.end(), second_psk.end() - expected.size()),
            "boundary-size CH2 keeps PSK last with an independently verified binder");
    }
  }
}

uint32_t PskAge(ByteSpan psk) {
  Check(psk.size() >= 8, "PSK identity framing");
  const size_t length = (size_t{psk[2]} << 8) | psk[3];
  const size_t offset = 4 + length;
  Check(offset + 4 <= psk.size(), "PSK age framing");
  return (uint32_t{psk[offset]} << 24) | (uint32_t{psk[offset + 1]} << 16) |
      (uint32_t{psk[offset + 2]} << 8) | psk[offset + 3];
}

void RetryTicketAges() {
  ClientOptions options;
  options.ordinary_httpps = false;
  options.allow_unauthenticated = true;
  SessionTicket ticket;
  ticket.identity = Bytes{0x54};
  ticket.psk = Bytes(32, 0x71);
  ticket.hostname = "example.test";
  ticket.authentication = Authentication::kUnauthenticated;
  ticket.lifetime = 3600;
  ticket.received_milliseconds = MonotonicMilliseconds() - 1000;
  ticket.age_add = std::numeric_limits<uint32_t>::max() - 5000;
  Client client("example.test", {}, false, options);
  Check(client.Start(&ticket), "resumption ClientHello before retry");
  const auto first_records = client.TakeOutput();
  const auto first = ByteSpan(first_records).subspan(kPreface.size() + 5);
  const auto first_psk = HelloPsk(first);
  // Move only the private ticket timestamp, so this test needs no clock sleep.
  ProtocolRegressionPeer::AgeTicket(client, 9000);
  const auto before = ProtocolRegressionPeer::TicketAge(client);
  const auto retry = CookieRetry();
  Bytes application;
  Check(client.Receive(Plaintext(retry), &application), "ticket cookie retry accepted");
  const auto after = ProtocolRegressionPeer::TicketAge(client);
  const auto second_records = client.TakeOutput();
  const auto second = ByteSpan(second_records).subspan(5u);
  const auto second_psk = HelloPsk(second);
  const auto age = PskAge(second_psk);
  Check(age >= before && age <= after &&
            static_cast<uint32_t>(age - PskAge(first_psk)) >= 9000,
        "CH2 refreshes ticket age with uint32 obfuscation wrap");
  Check(first_psk.size() == second_psk.size() &&
            std::equal(first_psk.begin(), first_psk.begin() + 5, second_psk.begin()),
        "retry preserves offered ticket identity and vector lengths");
  Bytes transcript(StringBytes(kPreface).begin(), StringBytes(kPreface).end());
  Append(&transcript, Frame(254, SuiteHash(0x1301, first)));
  Append(&transcript, retry);
  Append(&transcript, second.first(second.size() - 35));
  const auto early = SuiteMac(0x1301, Bytes(32), ticket.psk);
  const auto binder = SuiteLabel(0x1301, early, "res binder", SuiteHash(0x1301, {}), 32);
  const auto finished = SuiteLabel(0x1301, binder, "finished", {}, 32);
  const auto expected = SuiteMac(0x1301, finished, SuiteHash(0x1301, transcript));
  Check(std::equal(expected.begin(), expected.end(), second_psk.end() - 32),
        "CH2 binder authenticates the refreshed ticket age and HRR transcript");

  Client expired("example.test", {}, false, options);
  Check(expired.Start(&ticket), "unexpired ticket initial offer");
  expired.TakeOutput();
  ProtocolRegressionPeer::AgeTicket(expired, 3600000);
  Check(!expired.Receive(Plaintext(retry), &application) && expired.TakeOutput().empty(),
        "ticket expiring during retry is not offered again");

  ClientOptions external_options;
  ExternalPSK external;
  external.identity = Bytes{0x45};
  external.secret = Bytes(32, 0x65);
  external.hostname = "example.test";
  external_options.external_psks.push_back(external);
  Client external_client("example.test", {}, false, external_options);
  Check(external_client.Start(), "external PSK initial offer");
  external_client.TakeOutput();
  Check(external_client.Receive(Plaintext(retry), &application), "external PSK retry");
  const auto external_records = external_client.TakeOutput();
  Check(PskAge(HelloPsk(ByteSpan(external_records).subspan(5u))) == 0,
        "external PSK age remains zero after retry");
}

void FragmentInterleaving() {
  const auto retry = CookieRetry();
  for (uint8_t alert : {0, 90}) {
    Client client("example.test", {}, true);
    Check(client.Start(), "fragmented HRR ClientHello");
    client.TakeOutput();
    Bytes application;
    Check(client.Receive(Plaintext(ByteSpan(retry).first(9u)), &application),
          "initial HRR fragment accepted");
    // RFC compatibility CCS remains ignorable anywhere in this initial flight.
    Check(client.Receive(Bytes{20, 3, 3, 0, 1, 1}, &application),
          "compatibility CCS does not interrupt handshake reassembly");
    Check(!client.Receive(Bytes{21, 3, 3, 0, 2, 1, alert}, &application),
          "plaintext alert cannot interrupt fragmented HRR");
    CheckAlert(client, 10, false);
    Check(!client.Receive(Plaintext(ByteSpan(retry).subspan(9u)), &application) &&
              client.TakeOutput().empty(), "failed fragmented HRR never emits CH2");
    for (bool initial : {false, true}) {
      Client protected_client("example.test", {}, true);
      ProtocolRegressionPeer::Prepare(protected_client, initial);
      Check(protected_client.Receive(Protect(Bytes{initial ? uint8_t{8} : uint8_t{24}, 0, 22}),
                                     &application), "protected handshake fragment accepted");
      Check(!protected_client.Receive(Protect(Bytes{1, alert, 21}, 1), &application),
            "protected alert cannot interrupt initial or post-handshake message");
      CheckAlert(protected_client, 10);
    }
  }
}

void FailedSecretErasure() {
  auto password = std::make_shared<PasswordCredential>();
  password->password = "public test password";
  for (bool peer_alert : {false, true}) {
    ClientOptions options;
    options.password = password;
    options.post_handshake_auth = true;
    Client client("example.test", {}, true, options);
    ProtocolRegressionPeer::Prepare(client);
    ProtocolRegressionPeer::PopulateSecrets(client);
    Bytes application;
    Check(!client.Receive(peer_alert ? Protect(Bytes{2, 40, 21}) : Bytes{23, 3, 3, 0, 0},
                          &application), "fatal peer or local record error latches failure");
    Check(ProtocolRegressionPeer::SecretsErased(client),
          "failed live Client immediately erases derived secrets and credential copies");
    Check(client.TakeTickets().empty() && !client.Export("test", {}, 32, &application) &&
              !client.ExportEarly("test", {}, 32, &application),
          "failed connection retains no ticket or exporter capability");
    Check(password->password == "public test password" &&
              options.password->password == password->password,
          "failure never mutates shared persistent provisioning");
    if (peer_alert)
      Check(client.TakeFatalAlert().empty(), "peer fatal alert is not answered");
    else
      CheckAlert(client, 20);
  }
}

void HandshakeFailureLifecycle() {
  ClientOptions options;
  ExternalPSK psk;
  psk.identity = Bytes{0x50};
  psk.secret = Bytes(32, 0x70);
  psk.hostname = "example.test";
  options.external_psks.push_back(psk);
  Client client("example.test", {}, true, options);
  Check(client.Start(), "failure-lifecycle initial ClientHello");
  client.TakeOutput();
  Secret private_key{}, public_key{};
  private_key.fill(0x29);
  X25519_public_from_private(public_key.data(), private_key.data());
  Bytes share{0, 29};
  Append(&share, Vector16(public_key));
  Bytes extensions;
  Extension(&extensions, 43, Bytes{4, 0});
  Extension(&extensions, 41, Bytes{0, 0});
  Extension(&extensions, 51, share);
  Bytes body{3, 3};
  Append(&body, Bytes(32, 0x53));
  Append(&body, Bytes{0, 0x13, 1, 0});
  Append(&body, Vector16(extensions));
  Bytes application;
  Check(client.Receive(Plaintext(Frame(2, body)), &application) &&
            ProtocolRegressionPeer::HasHandshakeSecrets(client),
        "actual ServerHello derives all handshake secrets before failure");
  const auto sending_secret = ProtocolRegressionPeer::HandshakeSendingSecret(client);
  ProtocolRegressionPeer::AwaitVerification(client);
  Check(!client.CompleteCertificateVerification(false) &&
            ProtocolRegressionPeer::SecretsErased(client),
        "negative asynchronous verifier decision immediately erases derived state");
  Check(!client.CompleteCertificateVerification(true) &&
            !client.Receive(Bytes{23, 3, 3, 0, 0}, &application) &&
            !client.OutputFlushed() && client.error() == Client::Error::kCertificate &&
            ProtocolRegressionPeer::SecretsErased(client),
        "repeated failure cannot revive secrets or overwrite the original error");
  RecordCipher peer(sending_secret);
  uint8_t type = 0;
  Check(peer.Open(client.TakeFatalAlert(), &type, &application) && type == 21 &&
            application == Bytes({2, 42}),
        "single outbound fatal alert uses the old handshake key before erasure");
  Check(client.TakeFatalAlert().empty() && !client.CompleteCertificateVerification(false) &&
            client.TakeFatalAlert().empty(), "repeated failures cannot duplicate the fatal alert");
  Check(options.external_psks.front().secret == psk.secret && psk.secret == Bytes(32, 0x70),
        "failed Client erases only its own copies of persistent external PSKs");

  Client unflushed("example.test", {}, true, options);
  Check(unflushed.Start(), "initial output deliberately remains unflushed");
  Check(!unflushed.Receive(Bytes{23, 3, 3, 0, 0}, &application) &&
            ProtocolRegressionPeer::SecretsErased(unflushed) &&
            unflushed.TakeOutput().empty() && unflushed.TakeFatalAlert().empty(),
        "failure discards queued output without emitting an alert ahead of it");
}

void HalfCloseKeepsOppositeDirection() {
  Client incoming_close("example.test", {}, true);
  ProtocolRegressionPeer::Prepare(incoming_close);
  ProtocolRegressionPeer::RetainTicket(incoming_close);
  Bytes application, record;
  Check(incoming_close.Receive(Protect(Bytes{1, 0, 21}), &application) &&
            incoming_close.closed(), "authenticated peer closure closes the read direction");
  Check(incoming_close.Export("half-close", {}, 32, &application) &&
            incoming_close.Send(Bytes{7, 8}, &record),
        "peer half-close retains exporter and opposite-direction traffic keys");
  RecordCipher peer(ProtocolRegressionPeer::SendingSecret());
  uint8_t type = 0;
  Check(peer.Open(record, &type, &application) && type == 23 && application == Bytes({7, 8}),
        "application bytes remain authenticated after peer half-close");
  Check(incoming_close.Close(&record) && peer.Open(record, &type, &application) &&
            type == 21 && application == Bytes({1, 0}), "local close follows the final application record");
  auto tickets = incoming_close.TakeTickets();
  Check(tickets.size() == 1 && tickets.front().psk == Bytes(32, 0x70) &&
            ProtocolRegressionPeer::SecretsErased(incoming_close) &&
            !incoming_close.Export("half-close", {}, 32, &application),
        "peer-first full close erases connection secrets but permits ticket cache handoff");

  Client outgoing_close("example.test", {}, true);
  ProtocolRegressionPeer::Prepare(outgoing_close);
  ProtocolRegressionPeer::RetainTicket(outgoing_close);
  Check(outgoing_close.Close(&record) && !outgoing_close.closed(),
        "local close leaves the peer read direction open");
  Check(outgoing_close.Receive(Protect(Bytes{9, 23}), &application) && application == Bytes{9},
        "local close retains receiving keys until authenticated peer closure");
  Check(outgoing_close.Receive(Protect(Bytes{1, 0, 21}, 1), &application) &&
            outgoing_close.closed() && outgoing_close.TakeFatalAlert().empty(),
        "orderly bidirectional close does not become a failure");
  tickets = outgoing_close.TakeTickets();
  Check(tickets.size() == 1 && tickets.front().psk == Bytes(32, 0x70) &&
            ProtocolRegressionPeer::SecretsErased(outgoing_close) &&
            !outgoing_close.Export("half-close", {}, 32, &application),
        "local-first full close erases connection secrets but permits ticket cache handoff");
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
  {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    RecordCipher peer_sender(ProtocolRegressionPeer::ReceivingSecret());
    Bytes record, application;
    Check(peer_sender.Seal(Frame(24, Bytes{1}), 22, &record) &&
              client.Receive(record, &application), "peer requests update before read half-close");
    const auto next_receiving = SuiteLabel(0x1301,
        ProtocolRegressionPeer::ReceivingSecret(), "traffic upd", {}, 32);
    RecordCipher next_peer_sender(next_receiving);
    Check(next_peer_sender.Seal(Bytes{1, 0}, 21, &record) &&
              client.Receive(record, &application) && application.empty() &&
              ProtocolRegressionPeer::UpdateResponsePending(client),
          "peer close_notify preserves the outstanding writing-side update response");
    Check(client.Send(Bytes{7, 8}, &record), "application write remains legal after read half-close");
    Check(record.size() >= 5, "half-close update response is framed");
    const size_t first_length = 5 + (size_t{record[3]} << 8) + record[4];
    RecordCipher peer_receiver(ProtocolRegressionPeer::SendingSecret());
    uint8_t type = 0;
    Check(first_length < record.size() &&
              peer_receiver.Open(ByteSpan(record).first(first_length), &type, &application) &&
              type == 22 && application == Frame(24, Bytes{0}),
          "required KeyUpdate response precedes application data in the old writing epoch");
    const auto next_sending = SuiteLabel(0x1301,
        ProtocolRegressionPeer::SendingSecret(), "traffic upd", {}, 32);
    RecordCipher next_peer_receiver(next_sending);
    Check(next_peer_receiver.Open(ByteSpan(record).subspan(first_length), &type, &application) &&
              type == 23 && application == Bytes({7, 8}) &&
              !ProtocolRegressionPeer::UpdateResponsePending(client),
          "post-half-close application data uses the new epoch and clears its response obligation");
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

void RequestedKeyUpdatePreservesResponse() {
  const auto inspect = [](const Bytes& records, const Bytes& expected_updates,
                          const Bytes& expected_application) {
    auto secret = ProtocolRegressionPeer::SendingSecret();
    auto receiver = std::make_unique<RecordCipher>(secret);
    size_t cursor = 0, updates = 0, applications = 0;
    while (cursor < records.size()) {
      Check(records.size() - cursor >= 5, "KU response record header");
      const size_t length = 5 + (size_t{records[cursor + 3]} << 8) + records[cursor + 4];
      Check(length <= records.size() - cursor, "KU response record length");
      Bytes content;
      uint8_t type;
      Check(receiver->Open(ByteSpan(records).subspan(cursor, length), &type, &content),
            "every response record opens in the exact successive sending epoch");
      if (type == 22) {
        Check(!applications && updates < expected_updates.size() &&
                  content == Frame(24, Bytes{expected_updates[updates]}),
              "KU response flags and ordering match the independent expectation");
        ++updates;
        secret = SuiteLabel(0x1301, secret, "traffic upd", {}, 32);
        receiver = std::make_unique<RecordCipher>(secret);
      } else {
        Check(type == 23 && updates == expected_updates.size() &&
                  content == expected_application,
              "all required KU0 responses precede even empty application data");
        ++applications;
      }
      cursor += length;
    }
    Check(updates == expected_updates.size() && applications == 1,
          "exact KU response and application record counts");
  };

  for (bool crossed_request : {false, true}) {
    for (uint8_t incoming_request : {0, 1}) {
      for (int manual_request : {-1, 0, 1}) {
        for (const Bytes application : {Bytes{}, Bytes{0x42, 0x43}}) {
          Client client("example.test", {}, true);
          ProtocolRegressionPeer::Prepare(client);
          Bytes part, records, updates, received;
          if (crossed_request) {
            Check(client.RequestKeyUpdate(true, &part), "own KU1 precedes crossing peer update");
            Append(&records, part);
            updates.push_back(1);
            Check(!client.RequestKeyUpdate(true, &part),
                  "own outstanding request prohibits another KU1");
          }
          RecordCipher sender(ProtocolRegressionPeer::ReceivingSecret());
          Check(sender.Seal(Frame(24, Bytes{incoming_request}), 22, &part) &&
                    client.Receive(part, &received), "receive crossing or independent peer update");
          Check(ProtocolRegressionPeer::UpdateResponsePending(client) == (incoming_request == 1),
                "only peer KU1 creates a response obligation");
          if (manual_request >= 0) {
            Check(client.RequestKeyUpdate(manual_request != 0, &part),
                  "peer update permits a fresh manual key update");
            Append(&records, part);
            updates.push_back(static_cast<uint8_t>(manual_request));
          }
          const bool response_pending = incoming_request == 1 && manual_request != 0;
          Check(ProtocolRegressionPeer::UpdateResponsePending(client) == response_pending,
                "manual KU1 cannot consume the peer's required KU0 response");
          if (response_pending) updates.push_back(0);
          Check(client.Send(application, &part), "application flushes the outstanding KU0");
          Append(&records, part);
          inspect(records, updates, application);
          Check(!ProtocolRegressionPeer::UpdateResponsePending(client),
                "actual KU0 consumes the response obligation");
          Check(client.RequestKeyUpdate(true, &part) == (manual_request != 1),
                "automatic KU0 never clears an independent outbound KU1 latch");
        }
      }
    }
  }

  // The RFC epoch exception also applies when an explicitly initiated KU1
  // consumes the last allowed epoch after a peer request was already received.
  constexpr uint64_t kLastEpoch = (uint64_t{1} << 48) - 1;
  Client client("example.test", {}, true);
  ProtocolRegressionPeer::Prepare(client);
  ProtocolRegressionPeer::SendingEpoch(client, kLastEpoch - 1);
  RecordCipher sender(ProtocolRegressionPeer::ReceivingSecret());
  Bytes part, records, received;
  Check(sender.Seal(Frame(24, Bytes{1}), 22, &part) && client.Receive(part, &received) &&
            ProtocolRegressionPeer::UpdateResponsePending(client),
        "peer KU1 is pending before the last locally initiated epoch");
  Check(client.RequestKeyUpdate(true, &records), "manual KU1 consumes the final permitted epoch");
  Check(!ProtocolRegressionPeer::UpdateResponsePending(client),
        "RFC epoch ceiling ignores only the now-impossible extra response");
  Check(client.Send(Bytes{0x51}, &part), "final epoch remains usable within its key quota");
  Append(&records, part);
  inspect(records, Bytes{1}, Bytes{0x51});
  Check(!client.RequestKeyUpdate(false, &part), "pending response cannot cause an epoch wrap");
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

void CertificateResponseOffers() {
  for (uint16_t code : {0xfafa, 5, 18, 34, 52, 59, 15, 43, 0xff02}) {
    Client client("example.test", {}, true);
    Check(client.Start(), "CertificateEntry offer fixture starts");
    ProtocolRegressionPeer::Prepare(client);
    ProtocolRegressionPeer::AwaitInitialCertificateRequest(client);
    Bytes extensions;
    Extension(&extensions, code, {});
    Bytes entry{0, 0, 1, 0};  // Rejected metadata precedes any DER trust decision.
    Append(&entry, Vector16(extensions));
    Bytes body{0, 0, 0, static_cast<uint8_t>(entry.size())};
    Append(&body, entry);
    auto certificate = Frame(11, body);
    certificate.push_back(22);
    Bytes application;
    Check(!client.Receive(Protect(certificate), &application) && application.empty(),
          "CertificateEntry response cannot invent an offer");
    CheckAlert(client, code == 34 ? 10 : code == 15 || code == 43 || code == 0xff02 ? 47 : 110);
  }
}

void CertificateRequestValidation() {
  // Independently encoded DER Name (CN=A), not produced by the parser under test.
  const Bytes name{0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03,
                   0x55, 0x04, 0x03, 0x0c, 0x01, 0x41};
  const auto names = Vector16(Vector16(name));
  Bytes trailing_name = name;
  trailing_name.push_back(0);
  Bytes nonminimal_name = name;
  nonminimal_name.insert(nonminimal_name.begin() + 1, 0x81);
  Bytes malformed_oid = name;
  malformed_oid[8] = 0x80;
  Bytes unsorted_name{0x30, 0x16, 0x31, 0x14};
  Bytes attribute(name.begin() + 4, name.end());
  attribute.back() = 0x42;
  Append(&unsorted_name, attribute);
  attribute.back() = 0x41;
  Append(&unsorted_name, attribute);
  struct Case { uint16_t type; Bytes data; bool valid; };
  const Case cases[] = {
      {47, names, true}, {47, Vector16(Vector16(Bytes{0x30, 0})), true},
      {47, {}, false}, {47, {0, 0}, false}, {47, {0, 3, 0, 1, 0}, false},
      {47, {0, 2, 0, 0}, false}, {47, Vector16(Vector16(trailing_name)), false},
      {47, Vector16(Vector16(nonminimal_name)), false},
      {47, Vector16(Vector16(malformed_oid)), false},
      {47, Vector16(Vector16(unsorted_name)), false},
      {5, {}, true}, {5, {0}, false}, {5, {1, 0, 0, 0, 0}, false},
      {0xaaa0, {0}, true}};
  for (const auto& test : cases) {
    for (bool pha : {false, true}) {
      ClientOptions options;
      options.post_handshake_auth = true;
      Client client("example.test", {}, true, options);
      Check(client.Start(), "CR validation ClientHello");
      ProtocolRegressionPeer::Prepare(client);
      if (!pha) ProtocolRegressionPeer::AwaitInitialCertificateRequest(client);
      auto base = CertificateRequest();
      Bytes extensions(base.begin() + 8, base.end());
      Extension(&extensions, 50, Bytes{0, 2, 8, 7});
      Extension(&extensions, test.type, test.data);
      Bytes body = pha ? Bytes{1, 7} : Bytes{0};
      Append(&body, Vector16(extensions));
      auto request = Frame(13, body);
      Bytes record, application;
      RecordCipher sender(ProtocolRegressionPeer::ReceivingSecret());
      Check(sender.Seal(request, 22, &record), "protect known CR extension");
      Check(client.Receive(record, &application) == test.valid,
            "known CR/PHA syntax is validated without a local credential");
      Check(application.empty(), "CR/PHA does not release application bytes");
      if (!test.valid) {
        CheckAlert(client, 50);
        Check(ProtocolRegressionPeer::SecretsErased(client),
              "malformed request erases connection secrets");
      } else if (pha) {
        Check(!client.TakeOutput().empty(), "valid PHA permits empty-credential refusal");
      }

      // Exported client authenticators must validate requests even when the
      // caller selects no credential. Do not consume the context on failure.
      Client authenticator("example.test", {}, true, options);
      Check(authenticator.Start(), "authenticator request fixture starts");
      ProtocolRegressionPeer::Prepare(authenticator);
      Bytes response;
      Check(authenticator.AuthenticateClient(request, nullptr, &response) == test.valid,
            "client authenticator validates CA/OCSP syntax before empty response");
      Check(response.empty() == !test.valid, "malformed EA request has no response");
    }
  }
}

void DelegationRequestDuplicates() {
  for (bool pha : {false, true}) {
    for (uint16_t duplicate : {0, 34, 50, 0xff04}) {
      ClientOptions options;
      options.post_handshake_auth = true;
      Client client("example.test", {}, true, options);
      Check(client.Start(), "delegation request fixture advertises PHA");
      ProtocolRegressionPeer::Prepare(client);
      if (!pha) ProtocolRegressionPeer::AwaitInitialCertificateRequest(client);
      Bytes extensions;
      Extension(&extensions, 0xff03, Bytes(32, 0x67));
      Extension(&extensions, 50, Bytes{0, 2, 8, 7});
      Extension(&extensions, 34, Bytes{0, 2, 0xfe, 1});
      Extension(&extensions, 0xff04, Bytes{0, 2, 8, 7});
      if (duplicate)
        Extension(&extensions, duplicate,
                  duplicate == 34 ? Bytes{0, 2, 0xfe, 1} : Bytes{0, 2, 8, 7});
      Bytes body = pha ? Bytes{1, 7} : Bytes{0};
      Append(&body, Vector16(extensions));
      auto request = Frame(13, body);
      request.push_back(22);
      Bytes application;
      Check(client.Receive(Protect(request), &application) == (duplicate == 0),
            "delegation offers reject duplicate extensions, not valid independent lists");
      Check(application.empty(), "CR never releases application data");
      if (duplicate) {
        CheckAlert(client, 47);
        Check(ProtocolRegressionPeer::SecretsErased(client),
              "duplicate delegation offers erase failed connection secrets");
      } else if (pha) {
        Check(!client.TakeOutput().empty(), "valid delegation PHA permits credential refusal");
      }
    }
  }
}

void OidFilterRequestValidation() {
  const Bytes unknown{6, 2, 0x2a, 3}, ku{6, 3, 0x55, 0x1d, 0x0f},
      eku{6, 3, 0x55, 0x1d, 0x25};
  auto filter = [](const Bytes& oid, const Bytes& values, bool duplicate = false) {
    Bytes item{static_cast<uint8_t>(oid.size())};
    Append(&item, oid);
    Append(&item, Vector16(values));
    Bytes entries = item;
    if (duplicate) Append(&entries, item);
    return Vector16(entries);
  };
  const std::pair<Bytes, uint8_t> cases[] = {
      {Bytes{0, 0}, 0}, {filter(unknown, {}), 0},
      // Unknown value semantics must be ignored, including non-DER bytes.
      {filter(unknown, {0xff, 0, 0x80}), 0},
      {filter(ku, {}), 0}, {filter(ku, {3, 1, 0}), 0},
      {filter(ku, {3, 2, 7, 0x80}), 0},
      {filter(eku, {0x30, 0x0a, 6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 2}), 0},
      {filter(unknown, {}, true), 47},
      {{}, 50}, {{0, 1, 0}, 50}, {{0, 0, 0}, 50},
      {filter({}, {}), 50}, {filter({6, 0}, {}), 50},
      {filter({6, 1, 0x80}, {}), 50},
      {filter({6, 2, 0x2a, 3, 0}, {}), 50},
      {filter({6, 0x81, 2, 0x2a, 3}, {}), 50},
      {filter(ku, {3, 2, 8, 0x80}), 50},
      {filter(ku, {3, 2, 0, 0x80}), 50},
      {filter(ku, {3, 3, 6, 0, 0x40}), 47},
      {filter(eku, {0x30, 0}), 50},
      {filter(eku, {0x30, 3, 6, 1, 0x80}), 50},
      {filter(eku, {0x30, 6, 6, 4, 0x55, 0x1d, 0x25, 0}), 47}};
  for (const auto& [encoded, alert] : cases) {
    for (bool pha : {false, true}) {
      ClientOptions options;
      options.post_handshake_auth = true;
      Client client("example.test", {}, true, options);
      Check(client.Start(), "OID request fixture starts");
      ProtocolRegressionPeer::Prepare(client);
      if (!pha) ProtocolRegressionPeer::AwaitInitialCertificateRequest(client);
      Bytes extensions;
      Extension(&extensions, 0xff03, Bytes(32, 9));
      Extension(&extensions, 50, Bytes{0, 2, 8, 7});
      Extension(&extensions, 48, encoded);
      Bytes body = pha ? Bytes{1, 7} : Bytes{0};
      Append(&body, Vector16(extensions));
      const auto frame = Frame(13, body);
      auto protected_body = frame;
      protected_body.push_back(22);
      Bytes application;
      Check(client.Receive(Protect(protected_body), &application) == (alert == 0),
            "CR/PHA validates OID and recognized values without a credential");
      Check(application.empty(), "OID filter parsing releases no application bytes");
      if (alert) {
        CheckAlert(client, alert);
        Check(ProtocolRegressionPeer::SecretsErased(client) && client.TakeOutput().empty(),
              "malformed CR/PHA cannot emit a credential refusal and erases secrets");
      } else if (pha) {
        Check(!client.TakeOutput().empty(), "valid OID filters permit an empty credential response");
      }
      Client authenticator("example.test", {}, true, options);
      Check(authenticator.Start(), "OID authenticator fixture starts");
      ProtocolRegressionPeer::Prepare(authenticator);
      Bytes response;
      Check(authenticator.AuthenticateClient(frame, nullptr, &response) == (alert == 0),
            "shared OID parser preserves EA acceptance and refusal policy");
      Check(response.empty() == (alert != 0), "invalid EA filter has no response");
    }
  }
}

void CertificateTransparencyRequestSyntax() {
  for (uint16_t type : {18, 52, 0xaaaa}) {
    for (const Bytes& value : {Bytes{}, Bytes{1}, Bytes{0, 0}, Bytes{0, 3, 0, 1, 0xff}}) {
      const bool valid = type == 0xaaaa || value.empty();
      Bytes template_extensions;
      Extension(&template_extensions, 50, Bytes{0, 2, 8, 7});
      Extension(&template_extensions, type, value);
      const auto request_template = Vector16(template_extensions);
      for (bool pha : {false, true}) {
        for (bool cached : {false, true}) {
          ClientOptions options;
          options.post_handshake_auth = true;
          if (cached) options.cached_request_templates = {request_template};
          Client client("example.test", {}, true, options);
          Check(client.Start(), "CT request fixture starts");
          ProtocolRegressionPeer::Prepare(client);
          if (!pha) ProtocolRegressionPeer::AwaitInitialCertificateRequest(client);
          Bytes body = pha ? Bytes{1, 7} : Bytes{0};
          if (cached) {
            ProtocolRegressionPeer::SelectCachedRequest(client);
            Append(&body, net::httpps::Hash(request_template));
            Append(&body, Bytes(32, 0x67));
          } else {
            Bytes extensions = template_extensions;
            Extension(&extensions, 0xff03, Bytes(32, 0x67));
            Append(&body, Vector16(extensions));
          }
          const auto frame = Frame(cached ? 252 : 13, body);
          Bytes record, application;
          RecordCipher sender(ProtocolRegressionPeer::ReceivingSecret());
          Check(sender.Seal(frame, 22, &record), "protect ordinary or cached CT request");
          Check(client.Receive(record, &application) == valid && application.empty(),
                "CR/PHA and reconstructed cache require empty CT requests, not opaque responses");
          if (!valid) {
            CheckAlert(client, 50);
            Check(ProtocolRegressionPeer::SecretsErased(client), "malformed CT request erases secrets");
          } else if (pha) {
            Check(!client.TakeOutput().empty(), "empty CT or unknown offer permits PHA refusal");
          }
        }
      }
      Client client("example.test", {}, true);
      Check(client.Start(), "EA CT fixture starts");
      ProtocolRegressionPeer::Prepare(client);
      Bytes extensions = template_extensions;
      Extension(&extensions, 0xff03, Bytes(32, 0x67));
      Bytes body{1, 7};
      Append(&body, Vector16(extensions));
      Bytes response, request;
      Check(client.AuthenticateClient(Frame(13, body), nullptr, &response) == valid,
            "EA client request validates CT syntax even for refusal");
      Check(client.established() && client.TakeFatalAlert().empty() && client.TakeOutput().empty(),
            "EA request syntax never emits a TLS alert or closes its channel");
      if (!valid) {
        extensions.clear();
        Extension(&extensions, 50, Bytes{0, 2, 8, 7});
        Extension(&extensions, type, {});
        Extension(&extensions, 0xff03, Bytes(32, 0x67));
        body = Bytes{1, 7};
        Append(&body, Vector16(extensions));
        Check(client.AuthenticateClient(Frame(13, body), nullptr, &response),
              "invalid EA client CT request does not consume its context");
      }
      Check(client.RequestServerAuthenticator(Bytes{8}, {{type, value}}, &request) == valid,
            "EA server request requires empty known CT requests but accepts unknown opaque offers");
      if (!valid)
        Check(client.RequestServerAuthenticator(Bytes{8}, {{type, {}}}, &request),
              "invalid EA server CT request does not consume its context");
      Check(client.CancelAuthenticator(request), "valid EA CT request can be cancelled");
    }
  }
}

void PskHelloGroupSharePair() {
  for (const auto& modes : {Bytes{0}, Bytes{1}, Bytes{0, 1}}) {
    for (bool early : {false, true}) {
      ClientOptions options;
      options.psk_modes = modes;
      ExternalPSK psk;
      psk.identity = Bytes{1}; psk.secret = Bytes(32, 0x70);
      psk.hostname = "example.test"; psk.max_early_data = 1024;
      options.external_psks.push_back(psk);
      Client client("example.test", {}, true, options);
      Check(client.Start(nullptr, {}, early), "PSK ClientHello starts");
      auto output = client.TakeOutput();
      auto first = HelloExtensions(JoinPlaintextRecords(ByteSpan(output).subspan(kPreface.size())));
      Check(first.count(10) == 1 && first.count(51) == 1 && first.count(41) == 1,
            "ClientHello1 keeps supported_groups/key_share paired, including PSK-ke");
      Check(first.count(42) == size_t(early), "PSK early offer control");
      Check(ReceivePlaintextHandshake(client, CookieRetry()), "PSK cookie-only HRR accepted");
      auto second = HelloExtensions(JoinPlaintextRecords(client.TakeOutput()));
      Check(second.count(10) == 1 && second.count(51) == 1 && second.count(41) == 1 &&
                second.count(42) == 0 && first.at(10) == second.at(10) && first.at(51) == second.at(51),
            "ClientHello2 preserves group/share pair while rejecting early data");
    }
  }
}

void AuthenticatorServerNameValidation() {
  auto entry = [](std::string_view name, uint8_t type = 0) {
    Bytes value{type};
    Append(&value, Vector16(StringBytes(name)));
    return value;
  };
  auto server_name = [&](std::string_view name) { return Vector16(entry(name)); };
  Bytes duplicate = entry("first.example");
  Append(&duplicate, entry("second.example"));
  Bytes mixed = entry("first.example");
  Append(&mixed, entry("opaque", 1));
  Bytes trailing = server_name("localhost");
  trailing.push_back(0);
  Bytes truncated = server_name("localhost");
  truncated.pop_back();
  std::vector<Bytes> invalid{
      {}, {0}, {0, 0}, {0, 1, 0}, {0, 2, 0, 0}, {0, 3, 0, 0, 0},
      {0, 4, 0, 0, 2, 'a'}, {0, 5, 0, 0, 1, 'a', 'X'},
      Vector16(entry("localhost", 1)), Vector16(entry("localhost", 255)),
      Vector16(duplicate), Vector16(mixed), trailing, truncated};
  for (std::string_view name : {"", ".", ".example", "example.", "a..example",
                               "-a.example", "a-.example", "a_b.example", "a/b",
                               "a b", "*.example", "127.0.0.1", "1234", "::1",
                               "[::1]", "localhost:343"})
    invalid.push_back(server_name(name));
  invalid.push_back(server_name(std::string_view("a\0.example", 10)));
  invalid.push_back(server_name("b\xc3\xbc" "cher.example"));
  invalid.push_back(server_name(std::string(64, 'a') + ".example"));
  invalid.push_back(server_name(std::string(63, 'a') + "." + std::string(63, 'b') +
                                "." + std::string(63, 'c') + "." + std::string(62, 'd')));
  for (const auto& value : invalid) {
    Client client("original.example", {}, true);
    Check(client.Start(), "EA server-name fixture starts");
    ProtocolRegressionPeer::Prepare(client);
    Bytes request, binding;
    Check(!client.RequestServerAuthenticator(Bytes{7}, {{0, value}}, &request),
          "EA rejects malformed server_name before claiming its context");
    Check(request.empty() && client.established() && client.TakeOutput().empty() &&
              client.TakeFatalAlert().empty() && client.ChannelBinding(&binding),
          "EA syntax rejection is nonfatal and releases no request or TLS alert");
    Check(client.RequestServerAuthenticator(Bytes{7}, {}, &request) &&
              client.CancelAuthenticator(request),
          "invalid SNI consumes no context and SNI remains optional");
  }
  const std::vector<std::string> valid{
      "localhost", "LoCaLhOsT", "different.example", "XN--BCHER-KVA.Example",
      "a-b.example", std::string(63, 'a') + ".example",
      std::string(63, 'a') + "." + std::string(63, 'b') + "." +
          std::string(63, 'c') + "." + std::string(61, 'd')};
  for (const auto& name : valid) {
    Client client("original.example", {}, true);
    Check(client.Start(), "EA valid server-name fixture starts");
    ProtocolRegressionPeer::Prepare(client);
    const auto value = server_name(name);
    Bytes request;
    Check(client.RequestServerAuthenticator(Bytes{7}, {{0, value}}, &request),
          "EA accepts case-insensitive DNS syntax without new identity policy");
    Bytes encoded;
    Extension(&encoded, 0, value);
    Check(std::search(request.begin(), request.end(), encoded.begin(), encoded.end()) != request.end(),
          "EA preserves original SNI bytes in its request transcript");
    Check(client.CancelAuthenticator(request) && !client.CancelAuthenticator(request),
          "valid SNI request context is consumed exactly once");

    Bytes extensions;
    Extension(&extensions, 0xff03, Bytes(32, 0x67));
    Extension(&extensions, 50, Bytes{0, 2, 8, 7});
    Extension(&extensions, 0, value);
    Bytes body{1, 8};
    Append(&body, Vector16(extensions));
    Bytes response;
    Check(!client.AuthenticateClient(Frame(13, body), nullptr, &response) &&
              client.established() && client.TakeFatalAlert().empty(),
          "SNI is not permitted in the opposite client-authenticator direction");
  }
}

void ClosedWriterControlMessages() {
  ClientCredential credential;
  credential.certificate_type = 2;
  credential.private_key.fill(0x43);
  Secret public_key;
  X25519_public_from_private(public_key.data(), credential.private_key.data());
  Bytes spki{0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 3, 0x21, 0};
  Append(&spki, public_key);
  credential.certificates.emplace_back(reinterpret_cast<const char*>(spki.data()), spki.size());
  for (bool pha : {false, true}) {
    for (bool close_first : {false, true}) {
      for (bool pending_update : {false, true}) {
        ClientOptions options;
        options.heartbeat_mode = 1;
        options.post_handshake_auth = true;
        Client client("example.test", {}, true, options);
        Check(client.SetClientCredential(credential) && client.Start(),
              "half-close control fixture offers a real RPK client credential");
        ProtocolRegressionPeer::Prepare(client);
        ProtocolRegressionPeer::AuthenticationMode(client, Authentication::kCertificate);
        ProtocolRegressionPeer::HeartbeatLimits(client, 16385, 16385);
        Bytes incoming_secret = ProtocolRegressionPeer::ReceivingSecret();
        auto sender = std::make_unique<RecordCipher>(incoming_secret);
        Bytes record, application;
        auto peer_update = [&] {
          Check(sender->Seal(Frame(24, Bytes{1}), 22, &record) &&
                    client.Receive(record, &application), "peer key update opens during half-close");
          incoming_secret = SuiteLabel(0x1301, incoming_secret, "traffic upd", {}, 32);
          sender = std::make_unique<RecordCipher>(incoming_secret);
        };
        if (pending_update) {
          peer_update();
          Check(ProtocolRegressionPeer::UpdateResponsePending(client),
                "peer requested update is pending before local close");
        }
        if (close_first) {
          Check(client.Close(&record) && ProtocolRegressionPeer::WritingSecretsErased(client),
                "local close erases only writing keys, credentials and update latches");
          RecordCipher receiver(ProtocolRegressionPeer::SendingSecret());
          uint8_t type = 0;
          Check(receiver.Open(record, &type, &application) && type == 21 &&
                    application == Bytes({1, 0}), "close_notify is the final local record");
        }
        Bytes content{1, 0, 1, 0x42};
        content.resize(20, 0x99);
        if (pha) content = CertificateRequest();
        Check(sender->Seal(content, pha ? 22 : 24, &record) && client.Receive(record, &application),
              "valid control request still opens after local write close");
        Check(client.TakeOutput().empty() == close_first,
              "heartbeat and authenticated PHA responses occur only before local close");
        if (!close_first) continue;
        Check(!client.RequestKeyUpdate(false, &record) && !client.RequestHeartbeat({}, &record) &&
                  !client.Close(&record) && client.TakeOutput().empty(),
              "explicit control writes cannot reopen the closed direction");
        peer_update();
        Check(ProtocolRegressionPeer::WritingSecretsErased(client),
              "incoming key update cannot recreate sending state or response obligation");
        Check(sender->Seal(Bytes{7, 8}, 23, &record) && client.Receive(record, &application) &&
                  application == Bytes({7, 8}), "new-epoch application data remains readable after local close");
        Check(client.Export("half-close", {}, 32, &application) &&
                  client.TakeOutput().empty() && client.TakeFatalAlert().empty(),
              "half-close keeps exporter without producing post-close records");
      }
    }
  }
  Check(std::all_of(credential.private_key.begin(), credential.private_key.end(),
                   [](uint8_t value) { return value == 0x43; }),
        "closing connection-owned credential copies preserves caller provisioning");

  ClientOptions options;
  options.post_handshake_auth = true;
  Client queued("example.test", {}, true, options);
  Check(queued.Start(), "queued PHA control fixture");
  ProtocolRegressionPeer::Prepare(queued);
  ProtocolRegressionPeer::AuthenticationMode(queued, Authentication::kCertificate);
  auto request = CertificateRequest(); request.push_back(22);
  Bytes application, record;
  Check(queued.Receive(Protect(request), &application) && queued.Close(&record),
        "close flushes an already-encrypted control response before its alert");
  RecordCipher receiver(ProtocolRegressionPeer::SendingSecret());
  ByteSpan remaining(record);
  const uint8_t expected_types[] = {22, 22, 21};
  const uint8_t expected_messages[] = {11, 20, 1};
  for (size_t i = 0; i < 3; ++i) {
    Check(remaining.size() >= 5, "queued control record framing");
    const size_t length = 5 + (size_t{remaining[3]} << 8) + remaining[4];
    uint8_t type = 0;
    Check(length <= remaining.size() && receiver.Open(remaining.first(length), &type, &application) &&
              type == expected_types[i] && !application.empty() && application[0] == expected_messages[i],
          "queued Certificate and Finished precede final close_notify in the correct sequence");
    remaining = remaining.subspan(length);
  }
  Check(remaining.empty() && application == Bytes({1, 0}) && queued.TakeOutput().empty(),
        "no queued ciphertext follows close_notify");
}

void ClosedWriterFailures() {
  for (int fault = 0; fault < 6; ++fault) {
    ClientOptions options;
    options.post_handshake_auth = true;
    Client client("example.test", {}, true, options);
    Check(client.Start(), "closed-writer error fixture");
    ProtocolRegressionPeer::Prepare(client);
    ProtocolRegressionPeer::AuthenticationMode(client, Authentication::kCertificate);
    Bytes record, application;
    Check(client.RequestKeyUpdate(true, &record) && client.Close(&record) &&
              ProtocolRegressionPeer::WritingSecretsErased(client),
          "write close clears an outstanding local key-update request");
    Bytes invalid = fault == 0 ? Bytes{2, 40, 21} : fault == 1 ? Bytes{22} :
        fault == 2 ? Frame(13, {}) : Frame(24, Bytes{2});
    if (fault >= 2) invalid.push_back(22);
    auto protected_record = Protect(invalid);
    if (fault == 4) protected_record.back() ^= 1;
    const bool accepted = fault == 5 ? client.Send(Bytes{1}, &record)
                                     : client.Receive(protected_record, &application);
    Check(!accepted && application.empty() &&
              client.TakeOutput().empty() && client.TakeFatalAlert().empty() &&
              ProtocolRegressionPeer::SecretsErased(client),
          "peer fatal, malformed PHA/KU, record errors and late writes fail without post-close alerts");
    Check(!client.Receive(protected_record, &application) && client.TakeFatalAlert().empty(),
          "repeated post-close errors cannot emit an alert");
  }
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
        Check(client.Start(), "record-limit test builds the actual extension offer");
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

void FixedExtensionFields() {
  struct Case { uint16_t code; Bytes value; uint8_t alert; };
  const Case cases[] = {
    {0, {}, 0}, {0, {0}, 50},
    {1, {1}, 0}, {1, {}, 50}, {1, {1, 0}, 50}, {1, {5}, 47},
    {15, {1}, 0}, {15, {}, 50}, {15, {1, 0}, 50}, {15, {0}, 47},
    {19, {2}, 0}, {19, {}, 50}, {19, {2, 0}, 50}, {19, {3}, 47},
    {20, {0}, 0}, {20, {}, 50}, {20, {0, 0}, 50}, {20, {3}, 47},
    {28, {0, 64}, 0}, {28, {}, 50}, {28, {0}, 50}, {28, {0, 64, 0}, 50},
    {28, {0, 63}, 47}, {28, {0x40, 2}, 47},
    {42, {}, 0}, {42, {0}, 50},
    {58, {0}, 0}, {58, {255}, 0}, {58, {}, 50}, {58, {1, 0}, 50},
  };
  for (const auto& item : cases) {
    ClientOptions options;
    options.no_alpn_http11 = true;
    if (item.code == 1) options.max_fragment_length = 1;
    if (item.code == 15) options.heartbeat_mode = 1;
    if (item.code == 20) options.server_certificate_types = {0, 2};
    if (item.code == 28) options.record_size_limit = 16385;
    if (item.code == 58) options.ticket_request = TicketRequest{};
    if (item.code == 42) {
      ExternalPSK psk;
      psk.identity = Bytes{0x50};
      psk.secret = Bytes(32, 0x70);
      psk.hostname = "example.test";
      psk.max_early_data = 1024;
      options.external_psks.push_back(psk);
    }
    Client client("example.test", {}, true, options);
    if (item.code == 19) {
      ClientCredential credential;
      credential.certificate_type = 2;
      credential.private_key.fill(0x37);
      Secret public_key;
      X25519_public_from_private(public_key.data(), credential.private_key.data());
      Bytes spki{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0};
      Append(&spki, public_key);
      credential.certificates.emplace_back(spki.begin(), spki.end());
      Check(client.SetClientCredential(credential), "fixed-field fixture has a valid raw client key");
    }
    Check(client.Start(nullptr, {}, item.code == 42), "fixed-field fixture constructs actual CH offer");
    const auto output = client.TakeOutput();
    const auto hello = JoinPlaintextRecords(ByteSpan(output).subspan(kPreface.size()));
    Check(HelloExtensions(hello).count(item.code), "tested EE extension was actually offered");
    ProtocolRegressionPeer::Prepare(client, true);
    if (item.code == 42) ProtocolRegressionPeer::SelectFirstExternalPsk(client);
    Bytes extensions;
    Extension(&extensions, item.code, item.value);
    Bytes frame = Frame(8, Vector16(extensions));
    frame.push_back(22);
    Bytes application;
    Check(client.Receive(Protect(frame), &application) == (item.alert == 0),
          "fixed-width syntax is distinct from an invalid scalar value");
    Check(application.empty(), "EE processing never releases application bytes");
    if (item.alert) CheckAlert(client, item.alert);
    else Check(client.TakeFatalAlert().empty(), "valid fixed-width control has no fatal alert");
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

void TicketSyntaxAlerts() {
  const Bytes prefix{0, 0, 0x0e, 0x10, 0, 0, 0, 0};
  auto ticket = [&](ByteSpan extensions) {
    Bytes body = prefix;
    Append(&body, Bytes{1, 'N', 0, 1, 'T'});
    Append(&body, Vector16(extensions));
    return body;
  };
  std::vector<std::pair<Bytes, uint8_t>> cases{{ticket({}), 0}};
  Bytes unknown;
  Extension(&unknown, 0xfafa, Bytes{1, 2});
  cases.emplace_back(ticket(unknown), 0);
  Bytes early;
  Extension(&early, 42, Bytes(4));
  cases.emplace_back(ticket(early), 0);
  for (const auto& suffix : {Bytes{255, 0, 0, 0, 0, 0, 0, 0},
                            Bytes{1, 'N', 0, 0, 0, 0},
                            Bytes{1, 'N', 1, 0, 'T', 0, 0}}) {
    auto body = prefix;
    Append(&body, suffix);
    cases.emplace_back(std::move(body), 50);
  }
  for (size_t size : {0u, 1u, 3u, 5u}) {
    Bytes malformed;
    Extension(&malformed, 42, Bytes(size));
    cases.emplace_back(ticket(malformed), 50);
  }
  for (const auto& [body, alert] : cases) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::PrepareTicket(client);
    Bytes plaintext = Frame(4, body);
    plaintext.push_back(22);
    Bytes application;
    Check(client.Receive(Protect(plaintext), &application) == (alert == 0),
          "ticket syntax rejection versus well-formed extensible ticket");
    Check(application.empty(), "tickets never release application bytes");
    if (alert) {
      CheckAlert(client, alert);
      Check(ProtocolRegressionPeer::SecretsErased(client),
            "ticket parse failure erases connection-owned secrets and tickets");
      Check(client.TakeTickets().empty(), "malformed tickets cannot reach the session cache");
    } else {
      Check(client.TakeTickets().size() == 1 && client.established(),
            "well-formed ticket is retained without ending the connection");
      Check(client.TakeFatalAlert().empty(), "valid ticket has no fatal alert");
    }
  }
}

void CertificateAlertOverrides() {
  for (bool explicit_alert : {false, true}) {
    Client client("example.test", {}, true);
    ProtocolRegressionPeer::Prepare(client);
    Check(!ProtocolRegressionPeer::CertificateFailure(client, explicit_alert) &&
              client.error() == Client::Error::kCertificate,
          "wire alert override preserves the local certificate-error classification");
    CheckAlert(client, explicit_alert ? 47 : 42);
    Check(ProtocolRegressionPeer::SecretsErased(client),
          "both certificate alert paths erase connection secrets");
  }
}
}  // namespace

// The loopback negative-chain driver verifies the locally generated fatal alert
// before closing its TCP socket. Never expose this test helper in production.
net::httpps::Bytes HandshakeSendingSecretForTest(const net::httpps::Client& client) {
  return net::httpps::ProtocolRegressionPeer::HandshakeSendingSecret(client);
}

// Called only by the explicit-provider test runner. This uses the production
// ServerHello parser/key schedule, not a synthetic destructor-only fixture.
void RunNativeStageLifecycleTests(const std::shared_ptr<net::httpps::NativeProvider>& provider) {
  for (uint16_t group : {30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41}) {
    if (!provider->SupportsGroup(group)) continue;
    // Valid agreement, invalid peer share, and a PSK-only selection that makes
    // the previously generated traffic scalar unnecessary without using it.
    for (int path : {0, 1, 2}) {
      const bool valid = path != 1;
      const bool psk_only = path == 2;
      ClientOptions options;
      options.native_provider = provider;
      options.groups = {group};
      options.cipher_suites = {static_cast<uint16_t>(group == 41 ? 0x00c6 :
          group >= 34 && group <= 40 ? 0xc103 : 0x1301)};
      if (psk_only) {
        ExternalPSK psk;
        psk.identity = Bytes{1}; psk.secret = Bytes(32, 7);
        psk.hostname = "example.test";
        psk.cipher_suite = options.cipher_suites.front();
        options.external_psks = {psk};
        options.psk_modes = {0, 1};
      }
      Client client("example.test", {}, true, options);
      Check(client.Start() && ProtocolRegressionPeer::HasNativeTrafficKey(client),
            "provider traffic scalar exists while awaiting ServerHello");
      client.TakeOutput();
      Bytes public_key;
      auto peer_key = provider->Generate(group, &public_key);
      Check(peer_key != nullptr, "independent peer traffic key");
      if (!valid) std::fill(public_key.begin(), public_key.end(), 0);
      Bytes body{3, 3};
      Append(&body, Bytes(32, 0x53));
      body.push_back(0);
      U16(&body, options.cipher_suites.front());
      body.push_back(0);
      Bytes extensions, share;
      U16(&share, group);
      Append(&share, Vector16(public_key));
      Extension(&extensions, 43, Bytes{4, 0});
      if (psk_only)
        Extension(&extensions, 41, Bytes{0, 0});
      else
        Extension(&extensions, 51, share);
      Append(&body, Vector16(extensions));
      Check(ReceivePlaintextHandshake(client, Frame(2, body)) == valid,
            "provider ServerHello accepts valid and rejects invalid shared secrets");
      Check(!ProtocolRegressionPeer::HasNativeTrafficKey(client),
            "provider private scalar ends at agreement or failure, before EE");
      if (valid)
        Check(ProtocolRegressionPeer::HasHandshakeSecrets(client),
              "retiring private scalar preserves the derived handshake keys");
      else
        Check(ProtocolRegressionPeer::SecretsErased(client),
              "invalid provider agreement erases all connection secrets");
    }
  }
}

void RunProtocolRegressionTests() {
  RecordAlerts();
  RecordFramingAlerts();
  UnexpectedMessageAlerts();
  VersionAlerts();
  HelloResponseOffers();
  HelloResponseSyntax();
  HelloSessionSyntax();
  RetryGroups();
  RetryCookieBounds();
  RetryTicketAges();
  FragmentInterleaving();
  FailedSecretErasure();
  HandshakeFailureLifecycle();
  HalfCloseKeepsOppositeDirection();
  ClosedWriterControlMessages();
  ClosedWriterFailures();
  CertificateResponseOffers();
  CertificateRequestValidation();
  DelegationRequestDuplicates();
  OidFilterRequestValidation();
  CertificateTransparencyRequestSyntax();
  PskHelloGroupSharePair();
  AuthenticatorServerNameValidation();
  KeyUpdates();
  RequestedKeyUpdatePreservesResponse();
  PostHandshakeAuthentication();
  RetrospectiveLimits();
  FixedExtensionFields();
  HeartbeatLimits();
  TicketSyntaxAlerts();
  CertificateAlertOverrides();
  std::cout << "Protocol alert, key-update, PHA, record-limit and heartbeat regressions passed\n";
}
