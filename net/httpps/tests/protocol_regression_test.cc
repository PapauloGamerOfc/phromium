// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Deterministic state/record tests for boundaries that successful connections
// do not exercise. Secrets below are public test-only traffic-key fixtures.
#include "net/httpps/draft01.h"

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
  static void AwaitVerification(Client& client) {
    client.state_ = Client::State::kVerifyingCertificate;
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

Bytes CookieRetry() {
  Bytes body{3, 3};
  Append(&body, Bytes{0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,
      0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
      0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,
      0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c});
  Append(&body, Bytes{0, 0x13, 1, 0});
  Bytes extensions;
  Extension(&extensions, 43, Bytes{4, 0});
  Extension(&extensions, 44, Bytes{0, 1, 7});
  Append(&body, Vector16(extensions));
  return Frame(2, body);
}

Bytes HelloPsk(ByteSpan hello) {
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
  while (cursor + 4 <= hello.size()) {
    const auto type = read16(cursor), length = read16(cursor + 2);
    cursor += 4;
    Check(cursor + length <= hello.size(), "ClientHello extension length");
    if (type == 41) {
      Check(cursor + length == hello.size(), "PSK is last after retry cookie");
      return Bytes(hello.begin() + cursor, hello.begin() + cursor + length);
    }
    cursor += length;
  }
  Check(false, "ClientHello offers PSK");
  return {};
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

  Client outgoing_close("example.test", {}, true);
  ProtocolRegressionPeer::Prepare(outgoing_close);
  Check(outgoing_close.Close(&record) && !outgoing_close.closed(),
        "local close leaves the peer read direction open");
  Check(outgoing_close.Receive(Protect(Bytes{9, 23}), &application) && application == Bytes{9},
        "local close retains receiving keys until authenticated peer closure");
  Check(outgoing_close.Receive(Protect(Bytes{1, 0, 21}, 1), &application) &&
            outgoing_close.closed() && outgoing_close.TakeFatalAlert().empty(),
        "orderly bidirectional close does not become a failure");
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
  RetryTicketAges();
  FragmentInterleaving();
  FailedSecretErasure();
  HandshakeFailureLifecycle();
  HalfCloseKeepsOppositeDirection();
  KeyUpdates();
  PostHandshakeAuthentication();
  RetrospectiveLimits();
  HeartbeatLimits();
  std::cout << "Protocol alert, key-update, PHA, record-limit and heartbeat regressions passed\n";
}
