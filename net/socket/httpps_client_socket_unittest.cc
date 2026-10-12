// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/httpps_client_socket.h"

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "base/time/time_override.h"
#include "net/base/address_list.h"
#include "net/base/auth.h"
#include "net/base/ip_address.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_cache.h"
#include "net/http/http_auth_controller.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_proxy_client_socket.h"
#include "net/http/http_response_headers.h"
#include "net/http/transport_security_state.h"
#include "net/httpps/transparency.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/socks5_client_socket.h"
#include "net/ssl/ssl_config.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/test/cert_builder.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#include "third_party/boringssl/src/pki/parse_certificate.h"
#include "url/gurl.h"

namespace net {
namespace {

using httpps::Bytes;
using httpps::ByteSpan;
using httpps::Secret;

void Append(Bytes& out, ByteSpan bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}
ByteSpan Octets(std::string_view input) {
  return httpps::StringBytes(input);
}
void U24(Bytes& out, size_t length) {
  out.push_back(static_cast<uint8_t>(length >> 16));
  out.push_back(static_cast<uint8_t>(length >> 8));
  out.push_back(static_cast<uint8_t>(length));
}
void U16(Bytes& out, size_t length) {
  out.push_back(static_cast<uint8_t>(length >> 8));
  out.push_back(static_cast<uint8_t>(length));
}
void U64(Bytes& out, uint64_t value) {
  for (size_t i = 8; i; --i) {
    out.push_back(static_cast<uint8_t>(value >> ((i - 1) * 8)));
  }
}
Bytes HelloExtension(ByteSpan hello, uint16_t wanted, bool* found = nullptr) {
  if (found) {
    *found = false;
  }
  size_t offset = 39 + hello[38];
  offset += 2 + (size_t(hello[offset]) << 8) + hello[offset + 1];
  offset += 1 + hello[offset];
  auto extensions = hello.subspan(offset + 2);
  while (extensions.size() >= 4) {
    uint16_t type = (extensions[0] << 8) | extensions[1];
    size_t length = (extensions[2] << 8) | extensions[3];
    if (length > extensions.size() - 4) {
      return {};
    }
    if (type == wanted) {
      if (found) {
        *found = true;
      }
      auto value = extensions.subspan(4u, length);
      return Bytes(value.begin(), value.end());
    }
    extensions = extensions.subspan(4 + length);
  }
  return {};
}
Bytes Frame(uint8_t type, ByteSpan body) {
  Bytes output{type};
  U24(output, body.size());
  Append(output, body);
  return output;
}

// A scripted peer which derives its own server-side keys from the client's
// fresh CH. This exercises partial asynchronous transport I/O, not just the
// portable crypto engine. Test keys never leave this in-memory mock.
class Peer : public SocketDataProvider {
 public:
  explicit Peer(uint8_t key_offset = 0) {
    set_connect_data(MockConnect(SYNCHRONOUS, OK));
    chain_ = CertBuilder::CreateSimpleChain2();
    // The private-CA verifier uses BoringSSL's system wall clock, not the
    // TaskEnvironment clock. Keep the certificates valid on that clock while
    // retaining MOCK_TIME for handshake deadlines and asynchronous I/O tests.
    const base::Time now = base::subtle::TimeNowIgnoringOverride();
    for (const auto& certificate : chain_) {
      certificate->SetValidity(now - base::Days(7), now + base::Days(7));
    }
    for (size_t i = 0; i < static_private_.size(); ++i) {
      static_private_[i] = static_cast<uint8_t>(i + 1 + key_offset);
    }
    chain_[0]->SetKey(bssl::UniquePtr<EVP_PKEY>(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, static_private_.data(),
        static_private_.size())));
    chain_[0]->SetSubjectAltName("localhost");
    chain_[0]->SetBasicConstraints(false, -1);
    chain_[0]->SetKeyUsages({bssl::KEY_USAGE_BIT_KEY_AGREEMENT});
    // The default test leaf already carries serverAuth EKU.
    root = chain_[1]->GetDER();
    Secret verified_key;
    EXPECT_TRUE(httpps::VerifyLabChain({chain_[0]->GetDER()}, {root},
                                       "localhost", &verified_key));
  }

  MockRead OnRead() override {
    if (stall || server_bytes_.empty()) {
      return MockRead(ASYNC, eof ? 0 : ERR_IO_PENDING);
    }
    server_flight_read_ = true;
    read_storage_ = server_bytes_.substr(0, read_chunk);
    server_bytes_.erase(0, read_storage_.size());
    return MockRead(mode, std::string_view(read_storage_));
  }

  MockWriteResult OnWrite(const std::string& bytes) override {
    if (fail_writes) {
      return MockWriteResult(SYNCHRONOUS, ERR_CONNECTION_RESET);
    }
    if (hold_writes) {
      held_write_ = bytes;
      return MockWriteResult(ASYNC, ERR_IO_PENDING);
    }
    size_t length = std::min(write_chunk, bytes.size());
    input_.insert(input_.end(), bytes.begin(), bytes.begin() + length);
    if (hello_) {
      constexpr size_t prefix = httpps::kPreface.size();
      if (input_.size() >= prefix + 5) {
        size_t frame_length =
            (size_t(input_[prefix + 3]) << 8) | input_[prefix + 4];
        if (input_.size() >= prefix + 5 + frame_length) {
          BuildFlight(ByteSpan(input_).subspan(prefix + 5, frame_length));
          input_.erase(input_.begin(),
                       input_.begin() + prefix + 5 + frame_length);
          hello_ = false;
        }
      }
    }
    while (!hello_ && input_.size() >= 5) {
      size_t record_length = 5 + (size_t(input_[3]) << 8) + input_[4];
      if (input_.size() < record_length) {
        break;
      }
      ConsumeRecord(ByteSpan(input_).first(record_length));
      input_.erase(input_.begin(), input_.begin() + record_length);
    }
    return MockWriteResult(mode, static_cast<int>(length));
  }

  bool AllReadDataConsumed() const override { return server_bytes_.empty(); }
  bool AllWriteDataConsumed() const override { return input_.empty(); }

  void Application(std::string_view data, bool close = false) {
    Bytes encrypted;
    ASSERT_TRUE(sender_->Seal(Octets(data), 23, &encrypted));
    server_bytes_.append(encrypted.begin(), encrypted.end());
    if (close) {
      ASSERT_TRUE(sender_->Seal(std::array<uint8_t, 2>{1, 0}, 21, &encrypted));
      server_bytes_.append(encrypted.begin(), encrypted.end());
    }
  }

  void RequestClientAuth(uint8_t context = 1, ByteSpan extra = {}) {
    Secret private_key{}, public_key{};
    X25519_keypair(public_key.data(), private_key.data());
    Bytes extensions{0, 50, 0, 4, 0, 2, 8, 7, 0xff, 3, 0, 32};
    Append(extensions, public_key);
    Append(extensions, extra);
    Bytes body{1, context};
    U16(body, extensions.size());
    Append(body, extensions);
    const auto request = Frame(13, body);
    pha_context_ = context;
    pha_transcript_ = transcript_;
    Append(pha_transcript_, request);
    Bytes encrypted;
    ASSERT_TRUE(sender_->Seal(request, 22, &encrypted));
    server_bytes_.append(encrypted.begin(), encrypted.end());
  }

  void Alert(uint8_t description) {
    Bytes encrypted;
    ASSERT_TRUE(sender_->Seal(Bytes{1, description}, 21, &encrypted));
    server_bytes_.append(encrypted.begin(), encrypted.end());
  }

  void RawRecord(ByteSpan record) {
    server_bytes_.append(record.begin(), record.end());
  }

  void NewTicket() {
    // lifetime=3600, age_add=0, one-byte nonce/ticket, no extensions.
    const Bytes body{0, 0, 14, 16, 0, 0, 0, 0, 1, 7, 0, 1, 9, 0, 0};
    Bytes encrypted;
    ASSERT_TRUE(sender_->Seal(Frame(4, body), 22, &encrypted));
    server_bytes_.append(encrypted.begin(), encrypted.end());
  }

  void KeyUpdate(bool request_peer = true) {
    Bytes encrypted;
    const auto update = Frame(24, Bytes{static_cast<uint8_t>(request_peer)});
    ASSERT_TRUE(sender_->Seal(update, 22, &encrypted));
    server_bytes_.append(encrypted.begin(), encrypted.end());
    s_app_ = httpps::Label(s_app_, "traffic upd", {}, 32);
    sender_ = std::make_unique<httpps::RecordCipher>(s_app_);
  }

  void FragmentedKeyUpdate(std::optional<uint8_t> interleaved_alert) {
    const auto update = Frame(24, Bytes{0});
    Bytes encrypted;
    ASSERT_TRUE(sender_->Seal(ByteSpan(update).first(2u), 22, &encrypted));
    server_bytes_.append(encrypted.begin(), encrypted.end());
    if (interleaved_alert) {
      Alert(*interleaved_alert);
    }
    ASSERT_TRUE(sender_->Seal(ByteSpan(update).subspan(2u), 22, &encrypted));
    server_bytes_.append(encrypted.begin(), encrypted.end());
    s_app_ = httpps::Label(s_app_, "traffic upd", {}, 32);
    sender_ = std::make_unique<httpps::RecordCipher>(s_app_);
  }

  void ReleaseWrite() {
    ASSERT_FALSE(held_write_.empty());
    hold_writes = false;
    auto written = OnWrite(std::exchange(held_write_, {}));
    socket()->OnWriteComplete(written.result);
  }

  void CertificateFeatures(const Bytes& value) {
    static constexpr uint8_t kOid[] = {0x2b, 6, 1, 5, 5, 7, 1, 24};
    chain_[0]->SetExtension(bssl::der::Input(kOid),
                           std::string(value.begin(), value.end()));
  }

  std::shared_ptr<httpps::CTv2Policy> TransparencyPolicy() {
    auto policy = std::make_shared<httpps::CTv2Policy>();
    std::array<uint8_t, 32> public_key{};
    std::array<uint8_t, 64> private_key{};
    ED25519_keypair(public_key.data(), private_key.data());
    httpps::CTLog log;
    log.id = {0x2b, 6, 1, 4, 1, 0x82, 0x37};
    log.signature_scheme = 0x0807;
    log.public_key_spki = {0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 3, 0x21, 0};
    Append(log.public_key_spki, public_key);
    const std::string leaf = chain_[0]->GetDER();
    const auto leaf_bytes = Octets(leaf);
    const auto* cursor = leaf_bytes.data();
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &cursor, leaf_bytes.size()));
    EXPECT_TRUE(cert);
    if (!cert) return policy;
    int length = i2d_re_X509_tbs(cert.get(), nullptr);
    EXPECT_GT(length, 0);
    if (length <= 0) return policy;
    Bytes tbs(length);
    auto* output = tbs.data();
    EXPECT_EQ(length, i2d_re_X509_tbs(cert.get(), &output));
    length = i2d_PUBKEY(chain_[1]->GetKey(), nullptr);
    EXPECT_GT(length, 0);
    if (length <= 0) return policy;
    Bytes issuer_spki(length);
    output = issuer_spki.data();
    EXPECT_EQ(length, i2d_PUBKEY(chain_[1]->GetKey(), &output));
    const uint64_t timestamp = static_cast<uint64_t>(
        base::subtle::TimeNowIgnoringOverride().InMillisecondsSinceUnixEpoch());
    Bytes signed_entry{1, 0};
    U64(signed_entry, timestamp);
    signed_entry.push_back(32);
    Append(signed_entry, httpps::Hash(issuer_spki));
    U24(signed_entry, tbs.size());
    Append(signed_entry, tbs);
    U16(signed_entry, 0);
    std::array<uint8_t, 64> signature{};
    EXPECT_TRUE(ED25519_sign(signature.data(), signed_entry.data(),
                             signed_entry.size(), private_key.data()));
    Bytes sct{1, 2, static_cast<uint8_t>(log.id.size())};
    Append(sct, log.id);
    U64(sct, timestamp);
    U16(sct, 0);
    U16(sct, signature.size());
    Append(sct, signature);
    Bytes list;
    U16(list, sct.size() + 2);
    U16(list, sct.size());
    Append(list, sct);
    leaf_extensions[52] = std::move(list);
    policy->logs.push_back(std::move(log));
    EXPECT_TRUE(policy->IsValid());
    return policy;
  }

  bool stall = false;
  bool eof = false;
  bool hold_writes = false;
  bool fail_writes = false;
  bool tamper = false;
  bool bad_proof = false;
  bool accept_early_data = true;
  bool reject_ticket = false;
  bool omit_alpn = false;
  bool send_initial_cr = false;
  bool client_offered_alpn = false;
  bool client_offered_pha = false;
  bool client_offered_pinning = false;
  Bytes client_pin;
  std::optional<Bytes> pin_response;
  Bytes initial_cr_extra;
  Bytes encrypted_extensions_extra;
  Bytes hello_response_extra;
  bool hello_retry = false;
  uint8_t last_client_alert = 0;
  std::optional<httpps::SessionTicket> resume_ticket;
  IoMode mode = ASYNC;
  size_t read_chunk = 1;
  size_t write_chunk = 7;
  std::string root;
  std::string received_application;
  std::string received_early;
  std::string application_after_finished;
  size_t discarded_early_bytes = 0;
  int client_hellos = 0;
  int client_finished = 0;
  int initial_empty_certificates = 0;
  int end_of_early_data = 0;
  int pha_empty_certificates = 0;
  int pha_finished = 0;
  int key_updates = 0;
  int close_notifies = 0;
  std::map<uint16_t, Bytes> leaf_extensions;
  bool requested_ocsp = false;
  bool requested_scts = false;
  bool requested_ct_v2 = false;

  httpps::SessionTicket Ticket() {
    httpps::SessionTicket ticket;
    ticket.identity = {0x71, 0x72, 0x73, 0x74};
    std::fill(ticket.psk.begin(), ticket.psk.end(), 0x37);
    ticket.lifetime = 3600;
    ticket.age_add = 123;
    ticket.max_early_data = 4096;
    ticket.received_milliseconds = httpps::MonotonicMilliseconds();
    ticket.hostname = "localhost";
    ticket.certificates = {chain_[0]->GetDER()};
    ticket.certificate_extensions = {leaf_extensions};
    return ticket;
  }

  scoped_refptr<X509Certificate> certificate() {
    return chain_[0]->GetX509Certificate();
  }

 protected:
  virtual void OnApplication(std::string_view plaintext) {}

  void Reset() override {
    // SocketDataProvider calls this when a socket is attached. Preserve the
    // test's configured fault/fragmentation settings, but never reuse a prior
    // connection's transcript, record counters or traffic keys.
    sender_.reset();
    receiver_.reset();
    early_receiver_.reset();
    root_secret_.fill(0);
    c_hs_.fill(0);
    input_.clear();
    transcript_.clear();
    read_storage_.clear();
    server_bytes_.clear();
    held_write_.clear();
    received_application.clear();
    received_early.clear();
    discarded_early_bytes = 0;
    client_hellos = 0;
    last_client_alert = 0;
    client_finished = 0;
    initial_empty_certificates = 0;
    end_of_early_data = 0;
    pha_empty_certificates = pha_finished = key_updates = close_notifies = 0;
    pha_transcript_.clear();
    pha_input_.clear();
    early_offered_ = early_accepted_ = server_flight_read_ = false;
    hello_ = true;
    finished_ = true;
  }

 private:
  void ConsumeRecord(ByteSpan record) {
    Bytes plaintext;
    uint8_t type = 0;
    if (record[0] == 21) {
      ASSERT_EQ(record.size(), 7u);
      EXPECT_EQ(record[5], 2);
      last_client_alert = record[6];
      return;
    }
    // This peer's resumed Connect returns after CH, before any server flight
    // read. Rejected early bytes may arrive only before the client reads SH.
    const bool early_epoch =
        finished_ && early_receiver_ &&
        (early_accepted_ ? end_of_early_data == 0 : !server_flight_read_);
    if (early_epoch) {
      ASSERT_TRUE(early_receiver_->Open(record, &type, &plaintext));
      if (type == 22) {
        ASSERT_TRUE(early_accepted_);
        EXPECT_EQ(plaintext, Frame(5, {}));
        Append(transcript_, plaintext);
        ++end_of_early_data;
      } else {
        ASSERT_EQ(type, 23);
        if (early_accepted_) {
          received_early.append(plaintext.begin(), plaintext.end());
        } else {
          discarded_early_bytes += plaintext.size();
        }
      }
      return;
    }
    ASSERT_TRUE(receiver_->Open(record, &type, &plaintext));
    if (type == 21 && plaintext.size() == 2 && plaintext[0] == 2) {
      last_client_alert = plaintext[1];
      return;
    }
    if (finished_) {
      ASSERT_EQ(type, 22);
      if (send_initial_cr && !plaintext.empty() && plaintext[0] == 11) {
        EXPECT_EQ(plaintext, Frame(11, Bytes{0, 0, 0, 0}));
        EXPECT_EQ(initial_empty_certificates, 0);
        Append(transcript_, plaintext);
        ++initial_empty_certificates;
        return;
      }
      auto expected = httpps::Mac(httpps::Label(c_hs_, "finished", {}, 32),
                                  httpps::Hash(transcript_));
      EXPECT_EQ(plaintext, Frame(20, expected));
      Append(transcript_, plaintext);
      sender_ = std::make_unique<httpps::RecordCipher>(s_app_);
      receiver_ = std::make_unique<httpps::RecordCipher>(c_app_);
      finished_ = false;
      ++client_finished;
      if (!application_after_finished.empty()) {
        Application(application_after_finished);
      }
    } else if (type == 23) {
      received_application.append(plaintext.begin(), plaintext.end());
      OnApplication(std::string_view(
          reinterpret_cast<const char*>(plaintext.data()), plaintext.size()));
    } else if (type == 21) {
      EXPECT_EQ(plaintext, (Bytes{1, 0}));
      ++close_notifies;
    } else if (type == 22) {
      Append(pha_input_, plaintext);
      while (pha_input_.size() >= 4) {
        const size_t size = 4 + (size_t(pha_input_[1]) << 16) +
                            (size_t(pha_input_[2]) << 8) + pha_input_[3];
        if (size > pha_input_.size())
          break;
        Bytes frame(pha_input_.begin(), pha_input_.begin() + size);
        pha_input_.erase(pha_input_.begin(), pha_input_.begin() + size);
        if (frame[0] == 24) {
          EXPECT_EQ(frame, Frame(24, Bytes{0}));
          c_app_ = httpps::Label(c_app_, "traffic upd", {}, 32);
          receiver_ = std::make_unique<httpps::RecordCipher>(c_app_);
          ++key_updates;
        } else if (frame[0] == 11) {
          EXPECT_EQ(frame, Frame(11, Bytes{1, pha_context_, 0, 0, 0}));
          Append(pha_transcript_, frame);
          ++pha_empty_certificates;
        } else if (frame[0] == 20) {
          const auto expected = httpps::Mac(
              httpps::Label(c_app_, "finished", {}, 32),
              httpps::Hash(pha_transcript_));
          EXPECT_EQ(frame, Frame(20, expected));
          ++pha_finished;
        } else {
          ADD_FAILURE() << "Unexpected post-handshake client message "
                        << static_cast<int>(frame[0]);
        }
      }
    }
  }

  void BuildFlight(ByteSpan hello) {
    ++client_hellos;
    Secret ephemeral_private{}, ephemeral_public{}, shared{};
    X25519_keypair(ephemeral_public.data(), ephemeral_private.data());
    auto key_share = HelloExtension(hello, 51);
    auto auth_share = HelloExtension(hello, 0xff02);
    const auto status_request = HelloExtension(hello, 5, &requested_ocsp);
    const auto sct_request = HelloExtension(hello, 18, &requested_scts);
    const auto ct_request = HelloExtension(hello, 52, &requested_ct_v2);
    EXPECT_TRUE(ct_request.empty());
    if (requested_ocsp)
      EXPECT_EQ(status_request, (Bytes{1, 0, 0, 0, 0}));
    if (requested_scts)
      EXPECT_TRUE(sct_request.empty());
    ASSERT_EQ(key_share.size(), 38u);
    ASSERT_EQ(auth_share.size(), 32u);
    ASSERT_TRUE(X25519(shared.data(), ephemeral_private.data(),
                       ByteSpan(key_share).subspan(6u).data()));
    auto psk_extension = HelloExtension(hello, 41);
    HelloExtension(hello, 42, &early_offered_);
    const bool resumed =
        resume_ticket && !psk_extension.empty() && !reject_ticket;
    early_accepted_ = resumed && early_offered_ && accept_early_data;
    if (resume_ticket && !psk_extension.empty()) {
      ASSERT_GT(hello.size(), 35u);
      Bytes binder_transcript;
      Append(binder_transcript, Octets(httpps::kPreface));
      Append(binder_transcript, hello.first(hello.size() - 35));
      auto binder_key = httpps::Label(httpps::Mac(Secret{}, resume_ticket->psk),
                                      "res binder", httpps::Hash({}), 32);
      auto binder = httpps::Mac(httpps::Label(binder_key, "finished", {}, 32),
                                httpps::Hash(binder_transcript));
      EXPECT_TRUE(std::equal(binder.begin(), binder.end(), hello.end() - 32));
      if (early_offered_) {
        Bytes early_transcript;
        Append(early_transcript, Octets(httpps::kPreface));
        Append(early_transcript, hello);
        early_receiver_ = std::make_unique<httpps::RecordCipher>(
            httpps::Label(httpps::Mac(Secret{}, resume_ticket->psk),
                          "c e traffic", httpps::Hash(early_transcript), 32));
      }
    }
    auto early = httpps::Mac(Secret{}, resumed ? resume_ticket->psk : Bytes(32));
    root_secret_ = httpps::Mac(
        httpps::Label(early, "derived", httpps::Hash({}), 32), shared);
    Bytes body(38);
    body[0] = body[1] = 3;
    body[35] = 0x13;
    body[36] = 1;
    Bytes extensions_body{0, 43, 0, 2, 4, 0, 0, 51, 0, 36, 0, 29, 0, 32};
    Append(extensions_body, ephemeral_public);
    if (resumed) {
      extensions_body.insert(extensions_body.end(), {0, 41, 0, 2, 0, 0});
    }
    if (hello_retry) {
      const Bytes random{0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,
          0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
          0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,
          0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
      std::copy(random.begin(), random.end(), body.begin() + 2);
      extensions_body = {0, 43, 0, 2, 4, 0, 0, 44, 0, 3, 0, 1, 7};
    }
    Append(extensions_body, hello_response_extra);
    U16(body, extensions_body.size());
    Append(body, extensions_body);
    Bytes server_hello = Frame(2, body);
    Append(transcript_, Octets(httpps::kPreface));
    Append(transcript_, hello);
    Append(transcript_, server_hello);
    auto client_secret = httpps::Label(root_secret_, "c hs traffic",
                                       httpps::Hash(transcript_), 32);
    std::copy(client_secret.begin(), client_secret.end(), c_hs_.begin());
    auto server_secret = httpps::Label(root_secret_, "s hs traffic",
                                       httpps::Hash(transcript_), 32);
    receiver_ = std::make_unique<httpps::RecordCipher>(client_secret);
    sender_ = std::make_unique<httpps::RecordCipher>(server_secret);
    Bytes wire{22, 3, 3, 0, static_cast<uint8_t>(server_hello.size())};
    Append(wire, server_hello);
    server_bytes_.append(wire.begin(), wire.end());
    if (hello_retry)
      return;  // This fixture exercises rejection before a second ClientHello.

    Bytes extensions = {0, 19, 0,   0,   0,   0,   0,   16,  0,   11, 0,
                        9, 8,  'h', 't', 't', 'p', '/', '1', '.', '1'};
    HelloExtension(hello, 16, &client_offered_alpn);
    HelloExtension(hello, 49, &client_offered_pha);
    client_pin = HelloExtension(hello, 32, &client_offered_pinning);
    if (omit_alpn) extensions = {0, 4, 0, 0, 0, 0};
    if (pin_response) {
      const size_t size = extensions.size() - 2 + 4 + pin_response->size();
      extensions[0] = static_cast<uint8_t>(size >> 8);
      extensions[1] = static_cast<uint8_t>(size);
      U16(extensions, 32);
      U16(extensions, pin_response->size());
      Append(extensions, *pin_response);
    }
    if (early_accepted_) {
      extensions[1] += 4;
      extensions.insert(extensions.end(), {0, 42, 0, 0});
    }
    Append(extensions, encrypted_extensions_extra);
    extensions[0] = static_cast<uint8_t>((extensions.size() - 2) >> 8);
    extensions[1] = static_cast<uint8_t>(extensions.size() - 2);
    Bytes flight = Frame(8, extensions);
    Append(transcript_, flight);
    if (!resumed) {
      if (send_initial_cr) {
        Secret verifier_private{}, verifier_public{};
        X25519_keypair(verifier_public.data(), verifier_private.data());
        Bytes offered{0, 50, 0, 4, 0, 2, 8, 7, 0xff, 3, 0, 32};
        Append(offered, verifier_public);
        Append(offered, initial_cr_extra);
        Bytes request{0};
        U16(request, offered.size());
        Append(request, offered);
        const auto frame = Frame(13, request);
        Append(transcript_, frame);
        Append(flight, frame);
      }
      std::string certificate = chain_[0]->GetDER();
      Bytes entry;
      U24(entry, certificate.size());
      Append(entry, Octets(certificate));
      Bytes metadata;
      for (const auto& [type, value] : leaf_extensions) {
        U16(metadata, type);
        U16(metadata, value.size());
        Append(metadata, value);
      }
      U16(entry, metadata.size());
      Append(entry, metadata);
      Bytes cert_body{0};
      U24(cert_body, entry.size());
      Append(cert_body, entry);
      auto cert_frame = Frame(11, cert_body);
      Append(transcript_, cert_frame);
      Append(flight, cert_frame);
      ASSERT_TRUE(
          X25519(shared.data(), static_private_.data(), auth_share.data()));
      auto salt = httpps::Label(root_secret_, "auth salt",
                                httpps::Hash(transcript_), 32);
      auto auth_root = httpps::Mac(salt, shared);
      auto proof_key = httpps::Label(auth_root, "server mac", {}, 32);
      Bytes proof_context(64, 0x20);
      Append(proof_context, Octets("TLS 2.0, server CertificateVerify"));
      proof_context.push_back(0);
      Append(proof_context, httpps::Hash(transcript_));
      Bytes proof_body{0xfe, 0, 0, 32};
      Append(proof_body, httpps::Mac(proof_key, proof_context));
      if (bad_proof) proof_body.back() ^= 1;
      auto proof = Frame(15, proof_body);
      Append(transcript_, proof);
      Append(flight, proof);
    }
    auto finished =
        Frame(20, httpps::Mac(httpps::Label(server_secret, "finished", {}, 32),
                              httpps::Hash(transcript_)));
    Append(transcript_, finished);
    Append(flight, finished);
    auto master = httpps::Mac(
        httpps::Label(root_secret_, "derived", httpps::Hash({}), 32), Secret{});
    c_app_ =
        httpps::Label(master, "c ap traffic", httpps::Hash(transcript_), 32);
    s_app_ =
        httpps::Label(master, "s ap traffic", httpps::Hash(transcript_), 32);
    ASSERT_TRUE(sender_->Seal(flight, 22, &wire));
    if (tamper) {
      wire.back() ^= 1;
    }
    server_bytes_.append(wire.begin(), wire.end());
  }

  std::array<std::unique_ptr<CertBuilder>, 2> chain_;
  Secret static_private_{}, root_secret_{}, c_hs_{};
  Bytes c_app_, s_app_;
  Bytes input_, transcript_;
  Bytes pha_input_, pha_transcript_;
  uint8_t pha_context_ = 0;
  bool hello_ = true;
  bool finished_ = true;
  bool early_offered_ = false;
  bool early_accepted_ = false;
  bool server_flight_read_ = false;
  std::string read_storage_, server_bytes_, held_write_;
  std::unique_ptr<httpps::RecordCipher> sender_, receiver_;
  std::unique_ptr<httpps::RecordCipher> early_receiver_;
};

// The underlying TCP peer first acts as a proxy, then forwards opaque bytes to
// Peer. The real Chromium proxy sockets must finish their tunnel negotiation
// before HttppsClientSocket can emit a ClientHello or any HTTP application
// data.
class TunnelPeer : public Peer {
 public:
  enum class Kind { kHttp, kSocks5 };

  explicit TunnelPeer(Kind kind) : kind_(kind) {}

  MockRead OnRead() override {
    if (close_before_response) {
      return MockRead(ASYNC, 0);
    }
    if (!response_.empty()) {
      proxy_read_storage_ = response_.substr(0, read_chunk);
      response_.erase(0, proxy_read_storage_.size());
      return MockRead(mode, std::string_view(proxy_read_storage_));
    }
    if (stage_ != 2) {
      return MockRead(ASYNC, ERR_IO_PENDING);
    }
    return Peer::OnRead();
  }

  MockWriteResult OnWrite(const std::string& bytes) override {
    if (stage_ == 2) {
      ++tunneled_writes;
      return Peer::OnWrite(bytes);
    }
    size_t length = std::min(write_chunk, bytes.size());
    request_.append(bytes.data(), length);
    if (kind_ == Kind::kHttp && request_.ends_with("\r\n\r\n")) {
      requests.push_back(request_);
      EXPECT_TRUE(request_.starts_with("CONNECT localhost:343 HTTP/1.1\r\n"));
      EXPECT_NE(std::string::npos,
                request_.find("\r\nHost: localhost:343\r\n"));
      request_.clear();
      response_ = http_response;
      if (response_.starts_with("HTTP/1.1 200 ")) {
        stage_ = 2;
      }
    } else if (kind_ == Kind::kSocks5 && stage_ == 0 && request_.size() == 3) {
      EXPECT_EQ(std::string("\x05\x01\x00", 3), request_);
      requests.push_back(request_);
      request_.clear();
      response_.assign("\x05\x00", 2);
      stage_ = 1;
    } else if (kind_ == Kind::kSocks5 && stage_ == 1 && request_.size() == 16) {
      // SOCKS5 forwards the hostname to the proxy, including the experimental
      // default port 343 (0x0157), instead of resolving the origin locally.
      EXPECT_EQ(std::string("\x05\x01\x00\x03\x09localhost\x01\x57", 16),
                request_);
      requests.push_back(request_);
      request_.clear();
      response_.assign("\x05\x00\x00\x01\x7f\x00\x00\x01\x01\x57", 10);
      response_[1] = socks_reply;
      stage_ = socks_reply == 0 ? 2 : 3;
    }
    return MockWriteResult(mode, static_cast<int>(length));
  }

  bool AllReadDataConsumed() const override {
    return response_.empty() && Peer::AllReadDataConsumed();
  }

  bool AllWriteDataConsumed() const override {
    return request_.empty() && Peer::AllWriteDataConsumed();
  }

  std::string http_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
  uint8_t socks_reply = 0;
  bool close_before_response = false;
  int tunneled_writes = 0;
  std::vector<std::string> requests;

 private:
  void Reset() override {
    Peer::Reset();
    stage_ = 0;
    tunneled_writes = 0;
    request_.clear();
    response_.clear();
    proxy_read_storage_.clear();
    requests.clear();
  }

  const Kind kind_;
  int stage_ = 0;
  std::string request_, response_, proxy_read_storage_;
};

// A real HTTPPS proxy peer: decrypt the outer channel, process CONNECT, then
// relay the inner encrypted channel without interpreting its application data.
// The proxy and origin have independent certificates, keys and record counters.
class SecureProxyPeer : public Peer {
 public:
  SecureProxyPeer() : Peer(/*key_offset=*/64) {
    origin.mode = SYNCHRONOUS;
    origin.read_chunk = 20000;
    origin.write_chunk = 20000;
  }

  TunnelPeer origin{TunnelPeer::Kind::kHttp};

  void FlushOrigin() {
    while (!origin.AllReadDataConsumed()) {
      MockRead next = origin.OnRead();
      ASSERT_FALSE(next.data.empty());
      Application(next.data);
    }
  }

 private:
  void OnApplication(std::string_view plaintext) override {
    size_t offset = 0;
    while (offset < plaintext.size()) {
      MockWriteResult written =
          origin.OnWrite(std::string(plaintext.substr(offset)));
      ASSERT_GT(written.result, 0);
      offset += written.result;
    }
    FlushOrigin();
  }
};

// Holds a verifier result until a test explicitly completes or cancels it.
// The request lifetime has the same cancellation semantics as CertVerifier.
class DeferredCertVerifier : public MockCertVerifier {
 public:
  int Verify(const RequestParams& params,
             CertVerifyResult* result,
             CompletionOnceCallback callback,
             std::unique_ptr<Request>* request,
             const NetLogWithSource& net_log) override {
    EXPECT_FALSE(active);
    active = true;
    result->verified_cert = params.certificate();
    result->cert_status = 0;
    callback_ = std::move(callback);
    *request = std::make_unique<PendingRequest>(base::BindOnce(
        &DeferredCertVerifier::Cancel, weak_factory_.GetWeakPtr()));
    return ERR_IO_PENDING;
  }

  void Complete(int result) {
    ASSERT_TRUE(active);
    std::move(callback_).Run(result);
  }

  bool active = false;

 private:
  class PendingRequest : public Request {
   public:
    explicit PendingRequest(base::OnceClosure cancellation)
        : cancellation_(std::move(cancellation)) {}

   private:
    base::ScopedClosureRunner cancellation_;
  };
  void Cancel() {
    active = false;
    callback_.Reset();
  }
  CompletionOnceCallback callback_;
  base::WeakPtrFactory<DeferredCertVerifier> weak_factory_{this};
};

class HttppsClientSocketTest : public testing::Test {
 protected:
  std::unique_ptr<HttppsClientSocket> Make(
      bool trust = true,
      CertVerifier* verifier = nullptr,
      std::optional<httpps::SessionTicket> session = std::nullopt,
      bool early_data = false,
      httpps::ClientOptions options = {}) {
    auto tcp = std::make_unique<MockTCPClientSocket>(
        AddressList::CreateFromIPAddress(IPAddress::IPv4Localhost(), 343),
        nullptr, &peer_);
    TestCompletionCallback connected;
    EXPECT_EQ(OK, tcp->Connect(connected.callback()));
    return std::make_unique<HttppsClientSocket>(
        std::move(tcp), HostPortPair("localhost", 343),
        trust ? std::vector<std::string>{peer_.root}
              : std::vector<std::string>{},
        verifier, std::move(session),
        base::RepeatingCallback<void(httpps::SessionTicket)>(), early_data,
        std::move(options));
  }
  base::test::TaskEnvironment tasks_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  Peer peer_;
};

class HttppsClientSocketProxyTest : public testing::Test {
 protected:
  std::unique_ptr<StreamSocket> MakeTransport(Peer& peer) {
    auto tcp = std::make_unique<MockTCPClientSocket>(
        AddressList::CreateFromIPAddress(IPAddress::IPv4Localhost(), 8080),
        nullptr, &peer);
    TestCompletionCallback connected;
    EXPECT_EQ(OK, tcp->Connect(connected.callback()));
    return tcp;
  }

  std::unique_ptr<HttpProxyClientSocket> MakeHttpTunnel(TunnelPeer& peer) {
    auto auth = base::MakeRefCounted<HttpAuthController>(
        HttpAuth::AUTH_PROXY, GURL("http://proxy.test:8080"),
        NetworkAnonymizationKey(), &auth_cache_, auth_factory_.get(),
        &resolver_);
    return std::make_unique<HttpProxyClientSocket>(
        MakeTransport(peer), /*user_agent=*/"", HostPortPair("localhost", 343),
        ProxyChain(ProxyServer::SCHEME_HTTP, HostPortPair("proxy.test", 8080)),
        /*proxy_chain_index=*/0, std::move(auth), /*proxy_delegate=*/nullptr,
        TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  std::unique_ptr<HttppsClientSocket> WrapTunnel(
      std::unique_ptr<StreamSocket> tunnel,
      const TunnelPeer& peer) {
    return std::make_unique<HttppsClientSocket>(
        std::move(tunnel), HostPortPair("localhost", 343),
        std::vector<std::string>{peer.root});
  }

  void ExchangeApplication(HttppsClientSocket& socket,
                           TunnelPeer& peer,
                           base::RepeatingClosure flush_peer = {}) {
    TestCompletionCallback connect;
    ASSERT_EQ(OK, connect.GetResult(socket.Connect(connect.callback())));
    EXPECT_EQ(1, peer.client_hellos);
    EXPECT_EQ(NextProto::kProtoHTTP11, socket.GetNegotiatedProtocol());
    auto request = base::MakeRefCounted<StringIOBuffer>(
        "GET / HTTP/1.1\r\nHost: localhost:343\r\n\r\n");
    TestCompletionCallback write;
    ASSERT_EQ(request->size(),
              write.GetResult(socket.Write(request.get(), request->size(),
                                           write.callback(),
                                           TRAFFIC_ANNOTATION_FOR_TESTS)));
    EXPECT_EQ(std::string(request->data(), request->size()),
              peer.received_application);
    constexpr std::string_view kResponse =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    peer.Application(kResponse, /*close=*/true);
    if (flush_peer) {
      flush_peer.Run();
    }
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(100);
    TestCompletionCallback read;
    int result = socket.Read(buffer.get(), buffer->size(), read.callback());
    ASSERT_EQ(static_cast<int>(kResponse.size()), read.GetResult(result));
    EXPECT_EQ(kResponse, std::string_view(buffer->data(), kResponse.size()));
    result = socket.Read(buffer.get(), buffer->size(), read.callback());
    EXPECT_EQ(0, read.GetResult(result));
  }

  base::test::TaskEnvironment tasks_;
  HttpAuthCache auth_cache_{false};
  std::unique_ptr<HttpAuthHandlerRegistryFactory> auth_factory_ =
      HttpAuthHandlerFactory::CreateDefault();
  MockHostResolver resolver_;
};

TEST_F(HttppsClientSocketProxyTest, ContextDoesNotFallBackToOtherRoleTrust) {
  for (SessionUsage usage :
       {SessionUsage::kDestination, SessionUsage::kProxy}) {
    SCOPED_TRACE(static_cast<int>(usage));
    Peer peer;
    MockCertVerifier verifier;
    verifier.set_default_result(ERR_CERT_AUTHORITY_INVALID);
    TransportSecurityState security_state;
    SSLClientContext context(/*ssl_config_service=*/nullptr, &verifier,
                             &security_state,
                             /*ssl_client_session_cache=*/nullptr,
                             /*sct_auditing_delegate=*/nullptr);
    // Only the opposite role trusts this peer. The selected role must ask the
    // shared HTTPS verifier, whose rejection must not fall back to that CA.
    if (usage == SessionUsage::kDestination) {
      context.SetHttppsProxyTrustAnchors({peer.root});
    } else {
      context.SetHttppsTrustAnchors({peer.root});
    }
    SSLConfig config;
    config.is_httpps = true;
    config.session_usage = usage;
    auto socket = context.CreateSSLClientSocket(
        MakeTransport(peer), HostPortPair("localhost", 343), config);
    TestCompletionCallback connect;
    EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
              connect.GetResult(socket->Connect(connect.callback())));
    EXPECT_EQ(1, peer.client_hellos);
    EXPECT_EQ(0, peer.client_finished);
    EXPECT_FALSE(socket->IsConnected());
    EXPECT_TRUE(peer.received_application.empty());
  }
}

TEST_F(HttppsClientSocketProxyTest, ContextPinningPersistsAndPartitionsAttempts) {
  Peer peer;
  peer.write_chunk = 65536;
  peer.pin_response = Bytes{0, 0, 1, 0x77, 0, 0, 0x0e, 0x10};
  MockCertVerifier verifier;
  verifier.set_default_result(ERR_CERT_AUTHORITY_INVALID);
  TransportSecurityState security_state;
  SSLClientContext context(nullptr, &verifier, &security_state, nullptr, nullptr);
  context.SetHttppsTrustAnchors({peer.root});
  SSLConfig config;
  config.is_httpps = true;
  httpps::ClientOptions options;
  options.continuity_pinning = true;
  const HostPortPair destination("localhost", 343);
  ASSERT_TRUE(context.SetHttppsOptions(destination, config, options));
  TestCompletionCallback done;
  auto socket = context.CreateSSLClientSocket(MakeTransport(peer), destination, config);
  ASSERT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
  EXPECT_TRUE(peer.client_offered_pinning);
  EXPECT_TRUE(peer.client_pin.empty());
  socket.reset();
  peer.pin_response.reset();
  socket = context.CreateSSLClientSocket(MakeTransport(peer), destination, config);
  EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
            done.GetResult(socket->Connect(done.callback())));
  EXPECT_EQ(peer.client_pin, (Bytes{0, 1, 0x77}));
  EXPECT_EQ(peer.last_client_alert, 40);
  socket.reset();
  auto other = config;
  other.privacy_mode = PRIVACY_MODE_ENABLED;
  ASSERT_TRUE(context.SetHttppsOptions(destination, other, options));
  socket = context.CreateSSLClientSocket(MakeTransport(peer), destination, other);
  EXPECT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
  EXPECT_TRUE(peer.client_offered_pinning);
  EXPECT_TRUE(peer.client_pin.empty());
  socket.reset();
  // The first partition retains its pin after an unrelated partition is used.
  socket = context.CreateSSLClientSocket(MakeTransport(peer), destination, config);
  EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
            done.GetResult(socket->Connect(done.callback())));
  EXPECT_EQ(peer.client_pin, (Bytes{0, 1, 0x77}));
}

TEST_F(HttppsClientSocketProxyTest, OmitCredentialsProfileFailsBeforeClientHello) {
  Peer peer;
  MockCertVerifier verifier;
  TransportSecurityState security_state;
  SSLClientContext context(nullptr, &verifier, &security_state, nullptr, nullptr);
  context.SetHttppsTrustAnchors({peer.root});
  context.SetHttppsProfileProvider(base::BindLambdaForTesting(
      [](const HostPortPair& server, const SSLConfig&,
         httpps::ClientOptions* options,
         std::optional<httpps::ClientCredential>*,
         std::vector<std::string>*) -> std::optional<bool> {
        auto password = std::make_shared<httpps::PasswordCredential>();
        password->service = server.host();
        password->username = "fixture-account";
        password->password = "fixture-secret";
        options->password = std::move(password);
        return true;
      }));
  SSLConfig config;
  config.is_httpps = true;
  config.privacy_mode = PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS;
  auto socket = context.CreateSSLClientSocket(
      MakeTransport(peer), HostPortPair("localhost", 343), config);
  TestCompletionCallback done;
  EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, done.GetResult(socket->Connect(done.callback())));
  EXPECT_EQ(peer.client_hellos, 0);
  EXPECT_TRUE(peer.received_application.empty());
}

TEST_F(HttppsClientSocketProxyTest, ConfiguredPostHandshakeAuthChoiceIsRespected) {
  Peer peer;
  MockCertVerifier verifier;
  TransportSecurityState security_state;
  SSLClientContext context(nullptr, &verifier, &security_state, nullptr, nullptr);
  context.SetHttppsTrustAnchors({peer.root});
  SSLConfig config;
  config.is_httpps = true;
  const HostPortPair destination("localhost", 343);
  httpps::ClientCredential credential;
  credential.certificate_type = 2;
  Secret public_key{};
  X25519_keypair(public_key.data(), credential.private_key.data());
  Bytes spki{0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 3, 0x21, 0};
  Append(spki, public_key);
  credential.certificates.emplace_back(spki.begin(), spki.end());
  ASSERT_TRUE(context.SetHttppsClientCredential(destination, config, credential));
  for (bool enable : {false, true}) {
    httpps::ClientOptions options;
    options.post_handshake_auth = enable;
    ASSERT_TRUE(context.SetHttppsOptions(destination, config, options));
    auto socket = context.CreateSSLClientSocket(MakeTransport(peer), destination, config);
    TestCompletionCallback done;
    ASSERT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
    EXPECT_EQ(peer.client_offered_pha, enable);
  }
  config.privacy_mode = PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS;
  EXPECT_FALSE(context.SetHttppsClientCredential(destination, config, credential));
}

TEST_F(HttppsClientSocketProxyTest, ContextSelectsIndependentRoleTrustStores) {
  struct TestCase {
    const char* description;
    SessionUsage usage;
    bool proxy_peer;
    int expected;
  };
  const TestCase cases[] = {
      {"origin trusts origin CA", SessionUsage::kDestination, false, OK},
      {"proxy trusts proxy CA", SessionUsage::kProxy, true, OK},
      {"origin rejects proxy CA", SessionUsage::kDestination, true,
       ERR_SSL_SERVER_CERT_BAD_FORMAT},
      {"proxy rejects origin CA", SessionUsage::kProxy, false,
       ERR_SSL_SERVER_CERT_BAD_FORMAT},
  };
  for (const TestCase& test : cases) {
    SCOPED_TRACE(test.description);
    Peer origin;
    Peer proxy(/*key_offset=*/64);
    Peer& peer = test.proxy_peer ? proxy : origin;
    MockCertVerifier verifier;
    verifier.set_default_result(ERR_CERT_AUTHORITY_INVALID);
    TransportSecurityState security_state;
    SSLClientContext context(/*ssl_config_service=*/nullptr, &verifier,
                             &security_state,
                             /*ssl_client_session_cache=*/nullptr,
                             /*sct_auditing_delegate=*/nullptr);
    context.SetHttppsTrustAnchors({origin.root});
    context.SetHttppsProxyTrustAnchors({proxy.root});
    SSLConfig config;
    config.is_httpps = true;
    config.session_usage = test.usage;
    // Every case uses exactly the same host and port: role alone determines
    // which trust store is allowed to authenticate the peer.
    auto socket = context.CreateSSLClientSocket(
        MakeTransport(peer), HostPortPair("localhost", 343), config);
    TestCompletionCallback connect;
    EXPECT_EQ(test.expected,
              connect.GetResult(socket->Connect(connect.callback())));
    EXPECT_EQ(1, peer.client_hellos);
    EXPECT_EQ(test.expected == OK ? 1 : 0, peer.client_finished);
    EXPECT_EQ(test.expected == OK, socket->IsConnected());
  }
}

TEST_F(HttppsClientSocketProxyTest, CertificateExceptionsCannotBypassBrowser) {
  for (SessionUsage usage :
       {SessionUsage::kDestination, SessionUsage::kProxy}) {
    Peer peer;
    ParamRecordingMockCertVerifier verifier;
    verifier.set_async(true);
    verifier.set_default_result(ERR_CERT_AUTHORITY_INVALID);
    TransportSecurityState security_state;
    SSLClientContext context(nullptr, &verifier, &security_state, nullptr,
                             nullptr);
    SSLConfig config;
    config.is_httpps = true;
    config.session_usage = usage;
    config.ignore_certificate_errors = true;
    config.allowed_bad_certs.emplace_back(peer.certificate(),
                                          CERT_STATUS_AUTHORITY_INVALID);
    auto socket = context.CreateSSLClientSocket(
        MakeTransport(peer), HostPortPair("localhost", 343), config);
    TestCompletionCallback connect;
    EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
              connect.GetResult(socket->Connect(connect.callback())));
    EXPECT_EQ(1u, verifier.GetVerifyParams().size());
    EXPECT_EQ(0, peer.client_finished);
    EXPECT_FALSE(socket->IsConnected());
    EXPECT_TRUE(peer.received_application.empty());
  }
}

TEST_F(HttppsClientSocketProxyTest, HttpConnectCarriesEncryptedApplication) {
  TunnelPeer peer(TunnelPeer::Kind::kHttp);
  auto tunnel = MakeHttpTunnel(peer);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(tunnel->Connect(connect.callback())));
  ASSERT_EQ(1u, peer.requests.size());
  EXPECT_EQ(0, peer.client_hellos);
  EXPECT_EQ(0, peer.tunneled_writes);
  auto socket = WrapTunnel(std::move(tunnel), peer);
  ExchangeApplication(*socket, peer);
}

TEST_F(HttppsClientSocketProxyTest, Socks5ConnectCarriesEncryptedApplication) {
  TunnelPeer peer(TunnelPeer::Kind::kSocks5);
  auto tunnel = std::make_unique<SOCKS5ClientSocket>(
      MakeTransport(peer), HostPortPair("localhost", 343),
      TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(tunnel->Connect(connect.callback())));
  ASSERT_EQ(2u, peer.requests.size());
  EXPECT_EQ(0, peer.client_hellos);
  EXPECT_EQ(0, peer.tunneled_writes);
  auto socket = WrapTunnel(std::move(tunnel), peer);
  ExchangeApplication(*socket, peer);
}

TEST_F(HttppsClientSocketProxyTest,
       HttppsProxyAndOriginUseIndependentChannels) {
  SecureProxyPeer peer;
  auto proxy_channel = std::make_unique<HttppsClientSocket>(
      MakeTransport(peer), HostPortPair("localhost", 343),
      std::vector<std::string>{peer.root});
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(proxy_channel->Connect(connect.callback())));
  EXPECT_EQ(1, peer.client_hellos);
  EXPECT_EQ(0, peer.origin.client_hellos);
  EXPECT_TRUE(peer.received_application.empty());

  auto auth = base::MakeRefCounted<HttpAuthController>(
      HttpAuth::AUTH_PROXY, GURL("httpps://localhost:343"),
      NetworkAnonymizationKey(), &auth_cache_, auth_factory_.get(), &resolver_);
  auto tunnel = std::make_unique<HttpProxyClientSocket>(
      std::move(proxy_channel), /*user_agent=*/"",
      HostPortPair("localhost", 343),
      ProxyChain(ProxyServer::SCHEME_HTTPPS, HostPortPair("localhost", 343)),
      /*proxy_chain_index=*/0, std::move(auth), /*proxy_delegate=*/nullptr,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_EQ(OK, connect.GetResult(tunnel->Connect(connect.callback())));
  ASSERT_EQ(1u, peer.origin.requests.size());
  EXPECT_EQ(0, peer.origin.client_hellos);
  auto origin_channel = WrapTunnel(std::move(tunnel), peer.origin);
  ExchangeApplication(*origin_channel, peer.origin,
                      base::BindLambdaForTesting([&] { peer.FlushOrigin(); }));
  EXPECT_EQ(1, peer.client_hellos);
  EXPECT_EQ(1, peer.origin.client_hellos);
  EXPECT_EQ(std::string::npos,
            peer.received_application.find("GET / HTTP/1.1"));
}

TEST_F(HttppsClientSocketProxyTest, UntrustedHttppsProxyNeverReceivesConnect) {
  SecureProxyPeer peer;
  auto proxy_channel = std::make_unique<HttppsClientSocket>(
      MakeTransport(peer), HostPortPair("localhost", 343),
      // Trusting the origin does not implicitly trust the proxy's certificate.
      std::vector<std::string>{peer.origin.root});
  TestCompletionCallback connect;
  EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
            connect.GetResult(proxy_channel->Connect(connect.callback())));
  EXPECT_FALSE(proxy_channel->IsConnected());
  EXPECT_EQ(1, peer.client_hellos);
  EXPECT_EQ(0, peer.origin.client_hellos);
  EXPECT_TRUE(peer.received_application.empty());
  EXPECT_TRUE(peer.origin.requests.empty());
}

TEST_F(HttppsClientSocketProxyTest, ProxyAuthCompletesBeforeHttppsHandshake) {
  TunnelPeer peer(TunnelPeer::Kind::kHttp);
  peer.http_response =
      "HTTP/1.1 407 Proxy Authentication Required\r\n"
      "Proxy-Authenticate: Basic realm=\"tunnel\"\r\n"
      "Content-Length: 0\r\n\r\n";
  auto tunnel = MakeHttpTunnel(peer);
  TestCompletionCallback connect;
  ASSERT_EQ(ERR_PROXY_AUTH_REQUESTED,
            connect.GetResult(tunnel->Connect(connect.callback())));
  EXPECT_FALSE(tunnel->IsConnected());
  ASSERT_EQ(1u, peer.requests.size());
  EXPECT_EQ(std::string::npos, peer.requests[0].find("Proxy-Authorization:"));
  EXPECT_EQ(0, peer.client_hellos);
  EXPECT_EQ(0, peer.tunneled_writes);

  peer.http_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
  tunnel->GetAuthController()->ResetAuth(AuthCredentials(u"user", u"password"));
  ASSERT_EQ(OK, connect.GetResult(tunnel->RestartWithAuth(connect.callback())));
  ASSERT_EQ(2u, peer.requests.size());
  EXPECT_NE(std::string::npos,
            peer.requests[1].find(
                "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"));
  EXPECT_EQ(0, peer.client_hellos);
  auto socket = WrapTunnel(std::move(tunnel), peer);
  ExchangeApplication(*socket, peer);
  EXPECT_EQ(std::string::npos,
            peer.received_application.find("Proxy-Authorization"));
}

TEST_F(HttppsClientSocketProxyTest, RejectedHttpTunnelNeverStartsHttpps) {
  TunnelPeer peer(TunnelPeer::Kind::kHttp);
  peer.http_response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
  auto tunnel = MakeHttpTunnel(peer);
  TestCompletionCallback connect;
  EXPECT_EQ(ERR_TUNNEL_CONNECTION_FAILED,
            connect.GetResult(tunnel->Connect(connect.callback())));
  auto socket = WrapTunnel(std::move(tunnel), peer);
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED, socket->Connect(connect.callback()));
  EXPECT_EQ(0, peer.client_hellos);
  EXPECT_EQ(0, peer.tunneled_writes);
  EXPECT_TRUE(peer.received_application.empty());
}

TEST_F(HttppsClientSocketProxyTest, ClosedHttpTunnelNeverStartsHttpps) {
  TunnelPeer peer(TunnelPeer::Kind::kHttp);
  peer.close_before_response = true;
  auto tunnel = MakeHttpTunnel(peer);
  TestCompletionCallback connect;
  EXPECT_LT(connect.GetResult(tunnel->Connect(connect.callback())), OK);
  auto socket = WrapTunnel(std::move(tunnel), peer);
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED, socket->Connect(connect.callback()));
  EXPECT_EQ(0, peer.client_hellos);
  EXPECT_EQ(0, peer.tunneled_writes);
}

TEST_F(HttppsClientSocketProxyTest, RejectedSocksTunnelNeverStartsHttpps) {
  TunnelPeer peer(TunnelPeer::Kind::kSocks5);
  peer.socks_reply = 2;  // Connection not allowed by the proxy's ruleset.
  auto tunnel = std::make_unique<SOCKS5ClientSocket>(
      MakeTransport(peer), HostPortPair("localhost", 343),
      TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback connect;
  EXPECT_EQ(ERR_SOCKS_CONNECTION_FAILED,
            connect.GetResult(tunnel->Connect(connect.callback())));
  auto socket = WrapTunnel(std::move(tunnel), peer);
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED, socket->Connect(connect.callback()));
  EXPECT_EQ(0, peer.client_hellos);
  EXPECT_EQ(0, peer.tunneled_writes);
}

TEST_F(HttppsClientSocketTest, PartialAsyncHandshakeAndApplication) {
  auto socket = Make();
  TestCompletionCallback connect;
  EXPECT_EQ(ERR_IO_PENDING, socket->Connect(connect.callback()));
  EXPECT_EQ(OK, connect.WaitForResult());
  EXPECT_TRUE(socket->IsConnected());
  EXPECT_EQ(NextProto::kProtoHTTP11, socket->GetNegotiatedProtocol());
  SSLInfo info;
  EXPECT_TRUE(socket->GetSSLInfo(&info));
  EXPECT_EQ(0xfe00, info.peer_signature_algorithm);
  EXPECT_FALSE(info.is_issued_by_known_root);
  EXPECT_EQ(SSL_CONNECTION_VERSION_UNKNOWN,
            SSLConnectionStatusToVersion(info.connection_status));
  EXPECT_TRUE(SSLConnectionStatusIsHttpps(info.connection_status));
  peer_.Application("hello");
  peer_.Application("");
  peer_.Application("world", true);
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(100);
  TestCompletionCallback read;
  int result = socket->Read(buffer.get(), 100, read.callback());
  EXPECT_EQ(5, read.GetResult(result));
  EXPECT_EQ("hello", std::string(buffer->data(), 5));
  result = socket->Read(buffer.get(), 100, read.callback());
  EXPECT_EQ(5, read.GetResult(result));
  EXPECT_EQ("world", std::string(buffer->data(), 5));
  result = socket->Read(buffer.get(), 100, read.callback());
  EXPECT_EQ(0, read.GetResult(result));
}

TEST_F(HttppsClientSocketTest, HelloResponseAlertsDistinguishOfferAndContext) {
  peer_.write_chunk = 65536;
  for (bool retry : {false, true}) {
    peer_.hello_retry = retry;
    for (uint16_t type : {0xfafa, 15, 41, 33, 0xff02}) {
      SCOPED_TRACE(testing::Message() << "retry=" << retry << " type=" << type);
      peer_.hello_response_extra.clear();
      U16(peer_.hello_response_extra, type);
      U16(peer_.hello_response_extra, 0);
      auto socket = Make();
      TestCompletionCallback connected;
      EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, connected.GetResult(socket->Connect(connected.callback())));
      EXPECT_EQ(peer_.client_hellos, 1);
      EXPECT_EQ(peer_.client_finished, 0);
      EXPECT_EQ(peer_.last_client_alert, type == 0xfafa || (!retry && (type == 41 || type == 33)) ? 110 : 47);
    }
  }
}

TEST_F(HttppsClientSocketTest, EncryptedExtensionAlertsDistinguishMissingOffer) {
  struct Case { uint16_t type; Bytes value; bool offered; uint8_t alert; };
  const Case cases[] = {{0xfafa, {}, false, 110}, {15, {1}, false, 110},
                        {28, {0, 64}, false, 110}, {15, {0}, true, 47},
                        {15, {}, true, 50}, {15, {1, 1}, true, 50}};
  peer_.write_chunk = 65536;
  for (const auto& test : cases) {
    SCOPED_TRACE(test.type);
    peer_.encrypted_extensions_extra.clear();
    U16(peer_.encrypted_extensions_extra, test.type);
    U16(peer_.encrypted_extensions_extra, test.value.size());
    Append(peer_.encrypted_extensions_extra, test.value);
    httpps::ClientOptions options;
    if (test.offered) options.heartbeat_mode = 1;
    auto socket = Make(true, nullptr, std::nullopt, false, options);
    TestCompletionCallback connected;
    EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, connected.GetResult(socket->Connect(connected.callback())));
    EXPECT_EQ(peer_.client_finished, 0);
    EXPECT_EQ(peer_.last_client_alert, test.alert);
  }
}

TEST_F(HttppsClientSocketTest, MisplacedEncryptedExtensionsKeepIllegalParameter) {
  peer_.write_chunk = 65536;
  for (uint16_t type : {2, 3, 4, 5, 13, 17, 18, 21, 27, 29, 30, 31, 33, 34,
                        41, 43, 44, 45, 47, 48, 49, 50, 51, 52, 59, 0xff02, 0xff03, 0xff04}) {
    SCOPED_TRACE(type);
    peer_.encrypted_extensions_extra.clear();
    U16(peer_.encrypted_extensions_extra, type);
    U16(peer_.encrypted_extensions_extra, 0);
    auto socket = Make();
    TestCompletionCallback connected;
    EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, connected.GetResult(socket->Connect(connected.callback())));
    EXPECT_EQ(peer_.client_finished, 0);
    EXPECT_EQ(peer_.last_client_alert, 47);
  }
}

TEST_F(HttppsClientSocketTest, CertificateExtensionAlertsDistinguishOfferAndContext) {
  peer_.write_chunk = 65536;
  for (uint16_t type : {0xfafa, 5, 18, 34, 52, 59, 15, 43, 0xff02}) {
    SCOPED_TRACE(type);
    peer_.leaf_extensions = {{type, {}}};
    auto socket = Make();
    TestCompletionCallback connected;
    EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, connected.GetResult(socket->Connect(connected.callback())));
    EXPECT_EQ(peer_.client_finished, 0);
    EXPECT_EQ(peer_.last_client_alert, type == 15 || type == 43 || type == 0xff02 ? 47 : 110);
  }
}

TEST_F(HttppsClientSocketTest, KnownExtensionsAreRejectedInCertificateRequest) {
  peer_.write_chunk = 65536;
  for (uint16_t type : {0, 1, 10, 13, 15, 16, 17, 19, 20, 21, 25, 28,
                        29, 30, 31, 32, 33, 41, 42, 43, 44, 45, 49, 51,
                        55, 56, 58, 59, 0xff02}) {
    SCOPED_TRACE(type);
    peer_.send_initial_cr = true;
    peer_.initial_cr_extra.clear();
    U16(peer_.initial_cr_extra, type);
    U16(peer_.initial_cr_extra, 0);
    auto socket = Make();
    TestCompletionCallback connected;
    EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, connected.GetResult(socket->Connect(connected.callback())));
    EXPECT_EQ(peer_.client_finished, 0);
    EXPECT_EQ(peer_.last_client_alert, 47);
  }
}

TEST_F(HttppsClientSocketTest, MalformedCertificateRequestVectorsSendDecodeError) {
  peer_.write_chunk = 65536;
  for (uint16_t type : {27, 34, 47, 48, 0xff04}) {
    for (const Bytes& malformed : {Bytes{}, Bytes{0, 0}, Bytes{0, 3, 4},
                                  Bytes{0, 2, 4, 3, 0}}) {
      // OID filters may be empty; an authority list must contain a DER Name.
      if (type == 48 && malformed == Bytes({0, 0}))
        continue;
      SCOPED_TRACE(type);
      peer_.send_initial_cr = true;
      peer_.initial_cr_extra.clear();
      U16(peer_.initial_cr_extra, type);
      U16(peer_.initial_cr_extra, malformed.size());
      Append(peer_.initial_cr_extra, malformed);
      if (type == 34 || type == 0xff04) {
        U16(peer_.initial_cr_extra, type == 34 ? 0xff04 : 34);
        U16(peer_.initial_cr_extra, 4);
        Append(peer_.initial_cr_extra, Bytes{0, 2, 4, 3});
      }
      auto socket = Make();
      TestCompletionCallback connected;
      EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR,
                connected.GetResult(socket->Connect(connected.callback())));
      EXPECT_EQ(peer_.client_finished, 0);
      EXPECT_EQ(peer_.last_client_alert, 50);
    }
  }
}

TEST_F(HttppsClientSocketTest, CertificateRequestEvidenceSyntaxWithoutCredential) {
  const Bytes name{0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03,
                   0x55, 0x04, 0x03, 0x0c, 0x01, 0x41};
  Bytes authorities;
  U16(authorities, name.size() + 2);
  U16(authorities, name.size());
  Append(authorities, name);
  struct Case { uint16_t type; Bytes data; bool valid; };
  const Case cases[] = {
      {47, authorities, true}, {47, {0, 0}, false},
      {47, {0, 3, 0, 1, 0}, false},
      {5, {}, true}, {5, {0}, false}, {5, {1, 0, 0, 0, 0}, false},
      {0xaaa0, {0}, true}};
  for (IoMode mode : {SYNCHRONOUS, ASYNC}) {
    for (bool pha : {false, true}) {
      for (const auto& test : cases) {
        SCOPED_TRACE(mode);
        SCOPED_TRACE(pha);
        SCOPED_TRACE(test.type);
        SCOPED_TRACE(test.valid);
        peer_.mode = mode;
        peer_.read_chunk = 3;
        // Fatal alerts are best effort before immediate disconnect. Give error
        // cases a complete Write so this checks the exact decode_error; keep
        // successful controls fragmented. Short fatal writes are tested below.
        peer_.write_chunk = test.valid ? 7 : 65536;
        Bytes extra;
        U16(extra, test.type);
        U16(extra, test.data.size());
        Append(extra, test.data);
        peer_.send_initial_cr = !pha;
        peer_.initial_cr_extra = pha ? Bytes{} : extra;
        httpps::ClientOptions options;
        options.post_handshake_auth = true;
        auto socket = Make(true, nullptr, std::nullopt, false, options);
        TestCompletionCallback connected;
        const int result = connected.GetResult(socket->Connect(connected.callback()));
        if (!pha) {
          EXPECT_EQ(test.valid ? OK : ERR_SSL_PROTOCOL_ERROR, result);
          EXPECT_EQ(test.valid ? 1 : 0, peer_.initial_empty_certificates);
          EXPECT_EQ(test.valid ? 1 : 0, peer_.client_finished);
        } else {
          ASSERT_EQ(OK, result);
          peer_.RequestClientAuth(1, extra);
          peer_.Application("after request");
          auto response = base::MakeRefCounted<IOBufferWithSize>(32);
          TestCompletionCallback read;
          EXPECT_EQ(test.valid ? 13 : ERR_SSL_PROTOCOL_ERROR,
                    read.GetResult(socket->Read(response.get(), response->size(), read.callback())));
          EXPECT_EQ(test.valid ? 1 : 0, peer_.pha_empty_certificates);
          EXPECT_EQ(test.valid ? 1 : 0, peer_.pha_finished);
          if (test.valid)
            EXPECT_EQ("after request", std::string(response->data(), 13));
        }
        EXPECT_EQ(test.valid ? 0 : 50, peer_.last_client_alert);
        EXPECT_EQ(test.valid, socket->IsConnected());
      }
    }
  }
}

TEST_F(HttppsClientSocketTest, MalformedCertificateRequestClosesAfterShortAlertWrite) {
  for (IoMode mode : {SYNCHRONOUS, ASYNC}) {
    for (bool pha : {false, true}) {
      for (uint16_t type : {47, 5}) {
        SCOPED_TRACE(mode);
        SCOPED_TRACE(pha);
        SCOPED_TRACE(type);
        peer_.mode = mode;
        peer_.read_chunk = 3;
        peer_.write_chunk = 3;  // Shorter than even an unencrypted alert record.
        // Empty authorities and nonempty status_request are malformed even
        // when no client credential is configured.
        const Bytes data = type == 47 ? Bytes{0, 0} : Bytes{0};
        Bytes extra;
        U16(extra, type);
        U16(extra, data.size());
        Append(extra, data);
        peer_.send_initial_cr = !pha;
        peer_.initial_cr_extra = pha ? Bytes{} : extra;
        httpps::ClientOptions options;
        options.post_handshake_auth = true;
        auto socket = Make(true, nullptr, std::nullopt, false, options);
        TestCompletionCallback connected;
        const int result = connected.GetResult(socket->Connect(connected.callback()));
        auto response = base::MakeRefCounted<IOBufferWithSize>(32);
        if (!pha) {
          EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, result);
          EXPECT_EQ(0, peer_.client_finished);
        } else {
          ASSERT_EQ(OK, result);
          peer_.RequestClientAuth(1, extra);
          peer_.Application("must not be delivered");
          TestCompletionCallback read;
          EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR,
                    read.GetResult(socket->Read(response.get(), response->size(),
                                                read.callback())));
          EXPECT_EQ(1, peer_.client_finished);
        }
        // The partial fatal record proves an alert was attempted, but closing
        // must not depend on the peer receiving its complete record.
        EXPECT_FALSE(peer_.AllWriteDataConsumed());
        EXPECT_EQ(0, peer_.last_client_alert);
        EXPECT_EQ(0, peer_.initial_empty_certificates);
        EXPECT_EQ(0, peer_.pha_empty_certificates);
        EXPECT_EQ(0, peer_.pha_finished);
        EXPECT_FALSE(socket->IsConnected());
        EXPECT_FALSE(socket->IsConnectedAndIdle());
        int unexpected_callbacks = 0;
        EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR,
                  socket->Read(response.get(), response->size(),
                               base::BindLambdaForTesting([&](int) {
                                 ++unexpected_callbacks;
                               })));
        auto request = base::MakeRefCounted<StringIOBuffer>("must not be sent");
        EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR,
                  socket->Write(request.get(), request->size(),
                                base::BindLambdaForTesting([&](int) {
                                  ++unexpected_callbacks;
                                }), TRAFFIC_ANNOTATION_FOR_TESTS));
        tasks_.RunUntilIdle();
        EXPECT_EQ(0, unexpected_callbacks);
        EXPECT_TRUE(peer_.received_application.empty());
      }
    }
  }
}

TEST_F(HttppsClientSocketTest, UserCanceledWaitsForCloseNotify) {
  auto socket = Make();
  TestCompletionCallback done;
  ASSERT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
  peer_.Alert(90);
  peer_.Application("still readable");
  peer_.Alert(90);
  peer_.Alert(0);
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(100);
  EXPECT_EQ(14, done.GetResult(socket->Read(buffer.get(), 100, done.callback())));
  EXPECT_EQ(0, done.GetResult(socket->Read(buffer.get(), 100, done.callback())));
}

TEST_F(HttppsClientSocketTest, FragmentedKeyUpdatePreservesEpoch) {
  for (IoMode mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(mode);
    peer_.mode = mode;
    peer_.read_chunk = peer_.write_chunk = 20000;
    auto socket = Make();
    TestCompletionCallback done;
    ASSERT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
    peer_.FragmentedKeyUpdate(std::nullopt);
    peer_.Application("after update");
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(100);
    EXPECT_EQ(12, done.GetResult(socket->Read(buffer.get(), 100, done.callback())));
    EXPECT_EQ("after update", std::string(buffer->data(), 12));
    EXPECT_TRUE(socket->IsConnected());
  }
}

TEST_F(HttppsClientSocketTest, InterleavedAlertCannotResumeFragmentedKeyUpdate) {
  for (IoMode mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(mode);
    peer_.mode = mode;
    peer_.read_chunk = peer_.write_chunk = 20000;
    auto socket = Make();
    TestCompletionCallback done;
    ASSERT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
    peer_.FragmentedKeyUpdate(90);
    peer_.Application("must not be delivered");
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(100);
    EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR,
              done.GetResult(socket->Read(buffer.get(), 100, done.callback())));
    EXPECT_EQ(peer_.last_client_alert, 10);
    EXPECT_FALSE(socket->IsConnected());
  }
}

TEST_F(HttppsClientSocketTest, NoAlpnRequiresExplicitHttp11Profile) {
  peer_.write_chunk = 65536;
  peer_.omit_alpn = true;
  auto socket = Make();
  TestCompletionCallback done;
  EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, done.GetResult(socket->Connect(done.callback())));
  EXPECT_EQ(peer_.last_client_alert, 109);
  socket.reset();
  httpps::ClientOptions options;
  options.no_alpn_http11 = true;
  socket = Make(true, nullptr, std::nullopt, false, options);
  EXPECT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
  EXPECT_FALSE(peer_.client_offered_alpn);
  EXPECT_EQ(socket->GetNegotiatedProtocol(), NextProto::kProtoHTTP11);
}

TEST_F(HttppsClientSocketTest, UnauthenticatedLibraryModeCannotReachBrowser) {
  httpps::ClientOptions options;
  options.allow_unauthenticated = true;
  auto socket = Make(false, nullptr, std::nullopt, false, options);
  TestCompletionCallback done;
  EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, done.GetResult(socket->Connect(done.callback())));
  EXPECT_EQ(peer_.client_hellos, 0);
}

TEST(HttppsLibraryTest, UnauthenticatedOptInStillChecksMacAndPreservesTicketLineage) {
  for (bool bad_proof : {false, true}) {
    Peer peer;
    peer.mode = SYNCHRONOUS;
    peer.write_chunk = peer.read_chunk = 65536;
    peer.bad_proof = bad_proof;
    httpps::ClientOptions options;
    options.ordinary_httpps = false;
    options.allow_unauthenticated = true;
    httpps::Client client("localhost", {}, false, options);
    ASSERT_TRUE(client.Start());
    auto output = client.TakeOutput();
    ASSERT_EQ(static_cast<int>(output.size()), peer.OnWrite(
        std::string(output.begin(), output.end())).result);
    ASSERT_TRUE(client.OutputFlushed());
    const auto wire = peer.OnRead();
    auto bytes = Octets(wire.data);
    Bytes application;
    bool accepted = true;
    while (!bytes.empty() && accepted) {
      ASSERT_GE(bytes.size(), 5u);
      const size_t length = 5 + (size_t(bytes[3]) << 8) + bytes[4];
      ASSERT_LE(length, bytes.size());
      accepted = client.Receive(bytes.first(length), &application);
      bytes = bytes.subspan(length);
    }
    EXPECT_EQ(accepted, !bad_proof);
    if (bad_proof) {
      EXPECT_FALSE(client.established());
      continue;
    }
    EXPECT_EQ(client.authentication(), httpps::Authentication::kUnauthenticated);
    EXPECT_FALSE(client.certificate_verification_pending());
    output = client.TakeOutput();
    ASSERT_FALSE(output.empty());
    EXPECT_EQ(static_cast<int>(output.size()), peer.OnWrite(
        std::string(output.begin(), output.end())).result);
    EXPECT_TRUE(client.OutputFlushed());
    EXPECT_TRUE(client.established());
    auto ticket = peer.Ticket();
    ticket.authentication = httpps::Authentication::kUnauthenticated;
    httpps::Client authenticated("localhost", {peer.root});
    EXPECT_FALSE(authenticated.Start(&ticket));
    httpps::Client unauthenticated("localhost", {}, false, options);
    EXPECT_TRUE(unauthenticated.Start(&ticket));
    ticket.authentication = httpps::Authentication::kCertificate;
    httpps::Client no_downgrade("localhost", {}, false, options);
    EXPECT_FALSE(no_downgrade.Start(&ticket));
  }
}

TEST_F(HttppsClientSocketTest, ApplicationAuthenticatorApiHasConnectionLifetime) {
  auto socket = Make();
  SSLClientSocket* api = socket.get();
  Bytes request;
  EXPECT_FALSE(api->RequestHttppsServerAuthenticator(Bytes{1}, {}, &request));
  TestCompletionCallback done;
  ASSERT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
  ASSERT_TRUE(api->RequestHttppsServerAuthenticator(Bytes{1}, {}, &request));
  EXPECT_EQ(request.front(), 17);
  EXPECT_TRUE(api->CancelHttppsAuthenticator(request));
  EXPECT_FALSE(api->CancelHttppsAuthenticator(request));
  EXPECT_FALSE(api->RequestHttppsServerAuthenticator(Bytes{1}, {}, &request));
  EXPECT_FALSE(api->RequestHttppsServerAuthenticator(Bytes(256), {}, &request));
  EXPECT_TRUE(peer_.received_application.empty());  // No invented HTTP framing.
  socket->Disconnect();
  EXPECT_FALSE(api->RequestHttppsServerAuthenticator(Bytes{2}, {}, &request));
  bool authenticated = true;
  EXPECT_FALSE(api->ValidateHttppsServerAuthenticator({}, {}, &authenticated));
  EXPECT_FALSE(authenticated);
}

TEST_F(HttppsClientSocketTest, EarlyExporterApiRequiresLivePskConnection) {
  peer_.resume_ticket = peer_.Ticket();
  auto socket = Make(true, nullptr, peer_.resume_ticket, true);
  SSLClientSocket* api = socket.get();
  std::array<uint8_t, 32> exported{};
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED, api->ExportEarlyKeyingMaterial("test", {}, exported));
  TestCompletionCallback done;
  ASSERT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
  EXPECT_EQ(OK, api->ExportEarlyKeyingMaterial("test", {}, exported));
  EXPECT_NE(exported, (std::array<uint8_t, 32>{}));
  socket->Disconnect();
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED, api->ExportEarlyKeyingMaterial("test", {}, exported));
}

TEST_F(HttppsClientSocketTest, ResumptionWithoutEarlyDataCompletesHandshake) {
  peer_.resume_ticket = peer_.Ticket();
  auto socket = Make(true, nullptr, peer_.resume_ticket);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  EXPECT_EQ(1, peer_.client_finished);
  EXPECT_EQ(0, peer_.end_of_early_data);
  EXPECT_TRUE(peer_.received_early.empty());
  SSLInfo info;
  ASSERT_TRUE(socket->GetSSLInfo(&info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, info.handshake_type);
  EXPECT_FALSE(info.early_data_accepted);
}

TEST_F(HttppsClientSocketTest, EarlyExporterDoesNotRequireEarlyDataPermission) {
  peer_.resume_ticket = peer_.Ticket();
  peer_.resume_ticket->max_early_data = 0;
  auto socket = Make(true, nullptr, peer_.resume_ticket);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  std::array<uint8_t, 32> exported{};
  EXPECT_EQ(OK, socket->ExportEarlyKeyingMaterial("test", {}, exported));
  EXPECT_NE(exported, (std::array<uint8_t, 32>{}));
  EXPECT_TRUE(peer_.received_early.empty());
}

TEST_F(HttppsClientSocketTest, RejectedTicketInvalidatesEarlyExporter) {
  peer_.resume_ticket = peer_.Ticket();
  peer_.reject_ticket = true;
  auto socket = Make(true, nullptr, peer_.resume_ticket);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  std::array<uint8_t, 32> exported{};
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED,
            socket->ExportEarlyKeyingMaterial("test", {}, exported));
  SSLInfo info;
  ASSERT_TRUE(socket->GetSSLInfo(&info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, info.handshake_type);
}

TEST(HttppsLibraryTest, TicketModesCannotBroadenAcrossSuccessors) {
  Peer peer;
  peer.mode = SYNCHRONOUS;
  peer.write_chunk = peer.read_chunk = 65536;
  auto ticket = peer.Ticket();
  ticket.allowed_psk_modes = {1};
  peer.resume_ticket = ticket;
  httpps::ClientOptions options;
  options.psk_modes = {0, 1};
  httpps::Client client("localhost", {peer.root}, false, options);
  ASSERT_TRUE(client.Start(&ticket));
  auto output = client.TakeOutput();
  const auto hello = ByteSpan(output).subspan(httpps::kPreface.size() + 5);
  EXPECT_EQ(HelloExtension(hello, 45), (Bytes{1, 1}));
  ASSERT_EQ(static_cast<int>(output.size()), peer.OnWrite(
      std::string(output.begin(), output.end())).result);
  ASSERT_TRUE(client.OutputFlushed());
  auto receive = [&] {
    const auto wire = peer.OnRead();
    auto bytes = Octets(wire.data);
    Bytes application;
    while (!bytes.empty()) {
      ASSERT_GE(bytes.size(), 5u);
      const size_t length = 5 + (size_t(bytes[3]) << 8) + bytes[4];
      ASSERT_LE(length, bytes.size());
      ASSERT_TRUE(client.Receive(bytes.first(length), &application));
      bytes = bytes.subspan(length);
    }
  };
  receive();
  output = client.TakeOutput();
  ASSERT_FALSE(output.empty());
  ASSERT_EQ(static_cast<int>(output.size()), peer.OnWrite(
      std::string(output.begin(), output.end())).result);
  ASSERT_TRUE(client.OutputFlushed());
  ASSERT_TRUE(client.established());
  peer.NewTicket();
  receive();
  auto successors = client.TakeTickets();
  ASSERT_EQ(successors.size(), 1u);
  EXPECT_EQ(successors.front().allowed_psk_modes, (std::vector<uint8_t>{1}));

  options.psk_modes = {0};
  httpps::Client fresh("localhost", {peer.root}, false, options);
  ASSERT_TRUE(fresh.Start(&ticket, {}, true));
  output = fresh.TakeOutput();
  bool offered = true;
  HelloExtension(ByteSpan(output).subspan(httpps::kPreface.size() + 5), 41, &offered);
  EXPECT_FALSE(offered);
  EXPECT_FALSE(fresh.early_data_available());
  httpps::Client early("localhost", {peer.root}, false, options);
  EXPECT_FALSE(early.Start(&ticket, Bytes{1}));
  EXPECT_TRUE(early.TakeOutput().empty());
}

TEST_F(HttppsClientSocketTest, EarlyDataWaitsForCachedCertificateVerification) {
  peer_.resume_ticket = peer_.Ticket();
  DeferredCertVerifier verifier;
  auto socket = Make(false, &verifier, peer_.resume_ticket, true);
  TestCompletionCallback connect;
  ASSERT_EQ(ERR_IO_PENDING, socket->Connect(connect.callback()));
  ASSERT_TRUE(verifier.active);
  EXPECT_EQ(0, peer_.client_hellos);
  auto request = base::MakeRefCounted<StringIOBuffer>("GET / HTTP/1.1\r\n\r\n");
  TestCompletionCallback write;
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED,
            socket->Write(request.get(), request->size(), write.callback(),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  verifier.Complete(OK);
  ASSERT_EQ(OK, connect.WaitForResult());
  EXPECT_EQ(1, peer_.client_hellos);
  EXPECT_EQ(0, peer_.client_finished);
  EXPECT_TRUE(socket->IsConnectedAndIdle());
  ASSERT_EQ(request->size(),
            write.GetResult(socket->Write(request.get(), request->size(),
                                          write.callback(),
                                          TRAFFIC_ANNOTATION_FOR_TESTS)));
  EXPECT_EQ("GET / HTTP/1.1\r\n\r\n", peer_.received_early);
  EXPECT_TRUE(peer_.received_application.empty());
  TestCompletionCallback confirm;
  ASSERT_EQ(OK,
            confirm.GetResult(socket->ConfirmHandshake(confirm.callback())));
  EXPECT_EQ(1, peer_.end_of_early_data);
  EXPECT_EQ(1, peer_.client_finished);
  SSLInfo info;
  ASSERT_TRUE(socket->GetSSLInfo(&info));
  EXPECT_TRUE(info.early_data_accepted);
}

TEST_F(HttppsClientSocketTest, EarlyDataRejectionDoesNotReplayApplication) {
  for (bool reject_ticket : {false, true}) {
    SCOPED_TRACE(reject_ticket);
    peer_.resume_ticket = peer_.Ticket();
    peer_.accept_early_data = false;
    peer_.reject_ticket = reject_ticket;
    auto socket = Make(true, nullptr, peer_.resume_ticket, true);
    TestCompletionCallback connect;
    ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
    auto request = base::MakeRefCounted<StringIOBuffer>("safe request");
    TestCompletionCallback write;
    ASSERT_EQ(request->size(),
              write.GetResult(socket->Write(request.get(), request->size(),
                                            write.callback(),
                                            TRAFFIC_ANNOTATION_FOR_TESTS)));
    EXPECT_EQ(static_cast<size_t>(request->size()),
              peer_.discarded_early_bytes);
    TestCompletionCallback confirm;
    EXPECT_EQ(ERR_EARLY_DATA_REJECTED,
              confirm.GetResult(socket->ConfirmHandshake(confirm.callback())));
    EXPECT_FALSE(socket->IsConnected());
    EXPECT_TRUE(peer_.received_early.empty());
    EXPECT_TRUE(peer_.received_application.empty());
    EXPECT_EQ(0, peer_.end_of_early_data);
    tasks_.RunUntilIdle();
  }
}

TEST_F(HttppsClientSocketTest,
       ConfirmBeforeUnsafeWriteSendsNoEarlyApplication) {
  peer_.resume_ticket = peer_.Ticket();
  auto socket = Make(true, nullptr, peer_.resume_ticket, true);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  EXPECT_EQ(0, peer_.client_finished);
  TestCompletionCallback confirm;
  ASSERT_EQ(OK,
            confirm.GetResult(socket->ConfirmHandshake(confirm.callback())));
  EXPECT_EQ(1, peer_.client_finished);
  EXPECT_EQ(1, peer_.end_of_early_data);
  EXPECT_TRUE(peer_.received_early.empty());
  auto request =
      base::MakeRefCounted<StringIOBuffer>("POST / HTTP/1.1\r\n\r\n");
  TestCompletionCallback write;
  EXPECT_EQ(request->size(),
            write.GetResult(socket->Write(request.get(), request->size(),
                                          write.callback(),
                                          TRAFFIC_ANNOTATION_FOR_TESTS)));
  EXPECT_EQ("POST / HTTP/1.1\r\n\r\n", peer_.received_application);
}

TEST_F(HttppsClientSocketTest, ConfirmWaitsForPendingEarlyWrite) {
  peer_.resume_ticket = peer_.Ticket();
  auto socket = Make(true, nullptr, peer_.resume_ticket, true);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  auto request = base::MakeRefCounted<StringIOBuffer>("early request");
  TestCompletionCallback write;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Write(request.get(), request->size(), write.callback(),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  TestCompletionCallback confirm;
  ASSERT_EQ(ERR_IO_PENDING, socket->ConfirmHandshake(confirm.callback()));
  EXPECT_FALSE(socket->IsConnectedAndIdle());
  EXPECT_EQ(request->size(), write.WaitForResult());
  EXPECT_EQ(OK, confirm.WaitForResult());
  EXPECT_EQ("early request", peer_.received_early);
  EXPECT_EQ(1, peer_.client_finished);
}

TEST_F(HttppsClientSocketTest, ConfirmAndReadShareOnePendingHandshake) {
  for (bool read_first : {false, true}) {
    SCOPED_TRACE(read_first);
    peer_.resume_ticket = peer_.Ticket();
    peer_.application_after_finished = "reply";
    auto socket = Make(true, nullptr, peer_.resume_ticket, true);
    TestCompletionCallback connect;
    ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
    auto response = base::MakeRefCounted<IOBufferWithSize>(100);
    TestCompletionCallback read;
    TestCompletionCallback confirm;
    if (read_first) {
      ASSERT_EQ(ERR_IO_PENDING, socket->Read(response.get(), response->size(),
                                             read.callback()));
      ASSERT_EQ(ERR_IO_PENDING, socket->ConfirmHandshake(confirm.callback()));
    } else {
      ASSERT_EQ(ERR_IO_PENDING, socket->ConfirmHandshake(confirm.callback()));
      ASSERT_EQ(ERR_IO_PENDING, socket->Read(response.get(), response->size(),
                                             read.callback()));
    }
    EXPECT_EQ(OK, confirm.WaitForResult());
    EXPECT_EQ(5, read.WaitForResult());
    EXPECT_EQ("reply", std::string(response->data(), 5));
    EXPECT_EQ(1, peer_.client_finished);
    EXPECT_TRUE(peer_.received_early.empty());
    EXPECT_TRUE(peer_.received_application.empty());
  }
}

TEST_F(HttppsClientSocketTest,
       WriteDuringConfirmationDoesNotInterleaveRecords) {
  peer_.resume_ticket = peer_.Ticket();
  auto socket = Make(true, nullptr, peer_.resume_ticket, true);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  // The server flight is read much faster than a write can finish. A new user
  // write must not overwrite a pending Finished or be overwritten by it.
  peer_.read_chunk = 20000;
  peer_.write_chunk = 1;
  TestCompletionCallback confirm;
  ASSERT_EQ(ERR_IO_PENDING, socket->ConfirmHandshake(confirm.callback()));
  auto request = base::MakeRefCounted<StringIOBuffer>(std::string(2048, 'x'));
  TestCompletionCallback write;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Write(request.get(), request->size(), write.callback(),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(OK, confirm.WaitForResult());
  EXPECT_EQ(request->size(), write.WaitForResult());
  EXPECT_EQ(std::string(2048, 'x'), peer_.received_application);
  EXPECT_TRUE(peer_.received_early.empty());
  EXPECT_EQ(1, peer_.client_finished);
}

TEST_F(HttppsClientSocketTest, EarlyRejectionCompletesReadAndConfirmOnce) {
  peer_.resume_ticket = peer_.Ticket();
  peer_.accept_early_data = false;
  auto socket = Make(true, nullptr, peer_.resume_ticket, true);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  auto request = base::MakeRefCounted<StringIOBuffer>("safe request");
  TestCompletionCallback write;
  ASSERT_EQ(request->size(),
            write.GetResult(socket->Write(request.get(), request->size(),
                                          write.callback(),
                                          TRAFFIC_ANNOTATION_FOR_TESTS)));
  auto response = base::MakeRefCounted<IOBufferWithSize>(100);
  TestCompletionCallback read;
  TestCompletionCallback confirm;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Read(response.get(), response->size(), read.callback()));
  ASSERT_EQ(ERR_IO_PENDING, socket->ConfirmHandshake(confirm.callback()));
  EXPECT_EQ(ERR_EARLY_DATA_REJECTED, confirm.WaitForResult());
  EXPECT_EQ(ERR_EARLY_DATA_REJECTED, read.WaitForResult());
  EXPECT_TRUE(peer_.received_application.empty());
  EXPECT_FALSE(socket->IsConnected());
  tasks_.RunUntilIdle();
}

TEST_F(HttppsClientSocketTest, ConfirmCallbackCanDestroyPendingReader) {
  peer_.resume_ticket = peer_.Ticket();
  auto socket = Make(true, nullptr, peer_.resume_ticket, true);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  auto response = base::MakeRefCounted<IOBufferWithSize>(100);
  int reads = 0;
  int confirmations = 0;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Read(response.get(), response->size(),
                         base::BindLambdaForTesting([&](int) { ++reads; })));
  ASSERT_EQ(ERR_IO_PENDING, socket->ConfirmHandshake(
                                base::BindLambdaForTesting([&](int result) {
                                  EXPECT_EQ(OK, result);
                                  ++confirmations;
                                  socket.reset();
                                })));
  tasks_.RunUntilIdle();
  EXPECT_EQ(1, confirmations);
  EXPECT_EQ(0, reads);
  EXPECT_FALSE(socket);
}

TEST_F(HttppsClientSocketTest, ConnectCallbackCanStartPendingApplicationRead) {
  auto socket = Make();
  auto response = base::MakeRefCounted<IOBufferWithSize>(100);
  TestCompletionCallback read;
  int confirmations = 0;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Connect(base::BindLambdaForTesting([&](int result) {
              ASSERT_EQ(OK, result);
              ++confirmations;
              EXPECT_EQ(ERR_IO_PENDING,
                        socket->Read(response.get(), response->size(),
                                     read.callback()));
            })));
  tasks_.RunUntilIdle();
  EXPECT_EQ(1, confirmations);
  EXPECT_FALSE(read.have_result());
  ASSERT_TRUE(socket->IsConnected());
  peer_.Application("reply");
  peer_.socket()->OnReadComplete(peer_.OnRead());
  EXPECT_EQ(5, read.WaitForResult());
  EXPECT_EQ("reply", std::string(response->data(), 5));
}

TEST_F(HttppsClientSocketTest, CachedVerificationSharesHandshakeDeadline) {
  peer_.resume_ticket = peer_.Ticket();
  DeferredCertVerifier verifier;
  auto socket = Make(false, &verifier, peer_.resume_ticket, true);
  TestCompletionCallback connect;
  ASSERT_EQ(ERR_IO_PENDING, socket->Connect(connect.callback()));
  ASSERT_TRUE(verifier.active);
  tasks_.FastForwardBy(base::Seconds(30));
  EXPECT_EQ(ERR_TIMED_OUT, connect.WaitForResult());
  EXPECT_FALSE(verifier.active);
  EXPECT_EQ(0, peer_.client_hellos);
  EXPECT_FALSE(socket->IsConnected());
}

TEST_F(HttppsClientSocketTest, MalformedCachedChainNeverAuthorizesEarlyData) {
  peer_.resume_ticket = peer_.Ticket();
  auto cached = *peer_.resume_ticket;
  cached.certificates = {"not a certificate"};
  auto socket = Make(true, nullptr, std::move(cached), true);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  EXPECT_EQ(1, peer_.client_finished);
  EXPECT_EQ(0, peer_.end_of_early_data);
  EXPECT_TRUE(peer_.received_early.empty());
  SSLInfo info;
  ASSERT_TRUE(socket->GetSSLInfo(&info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, info.handshake_type);
  EXPECT_FALSE(info.early_data_accepted);
}

TEST_F(HttppsClientSocketTest, EarlyConnectStillHasAbsoluteHandshakeDeadline) {
  peer_.resume_ticket = peer_.Ticket();
  auto socket = Make(true, nullptr, peer_.resume_ticket, true);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  EXPECT_EQ(0, peer_.client_finished);
  SSLInfo before;
  ASSERT_TRUE(socket->GetSSLInfo(&before));
  tasks_.FastForwardBy(base::Seconds(30));
  EXPECT_FALSE(socket->IsConnected());
  TestCompletionCallback confirm;
  EXPECT_EQ(ERR_TIMED_OUT, socket->ConfirmHandshake(confirm.callback()));
  SSLInfo after;
  ASSERT_TRUE(socket->GetSSLInfo(&after));
  EXPECT_EQ(before.cert, after.cert);
  EXPECT_EQ(before.connection_status, after.connection_status);
  EXPECT_EQ(before.client_cert_sent, after.client_cert_sent);
  socket->Disconnect();
  EXPECT_FALSE(socket->GetSSLInfo(&after));
}

TEST_F(HttppsClientSocketTest, BrowserVerifierSyncAndAsyncShareTrustPolicy) {
  for (bool asynchronous : {false, true}) {
    SCOPED_TRACE(asynchronous);
    peer_.mode = SYNCHRONOUS;
    peer_.read_chunk = peer_.write_chunk = 20000;
    ParamRecordingMockCertVerifier verifier;
    verifier.set_async(asynchronous);
    CertVerifyResult verified;
    verified.verified_cert = peer_.certificate();
    verified.is_issued_by_known_root = true;
    verifier.AddResultForCert(verified.verified_cert, verified, OK);
    auto socket = Make(/*trust=*/false, &verifier);
    TestCompletionCallback callback;
    int result = socket->Connect(callback.callback());
    if (asynchronous) {
      EXPECT_EQ(ERR_IO_PENDING, result);
      EXPECT_EQ(0, peer_.client_finished);
      EXPECT_FALSE(socket->IsConnected());
    }
    ASSERT_EQ(OK, callback.GetResult(result));
    EXPECT_EQ(1, peer_.client_finished);
    ASSERT_EQ(1u, verifier.GetVerifyParams().size());
    const auto& params = verifier.GetVerifyParams()[0];
    EXPECT_EQ("localhost", params.hostname());
    EXPECT_EQ(CertVerifier::VERIFY_HTTPPS_SERVER |
                  CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES,
              params.flags());
    SSLInfo info;
    ASSERT_TRUE(socket->GetSSLInfo(&info));
    EXPECT_TRUE(info.is_issued_by_known_root);
    EXPECT_EQ(verified.verified_cert, info.cert);
    auto request = base::MakeRefCounted<StringIOBuffer>("request");
    TestCompletionCallback write;
    EXPECT_EQ(request->size(),
              write.GetResult(socket->Write(request.get(), request->size(),
                                            write.callback(),
                                            TRAFFIC_ANNOTATION_FOR_TESTS)));
    EXPECT_EQ("request", peer_.received_application);
  }
}

TEST_F(HttppsClientSocketTest, FreshAndCachedEvidenceReachCurrentBrowserPolicy) {
  peer_.leaf_extensions[5] = Bytes{1, 0, 0, 3, 'o', 'c', 's'};
  peer_.leaf_extensions[18] = Bytes{0, 3, 0, 1, 's'};
  // This tests forwarding and policy decisions, not fake OCSP cryptography.
  // The mock verifier is the trust oracle; real provider tests live in net/cert.
  for (bool resumed : {false, true}) {
    SCOPED_TRACE(resumed);
    ParamRecordingMockCertVerifier verifier;
    verifier.set_async(true);
    CertVerifyResult verified;
    verified.verified_cert = peer_.certificate();
    verifier.AddResultForCert(verified.verified_cert, verified, OK);
    if (resumed)
      peer_.resume_ticket = peer_.Ticket();
    auto socket = Make(false, &verifier, peer_.resume_ticket, resumed);
    TestCompletionCallback connect, confirm;
    ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
    ASSERT_EQ(1u, verifier.GetVerifyParams().size());
    EXPECT_EQ("ocs", verifier.GetVerifyParams()[0].ocsp_response());
    EXPECT_EQ(std::string("\0\3\0\1s", 5), verifier.GetVerifyParams()[0].sct_list());
    EXPECT_TRUE(peer_.requested_ocsp);
    EXPECT_TRUE(peer_.requested_scts);
    ASSERT_EQ(OK, confirm.GetResult(socket->ConfirmHandshake(confirm.callback())));
    EXPECT_EQ(1, peer_.client_finished);
  }
}

TEST_F(HttppsClientSocketTest, MalformedOrUnsolicitedEvidenceCannotReachVerifier) {
  peer_.write_chunk = 65536;
  for (const Bytes& status : {Bytes{}, Bytes{1}, Bytes{1, 0, 0, 0},
                             Bytes{1, 0, 0, 2, 1}, Bytes{2, 0, 0, 1, 1}}) {
    peer_.leaf_extensions[5] = status;
    ParamRecordingMockCertVerifier verifier;
    auto socket = Make(false, &verifier);
    TestCompletionCallback connect;
    EXPECT_LT(connect.GetResult(socket->Connect(connect.callback())), 0);
    EXPECT_TRUE(verifier.GetVerifyParams().empty());
    EXPECT_EQ(0, peer_.client_finished);
    EXPECT_EQ(status.empty() || status[0] == 1 ? 50 : 47, peer_.last_client_alert);
  }
  for (const Bytes& list : {Bytes{}, Bytes{0}, Bytes{0, 0}, Bytes{0, 1, 0},
                           Bytes{0, 2, 0, 0}, Bytes{0, 3, 0, 2, 1}}) {
    peer_.leaf_extensions = {{18, list}};
    ParamRecordingMockCertVerifier verifier;
    auto socket = Make(false, &verifier);
    TestCompletionCallback connect;
    EXPECT_LT(connect.GetResult(socket->Connect(connect.callback())), 0);
    EXPECT_TRUE(verifier.GetVerifyParams().empty());
    EXPECT_EQ(0, peer_.client_finished);
    EXPECT_EQ(50, peer_.last_client_alert);
  }
  peer_.leaf_extensions = {{5, Bytes{1, 0, 0, 1, 1}}};
  auto socket = Make();  // Standalone offline policy does not advertise status.
  TestCompletionCallback connect;
  EXPECT_LT(connect.GetResult(socket->Connect(connect.callback())), 0);
  EXPECT_FALSE(peer_.requested_ocsp);
  EXPECT_EQ(0, peer_.client_finished);
  EXPECT_EQ(110, peer_.last_client_alert);
}

TEST_F(HttppsClientSocketTest, MustStapleUsesCurrentBrowserPolicyForFreshAndCachedEvidence) {
  peer_.CertificateFeatures(Bytes{0x30, 3, 2, 1, 5});
  peer_.leaf_extensions[5] = Bytes{1, 0, 0, 3, 'o', 'c', 's'};
  // The browser verifier mock is the trust oracle for this routing test, not
  // a cryptographic OCSP fixture. No private anchor may bypass that oracle.
  for (bool good : {false, true}) {
    for (bool resumed : {false, true}) {
      SCOPED_TRACE(good);
      SCOPED_TRACE(resumed);
      peer_.resume_ticket = resumed ? std::optional(peer_.Ticket()) : std::nullopt;
      ParamRecordingMockCertVerifier verifier;
      CertVerifyResult verified;
      verified.verified_cert = peer_.certificate();
      if (good) {
        verified.ocsp_result.response_status = bssl::OCSPVerifyResult::PROVIDED;
        verified.ocsp_result.revocation_status = bssl::OCSPRevocationStatus::GOOD;
      }
      verifier.AddResultForCert(verified.verified_cert, verified, OK);
      auto socket = Make(false, &verifier, peer_.resume_ticket, resumed);
      TestCompletionCallback connect, confirm;
      int result = connect.GetResult(socket->Connect(connect.callback()));
      if (good) {
        EXPECT_EQ(OK, result);
        EXPECT_EQ(OK, confirm.GetResult(socket->ConfirmHandshake(confirm.callback())));
        EXPECT_EQ(1, peer_.client_finished);
        SSLInfo info;
        ASSERT_TRUE(socket->GetSSLInfo(&info));
        EXPECT_EQ(resumed ? SSLInfo::HANDSHAKE_RESUME : SSLInfo::HANDSHAKE_FULL,
                  info.handshake_type);
      } else {
        EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT, result);
        EXPECT_EQ(0, peer_.client_finished);
        EXPECT_TRUE(peer_.received_early.empty());
      }
      EXPECT_FALSE(verifier.GetVerifyParams().empty());
      for (const auto& params : verifier.GetVerifyParams())
        EXPECT_EQ("ocs", params.ocsp_response());
    }
  }
}

TEST_F(HttppsClientSocketTest, MustStapleCannotBeBypassedByPrivateAnchorOrCachedBytes) {
  peer_.CertificateFeatures(Bytes{0x30, 3, 2, 1, 5});
  peer_.leaf_extensions[5] = Bytes{1, 0, 0, 3, 'o', 'c', 's'};
  // A real private path uses cryptographic evidence verification. The unrelated
  // browser mock cannot turn malformed OCSP bytes into an authenticated staple,
  // even when it claims GOOD. Real signed positives are covered by the browser
  // evidence interop tests, including private/DANE paths and resumption.
  for (bool mock_good : {false, true}) {
    for (bool resumed : {false, true}) {
      SCOPED_TRACE(mock_good);
      SCOPED_TRACE(resumed);
      peer_.resume_ticket = resumed ? std::optional(peer_.Ticket()) : std::nullopt;
      ParamRecordingMockCertVerifier verifier;
      CertVerifyResult verified;
      verified.verified_cert = peer_.certificate();
      if (mock_good) {
        verified.ocsp_result.response_status = bssl::OCSPVerifyResult::PROVIDED;
        verified.ocsp_result.revocation_status = bssl::OCSPRevocationStatus::GOOD;
      }
      verifier.AddResultForCert(verified.verified_cert, verified, OK);
      auto socket = Make(true, &verifier, peer_.resume_ticket, resumed);
      TestCompletionCallback connect, confirm;
      EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
                connect.GetResult(socket->Connect(connect.callback())));
      EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
                confirm.GetResult(socket->ConfirmHandshake(confirm.callback())));
      EXPECT_EQ(0, peer_.client_finished);
      EXPECT_EQ(0, peer_.end_of_early_data);
      EXPECT_TRUE(peer_.received_early.empty());
      EXPECT_TRUE(peer_.received_application.empty());
      EXPECT_FALSE(socket->IsConnected());
      EXPECT_TRUE(verifier.GetVerifyParams().empty());
    }
  }
}

TEST_F(HttppsClientSocketTest, UnofferedCertificateFeatureAddsNoClientRequirement) {
  peer_.CertificateFeatures(Bytes{0x30, 3, 2, 1, 17});
  ParamRecordingMockCertVerifier verifier;
  CertVerifyResult verified;
  verified.verified_cert = peer_.certificate();
  verifier.AddResultForCert(verified.verified_cert, verified, OK);
  auto socket = Make(true, &verifier);
  TestCompletionCallback connect;
  EXPECT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  EXPECT_EQ(1, peer_.client_finished);
}

TEST_F(HttppsClientSocketTest, MandatoryTlsSctRequiresCurrentVerifiedTlsEvidence) {
  peer_.CertificateFeatures(Bytes{0x30, 3, 2, 1, 18});
  enum Evidence { kMissing, kInvalidSignature, kWrongOrigin, kVerified };
  // The mock verifier is the browser policy oracle, not a replacement for
  // cryptographic tests. This verifies placement, provenance, and cache gates.
  for (Evidence evidence : {kMissing, kInvalidSignature, kWrongOrigin, kVerified}) {
    for (bool resumed : {false, true}) {
      SCOPED_TRACE(evidence);
      SCOPED_TRACE(resumed);
      peer_.leaf_extensions.clear();
      if (evidence != kMissing)
        peer_.leaf_extensions[18] = Bytes{0, 3, 0, 1, 's'};
      peer_.resume_ticket = resumed ? std::optional(peer_.Ticket()) : std::nullopt;
      ParamRecordingMockCertVerifier verifier;
      verifier.set_async(true);
      CertVerifyResult verified;
      verified.verified_cert = peer_.certificate();
      auto sct = base::MakeRefCounted<ct::SignedCertificateTimestamp>();
      sct->origin = evidence == kWrongOrigin
          ? ct::SignedCertificateTimestamp::SCT_EMBEDDED
          : ct::SignedCertificateTimestamp::SCT_FROM_TLS_EXTENSION;
      verified.scts.emplace_back(sct, evidence == kInvalidSignature
          ? ct::SCT_STATUS_INVALID_SIGNATURE : ct::SCT_STATUS_OK);
      verifier.AddResultForCert(verified.verified_cert, verified, OK);
      auto socket = Make(true, &verifier, peer_.resume_ticket, resumed);
      TestCompletionCallback connect, confirm;
      const int result = connect.GetResult(socket->Connect(connect.callback()));
      if (evidence == kVerified) {
        EXPECT_EQ(OK, result);
        EXPECT_EQ(OK, confirm.GetResult(socket->ConfirmHandshake(confirm.callback())));
        EXPECT_EQ(1, peer_.client_finished);
      } else {
        EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT, result);
        EXPECT_EQ(0, peer_.client_finished);
        EXPECT_TRUE(peer_.received_early.empty());
      }
      EXPECT_FALSE(verifier.GetVerifyParams().empty());
    }
  }
}

TEST_F(HttppsClientSocketTest, UnofferedTlsSctFeatureDoesNotActivateOfflineCt) {
  peer_.CertificateFeatures(Bytes{0x30, 3, 2, 1, 18});
  auto socket = Make();
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  EXPECT_FALSE(peer_.requested_scts);
  EXPECT_EQ(1, peer_.client_finished);
}

TEST_F(HttppsClientSocketTest, CTv2RealSignatureAppliesToPrivateAnchorAndCachedEarly) {
  auto policy = peer_.TransparencyPolicy();
  httpps::ClientOptions options;
  options.ct_v2_policy = policy;
  for (bool resumed : {false, true}) {
    SCOPED_TRACE(resumed);
    peer_.resume_ticket = resumed ? std::optional(peer_.Ticket()) : std::nullopt;
    if (peer_.resume_ticket)
      peer_.resume_ticket->ct_policy_context = policy->Context();
    auto socket = Make(true, nullptr, peer_.resume_ticket, resumed, options);
    TestCompletionCallback connect, confirm;
    ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
    EXPECT_TRUE(peer_.requested_ct_v2);
    EXPECT_TRUE(peer_.requested_ocsp);
    EXPECT_EQ(resumed ? 0 : 1, peer_.client_finished);
    ASSERT_EQ(OK, confirm.GetResult(socket->ConfirmHandshake(confirm.callback())));
    EXPECT_EQ(1, peer_.client_finished);
  }
}

TEST_F(HttppsClientSocketTest, CTv2TamperIsRejectedBeforeCachedEarlyOrFinished) {
  auto policy = peer_.TransparencyPolicy();
  httpps::ClientOptions options;
  options.ct_v2_policy = policy;
  peer_.leaf_extensions[52].back() ^= 1;
  for (bool resumed : {false, true}) {
    SCOPED_TRACE(resumed);
    peer_.resume_ticket = resumed ? std::optional(peer_.Ticket()) : std::nullopt;
    if (peer_.resume_ticket)
      peer_.resume_ticket->ct_policy_context = policy->Context();
    auto socket = Make(true, nullptr, peer_.resume_ticket, resumed, options);
    TestCompletionCallback connect;
    EXPECT_LT(connect.GetResult(socket->Connect(connect.callback())), 0);
    EXPECT_EQ(0, peer_.client_finished);
    EXPECT_TRUE(peer_.received_early.empty());
  }
}

TEST_F(HttppsClientSocketTest, CTv2CurrentBrowserIssuerAndDelayedTrustGateEarly) {
  auto policy = peer_.TransparencyPolicy();
  httpps::ClientOptions options;
  options.ct_v2_policy = policy;
  peer_.resume_ticket = peer_.Ticket();
  peer_.resume_ticket->ct_policy_context = policy->Context();
  DeferredCertVerifier verifier;
  auto socket = Make(false, &verifier, peer_.resume_ticket, true, options);
  TestCompletionCallback connect;
  ASSERT_EQ(ERR_IO_PENDING, socket->Connect(connect.callback()));
  EXPECT_TRUE(verifier.active);
  EXPECT_EQ(0, peer_.client_hellos);
  EXPECT_TRUE(peer_.received_early.empty());
  // The verifier's cancellation/error must not turn cached, correctly signed
  // CT into PKIX authorization or early-write permission.
  socket->Disconnect();
  EXPECT_FALSE(verifier.active);
  tasks_.RunUntilIdle();
  EXPECT_FALSE(connect.have_result());
  EXPECT_TRUE(peer_.received_early.empty());
}

TEST_F(HttppsClientSocketTest, CTv2IsNotAdvertisedOrTrustedWithoutExplicitPolicy) {
  peer_.TransparencyPolicy();
  auto socket = Make();
  TestCompletionCallback connect;
  EXPECT_LT(connect.GetResult(socket->Connect(connect.callback())), 0);
  EXPECT_FALSE(peer_.requested_ct_v2);
  EXPECT_EQ(0, peer_.client_finished);
}

TEST_F(HttppsClientSocketTest,
       BrowserRejectionCannotSendFinishedOrApplication) {
  for (bool asynchronous : {false, true}) {
    SCOPED_TRACE(asynchronous);
    ParamRecordingMockCertVerifier verifier;
    verifier.set_async(asynchronous);
    verifier.set_default_result(ERR_CERT_AUTHORITY_INVALID);
    auto socket = Make(/*trust=*/false, &verifier);
    TestCompletionCallback callback;
    EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
              callback.GetResult(socket->Connect(callback.callback())));
    EXPECT_EQ(1u, verifier.GetVerifyParams().size());
    EXPECT_EQ(1, peer_.client_hellos);
    EXPECT_EQ(0, peer_.client_finished);
    EXPECT_FALSE(socket->IsConnected());
    auto request = base::MakeRefCounted<StringIOBuffer>("must not leave");
    TestCompletionCallback write;
    EXPECT_LT(socket->Write(request.get(), request->size(), write.callback(),
                            TRAFFIC_ANNOTATION_FOR_TESTS),
              0);
    EXPECT_TRUE(peer_.received_application.empty());
    tasks_.RunUntilIdle();
  }
}

TEST_F(HttppsClientSocketTest, PendingBrowserVerificationBlocksApplication) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  DeferredCertVerifier verifier;
  auto socket = Make(/*trust=*/false, &verifier);
  TestCompletionCallback connect;
  ASSERT_EQ(ERR_IO_PENDING, socket->Connect(connect.callback()));
  ASSERT_TRUE(verifier.active);
  EXPECT_EQ(0, peer_.client_finished);
  EXPECT_FALSE(socket->IsConnected());
  auto request = base::MakeRefCounted<StringIOBuffer>("blocked");
  TestCompletionCallback write;
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED,
            socket->Write(request.get(), request->size(), write.callback(),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_TRUE(peer_.received_application.empty());
  verifier.Complete(OK);
  EXPECT_EQ(OK, connect.WaitForResult());
  EXPECT_FALSE(verifier.active);
  EXPECT_EQ(1, peer_.client_finished);
  EXPECT_TRUE(socket->IsConnected());
}

TEST_F(HttppsClientSocketTest, BrowserVerificationCancelledOnDisconnect) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  DeferredCertVerifier verifier;
  auto socket = Make(/*trust=*/false, &verifier);
  int callbacks = 0;
  ASSERT_EQ(
      ERR_IO_PENDING,
      socket->Connect(base::BindLambdaForTesting([&](int) { ++callbacks; })));
  ASSERT_TRUE(verifier.active);
  socket->Disconnect();
  EXPECT_FALSE(verifier.active);
  tasks_.FastForwardBy(base::Minutes(1));
  EXPECT_EQ(0, callbacks);
  EXPECT_EQ(0, peer_.client_finished);
}

TEST_F(HttppsClientSocketTest, BrowserVerificationSharesHandshakeDeadline) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  DeferredCertVerifier verifier;
  auto socket = Make(/*trust=*/false, &verifier);
  TestCompletionCallback callback;
  ASSERT_EQ(ERR_IO_PENDING, socket->Connect(callback.callback()));
  ASSERT_TRUE(verifier.active);
  tasks_.FastForwardBy(base::Seconds(30));
  EXPECT_EQ(ERR_TIMED_OUT, callback.WaitForResult());
  EXPECT_FALSE(verifier.active);
  EXPECT_EQ(0, peer_.client_finished);
  EXPECT_FALSE(socket->IsConnected());
}

TEST_F(HttppsClientSocketTest, MissingTrustNeverSendsHandshake) {
  auto socket = Make(false);
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_SSL_SERVER_CERT_BAD_FORMAT,
            socket->Connect(callback.callback()));
  EXPECT_FALSE(socket->IsConnected());
  EXPECT_TRUE(peer_.AllWriteDataConsumed());
}

TEST_F(HttppsClientSocketTest, TamperedServerFlightIsFatal) {
  peer_.tamper = true;
  auto socket = Make();
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR,
            callback.GetResult(socket->Connect(callback.callback())));
  EXPECT_FALSE(socket->IsConnected());
}

TEST_F(HttppsClientSocketTest, RecordHeaderFailuresReachProtocolAlerts) {
  const std::pair<Bytes, uint8_t> cases[] = {
      {Bytes{23, 3, 3, 0, 0}, 20},
      {Bytes{21, 3, 3, 0, 0}, 10},
      {Bytes{23, 3, 2, 0, 0}, 47},
      {Bytes{23, 3, 2, 0, 16}, 47},
      // Only the header is supplied: never wait for or allocate this body.
      {Bytes{23, 3, 3, 0x41, 1}, 22}};
  for (const auto& [record, expected] : cases) {
    SCOPED_TRACE(expected);
    peer_.mode = SYNCHRONOUS;
    peer_.read_chunk = peer_.write_chunk = 20000;
    auto socket = Make();
    TestCompletionCallback done;
    ASSERT_EQ(OK, done.GetResult(socket->Connect(done.callback())));
    peer_.RawRecord(record);
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(32);
    EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR,
              done.GetResult(socket->Read(buffer.get(), buffer->size(), done.callback())));
    EXPECT_EQ(peer_.last_client_alert, expected);
    EXPECT_FALSE(socket->IsConnected());
  }
}

TEST_F(HttppsClientSocketTest, AbsoluteHandshakeDeadline) {
  peer_.stall = true;
  auto socket = Make();
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING, socket->Connect(callback.callback()));
  tasks_.FastForwardBy(base::Seconds(30));
  EXPECT_EQ(ERR_TIMED_OUT, callback.WaitForResult());
  EXPECT_FALSE(socket->IsConnected());
}

TEST_F(HttppsClientSocketTest, DisconnectCancelsCallbacksAndDeadline) {
  peer_.stall = true;
  auto cancelled = Make();
  int count = 0;
  EXPECT_EQ(
      ERR_IO_PENDING,
      cancelled->Connect(base::BindLambdaForTesting([&](int) { ++count; })));
  cancelled->Disconnect();
  tasks_.FastForwardBy(base::Minutes(1));
  EXPECT_EQ(0, count);
}

TEST_F(HttppsClientSocketTest, QueuedEmptyRecordReadIsNotIdle) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  auto socket = Make();
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));
  for (int i = 0; i < 64; ++i) {
    peer_.Application("");
  }
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(32);
  TestCompletionCallback read;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Read(buffer.get(), buffer->size(), read.callback()));
  // The empty-record yield has no transport read or buffered payload, but the
  // caller still has a pending read and the socket must not be reused as idle.
  EXPECT_FALSE(socket->IsConnectedAndIdle());
  peer_.Application("ready");
  EXPECT_EQ(5, read.WaitForResult());
  EXPECT_EQ("ready", std::string(buffer->data(), 5));
  EXPECT_TRUE(socket->IsConnectedAndIdle());
}

TEST_F(HttppsClientSocketTest, PendingWriteRetainsBufferUntilCompletion) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  auto socket = Make();
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));
  peer_.mode = ASYNC;
  auto buffer = base::MakeRefCounted<StringIOBuffer>("request");
  int callbacks = 0;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Write(buffer.get(), buffer->size(),
                          base::BindLambdaForTesting([&](int result) {
                            EXPECT_EQ(buffer->size(), result);
                            EXPECT_TRUE(buffer->HasOneRef());
                            ++callbacks;
                          }),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_FALSE(buffer->HasOneRef());
  tasks_.RunUntilIdle();
  EXPECT_EQ(1, callbacks);
  EXPECT_TRUE(buffer->HasOneRef());
  EXPECT_EQ("request", peer_.received_application);
}

TEST_F(HttppsClientSocketTest, PostHandshakeRefusalPreservesPartialUserWrite) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  httpps::ClientOptions options;
  options.post_handshake_auth = true;
  auto socket = Make(true, nullptr, std::nullopt, false, options);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));

  peer_.mode = ASYNC;
  peer_.write_chunk = 7;
  auto request = base::MakeRefCounted<StringIOBuffer>("partially written request");
  TestCompletionCallback write, read;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Write(request.get(), request->size(), write.callback(),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  peer_.mode = SYNCHRONOUS;
  peer_.RequestClientAuth();
  peer_.Application("ready");
  auto response = base::MakeRefCounted<IOBufferWithSize>(32);
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Read(response.get(), response->size(), read.callback()));
  EXPECT_EQ(0, peer_.pha_finished);
  EXPECT_FALSE(socket->IsConnectedAndIdle());
  EXPECT_EQ(request->size(), write.WaitForResult());
  EXPECT_EQ(5, read.WaitForResult());
  EXPECT_EQ("ready", std::string(response->data(), 5));
  EXPECT_EQ("partially written request", peer_.received_application);
  EXPECT_EQ(1, peer_.pha_empty_certificates);
  EXPECT_EQ(1, peer_.pha_finished);
  EXPECT_TRUE(socket->IsConnectedAndIdle());
}

TEST_F(HttppsClientSocketTest, PostHandshakeRefusalUsesUpdatedApplicationEpoch) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  httpps::ClientOptions options;
  options.post_handshake_auth = true;
  auto socket = Make(true, nullptr, std::nullopt, false, options);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));
  peer_.KeyUpdate();
  peer_.RequestClientAuth(3);
  peer_.Application("after update");
  peer_.mode = ASYNC;
  peer_.write_chunk = 5;
  peer_.read_chunk = 2;
  auto response = base::MakeRefCounted<IOBufferWithSize>(32);
  TestCompletionCallback read, write;
  EXPECT_EQ(12, read.GetResult(socket->Read(response.get(), response->size(), read.callback())));
  EXPECT_EQ(1, peer_.key_updates);
  EXPECT_EQ(1, peer_.pha_empty_certificates);
  EXPECT_EQ(1, peer_.pha_finished);
  auto request = base::MakeRefCounted<StringIOBuffer>("new epoch");
  EXPECT_EQ(request->size(), write.GetResult(socket->Write(
      request.get(), request->size(), write.callback(), TRAFFIC_ANNOTATION_FOR_TESTS)));
  EXPECT_EQ("new epoch", peer_.received_application);
}

TEST_F(HttppsClientSocketTest, UserWriteWaitsForPartialPostHandshakeRefusal) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  httpps::ClientOptions options;
  options.post_handshake_auth = true;
  auto socket = Make(true, nullptr, std::nullopt, false, options);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));
  peer_.RequestClientAuth();
  peer_.Application("response");
  peer_.mode = ASYNC;
  peer_.read_chunk = 20000;
  peer_.write_chunk = 1;
  auto response = base::MakeRefCounted<IOBufferWithSize>(32);
  auto request = base::MakeRefCounted<StringIOBuffer>("queued user write");
  TestCompletionCallback read, write;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Read(response.get(), response->size(), read.callback()));
  // First exercise partial asynchronous control I/O to completion.
  tasks_.RunUntilIdle();
  EXPECT_EQ(8, read.WaitForResult());
  EXPECT_EQ(1, peer_.pha_finished);
  // A second exchange can be stalled exactly after reading the CR by using
  // synchronous reads and a held write, without relying on scheduler timing.
  peer_.mode = SYNCHRONOUS;
  peer_.RequestClientAuth(2);
  peer_.Application("second");
  peer_.hold_writes = true;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Read(response.get(), response->size(), read.callback()));
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Write(request.get(), request->size(), write.callback(),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_TRUE(peer_.received_application.empty());
  EXPECT_FALSE(request->HasOneRef());
  peer_.ReleaseWrite();
  EXPECT_EQ(request->size(), write.WaitForResult());
  EXPECT_EQ(6, read.WaitForResult());
  EXPECT_EQ("queued user write", peer_.received_application);
  EXPECT_EQ(2, peer_.pha_empty_certificates);
  EXPECT_EQ(2, peer_.pha_finished);
  EXPECT_TRUE(request->HasOneRef());
}

TEST_F(HttppsClientSocketTest, DisconnectInWriteCallbackDoesNotSkipQueuedControl) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  httpps::ClientOptions options;
  options.post_handshake_auth = true;
  auto socket = Make(true, nullptr, std::nullopt, false, options);
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));
  peer_.mode = ASYNC;
  auto request = base::MakeRefCounted<StringIOBuffer>("completed before control");
  int writes = 0, reads = 0;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Write(request.get(), request->size(),
                          base::BindLambdaForTesting([&](int result) {
                            EXPECT_EQ(request->size(), result);
                            ++writes;
                            socket->Disconnect();
                          }), TRAFFIC_ANNOTATION_FOR_TESTS));
  peer_.mode = SYNCHRONOUS;
  peer_.RequestClientAuth();
  auto response = base::MakeRefCounted<IOBufferWithSize>(32);
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Read(response.get(), response->size(),
                         base::BindLambdaForTesting([&](int) { ++reads; })));
  tasks_.RunUntilIdle();
  EXPECT_EQ(1, writes);
  EXPECT_EQ(0, reads);
  EXPECT_EQ(0, peer_.key_updates);
  EXPECT_EQ(0, peer_.pha_empty_certificates);
  EXPECT_EQ(0, peer_.pha_finished);
  EXPECT_EQ(0, peer_.close_notifies);
  EXPECT_FALSE(socket->IsConnected());
}

TEST_F(HttppsClientSocketTest, DisconnectMayCloseBeforeDeferredKeyUpdate) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  auto socket = Make();
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));
  peer_.mode = ASYNC;
  auto request = base::MakeRefCounted<StringIOBuffer>("completed before update");
  int writes = 0, reads = 0;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Write(request.get(), request->size(),
                          base::BindLambdaForTesting([&](int result) {
                            EXPECT_EQ(request->size(), result);
                            ++writes;
                            socket->Disconnect();
                          }), TRAFFIC_ANNOTATION_FOR_TESTS));
  peer_.mode = SYNCHRONOUS;
  peer_.KeyUpdate();
  auto response = base::MakeRefCounted<IOBufferWithSize>(32);
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Read(response.get(), response->size(),
                         base::BindLambdaForTesting([&](int) { ++reads; })));
  tasks_.RunUntilIdle();
  EXPECT_EQ(1, writes);
  EXPECT_EQ(0, reads);
  EXPECT_EQ(0, peer_.key_updates);
  EXPECT_EQ(1, peer_.close_notifies);
  EXPECT_FALSE(socket->IsConnected());
}

TEST_F(HttppsClientSocketTest, DisconnectReleasesPendingWriteBuffer) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  auto socket = Make();
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));
  peer_.hold_writes = true;
  auto buffer = base::MakeRefCounted<StringIOBuffer>("request");
  int callbacks = 0;
  ASSERT_EQ(ERR_IO_PENDING,
            socket->Write(buffer.get(), buffer->size(),
                          base::BindLambdaForTesting([&](int) { ++callbacks; }),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_FALSE(buffer->HasOneRef());
  socket->Disconnect();
  EXPECT_TRUE(buffer->HasOneRef());
  tasks_.RunUntilIdle();
  EXPECT_EQ(0, callbacks);
}

TEST_F(HttppsClientSocketTest, QueuedEmptyRecordReadIsCancelledOnWriteFailure) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = 20000;
  peer_.write_chunk = 20000;
  auto socket = Make();
  TestCompletionCallback connect;
  ASSERT_EQ(OK, socket->Connect(connect.callback()));
  for (int i = 0; i < 64; ++i) {
    peer_.Application("");
  }
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(32);
  int reads = 0;
  EXPECT_EQ(ERR_IO_PENDING,
            socket->Read(read_buffer.get(), 32,
                         base::BindLambdaForTesting([&](int result) {
                           EXPECT_EQ(ERR_CONNECTION_RESET, result);
                           ++reads;
                         })));
  peer_.fail_writes = true;
  auto write_buffer = base::MakeRefCounted<StringIOBuffer>("request");
  TestCompletionCallback write;
  EXPECT_EQ(ERR_CONNECTION_RESET,
            socket->Write(write_buffer.get(), write_buffer->size(),
                          write.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  tasks_.RunUntilIdle();
  EXPECT_EQ(1, reads);
}

TEST_F(HttppsClientSocketTest, UnexpectedEofFailsBothConcurrentOperationsOnce) {
  peer_.mode = SYNCHRONOUS;
  auto socket = Make();
  TestCompletionCallback connect;
  EXPECT_EQ(OK, socket->Connect(connect.callback()));
  peer_.hold_writes = true;
  int writes = 0;
  auto buffer = base::MakeRefCounted<StringIOBuffer>("request");
  EXPECT_EQ(ERR_IO_PENDING,
            socket->Write(buffer.get(), buffer->size(),
                          base::BindLambdaForTesting([&](int result) {
                            EXPECT_EQ(ERR_CONNECTION_CLOSED, result);
                            ++writes;
                          }),
                          TRAFFIC_ANNOTATION_FOR_TESTS));
  peer_.eof = true;
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(32);
  TestCompletionCallback read;
  EXPECT_EQ(
      ERR_CONNECTION_CLOSED,
      read.GetResult(socket->Read(read_buffer.get(), 32, read.callback())));
  tasks_.RunUntilIdle();
  EXPECT_EQ(1, writes);
  EXPECT_FALSE(socket->IsConnected());
}

TEST_F(HttppsClientSocketTest, SSLInfoSurvivesFatalWriteUntilDisconnect) {
  peer_.mode = SYNCHRONOUS;
  peer_.read_chunk = peer_.write_chunk = 20000;
  auto socket = Make();
  SSLInfo before;
  EXPECT_FALSE(socket->GetSSLInfo(&before));
  TestCompletionCallback connect;
  ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
  ASSERT_TRUE(socket->GetSSLInfo(&before));
  peer_.fail_writes = true;
  auto buffer = base::MakeRefCounted<StringIOBuffer>("request");
  TestCompletionCallback write;
  EXPECT_EQ(ERR_CONNECTION_RESET, write.GetResult(socket->Write(
      buffer.get(), buffer->size(), write.callback(), TRAFFIC_ANNOTATION_FOR_TESTS)));
  EXPECT_FALSE(socket->IsConnected());
  SSLInfo after;
  ASSERT_TRUE(socket->GetSSLInfo(&after));
  EXPECT_EQ(before.connection_status, after.connection_status);
  EXPECT_EQ(before.cert, after.cert);
  EXPECT_EQ(before.client_cert_sent, after.client_cert_sent);
  std::array<uint8_t, 32> exported{};
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED,
            socket->ExportKeyingMaterial("audit", std::nullopt, exported));
  tasks_.RunUntilIdle();
  EXPECT_TRUE(socket->GetSSLInfo(&after));
  socket->Disconnect();
  EXPECT_FALSE(socket->GetSSLInfo(&after));
}

TEST_F(HttppsClientSocketTest, SSLInfoSurvivesFatalReadUntilDisconnect) {
  for (int failure : {0, 1, 2}) {
    SCOPED_TRACE(failure);
    peer_.mode = SYNCHRONOUS;
    peer_.read_chunk = peer_.write_chunk = 20000;
    auto socket = Make();
    TestCompletionCallback connect;
    ASSERT_EQ(OK, connect.GetResult(socket->Connect(connect.callback())));
    SSLInfo before;
    ASSERT_TRUE(socket->GetSSLInfo(&before));
    if (failure == 0) {
      peer_.eof = true;
    } else if (failure == 1) {
      peer_.Alert(40);
    } else {
      // An invalid encrypted record exercises native protocol-failure cleanup.
      peer_.RawRecord(Bytes{23, 3, 3, 0, 1, 0});
    }
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(32);
    TestCompletionCallback read;
    EXPECT_LT(read.GetResult(socket->Read(buffer.get(), buffer->size(),
                                          read.callback())), OK);
    EXPECT_FALSE(socket->IsConnected());
    SSLInfo after;
    ASSERT_TRUE(socket->GetSSLInfo(&after));
    EXPECT_EQ(before.connection_status, after.connection_status);
    EXPECT_EQ(before.cert, after.cert);
    EXPECT_EQ(before.client_cert_sent, after.client_cert_sent);
    tasks_.RunUntilIdle();
    socket->Disconnect();
    EXPECT_FALSE(socket->GetSSLInfo(&after));
    peer_.eof = false;
  }
}

TEST_F(HttppsClientSocketTest, FailedHandshakeDoesNotInventSSLInfo) {
  peer_.bad_proof = true;
  auto socket = Make();
  TestCompletionCallback connect;
  EXPECT_LT(connect.GetResult(socket->Connect(connect.callback())), OK);
  SSLInfo info;
  EXPECT_FALSE(socket->GetSSLInfo(&info));
}

}  // namespace
}  // namespace net
