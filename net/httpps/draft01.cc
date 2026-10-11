// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/draft01.h"

#include <algorithm>
#include <limits>
#include <map>
#include <utility>

#include "third_party/boringssl/src/include/openssl/aead.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/include/openssl/bn.h"
#include "third_party/boringssl/src/include/openssl/ec.h"
#include "third_party/boringssl/src/include/openssl/ecdh.h"
#include "third_party/boringssl/src/include/openssl/hkdf.h"
#include "third_party/boringssl/src/include/openssl/hmac.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/nid.h"
#include "third_party/boringssl/src/include/openssl/rand.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace net::httpps {
namespace {

ByteSpan Octets(std::string_view value) {
  return StringBytes(value);
}

void Append(Bytes* out, ByteSpan bytes) {
  out->insert(out->end(), bytes.begin(), bytes.end());
}

void U16(Bytes* out, size_t value) {
  out->push_back(static_cast<uint8_t>(value >> 8));
  out->push_back(static_cast<uint8_t>(value));
}

void U32(Bytes* out, uint32_t value) {
  for (int shift : {24, 16, 8, 0})
    out->push_back(static_cast<uint8_t>(value >> shift));
}

uint32_t Read32(ByteSpan value) {
  uint32_t result = 0;
  for (uint8_t octet : value)
    result = (result << 8) | octet;
  return result;
}

void Vector16(Bytes* out, ByteSpan body) {
  U16(out, body.size());
  Append(out, body);
}

void Extension(Bytes* out, uint16_t type, ByteSpan data) {
  U16(out, type);
  Vector16(out, data);
}

size_t Read16(ByteSpan bytes) {
  return (static_cast<size_t>(bytes[0]) << 8) | bytes[1];
}

size_t Read24(ByteSpan bytes) {
  return (static_cast<size_t>(bytes[0]) << 16) |
         (static_cast<size_t>(bytes[1]) << 8) | bytes[2];
}

bool Extensions(ByteSpan data, std::map<uint16_t, Bytes>* out) {
  if (data.size() < 2 || Read16(data.first(2u)) != data.size() - 2)
    return false;
  data = data.subspan(2u);
  while (!data.empty()) {
    if (data.size() < 4)
      return false;
    uint16_t type = static_cast<uint16_t>(Read16(data.first(2u)));
    size_t length = Read16(data.subspan(2u, 2u));
    if (length > data.size() - 4 || out->count(type))
      return false;
    auto value = data.subspan(4u, length);
    out->emplace(type, Bytes(value.begin(), value.end()));
    data = data.subspan(4 + length);
  }
  return true;
}

bool P256Keypair(Secret* private_key, Bytes* public_key) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  public_key->resize(65);
  return key && EC_KEY_generate_key(key.get()) &&
      BN_bn2bin_padded(private_key->data(), private_key->size(),
                       EC_KEY_get0_private_key(key.get())) &&
      EC_POINT_point2oct(EC_KEY_get0_group(key.get()),
                        EC_KEY_get0_public_key(key.get()),
                        POINT_CONVERSION_UNCOMPRESSED, public_key->data(),
                        public_key->size(), nullptr) == public_key->size();
}

bool P256Agreement(const Secret& private_key, ByteSpan peer, Secret* shared) {
  if (peer.size() != 65 || peer[0] != 4)
    return false;
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  bssl::UniquePtr<BIGNUM> scalar(
      BN_bin2bn(private_key.data(), private_key.size(), nullptr));
  if (!key || !scalar || !EC_KEY_set_private_key(key.get(), scalar.get()))
    return false;
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(EC_KEY_get0_group(key.get())));
  return point && EC_POINT_oct2point(EC_KEY_get0_group(key.get()), point.get(),
                                     peer.data(), peer.size(), nullptr) &&
      !EC_POINT_is_at_infinity(EC_KEY_get0_group(key.get()), point.get()) &&
      ECDH_compute_key(shared->data(), shared->size(), point.get(), key.get(),
                       nullptr) == static_cast<int>(shared->size());
}

Bytes Frame(uint8_t type, ByteSpan body) {
  Bytes out = {type, static_cast<uint8_t>(body.size() >> 16),
               static_cast<uint8_t>(body.size() >> 8),
               static_cast<uint8_t>(body.size())};
  Append(&out, body);
  return out;
}

Bytes PlainRecord(ByteSpan frame) {
  Bytes out = {22, 3, 3};
  U16(&out, frame.size());
  Append(&out, frame);
  return out;
}

bool Equal(ByteSpan a, ByteSpan b) {
  return a.size() == b.size() &&
         CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

void CopySecret(ByteSpan in, Secret* out) {
  std::copy(in.begin(), in.end(), out->begin());
}

bool DeriveSecret(ByteSpan secret,
                  std::string_view label,
                  ByteSpan context,
                  Secret* output) {
  auto derived = Label(secret, label, context, output->size());
  if (derived.size() != output->size()) {
    return false;
  }
  CopySecret(derived, output);
  OPENSSL_cleanse(derived.data(), derived.size());
  return true;
}

Secret Finished(const Secret& traffic_secret, const Bytes& transcript) {
  auto key = Label(traffic_secret, "finished", {}, 32);
  Secret result = Mac(key, Hash(transcript));
  OPENSSL_cleanse(key.data(), key.size());
  return result;
}

Secret CredentialIdentity(const std::vector<std::string>& certificates) {
  Bytes encoded;
  for (const auto& der : certificates) {
    U32(&encoded, der.size());
    Append(&encoded, Octets(der));
  }
  return Hash(encoded);
}

bool ParseCertificates(ByteSpan body, std::vector<std::string>* certificates) {
  if (body.size() < 4 || body[0] != 0 ||
      Read24(body.subspan(1u, 3u)) != body.size() - 4) {
    return false;
  }
  body = body.subspan(4u);
  while (!body.empty()) {
    if (certificates->size() == 8 || body.size() < 5) {
      return false;
    }
    size_t length = Read24(body.first(3u));
    if (!length || length > 65536 || length > body.size() - 5 ||
        body[3 + length] != 0 || body[4 + length] != 0) {
      return false;
    }
    const auto certificate = body.subspan(3u, length);
    certificates->emplace_back(
        reinterpret_cast<const char*>(certificate.data()), certificate.size());
    body = body.subspan(length + 5);
  }
  return !certificates->empty();
}

}  // namespace

bool ValidServerName(std::string_view name) {
  if (name.empty() || name.size() > 253 || name.back() == '.') {
    return false;
  }
  bool all_numeric = true;
  while (!name.empty()) {
    size_t end = name.find('.');
    std::string_view label = name.substr(0, end);
    if (label.empty() || label.size() > 63 || label.front() == '-' ||
        label.back() == '-') {
      return false;
    }
    for (char c : label) {
      if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
        return false;
      }
      all_numeric &= c >= '0' && c <= '9';
    }
    if (end == std::string_view::npos) {
      break;
    }
    name.remove_prefix(end + 1);
  }
  // Numeric/IP-literal identities are outside this profile. URL parsing has
  // already canonicalized internationalized names to ASCII A-labels.
  return !all_numeric;
}

Secret Hash(ByteSpan input) {
  Secret out;
  SHA256(input.data(), input.size(), out.data());
  return out;
}

Secret Mac(ByteSpan key, ByteSpan input) {
  Secret out;
  unsigned int size = 0;
  HMAC(EVP_sha256(), key.data(), key.size(), input.data(), input.size(),
       out.data(), &size);
  return out;
}

Bytes Label(ByteSpan secret,
            std::string_view label,
            ByteSpan context,
            size_t length) {
  std::string full_label = "tls20 ";
  full_label += label;
  if (full_label.size() > 255 || context.size() > 255 ||
      length > 255 * 32) {
    return {};
  }
  Bytes info;
  U16(&info, length);
  info.push_back(static_cast<uint8_t>(full_label.size()));
  Append(&info, Octets(full_label));
  info.push_back(static_cast<uint8_t>(context.size()));
  Append(&info, context);
  Bytes result(length);
  if (!length)
    return result;
  if (!HKDF_expand(result.data(), result.size(), EVP_sha256(), secret.data(),
                   secret.size(), info.data(), info.size())) {
    return {};
  }
  return result;
}

SessionTicket::~SessionTicket() {
  OPENSSL_cleanse(psk.data(), psk.size());
}

ClientCredential::~ClientCredential() {
  OPENSSL_cleanse(private_key.data(), private_key.size());
}

RecordCipher::RecordCipher(ByteSpan secret) {
  auto key = Label(secret, "key", {}, key_.size());
  auto iv = Label(secret, "iv", {}, iv_.size());
  failed_ = secret.size() != 32 || key.size() != key_.size() ||
            iv.size() != iv_.size();
  if (!failed_) {
    std::copy(key.begin(), key.end(), key_.begin());
    std::copy(iv.begin(), iv.end(), iv_.begin());
  }
  OPENSSL_cleanse(key.data(), key.size());
  OPENSSL_cleanse(iv.data(), iv.size());
}

RecordCipher::~RecordCipher() {
  OPENSSL_cleanse(key_.data(), key_.size());
  OPENSSL_cleanse(iv_.data(), iv_.size());
}

bool RecordCipher::Account(size_t length) {
  // AES-GCM's RFC 9846 per-key usage limit. A connection rotates traffic keys
  // rather than retaining the prototype's arbitrary 1 GiB connection limit.
  if (failed_ || sequence_ >= 23726566 || length > kMaxRecordContent + 239) {
    failed_ = true;
    return false;
  }
  ++sequence_;
  content_bytes_ += length;
  return true;
}

bool RecordCipher::Seal(ByteSpan content, uint8_t type, Bytes* record,
                        size_t padding) {
  if (failed_ || (type != 21 && type != 22 && type != 23) ||
      content.size() > kMaxRecordContent || padding > 239 ||
      (type == 21 && content.size() != 2) || (type == 22 && content.empty())) {
    failed_ = true;
    return false;
  }
  auto nonce = iv_;
  for (size_t i = 0; i < 8; ++i) {
    nonce[11 - i] ^= static_cast<uint8_t>(sequence_ >> (8 * i));
  }
  if (!Account(content.size())) {
    return false;
  }
  Bytes plaintext(content.begin(), content.end());
  plaintext.push_back(type);
  plaintext.resize(plaintext.size() + padding, 0);
  *record = {23, 3, 3};
  U16(record, plaintext.size() + 16);
  record->resize(5 + plaintext.size() + 16);
  bssl::ScopedEVP_AEAD_CTX context;
  size_t written = 0;
  bool ok =
      EVP_AEAD_CTX_init(context.get(), EVP_aead_aes_128_gcm(), key_.data(),
                        key_.size(), 16, nullptr) &&
      EVP_AEAD_CTX_seal(context.get(), &record->at(5), &written,
                        record->size() - 5, nonce.data(), nonce.size(),
                        plaintext.data(), plaintext.size(), record->data(), 5);
  OPENSSL_cleanse(plaintext.data(), plaintext.size());
  if (!ok || written != record->size() - 5) {
    failed_ = true;
    record->clear();
    return false;
  }
  return true;
}

bool RecordCipher::Open(ByteSpan record, uint8_t* type, Bytes* content) {
  if (failed_ || record.size() < 22 || record.size() > kMaxRecord ||
      record[0] != 23 || record[1] != 3 || record[2] != 3 ||
      Read16(record.subspan(3u, 2u)) != record.size() - 5) {
    failed_ = true;
    return false;
  }
  auto nonce = iv_;
  for (size_t i = 0; i < 8; ++i) {
    nonce[11 - i] ^= static_cast<uint8_t>(sequence_ >> (8 * i));
  }
  if (!Account(record.size() - 22)) {
    return false;
  }
  bssl::ScopedEVP_AEAD_CTX context;
  Bytes plaintext(record.size() - 21);
  size_t written = 0;
  bool ok =
      EVP_AEAD_CTX_init(context.get(), EVP_aead_aes_128_gcm(), key_.data(),
                        key_.size(), 16, nullptr) &&
      EVP_AEAD_CTX_open(context.get(), plaintext.data(), &written,
                        plaintext.size(), nonce.data(), nonce.size(),
                        record.subspan(5u).data(), record.size() - 5,
                        record.data(), 5);
  if (!ok || written != plaintext.size()) {
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    failed_ = true;
    return false;
  }
  while (!plaintext.empty() && plaintext.back() == 0)
    plaintext.pop_back();
  if (plaintext.empty()) {
    failed_ = true;
    return false;
  }
  *type = plaintext.back();
  plaintext.pop_back();
  if (plaintext.size() > kMaxRecordContent ||
      (*type != 21 && *type != 22 && *type != 23) ||
      (*type == 21 && plaintext.size() != 2) ||
      (*type == 22 && plaintext.empty())) {
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    failed_ = true;
    return false;
  }
  *content = std::move(plaintext);
  return true;
}

Client::Client(std::string hostname,
               std::vector<std::string> trust_anchors,
               bool use_external_verifier)
    : hostname_(std::move(hostname)),
      anchors_(std::move(trust_anchors)),
      use_external_verifier_(use_external_verifier) {}

Client::~Client() {
  EraseHandshakeSecrets();
  for (auto* secret : {&master_, &c_app_, &s_app_, &exporter_, &resumption_})
    OPENSSL_cleanse(secret->data(), secret->size());
}

void Client::EraseHandshakeSecrets() {
  for (auto* secret : {&a_, &b_, &p256_private_, &root_, &c_hs_, &s_hs_, &expected_proof_}) {
    OPENSSL_cleanse(secret->data(), secret->size());
  }
  client_credential_.reset();
  OPENSSL_cleanse(client_verifier_share_.data(), client_verifier_share_.size());
}

bool Client::Fail(Error error) {
  if (state_ == State::kFailed) {
    return false;
  }
  state_ = State::kFailed;
  error_ = error;
  EraseHandshakeSecrets();
  sender_.reset();
  receiver_.reset();
  early_sender_.reset();
  output_.clear();
  reassembly_.clear();
  return false;
}

bool Client::Deadline() {
  return MonotonicMilliseconds() < deadline_milliseconds_ ||
         Fail(Error::kTimeout);
}

bool Client::SetClientCredential(const ClientCredential& credential) {
  if (state_ != State::kNew || credential.certificates.empty() ||
      credential.certificates.size() > 8)
    return false;
  size_t total = 0;
  for (const auto& der : credential.certificates) {
    if (der.empty() || der.size() > 65536 || (total += der.size()) > 262144)
      return false;
  }
  Secret actual, expected;
  X25519_public_from_private(actual.data(), credential.private_key.data());
  if (!ExtractServerPublicKey(credential.certificates.front(), &expected) ||
      !Equal(actual, expected))
    return false;
  client_credential_ = credential;
  return true;
}

bool Client::AppendClientAuthentication() {
  if (!client_auth_requested_)
    return true;
  Bytes entries;
  if (client_credential_) {
    for (const auto& der : client_credential_->certificates) {
      auto entry = Frame(0, Octets(der));
      // CertificateEntry is uint24 DER length, DER and an empty extensions.
      Append(&entries, ByteSpan(entry).subspan(1u));
      U16(&entries, 0);
    }
  }
  auto list = Frame(0, entries);
  Bytes certificate_body{0};  // Empty initial request context.
  Append(&certificate_body, ByteSpan(list).subspan(1u));
  auto certificate = Frame(11, certificate_body);
  // Certificate lists may span records, but the handshake transcript contains
  // the exact complete frame, independent of record fragmentation.
  for (size_t offset = 0; offset < certificate.size(); offset += kMaxRecordContent) {
    Bytes record;
    if (!sender_->Seal(ByteSpan(certificate).subspan(
                          offset, std::min(kMaxRecordContent, certificate.size() - offset)),
                       22, &record))
      return Fail();
    Append(&output_, record);
  }
  if (!AppendTranscript(certificate))
    return Fail();
  if (!client_credential_)
    return true;  // Ordinary no-credential response, not an authenticated user.
  authenticated_client_identity_ = CredentialIdentity(client_credential_->certificates);
  Secret shared{};
  if (!X25519(shared.data(), client_credential_->private_key.data(),
              client_verifier_share_.data()))
    return Fail();
  const auto transcript_hash = Hash(transcript_);
  auto exported = Label(exporter_, "EXPORTER-TLS20-Client-Auth", Hash({}), 32);
  auto salt = Label(exported, "exporter", Hash(transcript_hash), 32);
  auto root = Mac(salt, shared);
  auto key = Label(root, "client mac", {}, 32);
  Bytes input(64, 0x20);
  Append(&input, Octets("TLS 2.0, client CertificateVerify"));
  input.push_back(0);
  Append(&input, transcript_hash);
  auto proof = Mac(key, input);
  Bytes body{0xfe, 1};
  Vector16(&body, proof);
  auto frame = Frame(15, body);
  Bytes record;
  const bool ok = sender_->Seal(frame, 22, &record) && AppendTranscript(frame);
  for (auto* secret : {&exported, &salt, &key})
    OPENSSL_cleanse(secret->data(), secret->size());
  for (auto* secret : {&shared, &root, &proof})
    OPENSSL_cleanse(secret->data(), secret->size());
  client_credential_.reset();
  if (!ok)
    return Fail();
  Append(&output_, record);
  return true;
}

bool Client::Start(const SessionTicket* ticket, ByteSpan early_data,
                   bool enable_early_data) {
  if (state_ != State::kNew || !ValidServerName(hostname_) ||
      (!use_external_verifier_ && anchors_.empty()) || anchors_.size() > 32) {
    return Fail(Error::kCertificate);
  }
  for (const auto& anchor : anchors_) {
    if (anchor.empty() || anchor.size() > 65536) {
      return Fail(Error::kCertificate);
    }
  }
  deadline_milliseconds_ = MonotonicMilliseconds() + 30000;
  if (ticket) {
    const auto age = MonotonicMilliseconds() - ticket->received_milliseconds;
    const Secret selected_identity = client_credential_
        ? CredentialIdentity(client_credential_->certificates) : Secret{};
    if (ticket->hostname != hostname_ || ticket->identity.empty() ||
        ticket->identity.size() > 65535 || ticket->certificates.empty() ||
        ticket->lifetime == 0 || ticket->lifetime > 604800 || age < 0 ||
        static_cast<uint64_t>(age) >= uint64_t(ticket->lifetime) * 1000 ||
        !Equal(ticket->client_identity, selected_identity)) {
      return Fail(Error::kCertificate);
    }
    // Browser callers must validate their cached chain against current policy
    // before permitting early data. The standalone CA path validates here.
    Secret unused;
    if (!use_external_verifier_ &&
        !VerifyLabChain(ticket->certificates, anchors_, hostname_, &unused))
      return Fail(Error::kCertificate);
    offered_ticket_ = *ticket;
    early_offered_ = (enable_early_data || !early_data.empty()) &&
                     ticket->max_early_data > 0;
  }
  if (!early_data.empty() && !early_offered_)
    return Fail();
  X25519_keypair(A_.data(), a_.data());
  X25519_keypair(B_.data(), b_.data());
  if (A_ == B_) {
    return Fail();
  }
  Secret random;
  RAND_bytes(random.data(), random.size());
  Bytes body = {3, 3};
  Append(&body, random);
  Append(&body, Bytes{0, 0, 2, 0x13, 1, 1, 0});
  Bytes extensions, server_name, name{0};
  Vector16(&name, Octets(hostname_));
  Vector16(&server_name, name);
  Extension(&extensions, 0, server_name);
  Extension(&extensions, 10, Bytes{0, 4, 0, 0x1d, 0, 0x17});
  Extension(&extensions, 50,
            Bytes{0, 12, 4, 3, 8, 4, 8, 5, 8, 6, 8, 7, 5, 3});
  Extension(&extensions, 43, Bytes{2, 4, 0});
  Bytes alpn{0, 9, 8};
  Append(&alpn, Octets("http/1.1"));
  Extension(&extensions, 16, alpn);
  Bytes share{0, 36, 0, 0x1d, 0, 32};
  Append(&share, B_);
  Extension(&extensions, 51, share);
  Extension(&extensions, 0xff02, A_);
  Extension(&extensions, 45, Bytes{1, 1});
  if (offered_ticket_) {
    if (early_offered_)
      Extension(&extensions, 42, {});
    Bytes identity;
    Vector16(&identity, offered_ticket_->identity);
    U32(&identity, static_cast<uint32_t>(MonotonicMilliseconds() -
                                      offered_ticket_->received_milliseconds) +
                       offered_ticket_->age_add);
    Bytes psk;
    Vector16(&psk, identity);
    Append(&psk, Bytes{0, 33, 32});
    psk.resize(psk.size() + 32, 0);
    Extension(&extensions, 41, psk);  // RFC requires this extension to be last.
  }
  Vector16(&body, extensions);
  auto hello = Frame(1, body);
  if (offered_ticket_) {
    Secret early = Mac(Secret{}, offered_ticket_->psk);
    auto binder_key = Label(early, "res binder", Hash({}), 32);
    auto finished_key = Label(binder_key, "finished", {}, 32);
    Bytes truncated(Octets(kPreface).begin(), Octets(kPreface).end());
    Append(&truncated, ByteSpan(hello).first(hello.size() - 35));
    auto binder = Mac(finished_key, Hash(truncated));
    std::copy(binder.begin(), binder.end(), hello.end() - 32);
    OPENSSL_cleanse(early.data(), early.size());
    OPENSSL_cleanse(binder_key.data(), binder_key.size());
    OPENSSL_cleanse(finished_key.data(), finished_key.size());
  }
  client_hello_ = hello;
  Append(&transcript_, Octets(kPreface));
  AppendTranscript(hello);
  Append(&output_, Octets(kPreface));
  Append(&output_, PlainRecord(hello));
  handshake_records_ = 1;
  state_ = State::kHello;
  if (early_offered_) {
    Secret early = Mac(Secret{}, offered_ticket_->psk);
    auto traffic = Label(early, "c e traffic", Hash(transcript_), 32);
    early_sender_ = std::make_unique<RecordCipher>(traffic);
    OPENSSL_cleanse(early.data(), early.size());
    OPENSSL_cleanse(traffic.data(), traffic.size());
    while (!early_data.empty()) {
      Bytes record;
      size_t count = std::min(early_data.size(), kMaxRecordContent);
      if (!SendEarlyData(early_data.first(count), &record))
        return false;
      Append(&output_, record);
      early_data = early_data.subspan(count);
    }
  }
  return true;
}

bool Client::SendEarlyData(ByteSpan data, Bytes* record) {
  if (!early_data_available() || !early_sender_ || !offered_ticket_ ||
      data.size() > offered_ticket_->max_early_data - early_bytes_ ||
      !Deadline() || !early_sender_->Seal(data, 23, record))
    return Fail();
  early_bytes_ += static_cast<uint32_t>(data.size());
  return true;
}

bool Client::RetryHello(ByteSpan frame, ByteSpan cookie, uint16_t group) {
  if (retried_ || (group != 0 && group != 0x17) ||
      (group == 0 && cookie.empty()))
    return Fail();
  retried_ = true;
  Bytes public_key;
  if (group && !P256Keypair(&p256_private_, &public_key))
    return Fail();
  if (group)
    traffic_group_ = group;
  auto inner_hash = Hash(client_hello_);
  transcript_.assign(Octets(kPreface).begin(), Octets(kPreface).end());
  Append(&transcript_, Frame(254, inner_hash));
  if (!AppendTranscript(frame))
    return false;
  Bytes extensions;
  auto old_extensions = ByteSpan(client_hello_).subspan(47u);
  while (!old_extensions.empty()) {
    auto type = static_cast<uint16_t>(Read16(old_extensions.first(2u)));
    size_t length = Read16(old_extensions.subspan(2u, 2u));
    auto value = old_extensions.subspan(4u, length);
    if (type == 51 && group) {
      Bytes share;
      U16(&share, group);
      Vector16(&share, public_key);
      Bytes shares;
      Vector16(&shares, share);
      Extension(&extensions, type, shares);
    } else if (type != 42) {
      if (type == 41 && !cookie.empty())
        Extension(&extensions, 44, cookie);
      Extension(&extensions, type, value);
    }
    old_extensions = old_extensions.subspan(length + 4);
  }
  if (!offered_ticket_ && !cookie.empty())
    Extension(&extensions, 44, cookie);
  Bytes body(client_hello_.begin() + 4, client_hello_.begin() + 45);
  Vector16(&body, extensions);
  auto hello = Frame(1, body);
  if (offered_ticket_) {
    auto early = Mac(Secret{}, offered_ticket_->psk);
    auto binder = Label(early, "res binder", Hash({}), 32);
    auto finished = Label(binder, "finished", {}, 32);
    Bytes truncated = transcript_;
    Append(&truncated, ByteSpan(hello).first(hello.size() - 35));
    auto proof = Mac(finished, Hash(truncated));
    std::copy(proof.begin(), proof.end(), hello.end() - 32);
    OPENSSL_cleanse(early.data(), early.size());
    OPENSSL_cleanse(binder.data(), binder.size());
    OPENSSL_cleanse(finished.data(), finished.size());
  }
  early_offered_ = false;
  early_sender_.reset();
  if (!AppendTranscript(hello))
    return false;
  output_ = PlainRecord(hello);
  return true;
}

bool Client::AppendTranscript(ByteSpan frame) {
  if (transcript_.size() + frame.size() > 1048576) {
    return Fail();
  }
  Append(&transcript_, frame);
  return true;
}

Bytes Client::TakeOutput() {
  return std::exchange(output_, {});
}

bool Client::established() const {
  return state_ == State::kEstablished;
}
bool Client::closed() const {
  return state_ == State::kClosed;
}

bool Client::certificate_verification_pending() const {
  return state_ == State::kVerifyingCertificate;
}

bool Client::CompleteCertificateVerification(bool trusted) {
  if (!certificate_verification_pending() || !trusted) {
    return Fail(Error::kCertificate);
  }
  if (resume_verification_) {
    state_ = State::kFinished;
    return DrainHandshakeFrames();
  }
  return PrepareServerProof() && DrainHandshakeFrames();
}

bool Client::PrepareServerProof() {
  if (!Deadline() || S_ == A_ || S_ == B_ || S_ == E_) {
    return Fail();
  }
  Secret shared{};
  if (!X25519(shared.data(), a_.data(), S_.data())) {
    return Fail();
  }
  auto salt = Label(root_, "auth salt", Hash(transcript_), 32);
  Secret auth_root = Mac(salt, shared);
  auto proof_key = Label(auth_root, "server mac", {}, 32);
  Bytes context(64, 0x20);
  Append(&context, Octets("TLS 2.0, server CertificateVerify"));
  context.push_back(0);
  Append(&context, Hash(transcript_));
  expected_proof_ = Mac(proof_key, context);
  OPENSSL_cleanse(shared.data(), shared.size());
  OPENSSL_cleanse(salt.data(), salt.size());
  OPENSSL_cleanse(a_.data(), a_.size());
  OPENSSL_cleanse(auth_root.data(), auth_root.size());
  OPENSSL_cleanse(proof_key.data(), proof_key.size());
  state_ = State::kProof;
  return true;
}

bool Client::OutputFlushed() {
  if (state_ == State::kHello) {
    return Deadline();
  }
  if (state_ != State::kFlushing || !Deadline()) {
    return Fail();
  }
  sender_ = std::make_unique<RecordCipher>(c_app_);
  receiver_ = std::make_unique<RecordCipher>(s_app_);
  early_sender_.reset();
  offered_ticket_.reset();
  EraseHandshakeSecrets();
  OPENSSL_cleanse(master_.data(), master_.size());
  transcript_.clear();
  state_ = State::kEstablished;
  return true;
}

bool Client::AcceptFrame(ByteSpan frame) {
  auto body = frame.subspan(4u);
  switch (state_) {
    case State::kHello: {
      if (frame[0] != 2 || body.size() < 40 || body[0] != 3 || body[1] != 3 ||
          body[34] != 0 || body[35] != 0x13 || body[36] != 1 || body[37] != 0) {
        return Fail();
      }
      std::map<uint16_t, Bytes> extensions;
      if (!Extensions(body.subspan(38u), &extensions) ||
          extensions[43] != Bytes({4, 0}))
        return Fail();
      constexpr std::array<uint8_t, 32> kRetryRandom = {
          0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,
          0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
          0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,
          0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
      if (Equal(body.subspan(2u, 32u), kRetryRandom)) {
        uint16_t group = 0;
        for (const auto& [type, data] : extensions) {
          if (type == 43)
            continue;
          if (type == 51 && data.size() == 2) {
            group = static_cast<uint16_t>(Read16(data));
            continue;
          }
          if (type == 44 && data.size() >= 3 &&
              Read16(ByteSpan(data).first(2u)) == data.size() - 2)
            continue;
          return Fail();
        }
        return RetryHello(frame, extensions.count(44) ? ByteSpan(extensions[44])
                                                      : ByteSpan(), group);
      }
      if (extensions[51].size() < 4 ||
          Read16(ByteSpan(extensions[51]).first(2u)) != traffic_group_ ||
          Read16(ByteSpan(extensions[51]).subspan(2u, 2u)) !=
              extensions[51].size() - 4)
        return Fail();
      for (const auto& [type, data] : extensions) {
        if (type != 43 && type != 51 && type != 41)
          return Fail();
      }
      resumed_ = extensions.count(41) != 0;
      if (resumed_ && (!offered_ticket_ || extensions[41] != Bytes({0, 0})))
        return Fail();
      auto peer = ByteSpan(extensions[51]).subspan(4u);
      if (traffic_group_ == 0x1d) {
        if (peer.size() != 32)
          return Fail();
        CopySecret(peer, &E_);
      }
      if ((traffic_group_ == 0x1d && (E_ == A_ || E_ == B_)) ||
          !AppendTranscript(frame)) {
        return Fail();
      }
      Secret shared{};
      if (!(traffic_group_ == 0x1d
                ? X25519(shared.data(), b_.data(), E_.data())
                : P256Agreement(p256_private_, peer, &shared))) {
        return Fail();
      }
      Secret early = Mac(Secret{}, resumed_ ? offered_ticket_->psk : Secret{});
      auto derived = Label(early, "derived", Hash({}), 32);
      root_ = Mac(derived, shared);
      OPENSSL_cleanse(early.data(), early.size());
      OPENSSL_cleanse(derived.data(), derived.size());
      OPENSSL_cleanse(shared.data(), shared.size());
      OPENSSL_cleanse(b_.data(), b_.size());
      OPENSSL_cleanse(p256_private_.data(), p256_private_.size());
      if (!DeriveSecret(root_, "c hs traffic", Hash(transcript_), &c_hs_) ||
          !DeriveSecret(root_, "s hs traffic", Hash(transcript_), &s_hs_)) {
        return Fail();
      }
      sender_ = std::make_unique<RecordCipher>(c_hs_);
      receiver_ = std::make_unique<RecordCipher>(s_hs_);
      state_ = State::kExtensions;
      return true;
    }
    case State::kExtensions: {
      std::map<uint16_t, Bytes> extensions;
      Bytes alpn{0, 9, 8};
      Append(&alpn, Octets("http/1.1"));
      if (frame[0] != 8 || !Extensions(body, &extensions) ||
          extensions[16] != alpn ||
          !AppendTranscript(frame)) {
        return Fail();
      }
      for (const auto& [type, data] : extensions) {
        if (type == 0 && data.empty())
          continue;
        if (type == 16)
          continue;
        if (type == 42 && data.empty() && resumed_ && early_offered_) {
          early_accepted_ = true;
          continue;
        }
        return Fail();
      }
      if (resumed_) {
        certificates_ = offered_ticket_->certificates;
        authenticated_client_identity_ = offered_ticket_->client_identity;
        Secret unused;
        const bool trusted = !anchors_.empty() &&
            VerifyLabChain(certificates_, anchors_, hostname_, &unused);
        if (!trusted && !use_external_verifier_)
          return Fail(Error::kCertificate);
        resume_verification_ = !trusted;
        state_ = trusted ? State::kFinished : State::kVerifyingCertificate;
        return true;
      }
      state_ = State::kCertificate;
      return true;
    }
    case State::kCertificate: {
      if (frame[0] == 13) {
        std::map<uint16_t, Bytes> extensions;
        if (client_auth_requested_ || body.empty() || body[0] != 0 ||
            !Extensions(body.subspan(1u), &extensions) ||
            !extensions.count(0xff03) || extensions[0xff03].size() != 32 ||
            !extensions.count(50) || extensions.count(13) || extensions.count(0xff02) ||
            extensions[50].size() < 4 || extensions[50].size() % 2 ||
            Read16(ByteSpan(extensions[50]).first(2u)) != extensions[50].size() - 2 ||
            !AppendTranscript(frame))
          return Fail();
        for (size_t offset = 2; offset < extensions[50].size(); offset += 2) {
          const size_t algorithm = Read16(ByteSpan(extensions[50]).subspan(offset, 2u));
          if (algorithm == 0xfe00 || algorithm == 0xfe01 || algorithm == 0x0420 ||
              algorithm == 0x0520 || algorithm == 0x0620)
            return Fail();
        }
        CopySecret(extensions[0xff03], &client_verifier_share_);
        client_auth_requested_ = true;
        return true;
      }
      if (frame[0] != 11 || !ParseCertificates(body, &certificates_)) {
        return Fail(Error::kCertificate);
      }
      // Explicit, role-specific private anchors are additive. A successful lab
      // verification is sufficient; otherwise use the browser's HTTPS verifier.
      // Never turn a failed external decision into a lab or insecure fallback.
      const bool private_trusted =
          !anchors_.empty() &&
          VerifyLabChain(certificates_, anchors_, hostname_, &S_);
      if (!private_trusted &&
          (!use_external_verifier_ ||
           !ExtractServerPublicKey(certificates_.front(), &S_))) {
        return Fail(Error::kCertificate);
      }
      if (!AppendTranscript(frame)) {
        return Fail();
      }
      if (!private_trusted) {
        state_ = State::kVerifyingCertificate;
        return true;
      }
      return PrepareServerProof();
    }
    case State::kProof:
      if (frame[0] != 15 || body.size() != 36 || body[0] != 0xfe ||
          body[1] != 0 || body[2] != 0 || body[3] != 32 ||
          !Equal(body.subspan(4u), expected_proof_) ||
          !AppendTranscript(frame)) {
        return Fail();
      }
      OPENSSL_cleanse(expected_proof_.data(), expected_proof_.size());
      state_ = State::kFinished;
      return true;
    case State::kFinished: {
      Secret expected = Finished(s_hs_, transcript_);
      bool ok = frame[0] == 20 && Equal(body, expected);
      OPENSSL_cleanse(expected.data(), expected.size());
      if (!ok || !AppendTranscript(frame)) {
        return Fail();
      }
      auto derived = Label(root_, "derived", Hash({}), 32);
      master_ = Mac(derived, Secret{});
      OPENSSL_cleanse(derived.data(), derived.size());
      if (!DeriveSecret(master_, "c ap traffic", Hash(transcript_), &c_app_) ||
          !DeriveSecret(master_, "s ap traffic", Hash(transcript_), &s_app_) ||
          !DeriveSecret(master_, "exp master", Hash(transcript_), &exporter_))
        return Fail();
      output_.clear();
      if (early_accepted_) {
        auto end = Frame(5, {});
        Bytes end_record;
        if (!early_sender_ || !early_sender_->Seal(end, 22, &end_record) ||
            !AppendTranscript(end))
          return Fail();
        Append(&output_, end_record);
      }
      if (!AppendClientAuthentication())
        return false;
      auto client_finished = Frame(20, Finished(c_hs_, transcript_));
      Bytes finished_record;
      if (++handshake_records_ > 4096 ||
          !sender_->Seal(client_finished, 22, &finished_record) ||
          !AppendTranscript(client_finished)) {
        return Fail();
      }
      Append(&output_, finished_record);
      if (!DeriveSecret(master_, "res master", Hash(transcript_), &resumption_))
        return Fail();
      state_ = State::kFlushing;
      return true;
    }
    default:
      return Fail();
  }
}

bool Client::Receive(ByteSpan record, Bytes* application_data) {
  application_data->clear();
  if (state_ == State::kNew || state_ == State::kFailed ||
      state_ == State::kClosed || state_ == State::kFlushing ||
      state_ == State::kVerifyingCertificate) {
    return Fail();
  }
  bool handshake = state_ != State::kEstablished;
  if (handshake && (!Deadline() || ++handshake_records_ > 4096)) {
    return Fail();
  }
  if (handshake && record.size() == 6 && record[0] == 20 &&
      record[3] == 0 && record[4] == 1 && record[5] == 1)
    return true;  // Compatibility CCS, never part of the handshake transcript.
  Bytes content;
  uint8_t type = 0;
  if (state_ == State::kHello) {
    if (record.size() < 6 || record.size() > 16389 || record[0] != 22 ||
        Read16(record.subspan(3u, 2u)) != record.size() - 5) {
      return Fail();
    }
    type = 22;
    content.assign(record.begin() + 5, record.end());
  } else if (!receiver_ || !receiver_->Open(record, &type, &content)) {
    return Fail();
  }
  if (type == 21) {
    if (!handshake && content.size() == 2 && content[1] == 0) {
      state_ = State::kClosed;
      return true;
    }
    return Fail();
  }
  if (!handshake) {
    if (type == 22) {
      if (reassembly_.size() + content.size() > 1048576)
        return Fail();
      Append(&reassembly_, content);
      while (reassembly_.size() >= 4) {
        size_t length = Read24(ByteSpan(reassembly_).subspan(1u, 3u));
        if (length > 1048572)
          return Fail();
        if (reassembly_.size() < length + 4)
          break;
        // A KeyUpdate terminates the old record epoch, never a mixed record.
        if (reassembly_[0] == 24 && reassembly_.size() != length + 4)
          return Fail();
        if (!AcceptPostHandshake(ByteSpan(reassembly_).first(length + 4)))
          return false;
        reassembly_.erase(reassembly_.begin(), reassembly_.begin() + length + 4);
      }
      return true;
    }
    if (type != 23 || !reassembly_.empty()) {
      return Fail();
    }
    *application_data = std::move(content);
    return true;
  }
  if (type != 22 || reassembly_.size() + content.size() > 262148 + 16384) {
    return Fail();
  }
  Append(&reassembly_, content);
  return DrainHandshakeFrames();
}

bool Client::AcceptPostHandshake(ByteSpan frame) {
  auto body = frame.subspan(4u);
  if (frame[0] == 24) {
    if (body.size() != 1 || body[0] > 1)
      return Fail();
    if (!DeriveSecret(s_app_, "traffic upd", {}, &s_app_))
      return Fail();
    receiver_ = std::make_unique<RecordCipher>(s_app_);
    update_response_pending_ |= body[0] == 1;
    return true;
  }
  if (frame[0] != 4 || body.size() < 13)
    return Fail();
  SessionTicket ticket;
  ticket.lifetime = Read32(body.first(4u));
  ticket.age_add = Read32(body.subspan(4u, 4u));
  size_t nonce_length = body[8];
  if (nonce_length > body.size() - 11)
    return Fail();
  auto nonce = body.subspan(9u, nonce_length);
  size_t ticket_length = Read16(body.subspan(9 + nonce_length, 2u));
  if (ticket_length == 0 || ticket_length > body.size() - 11 - nonce_length)
    return Fail();
  auto identity = body.subspan(11 + nonce_length, ticket_length);
  ticket.identity.assign(identity.begin(), identity.end());
  std::map<uint16_t, Bytes> extensions;
  if (!Extensions(body.subspan(11 + nonce_length + ticket_length), &extensions))
    return Fail();
  for (const auto& [type, data] : extensions) {
    if (type != 42)
      continue;  // NewSessionTicket is extensible; unknown well-formed values.
    if (data.size() != 4)
      return Fail();
    ticket.max_early_data = Read32(data);
  }
  if (ticket.lifetime == 0 || ticket.lifetime > 604800)
    return true;  // RFC: invalid lifetimes are ignored, not used for resumption.
  if (!DeriveSecret(resumption_, "resumption", nonce, &ticket.psk))
    return Fail();
  ticket.received_milliseconds = MonotonicMilliseconds();
  ticket.hostname = hostname_;
  ticket.certificates = certificates_;
  ticket.client_identity = authenticated_client_identity_;
  if (tickets_.size() == 4)
    tickets_.erase(tickets_.begin());  // Bounded local cache, not a wire limit.
  tickets_.push_back(std::move(ticket));
  return true;
}

std::vector<SessionTicket> Client::TakeTickets() {
  return std::exchange(tickets_, {});
}

bool Client::Export(std::string_view label, ByteSpan context, size_t length,
                    Bytes* output) const {
  if (!established() || label.size() > 249 || length > 255 * 32)
    return false;
  auto secret = Label(exporter_, label, Hash({}), 32);
  *output = Label(secret, "exporter", Hash(context), length);
  OPENSSL_cleanse(secret.data(), secret.size());
  return output->size() == length;
}

bool Client::RequestKeyUpdate(bool request_peer, Bytes* record) {
  if (!established() || close_sent_)
    return false;
  if (!sender_->Seal(Frame(24, Bytes{static_cast<uint8_t>(request_peer)}), 22,
                     record) ||
      !DeriveSecret(c_app_, "traffic upd", {}, &c_app_))
    return Fail();
  sender_ = std::make_unique<RecordCipher>(c_app_);
  update_response_pending_ = false;
  return true;
}

bool Client::DrainHandshakeFrames() {
  while (reassembly_.size() >= 4) {
    size_t length = Read24(ByteSpan(reassembly_).subspan(1u, 3u));
    if (length > 262144 || !Deadline()) {
      return Fail();
    }
    if (reassembly_.size() < 4 + length) {
      return true;
    }
    bool boundary = state_ == State::kHello || state_ == State::kFinished;
    if (boundary && reassembly_.size() != length + 4) {
      return Fail();
    }
    if (!AcceptFrame(ByteSpan(reassembly_).first(length + 4))) {
      return false;
    }
    reassembly_.erase(reassembly_.begin(), reassembly_.begin() + length + 4);
    if (boundary || certificate_verification_pending()) {
      return true;
    }
  }
  return true;
}

bool Client::Send(ByteSpan data, Bytes* record) {
  if (state_ != State::kEstablished || close_sent_) {
    return Fail();
  }
  record->clear();
  if ((update_response_pending_ || sender_->needs_update()) &&
      !RequestKeyUpdate(false, record))
    return false;
  Bytes application;
  if (!sender_->Seal(data, 23, &application))
    return Fail();
  Append(record, application);
  return true;
}

bool Client::Close(Bytes* record) {
  if ((state_ != State::kEstablished && state_ != State::kClosed) ||
      close_sent_) {
    return false;
  }
  close_sent_ = true;
  return sender_->Seal(std::array<uint8_t, 2>{1, 0}, 21, record);
}

}  // namespace net::httpps
