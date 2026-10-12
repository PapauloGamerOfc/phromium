// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/draft01.h"
#include "net/httpps/credential_validation.h"
#include "net/httpps/certificate_features.h"
#include "net/httpps/pinning.h"
#include "net/httpps/ffdhe.h"
#include "net/httpps/integrity_only.h"
#include "net/httpps/native_provider.h"
#include "net/httpps/transparency.h"
#include "net/httpps/dnssec.h"
#include "net/httpps/its_credentials.h"

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <utility>

#if !defined(PHROMIUM_HTTPPS_STANDALONE)
#include "base/memory/stack_allocated.h"
#endif

#include "third_party/boringssl/src/include/openssl/aead.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "third_party/boringssl/src/include/openssl/bn.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/ec.h"
#include "third_party/boringssl/src/include/openssl/ecdh.h"
#include "third_party/boringssl/src/include/openssl/hkdf.h"
#include "third_party/boringssl/src/include/openssl/hmac.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/mlkem.h"
#include "third_party/boringssl/src/include/openssl/nid.h"
#include "third_party/boringssl/src/include/openssl/rand.h"
#include "third_party/boringssl/src/include/openssl/sha.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"
#include "third_party/zlib/zlib.h"
#include "third_party/brotli/include/brotli/decode.h"
#include "third_party/brotli/include/brotli/encode.h"
#include "third_party/zstd/src/lib/zstd.h"

namespace net::httpps {
namespace {

// Keep temporary key material covered on every return path. The vector itself
// must outlive this guard; moving its storage transfers the cleanup obligation.
class ScopedSecretCleanser {
#if !defined(PHROMIUM_HTTPPS_STANDALONE)
  STACK_ALLOCATED();
#endif

 public:
  explicit ScopedSecretCleanser(Bytes& secret) : secret_(secret) {}
  ~ScopedSecretCleanser() {
    OPENSSL_cleanse(secret_.data(), secret_.size());
  }
  ScopedSecretCleanser(const ScopedSecretCleanser&) = delete;
  ScopedSecretCleanser& operator=(const ScopedSecretCleanser&) = delete;

 private:
  Bytes& secret_;
};

ByteSpan Octets(std::string_view value) {
  return StringBytes(value);
}

int64_t WallMilliseconds() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
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

bool Extensions(ByteSpan data, std::map<uint16_t, Bytes>* out,
                uint8_t* alert = nullptr) {
  if (alert) *alert = 50;
  if (data.size() < 2 || Read16(data.first(2u)) != data.size() - 2)
    return false;
  data = data.subspan(2u);
  while (!data.empty()) {
    if (data.size() < 4)
      return false;
    uint16_t type = static_cast<uint16_t>(Read16(data.first(2u)));
    size_t length = Read16(data.subspan(2u, 2u));
    if (length > data.size() - 4)
      return false;
    if (out->count(type)) {
      if (alert && type == 43) *alert = 47;
      return false;
    }
    auto value = data.subspan(4u, length);
    out->emplace(type, Bytes(value.begin(), value.end()));
    data = data.subspan(4 + length);
  }
  return true;
}

enum class ResponseContext { kServerHello, kRetry, kEncryptedExtensions, kCertificate };

bool ResponseExtensionAllowed(uint16_t type, ResponseContext context) {
  // Placement and solicitation are independent. Unknown responses still need
  // an actual offer; known extensions in a forbidden message use alert 47.
  switch (type) {
    case 0: case 1: case 10: case 15: case 16: case 19: case 20: case 25:
    case 28: case 32: case 42: case 55: case 56: case 58:
      return context == ResponseContext::kEncryptedExtensions;
    case 33: case 41:
      return context == ResponseContext::kServerHello;
    case 31: case 44:
      return context == ResponseContext::kRetry;
    case 43: case 51:
      return context == ResponseContext::kServerHello || context == ResponseContext::kRetry;
    case 5: case 18: case 34: case 52: case 59:
      return context == ResponseContext::kCertificate;
    case 2: case 3: case 4: case 13: case 17: case 21:
    case 27: case 29: case 30: case 45: case 47: case 48:
    case 49: case 50: case 0xff02: case 0xff03: case 0xff04:
      return false;
    default:
      return true;
  }
}

int GroupNid(uint16_t group) {
  switch (group) {
    case 23: return NID_X9_62_prime256v1;
    case 24: return NID_secp384r1;
    case 25: return NID_secp521r1;
    default: return NID_undef;
  }
}

bool EcKeypair(uint16_t group, Bytes* private_key, Bytes* public_key) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(GroupNid(group)));
  if (!key)
    return false;
  private_key->resize((EC_GROUP_get_degree(EC_KEY_get0_group(key.get())) + 7) / 8);
  public_key->resize(1 + 2 * private_key->size());
  return key && EC_KEY_generate_key(key.get()) &&
      BN_bn2bin_padded(private_key->data(), private_key->size(),
                       EC_KEY_get0_private_key(key.get())) &&
      EC_POINT_point2oct(EC_KEY_get0_group(key.get()),
                        EC_KEY_get0_public_key(key.get()),
                        POINT_CONVERSION_UNCOMPRESSED, public_key->data(),
                        public_key->size(), nullptr) == public_key->size();
}

bool EcAgreement(uint16_t group, ByteSpan private_key, ByteSpan peer, Bytes* shared) {
  if (peer.size() != 1 + 2 * private_key.size() || peer[0] != 4)
    return false;
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(GroupNid(group)));
  bssl::UniquePtr<BIGNUM> scalar(
      BN_bin2bn(private_key.data(), private_key.size(), nullptr));
  if (!key || !scalar || !EC_KEY_set_private_key(key.get(), scalar.get()))
    return false;
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(EC_KEY_get0_group(key.get())));
  shared->resize(private_key.size());
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

Secret CredentialIdentity(const std::vector<std::string>& certificates) {
  Bytes encoded;
  for (const auto& der : certificates) {
    U32(&encoded, der.size());
    Append(&encoded, Octets(der));
  }
  return Hash(encoded);
}

bool ProvisioningKey(const std::vector<std::string>& chain, uint8_t type,
                     const std::vector<std::map<uint16_t, Bytes>>& metadata,
                     Secret* key) {
  if (chain.empty() || std::any_of(metadata.begin(), metadata.end(),
                                  [](const auto& values) { return !values.empty(); }))
    return false;
  if (type == 2)
    return chain.size() == 1 && ExtractRawPublicKey(Octets(chain[0]), key);
  if (type != 0)
    return false;
  for (const auto& der : chain) {
    const uint8_t* input = Octets(der).data();
    bssl::UniquePtr<X509> parsed(d2i_X509(nullptr, &input, der.size()));
    if (!parsed || input != Octets(der).subspan(der.size()).data())
      return false;
  }
  return ExtractServerPublicKey(chain[0], key);
}

Secret PskBinding(const ExternalPSK& psk) {
  Bytes encoded;
  for (ByteSpan value : {ByteSpan(psk.identity), Octets(psk.hostname), Octets(psk.alpn)}) {
    U16(&encoded, value.size());
    Append(&encoded, value);
  }
  U16(&encoded, psk.cipher_suite);
  encoded.push_back(psk.imported);
  encoded.push_back(psk.combined);
  return net::httpps::Mac(psk.secret, encoded);
}

const EVP_MD* SuiteDigest(uint16_t suite) {
  switch (suite) {
    case 0x1301: case 0x1303: case 0x1304: case 0x1305: case 0xc0b4:
    case 0xc0b0: case 0xc0b2: return EVP_sha256();
    case 0x1302: case 0xc0b5: case 0xc0b1: case 0xc0b3: return EVP_sha384();
    default: return nullptr;
  }
}

const EVP_AEAD* SuiteAead(uint16_t suite) {
  switch (suite) {
    case 0x1301: case 0xc0b0: return EVP_aead_aes_128_gcm();
    case 0x1302: case 0xc0b1: return EVP_aead_aes_256_gcm();
    case 0x1303: return EVP_aead_chacha20_poly1305();
    case 0x1304: case 0xc0b2: return EVP_aead_aes_128_ccm_tls();
    case 0x1305: return EVP_aead_aes_128_ccm_8_tls();
    default: return nullptr;
  }
}

bool PasswordSuite(uint16_t suite) { return suite >= 0xc0b0 && suite <= 0xc0b3; }
uint16_t PasswordSuccessor(uint16_t suite) {
  return suite == 0xc0b0 ? 0x1301 : suite == 0xc0b2 ? 0x1304 :
      suite == 0xc0b1 || suite == 0xc0b3 ? 0x1302 : suite;
}

bool ParseCertificates(ByteSpan body, std::vector<std::string>* certificates,
                        std::vector<std::map<uint16_t, Bytes>>* entry_extensions,
                        uint8_t* alert) {
  *alert = 50;
  if (body.size() < 4 || body[0] != 0 ||
      Read24(body.subspan(1u, 3u)) != body.size() - 4) {
    return false;
  }
  body = body.subspan(4u);
  while (!body.empty()) {
    if (certificates->size() >= kMaxCertificates || body.size() < 5) {
      return false;
    }
    size_t length = Read24(body.first(3u));
    if (!length || length > 65536 || length > body.size() - 5) {
      return false;
    }
    const size_t extensions_length = Read16(body.subspan(3 + length, 2u));
    if (extensions_length > body.size() - 5 - length)
      return false;
    std::map<uint16_t, Bytes> extensions;
    if (!Extensions(body.subspan(3 + length, 2 + extensions_length), &extensions, alert))
      return false;
    const auto certificate = body.subspan(3u, length);
    certificates->emplace_back(
        reinterpret_cast<const char*>(certificate.data()), certificate.size());
    entry_extensions->push_back(std::move(extensions));
    body = body.subspan(length + 5 + extensions_length);
  }
  return !certificates->empty();
}

bool DecompressCertificate(ByteSpan body, Bytes* decompressed, uint8_t* alert) {
  *alert = 47;
  if (body.size() < 9 || Read24(body.subspan(5u, 3u)) != body.size() - 8)
    return false;
  const size_t size = Read24(body.subspan(2u, 3u));
  // This is the existing engine handshake memory budget, not a wire limit.
  if (!size || size > 1048572)
    return false;
  // RFC8879 requires bad_certificate for failed decompression or a declared
  // output-length mismatch, distinct from the envelope/offer checks above.
  *alert = 42;
  auto input = body.subspan(8u);
  decompressed->resize(size);
  switch (Read16(body.first(2u))) {
    case 1: {
      uLongf written = size;
      uLong consumed = input.size();
      return uncompress2(decompressed->data(), &written, input.data(), &consumed) == Z_OK &&
             written == size && consumed == input.size();
    }
    case 2: {
      auto* state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
      if (!state)
        return false;
      size_t available_in = input.size(), available_out = size;
      const uint8_t* next_in = input.data();
      uint8_t* next_out = decompressed->data();
      const auto result = BrotliDecoderDecompressStream(state, &available_in, &next_in,
                                                       &available_out, &next_out, nullptr);
      BrotliDecoderDestroyInstance(state);
      return result == BROTLI_DECODER_RESULT_SUCCESS && available_in == 0 && available_out == 0;
    }
    case 3:
      // RFC8879 adopts RFC8478's stream of concatenated and skippable frames,
      // not just its first frame. The one-shot decoder consumes the entire
      // input and rejects incomplete/trailing data; its fixed destination
      // enforces the declared output bound even across multiple frames.
      return ZSTD_decompress(decompressed->data(), size, input.data(), input.size()) == size;
    default:
      *alert = 47;
      return false;
  }
}

bool CompressCertificate(ByteSpan body, uint16_t algorithm, Bytes* frame) {
  Bytes compressed;
  size_t written;
  switch (algorithm) {
    case 1: {
      uLongf size = compressBound(body.size());
      compressed.resize(size);
      if (compress2(compressed.data(), &size, body.data(), body.size(), Z_DEFAULT_COMPRESSION) != Z_OK)
        return false;
      written = size;
      break;
    }
    case 2:
      written = BrotliEncoderMaxCompressedSize(body.size());
      compressed.resize(written);
      if (!BrotliEncoderCompress(5, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC,
              body.size(), body.data(), &written, compressed.data()))
        return false;
      break;
    case 3:
      compressed.resize(ZSTD_compressBound(body.size()));
      written = ZSTD_compress(compressed.data(), compressed.size(), body.data(), body.size(), 3);
      if (ZSTD_isError(written))
        return false;
      break;
    default:
      return false;
  }
  compressed.resize(written);
  Bytes encoded;
  U16(&encoded, algorithm);
  auto length = Frame(0, body);
  Append(&encoded, ByteSpan(length).subspan(1u, 3u));
  auto vector = Frame(0, compressed);
  Append(&encoded, ByteSpan(vector).subspan(1u));
  *frame = Frame(25, encoded);
  return true;
}

Bytes CertificateMaterial(const std::vector<std::string>& certificates) {
  Bytes list;
  for (const auto& der : certificates) {
    auto entry = Frame(0, Octets(der));
    Append(&list, ByteSpan(entry).subspan(1u));
  }
  auto vector = Frame(0, list);
  return Bytes(vector.begin() + 1, vector.end());
}

bool RequestTemplate(ByteSpan extensions, Bytes* output) {
  std::map<uint16_t, Bytes> parsed;
  if (!Extensions(extensions, &parsed) || parsed.count(13))
    return false;
  Bytes raw;
  auto remaining = extensions.subspan(2u);
  while (!remaining.empty()) {
    const size_t size = 4 + Read16(remaining.subspan(2u, 2u));
    if (Read16(remaining.first(2u)) != 0xff03)
      Append(&raw, remaining.first(size));
    remaining = remaining.subspan(size);
  }
  output->clear();
  Vector16(output, raw);
  return true;
}

bool ResolveCachedCertificate(ByteSpan body, const ClientOptions& options, uint8_t type,
                               Bytes* reconstructed) {
  if (body.size() < 36 || body[0] != 0 || Read24(body.subspan(33u, 3u)) != body.size() - 36)
    return false;
  const std::vector<std::string>* matched = nullptr;
  for (const auto& [kind, chain] : options.cached_certificates) {
    if (Equal(net::httpps::Hash(CertificateMaterial(chain)), body.subspan(1u, 32u))) {
      if (kind != type || (matched && *matched != chain))
        return false;
      matched = &chain;
    }
  }
  if (!matched)
    return false;
  Bytes entries;
  auto metadata = body.subspan(36u);
  for (const auto& der : *matched) {
    if (metadata.size() < 2)
      return false;
    const size_t size = Read16(metadata.first(2u));
    if (size > metadata.size() - 2)
      return false;
    auto entry = Frame(0, Octets(der));
    Append(&entries, ByteSpan(entry).subspan(1u));
    Append(&entries, metadata.first(size + 2));
    metadata = metadata.subspan(size + 2);
    if (entries.size() > 1048568)
      return false;
  }
  if (!metadata.empty())
    return false;
  auto list = Frame(0, entries);
  *reconstructed = {0};
  Append(reconstructed, ByteSpan(list).subspan(1u));
  return true;
}

}  // namespace

std::string ValidatedPrivateIssuer(const std::vector<std::string>& chain,
    const std::vector<std::string>& anchors, std::string_view hostname,
    bool signing_parent, const NativeProvider* provider) {
  const auto path = ValidatedPrivatePath(chain, anchors, hostname, signing_parent, provider);
  return path.size() > 1 ? path[1] : std::string{};
}

std::vector<std::string> ValidatedPrivatePath(const std::vector<std::string>& chain,
    const std::vector<std::string>& anchors, std::string_view hostname,
    bool signing_parent, const NativeProvider* provider) {
  if (provider) {
    auto path = provider->VerifyCertificatePath(chain, anchors, hostname);
    if (path)
      return *path;
  }
  Secret ignored;
  for (const auto& anchor : anchors) {
    if (VerifyLabChain(chain, {anchor}, hostname, &ignored, signing_parent)) {
      auto result = chain;
      if (result.back() != anchor)
        result.push_back(anchor);
      return result;
    }
  }
  return {};
}

std::optional<int> VerifyDNSSECPolicy(const DANEPolicy* policy, std::string_view hostname,
    const std::vector<std::string>& chain, uint8_t certificate_type,
    const std::vector<std::map<uint16_t, Bytes>>& extensions,
    const std::vector<std::string>& validated_path, int64_t* expires_unix_seconds,
    std::vector<std::string>* authenticated_path) {
  if (authenticated_path) *authenticated_path = validated_path;
  if (!policy)
    return -1;
  if (!policy->IsValid() || extensions.empty())
    return {};
  const auto evidence = extensions.front().find(59);
  if (evidence == extensions.front().end())
    return {};
  std::vector<DNSBytes> material;
  // Locally validated roots/intermediates may be omitted on the wire. They are
  // valid DANE-TA candidates, unlike an unverified guessed issuer.
  for (const auto& value : (validated_path.empty() ? chain : validated_path))
    material.emplace_back(value.begin(), value.end());
  auto effective = *policy;
  if (!validated_path.empty()) {
    // This result comes from the caller's CURRENT verifier, not from peer
    // metadata. The policy context still identifies that verifier's scope.
    effective.pkix_validator = [&validated_path](const std::vector<DNSBytes>& received)
        -> std::optional<std::vector<DNSBytes>> {
      if (received.empty() || !Equal(received.front(), Octets(validated_path.front())))
        return {};
      std::vector<DNSBytes> path;
      for (const auto& value : validated_path)
        path.emplace_back(value.begin(), value.end());
      return path;
    };
    if (effective.application_policy_context.empty())
      effective.application_policy_context = {'c','u','r','r','e','n','t','-','p','k','i','x'};
  }
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  const auto result = effective.Verify(hostname, material, certificate_type, evidence->second, now);
  if (result && expires_unix_seconds)
    *expires_unix_seconds = result->expires_unix_seconds;
  if (result && authenticated_path && !result->validated_path.empty()) {
    authenticated_path->clear();
    for (const auto& value : result->validated_path)
      authenticated_path->emplace_back(value.begin(), value.end());
  }
  return result ? std::optional<int>(result->usage) : std::nullopt;
}

bool VerifyCertificateTransparency(const CTv2Policy* policy,
    const std::vector<std::string>& chain,
    const std::vector<std::map<uint16_t, Bytes>>& extensions,
    std::string_view validated_issuer) {
  if (!policy)
    return true;
  if (!policy->IsValid() || chain.empty() || validated_issuer.empty())
    return false;
  ByteSpan tls, ocsp;
  if (!extensions.empty()) {
    if (const auto found = extensions.front().find(52); found != extensions.front().end())
      tls = found->second;
    if (const auto found = extensions.front().find(5); found != extensions.front().end()) {
      const ByteSpan value = found->second;
      if (value.size() < 5 || value[0] != 1 ||
          ((size_t(value[1]) << 16) | (size_t(value[2]) << 8) | value[3]) != value.size() - 4)
        return false;
      ocsp = value.subspan(4u);
    }
  }
  const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  return now >= 0 && policy->Verify(Octets(chain.front()), Octets(validated_issuer),
                                   tls, ocsp, static_cast<uint64_t>(now)).has_value();
}

bool ExtractRawPublicKey(ByteSpan spki, Secret* public_key) {
  constexpr std::array<uint8_t, 12> prefix{
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0};
  if (spki.size() != 44 || !Equal(spki.first(12u), prefix))
    return false;
  CopySecret(spki.subspan(12u), public_key);
  return true;
}

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
  // SNI never encodes IP literals. URL parsing has already canonicalized
  // internationalized names to ASCII A-labels.
  return !all_numeric;
}

bool IsIpIdentity(std::string_view name) {
  if (name.empty() || name.size() > 45 ||
      name.find_first_of(std::string_view("\0%[]", 4)) != std::string_view::npos)
    return false;
  const std::string terminated(name);
  bssl::UniquePtr<ASN1_OCTET_STRING> address(a2i_IPADDRESS(terminated.c_str()));
  return address && (ASN1_STRING_length(address.get()) == 4 ||
                     ASN1_STRING_length(address.get()) == 16);
}

bool ValidServiceIdentity(std::string_view name) {
  return ValidServerName(name) || IsIpIdentity(name);
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
  return SuiteLabel(0x1301, secret, label, context, length);
}

size_t SuiteHashLength(uint16_t suite) {
  if (suite == 0x00c6 || suite == 0x00c7 || GostTagLength(suite))
    return 32;
  const auto* digest = SuiteDigest(suite);
  return digest ? EVP_MD_size(digest) : 0;
}

uint16_t SuiteHashId(uint16_t suite) {
  return GostTagLength(suite) ? 4 : suite == 0x00c6 || suite == 0x00c7 ? 3 : SuiteHashLength(suite) == 48 ? 2 : SuiteHashLength(suite) == 32 ? 1 : 0;
}
Bytes SuiteHash(uint16_t suite, ByteSpan input, const NativeProvider* provider) {
  if (GostTagLength(suite)) return provider ? provider->GostHash(input) : Bytes{};
  if (suite == 0x00c6 || suite == 0x00c7)
    return provider ? provider->Sm3(input) : Bytes{};
  const auto* digest = SuiteDigest(suite);
  if (!digest)
    return {};
  Bytes output(EVP_MD_size(digest));
  unsigned length = 0;
  if (!EVP_Digest(input.data(), input.size(), output.data(), &length, digest, nullptr))
    return {};
  return output;
}

Bytes SuiteMac(uint16_t suite, ByteSpan key, ByteSpan input, const NativeProvider* provider) {
  if (GostTagLength(suite)) return provider ? provider->GostMac(key, input) : Bytes{};
  if (suite == 0x00c6 || suite == 0x00c7)
    return provider ? provider->Sm3Mac(key, input) : Bytes{};
  const auto* digest = SuiteDigest(suite);
  if (!digest)
    return {};
  Bytes output(EVP_MD_size(digest));
  unsigned length = 0;
  if (!HMAC(digest, key.data(), key.size(), input.data(), input.size(), output.data(), &length))
    return {};
  return output;
}

Bytes SuiteLabel(uint16_t suite, ByteSpan secret, std::string_view label,
                  ByteSpan context, size_t length, const NativeProvider* provider) {
  const auto* digest = SuiteDigest(suite);
  std::string full_label = "tls20 ";
  full_label += label;
  const bool sm = suite == 0x00c6 || suite == 0x00c7;
  const bool gost = GostTagLength(suite) != 0;
  if ((!digest && (!(sm || gost) || !provider)) || full_label.size() > 255 || context.size() > 255 ||
      length > 255 * SuiteHashLength(suite)) {
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
  if (sm)
    return provider->Sm3Expand(secret, info, length);
  if (gost) return provider->GostExpand(secret, info, length);
  if (!HKDF_expand(result.data(), result.size(), digest, secret.data(),
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

ExternalPSK::~ExternalPSK() {
  OPENSSL_cleanse(secret.data(), secret.size());
}

PasswordCredential::~PasswordCredential() {
  OPENSSL_cleanse(password.data(), password.size());
}

std::optional<ExternalPSK> ImportPSK(
    ByteSpan base_key, ByteSpan identity, ByteSpan context, std::string hostname,
    std::string alpn, uint16_t base_suite, uint16_t target_suite, bool combined) {
  if (base_key.empty() || identity.empty() || identity.size() > 65535 ||
      context.size() > 65535 || !ValidServiceIdentity(hostname) || alpn.empty() ||
      alpn.size() > 255 || !SuiteHashLength(base_suite) || !SuiteHashLength(target_suite) ||
      SuiteHashId(base_suite) > 2 || SuiteHashId(target_suite) > 2)
    return std::nullopt;
  ExternalPSK result;
  Vector16(&result.identity, identity);
  Vector16(&result.identity, context);
  U16(&result.identity, 0x0400);
  U16(&result.identity, SuiteHashLength(target_suite) == 48 ? 2 : 1);
  if (result.identity.size() > 65535)
    return std::nullopt;
  auto extracted = SuiteMac(base_suite, Bytes(SuiteHashLength(base_suite)), base_key);
  result.secret = SuiteLabel(base_suite, extracted, "derived psk",
                            SuiteHash(base_suite, result.identity), SuiteHashLength(target_suite));
  OPENSSL_cleanse(extracted.data(), extracted.size());
  if (result.secret.size() != SuiteHashLength(target_suite))
    return std::nullopt;
  result.hostname = std::move(hostname);
  result.alpn = std::move(alpn);
  result.cipher_suite = target_suite;
  result.imported = true;
  result.combined = combined;
  return result;
}

RecordCipher::RecordCipher(ByteSpan secret, uint16_t suite, std::shared_ptr<NativeProvider> provider)
    : native_provider_(std::move(provider)), suite_(suite) {
  SetLimit(0);
  const auto integrity_size = IntegrityTagLength(suite);
  const auto gost_size = GostTagLength(suite);
  key_.resize(integrity_size ? integrity_size : gost_size || suite == 0x1302 || suite == 0x1303 || suite == 0xc0b1 || suite == 0xc0b3 ? 32 : 16);
  iv_.resize(integrity_size ? integrity_size : gost_size ? gost_size : 12);
  auto key = SuiteLabel(suite_, secret, "key", {}, key_.size(), native_provider_.get());
  auto iv = SuiteLabel(suite_, secret, "iv", {}, iv_.size(), native_provider_.get());
  const bool sm = SuiteHashId(suite) == 3 && native_provider_ && native_provider_->SupportsSM();
  const bool pwd_ccm = suite == 0xc0b3 && native_provider_ && native_provider_->SupportsPasswordAead();
  const bool gost = gost_size && native_provider_ && native_provider_->SupportsGost();
  failed_ = (!integrity_size && !sm && !pwd_ccm && !gost && !SuiteAead(suite_)) || secret.size() != SuiteHashLength(suite_) || key.size() != key_.size() ||
            iv.size() != iv_.size();
  if (!failed_) {
    std::copy(key.begin(), key.end(), key_.begin());
    std::copy(iv.begin(), iv.end(), iv_.begin());
    if (gost) gost_record_ = std::make_unique<NativeGostRecord>(native_provider_, suite_, key_);
  }
  OPENSSL_cleanse(key.data(), key.size());
  OPENSSL_cleanse(iv.data(), iv.size());
}

RecordCipher::~RecordCipher() {
  OPENSSL_cleanse(key_.data(), key_.size());
  OPENSSL_cleanse(iv_.data(), iv_.size());
}

bool RecordCipher::needs_update() const {
  if (GostTagLength(suite_)) return sequence_ >= GostSequenceLimit(suite_) - 1024;
  const uint64_t limit = suite_ == 0x1303 || IntegrityTagLength(suite_) ? std::numeric_limits<uint64_t>::max()
      : suite_ == 0x1304 || suite_ == 0x1305 || suite_ == 0x00c7 || suite_ == 0xc0b2 || suite_ == 0xc0b3 ? uint64_t{1} << 23 : 23726566;
  return sequence_ >= limit - 1024;
}

bool RecordCipher::Account(size_t length, bool sending) {
  // RFC 9846 section 5.5 and RFC 9147 appendix B's CCM analysis. A receiver
  // does not impose the sender's conservative usage policy on a peer.
  const uint64_t limit = suite_ == 0x1303 || IntegrityTagLength(suite_) ? std::numeric_limits<uint64_t>::max()
      : suite_ == 0x1304 || suite_ == 0x1305 || suite_ == 0x00c7 || suite_ == 0xc0b2 || suite_ == 0xc0b3 ? uint64_t{1} << 23 : 23726566;
  if (failed_ || sequence_ == std::numeric_limits<uint64_t>::max() ||
      (GostTagLength(suite_) ? sequence_ > GostSequenceLimit(suite_) : (sending && sequence_ >= limit)) || length > kMaxRecordContent + 239) {
    failed_ = true;
    return false;
  }
  ++sequence_;
  content_bytes_ += length;
  return true;
}

bool RecordCipher::Seal(ByteSpan content, uint8_t type, Bytes* record,
                        size_t padding) {
  if (failed_ || (type != 21 && type != 22 && type != 23 && type != 24) ||
      content.size() > content_limit_ || padding > inner_limit_ ||
      content.size() + padding + 1 > inner_limit_ ||
      (type == 21 && content.size() != 2) || (type == 22 && content.empty())) {
    failed_ = true;
    return false;
  }
  auto nonce = iv_;
  for (size_t i = 0; i < 8; ++i) {
    nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>(sequence_ >> (8 * i));
  }
  if (!Account(content.size(), true)) {
    return false;
  }
  Bytes plaintext(content.begin(), content.end());
  plaintext.push_back(type);
  plaintext.resize(plaintext.size() + padding, 0);
  *record = {23, 3, 3};
  const size_t integrity_size = IntegrityTagLength(suite_);
  const size_t tag = integrity_size ? integrity_size : GostTagLength(suite_) ? GostTagLength(suite_) : suite_ == 0x1305 ? 8 : 16;
  U16(record, plaintext.size() + tag);
  if (integrity_size || SuiteHashId(suite_) == 3 || suite_ == 0xc0b3 || gost_record_) {
    Bytes protected_data;
    const bool ok = integrity_size ? IntegrityProtect(suite_, key_, nonce, *record, plaintext, &protected_data)
        : gost_record_ ? gost_record_->Crypt(true, sequence_ - 1, nonce, *record, plaintext, &protected_data)
        : suite_ == 0xc0b3 ? native_provider_->PasswordAead(true, key_, nonce, *record, plaintext, &protected_data)
        : native_provider_->Sm4(true, suite_, key_, nonce, *record, plaintext, &protected_data);
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    if (!ok) {
      failed_ = true;
      record->clear();
      return false;
    }
    Append(record, protected_data);
    return true;
  }
  record->resize(5 + plaintext.size() + tag);
  bssl::ScopedEVP_AEAD_CTX context;
  size_t written = 0;
  bool ok =
      EVP_AEAD_CTX_init(context.get(), SuiteAead(suite_), key_.data(),
                        key_.size(), tag, nullptr) &&
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
  const size_t integrity_size = IntegrityTagLength(suite_);
  const size_t tag = integrity_size ? integrity_size : GostTagLength(suite_) ? GostTagLength(suite_) : suite_ == 0x1305 ? 8 : 16;
  const auto reject = [&](uint8_t alert) {
    alert_ = alert;
    failed_ = true;
    return false;
  };
  if (failed_) return false;
  if (record.size() < 5) return reject(50);
  if (record[0] != 23) return reject(10);
  if (record[1] != 3 || record[2] != 3) return reject(47);
  const size_t length = Read16(record.subspan(3u, 2u));
  // The transport may hand off only an oversized header, avoiding allocation
  // or reads of an invalid fragment. Preserve its record_overflow diagnosis.
  if (length > kMaxRecord - 5) return reject(22);
  if (length != record.size() - 5) return reject(50);
  if (length < tag) return reject(20);
  auto nonce = iv_;
  for (size_t i = 0; i < 8; ++i) {
    nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>(sequence_ >> (8 * i));
  }
  const size_t protected_plaintext = record.size() - 5 - tag;
  if (!Account(protected_plaintext ? protected_plaintext - 1 : 0, false)) {
    return false;
  }
  bssl::ScopedEVP_AEAD_CTX context;
  Bytes plaintext(record.size() - 5 - tag);
  size_t written = 0;
  bool ok = integrity_size
      ? IntegrityUnprotect(suite_, key_, nonce, record.first(5u), record.subspan(5u), &plaintext)
      : gost_record_ ? gost_record_->Crypt(false, sequence_ - 1, nonce, record.first(5u), record.subspan(5u), &plaintext)
      : suite_ == 0xc0b3 ? native_provider_->PasswordAead(false, key_, nonce, record.first(5u), record.subspan(5u), &plaintext)
      : SuiteHashId(suite_) == 3 ? native_provider_->Sm4(false, suite_, key_, nonce, record.first(5u), record.subspan(5u), &plaintext) :
      EVP_AEAD_CTX_init(context.get(), SuiteAead(suite_), key_.data(),
                        key_.size(), tag, nullptr) &&
      EVP_AEAD_CTX_open(context.get(), plaintext.data(), &written,
                        plaintext.size(), nonce.data(), nonce.size(),
                        record.subspan(5u).data(), record.size() - 5,
                        record.data(), 5);
  if (integrity_size || SuiteHashId(suite_) == 3 || suite_ == 0xc0b3 || gost_record_)
    written = plaintext.size();
  if (!ok || written != plaintext.size() || written > inner_limit_) {
    if (ok && written == plaintext.size() && written > inner_limit_)
      alert_ = 22;
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    failed_ = true;
    return false;
  }
  max_opened_inner_ = std::max(max_opened_inner_, written);
  while (!plaintext.empty() && plaintext.back() == 0)
    plaintext.pop_back();
  if (plaintext.empty()) {
    alert_ = 10;
    failed_ = true;
    return false;
  }
  *type = plaintext.back();
  plaintext.pop_back();
  if (plaintext.size() > content_limit_ ||
      (*type != 21 && *type != 22 && *type != 23 && *type != 24) ||
      (*type == 21 && plaintext.size() != 2) ||
      (*type == 22 && plaintext.empty())) {
    alert_ = plaintext.size() > content_limit_ ? 22 :
        (*type != 21 && *type != 22 && *type != 23 && *type != 24) ||
        ((*type == 21 || *type == 22) && plaintext.empty()) ? 10 : 50;
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    failed_ = true;
    return false;
  }
  max_opened_content_ = std::max(max_opened_content_, plaintext.size());
  *content = std::move(plaintext);
  return true;
}

Client::Client(std::string hostname,
               std::vector<std::string> trust_anchors,
               bool use_external_verifier,
               ClientOptions options)
    : hostname_(std::move(hostname)),
      anchors_(std::move(trust_anchors)),
      options_(std::move(options)),
      use_external_verifier_(use_external_verifier) {}

Client::~Client() {
  EraseConnectionSecrets();
}

Bytes Client::Hash(ByteSpan input) const { return SuiteHash(suite_, input, options_.native_provider.get()); }
Bytes Client::Mac(ByteSpan key, ByteSpan input) const { return SuiteMac(suite_, key, input, options_.native_provider.get()); }
Bytes Client::Label(ByteSpan secret, std::string_view label, ByteSpan context,
                    size_t length) const {
  return SuiteLabel(suite_, secret, label, context,
      length == static_cast<size_t>(-1) ? SuiteHashLength(suite_) : length, options_.native_provider.get());
}
bool Client::DeriveSecret(ByteSpan secret, std::string_view label,
                          ByteSpan context, Bytes* output) const {
  // KeyUpdate derives in place. Read all inputs before erasing the previous
  // generation, including when the secret or context aliases the destination.
  auto derived = Label(secret, label, context);
  ScopedSecretCleanser cleanse_derived(derived);
  OPENSSL_cleanse(output->data(), output->size());
  output->clear();
  if (derived.size() != SuiteHashLength(suite_))
    return false;
  output->swap(derived);
  return true;
}
Bytes Client::Finished(ByteSpan secret, ByteSpan transcript) const {
  auto key = Label(secret, "finished", {});
  auto value = Mac(key, Hash(transcript));
  OPENSSL_cleanse(key.data(), key.size());
  return value;
}

void Client::EraseHandshakeSecrets() {
  password_state_.reset();
  native_traffic_key_.reset();
  for (auto* secret : {&a_, &b_}) {
    OPENSSL_cleanse(secret->data(), secret->size());
  }
  for (auto* secret : {&ec_private_, &kem_seed_, &root_, &c_hs_, &s_hs_, &expected_proof_}) {
    OPENSSL_cleanse(secret->data(), secret->size());
  }
  if (!options_.post_handshake_auth || state_ == State::kFailed)
    client_credential_.reset();
  for (auto& binding : options_.bootstraps) binding.credential.reset();
  if (options_.bootstrap) options_.bootstrap->credential.reset();
  OPENSSL_cleanse(client_verifier_share_.data(), client_verifier_share_.size());
}

void Client::EraseConnectionSecrets() {
  DisableAuthenticators();
  EraseHandshakeSecrets();
  for (auto* secret : {&master_, &c_app_, &s_app_, &exporter_, &resumption_,
                       &early_exporter_}) {
    OPENSSL_cleanse(secret->data(), secret->size());
    secret->clear();
  }
  for (auto* secret : {&password_context_, &external_psk_binding_})
    OPENSSL_cleanse(secret->data(), secret->size());
  sender_.reset();
  receiver_.reset();
  early_sender_.reset();
  client_credential_.reset();
  // These are connection-owned copies. Their destructors erase secret bytes;
  // releasing a shared provisioned credential never mutates its other owners.
  offered_ticket_.reset();
  // A fully orderly close may precede the caller's handoff to its ticket cache.
  // Fatal failure still invalidates every unconsumed connection-owned ticket.
  if (state_ != State::kClosed || !close_sent_)
    tickets_.clear();
  offered_psks_.clear();
  options_.external_psks.clear();
  options_.password.reset();
  options_.pinning.reset();
}

bool Client::Fail(Error error) {
  return Fail(error, error == Error::kCertificate ? 42 : 47);
}

bool Client::Fail(Error error, uint8_t alert) {
  if (state_ == State::kFailed) {
    return false;
  }
  // Do not create an alert that skips already-encrypted unflushed records.
  // The transport may also suppress it if an application write is in flight.
  if (state_ != State::kNew && !close_sent_ && output_.empty() && alert &&
      error != Error::kTimeout) {
    Bytes value{2, alert};
    if (sender_)
      sender_->Seal(value, 21, &fatal_alert_);
    else if (state_ == State::kHello) {
      fatal_alert_ = {21, 3, 3, 0, 2};
      Append(&fatal_alert_, value);
    }
  }
  state_ = State::kFailed;
  error_ = error;
  EraseConnectionSecrets();
  output_.clear();
  reassembly_.clear();
  return false;
}

bool Client::Deadline() {
  return MonotonicMilliseconds() < deadline_milliseconds_ ||
         Fail(Error::kTimeout);
}

void Client::Diagnostic(std::string_view label, ByteSpan secret, bool exporter) {
#if defined(PHROMIUM_HTTPPS_TEST_DIAGNOSTICS)
  if (!options_.authorize_test_diagnostics || !options_.diagnostic_sink ||
      (exporter && !options_.authorize_exporter_diagnostics))
    return;
  std::string entry(label);
  constexpr char digits[] = "0123456789abcdef";
  for (auto bytes : {ByteSpan(diagnostic_random_), secret}) {
    entry.push_back(' ');
    for (uint8_t value : bytes) {
      entry.push_back(digits[value >> 4]);
      entry.push_back(digits[value & 15]);
    }
  }
  entry.push_back('\n');
  if (!options_.diagnostic_sink(entry)) {
    diagnostic_failed_ = true;
    options_.diagnostic_sink = {};
  }
  OPENSSL_cleanse(entry.data(), entry.size());
#else
  (void)label;
  (void)secret;
  (void)exporter;
#endif
}

bool Client::SetClientCredential(const ClientCredential& credential) {
  if (state_ != State::kNew || credential.certificates.empty() ||
      credential.certificates.size() > kMaxCertificates ||
      (credential.certificate_type != 0 && credential.certificate_type != 2 && credential.certificate_type != 3) ||
      (credential.certificate_type != 0 && credential.certificates.size() != 1))
    return false;
  size_t total = 0;
  for (const auto& der : credential.certificates) {
    if (der.empty() || der.size() > 65536 || (total += der.size()) > 262144)
      return false;
  }
  if (credential.ocsp_responses.size() > credential.certificates.size() ||
      (credential.certificate_type != 0 && !credential.ocsp_responses.empty()))
    return false;
  for (const auto& response : credential.ocsp_responses) {
    if (response.empty()) continue;
    // Each CE extension vector is uint16; its status_type/uint24 and extension
    // header consume eight bytes. This is syntax/budget validation, not trust.
    CBS input, sequence;
    CBS_init(&input, response.data(), response.size());
    if (response.size() > 65527 || (total += response.size() + 8) > 262144 ||
        !CBS_get_asn1(&input, &sequence, CBS_ASN1_SEQUENCE) || CBS_len(&input) ||
        !CBS_len(&sequence))
      return false;
  }
  Secret actual, expected;
  X25519_public_from_private(actual.data(), credential.private_key.data());
  if (credential.certificate_type == 3) {
    if (!credential.its_policy || !credential.delegation.empty()) return false;
    const auto authorization = credential.its_policy->Verify(Octets(credential.certificates.front()),
        1, credential.its_policy->identity, WallMilliseconds());
    if (!authorization || !Equal(actual, authorization->public_key)) return false;
    client_credential_ = credential;
    return true;
  }
  if (!(credential.certificate_type == 2
            ? ExtractRawPublicKey(Octets(credential.certificates.front()), &expected)
            : !credential.delegation.empty()
                ? ValidateLocalClientDelegation(credential.certificates.front(), credential.delegation,
                                               &expected, options_.native_provider.get())
            : ExtractServerPublicKey(credential.certificates.front(), &expected)) ||
      !Equal(actual, expected))
    return false;
  client_credential_ = credential;
  return true;
}

bool RequestExtensionAllowed(uint16_t code, RequestExtensionContext context) {
  using Context = RequestExtensionContext;
  switch (code) {
    case 5: case 18: case 34: case 47: case 48: case 50: case 52: case 0xff04:
      return context != Context::kNewSessionTicket;
    case 27:
      return context == Context::kCertificateRequest;
    case 0xff03:
      return context == Context::kCertificateRequest || context == Context::kClientAuthenticator;
    case 0: case 0xff02:
      return context == Context::kServerAuthenticator;
    case 42:
      return context == Context::kNewSessionTicket;
    case 1: case 10: case 13: case 15: case 16: case 17: case 19: case 20:
    case 21: case 25: case 28: case 29: case 30: case 31: case 32: case 33:
    case 41: case 43: case 44: case 45: case 49: case 51: case 55: case 56:
    case 58: case 59:
      return false;
    default:
      return true;  // Unknown, well-formed offers are extensible.
  }
}

bool Client::AcceptCertificateRequest(ByteSpan frame, bool post_handshake) {
  auto body = frame.subspan(4u);
  Bytes reconstructed;
  if (frame[0] == 252) {
    if (!cached_request_selected_ || body.empty() || body.size() != size_t{65} + body[0])
      return Fail();
    const size_t cursor = size_t{1} + body[0];
    std::optional<Bytes> matched;
    for (const auto& candidate : options_.cached_request_templates) {
      if (Equal(net::httpps::Hash(candidate), body.subspan(cursor, 32u))) {
        if (matched && *matched != candidate)
          return Fail();
        matched = candidate;
      }
    }
    if (!matched || matched->size() < 2 || matched->size() > 65501)
      return Fail();
    Bytes extensions(matched->begin() + 2, matched->end());
    Extension(&extensions, 0xff03, body.subspan(cursor + 32));
    Append(&reconstructed, body.first(cursor));
    Vector16(&reconstructed, extensions);
    body = reconstructed;
  }
  if (body.empty() || body[0] > body.size() - 1)
    return Fail(Error::kProtocol, 50);
  if (post_handshake ? body[0] == 0 : body[0] != 0)
    return Fail(Error::kProtocol, 47);
  Bytes context(body.begin() + 1, body.begin() + 1 + body[0]);
  if (post_handshake && (!post_handshake_auth_offered_ || alpn_ == "h2" ||
      (!resumed_ && (authentication_ == Authentication::kPassword ||
                    authentication_ == Authentication::kExternalPsk))))
    return Fail(Error::kProtocol, 10);
  if (options_.bootstrap && options_.bootstrap->expires_unix_seconds &&
      WallMilliseconds() / 1000 >= options_.bootstrap->expires_unix_seconds)
    return Fail(Error::kCertificate);
  if (post_handshake && (client_auth_contexts_.size() >= 256 ||
      !client_auth_contexts_.insert(context).second))
    return Fail(Error::kProtocol, 47);
  std::map<uint16_t, Bytes> extensions;
  uint8_t extension_alert;
  if (!Extensions(body.subspan(size_t{1} + body[0]), &extensions, &extension_alert))
    return Fail(Error::kProtocol, extension_alert);
  // Unknown request offers remain extensible. Known extensions must obey their
  // message placement, including reconstructed cached requests and PHA.
  for (const auto& [type, value] : extensions) {
    if (!RequestExtensionAllowed(type, RequestExtensionContext::kCertificateRequest))
      return Fail(Error::kProtocol, 47);
  }
  // A CR requests OCSP evidence with an empty extension, not the ClientHello
  // OCSP request structure. Check known syntax even without a local credential.
  if (extensions.count(5) && !extensions[5].empty())
    return Fail(Error::kProtocol, 50);
  client_ocsp_requested_ = extensions.count(5) != 0;
  if (!extensions.count(0xff03) ||
      (client_certificate_type_ == 0 && !extensions.count(50)))
    return Fail(Error::kProtocol, 109);
  if (extensions[0xff03].size() != 32 ||
      (extensions.count(50) && (extensions[50].size() < 4 || extensions[50].size() % 2 ||
      Read16(ByteSpan(extensions[50]).first(2u)) != extensions[50].size() - 2)))
    return Fail(Error::kProtocol, 50);
  Bytes learned;
  if (!RequestTemplate(body.subspan(size_t{1} + body[0]), &learned))
    return Fail();
  if (learned_request_templates_.size() < 64 &&
      std::find(learned_request_templates_.begin(), learned_request_templates_.end(), learned) == learned_request_templates_.end())
    learned_request_templates_.push_back(std::move(learned));
  client_signature_algorithms_.clear();
  for (size_t offset = 2; offset < extensions[50].size(); offset += 2) {
    uint16_t algorithm = Read16(ByteSpan(extensions[50]).subspan(offset, 2u));
    if (algorithm == 0xfe00 || algorithm == 0xfe01 || algorithm == 0x0420 ||
        algorithm == 0x0520 || algorithm == 0x0620)
      return Fail();
    client_signature_algorithms_.push_back(algorithm);
  }
  client_grant_algorithms_.clear();
  client_delegation_offered_ = false;
  if (extensions.count(34) && (!extensions.count(0xff04) || !extensions.count(50)))
    return Fail(Error::kProtocol, 109);
  if (extensions.count(0xff04) && !extensions.count(34))
    return Fail(Error::kProtocol, 47);
  if (extensions.count(34)) {
    for (uint16_t code : {uint16_t{34}, uint16_t{0xff04}}) {
      const auto& values = extensions[code];
      if (values.size() < 4 || values.size() % 2 || Read16(ByteSpan(values).first(2u)) != values.size() - 2)
        return Fail(Error::kProtocol, 50);
      for (size_t i = 2; i < values.size(); i += 2) {
        const uint16_t value = Read16(ByteSpan(values).subspan(i, 2u));
        if (code == 34)
          client_delegation_offered_ |= value == 0xfe01;
        else {
          if (value == 0xfe00 || value == 0xfe01 || value == 0x0420 || value == 0x0520 || value == 0x0620)
            return Fail();
          client_grant_algorithms_.push_back(value);
        }
      }
    }
  }
  client_authorities_.clear();
  if (extensions.count(47) &&
      !ParseCertificateAuthorities(extensions[47], &client_authorities_))
    return Fail(Error::kProtocol, 50);
  client_oid_filters_.clear();
  if (extensions.count(48)) {
    ByteSpan filters = extensions[48];
    if (filters.size() < 2 || Read16(filters.first(2u)) != filters.size() - 2)
      return Fail(Error::kProtocol, 50);
    filters = filters.subspan(2u);
    std::set<Bytes> oids;
    while (!filters.empty()) {
      const size_t oid_size = filters[0];
      if (!oid_size || filters.size() < oid_size + 3)
        return Fail(Error::kProtocol, 50);
      Bytes oid(filters.begin() + 1, filters.begin() + 1 + oid_size);
      size_t size = Read16(filters.subspan(oid_size + 1, 2u));
      if (size > filters.size() - oid_size - 3)
        return Fail(Error::kProtocol, 50);
      if (!oids.insert(oid).second)
        return Fail();
      auto value = filters.subspan(oid_size + 3, size);
      client_oid_filters_.emplace_back(std::move(oid), Bytes(value.begin(), value.end()));
      filters = filters.subspan(oid_size + 3 + size);
    }
  }
  client_auth_context_ = std::move(context);
  client_compression_algorithms_.clear();
  if (extensions.count(27)) {
    const auto& algorithms = extensions[27];
    if (algorithms.size() < 3 || algorithms[0] != algorithms.size() - 1 || algorithms[0] % 2)
      return Fail(Error::kProtocol, 50);
    for (size_t i = 1; i < algorithms.size(); i += 2) {
      const auto algorithm = Read16(ByteSpan(algorithms).subspan(i, 2u));
      if (algorithm >= 1 && algorithm <= 3)
        client_compression_algorithms_.push_back(algorithm);
    }
  }
  CopySecret(extensions[0xff03], &client_verifier_share_);
  client_auth_requested_ = true;
  return AppendTranscript(frame);
}

bool Client::ClientCredentialMatchesRequest() const {
  if (!client_credential_ || client_credential_->certificate_type != client_certificate_type_)
    return false;
  if (client_certificate_type_ == 2)
    return true;
  if (client_certificate_type_ == 3) {
    if (!client_credential_->its_policy) return false;
    const auto authorization = client_credential_->its_policy->Verify(
        Octets(client_credential_->certificates.front()), 1,
        client_credential_->its_policy->identity, WallMilliseconds());
    Secret actual;
    X25519_public_from_private(actual.data(), client_credential_->private_key.data());
    return authorization && Equal(actual, authorization->public_key);
  }
  if (!CertificateAlgorithmsAllowed(client_credential_->certificates,
                                     client_signature_algorithms_))
    return false;
  if (!client_credential_->delegation.empty()) {
    Secret ignored;
    if (!client_delegation_offered_ || !ValidateDelegation(client_credential_->certificates.front(),
            client_credential_->delegation, false, client_grant_algorithms_, &ignored, options_.native_provider.get()))
      return false;
  }
  for (const auto& der : client_credential_->certificates) {
    const uint8_t* pointer = reinterpret_cast<const uint8_t*>(der.data());
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &pointer, der.size()));
    if (!cert || pointer != StringBytes(der).subspan(der.size()).data())
      return false;
    if (&der == &client_credential_->certificates.front()) {
      for (const auto& [encoded_oid, requested_values] : client_oid_filters_) {
        const uint8_t* input = encoded_oid.data();
        bssl::UniquePtr<ASN1_OBJECT> oid(d2i_ASN1_OBJECT(nullptr, &input, encoded_oid.size()));
        if (!oid || input != ByteSpan(encoded_oid).subspan(encoded_oid.size()).data())
          return false;
        const int nid = OBJ_obj2nid(oid.get());
        // Unknown filters must be ignored, not interpreted as raw byte equality.
        if (nid != NID_key_usage && nid != NID_ext_key_usage)
          continue;
        int index = X509_get_ext_by_OBJ(cert.get(), oid.get(), -1);
        if (index < 0)
          return false;
        if (requested_values.empty())
          continue;
        const uint8_t* values = requested_values.data();
        if (nid == NID_key_usage) {
          bssl::UniquePtr<ASN1_BIT_STRING> required(d2i_ASN1_BIT_STRING(nullptr, &values,
                                                                    requested_values.size()));
          bssl::UniquePtr<ASN1_BIT_STRING> actual(static_cast<ASN1_BIT_STRING*>(
              X509_get_ext_d2i(cert.get(), nid, nullptr, nullptr)));
          if (!required || !actual || values != ByteSpan(requested_values).subspan(requested_values.size()).data())
            return false;
          for (int bit = 0; bit < 9; ++bit)
            if (ASN1_BIT_STRING_get_bit(required.get(), bit) &&
                !ASN1_BIT_STRING_get_bit(actual.get(), bit))
              return false;
        } else {
          bssl::UniquePtr<EXTENDED_KEY_USAGE> required(d2i_EXTENDED_KEY_USAGE(nullptr, &values,
                                                                          requested_values.size()));
          bssl::UniquePtr<EXTENDED_KEY_USAGE> actual(static_cast<EXTENDED_KEY_USAGE*>(
              X509_get_ext_d2i(cert.get(), nid, nullptr, nullptr)));
          if (!required || !actual || values != ByteSpan(requested_values).subspan(requested_values.size()).data())
            return false;
          for (size_t i = 0; i < sk_ASN1_OBJECT_num(required.get()); ++i) {
            bool found = false;
            for (size_t j = 0; j < sk_ASN1_OBJECT_num(actual.get()); ++j)
              found |= OBJ_cmp(sk_ASN1_OBJECT_value(required.get(), i),
                               sk_ASN1_OBJECT_value(actual.get(), j)) == 0;
            if (!found)
              return false;
          }
        }
      }
    }
  }
  // certificate_authorities is a selection preference, not a trust decision or
  // a prohibition on this application's explicitly selected single credential.
  return true;
}

bool Client::AppendClientAuthentication() {
  if (!client_auth_requested_)
    return true;
  Bytes entries;
  const bool selected = ClientCredentialMatchesRequest();
  if (selected) {
    for (size_t index = 0; index < client_credential_->certificates.size(); ++index) {
      const auto& der = client_credential_->certificates[index];
      auto entry = Frame(0, Octets(der));
      // CertificateEntry is uint24 DER length, DER and current-request metadata.
      Append(&entries, ByteSpan(entry).subspan(1u));
      Bytes metadata;
      if (&der == &client_credential_->certificates.front() && !client_credential_->delegation.empty())
        Extension(&metadata, 34, client_credential_->delegation);
      if (client_ocsp_requested_ && index < client_credential_->ocsp_responses.size() &&
          !client_credential_->ocsp_responses[index].empty()) {
        const auto response = Frame(1, client_credential_->ocsp_responses[index]);
        Extension(&metadata, 5, response);
      }
      if (metadata.size() > 65535) return Fail();
      Vector16(&entries, metadata);
    }
  }
  auto list = Frame(0, entries);
  Bytes certificate_body{static_cast<uint8_t>(client_auth_context_.size())};
  Append(&certificate_body, client_auth_context_);
  Append(&certificate_body, ByteSpan(list).subspan(1u));
  auto certificate = Frame(11, certificate_body);
  if (!client_compression_algorithms_.empty() &&
      !CompressCertificate(certificate_body, client_compression_algorithms_.front(), &certificate))
    return Fail();
  // Certificate lists may span records, but the handshake transcript contains
  // the exact complete frame, independent of record fragmentation.
  if (!SealHandshake(certificate))
    return false;
  if (!AppendTranscript(certificate))
    return Fail();
  if (!selected)
    return true;  // Ordinary no-credential response, not an authenticated user.
  authenticated_client_identity_ = CredentialIdentity(client_credential_->certificates);
  Secret shared{};
  if (!X25519(shared.data(), client_credential_->private_key.data(),
              client_verifier_share_.data()))
    return Fail();
  const auto transcript_hash = Hash(transcript_);
  auto exported = Label(exporter_, "EXPORTER-TLS20-Client-Auth", Hash({}));
  auto salt = Label(exported, "exporter", Hash(transcript_hash));
  auto root = Mac(salt, shared);
  auto key = Label(root, "client mac", {});
  Bytes input(64, 0x20);
  Append(&input, Octets("TLS 2.0, client CertificateVerify"));
  input.push_back(0);
  Append(&input, transcript_hash);
  auto proof = Mac(key, input);
  Bytes body{0xfe, 1};
  Vector16(&body, proof);
  auto frame = Frame(15, body);
  const bool ok = SealHandshake(frame) && AppendTranscript(frame);
  for (auto* secret : {&exported, &salt, &key, &root, &proof})
    OPENSSL_cleanse(secret->data(), secret->size());
  OPENSSL_cleanse(shared.data(), shared.size());
  if (!options_.post_handshake_auth)
    client_credential_.reset();
  if (!ok)
    return Fail();
  return true;
}

bool Client::SealHandshake(ByteSpan frame) {
  if (close_sent_ || !sender_)
    return Fail();
  while (!frame.empty()) {
    Bytes record;
    const size_t count = std::min(max_send_content(), frame.size());
    if (!sender_->Seal(frame.first(count), 22, &record))
      return Fail();
    Append(&output_, record);
    frame = frame.subspan(count);
  }
  return true;
}

void Client::SelectBootstrap(size_t index) {
  options_.bootstrap = options_.bootstraps[index];
  const auto& binding = *options_.bootstrap;
  client_credential_ = binding.credential;
  Bytes policy;
  Append(&policy, Octets("TLS20-POK local provisioning policy"));
  Vector16(&policy, binding.spki);
  Vector16(&policy, Octets(binding.service));
  Vector16(&policy, Octets(binding.scope));
  policy.push_back(binding.provisioning_trust);
  U32(&policy, static_cast<uint64_t>(binding.expires_unix_seconds) >> 32);
  U32(&policy, static_cast<uint64_t>(binding.expires_unix_seconds));
  bootstrap_policy_ = net::httpps::Hash(policy);
  Bytes selection;
  Append(&selection, CredentialIdentity(client_credential_->certificates));
  selection.push_back(client_credential_->certificate_type);
  Append(&selection, client_credential_->delegation);
  Secret public_key;
  X25519_public_from_private(public_key.data(), client_credential_->private_key.data());
  Append(&selection, public_key);
  selected_client_identity_ = net::httpps::Hash(selection);
}

bool Client::Start(const SessionTicket* ticket, ByteSpan early_data,
                   bool enable_early_data) {
  if (state_ != State::kNew) return Fail();
  if (options_.bootstrap) {
    options_.bootstraps.insert(options_.bootstraps.begin(), *options_.bootstrap);
    options_.bootstrap.reset();
  }
  const bool has_bootstrap = !options_.bootstraps.empty();
  std::erase_if(options_.bootstraps, [](const BootstrapBinding& binding) {
    return binding.expires_unix_seconds &&
           WallMilliseconds() / 1000 >= binding.expires_unix_seconds;
  });
  if (has_bootstrap && options_.bootstraps.empty())
    return Fail(Error::kCertificate);
  const bool provisioning_trust = std::any_of(
      options_.bootstraps.begin(), options_.bootstraps.end(),
      [](const BootstrapBinding& binding) { return binding.provisioning_trust; });
  if (options_.allow_unauthenticated &&
      (options_.ordinary_httpps || has_bootstrap || options_.password ||
       options_.pinning || options_.continuity_pinning || options_.dane_policy ||
       options_.its_policy || options_.ct_v2_policy || !options_.external_psks.empty()))
    return Fail(Error::kCertificate);
  if (ticket && (ticket->authentication == Authentication::kUnauthenticated) !=
                    options_.allow_unauthenticated)
    return Fail(Error::kCertificate);
  if (ticket) {
    if (ticket->allowed_psk_modes.empty() || ticket->allowed_psk_modes.size() > 2 ||
        std::any_of(ticket->allowed_psk_modes.begin(), ticket->allowed_psk_modes.end(),
                    [](uint8_t value) { return value > 1; }) ||
        (ticket->allowed_psk_modes.size() == 2 &&
         ticket->allowed_psk_modes[0] == ticket->allowed_psk_modes[1]))
      return Fail();
    std::vector<uint8_t> modes;
    for (uint8_t mode : options_.psk_modes) {
      if (std::find(ticket->allowed_psk_modes.begin(), ticket->allowed_psk_modes.end(), mode) !=
          ticket->allowed_psk_modes.end())
        modes.push_back(mode);
    }
    if (modes.empty()) {
      // A full handshake may establish a new lineage, but the old ticket must
      // not authorize a mode which its original ClientHello did not offer.
      if (!early_data.empty()) return Fail();
      ticket = nullptr;
      enable_early_data = false;
    } else {
      options_.psk_modes = std::move(modes);
    }
  }
  if (options_.no_alpn_http11 && options_.alpn_protocols !=
                                      std::vector<std::string>{"http/1.1"})
    return Fail();
  // A standalone caller may wait after selecting an ITS credential. Repeat
  // the local inventory/expiry check before any CH or cached early data.
  if (client_credential_ && client_credential_->certificate_type == 3) {
    const auto credential = *client_credential_;
    if (!SetClientCredential(credential)) return Fail(Error::kCertificate);
  }
  if (!CredentialRequestOptionsValid(options_)) return Fail();
  if (!options_.ocsp_responder_ids.empty() || !options_.ocsp_request_extensions.empty())
    options_.request_ocsp = true;
  if (options_.password) {
    password_only_ = std::all_of(options_.cipher_suites.begin(), options_.cipher_suites.end(), PasswordSuite);
    auto ascii_opaque = [](std::string_view value) {
      return !value.empty() && std::all_of(value.begin(), value.end(),
          [](unsigned char c) { return c >= 0x20 && c <= 0x7e; });
    };
    auto prepared = std::make_shared<PasswordCredential>(*options_.password);
    if (prepared->prepare_text) {
      auto username = prepared->prepare_text(prepared->username);
      auto password = prepared->prepare_text(prepared->password);
      if (!username || !password) return Fail(Error::kCertificate);
      prepared->username = std::move(*username);
      OPENSSL_cleanse(prepared->password.data(), prepared->password.size());
      prepared->password = std::move(*password);
    } else if (!ascii_opaque(prepared->username) || !ascii_opaque(prepared->password)) {
      return Fail(Error::kCertificate);
    }
    options_.password = std::move(prepared);
    const auto& credential = *options_.password;
    if (credential.service != hostname_ || credential.username.empty() || credential.password.empty() ||
        credential.username.find('\0') != std::string::npos || credential.password.find('\0') != std::string::npos ||
        credential.username.size() > 255 ||
        credential.password.size() > 65535 || credential.helper_path.empty() ||
        !options_.native_provider || !options_.native_provider->SupportsPasswordAead() ||
        (password_only_ && !options_.external_psks.empty()) || has_bootstrap || options_.pinning ||
        options_.ct_v2_policy || options_.dane_policy || options_.its_policy ||
        std::none_of(options_.cipher_suites.begin(), options_.cipher_suites.end(), PasswordSuite) ||
        std::none_of(options_.groups.begin(), options_.groups.end(), [](uint16_t group) {
          return (group >= 23 && group <= 25) || (group >= 256 && group <= 260);
        }))
      return Fail(Error::kCertificate);
    Bytes binding;
    Vector16(&binding, Octets("TLS20 password credential context"));
    Vector16(&binding, Octets(hostname_));
    Vector16(&binding, Octets(credential.username));
    Vector16(&binding, credential.protection_spki);
    password_context_ = net::httpps::Mac(Octets(credential.password), binding);
    if (ticket) {
      if (password_only_ && ticket->authentication != Authentication::kPassword)
        return Fail(Error::kCertificate);
      std::vector<uint16_t> suites;
      for (auto suite : options_.cipher_suites) {
        if (PasswordSuite(suite)) {
          if (ticket->authentication != Authentication::kPassword) continue;
          suite = PasswordSuccessor(suite);
        }
        if (std::find(suites.begin(), suites.end(), suite) == suites.end()) suites.push_back(suite);
      }
      options_.cipher_suites = std::move(suites);
    }
  } else if (std::any_of(options_.cipher_suites.begin(), options_.cipher_suites.end(), PasswordSuite)) {
    return Fail();
  }
  if (options_.dane_policy && (!options_.dane_policy->IsValid() || !ValidServerName(hostname_) ||
      std::any_of(options_.external_psks.begin(), options_.external_psks.end(),
                  [](const ExternalPSK& value) { return !value.combined; }) ||
      provisioning_trust))
    return Fail(Error::kCertificate);
  if (options_.its_policy && (!options_.its_policy->IsValid() ||
      options_.its_policy->identity != hostname_ || options_.its_policy->role != 0 ||
      options_.dane_policy || options_.ct_v2_policy || options_.pinning || has_bootstrap))
    return Fail(Error::kCertificate);
  if (options_.ct_v2_policy) {
    if (!options_.ct_v2_policy->IsValid() ||
        std::any_of(options_.server_certificate_types.begin(), options_.server_certificate_types.end(),
                    [](uint8_t value) { return value != 0; }) ||
        std::any_of(options_.external_psks.begin(), options_.external_psks.end(),
                    [](const ExternalPSK& value) { return !value.combined; }) ||
        provisioning_trust)
      return Fail(Error::kCertificate);
    options_.request_ocsp = true;
  }
  if (options_.pinning && (ticket || !options_.external_psks.empty() ||
      !early_data.empty() || enable_early_data))
    return Fail();
  if (state_ != State::kNew || !ValidServiceIdentity(hostname_) ||
      (!options_.allow_unauthenticated && !use_external_verifier_ && anchors_.empty() && options_.external_psks.empty() &&
       options_.server_raw_public_keys.empty() && !options_.dane_policy && !options_.password && !options_.its_policy &&
       !provisioning_trust) || anchors_.size() > 32) {
    return Fail(Error::kCertificate);
  }
  if (options_.cipher_suites.empty() || options_.cipher_suites.size() > 32767 ||
      options_.groups.empty() || options_.groups.size() > 32767 ||
      options_.alpn_protocols.empty())
    return Fail();
  const auto unavailable_algorithm = [&](uint16_t scheme) {
    if (scheme == 0x0708) return !options_.native_provider || !options_.native_provider->SupportsSM();
    if (scheme >= 0x0709 && scheme <= 0x070f)
      return !options_.native_provider || !options_.native_provider->SupportsGost();
    return (scheme == 0x0808 || (scheme >= 0x0809 && scheme <= 0x080b) ||
            (scheme >= 0x081a && scheme <= 0x081c)) && !options_.native_provider;
  };
  if (std::any_of(options_.certificate_signature_algorithms.begin(), options_.certificate_signature_algorithms.end(), unavailable_algorithm) ||
      std::any_of(options_.grant_signature_algorithms.begin(), options_.grant_signature_algorithms.end(), unavailable_algorithm)) return Fail();
  if (options_.certificate_signature_algorithms.empty() ||
      options_.certificate_signature_algorithms.size() > 32766 ||
      std::any_of(options_.certificate_signature_algorithms.begin(),
                  options_.certificate_signature_algorithms.end(), [](uint16_t value) {
                    return value == 0 || value == 0xfe00 || value == 0xfe01 ||
                           value == 0x0420 || value == 0x0520 || value == 0x0620;
                  }))
    return Fail();
  if (options_.certificate_compression.size() > 127 ||
      std::any_of(options_.certificate_compression.begin(), options_.certificate_compression.end(),
                  [](uint16_t value) { return value < 1 || value > 3; }))
    return Fail();
  size_t cached_bytes = 0;
  for (const auto& [kind, chain] : options_.cached_certificates) {
    if ((kind != 0 && kind != 2 && kind != 3) || chain.empty() ||
        chain.size() > kMaxCertificates || (kind != 0 && chain.size() != 1))
      return Fail();
    for (const auto& der : chain) {
      cached_bytes += der.size();
      if (der.empty() || der.size() > 65536 || cached_bytes > 1048576)
        return Fail();
    }
  }
  for (const auto& candidate : options_.cached_request_templates) {
    Bytes checked;
    if (!RequestTemplate(candidate, &checked) || checked != candidate)
      return Fail();
    cached_bytes += candidate.size();
    if (cached_bytes > 1048576)
      return Fail();
  }
  if (options_.server_certificate_types.empty() || options_.server_certificate_types.size() > 255 ||
      std::any_of(options_.server_certificate_types.begin(), options_.server_certificate_types.end(),
                  [&](uint8_t type) { return type != 0 && type != 2 && !(type == 3 && options_.its_policy); }))
    return Fail();
  for (const auto& pin : options_.server_raw_public_keys) {
    Secret ignored;
    if (!ExtractRawPublicKey(pin, &ignored))
      return Fail(Error::kCertificate);
  }
  for (uint16_t suite : options_.cipher_suites)
    if (!SuiteHashLength(suite) || (SuiteHashId(suite) == 3 &&
        (!options_.native_provider || !options_.native_provider->SupportsSM())) || (GostTagLength(suite) &&
        (!options_.native_provider || !options_.native_provider->SupportsGost())) || (IntegrityTagLength(suite) &&
        (options_.ordinary_httpps || !options_.allow_integrity_only)))
      return Fail();
  for (uint16_t group : options_.groups)
    if (group != 29 && (group < 256 || group > 260) && group != 4587 && group != 4588 && group != 4589 &&
        GroupNid(group) == NID_undef && (!options_.native_provider || !options_.native_provider->SupportsGroup(group)))
      return Fail();
  if (options_.psk_modes.empty() || options_.psk_modes.size() > 255 ||
      std::any_of(options_.psk_modes.begin(), options_.psk_modes.end(),
                  [](uint8_t mode) { return mode > 1; }))
    return Fail();
  if ((options_.record_size_limit && (*options_.record_size_limit < 64 ||
                                     *options_.record_size_limit > 16385)) ||
      (options_.max_fragment_length && (*options_.max_fragment_length < 1 ||
                                       *options_.max_fragment_length > 4)) ||
      (options_.heartbeat_mode && (*options_.heartbeat_mode < 1 || *options_.heartbeat_mode > 2)) ||
      options_.record_padding_multiple < 1 || options_.record_padding_multiple > 16385)
    return Fail();
  suite_ = options_.cipher_suites.front();
  traffic_group_ = options_.password && !ticket ? 0 : options_.groups.front();
  if (options_.signaling && !options_.signaling->IsValid())
    return Fail();
  if (has_bootstrap) {
    if (!options_.external_psks.empty() || options_.pinning)
      return Fail(Error::kCertificate);
    // The application authorizes the offered ALPN list. Fresh bootstrap binds
    // the selected identity to the protocol authenticated by EE; descendants
    // retain their selected protocol and must still be locally authorized.
    const std::string bootstrap_alpn = ticket ? ticket->alpn : options_.alpn_protocols.front();
    if (std::find(options_.alpn_protocols.begin(), options_.alpn_protocols.end(), bootstrap_alpn) ==
        options_.alpn_protocols.end())
      return Fail(Error::kCertificate);
    const auto legacy_credential = client_credential_;
    bool ticket_binding_found = false;
    size_t ticket_binding = 0;
    for (size_t index = 0; index < options_.bootstraps.size(); ++index) {
      auto& binding = options_.bootstraps[index];
      if (!binding.credential) binding.credential = legacy_credential;
      if (binding.service != hostname_ || !binding.credential ||
          binding.credential->certificate_type != 2 ||
          binding.credential->certificates.size() != 1 ||
          !Equal(Octets(binding.credential->certificates.front()), binding.spki) ||
          !binding.credential->delegation.empty() ||
          !SetClientCredential(*binding.credential) ||
          (binding.provisioning_trust && (options_.ordinary_httpps || options_.delegated_credentials ||
                                        options_.request_ocsp || options_.request_scts)))
        return Fail(Error::kCertificate);
      std::set<size_t> hashes;
      for (uint16_t suite : options_.cipher_suites) {
        if (!hashes.insert(SuiteHashId(suite)).second) continue;
        auto psk = BootstrapPSK(binding, suite, bootstrap_alpn);
        if (!psk || !bootstrap_offers_.emplace(psk->identity, index).second)
          return Fail(Error::kCertificate);
        options_.external_psks.push_back(std::move(*psk));
      }
      SelectBootstrap(index);
      if (ticket && Equal(ticket->bootstrap_policy, bootstrap_policy_)) {
        ticket_binding_found = true;
        ticket_binding = index;
      }
    }
    if (ticket && !ticket_binding_found) return Fail(Error::kCertificate);
    SelectBootstrap(ticket ? ticket_binding : 0);
  }
  for (const auto& anchor : anchors_) {
    if (anchor.empty() || anchor.size() > 65536) {
      return Fail(Error::kCertificate);
    }
  }
  deadline_milliseconds_ = MonotonicMilliseconds() + 30000;
  if (client_credential_) {
    Bytes selection;
    Append(&selection, CredentialIdentity(client_credential_->certificates));
    selection.push_back(client_credential_->certificate_type);
    Append(&selection, client_credential_->delegation);
    if (client_credential_->its_policy)
      Append(&selection, client_credential_->its_policy->Context());
    Secret public_key;
    X25519_public_from_private(public_key.data(), client_credential_->private_key.data());
    Append(&selection, public_key);
    selected_client_identity_ = net::httpps::Hash(selection);
  }
  if (ticket) {
    const auto age = MonotonicMilliseconds() - ticket->received_milliseconds;
    const bool external = ticket->authentication == Authentication::kExternalPsk ||
        ticket->authentication == Authentication::kCertificateAndPsk ||
        ticket->authentication == Authentication::kRawPublicKeyAndPsk ||
        ticket->authentication == Authentication::kDaneCertificateAndPsk ||
        ticket->authentication == Authentication::kDaneRawPublicKeyAndPsk ||
        ticket->authentication == Authentication::kITSAndPsk ||
        ticket->authentication == Authentication::kProvisioning;
    const bool certificate = ticket->authentication != Authentication::kExternalPsk &&
        ticket->authentication != Authentication::kPassword &&
        ticket->authentication != Authentication::kUnauthenticated;
    if (ticket->hostname != hostname_ || ticket->identity.empty() ||
        std::none_of(options_.cipher_suites.begin(), options_.cipher_suites.end(),
            [&](uint16_t suite) {
              return SuiteHashId(suite) == SuiteHashId(ticket->cipher_suite) &&
                  bool(IntegrityTagLength(suite)) == bool(IntegrityTagLength(ticket->cipher_suite));
            }) ||
        (IntegrityTagLength(ticket->cipher_suite) &&
         (options_.ordinary_httpps || !options_.allow_integrity_only)) ||
        (SuiteHashId(ticket->cipher_suite) == 3 &&
         (!options_.native_provider || !options_.native_provider->SupportsSM())) ||
        (GostTagLength(ticket->cipher_suite) && (!options_.native_provider || !options_.native_provider->SupportsGost())) ||
        ticket->identity.size() > 65535 || (certificate && ticket->certificates.empty()) ||
        (ticket->client_certificate_type != 0 && (!client_credential_ ||
         ticket->client_certificate_type != client_credential_->certificate_type)) ||
        ticket->peer_record_limit < 64 || ticket->peer_record_limit > 16385 ||
        !SuiteHashLength(ticket->cipher_suite) ||
        ticket->psk.size() != SuiteHashLength(ticket->cipher_suite) ||
        ticket->lifetime == 0 || ticket->lifetime > 604800 || age < 0 ||
        static_cast<uint64_t>(age) >= uint64_t(ticket->lifetime) * 1000 ||
        !Equal(ticket->selected_client_identity, selected_client_identity_) ||
        !Equal(ticket->bootstrap_policy, bootstrap_policy_) ||
        !Equal(ticket->password_context, password_context_) ||
        (ticket->authentication == Authentication::kPassword && !options_.password) ||
        !Equal(ticket->signaling_context, options_.signaling ? options_.signaling->Context() : Secret{}) ||
        !Equal(ticket->ct_policy_context, options_.ct_v2_policy ? options_.ct_v2_policy->Context() : Bytes{}) ||
        !Equal(ticket->dane_policy_context, options_.dane_policy ? options_.dane_policy->Context() : Bytes{}) ||
        !Equal(ticket->its_policy_context, options_.its_policy ? options_.its_policy->Context() : Bytes{}) ||
        (ticket->server_certificate_type == 3 && (!options_.its_policy ||
          ticket->its_expires_unix_milliseconds <= WallMilliseconds())) ||
        (options_.dane_policy && ticket->dane_expires_unix_seconds <=
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) ||
        (options_.ct_v2_policy && (!certificate || ticket->server_certificate_type != 0 ||
                                 ticket->authentication == Authentication::kProvisioning)) ||
        (external && std::none_of(options_.external_psks.begin(), options_.external_psks.end(),
            [&](const ExternalPSK& psk) { return Equal(PskBinding(psk), ticket->external_psk_binding); }))) {
      return Fail(Error::kCertificate);
    }
    // Browser callers must validate their cached chain against current policy
    // before permitting early data. The standalone CA path validates here.
    Secret unused;
    const bool raw = ticket->server_certificate_type == 2;
    const bool its = ticket->server_certificate_type == 3;
    if (its) {
      if (ticket->certificates.size() != 1 || !ticket->delegation.empty() ||
          (ticket->authentication != Authentication::kITS && ticket->authentication != Authentication::kITSAndPsk) ||
          std::any_of(ticket->certificate_extensions.begin(), ticket->certificate_extensions.end(),
                      [](const auto& value) { return !value.empty(); })) return Fail(Error::kCertificate);
      const auto authorization = options_.its_policy->Verify(Octets(ticket->certificates.front()),
          0, hostname_, WallMilliseconds());
      if (!authorization) return Fail(Error::kCertificate);
      its_expires_unix_milliseconds_ = std::min(ticket->its_expires_unix_milliseconds,
                                                authorization->expires_unix_milliseconds);
    }
    if (certificate && !raw && !its && ticket->authentication != Authentication::kProvisioning) {
      const auto required = CertificateRequiresBrowserEvidence(ticket->certificates.front(),
          options_.request_ocsp, options_.request_scts);
      if (!required || (*required && !use_external_verifier_))
        return Fail(Error::kCertificate);
      for (const auto& metadata : ticket->certificate_extensions) {
        const auto status = metadata.find(5);
        if (status != metadata.end()) {
          const auto& value = status->second;
          if (value.size() < 5 || value[0] != 1 ||
              ((size_t(value[1]) << 16) | (size_t(value[2]) << 8) | value[3]) != value.size() - 4 ||
              !OCSPRequestMatchesResponse(options_, ByteSpan(value).subspan(4u)))
            return Fail(Error::kCertificate);
        }
      }
    }
    const bool raw_trusted = raw && ticket->certificates.size() == 1 &&
        ExtractRawPublicKey(Octets(ticket->certificates.front()), &unused) &&
        std::any_of(options_.server_raw_public_keys.begin(), options_.server_raw_public_keys.end(),
                    [&](const Bytes& pin) { return Equal(pin, Octets(ticket->certificates.front())); });
    const bool provisioning = ticket->authentication == Authentication::kProvisioning;
    const auto private_path = raw || its ? std::vector<std::string>{}
        : ValidatedPrivatePath(ticket->certificates, anchors_, hostname_, !ticket->delegation.empty(), options_.native_provider.get());
    if (!private_path.empty() && !CertificateTLSFeaturesAllowed(private_path))
      return Fail(Error::kCertificate);
    if (certificate && !raw && !its && !provisioning && !use_external_verifier_ &&
        !CertificateAlgorithmsAllowed(private_path.empty() ? ticket->certificates : private_path,
                                       options_.certificate_signature_algorithms)) return Fail(Error::kCertificate);
    const auto dane = VerifyDNSSECPolicy(options_.dane_policy.get(), hostname_, ticket->certificates,
        ticket->server_certificate_type, ticket->certificate_extensions, private_path, nullptr,
        &validated_certificate_path_);
    const bool dane_trusted = options_.dane_policy && dane && *dane >= 0;
    if (options_.dane_policy && !use_external_verifier_ && (!dane || (*dane < 0 && private_path.empty())))
      return Fail(Error::kCertificate);
    if (provisioning && (!options_.bootstrap || !options_.bootstrap->provisioning_trust ||
        !ProvisioningKey(ticket->certificates, ticket->server_certificate_type, ticket->certificate_extensions, &unused)))
      return Fail(Error::kCertificate);
    if ((!options_.allow_unauthenticated && !provisioning && raw && !raw_trusted && !dane_trusted) || (certificate && !provisioning && !raw && !its && !use_external_verifier_ && !dane_trusted &&
        !VerifyLabChain(ticket->certificates, anchors_, hostname_, &unused, !ticket->delegation.empty(), options_.native_provider.get())) ||
        (!ticket->delegation.empty() && (!options_.delegated_credentials ||
         !ValidateDelegation(ticket->certificates.front(), ticket->delegation, true,
                              options_.grant_signature_algorithms, &unused, options_.native_provider.get()))))
      return Fail(Error::kCertificate);
    if (certificate && !raw && !its && !use_external_verifier_ &&
        !VerifyCertificateTransparency(options_.ct_v2_policy.get(), ticket->certificates,
            ticket->certificate_extensions,
            validated_certificate_path_.size() > 1 ? validated_certificate_path_[1] : std::string_view{}))
      return Fail(Error::kCertificate);
    offered_ticket_ = *ticket;
    dane_expires_unix_seconds_ = ticket->dane_expires_unix_seconds;
    ExternalPSK value;
    value.identity = ticket->identity;
    value.secret = ticket->psk;
    value.hostname = ticket->hostname;
    value.alpn = ticket->alpn;
    value.cipher_suite = ticket->cipher_suite;
    value.max_early_data = ticket->max_early_data;
    offered_psks_.push_back(std::move(value));
    offered_psk_ages_.push_back(static_cast<uint32_t>(age) + ticket->age_add);
  }
  std::set<Bytes> identities;
  if (ticket)
    identities.insert(ticket->identity);
  for (const auto& psk : options_.external_psks) {
    if (ticket)
      continue;  // A ticket's authorized lineage is checked above; do not mix fresh identities.
    if (psk.hostname != hostname_ || psk.identity.empty() || psk.identity.size() > 65535 ||
        (IntegrityTagLength(psk.cipher_suite) &&
         (options_.ordinary_httpps || !options_.allow_integrity_only)) ||
        (SuiteHashId(psk.cipher_suite) == 3 && (psk.imported ||
         !options_.native_provider || !options_.native_provider->SupportsSM())) ||
        (GostTagLength(psk.cipher_suite) && (psk.imported ||
         !options_.native_provider || !options_.native_provider->SupportsGost())) ||
        psk.secret.empty() || !SuiteHashLength(psk.cipher_suite) ||
        std::find(options_.alpn_protocols.begin(), options_.alpn_protocols.end(), psk.alpn) ==
            options_.alpn_protocols.end() || !identities.insert(psk.identity).second ||
        (psk.combined && (psk.max_early_data || ticket)) ||
        (!offered_psks_.empty() && psk.combined != offered_psks_.front().combined))
      return Fail();
    offered_psks_.push_back(psk);
    offered_psk_ages_.push_back(0);
  }
  if (!offered_psks_.empty()) {
    combined_psk_ = offered_psks_.front().combined;
    if (combined_psk_ && std::find(options_.psk_modes.begin(), options_.psk_modes.end(), 1) ==
                            options_.psk_modes.end())
      return Fail();
    early_suite_ = offered_psks_.front().cipher_suite;
    early_offered_ = (enable_early_data || !early_data.empty()) &&
        offered_psks_.front().max_early_data > 0 && !combined_psk_ &&
        std::find(options_.cipher_suites.begin(), options_.cipher_suites.end(), early_suite_) !=
            options_.cipher_suites.end();
  }
  if (!early_data.empty() && !early_offered_)
    return Fail();
  X25519_keypair(A_.data(), a_.data());
  if (options_.spontaneous_authenticators)
    authenticator_a_ = a_;
  Bytes traffic_public;
  if (traffic_group_ && !GenerateTrafficShare(traffic_group_, &traffic_public))
    return Fail();
  Secret random;
  RAND_bytes(random.data(), random.size());
#if defined(PHROMIUM_HTTPPS_TEST_DIAGNOSTICS)
  diagnostic_random_ = random;
#endif
  const uint16_t grease = uint16_t{static_cast<uint8_t>((random[0] & 0xf0) | 0x0a)} * 0x0101;
  Bytes body = {3, 3};
  Append(&body, random);
  body.push_back(0);
  Bytes suites;
  if (options_.grease)
    U16(&suites, grease);
  for (uint16_t suite : options_.cipher_suites)
    U16(&suites, suite);
  Vector16(&body, suites);
  Append(&body, Bytes{1, 0});
  hello_prefix_ = body;
  Bytes extensions;
  if (!IsIpIdentity(hostname_)) {
    Bytes server_name, name{0};
    Vector16(&name, Octets(hostname_));
    Vector16(&server_name, name);
    Extension(&extensions, 0, server_name);
  }
  Bytes groups, group_list;
  if (options_.grease)
    U16(&groups, grease);
  for (uint16_t group : options_.groups)
    U16(&groups, group);
  Vector16(&group_list, groups);
  Extension(&extensions, 10, group_list);
  Bytes certificate_codes, certificate_algorithms;
  for (uint16_t value : options_.certificate_signature_algorithms)
    U16(&certificate_codes, value);
  if (options_.grease)
    U16(&certificate_codes, grease);
  Vector16(&certificate_algorithms, certificate_codes);
  Extension(&extensions, 50, certificate_algorithms);
  Bytes versions{2, 4, 0};
  if (options_.grease) {
    U16(&versions, grease);
    versions[0] += 2;
    Extension(&extensions, grease, {});
  }
  Extension(&extensions, 43, versions);
  if (options_.password && !ticket) {
    Bytes identity(Octets(options_.password->username).begin(), Octets(options_.password->username).end());
    const bool protected_name = !options_.password->protection_spki.empty();
    if (protected_name && !options_.native_provider->ProtectUsername(options_.password->protection_spki,
        Octets(options_.password->username), &identity)) return Fail(Error::kCertificate);
    Bytes name{static_cast<uint8_t>(identity.size())};
    Append(&name, identity);
    Extension(&extensions, protected_name ? 29 : 30, name);
  }
  if (options_.request_ocsp) {
    Bytes ids, status{1};
    for (const auto& id : options_.ocsp_responder_ids) Vector16(&ids, id);
    Vector16(&status, ids);
    Vector16(&status, options_.ocsp_request_extensions);
    Extension(&extensions, 5, status);
  }
  if (!options_.certificate_authorities.empty()) {
    Bytes names, authorities;
    for (const auto& name : options_.certificate_authorities) Vector16(&names, name);
    Vector16(&authorities, names);
    Extension(&extensions, 47, authorities);
  }
  if (options_.request_scts)
    Extension(&extensions, 18, {});
  if (options_.ct_v2_policy)
    Extension(&extensions, 52, {});
  if (options_.dane_policy) {
    Bytes port;
    U16(&port, options_.dane_policy->port);
    Extension(&extensions, 59, port);
  }
  if (options_.pinning)
    Extension(&extensions, 32, options_.pinning->extension());
  if (options_.ticket_request)
    Extension(&extensions, 58, options_.ticket_request->Encode());
  if (options_.signaling)
    for (const auto& [kind, value] : options_.signaling->Offers())
      Extension(&extensions, kind, value);
  if (!options_.cached_certificates.empty() || !options_.cached_request_templates.empty()) {
    Bytes objects;
    std::set<std::pair<uint8_t, Secret>> seen;
    auto offer = [&](uint8_t type, const Secret& hash) {
      if (!seen.emplace(type, hash).second)
        return;
      objects.push_back(type);
      objects.push_back(32);
      Append(&objects, hash);
    };
    for (const auto& [kind, chain] : options_.cached_certificates)
      offer(1, net::httpps::Hash(CertificateMaterial(chain)));
    for (const auto& request : options_.cached_request_templates)
      offer(2, net::httpps::Hash(request));
    if (objects.size() > 65533)
      return Fail();
    Bytes offered;
    Vector16(&offered, objects);
    Extension(&extensions, 25, offered);
  }
  if (options_.delegated_credentials) {
    Extension(&extensions, 34, Bytes{0, 2, 0xfe, 0});
    Bytes algorithms;
    for (uint16_t value : options_.grant_signature_algorithms)
      U16(&algorithms, value);
    if (options_.grease)
      U16(&algorithms, grease);
    Bytes offered;
    Vector16(&offered, algorithms);
    Extension(&extensions, 0xff04, offered);
  }
  if (!options_.certificate_compression.empty()) {
    Bytes algorithms{static_cast<uint8_t>(options_.certificate_compression.size() * 2)};
    for (uint16_t algorithm : options_.certificate_compression)
      U16(&algorithms, algorithm);
    Extension(&extensions, 27, algorithms);
  }
  Bytes protocols, alpn;
  if (options_.grease) {
    protocols.push_back(2);
    U16(&protocols, grease);
  }
  for (const auto& protocol : options_.alpn_protocols) {
    if (protocol.empty() || protocol.size() > 255)
      return Fail();
    protocols.push_back(static_cast<uint8_t>(protocol.size()));
    Append(&protocols, Octets(protocol));
  }
  if (protocols.size() > 65533)
    return Fail();
  Vector16(&alpn, protocols);
  if (!options_.no_alpn_http11)
    Extension(&extensions, 16, alpn);
  if (options_.server_certificate_types != std::vector<uint8_t>{0}) {
    Bytes types{static_cast<uint8_t>(options_.server_certificate_types.size())};
    Append(&types, options_.server_certificate_types);
    Extension(&extensions, 20, types);
  }
  if (client_credential_ && client_credential_->certificate_type != 0)
    Extension(&extensions, 19, Bytes{1, client_credential_->certificate_type});
  if (options_.record_size_limit) {
    Bytes value;
    U16(&value, *options_.record_size_limit);
    Extension(&extensions, 28, value);
  }
  if (options_.max_fragment_length)
    Extension(&extensions, 1, Bytes{*options_.max_fragment_length});
  if (options_.heartbeat_mode)
    Extension(&extensions, 15, Bytes{*options_.heartbeat_mode});
  Bytes share, shares;
  if (traffic_group_) {
    U16(&share, traffic_group_);
    Vector16(&share, traffic_public);
  }
  Vector16(&shares, share);
  Extension(&extensions, 51, shares);
  Extension(&extensions, 0xff02, A_);
  Bytes modes{static_cast<uint8_t>(options_.psk_modes.size())};
  Append(&modes, options_.psk_modes);
  Extension(&extensions, 45, modes);
  if (combined_psk_)
    Extension(&extensions, 33, {});
  post_handshake_auth_offered_ = options_.post_handshake_auth &&
      std::find(options_.alpn_protocols.begin(), options_.alpn_protocols.end(), "h2") ==
          options_.alpn_protocols.end();
  if (post_handshake_auth_offered_)
    Extension(&extensions, 49, {});
  if (options_.client_hello_padding) {
    if (options_.client_hello_padding > 65535)
      return Fail();
    Extension(&extensions, 21, Bytes(options_.client_hello_padding));
  }
  if (!offered_psks_.empty()) {
    if (early_offered_ && ticket && ticket->server_certificate_type == 0 &&
        !ticket->certificates.empty()) {
      Bytes encoded;
      Vector16(&encoded, extensions);
      std::map<uint16_t, Bytes> offers;
      if (!Extensions(encoded, &offers)) return Fail();
      std::set<uint16_t> offered{41, 42};
      for (const auto& [type, unused] : offers) offered.insert(type);
      early_offered_ = CertificateFeaturesAllowEarlyData(ticket->certificates.front(), offered);
      if (!early_data.empty() && !early_offered_) return Fail();
    }
    if (early_offered_)
      Extension(&extensions, 42, {});
    if (!AddPskExtension(&extensions))
      return Fail();
  }
  if (extensions.size() > 65535)
    return Fail();
  Vector16(&body, extensions);
  {
    Bytes encoded;
    Vector16(&encoded, extensions);
    std::map<uint16_t, Bytes> offers;
    if (!Extensions(encoded, &offers)) return Fail();
    for (const auto& [type, unused] : offers) offered_features_.insert(type);
  }
  if (options_.spontaneous_authenticators) {
    Bytes encoded;
    Vector16(&encoded, extensions);
    if (!Extensions(encoded, &authenticator_capabilities_))
      return Fail();
  }
  auto hello = Frame(1, body);
  if (!BindClientHello(&hello, Octets(kPreface)))
    return Fail();
  client_hello_ = hello;
  Append(&transcript_, Octets(kPreface));
  AppendTranscript(hello);
  Append(&output_, Octets(kPreface));
  ByteSpan fragments = hello;
  while (!fragments.empty()) {
    const size_t size = std::min(fragments.size(), kMaxRecordContent);
    Append(&output_, PlainRecord(fragments.first(size)));
    fragments = fragments.subspan(size);
    ++handshake_records_;
  }
  state_ = State::kHello;
  if (!offered_psks_.empty()) {
    const uint16_t ps = offered_psks_.front().cipher_suite;
    const size_t hs = SuiteHashLength(ps);
    auto early = SuiteMac(ps, Bytes(hs), offered_psks_.front().secret, options_.native_provider.get());
    early_exporter_ = SuiteLabel(ps, early, "e exp master", SuiteHash(ps, transcript_, options_.native_provider.get()), hs, options_.native_provider.get());
    Diagnostic("TLS20_EARLY_EXPORTER_SECRET", early_exporter_, true);
    if (early_offered_) {
      auto traffic = SuiteLabel(ps, early, "c e traffic", SuiteHash(ps, transcript_, options_.native_provider.get()), hs, options_.native_provider.get());
      Diagnostic("TLS20_CLIENT_EARLY_TRAFFIC_SECRET", traffic);
      early_sender_ = std::make_unique<RecordCipher>(traffic, ps, options_.native_provider);
      if (offered_ticket_)
        early_sender_->SetLimit(offered_ticket_->peer_record_limit);
      OPENSSL_cleanse(traffic.data(), traffic.size());
    }
    OPENSSL_cleanse(early.data(), early.size());
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
  if (!early_data_available() || !early_sender_ || offered_psks_.empty() ||
      (offered_ticket_ && offered_ticket_->server_certificate_type == 3 &&
       its_expires_unix_milliseconds_ <= WallMilliseconds()) ||
      (options_.bootstrap && options_.bootstrap->expires_unix_seconds &&
       WallMilliseconds() / 1000 >= options_.bootstrap->expires_unix_seconds) ||
      data.size() > offered_psks_.front().max_early_data - early_bytes_ ||
      !Deadline())
    return Fail();
  record->clear();
  early_bytes_ += static_cast<uint32_t>(data.size());
  const size_t limit = offered_ticket_ ? offered_ticket_->peer_record_limit - 1 : kMaxRecordContent;
  do {
    const size_t count = std::min(data.size(), limit);
    Bytes part;
    if (!early_sender_->Seal(data.first(count), 23, &part))
      return Fail();
    Append(record, part);
    data = data.subspan(count);
  } while (!data.empty());
  return true;
}

bool Client::AddPskExtension(Bytes* extensions) const {
  Bytes identities, binders, payload;
  for (size_t i = 0; i < offered_psks_.size(); ++i) {
    const auto& psk = offered_psks_[i];
    Vector16(&identities, psk.identity);
    U32(&identities, offered_psk_ages_[i]);
    size_t length = SuiteHashLength(psk.cipher_suite);
    binders.push_back(static_cast<uint8_t>(length));
    binders.resize(binders.size() + length, 0);
  }
  if (identities.size() > 65535 || binders.size() > 65535 ||
      identities.size() + binders.size() + 4 > 65535)
    return false;
  Vector16(&payload, identities);
  Vector16(&payload, binders);
  Extension(extensions, 41, payload);
  return extensions->size() <= 65535;
}

bool Client::BindClientHello(Bytes* hello, ByteSpan prefix) const {
  size_t tail = 2;
  for (const auto& psk : offered_psks_)
    tail += 1 + SuiteHashLength(psk.cipher_suite);
  if (offered_psks_.empty())
    return true;
  if (tail > hello->size())
    return false;
  Bytes truncated(prefix.begin(), prefix.end());
  Append(&truncated, ByteSpan(*hello).first(hello->size() - tail));
  size_t offset = hello->size() - tail + 2;
  for (size_t i = 0; i < offered_psks_.size(); ++i) {
    const auto& psk = offered_psks_[i];
    const uint16_t suite = psk.cipher_suite;
    const size_t length = SuiteHashLength(suite);
    auto early = SuiteMac(suite, Bytes(length), psk.secret, options_.native_provider.get());
    const std::string_view label = i == 0 && offered_ticket_ ? "res binder"
        : psk.imported ? "imp binder" : "ext binder";
    auto binder = SuiteLabel(suite, early, label, SuiteHash(suite, {}, options_.native_provider.get()), length, options_.native_provider.get());
    auto finished = SuiteLabel(suite, binder, "finished", {}, length, options_.native_provider.get());
    auto proof = SuiteMac(suite, finished, SuiteHash(suite, truncated, options_.native_provider.get()), options_.native_provider.get());
    if (proof.size() != length)
      return false;
    std::copy(proof.begin(), proof.end(), hello->begin() + offset + 1);
    offset += length + 1;
    for (auto* secret : {&early, &binder, &finished, &proof})
      OPENSSL_cleanse(secret->data(), secret->size());
  }
  return true;
}

bool Client::GenerateTrafficShare(uint16_t group, Bytes* public_key) {
  if (options_.native_provider && options_.native_provider->SupportsGroup(group)) {
    native_traffic_key_ = options_.native_provider->Generate(group, public_key);
    return native_traffic_key_ != nullptr;
  }
  native_traffic_key_.reset();
  if (group >= 256 && group <= 260)
    return FfdheKeypair(group, &ec_private_, public_key);
  const bool hybrid = group >= 4587 && group <= 4589;
  const uint16_t classical = group == 4588 ? 29 : group == 4587 ? 23 : group == 4589 ? 24 : group;
  if (classical == 29) {
    X25519_keypair(B_.data(), b_.data());
    if (A_ == B_)
      return false;
    public_key->assign(B_.begin(), B_.end());
  } else if (!EcKeypair(classical, &ec_private_, public_key)) {
    return false;
  }
  if (hybrid) {
    Bytes kem_public(group == 4589 ? MLKEM1024_PUBLIC_KEY_BYTES : MLKEM768_PUBLIC_KEY_BYTES);
    kem_seed_.resize(MLKEM_SEED_BYTES);
    if (group == 4589) {
      MLKEM1024_private_key key;
      MLKEM1024_generate_key(kem_public.data(), kem_seed_.data(), &key);
      OPENSSL_cleanse(&key, sizeof(key));
    } else {
      MLKEM768_private_key key;
      MLKEM768_generate_key(kem_public.data(), kem_seed_.data(), &key);
      OPENSSL_cleanse(&key, sizeof(key));
    }
    if (group == 4588)
      public_key->insert(public_key->begin(), kem_public.begin(), kem_public.end());
    else
      Append(public_key, kem_public);
  }
  return true;
}

bool Client::TrafficAgreement(uint16_t group, ByteSpan public_key, Bytes* shared) {
  if (options_.native_provider && options_.native_provider->SupportsGroup(group))
    return native_traffic_key_ && native_traffic_key_->Agree(public_key, shared);
  if (group >= 256 && group <= 260)
    return FfdheAgreement(group, ec_private_, public_key, shared);
  const bool hybrid = group >= 4587 && group <= 4589;
  const uint16_t classical = group == 4588 ? 29 : group == 4587 ? 23 : group == 4589 ? 24 : group;
  Bytes kem_shared(hybrid ? MLKEM_SHARED_SECRET_BYTES : 0);
  ScopedSecretCleanser cleanse_kem(kem_shared);
  Bytes agreement;
  ScopedSecretCleanser cleanse_agreement(agreement);
  // Concatenating the KEM contribution must not reallocate a buffer already
  // containing the classical secret and release that allocation without wiping.
  agreement.reserve((classical == 29 ? 32 : ec_private_.size()) + kem_shared.size());
  auto peer = public_key;
  if (hybrid) {
    const size_t ciphertext_size = group == 4589 ? MLKEM1024_CIPHERTEXT_BYTES : MLKEM768_CIPHERTEXT_BYTES;
    const size_t classical_size = classical == 29 ? 32 : classical == 23 ? 65 : 97;
    if (public_key.size() != ciphertext_size + classical_size || kem_seed_.size() != MLKEM_SEED_BYTES)
      return false;
    const auto ciphertext = group == 4588 ? public_key.first(ciphertext_size) : public_key.last(ciphertext_size);
    peer = group == 4588 ? public_key.last(classical_size) : public_key.first(classical_size);
    bool valid;
    if (group == 4589) {
      MLKEM1024_private_key key;
      valid = MLKEM1024_private_key_from_seed(&key, kem_seed_.data(), kem_seed_.size()) &&
          MLKEM1024_decap(kem_shared.data(), ciphertext.data(), ciphertext.size(), &key);
      OPENSSL_cleanse(&key, sizeof(key));
    } else {
      MLKEM768_private_key key;
      valid = MLKEM768_private_key_from_seed(&key, kem_seed_.data(), kem_seed_.size()) &&
          MLKEM768_decap(kem_shared.data(), ciphertext.data(), ciphertext.size(), &key);
      OPENSSL_cleanse(&key, sizeof(key));
    }
    if (!valid)
      return false;
  }
  if (classical == 29) {
    if (peer.size() != 32)
      return false;
    CopySecret(peer, &E_);
    agreement.resize(32);
    if (E_ == A_ || E_ == B_ || !X25519(agreement.data(), b_.data(), E_.data()))
      return false;
  } else if (!EcAgreement(classical, ec_private_, peer, &agreement)) {
    return false;
  }
  if (hybrid) {
    if (group == 4588)
      agreement.insert(agreement.begin(), kem_shared.begin(), kem_shared.end());
    else
      Append(&agreement, kem_shared);
  }
  OPENSSL_cleanse(shared->data(), shared->size());
  shared->clear();
  shared->swap(agreement);
  return true;
}

bool Client::RetryHello(ByteSpan frame, ByteSpan cookie, uint16_t group) {
  if (retried_)
    return Fail(Error::kProtocol, 10);
  if ((group != 0 &&
      (group == traffic_group_ ||
       std::find(options_.groups.begin(), options_.groups.end(), group) == options_.groups.end())) ||
      (group == 0 && cookie.empty()))
    return Fail();
  if (offered_ticket_) {
    const auto age = MonotonicMilliseconds() - offered_ticket_->received_milliseconds;
    if (age < 0 || static_cast<uint64_t>(age) >=
                       uint64_t(offered_ticket_->lifetime) * 1000)
      return Fail();
    offered_psk_ages_[0] = static_cast<uint32_t>(age) + offered_ticket_->age_add;
  }
  retried_ = true;
  Bytes public_key;
  if (PasswordSuite(suite_)) {
    if (!options_.password || !group || offered_ticket_)
      return Fail();
    Bytes input;
    Append(&input, Octets(options_.password->username));
    Append(&input, Octets(options_.password->password));
    auto base = password_salt_.empty() ? net::httpps::Hash(input) : net::httpps::Mac(password_salt_, input);
    OPENSSL_cleanse(input.data(), input.size());
    password_state_ = options_.native_provider->PasswordExchange(options_.password->helper_path,
        base, ByteSpan(hello_prefix_).subspan(2u, 32u), group, static_cast<unsigned>(SuiteHashLength(suite_) * 8));
    OPENSSL_cleanse(base.data(), base.size());
    if (!password_state_ || !password_state_->Commit(&public_key)) return Fail();
  } else if (group && !GenerateTrafficShare(group, &public_key)) {
    return Fail();
  }
  if (group)
    traffic_group_ = group;
  auto inner_hash = Hash(client_hello_);
  transcript_.assign(Octets(kPreface).begin(), Octets(kPreface).end());
  Append(&transcript_, Frame(254, inner_hash));
  if (!AppendTranscript(frame))
    return false;
  Bytes extensions;
  auto old_extensions = ByteSpan(client_hello_).subspan(hello_prefix_.size() + 6);
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
    } else if (type == 41) {
      if (!cookie.empty())
        Extension(&extensions, 44, cookie);
      if (!AddPskExtension(&extensions))
        return Fail();
    } else if (type != 42) {
      Extension(&extensions, type, value);
    }
    old_extensions = old_extensions.subspan(length + 4);
  }
  if (offered_psks_.empty() && !cookie.empty())
    Extension(&extensions, 44, cookie);
  offered_features_.erase(42);  // CH2 never offers early_data.
  if (!cookie.empty()) {
    offered_features_.insert(44);
    negotiated_features_.insert(44);
  }
  // A valid HRR cookie can still make CH2's extension vector unencodable.
  // Do not truncate its uint16 length or emit a malformed ClientHello.
  if (extensions.size() > 65535)
    return Fail(Error::kProtocol, 80);
  Bytes body = hello_prefix_;
  Vector16(&body, extensions);
  auto hello = Frame(1, body);
  if (!BindClientHello(&hello, transcript_))
    return Fail();
  early_offered_ = false;
  early_sender_.reset();
  OPENSSL_cleanse(early_exporter_.data(), early_exporter_.size());
  early_exporter_.clear();
  if (!AppendTranscript(hello))
    return false;
  output_.clear();
  ByteSpan fragments(hello);
  while (!fragments.empty()) {
    const size_t size = std::min(fragments.size(), kMaxRecordContent);
    Append(&output_, PlainRecord(fragments.first(size)));
    fragments = fragments.subspan(size);
    ++handshake_records_;
  }
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
  return state_ == State::kEstablished || state_ == State::kClosed;
}
bool Client::closed() const {
  return state_ == State::kClosed;
}

bool Client::certificate_verification_pending() const {
  return state_ == State::kVerifyingCertificate;
}

bool Client::CompleteCertificateVerification(bool trusted, std::string_view validated_issuer,
    const std::vector<std::string>& validated_path) {
  if (!certificate_verification_pending() || !trusted ||
      !CertificateTLSFeaturesAllowed(validated_path.empty() ? certificates_ : validated_path) ||
      !CertificateAlgorithmsAllowed(validated_path.empty() ? certificates_ : validated_path,
                                      options_.certificate_signature_algorithms) ||
      !VerifyCertificateTransparency(options_.ct_v2_policy.get(), certificates_,
                                     certificate_extensions_, validated_issuer)) {
    return Fail(Error::kCertificate);
  }
  const auto dane = VerifyDNSSECPolicy(options_.dane_policy.get(), hostname_, certificates_,
      server_certificate_type_, certificate_extensions_,
      validated_certificate_path_.empty() ? validated_path :
          ValidatedPrivatePath(certificates_, anchors_, hostname_, delegated(), options_.native_provider.get()),
      resumed_ ? nullptr : &dane_expires_unix_seconds_);
  if (!dane)
    return Fail(Error::kCertificate);
  if (options_.dane_policy && *dane >= 0 && !resumed_)
    authentication_ = combined_psk_ ? Authentication::kDaneCertificateAndPsk : Authentication::kDaneCertificate;
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
  auto salt = Label(root_, "auth salt", Hash(transcript_));
  auto auth_root = Mac(salt, shared);
  auto proof_key = Label(auth_root, "server mac", {});
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
  if (established())
    return true;  // Post-handshake control frames keep the application epoch.
  if (state_ == State::kHello) {
    return Deadline();
  }
  if (state_ != State::kFlushing || !Deadline()) {
    return Fail();
  }
  if (options_.pinning && !options_.pinning->Commit())
    return Fail(Error::kCertificate, 40);
  sender_ = std::make_unique<RecordCipher>(c_app_, suite_, options_.native_provider);
  receiver_ = std::make_unique<RecordCipher>(s_app_, suite_, options_.native_provider);
  sender_->SetLimit(peer_record_limit_);
  receiver_->SetLimit(local_record_limit_);
  sender_->SetContentLimit(fragment_limit_);
  receiver_->SetContentLimit(fragment_limit_);
  early_sender_.reset();
  offered_ticket_.reset();
  EraseHandshakeSecrets();
  OPENSSL_cleanse(master_.data(), master_.size());
  if (post_handshake_auth_offered_ && alpn_ != "h2")
    initial_transcript_ = transcript_;
  transcript_.clear();
  state_ = State::kEstablished;
  return true;
}

bool Client::AcceptFrame(ByteSpan frame) {
  auto body = frame.subspan(4u);
  switch (state_) {
    case State::kHello: {
      if (frame[0] != 2) return Fail(Error::kProtocol, 10);
      if (body.size() < 40) return Fail(Error::kProtocol, 50);
      if (body[0] != 3 || body[1] != 3)
        return Fail(Error::kProtocol, 70);
      if (body[34] != 0 || body[37] != 0) {
        return Fail();
      }
      std::map<uint16_t, Bytes> extensions;
      uint8_t extension_alert;
      if (!Extensions(body.subspan(38u), &extensions, &extension_alert))
        return Fail(Error::kProtocol, extension_alert);
      if (!extensions.count(43))
        return Fail(Error::kProtocol, 109);
      if (extensions.at(43).size() != 2)
        return Fail(Error::kProtocol, 50);
      if (extensions.at(43) != Bytes({4, 0}))
        return Fail(Error::kProtocol, 47);
      constexpr std::array<uint8_t, 32> kRetryRandom = {
          0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,
          0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
          0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,
          0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
      const bool retry = Equal(body.subspan(2u, 32u), kRetryRandom);
      if (retry && retried_)
        return Fail(Error::kProtocol, 10);
      for (const auto& [type, unused] : extensions) {
        if (!ResponseExtensionAllowed(type, retry ? ResponseContext::kRetry
                                                 : ResponseContext::kServerHello))
          return Fail(Error::kProtocol, 47);
        // Cookie is expressly unsolicited. PWD salt responds to the actual
        // username offer (29/30), rather than an impossible CH salt extension.
        const bool retry_request = retry && (type == 44 ||
            (type == 31 && (offered_features_.count(29) || offered_features_.count(30))));
        if (!retry_request && !offered_features_.count(type))
          return Fail(Error::kProtocol, 110);
      }
      const auto selected_suite = static_cast<uint16_t>(Read16(body.subspan(35u, 2u)));
      if (std::find(options_.cipher_suites.begin(), options_.cipher_suites.end(), selected_suite) ==
              options_.cipher_suites.end() || (retried_ && selected_suite != suite_))
        return Fail();
      suite_ = selected_suite;
      if (retry) {
        uint16_t group = 0;
        for (const auto& [type, data] : extensions) {
          if (type == 43)
            continue;
          if (type == 51) {
            if (data.size() != 2) return Fail(Error::kProtocol, 50);
            group = static_cast<uint16_t>(Read16(data));
            // Zero denotes an omitted key_share only in RetryHello's API;
            // an explicit reserved group is not a cookie-only retry.
            if (group == 0)
              return Fail(Error::kProtocol, 47);
            continue;
          }
          if (type == 44) {
            if (data.size() < 3 || Read16(ByteSpan(data).first(2u)) != data.size() - 2)
              return Fail(Error::kProtocol, 50);
            continue;
          }
          if (type == 31 && PasswordSuite(suite_) && options_.password) {
            if (data.size() < 2 || Read16(ByteSpan(data).first(2u)) != data.size() - 2)
              return Fail(Error::kProtocol, 50);
            if (data.size() != 34) return Fail(Error::kProtocol, 47);
            password_salt_.assign(data.begin() + 2, data.end());
            continue;
          }
          return Fail();
        }
        return RetryHello(frame, extensions.count(44) ? ByteSpan(extensions[44])
                                                      : ByteSpan(), group);
      }
      for (const auto& [type, data] : extensions) {
        if (type != 43 && type != 51 && type != 41 && type != 33)
          return Fail();
      }
      psk_selected_ = extensions.count(41) != 0;
      if (psk_selected_) {
        if (extensions[41].size() != 2)
          return Fail(Error::kProtocol, 50);
        selected_psk_ = Read16(extensions[41]);
        if (selected_psk_ >= offered_psks_.size() ||
            bool(IntegrityTagLength(offered_psks_[selected_psk_].cipher_suite)) != bool(IntegrityTagLength(suite_)) ||
            SuiteHashId(offered_psks_[selected_psk_].cipher_suite) != SuiteHashId(suite_))
          return Fail();
      }
      resumed_ = psk_selected_ && selected_psk_ == 0 && offered_ticket_;
      if (!resumed_ && !options_.bootstraps.empty()) {
        if (!psk_selected_) return Fail(Error::kCertificate);
        const auto selected = bootstrap_offers_.find(offered_psks_[selected_psk_].identity);
        if (selected == bootstrap_offers_.end()) return Fail(Error::kCertificate);
        SelectBootstrap(selected->second);
      }
      if (!psk_selected_ || selected_psk_ != 0) {
        OPENSSL_cleanse(early_exporter_.data(), early_exporter_.size());
        early_exporter_.clear();
      }
      // Provisioned PSKs remain an authentication requirement when offering a
      // descendant ticket. A server losing its ticket store cannot silently
      // replace this policy with certificate-only authentication.
      if (!psk_selected_ && !options_.external_psks.empty() && !PasswordSuite(suite_))
        return Fail(Error::kCertificate);
      if (options_.password && (PasswordSuite(suite_) ? (psk_selected_ || !password_state_)
                                                    : (password_only_ && !resumed_)))
        return Fail(Error::kCertificate);
      const bool combined = extensions.count(33) != 0;
      if (combined && !extensions[33].empty()) return Fail(Error::kProtocol, 50);
      if ((combined && (!combined_psk_ || !psk_selected_)) ||
          (combined_psk_ && !combined && !PasswordSuite(suite_)))
        return Fail();
      combined_psk_ = combined;
      if (resumed_) {
        authentication_ = offered_ticket_->authentication;
        external_psk_binding_ = offered_ticket_->external_psk_binding;
      } else if (PasswordSuite(suite_)) {
        authentication_ = Authentication::kPassword;
      } else if (psk_selected_) {
        external_psk_binding_ = PskBinding(offered_psks_[selected_psk_]);
        authentication_ = combined ? Authentication::kCertificateAndPsk : Authentication::kExternalPsk;
      }
      const bool dhe = extensions.count(51) != 0;
      if (psk_selected_ && std::find(options_.psk_modes.begin(), options_.psk_modes.end(),
                                     dhe ? 1 : 0) == options_.psk_modes.end())
        return Fail();
      if (!dhe && (!psk_selected_ || combined))
        return Fail();
      Bytes shared(SuiteHashLength(suite_));
      ScopedSecretCleanser cleanse_shared(shared);
      if (dhe) {
        if (extensions[51].size() < 5 ||
            Read16(ByteSpan(extensions[51]).subspan(2u, 2u)) != extensions[51].size() - 4)
          return Fail(Error::kProtocol, 50);
        if (Read16(ByteSpan(extensions[51]).first(2u)) != traffic_group_)
          return Fail(Error::kProtocol, 47);
        auto peer = ByteSpan(extensions[51]).subspan(4u);
        const bool agreed = PasswordSuite(suite_) ? password_state_->Finish(peer, &shared)
                                                 : TrafficAgreement(traffic_group_, peer, &shared);
        password_state_.reset();
        if (!agreed)
          return Fail();
      } else {
        traffic_group_ = 0;
      }
      if (!AppendTranscript(frame)) {
        return Fail();
      }
      for (const auto& [type, unused] : extensions) negotiated_features_.insert(type);
      if (psk_selected_) negotiated_features_.insert(45);
      if (options_.pinning)
        pinning_transcript_ = transcript_;
      Bytes zeros(SuiteHashLength(suite_));
      auto early = Mac(zeros, psk_selected_ ? offered_psks_[selected_psk_].secret : zeros);
      auto derived = Label(early, "derived", Hash({}));
      root_ = Mac(derived, shared);
      OPENSSL_cleanse(early.data(), early.size());
      OPENSSL_cleanse(derived.data(), derived.size());
      OPENSSL_cleanse(shared.data(), shared.size());
      OPENSSL_cleanse(b_.data(), b_.size());
      OPENSSL_cleanse(ec_private_.data(), ec_private_.size());
      OPENSSL_cleanse(kem_seed_.data(), kem_seed_.size());
      if (!DeriveSecret(root_, "c hs traffic", Hash(transcript_), &c_hs_) ||
          !DeriveSecret(root_, "s hs traffic", Hash(transcript_), &s_hs_)) {
        return Fail();
      }
      sender_ = std::make_unique<RecordCipher>(c_hs_, suite_, options_.native_provider);
      Diagnostic("TLS20_CLIENT_HANDSHAKE_TRAFFIC_SECRET", c_hs_);
      Diagnostic("TLS20_SERVER_HANDSHAKE_TRAFFIC_SECRET", s_hs_);
      receiver_ = std::make_unique<RecordCipher>(s_hs_, suite_, options_.native_provider);
      state_ = State::kExtensions;
      return true;
    }
    case State::kExtensions: {
      std::map<uint16_t, Bytes> extensions;
      if (frame[0] != 8) return Fail(Error::kProtocol, 10);
      uint8_t extension_alert;
      if (!Extensions(body, &extensions, &extension_alert))
        return Fail(Error::kProtocol, extension_alert);
      for (const auto& [type, unused] : extensions) {
        // Recognized extensions in the wrong message retain illegal_parameter.
        // Otherwise a response needs an actual offer in this connection's CH,
        // including when the type is unknown (RFC 9846 section 4.3).
        if (!ResponseExtensionAllowed(type, ResponseContext::kEncryptedExtensions))
          return Fail(Error::kProtocol, 47);
        if (!offered_features_.count(type))
          return Fail(Error::kProtocol, 110);
      }
      if (!AppendTranscript(frame)) return Fail(Error::kProtocol, 50);
      if (options_.signaling && !options_.signaling->Validate(extensions))
        return Fail();
      if (options_.no_alpn_http11) {
        if (extensions.count(16))
          return Fail(Error::kProtocol, 110);
        alpn_ = "http/1.1";
      } else {
        if (!extensions.count(16))
          return Fail(Error::kProtocol, 109);
        const auto& alpn = extensions.at(16);
        if (alpn.size() < 4 || Read16(ByteSpan(alpn).first(2u)) != alpn.size() - 2 ||
            alpn[2] != alpn.size() - 3)
          return Fail(Error::kProtocol, 50);
        alpn_.assign(alpn.begin() + 3, alpn.end());
      }
      if (std::find(options_.alpn_protocols.begin(), options_.alpn_protocols.end(), alpn_) ==
          options_.alpn_protocols.end())
        return Fail();
      if (extensions.count(1) && extensions.count(28))
        return Fail();
      // Extension presence/placement was checked above. Fixed-width fields
      // with missing or trailing octets are syntax errors, not bad enums
      // (RFC 9846 section 6); well-formed invalid values still use alert 47.
      for (const auto& [type, data] : extensions) {
        switch (type) {
          case 0: case 42:
            if (!data.empty()) return Fail(Error::kProtocol, 50);
            break;
          case 1: case 15: case 19: case 20: case 58:
            if (data.size() != 1) return Fail(Error::kProtocol, 50);
            break;
          case 28:
            if (data.size() != 2) return Fail(Error::kProtocol, 50);
            break;
        }
      }
      if (extensions.count(28)) {
        if (!options_.record_size_limit || extensions[28].size() != 2)
          return Fail();
        peer_record_limit_ = Read16(extensions[28]);
        local_record_limit_ = *options_.record_size_limit;
        if (peer_record_limit_ < 64 || peer_record_limit_ > 16385)
          return Fail();
      } else if (extensions.count(1)) {
        if (!options_.max_fragment_length || extensions[1] != Bytes{*options_.max_fragment_length})
          return Fail();
        fragment_limit_ = size_t{1} << (8 + *options_.max_fragment_length);
        peer_record_limit_ = local_record_limit_ = fragment_limit_ + 1;
      }
      sender_->SetLimit(peer_record_limit_);
      receiver_->SetLimit(local_record_limit_);
      sender_->SetContentLimit(fragment_limit_);
      receiver_->SetContentLimit(fragment_limit_);
      if (!receiver_->OpenedRecordsWithinLimits())
        return Fail(Error::kProtocol, 22);
      for (const auto& [type, data] : extensions) {
        if (type == 0 && data.empty() && !IsIpIdentity(hostname_))
          continue;
        if (type == 10) {
          if (data.size() < 4 || data.size() % 2 ||
              Read16(ByteSpan(data).first(2u)) != data.size() - 2)
            return Fail(Error::kProtocol, 50);
          continue;  // RFC supported_groups preference, not a new key selection.
        }
        if (type == 16)
          continue;
        if ((type == 55 || type == 56) && options_.signaling)
          continue;
        if (type == 58 && options_.ticket_request) {
          uint8_t count;
          if (!TicketRequest::ParseHint(data, &count))
            return Fail();
          expected_ticket_count_ = count;
          continue;
        }
        if (type == 32 && options_.pinning) {
          pinning_response_ = data;
          continue;
        }
        if (type == 1 || type == 28)
          continue;
        if (type == 25 && data.size() >= 3 && Read16(ByteSpan(data).first(2u)) == data.size() - 2) {
          for (size_t i = 2; i < data.size(); ++i) {
            if (data[i] == 1 && !cached_certificate_selected_ && !options_.cached_certificates.empty() &&
                (!psk_selected_ || combined_psk_))
              cached_certificate_selected_ = true;
            else if (data[i] == 2 && !cached_request_selected_ && !options_.cached_request_templates.empty())
              cached_request_selected_ = true;
            else
              return Fail();
          }
          continue;
        }
        if (type == 20 && data.size() == 1 &&
            options_.server_certificate_types != std::vector<uint8_t>{0} &&
            std::find(options_.server_certificate_types.begin(), options_.server_certificate_types.end(), data[0]) !=
                options_.server_certificate_types.end()) {
          server_certificate_type_ = data[0];
          continue;
        }
        if (type == 19 && data.size() == 1 && client_credential_ &&
            client_credential_->certificate_type == data[0] && data[0] != 0) {
          client_certificate_type_ = data[0];
          continue;
        }
        if (type == 15 && options_.heartbeat_mode && data.size() == 1 && data[0] >= 1 && data[0] <= 2) {
          peer_heartbeat_mode_ = data[0];
          continue;
        }
        if (type == 42 && data.empty() && psk_selected_ && selected_psk_ == 0 && early_offered_ &&
            offered_psks_[0].cipher_suite == suite_ && offered_psks_[0].alpn == alpn_) {
          early_accepted_ = true;
          continue;
        }
        return Fail();
      }
      if ((!psk_selected_ || combined_psk_) &&
          std::find(options_.server_certificate_types.begin(), options_.server_certificate_types.end(),
                    server_certificate_type_) == options_.server_certificate_types.end())
        return Fail();
      for (const auto& [type, unused] : extensions) negotiated_features_.insert(type);
      if (options_.bootstrap && psk_selected_ && !resumed_) {
        offered_psks_[selected_psk_].alpn = alpn_;
        external_psk_binding_ = PskBinding(offered_psks_[selected_psk_]);
      }
      if (psk_selected_ && offered_psks_[selected_psk_].alpn != alpn_)
        return Fail();
      if (authentication_ == Authentication::kPassword || (psk_selected_ && !resumed_ && !combined_psk_)) {
        state_ = State::kFinished;
        return true;  // Explicit provisioning, not an implicit PKI bypass.
      }
      if (resumed_) {
        certificates_ = offered_ticket_->certificates;
        certificate_extensions_ = offered_ticket_->certificate_extensions;
        server_delegation_ = offered_ticket_->delegation;
        server_certificate_type_ = offered_ticket_->server_certificate_type;
        client_certificate_type_ = offered_ticket_->client_certificate_type;
        authenticated_client_identity_ = offered_ticket_->client_identity;
        if (authentication_ == Authentication::kUnauthenticated &&
            options_.allow_unauthenticated) {
          state_ = State::kFinished;
          return true;
        }
        if (server_certificate_type_ == 3) {
          const auto authorization = options_.its_policy->Verify(Octets(certificates_.front()),
              0, hostname_, WallMilliseconds());
          if (!authorization || its_expires_unix_milliseconds_ <= WallMilliseconds())
            return Fail(Error::kCertificate);
          state_ = State::kFinished;
          return true;
        }
        Secret unused;
        const auto required_evidence = authentication_ != Authentication::kProvisioning &&
            server_certificate_type_ == 0 && !certificates_.empty()
            ? CertificateRequiresBrowserEvidence(certificates_.front(), options_.request_ocsp,
                                                 options_.request_scts) : std::optional<bool>(false);
        if (!required_evidence)
          return Fail(Error::kCertificate);
        bool trusted = authentication_ == Authentication::kExternalPsk ||
            (authentication_ == Authentication::kProvisioning && options_.bootstrap &&
             options_.bootstrap->provisioning_trust && ProvisioningKey(certificates_, server_certificate_type_,
                                                                        certificate_extensions_, &unused)) ||
            server_certificate_type_ == 2 || (!anchors_.empty() &&
            !*required_evidence && VerifyLabChain(certificates_, anchors_, hostname_, &unused, delegated(), options_.native_provider.get()));
        const auto private_path = ValidatedPrivatePath(certificates_, anchors_, hostname_, delegated(), options_.native_provider.get());
        const auto dane = VerifyDNSSECPolicy(options_.dane_policy.get(), hostname_, certificates_,
            server_certificate_type_, certificate_extensions_, private_path, nullptr,
            &validated_certificate_path_);
        if (options_.dane_policy) {
          if (dane && *dane >= 0 && !*required_evidence)
            trusted = true;
          else if (!dane || *dane < 0)
            trusted = trusted && dane.has_value();
        }
        if (!dane) validated_certificate_path_.clear();
        if (options_.ct_v2_policy && validated_certificate_path_.empty())
          trusted = false;
        if (trusted && options_.ct_v2_policy &&
            !VerifyCertificateTransparency(options_.ct_v2_policy.get(), certificates_, certificate_extensions_,
                validated_certificate_path_.size() > 1 ? validated_certificate_path_[1] : std::string_view{}))
          return Fail(Error::kCertificate);
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
      const bool compressed_certificate = frame[0] == 25;
      if (frame[0] == 13 || frame[0] == 252) {
        if (client_auth_requested_)
          return Fail(Error::kProtocol, 10);
        return AcceptCertificateRequest(frame, false);
      }
      Bytes decompressed;
      if (frame[0] == 25) {
        if (body.size() < 2 || std::find(options_.certificate_compression.begin(),
              options_.certificate_compression.end(), Read16(body.first(2u))) ==
              options_.certificate_compression.end())
          return Fail();
        uint8_t compression_alert;
        if (!DecompressCertificate(body, &decompressed, &compression_alert))
          return Fail(Error::kProtocol, compression_alert);
        body = decompressed;
      } else if (frame[0] != (cached_certificate_selected_ ? 253 : 11)) {
        return Fail(Error::kProtocol, 10);
      }
      Bytes expanded;
      if (cached_certificate_selected_) {
        if (!ResolveCachedCertificate(body, options_, server_certificate_type_, &expanded))
          return Fail();
        body = expanded;
      }
      uint8_t certificate_alert;
      if (!ParseCertificates(body, &certificates_, &certificate_extensions_, &certificate_alert)) {
        return Fail(Error::kProtocol, certificate_alert);
      }
      for (size_t i = 0; i < certificate_extensions_.size(); ++i) {
        for (const auto& [code, value] : certificate_extensions_[i]) {
          if (!ResponseExtensionAllowed(code, ResponseContext::kCertificate))
            return Fail(Error::kProtocol, 47);
          if (!offered_features_.count(code))
            return Fail(Error::kProtocol, code == 34 ? 10 : 110);
          if (code == 34 && i == 0 && server_certificate_type_ == 0 && options_.delegated_credentials) {
            // Decode the nested vectors before cryptographic grant validation.
            // RFC 9345 distinguishes malformed encoding from a bad grant.
            if (value.size() < 13)
              return Fail(Error::kCertificate, 50);
            const auto spki_size = Read24(ByteSpan(value).subspan(6u, 3u));
            if (!spki_size || spki_size > value.size() - 13)
              return Fail(Error::kCertificate, 50);
            const auto signature_size = Read16(ByteSpan(value).subspan(11 + spki_size, 2u));
            if (!signature_size || signature_size != value.size() - 13 - spki_size)
              return Fail(Error::kCertificate, 50);
            server_delegation_ = value;
          } else if (code == 5 && options_.request_ocsp && server_certificate_type_ == 0) {
            if (value.empty()) return Fail(Error::kProtocol, 50);
            if (value[0] != 1) return Fail(Error::kProtocol, 47);
            if (value.size() < 5 ||
                ((size_t(value[1]) << 16) | (size_t(value[2]) << 8) | value[3]) != value.size() - 4)
              return Fail(Error::kProtocol, 50);
            if (!OCSPRequestMatchesResponse(options_, ByteSpan(value).subspan(4u)))
              return Fail();
          } else if (code == 18 && i == 0 && options_.request_scts && server_certificate_type_ == 0) {
            ByteSpan entries = value;
            if (entries.size() < 5 || Read16(entries.first(2u)) != entries.size() - 2)
              return Fail(Error::kProtocol, 50);
            entries = entries.subspan(2u);
            while (!entries.empty()) {
              if (entries.size() < 3)
                return Fail(Error::kProtocol, 50);
              const auto length = Read16(entries.first(2u));
              if (!length || length > entries.size() - 2)
                return Fail(Error::kProtocol, 50);
              entries = entries.subspan(size_t{2} + length);
            }
          } else if (code == 52 && i == 0 && options_.ct_v2_policy && server_certificate_type_ == 0) {
            // RFC9162 permits empty TLS extension_data. A present TransItemList
            // and each serialized TransItem must still have valid framing;
            // signature/log policy is checked only after credential trust.
            ByteSpan entries = value;
            if (entries.empty()) continue;
            if (entries.size() < 6 || Read16(entries.first(2u)) != entries.size() - 2)
              return Fail(Error::kProtocol, 50);
            entries = entries.subspan(2u);
            while (!entries.empty()) {
              if (entries.size() < 4) return Fail(Error::kProtocol, 50);
              const auto length = Read16(entries.first(2u));
              if (length < 2 || length > entries.size() - 2)
                return Fail(Error::kProtocol, 50);
              entries = entries.subspan(size_t{2} + length);
            }
          } else if (code == 59 && i == 0 && options_.dane_policy) {
            // DNSSEC/TLSA authorization is verified below, never the AD bit.
          } else {
            return Fail();
          }
        }
      }
      if (options_.bootstrap && options_.bootstrap->provisioning_trust) {
        if (!combined_psk_ || !ProvisioningKey(certificates_, server_certificate_type_, certificate_extensions_, &S_) ||
            !AppendTranscript(frame))
          return Fail(Error::kCertificate);
        authentication_ = Authentication::kProvisioning;
        return PrepareServerProof();
      }
      if (options_.allow_unauthenticated) {
        // Selected before the attempt, never a fallback from failed validation.
        // A delegated key still requires a cryptographically valid grant.
        if (delegated() && !ValidateDelegation(certificates_.front(), server_delegation_, true,
                options_.grant_signature_algorithms, &S_, options_.native_provider.get()))
          return Fail(Error::kCertificate, 47);
        const bool key_ok = server_certificate_type_ == 2
            ? certificates_.size() == 1 && ExtractRawPublicKey(Octets(certificates_[0]), &S_)
            : server_certificate_type_ == 0 &&
                CertificateAlgorithmsAllowed(certificates_, options_.certificate_signature_algorithms) &&
                (delegated() || ExtractServerPublicKey(certificates_.front(), &S_));
        if (!key_ok || combined_psk_ || !AppendTranscript(frame))
          return Fail(Error::kCertificate);
        authentication_ = Authentication::kUnauthenticated;
        return PrepareServerProof();
      }
      if (server_certificate_type_ == 3) {
        if (!options_.its_policy || certificates_.size() != 1 ||
            !certificate_extensions_.front().empty()) return Fail(Error::kCertificate);
        const auto authorization = options_.its_policy->Verify(Octets(certificates_.front()),
            0, hostname_, WallMilliseconds());
        if (!authorization || !AppendTranscript(frame)) return Fail(Error::kCertificate);
        S_ = authorization->public_key;
        its_expires_unix_milliseconds_ = authorization->expires_unix_milliseconds;
        authentication_ = combined_psk_ ? Authentication::kITSAndPsk : Authentication::kITS;
        return PrepareServerProof();
      }
      if (server_certificate_type_ == 2) {
        const auto dane = VerifyDNSSECPolicy(options_.dane_policy.get(), hostname_, certificates_,
            server_certificate_type_, certificate_extensions_, {}, &dane_expires_unix_seconds_);
        const bool dane_trusted = options_.dane_policy && dane && *dane == 3;
        if (certificates_.size() != 1 || !ExtractRawPublicKey(Octets(certificates_[0]), &S_) ||
            (options_.dane_policy && !dane_trusted) ||
            (!dane_trusted && std::none_of(options_.server_raw_public_keys.begin(), options_.server_raw_public_keys.end(),
                [&](const Bytes& pin) { return Equal(pin, Octets(certificates_[0])); })) ||
            !AppendTranscript(frame))
          return Fail(Error::kCertificate);
        authentication_ = combined_psk_ ? Authentication::kRawPublicKeyAndPsk
                                        : Authentication::kRawPublicKey;
        if (dane_trusted)
          authentication_ = combined_psk_ ? Authentication::kDaneRawPublicKeyAndPsk : Authentication::kDaneRawPublicKey;
        return PrepareServerProof();
      }
      // Explicit, role-specific private anchors are additive. A successful lab
      // verification is sufficient; otherwise use the browser's HTTPS verifier.
      // Never turn a failed external decision into a lab or insecure fallback.
      const auto required_evidence = CertificateRequiresBrowserEvidence(certificates_.front(),
          options_.request_ocsp, options_.request_scts);
      if (!required_evidence)
        return Fail(Error::kCertificate);
      bool private_trusted = !*required_evidence &&
          !anchors_.empty() &&
          VerifyLabChain(certificates_, anchors_, hostname_, &S_, delegated(), options_.native_provider.get());
      const auto private_path = ValidatedPrivatePath(certificates_, anchors_, hostname_, delegated(), options_.native_provider.get());
      if (!private_path.empty() && !CertificateTLSFeaturesAllowed(private_path))
        return Fail(Error::kCertificate);
      if ((!private_path.empty() || !use_external_verifier_) &&
          !CertificateAlgorithmsAllowed(private_path.empty() ? certificates_ : private_path,
                                         options_.certificate_signature_algorithms)) return Fail(Error::kCertificate);
      const auto dane = VerifyDNSSECPolicy(options_.dane_policy.get(), hostname_, certificates_,
          server_certificate_type_, certificate_extensions_, private_path, &dane_expires_unix_seconds_,
          &validated_certificate_path_);
      if (options_.dane_policy) {
        if (dane && *dane >= 0 && !*required_evidence) {
          private_trusted = true;
          if (!delegated() && !ExtractServerPublicKey(certificates_.front(), &S_))
            return Fail(Error::kCertificate);
          authentication_ = combined_psk_ ? Authentication::kDaneCertificateAndPsk : Authentication::kDaneCertificate;
        } else {
          private_trusted = private_trusted && dane.has_value();
        }
      }
      if (!dane) validated_certificate_path_.clear();
      if (!validated_certificate_path_.empty() &&
          !CertificateAlgorithmsAllowed(validated_certificate_path_, options_.certificate_signature_algorithms))
        return Fail(Error::kCertificate);
      if (options_.ct_v2_policy && validated_certificate_path_.empty())
        private_trusted = false;
      if (use_external_verifier_ && std::any_of(certificate_extensions_.begin(), certificate_extensions_.end(),
          [](const auto& metadata) { return metadata.contains(5); }))
        private_trusted = false;
      if (delegated() && !ValidateDelegation(certificates_.front(), server_delegation_, true,
                                            options_.grant_signature_algorithms, &S_, options_.native_provider.get()))
        return Fail(Error::kCertificate, 47);
      if (!private_trusted &&
          (!use_external_verifier_ ||
           (!delegated() && !ExtractServerPublicKey(certificates_.front(), &S_)))) {
        return Fail(Error::kCertificate);
      }
      if (!AppendTranscript(frame)) {
        return Fail();
      }
      if (compressed_certificate) negotiated_features_.insert(27);
      if (!private_trusted) {
        state_ = State::kVerifyingCertificate;
        return true;
      }
      if (!VerifyCertificateTransparency(options_.ct_v2_policy.get(), certificates_, certificate_extensions_,
              validated_certificate_path_.size() > 1 ? validated_certificate_path_[1] : std::string_view{}))
        return Fail(Error::kCertificate);
      return PrepareServerProof();
    }
    case State::kProof:
      if (frame[0] != 15) return Fail(Error::kProtocol, 10);
      if (body.size() != 4 + SuiteHashLength(suite_) ||
          Read16(body.subspan(2u, 2u)) != SuiteHashLength(suite_))
        return Fail(Error::kProtocol, 50);
      if (body[0] != 0xfe || body[1] != 0) return Fail(Error::kProtocol, 47);
      if (!Equal(body.subspan(4u), expected_proof_) ||
          !AppendTranscript(frame)) {
        return Fail(Error::kProtocol, 51);
      }
      OPENSSL_cleanse(expected_proof_.data(), expected_proof_.size());
      negotiated_features_.insert(0xff02);
      state_ = State::kFinished;
      return true;
    case State::kFinished: {
      if (frame[0] != 20) return Fail(Error::kProtocol, 10);
      if (body.size() != SuiteHashLength(suite_)) return Fail(Error::kProtocol, 50);
      if (server_certificate_type_ == 3 && its_expires_unix_milliseconds_ <= WallMilliseconds())
        return Fail(Error::kCertificate);
      if (options_.bootstrap && options_.bootstrap->expires_unix_seconds &&
          WallMilliseconds() / 1000 >= options_.bootstrap->expires_unix_seconds)
        return Fail(Error::kCertificate);
      auto expected = Finished(s_hs_, transcript_);
      bool ok = Equal(body, expected);
      OPENSSL_cleanse(expected.data(), expected.size());
      if (!ok || !AppendTranscript(frame)) {
        return Fail(Error::kProtocol, 51);
      }
      if (server_certificate_type_ == 0 && !certificates_.empty() &&
          authentication_ != Authentication::kProvisioning && authentication_ != Authentication::kUnauthenticated) {
        auto satisfied = negotiated_features_;
        // With no new credential flight, its compression/cache/MAC mechanisms
        // are redundant on PSK resumption (RFC7633), not an obligation to send
        // a forbidden Certificate/CertificateVerify flight. Cached evidence
        // and actual connection controls still retain their independent checks.
        if (resumed_) satisfied.insert({25, 27, 0xff02});
        // These unilateral offers are fulfilled by credential validation, not
        // an invented EE echo. Evidence has already passed its trust policy.
        satisfied.insert(50);
        if (delegated()) satisfied.insert(0xff04);
        if (!certificate_extensions_.empty())
          for (const auto& [type, unused] : certificate_extensions_.front()) satisfied.insert(type);
        if (!CertificateFeaturesNegotiated(certificates_.front(), offered_features_, satisfied))
          return Fail(Error::kCertificate);
      }
      if (options_.pinning) {
        Bytes spki{0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 3, 0x21, 0};
        Append(&spki, S_);
        if (psk_selected_ || !options_.pinning->Verify(
                pinning_response_ ? std::optional<ByteSpan>(*pinning_response_) : std::nullopt,
                suite_, root_, pinning_transcript_, spki, options_.native_provider.get()))
          return Fail(Error::kCertificate, 40);
        pinning_transcript_.clear();
      }
      if (options_.bootstrap && ((!resumed_ && (!combined_psk_ || !traffic_group_ || early_accepted_ ||
          !client_auth_requested_ || client_certificate_type_ != 2 || !ClientCredentialMatchesRequest())) ||
          (resumed_ && authenticated_client_identity_ == Secret{})))
        return Fail(Error::kCertificate);
      auto derived = Label(root_, "derived", Hash({}));
      master_ = Mac(derived, Bytes(SuiteHashLength(suite_)));
      OPENSSL_cleanse(derived.data(), derived.size());
      if (!DeriveSecret(master_, "c ap traffic", Hash(transcript_), &c_app_) ||
          !DeriveSecret(master_, "s ap traffic", Hash(transcript_), &s_app_) ||
          !DeriveSecret(master_, "exp master", Hash(transcript_), &exporter_))
        return Fail();
      output_.clear();
      Diagnostic("TLS20_CLIENT_TRAFFIC_SECRET_0", c_app_);
      Diagnostic("TLS20_SERVER_TRAFFIC_SECRET_0", s_app_);
      Diagnostic("TLS20_EXPORTER_SECRET", exporter_, true);
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
      if (++handshake_records_ > 4096 ||
          !SealHandshake(client_finished) ||
          !AppendTranscript(client_finished)) {
        return Fail();
      }
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
  if (state_ == State::kClosed) {
    application_data->clear();
    return true;  // Peer close_notify ends only its sending direction.
  }
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
    if (record.size() < 5) return Fail(Error::kProtocol, 50);
    if (record[0] != 21 && record[0] != 22) return Fail(Error::kProtocol, 10);
    const size_t length = Read16(record.subspan(3u, 2u));
    if (length > kMaxRecordContent) return Fail(Error::kProtocol, 22);
    if (length != record.size() - 5) return Fail(Error::kProtocol, 50);
    if (!length) return Fail(Error::kProtocol, 10);
    if (record[0] == 21 && length != 2) return Fail(Error::kProtocol, 50);
    type = record[0];
    content.assign(record.begin() + 5, record.end());
  } else if (!receiver_ || !receiver_->Open(record, &type, &content)) {
    return Fail(Error::kProtocol, receiver_ ? receiver_->alert() : 20);
  }
  if (type == 21 && content[1] != 0 && content[1] != 90)
    return Fail(Error::kProtocol, 0);  // Never answer a peer fatal alert.
  if (type != 22 && !reassembly_.empty())
    return Fail(Error::kProtocol, 10);
  if (type == 21) {
    if (content.size() == 2 && content[1] == 90)
      return true;  // Does not close a direction at a handshake boundary.
    if (!handshake && content.size() == 2 && content[1] == 0) {
      state_ = State::kClosed;
      DisableAuthenticators();
      if (close_sent_)
        EraseConnectionSecrets();  // Both directions ended; exporters end too.
      return true;
    }
    return Fail(Error::kProtocol, 0);  // Never answer a peer fatal alert.
  }
  if (!handshake) {
    if (type == 24) {
      if (!peer_heartbeat_mode_ || !options_.heartbeat_mode || !reassembly_.empty())
        return Fail(Error::kProtocol, 10);
      if (content.size() < 19)
        return true;
      const size_t length = Read16(ByteSpan(content).subspan(1u, 2u));
      if (length > content.size() - 19)
        return true;  // Never echo absent data (RFC 6520).
      ByteSpan payload = ByteSpan(content).subspan(3u, length);
      if (content[0] == 1 && *options_.heartbeat_mode == 1 && !close_sent_) {
        Bytes response{2};
        U16(&response, length);
        Append(&response, payload);
        if (response.size() + 16 > max_send_content())
          return true;
        const size_t padding_offset = response.size();
        response.resize(response.size() + 16);
        RAND_bytes(MutableByteSpan(response).subspan(padding_offset).data(), 16);
        Bytes response_record;
        if (!sender_->Seal(response, 24, &response_record))
          return Fail();
        Append(&output_, response_record);
      } else if (content[0] == 2 && heartbeat_request_ && Equal(*heartbeat_request_, payload)) {
        heartbeat_response_ = *heartbeat_request_;
        heartbeat_request_.reset();
      }
      return true;
    }
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
          return Fail(Error::kProtocol, 10);
        if (!AcceptPostHandshake(ByteSpan(reassembly_).first(length + 4)))
          return false;
        reassembly_.erase(reassembly_.begin(), reassembly_.begin() + length + 4);
      }
      return true;
    }
    if (type != 23 || !reassembly_.empty()) {
      return Fail(Error::kProtocol, 10);
    }
    *application_data = std::move(content);
    return true;
  }
  if (type != 22)
    return Fail(Error::kProtocol, 10);
  if (reassembly_.size() + content.size() > 262148 + 16384) {
    return Fail();
  }
  Append(&reassembly_, content);
  return DrainHandshakeFrames();
}

bool Client::AcceptPostHandshake(ByteSpan frame) {
  auto body = frame.subspan(4u);
  if (frame[0] == 13 || frame[0] == 252) {
    transcript_ = initial_transcript_;
    if (initial_transcript_.empty()) return Fail(Error::kProtocol, 10);
    if (!AcceptCertificateRequest(frame, true)) return false;
    if (close_sent_) {
      // A request already in flight may arrive after our write-side close.
      // Validate it, but never reopen that direction or abandon peer reads.
      transcript_.clear();
      OPENSSL_cleanse(client_verifier_share_.data(), client_verifier_share_.size());
      return true;
    }
    if (update_response_pending_) {
      Bytes update;
      if (!RequestKeyUpdate(false, &update))
        return false;
      Append(&output_, update);
    }
    if (!AppendClientAuthentication())
      return false;
    if (!SealHandshake(Frame(20, Finished(c_app_, transcript_))))
      return Fail();
    transcript_.clear();
    return true;
  }
  if (frame[0] == 24) {
    if (body.size() != 1)
      return Fail(Error::kProtocol, 50);
    if (body[0] > 1)
      return Fail(Error::kProtocol, 47);
    if (!DeriveSecret(s_app_, "traffic upd", {}, &s_app_))
      return Fail();
    receiver_ = std::make_unique<RecordCipher>(s_app_, suite_, options_.native_provider);
    receiver_->SetLimit(local_record_limit_);
    receiver_->SetContentLimit(fragment_limit_);
    // At the last permitted sending epoch, keep receiving peer updates but
    // ignore requests for an impossible sending update (RFC 9846 4.7.3).
    update_response_pending_ |= !close_sent_ && body[0] == 1 &&
        sending_epoch_ < (uint64_t{1} << 48) - 1;
    update_requested_pending_ = false;
    return true;
  }
  if (frame[0] != 4) return Fail(Error::kProtocol, 10);
  if (body.size() < 13) return Fail(Error::kProtocol, 50);
  SessionTicket ticket;
  ticket.lifetime = Read32(body.first(4u));
  ticket.age_add = Read32(body.subspan(4u, 4u));
  size_t nonce_length = body[8];
  if (nonce_length > body.size() - 11)
    return Fail(Error::kProtocol, 50);
  auto nonce = body.subspan(9u, nonce_length);
  size_t ticket_length = Read16(body.subspan(9 + nonce_length, 2u));
  if (ticket_length == 0 || ticket_length > body.size() - 11 - nonce_length)
    return Fail(Error::kProtocol, 50);
  auto identity = body.subspan(11 + nonce_length, ticket_length);
  ticket.identity.assign(identity.begin(), identity.end());
  std::map<uint16_t, Bytes> extensions;
  uint8_t extension_alert;
  if (!Extensions(body.subspan(11 + nonce_length + ticket_length), &extensions, &extension_alert))
    return Fail(Error::kProtocol, extension_alert);
  for (const auto& [type, data] : extensions) {
    if (!RequestExtensionAllowed(type, RequestExtensionContext::kNewSessionTicket))
      return Fail(Error::kProtocol, 47);
    if (type != 42)
      continue;  // NewSessionTicket is extensible; unknown well-formed values.
    if (data.size() != 4)
      return Fail(Error::kProtocol, 50);
    ticket.max_early_data = Read32(data);
  }
  if (ticket.lifetime == 0 || ticket.lifetime > 604800)
    return true;  // RFC: invalid lifetimes are ignored, not used for resumption.
  if (!DeriveSecret(resumption_, "resumption", nonce, &ticket.psk))
    return Fail();
  ticket.received_milliseconds = MonotonicMilliseconds();
  ticket.hostname = hostname_;
  ticket.certificates = certificates_;
  ticket.certificate_extensions = certificate_extensions_;
  ticket.cipher_suite = PasswordSuccessor(suite_);
  if (suite_ == 0xc0b3) ticket.max_early_data = 0;
  ticket.alpn = alpn_;
  ticket.peer_record_limit = peer_record_limit_;
  ticket.server_certificate_type = server_certificate_type_;
  ticket.client_certificate_type = client_certificate_type_;
  ticket.authentication = authentication_;
  ticket.allowed_psk_modes.clear();
  for (uint8_t mode : options_.psk_modes) {
    if (std::find(ticket.allowed_psk_modes.begin(), ticket.allowed_psk_modes.end(), mode) ==
        ticket.allowed_psk_modes.end())
      ticket.allowed_psk_modes.push_back(mode);
  }
  ticket.external_psk_binding = external_psk_binding_;
  ticket.selected_client_identity = selected_client_identity_;
  ticket.bootstrap_policy = bootstrap_policy_;
  ticket.password_context = password_context_;
  ticket.signaling_context = options_.signaling ? options_.signaling->Context() : Secret{};
  ticket.ct_policy_context = options_.ct_v2_policy ? options_.ct_v2_policy->Context() : Bytes{};
  ticket.dane_policy_context = options_.dane_policy ? options_.dane_policy->Context() : Bytes{};
  ticket.dane_expires_unix_seconds = dane_expires_unix_seconds_;
  ticket.its_policy_context = options_.its_policy ? options_.its_policy->Context() : Bytes{};
  ticket.its_expires_unix_milliseconds = its_expires_unix_milliseconds_;
  ticket.delegation = server_delegation_;
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
  if (state_ == State::kFailed || exporter_.size() != SuiteHashLength(suite_) ||
      label.size() > 249 || length > 255 * SuiteHashLength(suite_))
    return false;
  auto secret = Label(exporter_, label, Hash({}));
  *output = Label(secret, "exporter", Hash(context), length);
  OPENSSL_cleanse(secret.data(), secret.size());
  return output->size() == length;
}

bool Client::ExportEarly(std::string_view label, ByteSpan context, size_t length,
                         Bytes* output) const {
  const uint16_t suite = early_suite_;
  const size_t size = SuiteHashLength(suite);
  if (offered_psks_.empty() || retried_ || state_ == State::kFailed || closed() || close_sent_ ||
      (state_ != State::kHello && (!psk_selected_ || selected_psk_ != 0)) ||
      early_exporter_.size() != size || label.size() > 249 || length > 255 * size)
    return false;
  auto secret = SuiteLabel(suite, early_exporter_, label, SuiteHash(suite, {}, options_.native_provider.get()), size, options_.native_provider.get());
  *output = SuiteLabel(suite, secret, "exporter", SuiteHash(suite, context, options_.native_provider.get()), length, options_.native_provider.get());
  OPENSSL_cleanse(secret.data(), secret.size());
  return output->size() == length;
}

bool Client::RequestKeyUpdate(bool request_peer, Bytes* record) {
  if ((!established() && !closed()) || close_sent_)
    return false;
  if (request_peer && update_requested_pending_)
    return false;
  // RFC 9846 bounds only locally initiated sending epochs. Receiving a peer
  // update has no corresponding generation limit.
  if (sending_epoch_ == (uint64_t{1} << 48) - 1)
    return Fail();
  Bytes update;
  if (!sender_->Seal(Frame(24, Bytes{static_cast<uint8_t>(request_peer)}), 22,
                     &update) ||
      !DeriveSecret(c_app_, "traffic upd", {}, &c_app_))
    return Fail();
  sender_ = std::make_unique<RecordCipher>(c_app_, suite_, options_.native_provider);
  sender_->SetLimit(peer_record_limit_);
  sender_->SetContentLimit(fragment_limit_);
  update_response_pending_ = false;
  update_requested_pending_ |= request_peer;
  ++sending_epoch_;
  *record = TakeOutput();
  Append(record, update);
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
      return Fail(Error::kProtocol, 10);
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
  if ((state_ != State::kEstablished && state_ != State::kClosed) || close_sent_) {
    return Fail();
  }
  *record = TakeOutput();
  if (update_response_pending_ || sender_->needs_update()) {
    Bytes update;
    if (!RequestKeyUpdate(false, &update))
      return false;
    Append(record, update);
  }
  do {
    Bytes application;
    const size_t count = std::min(data.size(), max_send_content());
    const size_t multiple = options_.record_padding_multiple;
    const size_t padding = std::min((multiple - (count + 1) % multiple) % multiple,
                                    peer_record_limit_ - count - 1);
    if (!sender_->Seal(data.first(count), 23, &application, padding))
      return Fail();
    Append(record, application);
    data = data.subspan(count);
  } while (!data.empty());
  return true;
}

bool Client::RequestHeartbeat(ByteSpan payload, Bytes* record) {
  if (!established() || closed() || close_sent_ || !peer_heartbeat_mode_ ||
      *peer_heartbeat_mode_ != 1 || heartbeat_request_ ||
      payload.size() > max_send_content() - 19 ||
      payload.size() > std::min<size_t>(fragment_limit_,
          local_record_limit_ ? local_record_limit_ - 1 : 16384) - 19)
    return false;
  Bytes message{1};
  U16(&message, payload.size());
  Append(&message, payload);
  const size_t offset = message.size();
  message.resize(offset + 16);
  RAND_bytes(MutableByteSpan(message).subspan(offset).data(), 16);
  heartbeat_request_ = Bytes(payload.begin(), payload.end());
  *record = TakeOutput();
  if (update_response_pending_ || sender_->needs_update()) {
    Bytes update;
    if (!RequestKeyUpdate(false, &update))
      return false;
    Append(record, update);
  }
  Bytes request;
  if (!sender_->Seal(message, 24, &request))
    return Fail();
  Append(record, request);
  return true;
}

std::optional<Bytes> Client::TakeHeartbeatResponse() {
  return std::exchange(heartbeat_response_, std::nullopt);
}

bool Client::Close(Bytes* record) {
  if ((state_ != State::kEstablished && state_ != State::kClosed) ||
      close_sent_) {
    return false;
  }
  Bytes close;
  if (!sender_->Seal(std::array<uint8_t, 2>{1, 0}, 21, &close))
    return Fail();
  *record = TakeOutput();
  Append(record, close);
  close_sent_ = true;
  DisableAuthenticators();
  // Ciphertext already queued above precedes close_notify. No later response,
  // including a fatal alert, may use this direction again. Keep receiving keys
  // and exporter/resumption state for the still-open peer direction.
  sender_.reset();
  OPENSSL_cleanse(c_app_.data(), c_app_.size());
  c_app_.clear();
  client_credential_.reset();
  OPENSSL_cleanse(client_verifier_share_.data(), client_verifier_share_.size());
  update_response_pending_ = update_requested_pending_ = false;
  if (closed())
    EraseConnectionSecrets();  // Preserve keys only while the peer can send.
  return true;
}

}  // namespace net::httpps
