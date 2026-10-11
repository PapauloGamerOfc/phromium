// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/transparency.h"

#include <algorithm>
#include <set>
#include <utility>

#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/crypto.h"
#include "third_party/boringssl/src/include/openssl/ec.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/rsa.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

namespace net::httpps {
namespace {
constexpr uint8_t kCTOid[] = {0x2b, 0x65, 0x4b};
constexpr uint8_t kSctOid[] = {0x2b,0x06,0x01,0x04,0x01,0xd6,0x79,0x02,0x04,0x02};
constexpr uint8_t kBasicOcspOid[] = {0x2b,0x06,0x01,0x05,0x05,0x07,0x30,0x01,0x01};
constexpr size_t kMaxItems = 256;
constexpr size_t kMaxCertificate = 1024 * 1024;
constexpr unsigned kContext = CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED;

ByteSpan View(const CBS& value) {
  return ByteSpan(static_cast<bssl::Span<const uint8_t>>(value));
}
CBS Reader(ByteSpan data) { CBS cbs; CBS_init(&cbs, data.data(), data.size()); return cbs; }
CTBytes Copy(ByteSpan data) { return CTBytes(data.begin(), data.end()); }
bool Equal(ByteSpan a, ByteSpan b) {
  return a.size() == b.size() && (a.empty() || CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0);
}
void Append(CTBytes& out, ByteSpan data) { out.insert(out.end(), data.begin(), data.end()); }
void Number(CTBytes& out, uint64_t value, size_t width) {
  for (size_t i = width; i; --i) out.push_back(static_cast<uint8_t>(value >> ((i - 1) * 8)));
}
void Vector(CTBytes& out, ByteSpan data, size_t width) { Number(out, data.size(), width); Append(out, data); }
CTBytes DER(uint8_t tag, ByteSpan value) {
  CTBytes result{tag};
  if (value.size() < 128) result.push_back(static_cast<uint8_t>(value.size()));
  else {
    size_t width = 0;
    for (auto size = value.size(); size; size >>= 8) ++width;
    result.push_back(static_cast<uint8_t>(128 + width)); Number(result, value.size(), width);
  }
  Append(result, value); return result;
}
const EVP_MD* Digest(CTHash hash) {
  switch (hash) {
    case CTHash::kSHA256: return EVP_sha256();
    case CTHash::kSHA384: return EVP_sha384();
    case CTHash::kSHA512: return EVP_sha512();
  }
  return nullptr;
}
CTBytes Hash(CTHash hash, ByteSpan data) {
  const auto* md = Digest(hash);
  if (!md) return {};
  CTBytes result(EVP_MD_size(md)); unsigned size = 0;
  if (!EVP_Digest(data.data(), data.size(), result.data(), &size, md, nullptr) || size != result.size()) return {};
  return result;
}
CTBytes Node(CTHash hash, ByteSpan left, ByteSpan right) {
  CTBytes data{1}; Append(data, left); Append(data, right); return Hash(hash, data);
}
bool OidValid(ByteSpan oid) {
  if (oid.size() < 2 || oid.size() > 127) return false;
  bool first = true;
  for (auto byte : oid) {
    if (first && byte == 0x80) return false;
    first = !(byte & 0x80);
  }
  return first;
}
struct LogKey {
  bssl::UniquePtr<EVP_PKEY> key;
  std::optional<CTHash> digest;
  bool pss = false;
};
LogKey ParseKey(const CTLog& log) {
  LogKey result;
  if (log.public_key_spki.empty() || log.public_key_spki.size() > 8192) return result;
  auto input = Reader(log.public_key_spki);
  result.key.reset(EVP_parse_public_key(&input));
  if (!result.key || CBS_len(&input)) { result.key.reset(); return result; }
  const int type = EVP_PKEY_id(result.key.get());
  bool valid = false;
  if (log.signature_scheme == 0x0807) valid = type == EVP_PKEY_ED25519;
  else if (log.signature_scheme == 0x0403 || log.signature_scheme == 0x0503 || log.signature_scheme == 0x0603) {
    const auto* key = EVP_PKEY_get0_EC_KEY(result.key.get());
    const auto scheme = log.signature_scheme;
    const int curve = scheme == 0x0403 ? NID_X9_62_prime256v1 : scheme == 0x0503 ? NID_secp384r1 : NID_secp521r1;
    valid = key && EC_GROUP_get_curve_name(EC_KEY_get0_group(key)) == curve;
    result.digest = scheme == 0x0403 ? CTHash::kSHA256 : scheme == 0x0503 ? CTHash::kSHA384 : CTHash::kSHA512;
  } else if (log.signature_scheme >= 0x0804 && log.signature_scheme <= 0x0806) {
    valid = type == EVP_PKEY_RSA && EVP_PKEY_bits(result.key.get()) >= 2048;
    result.pss = true;
    result.digest = log.signature_scheme == 0x0804 ? CTHash::kSHA256 : log.signature_scheme == 0x0805 ? CTHash::kSHA384 : CTHash::kSHA512;
  }
  if (!valid) result.key.reset();
  return result;
}
bool VerifySignature(const LogKey& key, ByteSpan signature, ByteSpan data) {
  const auto* digest = key.digest ? Digest(*key.digest) : nullptr;
  bssl::UniquePtr<EVP_MD_CTX> context(EVP_MD_CTX_new()); EVP_PKEY_CTX* pkey_context = nullptr;
  if (!key.key || !context || signature.empty() ||
      !EVP_DigestVerifyInit(context.get(), &pkey_context, digest, nullptr, key.key.get()) ||
      (key.pss && (!EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_PSS_PADDING) ||
                   !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_context, EVP_MD_size(digest)) ||
                   !EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_context, digest)))) return false;
  return EVP_DigestVerify(context.get(), signature.data(), signature.size(), data.data(), data.size()) == 1;
}
bool Timestamp(const CTLog& log, uint64_t time, uint64_t now) {
  return time >= log.valid_from_ms && time <= log.valid_until_ms && time <= now;
}
bool Extensions(CBS input) {
  int previous = -1; uint16_t type; CBS value;
  while (CBS_len(&input)) {
    if (!CBS_get_u16(&input, &type) || type <= previous || !CBS_get_u16_length_prefixed(&input, &value)) return false;
    previous = type;
  }
  return true;
}
bool Path(CBS input, size_t width, std::vector<CTBytes>* result) {
  while (CBS_len(&input)) {
    CBS node;
    if (result->size() == 64 || !CBS_get_u8_length_prefixed(&input, &node) || CBS_len(&node) != width) return false;
    result->push_back(Copy(View(node)));
  }
  return true;
}
bool Items(ByteSpan data, bool embedded, std::vector<CTBytes>* result) {
  if (data.empty()) return true;
  auto input = Reader(data); CBS list;
  if (data.size() > 65537 || !CBS_get_u16_length_prefixed(&input, &list) || CBS_len(&input) || !CBS_len(&list)) return false;
  while (CBS_len(&list)) {
    CBS item;
    if (result->size() == kMaxItems || !CBS_get_u16_length_prefixed(&list, &item) || CBS_len(&item) < 2) return false;
    if (embedded) {
      auto check = item; uint16_t kind;
      if (!CBS_get_u16(&check, &kind) || kind == 0x0102) return false;
    }
    result->push_back(Copy(View(item)));
  }
  return true;
}
// Reads a strict Extensions SEQUENCE payload. CT data is itself an ASN.1
// OCTET STRING inside extnValue, not a raw TLS vector.
bool Embedded(CBS extensions, CTBytes* result, CTBytes* kept = nullptr) {
  std::set<CTBytes> seen;
  while (CBS_len(&extensions)) {
    CBS raw, ext, oid, value;
    if (!CBS_get_asn1_element(&extensions, &raw, CBS_ASN1_SEQUENCE)) return false;
    auto input = raw;
    if (!CBS_get_asn1(&input, &ext, CBS_ASN1_SEQUENCE) || !CBS_get_asn1(&ext, &oid, CBS_ASN1_OBJECT) ||
        !seen.insert(Copy(View(oid))).second) return false;
    int critical = 0;
    if ((CBS_peek_asn1_tag(&ext, CBS_ASN1_BOOLEAN) && !CBS_get_asn1_bool(&ext, &critical)) ||
        !CBS_get_asn1(&ext, &value, CBS_ASN1_OCTETSTRING) || CBS_len(&ext)) return false;
    if (Equal(View(oid), kCTOid)) {
      CBS wrapped;
      if (!CBS_get_asn1(&value, &wrapped, CBS_ASN1_OCTETSTRING) || CBS_len(&value) || !result->empty()) return false;
      *result = Copy(View(wrapped));
    }
    if (kept && !Equal(View(oid), kCTOid) && !Equal(View(oid), kSctOid)) Append(*kept, View(raw));
  }
  return true;
}
struct CertificateData {
  bssl::UniquePtr<X509> parsed;
  CTBytes tbs, precert, evidence, spki;
};
bool Certificate(ByteSpan der, CertificateData* result) {
  if (der.empty() || der.size() > kMaxCertificate) return false;
  auto input = Reader(der); CBS envelope, tbs;
  if (!CBS_get_asn1(&input, &envelope, CBS_ASN1_SEQUENCE) || CBS_len(&input) ||
      !CBS_get_asn1_element(&envelope, &tbs, CBS_ASN1_SEQUENCE)) return false;
  result->tbs = Copy(View(tbs)); input = tbs;
  if (!CBS_get_asn1(&input, &tbs, CBS_ASN1_SEQUENCE)) return false;
  CTBytes clean; bool saw_extensions = false;
  while (CBS_len(&tbs)) {
    CBS raw; unsigned tag;
    if (!CBS_get_any_asn1_element(&tbs, &raw, &tag, nullptr)) return false;
    if (tag != (CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 3)) { Append(clean, View(raw)); continue; }
    if (saw_extensions) return false;
    saw_extensions = true; CBS body, extensions; auto outer = raw;
    CTBytes kept;
    if (!CBS_get_asn1(&outer, &body, tag) || !CBS_get_asn1(&body, &extensions, CBS_ASN1_SEQUENCE) ||
        CBS_len(&body) || !Embedded(extensions, &result->evidence, &kept)) return false;
    if (!kept.empty()) Append(clean, DER(0xa3, DER(0x30, kept)));
  }
  result->precert = DER(0x30, clean);
  const auto* cursor = der.data();
  result->parsed.reset(d2i_X509(nullptr, &cursor, der.size()));
  if (!result->parsed || cursor != der.subspan(der.size()).data()) return false;
  auto* pub = X509_get_X509_PUBKEY(result->parsed.get());
  const int size = i2d_X509_PUBKEY(pub, nullptr);
  if (size <= 0 || size > 8192) return false;
  result->spki.resize(size); auto* target = result->spki.data();
  return i2d_X509_PUBKEY(pub, &target) == size;
}
CTBytes NameDER(X509_NAME* name) {
  const int size = i2d_X509_NAME(name, nullptr);
  if (size <= 0 || size > static_cast<int>(kMaxCertificate)) return {};
  CTBytes result(size); auto* target = result.data();
  return i2d_X509_NAME(name, &target) == size ? result : CTBytes{};
}
bool OcspSources(ByteSpan der, const CertificateData& certificate,
                 const CertificateData& issuer, std::vector<CTBytes>* items) {
  if (der.empty()) return true;
  if (der.size() > kMaxCertificate) return false;
  auto input = Reader(der); CBS envelope, status, explicit_response, response, oid, encoded, basic, tbs;
  if (!CBS_get_asn1(&input, &envelope, CBS_ASN1_SEQUENCE) || CBS_len(&input) ||
      !CBS_get_asn1(&envelope, &status, CBS_ASN1_ENUMERATED) || !Equal(View(status), CTBytes{0}) ||
      !CBS_get_asn1(&envelope, &explicit_response, kContext) || CBS_len(&envelope) ||
      !CBS_get_asn1(&explicit_response, &response, CBS_ASN1_SEQUENCE) || CBS_len(&explicit_response) ||
      !CBS_get_asn1(&response, &oid, CBS_ASN1_OBJECT) || !Equal(View(oid), kBasicOcspOid) ||
      !CBS_get_asn1(&response, &encoded, CBS_ASN1_OCTETSTRING) || CBS_len(&response) ||
      !CBS_get_asn1(&encoded, &basic, CBS_ASN1_SEQUENCE) || CBS_len(&encoded) ||
      !CBS_get_asn1(&basic, &tbs, CBS_ASN1_SEQUENCE)) return false;
  if (CBS_peek_asn1_tag(&tbs, kContext)) { CBS version; if (!CBS_get_asn1(&tbs, &version, kContext)) return false; }
  CBS responder, time, responses; unsigned tag;
  if (!CBS_get_any_asn1(&tbs, &responder, &tag) || (tag != (kContext | 1) && tag != (kContext | 2)) ||
      !CBS_get_asn1(&tbs, &time, CBS_ASN1_GENERALIZEDTIME) || !CBS_get_asn1(&tbs, &responses, CBS_ASN1_SEQUENCE)) return false;
  // Match CertID using its declared standard hash, independent of CT's log hash.
  size_t count = 0;
  while (CBS_len(&responses)) {
    CBS single, cert_id, algorithm, name_hash, key_hash, serial;
    if (++count > kMaxItems || !CBS_get_asn1(&responses, &single, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&single, &cert_id, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1_element(&cert_id, &algorithm, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&cert_id, &name_hash, CBS_ASN1_OCTETSTRING) ||
        !CBS_get_asn1(&cert_id, &key_hash, CBS_ASN1_OCTETSTRING) ||
        !CBS_get_asn1_element(&cert_id, &serial, CBS_ASN1_INTEGER) || CBS_len(&cert_id)) return false;
    const auto* digest = EVP_parse_digest_algorithm(&algorithm);
    if (!digest || CBS_len(&algorithm)) continue;
    const ASN1_INTEGER* leaf_serial = X509_get0_serialNumber(certificate.parsed.get());
    const int serial_size = i2d_ASN1_INTEGER(leaf_serial, nullptr);
    if (serial_size <= 0) return false;
    CTBytes expected_serial(serial_size); auto* target = expected_serial.data();
    if (i2d_ASN1_INTEGER(leaf_serial, &target) != serial_size) return false;
    auto spki_input = Reader(issuer.spki); CBS spki, skip, bits;
    if (!CBS_get_asn1(&spki_input, &spki, CBS_ASN1_SEQUENCE) || !CBS_get_asn1(&spki, &skip, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&spki, &bits, CBS_ASN1_BITSTRING) || !CBS_skip(&bits, 1)) return false;
    auto issuer_name = NameDER(X509_get_subject_name(issuer.parsed.get()));
    CTBytes expected_name(EVP_MD_size(digest)), expected_key(EVP_MD_size(digest)); unsigned width;
    if (!EVP_Digest(issuer_name.data(), issuer_name.size(), expected_name.data(), &width, digest, nullptr) ||
        !EVP_Digest(CBS_data(&bits), CBS_len(&bits), expected_key.data(), &width, digest, nullptr)) return false;
    if (!Equal(View(serial), expected_serial) || !Equal(View(name_hash), expected_name) || !Equal(View(key_hash), expected_key)) continue;
    while (CBS_len(&single)) {
      CBS body;
      if (!CBS_get_any_asn1(&single, &body, &tag)) return false;
      if (tag != (kContext | 1)) continue;
      CBS extensions; CTBytes evidence;
      if (!CBS_get_asn1(&body, &extensions, CBS_ASN1_SEQUENCE) || CBS_len(&body) ||
          !Embedded(extensions, &evidence) || !Items(evidence, false, items)) return false;
    }
  }
  return true;
}
std::optional<bool> RequiredTlsFeature(X509* certificate, uint64_t feature) {
  bssl::UniquePtr<ASN1_OBJECT> oid(OBJ_txt2obj("1.3.6.1.5.5.7.1.24", 1));
  const int index = X509_get_ext_by_OBJ(certificate, oid.get(), -1);
  if (index < 0) return false;
  if (X509_get_ext_by_OBJ(certificate, oid.get(), index) >= 0) return std::nullopt;
  const auto* value = X509_EXTENSION_get_data(X509_get_ext(certificate, index));
  CBS input, features;
  CBS_init(&input, ASN1_STRING_get0_data(value), ASN1_STRING_length(value));
  if (!CBS_get_asn1(&input, &features, CBS_ASN1_SEQUENCE) || CBS_len(&input)) return std::nullopt;
  bool required = false;
  while (CBS_len(&features)) {
    uint64_t current;
    if (!CBS_get_asn1_uint64(&features, &current) || current > UINT16_MAX) return std::nullopt;
    // Unknown/unoffered features do not create new client requirements.
    required |= current == feature;
  }
  return required;
}
}  // namespace

bool VerifyCTInclusion(CTHash hash, ByteSpan leaf, uint64_t index, uint64_t size,
                       const std::vector<CTBytes>& path, ByteSpan root) {
  const auto* digest = Digest(hash);
  if (!digest || index >= size || leaf.size() != EVP_MD_size(digest) || root.size() != leaf.size() || path.size() > 64) return false;
  uint64_t last = size - 1; auto value = Copy(leaf);
  for (const auto& sibling : path) {
    if (!last || sibling.size() != leaf.size()) return false;
    if ((index & 1) || index == last) {
      value = Node(hash, sibling, value);
      while (index && !(index & 1)) { index >>= 1; last >>= 1; }
    } else value = Node(hash, value, sibling);
    index >>= 1; last >>= 1;
  }
  return !last && Equal(value, root);
}

bool VerifyCTConsistency(CTHash hash, uint64_t old_size, uint64_t new_size,
                         ByteSpan old_root, ByteSpan new_root,
                         const std::vector<CTBytes>& path) {
  const auto* digest = Digest(hash);
  if (!digest || old_size > new_size || old_root.size() != EVP_MD_size(digest) ||
      new_root.size() != old_root.size() || path.size() > 64 ||
      std::any_of(path.begin(), path.end(), [&](const auto& p) { return p.size() != old_root.size(); })) return false;
  if (!old_size) return path.empty() && Equal(old_root, Hash(hash, {}));
  if (old_size == new_size) return path.empty() && Equal(old_root, new_root);
  uint64_t first = old_size - 1, second = new_size - 1;
  while (first & 1) { first >>= 1; second >>= 1; }
  size_t offset = 0; auto old_value = Copy(old_root);
  if (first) { if (path.empty()) return false; old_value = path[offset++]; }
  auto new_value = old_value;
  for (; offset < path.size(); ++offset) {
    if (!second) return false;
    if ((first & 1) || first == second) {
      old_value = Node(hash, path[offset], old_value); new_value = Node(hash, path[offset], new_value);
      while (first && !(first & 1)) { first >>= 1; second >>= 1; }
    } else new_value = Node(hash, new_value, path[offset]);
    first >>= 1; second >>= 1;
  }
  return !second && Equal(old_value, old_root) && Equal(new_value, new_root);
}

bool CTv2Policy::IsValid() const {
  if (logs.empty() || logs.size() > 64 || !minimum_logs || minimum_logs > logs.size() || trusted_tree_heads.size() > logs.size()) return false;
  std::set<CTBytes> ids;
  for (const auto& log : logs) {
    if (!OidValid(log.id) || !ids.insert(log.id).second || !Digest(log.hash) ||
        log.valid_from_ms >= log.valid_until_ms || !log.maximum_merge_delay_seconds ||
        log.maximum_merge_delay_seconds > UINT64_MAX / 1000 || !ParseKey(log).key) return false;
  }
  for (const auto& [id, head] : trusted_tree_heads) {
    auto log = std::find_if(logs.begin(), logs.end(), [&](const auto& l) { return l.id == id; });
    if (log == logs.end() || head.root.size() != EVP_MD_size(Digest(log->hash)) ||
        !Timestamp(*log, head.timestamp_ms, UINT64_MAX) || (!head.size && !Equal(head.root, Hash(log->hash, {})))) return false;
  }
  return true;
}

CTBytes CTv2Policy::Context() const {
  if (!IsValid()) return {};
  CTBytes value; Append(value, StringBytes("HTTPPS CTv2 explicit policy"));
  Number(value, minimum_logs, 8); Number(value, require_inclusion, 1); Number(value, require_inclusion_after_mmd, 1);
  Number(value, logs.size(), 2);
  for (const auto& log : logs) {
    Vector(value, log.id, 1); Vector(value, log.public_key_spki, 2);
    Number(value, log.signature_scheme, 2); Number(value, static_cast<uint8_t>(log.hash), 1);
    Number(value, log.valid_from_ms, 8); Number(value, log.valid_until_ms, 8); Number(value, log.maximum_merge_delay_seconds, 8);
  }
  Number(value, trusted_tree_heads.size(), 2);
  for (const auto& [id, head] : trusted_tree_heads) {
    Vector(value, id, 1); Number(value, head.size, 8); Number(value, head.timestamp_ms, 8); Vector(value, head.root, 1);
  }
  return Hash(CTHash::kSHA256, value);
}

std::optional<std::vector<CTVerifiedSCT>> CTv2Policy::Verify(ByteSpan certificate_der,
    ByteSpan issuer_der, ByteSpan tls_evidence, ByteSpan stapled_ocsp_der,
    uint64_t now_ms, std::string* error) const {
  auto fail = [&](const char* message) -> std::optional<std::vector<CTVerifiedSCT>> {
    if (error) *error = message; return std::nullopt;
  };
  if (error) error->clear();
  if (!IsValid()) return fail("invalid explicit CTv2 policy");
  CertificateData certificate, issuer;
  std::vector<CTBytes> items;
  if (!Certificate(certificate_der, &certificate) || !Certificate(issuer_der, &issuer) ||
      !Items(tls_evidence, false, &items)) return fail("invalid CT evidence carrier");
  const size_t tls_item_count = items.size();
  if (!Items(certificate.evidence, true, &items) ||
      !OcspSources(stapled_ocsp_der, certificate, issuer, &items)) return fail("invalid CT evidence carrier");
  const auto required_feature = RequiredTlsFeature(certificate.parsed.get(), 52);
  if (!required_feature || (*required_feature && tls_evidence.empty())) return fail("required transparency_info staple absent");
  std::map<CTBytes, const CTLog*> trusted; std::map<CTBytes, LogKey> keys;
  for (const auto& log : logs) { trusted[log.id] = &log; keys.emplace(log.id, ParseKey(log)); }
  using HeadKey = std::pair<CTBytes, uint64_t>;
  std::map<HeadKey, CTTreeHead> heads;
  struct Proof { CTBytes id; uint64_t first, second; std::vector<CTBytes> path; };
  std::vector<Proof> inclusions, consistencies;
  std::vector<CTVerifiedSCT> scts;
  bool verified_tls_sct = false;
  for (size_t index = 0; index < items.size(); ++index) {
    const auto& item = items[index];
    auto input = Reader(item); uint16_t kind; CBS id;
    if (!CBS_get_u16(&input, &kind)) return fail("truncated TransItem");
    if (kind < 0x0102 || kind > 0x0106) continue;
    if (!CBS_get_u8_length_prefixed(&input, &id) || !OidValid(View(id))) return fail("invalid log OID");
    auto identity = Copy(View(id)); auto found = trusted.find(identity);
    if (found == trusted.end()) continue;  // Peer input never provisions trust.
    const auto& log = *found->second; const size_t width = EVP_MD_size(Digest(log.hash));
    if (kind == 0x0102 || kind == 0x0103) {
      uint64_t time; CBS extensions, signature;
      if (!CBS_get_u64(&input, &time) || !CBS_get_u16_length_prefixed(&input, &extensions) || !Extensions(extensions) ||
          !CBS_get_u16_length_prefixed(&input, &signature) || CBS_len(&input) || !Timestamp(log, time, now_ms)) return fail("invalid SCT framing/time");
      CTBytes signed_entry; Number(signed_entry, kind - 2, 2); Number(signed_entry, time, 8);
      Vector(signed_entry, Hash(log.hash, issuer.spki), 1);
      Vector(signed_entry, kind == 0x0102 ? certificate.tbs : certificate.precert, 3); Vector(signed_entry, View(extensions), 2);
      if (!VerifySignature(keys.at(identity), View(signature), signed_entry)) return fail("invalid SCT signature");
      CTBytes leaf{0}; Append(leaf, signed_entry);
      scts.push_back({identity, time, Hash(log.hash, leaf), false});
      verified_tls_sct |= index < tls_item_count;
    } else if (kind == 0x0104) {
      const auto start = View(input); CTTreeHead head; CBS root, extensions, signature;
      if (!CBS_get_u64(&input, &head.timestamp_ms) || !CBS_get_u64(&input, &head.size) ||
          !CBS_get_u8_length_prefixed(&input, &root) || CBS_len(&root) != width ||
          !CBS_get_u16_length_prefixed(&input, &extensions) || !Extensions(extensions) ||
          !Timestamp(log, head.timestamp_ms, now_ms)) return fail("invalid STH framing/time");
      const auto signed_part = start.first(start.size() - CBS_len(&input));
      if (!CBS_get_u16_length_prefixed(&input, &signature) || CBS_len(&input) ||
          !VerifySignature(keys.at(identity), View(signature), signed_part)) return fail("invalid STH signature");
      head.root = Copy(View(root)); auto key = HeadKey{identity, head.size}; auto previous = heads.find(key);
      if (previous != heads.end() && previous->second.root != head.root) return fail("conflicting signed tree roots");
      // Preserve the newest signed timestamp for a root, independently of order.
      if (previous == heads.end() || previous->second.timestamp_ms < head.timestamp_ms) heads[key] = std::move(head);
    } else {
      Proof proof{identity, 0, 0, {}}; CBS path;
      if (!CBS_get_u64(&input, &proof.first) || !CBS_get_u64(&input, &proof.second) ||
          !CBS_get_u16_length_prefixed(&input, &path) || CBS_len(&input) || !Path(path, width, &proof.path)) return fail("invalid Merkle proof framing");
      (kind == 0x0106 ? inclusions : consistencies).push_back(std::move(proof));
    }
  }
  // Embedded/OCSP evidence may contribute log votes, but cannot satisfy an
  // offered TLSFeature52 requirement for verified evidence in the TLS staple.
  if (*required_feature && !verified_tls_sct)
    return fail("required transparency_info staple has no verified SCT");
  for (const auto& [key, head] : heads) {
    const auto previous = trusted_tree_heads.find(key.first);
    if (previous == trusted_tree_heads.end()) continue;
    const auto& old = previous->second;
    if (old.size > head.size || old.timestamp_ms > head.timestamp_ms) return fail("signed tree rollback");
    const auto hash = trusted.at(key.first)->hash;
    bool valid = VerifyCTConsistency(hash, old.size, head.size, old.root, head.root, {});
    for (const auto& proof : consistencies)
      if (proof.id == key.first && proof.first == old.size && proof.second == head.size &&
          VerifyCTConsistency(hash, old.size, head.size, old.root, head.root, proof.path)) valid = true;
    if (!valid) return fail("missing append-only consistency proof");
  }
  std::set<CTBytes> votes;
  for (auto& sct : scts) {
    const auto& log = *trusted.at(sct.log_id);
    for (const auto& proof : inclusions) {
      auto head = heads.find({proof.id, proof.first});
      if (proof.id == sct.log_id && head != heads.end() && head->second.timestamp_ms >= sct.timestamp_ms &&
          VerifyCTInclusion(log.hash, sct.leaf_hash, proof.second, proof.first, proof.path, head->second.root)) sct.included = true;
    }
    if ((require_inclusion || (require_inclusion_after_mmd && now_ms - sct.timestamp_ms > log.maximum_merge_delay_seconds * 1000)) && !sct.included)
      return fail("required inclusion proof absent");
    votes.insert(sct.log_id);
  }
  if (votes.size() < minimum_logs) return fail("insufficient distinct trusted logs");
  return scts;
}
}  // namespace net::httpps
