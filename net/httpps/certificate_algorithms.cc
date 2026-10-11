// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/draft01.h"

#include <algorithm>

#include "third_party/boringssl/src/include/openssl/asn1.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

namespace net::httpps {
namespace {
bssl::UniquePtr<X509> Parse(std::string_view der) {
  const auto bytes = StringBytes(der);
  auto* cursor = bytes.data();
  bssl::UniquePtr<X509> result(d2i_X509(nullptr, &cursor, bytes.size()));
  if (!result || cursor != bytes.subspan(bytes.size()).data())
    return nullptr;
  return result;
}

int DigestNid(const X509_ALGOR* algorithm) {
  if (!algorithm)
    return NID_undef;
  const ASN1_OBJECT* oid = nullptr;
  int type = V_ASN1_UNDEF;
  X509_ALGOR_get0(&oid, &type, nullptr, algorithm);
  return type == V_ASN1_UNDEF || type == V_ASN1_NULL ? OBJ_obj2nid(oid) : NID_undef;
}

uint16_t PssScheme(const X509_ALGOR* algorithm, X509* issuer) {
  int type = V_ASN1_UNDEF;
  const void* parameter = nullptr;
  X509_ALGOR_get0(nullptr, &type, &parameter, algorithm);
  if (type != V_ASN1_SEQUENCE || !parameter)
    return 0;
  const auto* encoded = static_cast<const ASN1_STRING*>(parameter);
  auto* cursor = ASN1_STRING_get0_data(encoded);
  const auto* begin = cursor;
  bssl::UniquePtr<RSA_PSS_PARAMS> params(d2i_RSA_PSS_PARAMS(
      nullptr, &cursor, ASN1_STRING_length(encoded)));
  if (!params || cursor - begin != ASN1_STRING_length(encoded))
    return 0;
  const int digest = DigestNid(params->hashAlgorithm);
  const int index = digest == NID_sha256 ? 0 : digest == NID_sha384 ? 1 : digest == NID_sha512 ? 2 : -1;
  const ASN1_OBJECT* mgf_oid = nullptr;
  const void* mgf_parameter = nullptr;
  if (index < 0 || !params->maskGenAlgorithm || !params->saltLength ||
      ASN1_INTEGER_get(params->saltLength) != (index == 0 ? 32 : index == 1 ? 48 : 64) ||
      (params->trailerField && ASN1_INTEGER_get(params->trailerField) != 1))
    return 0;
  X509_ALGOR_get0(&mgf_oid, &type, &mgf_parameter, params->maskGenAlgorithm);
  if (OBJ_obj2nid(mgf_oid) != NID_mgf1 || type != V_ASN1_SEQUENCE || !mgf_parameter)
    return 0;
  encoded = static_cast<const ASN1_STRING*>(mgf_parameter);
  cursor = ASN1_STRING_get0_data(encoded);
  begin = cursor;
  bssl::UniquePtr<X509_ALGOR> mgf_digest(d2i_X509_ALGOR(nullptr, &cursor, ASN1_STRING_length(encoded)));
  if (!mgf_digest || cursor - begin != ASN1_STRING_length(encoded) || DigestNid(mgf_digest.get()) != digest)
    return 0;
  ASN1_OBJECT* issuer_algorithm = nullptr;
  if (issuer && !X509_PUBKEY_get0_param(&issuer_algorithm, nullptr, nullptr, nullptr,
                                       X509_get_X509_PUBKEY(issuer)))
    return 0;
  // A missing issuer is resolved by the actual path verifier. The legacy RSAE
  // preference is only selection information, never an authorization decision.
  return static_cast<uint16_t>((issuer_algorithm && OBJ_obj2nid(issuer_algorithm) == NID_rsassaPss ? 0x0809 : 0x0804) + index);
}
}  // namespace

uint16_t GostPublicKeyGroup(ByteSpan spki) {
  CBS input, sequence, algorithm, key_oid, parameters, curve, digest, bits, point;
  CBS_init(&input, spki.data(), spki.size());
  if (spki.size() > 8192 || !CBS_get_asn1(&input, &sequence, CBS_ASN1_SEQUENCE) || CBS_len(&input) ||
      !CBS_get_asn1(&sequence, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&sequence, &bits, CBS_ASN1_BITSTRING) || CBS_len(&sequence) ||
      !CBS_get_asn1(&algorithm, &key_oid, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(&algorithm, &parameters, CBS_ASN1_SEQUENCE) || CBS_len(&algorithm) ||
      !CBS_get_asn1(&parameters, &curve, CBS_ASN1_OBJECT)) return 0;
  const auto oid_is = [](const CBS& encoded, const char* text) {
    bssl::UniquePtr<ASN1_OBJECT> oid(OBJ_txt2obj(text, 1));
    return oid && CBS_len(&encoded) == OBJ_length(oid.get()) &&
        CRYPTO_memcmp(CBS_data(&encoded), OBJ_get0_data(oid.get()), CBS_len(&encoded)) == 0;
  };
  uint16_t group = 0;
  bool legacy = false;
  for (uint16_t candidate = 34; candidate <= 40; ++candidate) {
    const auto name = std::string("1.2.643.7.1.2.1.") + (candidate <= 37 ? "1." : "2.") +
        std::to_string(candidate <= 37 ? candidate - 33 : candidate - 37);
    if (oid_is(curve, name.c_str())) group = candidate;
  }
  for (uint16_t candidate = 35; candidate <= 37; ++candidate) {
    const auto name = std::string("1.2.643.2.2.35.") + std::to_string(candidate - 34);
    if (oid_is(curve, name.c_str())) { group = candidate; legacy = true; }
  }
  if (!group || !oid_is(key_oid, group <= 37 ? "1.2.643.7.1.1.1.1" : "1.2.643.7.1.1.1.2")) return 0;
  const bool has_digest = CBS_len(&parameters) != 0;
  if ((legacy && !has_digest) || (!legacy && group >= 35 && group <= 37 && has_digest)) return 0;
  if (has_digest && (!CBS_get_asn1(&parameters, &digest, CBS_ASN1_OBJECT) ||
      !oid_is(digest, group <= 37 ? "1.2.643.7.1.1.2.2" : "1.2.643.7.1.1.2.3"))) return 0;
  uint8_t unused = 0;
  if (CBS_len(&parameters) || !CBS_get_u8(&bits, &unused) || unused ||
      !CBS_get_asn1(&bits, &point, CBS_ASN1_OCTETSTRING) || CBS_len(&bits) ||
      CBS_len(&point) != (group <= 37 ? 64u : 128u)) return 0;
  return group;
}

bool CertificateAlgorithmsAllowed(const std::vector<std::string>& chain,
                                  const std::vector<uint16_t>& offered) {
  if (chain.empty() || offered.empty())
    return false;
  for (size_t i = 0; i < chain.size(); ++i) {
    auto cert = Parse(chain[i]);
    auto issuer = i + 1 < chain.size() ? Parse(chain[i + 1]) : nullptr;
    if (!cert || (i + 1 < chain.size() && !issuer))
      return false;
    // The signature of a transmitted self-issued root does not validate the
    // path. Trust and its anchor exception remain the path verifier's job.
    if (i + 1 == chain.size() && X509_check_ca(cert.get()) > 0 &&
        X509_NAME_cmp(X509_get_subject_name(cert.get()), X509_get_issuer_name(cert.get())) == 0)
      continue;
    const X509_ALGOR* algorithm = nullptr;
    X509_get0_signature(nullptr, &algorithm, cert.get());
    if (!algorithm || X509_ALGOR_cmp(algorithm, X509_get0_tbs_sigalg(cert.get())) != 0)
      return false;
    uint16_t scheme = 0;
    switch (X509_get_signature_nid(cert.get())) {
      case NID_ED25519: scheme = 0x0807; break;
      case NID_ecdsa_with_SHA256: scheme = 0x0403; break;
      case NID_ecdsa_with_SHA384: scheme = 0x0503; break;
      case NID_ecdsa_with_SHA512: scheme = 0x0603; break;
      case NID_sha256WithRSAEncryption: scheme = 0x0401; break;
      case NID_sha384WithRSAEncryption: scheme = 0x0501; break;
      case NID_sha512WithRSAEncryption: scheme = 0x0601; break;
      case NID_rsassaPss: scheme = PssScheme(algorithm, issuer.get()); break;
      default: break;
    }
    if ((scheme == 0x0403 || scheme == 0x0503 || scheme == 0x0603) && issuer) {
      X509_ALGOR* issuer_algorithm = nullptr;
      if (!X509_PUBKEY_get0_param(nullptr, nullptr, nullptr, &issuer_algorithm,
                                  X509_get_X509_PUBKEY(issuer.get()))) return false;
      const ASN1_OBJECT* oid = nullptr; const void* parameter = nullptr; int type = 0;
      X509_ALGOR_get0(&oid, &type, &parameter, issuer_algorithm);
      if (OBJ_obj2nid(oid) == NID_X9_62_id_ecPublicKey && type == V_ASN1_OBJECT && parameter) {
        for (int index = 0; index < 3; ++index) {
          const std::array<const char*, 3> names = {"1.3.36.3.3.2.8.1.1.7", "1.3.36.3.3.2.8.1.1.11", "1.3.36.3.3.2.8.1.1.13"};
          bssl::UniquePtr<ASN1_OBJECT> expected(OBJ_txt2obj(names[index], 1));
          if (expected && OBJ_cmp(static_cast<const ASN1_OBJECT*>(parameter), expected.get()) == 0) {
            if (scheme != 0x0403 + index * 0x100) return false;
            scheme = static_cast<uint16_t>(0x081a + index);
          }
        }
      }
    }
    if (!scheme) {
      const ASN1_OBJECT* oid = nullptr;
      int type = 0;
      X509_ALGOR_get0(&oid, &type, nullptr, algorithm);
      bssl::UniquePtr<ASN1_OBJECT> sm2(OBJ_txt2obj("1.2.156.10197.1.501", 1));
      if (oid && sm2 && OBJ_cmp(oid, sm2.get()) == 0 && type == V_ASN1_UNDEF)
        scheme = 0x0708;
      bssl::UniquePtr<ASN1_OBJECT> ed448(OBJ_txt2obj("1.3.101.113", 1));
      if (oid && ed448 && OBJ_cmp(oid, ed448.get()) == 0 && type == V_ASN1_UNDEF) scheme = 0x0808;
      if (oid && type == V_ASN1_UNDEF && issuer) {
        const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(issuer.get()), nullptr);
        if (length < 1 || length > 8192) return false;
        Bytes spki(static_cast<size_t>(length)); auto* cursor = spki.data();
        if (i2d_X509_PUBKEY(X509_get_X509_PUBKEY(issuer.get()), &cursor) != length) return false;
        const auto group = GostPublicKeyGroup(spki);
        bssl::UniquePtr<ASN1_OBJECT> gost(OBJ_txt2obj(group <= 37 ? "1.2.643.7.1.1.3.2" : "1.2.643.7.1.1.3.3", 1));
        if (group && gost && OBJ_cmp(oid, gost.get()) == 0) scheme = 0x0709 + group - 34;
      }
    }
    if (!scheme || std::find(offered.begin(), offered.end(), scheme) == offered.end())
      return false;
  }
  return true;
}
}  // namespace net::httpps
