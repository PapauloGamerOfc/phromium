// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <set>
#include <ctime>

#include "net/httpps/draft01.h"
#include "net/httpps/credential_validation.h"
#include "net/httpps/certificate_features.h"
#include "net/httpps/native_provider.h"
#include "third_party/boringssl/src/include/openssl/asn1.h"
#include "third_party/boringssl/src/include/openssl/bn.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/ec.h"
#include "third_party/boringssl/src/include/openssl/ecdsa.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/rsa.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

namespace net::httpps {
namespace {

bssl::UniquePtr<X509> Parse(std::string_view der, bool require_v3 = true) {
  if (der.empty() || der.size() > 65536) {
    return nullptr;
  }
  auto* begin = reinterpret_cast<const uint8_t*>(der.data());
  auto* cursor = begin;
  bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &cursor, der.size()));
  if (!cert || static_cast<size_t>(cursor - begin) != der.size() ||
      (require_v3 && X509_get_version(cert.get()) != 2)) {
    return nullptr;
  }
  return cert;
}

bool AlgorithmSupported(X509* cert) {
  const X509_ALGOR* algorithm = nullptr;
  const ASN1_BIT_STRING* signature = nullptr;
  X509_get0_signature(&signature, &algorithm, cert);
  if (!signature || ASN1_BIT_STRING_unused_bits(signature) != 0 ||
      ASN1_STRING_length(signature) == 0) {
    return false;
  }
  const ASN1_OBJECT* oid = nullptr;
  int parameter_type = 0;
  X509_ALGOR_get0(&oid, &parameter_type, nullptr, algorithm);
  int nid = OBJ_obj2nid(oid);
  if (nid == NID_ED25519 && ASN1_STRING_length(signature) != 64) {
    return false;
  }
  if (nid == NID_ecdsa_with_SHA256) {
    const uint8_t* begin = ASN1_STRING_get0_data(signature);
    const uint8_t* cursor = begin;
    bssl::UniquePtr<ECDSA_SIG> parsed(
        d2i_ECDSA_SIG(nullptr, &cursor, ASN1_STRING_length(signature)));
    if (!parsed || cursor - begin != ASN1_STRING_length(signature) ||
        BN_is_zero(ECDSA_SIG_get0_r(parsed.get())) ||
        BN_is_negative(ECDSA_SIG_get0_r(parsed.get())) ||
        BN_num_bits(ECDSA_SIG_get0_r(parsed.get())) > 256 ||
        BN_is_zero(ECDSA_SIG_get0_s(parsed.get())) ||
        BN_is_negative(ECDSA_SIG_get0_s(parsed.get())) ||
        BN_num_bits(ECDSA_SIG_get0_s(parsed.get())) > 256) {
      return false;
    }
  }
  return (nid == NID_ED25519 || nid == NID_ecdsa_with_SHA256) &&
         parameter_type == V_ASN1_UNDEF &&
         X509_ALGOR_cmp(algorithm, X509_get0_tbs_sigalg(cert)) == 0;
}

bool ExtensionsSupported(X509* cert) {
  int count = X509_get_ext_count(cert);
  if (count > 32) {
    return false;
  }
  for (int i = 0; i < count; ++i) {
    auto* extension = X509_get_ext(cert, i);
    auto* object = X509_EXTENSION_get_object(extension);
    for (int j = 0; j < i; ++j) {
      if (OBJ_cmp(object, X509_EXTENSION_get_object(X509_get_ext(cert, j))) ==
          0) {
        return false;
      }
    }
    int nid = OBJ_obj2nid(object);
    // This is an intentionally constrained lab profile. Do not silently drop
    // policies or name constraints, even when marked non-critical.
    if (nid == NID_name_constraints || nid == NID_certificate_policies ||
        nid == NID_policy_constraints || nid == NID_inhibit_any_policy ||
        nid == NID_policy_mappings) {
      return false;
    }
    if (X509_EXTENSION_get_critical(extension) &&
        nid != NID_basic_constraints && nid != NID_key_usage &&
        nid != NID_ext_key_usage && nid != NID_subject_alt_name &&
        nid != NID_subject_key_identifier &&
        nid != NID_authority_key_identifier) {
      return false;
    }
  }
  return true;
}

bool ServerEku(X509* cert, bool required) {
  int critical = -1;
  bssl::UniquePtr<EXTENDED_KEY_USAGE> eku(static_cast<EXTENDED_KEY_USAGE*>(
      X509_get_ext_d2i(cert, NID_ext_key_usage, &critical, nullptr)));
  if (!eku) {
    return !required && critical == -1;
  }
  for (size_t i = 0; i < sk_ASN1_OBJECT_num(eku.get()); ++i) {
    if (OBJ_obj2nid(sk_ASN1_OBJECT_value(eku.get(), i)) == NID_server_auth) {
      return true;
    }
  }
  return false;
}

bool CanonicalPublicKeyEncoding(X509* cert) {
  bssl::UniquePtr<EVP_PKEY> key(X509_get_pubkey(cert));
  if (!key) {
    return false;
  }
  X509_PUBKEY* original = X509_get_X509_PUBKEY(cert);
  int encoded_length = i2d_X509_PUBKEY(original, nullptr);
  int canonical_length = i2d_PUBKEY(key.get(), nullptr);
  if (encoded_length <= 0 || encoded_length > 65536 ||
      encoded_length != canonical_length) {
    return false;
  }
  Bytes encoded(encoded_length), canonical(canonical_length);
  uint8_t* encoded_cursor = encoded.data();
  uint8_t* canonical_cursor = canonical.data();
  return i2d_X509_PUBKEY(original, &encoded_cursor) == encoded_length &&
         i2d_PUBKEY(key.get(), &canonical_cursor) == canonical_length &&
         encoded == canonical;
}

bool CommonChecks(X509* cert, bool ca, size_t ca_below = 0, bool signing_parent = false) {
  bssl::UniquePtr<BIGNUM> serial(
      ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert), nullptr));
  if (!serial || BN_is_negative(serial.get()) || BN_is_zero(serial.get()) ||
      BN_num_bits(serial.get()) > 159 || X509_get_version(cert) != 2 ||
      !ExtensionsSupported(cert) || !CanonicalPublicKeyEncoding(cert) ||
      X509_cmp_current_time(X509_get0_notBefore(cert)) >= 0 ||
      X509_cmp_current_time(X509_get0_notAfter(cert)) <= 0 ||
      X509_NAME_entry_count(X509_get_issuer_name(cert)) == 0 ||
      !ServerEku(cert, !ca)) {
    return false;
  }
  int critical = -1;
  bssl::UniquePtr<BASIC_CONSTRAINTS> constraints(
      static_cast<BASIC_CONSTRAINTS*>(
          X509_get_ext_d2i(cert, NID_basic_constraints, &critical, nullptr)));
  if (!constraints || critical != 1 || (constraints->ca != 0) != ca ||
      (!ca && constraints->pathlen)) {
    return false;
  }
  if (ca && constraints->pathlen) {
    bssl::UniquePtr<BIGNUM> path_length(
        ASN1_INTEGER_to_BN(constraints->pathlen, nullptr));
    if (!path_length || BN_is_negative(path_length.get()) ||
        (BN_num_bits(path_length.get()) <= 8 &&
         BN_get_word(path_length.get()) < ca_below)) {
      return false;
    }
  }
  if (!ca && X509_NAME_entry_count(X509_get_subject_name(cert)) == 0) {
    int san_index = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
    if (san_index < 0 ||
        !X509_EXTENSION_get_critical(X509_get_ext(cert, san_index))) {
      return false;
    }
  }
  bssl::UniquePtr<ASN1_BIT_STRING> usage(static_cast<ASN1_BIT_STRING*>(
      X509_get_ext_d2i(cert, NID_key_usage, &critical, nullptr)));
  if (!usage || critical != 1) {
    return false;
  }
  if (ca) {
    if (!ASN1_BIT_STRING_get_bit(usage.get(), 5)) {
      return false;
    }
    bssl::UniquePtr<EVP_PKEY> key(X509_get_pubkey(cert));
    if (!key || X509_NAME_entry_count(X509_get_subject_name(cert)) == 0) {
      return false;
    }
    if (EVP_PKEY_id(key.get()) == EVP_PKEY_ED25519) {
      return true;
    }
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(key.get());
    return ec && EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) ==
                     NID_X9_62_prime256v1;
  }
  // Leaf usage is exactly bit 4 (keyAgreement), including no unknown bits.
  if (signing_parent)
    return ASN1_BIT_STRING_get_bit(usage.get(), 0) == 1;
  for (int bit = 0; bit < ASN1_STRING_length(usage.get()) * 8; ++bit) {
    if (ASN1_BIT_STRING_get_bit(usage.get(), bit) != (bit == 4)) {
      return false;
    }
  }
  return ASN1_BIT_STRING_get_bit(usage.get(), 4) == 1;
}

bool VerifyOrderedIssuer(X509* cert, X509* issuer) {
  int critical = -1;
  bssl::UniquePtr<AUTHORITY_KEYID> authority(
      static_cast<AUTHORITY_KEYID*>(X509_get_ext_d2i(
          cert, NID_authority_key_identifier, &critical, nullptr)));
  if ((!authority && critical != -1) ||
      (authority && (authority->issuer || authority->serial))) {
    return false;
  }
  if (authority && authority->keyid) {
    bssl::UniquePtr<ASN1_OCTET_STRING> issuer_id(
        static_cast<ASN1_OCTET_STRING*>(X509_get_ext_d2i(
            issuer, NID_subject_key_identifier, nullptr, nullptr)));
    if (!issuer_id || ASN1_STRING_cmp(authority->keyid, issuer_id.get()) != 0) {
      return false;
    }
  }
  bssl::UniquePtr<EVP_PKEY> key(X509_get_pubkey(issuer));
  if (!key || !AlgorithmSupported(cert) ||
      X509_NAME_cmp(X509_get_issuer_name(cert),
                    X509_get_subject_name(issuer))) {
    return false;
  }
  int signature = X509_get_signature_nid(cert);
  if ((signature == NID_ED25519 &&
       EVP_PKEY_id(key.get()) != EVP_PKEY_ED25519) ||
      (signature == NID_ecdsa_with_SHA256 &&
       EVP_PKEY_id(key.get()) != EVP_PKEY_EC)) {
    return false;
  }
  return X509_verify(cert, key.get()) == 1;
}

}  // namespace

bool ExtractServerPublicKey(std::string_view leaf_der,
                            Secret* server_public_key) {
  auto leaf = Parse(leaf_der);
  if (!leaf) {
    return false;
  }
  // RFC 8410: no algorithm parameters, exactly 32 X25519 public-key octets.
  constexpr std::array<uint8_t, 12> kPrefix = {
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};
  auto* spki = X509_get_X509_PUBKEY(leaf.get());
  if (i2d_X509_PUBKEY(spki, nullptr) != 44) {
    return false;
  }
  std::array<uint8_t, 44> encoded{};
  auto* cursor = encoded.data();
  if (i2d_X509_PUBKEY(spki, &cursor) != 44 ||
      !std::equal(kPrefix.begin(), kPrefix.end(), encoded.begin())) {
    return false;
  }
  std::copy(encoded.begin() + 12, encoded.end(), server_public_key->begin());
  return true;
}

static std::optional<std::set<uint16_t>> CertificateTLSFeatures(
    std::string_view der) {
  // A validated path may include a v1 trust anchor. This helper only interprets
  // the TLSFeature extension; it does not impose the lab profile on that path.
  auto certificate = Parse(der, false);
  bssl::UniquePtr<ASN1_OBJECT> oid(OBJ_txt2obj("1.3.6.1.5.5.7.1.24", 1));
  if (!certificate || !oid)
    return std::nullopt;
  const int index = X509_get_ext_by_OBJ(certificate.get(), oid.get(), -1);
  if (index < 0)
    return std::set<uint16_t>{};
  if (X509_get_ext_by_OBJ(certificate.get(), oid.get(), index) >= 0)
    return std::nullopt;
  const auto* encoded = X509_EXTENSION_get_data(X509_get_ext(certificate.get(), index));
  CBS input, features;
  CBS_init(&input, ASN1_STRING_get0_data(encoded), ASN1_STRING_length(encoded));
  if (!CBS_get_asn1(&input, &features, CBS_ASN1_SEQUENCE) || CBS_len(&input))
    return std::nullopt;
  std::set<uint16_t> required;
  while (CBS_len(&features)) {
    uint64_t feature;
    if (!CBS_get_asn1_uint64(&features, &feature) || feature > 65535)
      return std::nullopt;
    required.insert(static_cast<uint16_t>(feature));
  }
  return required;
}

std::optional<bool> CertificateRequiresFeature(std::string_view der, uint16_t feature) {
  const auto features = CertificateTLSFeatures(der);
  if (!features)
    return std::nullopt;
  return features->contains(feature);
}

std::optional<bool> CertificateRequiresBrowserEvidence(std::string_view der,
                                                      bool offered_ocsp,
                                                      bool offered_scts) {
  const auto features = CertificateTLSFeatures(der);
  if (!features)
    return std::nullopt;
  return (offered_ocsp && features->contains(5)) ||
         (offered_scts && features->contains(18));
}

std::optional<bool> CertificateRequiresOCSP(std::string_view der) {
  return CertificateRequiresFeature(der, 5);
}

bool CertificateTLSFeaturesAllowed(
    const std::vector<std::string>& validated_path) {
  if (validated_path.empty() || validated_path.size() > kMaxCertificates + 1)
    return false;
  auto child = CertificateTLSFeatures(validated_path.front());
  if (!child)
    return false;
  for (size_t index = 1; index < validated_path.size(); ++index) {
    auto issuer = CertificateTLSFeatures(validated_path[index]);
    // RFC 7633 section 4.2.2: every subordinate certificate must preserve its
    // issuer's advertised requirements, including features unknown locally.
    // Only an independently validated, leaf-first path belongs in this check.
    if (!issuer || !std::includes(child->begin(), child->end(),
                                  issuer->begin(), issuer->end()))
      return false;
    child = std::move(issuer);
  }
  return true;
}

static bool VerifyRestrictedLabChain(const std::vector<std::string>& chain,
                    const std::vector<std::string>& anchors,
                    std::string_view hostname,
                    Secret* server_public_key, bool signing_parent) {
  if (chain.empty() || chain.size() > kMaxCertificates || anchors.empty() ||
      anchors.size() > 32 || !ValidServiceIdentity(hostname) ||
      std::set(chain.begin(), chain.end()).size() != chain.size()) {
    return false;
  }
  std::vector<bssl::UniquePtr<X509>> certificates;
  for (size_t i = 0; i < chain.size(); ++i) {
    auto cert = Parse(chain[i]);
    if (!cert || !CommonChecks(cert.get(), i != 0, i ? i - 1 : 0, signing_parent && i == 0) ||
        !AlgorithmSupported(cert.get())) {
      return false;
    }
    if (i && !VerifyOrderedIssuer(certificates.back().get(), cert.get())) {
      return false;
    }
    certificates.push_back(std::move(cert));
  }
  X509* leaf = certificates.front().get();
  // The lab profile does not let a wildcard authorize an IDNA A-label.
  // X509_check_host otherwise allows a complete-label wildcard to do so.
  unsigned host_flags = X509_CHECK_FLAG_NEVER_CHECK_SUBJECT |
                        X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
  if (hostname.starts_with("xn--")) {
    host_flags |= X509_CHECK_FLAG_NO_WILDCARDS;
  }
  const int matches = IsIpIdentity(hostname)
      ? X509_check_ip_asc(leaf, std::string(hostname).c_str(), 0)
      : X509_check_host(leaf, hostname.data(), hostname.size(), host_flags, nullptr);
  if (matches != 1) {
    return false;
  }
  // Enforce RFC 8410's absent parameters and exact X25519 SPKI, rather than
  // relying on a permissive generic key parser or accepting an RSA/ECDSA leaf.
  bssl::UniquePtr<EVP_PKEY> public_key(X509_get_pubkey(leaf));
  if (!public_key || (!signing_parent && EVP_PKEY_id(public_key.get()) != EVP_PKEY_X25519)) {
    return false;
  }
  constexpr std::array<uint8_t, 12> kX25519Prefix = {
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};
  X509_PUBKEY* spki = X509_get_X509_PUBKEY(leaf);
  int encoded_length = i2d_X509_PUBKEY(spki, nullptr);
  if (!signing_parent && encoded_length != 44) {
    return false;
  }
  std::array<uint8_t, 44> encoded{};
  uint8_t* encoded_ptr = encoded.data();
  if (!signing_parent && (i2d_X509_PUBKEY(spki, &encoded_ptr) != 44 ||
      !std::equal(kX25519Prefix.begin(), kX25519Prefix.end(),
                  encoded.begin()))) {
    return false;
  }

  // A fresh store contains ONLY the explicitly provisioned lab anchor. It has
  // no lookup callbacks and cannot fetch URLs contained in untrusted certs.
  // Try bounded anchors separately, enforcing the supplied issuer order; the
  // library then checks RFC 5280 constraints (including path length) as well.
  for (const auto& anchor_der : anchors) {
    auto anchor = Parse(anchor_der);
    bool root_in_chain = chain.back() == anchor_der;
    if (root_in_chain && chain.size() == 1) {
      continue;
    }
    size_t ca_below = certificates.size() - (root_in_chain ? 2 : 1);
    if (!anchor || !CommonChecks(anchor.get(), true, ca_below) ||
        !AlgorithmSupported(anchor.get())) {
      continue;
    }
    if ((!root_in_chain &&
         !VerifyOrderedIssuer(certificates.back().get(), anchor.get()))) {
      continue;
    }
    bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
    bssl::UniquePtr<X509_STORE_CTX> context(X509_STORE_CTX_new());
    bssl::UniquePtr<STACK_OF(X509)> intermediates(sk_X509_new_null());
    if (!store || !context || !intermediates ||
        !X509_STORE_add_cert(store.get(), anchor.get())) {
      return false;
    }
    for (size_t i = 1; i < certificates.size(); ++i) {
      if (!X509_up_ref(certificates[i].get())) {
        return false;
      }
      if (!sk_X509_push(intermediates.get(), certificates[i].get())) {
        X509_free(certificates[i].get());
        return false;
      }
    }
    if (!X509_STORE_CTX_init(context.get(), store.get(), leaf,
                             intermediates.get())) {
      return false;
    }
    auto* parameters = X509_STORE_CTX_get0_param(context.get());
    // Generic path verification: standard SSL_SERVER purpose incorrectly
    // requires digitalSignature/keyEncipherment. The TLS 2.0 static-DH leaf
    // keyAgreement-only requirement and serverAuth EKU were checked above.
    if (!X509_VERIFY_PARAM_set_purpose(parameters, X509_PURPOSE_ANY)) {
      return false;
    }
    // The separately provisioned trust anchor need not be sent in Certificate.
    // Permit the same presented-chain budget as the wire parser and selector.
    X509_VERIFY_PARAM_set_depth(parameters, static_cast<int>(kMaxCertificates));
    if (X509_verify_cert(context.get()) == 1) {
      if (!signing_parent)
        std::copy(encoded.begin() + 12, encoded.end(), server_public_key->begin());
      return true;
    }
  }
  return false;
}

bool VerifyLabChain(const std::vector<std::string>& chain,
                    const std::vector<std::string>& anchors,
                    std::string_view hostname, Secret* server_public_key,
                    bool signing_parent, const NativeProvider* provider) {
  if (VerifyRestrictedLabChain(chain, anchors, hostname, server_public_key, signing_parent))
    return true;
  return provider && !chain.empty() &&
      provider->VerifyCertificatePath(chain, anchors, hostname).has_value() &&
      (signing_parent || ExtractServerPublicKey(chain.front(), server_public_key));
}

namespace {

bool ValidateDelegationImpl(std::string_view parent_der, ByteSpan grant, bool server,
                            const std::vector<uint16_t>* algorithms, Secret* public_key,
                            const NativeProvider* provider) {
  auto parent = Parse(parent_der);
  if (!parent || grant.size() < 13)
    return false;
  auto integer = [](ByteSpan value) {
    uint32_t result = 0;
    for (uint8_t byte : value)
      result = (result << 8) | byte;
    return result;
  };
  const uint32_t valid_time = integer(grant.first(4u));
  if (integer(grant.subspan(4u, 2u)) != (server ? 0xfe00 : 0xfe01))
    return false;
  const size_t spki_size = integer(grant.subspan(6u, 3u));
  if (spki_size > grant.size() - 13 ||
      !ExtractRawPublicKey(grant.subspan(9u, spki_size), public_key))
    return false;
  const size_t cursor = 9 + spki_size;
  const uint16_t scheme = integer(grant.subspan(cursor, 2u));
  if ((algorithms && std::find(algorithms->begin(), algorithms->end(), scheme) == algorithms->end()) ||
      integer(grant.subspan(cursor + 2, 2u)) != grant.size() - cursor - 4)
    return false;
  bssl::UniquePtr<ASN1_OBJECT> usage_oid(OBJ_txt2obj("1.3.6.1.4.1.44363.44", 1));
  const int index = X509_get_ext_by_OBJ(parent.get(), usage_oid.get(), -1);
  if (index < 0 || X509_get_ext_by_OBJ(parent.get(), usage_oid.get(), index) >= 0)
    return false;
  auto* extension = X509_get_ext(parent.get(), index);
  auto* value = X509_EXTENSION_get_data(extension);
  CBS usage_encoding;
  CBS_init(&usage_encoding, ASN1_STRING_get0_data(value), ASN1_STRING_length(value));
  uint8_t usage_tag = 0;
  uint8_t usage_length = 0;
  if (X509_EXTENSION_get_critical(extension) ||
      !CBS_get_u8(&usage_encoding, &usage_tag) || usage_tag != 5 ||
      !CBS_get_u8(&usage_encoding, &usage_length) || usage_length != 0 ||
      CBS_len(&usage_encoding) != 0)
    return false;
  bssl::UniquePtr<ASN1_BIT_STRING> usage(static_cast<ASN1_BIT_STRING*>(
      X509_get_ext_d2i(parent.get(), NID_key_usage, nullptr, nullptr)));
  if (!usage || !ASN1_BIT_STRING_get_bit(usage.get(), 0))
    return false;
  int64_t before, after;
  if (!ASN1_TIME_to_posix(X509_get0_notBefore(parent.get()), &before) ||
      !ASN1_TIME_to_posix(X509_get0_notAfter(parent.get()), &after))
    return false;
  const int64_t now = std::time(nullptr), expiry = before + valid_time;
  if (now < before || now > expiry || expiry >= after || expiry - now > 604800)
    return false;
  Bytes message(64, 0x20);
  const std::string_view role = server ? "TLS20 server delegated credentials" : "TLS20 client delegated credentials";
  message.insert(message.end(), role.begin(), role.end());
  message.push_back(0);
  message.insert(message.end(), parent_der.begin(), parent_der.end());
  auto signed_grant = grant.first(cursor + 2);
  message.insert(message.end(), signed_grant.begin(), signed_grant.end());
  if (scheme == 0x0708 || (scheme >= 0x0709 && scheme <= 0x070f) ||
      scheme == 0x0808 || (scheme >= 0x0809 && scheme <= 0x080b) ||
      (scheme >= 0x081a && scheme <= 0x081c)) {
    const int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(parent.get()), nullptr);
    if (!provider || length < 1 || length > 16384)
      return false;
    Bytes spki(static_cast<size_t>(length));
    auto* encoded = spki.data();
    if (i2d_X509_PUBKEY(X509_get_X509_PUBKEY(parent.get()), &encoded) != length) return false;
    return scheme == 0x0708 ? provider->VerifySm2Signature(spki, message, grant.subspan(cursor + 4), "TLSv1.3+GM+Cipher+Suite")
        : provider->VerifyPublicSignature(spki, message, grant.subspan(cursor + 4), scheme);
  }
  bssl::UniquePtr<EVP_PKEY> key(X509_get_pubkey(parent.get()));
  if (!key)
    return false;
  const EVP_MD* digest = nullptr;
  bool pss = false;
  if (scheme == 0x0807) {
    if (EVP_PKEY_id(key.get()) != EVP_PKEY_ED25519)
      return false;
  } else if (scheme >= 0x0403 && scheme <= 0x0603 && (scheme & 255) == 3) {
    const auto* ec = EVP_PKEY_get0_EC_KEY(key.get());
    const int curve = scheme == 0x0403 ? NID_X9_62_prime256v1 : scheme == 0x0503 ? NID_secp384r1 : NID_secp521r1;
    if (!ec || EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) != curve)
      return false;
    digest = scheme == 0x0403 ? EVP_sha256() : scheme == 0x0503 ? EVP_sha384() : EVP_sha512();
  } else if (scheme >= 0x0804 && scheme <= 0x0806) {
    if (EVP_PKEY_id(key.get()) != EVP_PKEY_RSA || EVP_PKEY_bits(key.get()) < 2048)
      return false;
    digest = scheme == 0x0804 ? EVP_sha256() : scheme == 0x0805 ? EVP_sha384() : EVP_sha512();
    pss = true;
  } else {
    return false;
  }
  bssl::UniquePtr<EVP_MD_CTX> verifier(EVP_MD_CTX_new());
  EVP_PKEY_CTX* key_context = nullptr;
  if (!verifier || !EVP_DigestVerifyInit(verifier.get(), &key_context, digest, nullptr, key.get()) ||
      (pss && (!EVP_PKEY_CTX_set_rsa_padding(key_context, RSA_PKCS1_PSS_PADDING) ||
               !EVP_PKEY_CTX_set_rsa_pss_saltlen(key_context, EVP_MD_size(digest)))))
    return false;
  auto signature = grant.subspan(cursor + 4);
  return EVP_DigestVerify(verifier.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
}

}  // namespace

bool ValidateDelegation(std::string_view parent, ByteSpan grant, bool server,
                        const std::vector<uint16_t>& algorithms, Secret* public_key,
                        const NativeProvider* provider) {
  return ValidateDelegationImpl(parent, grant, server, &algorithms, public_key, provider);
}

bool ValidateLocalClientDelegation(std::string_view parent, ByteSpan grant,
                                  Secret* public_key, const NativeProvider* provider) {
  return ValidateDelegationImpl(parent, grant, false, nullptr, public_key, provider);
}

}  // namespace net::httpps
