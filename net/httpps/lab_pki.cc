// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <set>

#include "net/httpps/draft01.h"
#include "third_party/boringssl/src/include/openssl/asn1.h"
#include "third_party/boringssl/src/include/openssl/bn.h"
#include "third_party/boringssl/src/include/openssl/ec.h"
#include "third_party/boringssl/src/include/openssl/ecdsa.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

namespace net::httpps {
namespace {

bssl::UniquePtr<X509> Parse(std::string_view der) {
  if (der.empty() || der.size() > 65536) {
    return nullptr;
  }
  auto* begin = reinterpret_cast<const uint8_t*>(der.data());
  auto* cursor = begin;
  bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &cursor, der.size()));
  if (!cert || static_cast<size_t>(cursor - begin) != der.size() ||
      X509_get_version(cert.get()) != 2) {
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

bool CommonChecks(X509* cert, bool ca, size_t ca_below = 0) {
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

bool VerifyLabChain(const std::vector<std::string>& chain,
                    const std::vector<std::string>& anchors,
                    std::string_view hostname,
                    Secret* server_public_key) {
  if (chain.empty() || chain.size() > 8 || anchors.empty() ||
      anchors.size() > 32 || !ValidServerName(hostname) ||
      std::set(chain.begin(), chain.end()).size() != chain.size()) {
    return false;
  }
  std::vector<bssl::UniquePtr<X509>> certificates;
  for (size_t i = 0; i < chain.size(); ++i) {
    auto cert = Parse(chain[i]);
    if (!cert || !CommonChecks(cert.get(), i != 0, i ? i - 1 : 0) ||
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
  if (X509_check_host(leaf, hostname.data(), hostname.size(), host_flags,
                      nullptr) != 1) {
    return false;
  }
  // Enforce RFC 8410's absent parameters and exact X25519 SPKI, rather than
  // relying on a permissive generic key parser or accepting an RSA/ECDSA leaf.
  bssl::UniquePtr<EVP_PKEY> public_key(X509_get_pubkey(leaf));
  if (!public_key || EVP_PKEY_id(public_key.get()) != EVP_PKEY_X25519) {
    return false;
  }
  constexpr std::array<uint8_t, 12> kX25519Prefix = {
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00};
  X509_PUBKEY* spki = X509_get_X509_PUBKEY(leaf);
  int encoded_length = i2d_X509_PUBKEY(spki, nullptr);
  if (encoded_length != 44) {
    return false;
  }
  std::array<uint8_t, 44> encoded{};
  uint8_t* encoded_ptr = encoded.data();
  if (i2d_X509_PUBKEY(spki, &encoded_ptr) != 44 ||
      !std::equal(kX25519Prefix.begin(), kX25519Prefix.end(),
                  encoded.begin())) {
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
    X509_VERIFY_PARAM_set_depth(parameters, 8);
    if (X509_verify_cert(context.get()) == 1) {
      std::copy(encoded.begin() + 12, encoded.end(),
                server_public_key->begin());
      return true;
    }
  }
  return false;
}

}  // namespace net::httpps
