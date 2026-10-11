// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This standalone test checks real libpki path building, not Chrome's
// additional CT/CRLSet/root-store policy. Those remain covered by
// net_unittests.
#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"
#include "third_party/boringssl/src/pki/cert_errors.h"
#include "third_party/boringssl/src/pki/parsed_certificate.h"
#include "third_party/boringssl/src/pki/path_builder.h"
#include "third_party/boringssl/src/pki/simple_path_builder_delegate.h"
#include "third_party/boringssl/src/pki/trust_store_in_memory.h"

namespace {
void Require(bool condition, const char* description) {
  if (!condition) {
    std::cerr << "FAIL: " << description << '\n';
    std::exit(1);
  }
}

void Extension(X509* cert, int nid, const char* value) {
  bssl::UniquePtr<X509_EXTENSION> extension(
      X509V3_EXT_nconf_nid(nullptr, nullptr, nid, value));
  Require(extension && X509_add_ext(cert, extension.get(), -1),
          "create certificate extension");
}

bssl::UniquePtr<X509> Certificate(EVP_PKEY* key,
                                  X509* issuer,
                                  EVP_PKEY* signing_key,
                                  bool server_auth = true,
                                  bool excluded_name = false) {
  bssl::UniquePtr<X509> cert(X509_new());
  Require(
      cert && X509_set_version(cert.get(), 2) &&
          ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), issuer ? 2 : 1) &&
          X509_set_pubkey(cert.get(), key),
      "create certificate");
  const unsigned char* name = reinterpret_cast<const unsigned char*>(
      issuer ? "server.example" : "HTTPPS Test Root");
  Require(X509_NAME_add_entry_by_txt(X509_get_subject_name(cert.get()), "CN",
                                     MBSTRING_ASC, name, -1, -1, 0) &&
              X509_set_issuer_name(
                  cert.get(),
                  X509_get_subject_name(issuer ? issuer : cert.get())) &&
              ASN1_TIME_set_string(X509_getm_notBefore(cert.get()),
                                   "20260101000000Z") &&
              ASN1_TIME_set_string(X509_getm_notAfter(cert.get()),
                                   "20270101000000Z"),
          "create certificate names and dates");
  Extension(cert.get(), NID_basic_constraints,
            issuer ? "critical,CA:FALSE" : "critical,CA:TRUE");
  Extension(cert.get(), NID_key_usage,
            issuer ? "critical,keyAgreement" : "critical,keyCertSign,cRLSign");
  if (issuer) {
    Extension(cert.get(), NID_ext_key_usage,
              server_auth ? "serverAuth" : "clientAuth");
    Extension(cert.get(), NID_subject_alt_name, "DNS:server.example");
  } else if (excluded_name) {
    Extension(cert.get(), NID_name_constraints,
              "critical,excluded;DNS:server.example");
  }
  Require(X509_sign(cert.get(), signing_key, EVP_sha256()) > 0,
          "sign certificate");
  return cert;
}

std::shared_ptr<const bssl::ParsedCertificate> Parse(X509* cert) {
  int length = i2d_X509(cert, nullptr);
  Require(length > 0, "measure DER certificate");
  std::vector<uint8_t> der(length);
  uint8_t* cursor = der.data();
  Require(i2d_X509(cert, &cursor) == length, "encode DER certificate");
  bssl::CertErrors errors;
  auto parsed = bssl::ParsedCertificate::Create(
      bssl::UniquePtr<CRYPTO_BUFFER>(
          CRYPTO_BUFFER_new(der.data(), der.size(), nullptr)),
      {}, &errors);
  Require(parsed != nullptr, "parse DER certificate with libpki");
  return parsed;
}

// Deliberately opts in to this one generated target key. Ordinary HTTPS uses
// SimplePathBuilderDelegate's original restrictive implementation instead.
class TargetKeyDelegate : public bssl::SimplePathBuilderDelegate {
 public:
  explicit TargetKeyDelegate(EVP_PKEY* target)
      : SimplePathBuilderDelegate(2048, DigestPolicy::kStrong) {
    size_t length = key_.size();
    Require(EVP_PKEY_get_raw_public_key(target, key_.data(), &length) &&
                length == key_.size(),
            "read target public key");
  }
  bool IsPublicKeyAcceptable(EVP_PKEY* key, bssl::CertErrors* errors) override {
    if (EVP_PKEY_id(key) == EVP_PKEY_X25519) {
      std::array<uint8_t, 32> value;
      size_t length = value.size();
      return EVP_PKEY_get_raw_public_key(key, value.data(), &length) &&
             length == value.size() && value == key_;
    }
    return SimplePathBuilderDelegate::IsPublicKeyAcceptable(key, errors);
  }

 private:
  std::array<uint8_t, 32> key_;
};

bool Verify(const std::shared_ptr<const bssl::ParsedCertificate>& leaf,
            bssl::TrustStore* trust,
            bssl::CertPathBuilderDelegate* delegate,
            bool expired = false) {
  bssl::der::GeneralizedTime time{
      static_cast<uint16_t>(expired ? 2028 : 2026), 6, 1, 0, 0, 0};
  bssl::CertPathBuilder builder(leaf, trust, delegate, time,
                                bssl::KeyPurpose::SERVER_AUTH,
                                bssl::InitialExplicitPolicy::kFalse,
                                {bssl::der::Input(bssl::kAnyPolicyOid)},
                                bssl::InitialPolicyMappingInhibit::kFalse,
                                bssl::InitialAnyPolicyInhibit::kFalse);
  builder.SetIterationLimit(20);
  builder.SetDepthLimit(8);
  return builder.Run().HasValidPath();
}
}  // namespace

int main() {
  bssl::UniquePtr<EVP_PKEY> root_key(EVP_RSA_gen(2048));
  bssl::UniquePtr<EVP_PKEY> leaf_key(
      EVP_PKEY_generate_from_alg(EVP_pkey_x25519()));
  Require(root_key && leaf_key, "generate test keys");
  auto root = Certificate(root_key.get(), nullptr, root_key.get());
  auto leaf = Certificate(leaf_key.get(), root.get(), root_key.get());
  auto parsed_root = Parse(root.get());
  auto parsed_leaf = Parse(leaf.get());
  bssl::TrustStoreInMemory trust;
  trust.AddTrustAnchor(parsed_root);
  bssl::SimplePathBuilderDelegate ordinary(
      2048, bssl::SimplePathBuilderDelegate::DigestPolicy::kStrong);
  TargetKeyDelegate httpps(leaf_key.get());
  Require(Verify(parsed_leaf, &trust, &httpps),
          "SERVER_AUTH accepts X25519 keyAgreement-only leaf with opt-in");
  Require(!Verify(parsed_leaf, &trust, &ordinary),
          "same chain is rejected by ordinary HTTPS key policy");
  bssl::TrustStoreInMemory empty;
  Require(!Verify(parsed_leaf, &empty, &httpps), "unknown root rejected");
  Require(!Verify(parsed_leaf, &trust, &httpps, true), "expired leaf rejected");
  auto wrong_eku =
      Certificate(leaf_key.get(), root.get(), root_key.get(), false);
  Require(!Verify(Parse(wrong_eku.get()), &trust, &httpps),
          "clientAuth-only EKU rejected");
  const auto root_spki = parsed_root->tbs().spki_tlv;
  trust.AddDistrustedCertificateBySPKI(std::string(
      reinterpret_cast<const char*>(root_spki.data()), root_spki.size()));
  Require(!Verify(parsed_leaf, &trust, &httpps), "distrusted root rejected");
  auto constrained_root =
      Certificate(root_key.get(), nullptr, root_key.get(), true, true);
  bssl::TrustStoreInMemory constrained_trust;
  constrained_trust.AddTrustAnchorWithConstraints(
      Parse(constrained_root.get()));
  Require(!Verify(parsed_leaf, &constrained_trust, &httpps),
          "anchor name constraints rejected excluded DNS name");
  std::cout << "HTTPPS libpki path-building tests passed\n";
}
