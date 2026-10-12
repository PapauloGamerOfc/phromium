// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/draft01.h"
#include "net/httpps/certificate_features.h"

#include <cstdlib>
#include <iostream>
#include "third_party/boringssl/src/include/openssl/asn1.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

namespace {
void Check(bool result, const char* what) {
  if (!result) {
    std::cerr << "TLSFeature failure: " << what << '\n';
    std::exit(1);
  }
}

std::string Certificate(std::optional<net::httpps::Bytes> features = std::nullopt,
                        bool duplicate = false, bool v1 = false) {
  const std::array<uint8_t, 32> seed{};
  bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
  bssl::UniquePtr<X509> certificate(X509_new());
  Check(key && certificate && X509_set_version(certificate.get(), v1 ? 0 : 2) &&
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) &&
        X509_set_pubkey(certificate.get(), key.get()), "certificate fixture");
  Check(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) &&
        X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600), "validity fixture");
  auto* name = X509_get_subject_name(certificate.get());
  constexpr uint8_t kName[] = "TLSFeature test";
  Check(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                  kName, -1, -1, 0) &&
        X509_set_issuer_name(certificate.get(), name), "name fixture");
  if (features) {
    bssl::UniquePtr<ASN1_OBJECT> oid(OBJ_txt2obj("1.3.6.1.5.5.7.1.24", 1));
    bssl::UniquePtr<ASN1_OCTET_STRING> value(ASN1_OCTET_STRING_new());
    Check(oid && value && ASN1_OCTET_STRING_set(value.get(), features->data(),
                                               features->size()), "extension fixture");
    bssl::UniquePtr<X509_EXTENSION> extension(X509_EXTENSION_create_by_OBJ(
        nullptr, oid.get(), 0, value.get()));
    Check(extension && X509_add_ext(certificate.get(), extension.get(), -1), "add extension");
    if (duplicate)
      Check(X509_add_ext(certificate.get(), extension.get(), -1), "duplicate fixture");
  }
  Check(X509_sign(certificate.get(), key.get(), nullptr) > 0, "fixture signature");
  const int length = i2d_X509(certificate.get(), nullptr);
  Check(length > 0, "fixture encoding length");
  std::string result(static_cast<size_t>(length), '\0');
  auto* encoded = reinterpret_cast<uint8_t*>(result.data());
  Check(i2d_X509(certificate.get(), &encoded) == length, "fixture encoding");
  return result;
}
}  // namespace

void TlsFeaturesTests() {
  using net::httpps::Bytes;
  using net::httpps::CertificateRequiresOCSP;
  using net::httpps::CertificateTLSFeaturesAllowed;
  const auto none = Certificate();
  const auto ocsp = Certificate(Bytes{0x30, 3, 2, 1, 5});
  const auto extra = Certificate(Bytes{0x30, 7, 2, 1, 5, 2, 2, 0x12, 0x34});
  const auto unknown = Certificate(Bytes{0x30, 4, 2, 2, 0x12, 0x34});
  const auto scts = Certificate(Bytes{0x30, 3, 2, 1, 18});
  const auto heartbeat = Certificate(Bytes{0x30, 3, 2, 1, 15});
  Check(net::httpps::CertificateFeaturesNegotiated(heartbeat, {15}, {15}), "required negotiated feature");
  Check(!net::httpps::CertificateFeaturesNegotiated(heartbeat, {15}, {43, 51}), "offered required feature absent");
  Check(net::httpps::CertificateFeaturesNegotiated(heartbeat, {43, 51}, {43, 51}), "unoffered feature ignored");
  Check(net::httpps::CertificateFeaturesNegotiated(unknown, {0x1234}, {0x1234}), "generic required feature fulfilled");
  Check(!net::httpps::CertificateFeaturesNegotiated(unknown, {0x1234}, {}), "generic offered feature cannot be ignored");
  Check(!net::httpps::CertificateFeaturesAllowEarlyData(heartbeat, {15}), "fresh negotiation precedes application bytes");
  Check(net::httpps::CertificateFeaturesAllowEarlyData(heartbeat, {43}), "unoffered feature does not disable early data");
  Check(net::httpps::CertificateFeaturesAllowEarlyData(unknown, {43}), "unknown unoffered feature does not disable early data");
  Check(net::httpps::CertificateFeaturesAllowEarlyData(ocsp, {5}), "cached evidence may authorize early data after revalidation");
  for (uint8_t feature : {25, 27})
    Check(net::httpps::CertificateFeaturesAllowEarlyData(Certificate(Bytes{0x30, 3, 2, 1, feature}), {feature}),
          "omitted certificate-flight mechanism is redundant on resumption");
  Check(net::httpps::CertificateFeaturesAllowEarlyData(Certificate(Bytes{0x30, 5, 2, 3, 0, 0xff, 2}), {0xff02}),
        "original certificate MAC is authenticated by resumption PSK");
  Check(net::httpps::CertificateRequiresFeature(scts, 18) == true, "SCT must staple");
  Check(net::httpps::CertificateRequiresBrowserEvidence(scts, true, true) == true,
        "offered SCTs require independent browser evidence");
  Check(net::httpps::CertificateRequiresBrowserEvidence(scts, true, false) == false,
        "unoffered SCT feature not imposed");
  Check(net::httpps::CertificateRequiresBrowserEvidence(ocsp, false, true) == false,
        "unoffered OCSP feature not imposed");
  Check(net::httpps::CertificateRequiresBrowserEvidence(unknown, true, true) == false,
        "unknown feature does not fabricate evidence requirements");
  Check(CertificateRequiresOCSP(none) == false, "absent optional feature");
  Check(CertificateRequiresOCSP(ocsp) == true, "must staple leaf");
  Check(CertificateRequiresOCSP(unknown) == false, "unknown feature not locally imposed");
  Check(CertificateTLSFeaturesAllowed({extra, ocsp, none}), "child adds requirements");
  Check(CertificateTLSFeaturesAllowed({extra, extra, extra}), "identical requirements");
  Check(!CertificateTLSFeaturesAllowed({none, ocsp}), "child cannot remove issuer must staple");
  Check(!CertificateTLSFeaturesAllowed({ocsp, extra}), "child cannot remove unknown issuer feature");
  Check(!CertificateTLSFeaturesAllowed({extra, none, ocsp}), "intermediate cannot remove issuer feature");
  Check(CertificateTLSFeaturesAllowed({none, Certificate(std::nullopt, false, true)}), "v1 anchor remains usable");
  Check(!CertificateTLSFeaturesAllowed({}), "empty path is not validated");
  Check(CertificateTLSFeaturesAllowed(std::vector<std::string>(65, none)),
        "64 presented certificates plus a separate anchor remain usable");
  Check(!CertificateTLSFeaturesAllowed(std::vector<std::string>(66, none)), "path count bounded");
  for (const auto& malformed : {Bytes{0x30, 3, 2, 1, 0xff},
                                Bytes{0x30, 4, 2, 2, 0, 5},
                                Bytes{0x30, 5, 2, 3, 1, 0, 0},
                                Bytes{0x30, 0, 0}, Bytes{0x31, 0}}) {
    const auto cert = Certificate(malformed);
    Check(!CertificateRequiresOCSP(cert).has_value(), "malformed feature DER");
    Check(!CertificateTLSFeaturesAllowed({none, cert}), "malformed issuer feature DER");
  }
  const auto duplicate = Certificate(Bytes{0x30, 3, 2, 1, 5}, true);
  Check(!CertificateRequiresOCSP(duplicate).has_value() &&
        !CertificateTLSFeaturesAllowed({duplicate}), "duplicate extension rejected");
  Check(!CertificateTLSFeaturesAllowed({none + "x"}), "trailing certificate DER rejected");
  std::cout << "TLSFeature inherited policy and DER tests passed\n";
}
