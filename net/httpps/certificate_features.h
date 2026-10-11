// Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
#ifndef NET_HTTPPS_CERTIFICATE_FEATURES_H_
#define NET_HTTPPS_CERTIFICATE_FEATURES_H_

#include <optional>
#include <string_view>
#include <cstdint>

namespace net::httpps {
// A malformed extension is an error; unsupported/unoffered features are not
// silently reinterpreted as requirements for unrelated protocols.
std::optional<bool> CertificateRequiresFeature(std::string_view der,
                                              uint16_t feature);
std::optional<bool> CertificateRequiresBrowserEvidence(std::string_view der,
                                                      bool offered_ocsp,
                                                      bool offered_scts);
}  // namespace net::httpps
#endif
