// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_HTTPPS_DNSSEC_H_
#define NET_HTTPPS_DNSSEC_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "net/httpps/portable.h"
#if defined(PHROMIUM_HTTPPS_STANDALONE)
#define HTTPPS_DNS_EXPORT
#else
#include "net/base/net_export.h"
#define HTTPPS_DNS_EXPORT NET_EXPORT_PRIVATE
#endif

namespace net::httpps {
using DNSBytes = std::vector<uint8_t>;
struct HTTPPS_DNS_EXPORT TLSAAssociation {
  uint8_t usage = 0;
  uint8_t selector = 0;
  uint8_t matching = 0;
  DNSBytes association;
};
struct HTTPPS_DNS_EXPORT DNSSECService {
  std::vector<TLSAAssociation> records;
  int64_t expires_unix_seconds = 0;
  bool authenticated_denial = false;
};

// Optional BSD-licensed getdns provider. Only its offline public validation
// API is used: no resolver, OS DNS cache, AD flag, network or default anchors.
// The application selects an absolute library path and maintains its provenance.
class HTTPPS_DNS_EXPORT DNSSECProvider {
 public:
  static std::shared_ptr<DNSSECProvider> Load(std::string_view absolute_path);
  ~DNSSECProvider();
  std::optional<DNSSECService> Validate(
      ByteSpan uncompressed_rr_chain, ByteSpan trusted_dnskey_or_ds_records,
      std::string_view hostname, uint16_t port, int64_t now,
      std::string* error = nullptr) const;
 private:
  DNSSECProvider();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

struct HTTPPS_DNS_EXPORT DANEAuthorization {
  // -1 means authenticated absence, not identity authorization. The caller
  // MUST perform its independent PKIX policy if it chooses to allow fallback.
  int usage = -1;
  int64_t expires_unix_seconds = 0;
  uint16_t support_lifetime_hours = 0;
};
struct HTTPPS_DNS_EXPORT DANEPolicy {
  std::shared_ptr<DNSSECProvider> provider;
  DNSBytes trust_anchors;
  uint16_t port = 343;
  bool allow_authenticated_denial = false;
  // A current, independently validated path, leaf first. The callback must
  // verify signatures, hostname, time, constraints and application policy.
  using PKIXValidator = std::function<std::optional<std::vector<DNSBytes>>(
      const std::vector<DNSBytes>&)>;
  // Verify a path to the DNS-authorized trust anchor, including DANE-TA rules.
  using DANEPathValidator = std::function<bool(
      const std::vector<DNSBytes>&, const DNSBytes&)>;
  PKIXValidator pkix_validator;
  DANEPathValidator dane_path_validator;
  // Caller-supplied stable identity for callbacks/trust configuration. Change
  // it on any policy change; never derive it from server-controlled bytes.
  DNSBytes application_policy_context;
  bool IsValid() const;
  DNSBytes Context() const;
  // RFC 9102 envelope: uint16 lifetime, then vector16 authentication_chain.
  // Fresh validation is mandatory even for cached certificates and 0-RTT.
  // This authorizes credential material, not proof of possession: the caller
  // still MUST validate the online MAC and Finished and honor revocation policy.
  std::optional<DANEAuthorization> Verify(
      std::string_view hostname, const std::vector<DNSBytes>& material,
      uint8_t certificate_type, ByteSpan leaf_extension, int64_t now,
      std::string* error = nullptr) const;
};
}  // namespace net::httpps
#undef HTTPPS_DNS_EXPORT
#endif
