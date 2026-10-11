// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/draft01.h"
#include "net/httpps/integrity_only.h"
#include <ctime>
#include "third_party/boringssl/src/include/openssl/digest.h"
#include "third_party/boringssl/src/include/openssl/hkdf.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net::httpps {
std::optional<ExternalPSK> BootstrapPSK(const BootstrapBinding& binding,
                                      uint16_t suite, std::string alpn) {
  Secret key;
  if (!ExtractRawPublicKey(binding.spki, &key) || !ValidServiceIdentity(binding.service) ||
      binding.scope.empty() || (binding.expires_unix_seconds &&
                               std::time(nullptr) >= binding.expires_unix_seconds) ||
      !SuiteHashLength(suite) || IntegrityTagLength(suite))
    return std::nullopt;
  auto root = Mac(Secret{}, binding.spki);
  Secret identity;
  auto label = StringBytes("tls20-bspsk-identity");
  const bool ok = HKDF_expand(identity.data(), identity.size(), EVP_sha256(),
                              root.data(), root.size(), label.data(), label.size());
  OPENSSL_cleanse(root.data(), root.size());
  if (!ok)
    return std::nullopt;
  return ImportPSK(binding.spki, identity, StringBytes("tls20-bsk"),
                    binding.service, std::move(alpn), 0x1301, suite, true);
}
}  // namespace net::httpps
