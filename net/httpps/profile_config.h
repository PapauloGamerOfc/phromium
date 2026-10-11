// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_HTTPPS_PROFILE_CONFIG_H_
#define NET_HTTPPS_PROFILE_CONFIG_H_

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "net/socket/ssl_client_socket.h"

namespace net::httpps {
// Trusted local configuration only. Invalid documents fail closed for HTTPPS;
// credentials are never provided to HTTPS, proxies, or unmatched partitions.
// No filesystem discovery, environment expansion, or remote loading occurs.
NET_EXPORT_PRIVATE SSLClientContext::HttppsProfileProvider
CreateProfileProvider(std::string_view json);
// Browser-startup helper: collect only explicit, absolute native library paths
// from a structurally valid trusted local snapshot, without loading any code.
// nullopt means malformed configuration; empty means no modules requested.
NET_EXPORT_PRIVATE std::optional<std::vector<std::string>>
CollectProfileLibraries(std::string_view json);
inline constexpr size_t kMaxProfileConfigBytes = 4 * 1024 * 1024;
}  // namespace net::httpps
#endif  // NET_HTTPPS_PROFILE_CONFIG_H_
