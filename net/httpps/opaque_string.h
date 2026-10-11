// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTPPS_OPAQUE_STRING_H_
#define NET_HTTPPS_OPAQUE_STRING_H_

#include <optional>
#include <string>
#include <string_view>

#include "net/base/net_export.h"

namespace net::httpps {

// RFC 8265 OpaqueString, used by TLS-PWD for BOTH account and password text.
// No case/width folding, trimming, bidi reordering or replacement of malformed
// UTF-8. Maps non-ASCII Zs to SPACE, applies NFC, then enforces RFC 8264 Freeform
// and all RFC 5892 context rules. Returns no partial output on rejection.
// Uses the Unicode data shipped with Chromium ICU, never the OS locale.
NET_EXPORT_PRIVATE std::optional<std::string> PrepareOpaqueString(
    std::string_view input);

}  // namespace net::httpps

#endif  // NET_HTTPPS_OPAQUE_STRING_H_
