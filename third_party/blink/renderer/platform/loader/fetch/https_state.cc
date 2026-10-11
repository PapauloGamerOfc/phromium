// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/https_state.h"

#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

HttpsState CalculateHttpsState(const SecurityOrigin* security_origin,
                               std::optional<HttpsState> parent_https_state) {
  // HTTPPS is a separate encrypted transport, but must enforce the same
  // mixed-content restrictions as HTTPS in the Fetch state machine.
  if (security_origin && (security_origin->Protocol() == "https" ||
                          security_origin->Protocol() == "httpps")) {
    return HttpsState::kModern;
  }

  if (parent_https_state && *parent_https_state != HttpsState::kNone)
    return *parent_https_state;

  return HttpsState::kNone;
}

}  // namespace blink
