// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/https_state.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

TEST(HttpsStateTest, HttppsUsesModernFetchStateWithoutChangingOrigin) {
  auto origin = SecurityOrigin::Create(KURL("httpps://example.test/"));
  EXPECT_EQ(HttpsState::kModern, CalculateHttpsState(origin.get()));
  EXPECT_EQ(HttpsState::kModern,
            CalculateHttpsState(origin.get(), HttpsState::kNone));
  EXPECT_EQ("httpps", origin->Protocol());
  EXPECT_FALSE(origin->IsSameOriginWith(
      SecurityOrigin::Create(KURL("https://example.test:343/")).get()));
}

TEST(HttpsStateTest, ExistingSchemesAndParentInheritanceArePreserved) {
  auto https = SecurityOrigin::Create(KURL("https://example.test/"));
  auto http = SecurityOrigin::Create(KURL("http://example.test/"));
  EXPECT_EQ(HttpsState::kModern, CalculateHttpsState(https.get()));
  EXPECT_EQ(HttpsState::kNone, CalculateHttpsState(http.get()));
  EXPECT_EQ(HttpsState::kNone, CalculateHttpsState(nullptr));
  EXPECT_EQ(HttpsState::kModern,
            CalculateHttpsState(nullptr, HttpsState::kModern));
  EXPECT_EQ(HttpsState::kNone,
            CalculateHttpsState(nullptr, HttpsState::kNone));
}

}  // namespace blink
