// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/public/cpp/url_util.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace network {

TEST(URLUtilTest, IsURLHandledByNetworkServiceIncludesHttpps) {
  const struct {
    const char* url;
    bool handled;
  } kTestCases[] = {
      {"http://example.com/", true},
      {"https://example.com/", true},
      {"httpps://example.com/", true},
      {"HTTPPS://example.com:343/", true},
      {"httpps://example.com:8443/path", true},
      {"ws://example.com/", true},
      {"wss://example.com/", true},
      {"file:///tmp/example.html", false},
      {"blob:httpps://example.com/uuid", false},
      {"data:text/html,example", false},
      {"about:blank", false},
      {"chrome://version/", false},
      {"ftp://example.com/", false},
      {"httpps-other://example.com/", false},
      {"custom://example.com/", false},
      {"", false},
  };

  // Navigation and download routing use this helper to select the network
  // factory. HTTPPS must not fall through to external protocol handling, while
  // local resources and unsupported schemes still need their own factories.
  for (const auto& test_case : kTestCases) {
    SCOPED_TRACE(test_case.url);
    EXPECT_EQ(test_case.handled,
              IsURLHandledByNetworkService(GURL(test_case.url)));
  }
}

TEST(URLUtilTest, SerializeResponseUrlForReporting) {
  struct {
    const char* input;
    const char* expected;
  } kTestCases[] = {
      {"https://example.com/", "https://example.com/"},
      {"https://example.com/#fragment", "https://example.com/"},
      {"https://user:pass@example.com/", "https://example.com/"},
      {"https://user:pass@example.com/#fragment", "https://example.com/"},
      {"https://example.com/?query", "https://example.com/?query"},
      {"https://example.com/?query#fragment", "https://example.com/?query"},
      {"http://example.com/", "http://example.com/"},
      {"http://example.com/#fragment", "http://example.com/"},
      {"http://user:pass@example.com/", "http://example.com/"},
      {"http://user:pass@example.com/#fragment", "http://example.com/"},
      {"data:text/html,<html></html>", "data:text/html,<html></html>"},
      {"data:text/html,<html></html>#fragment", "data:text/html,<html></html>"},
      {"blob:https://example.com/uuid", "blob:https://example.com/uuid"},
      {"blob:https://example.com/uuid#fragment",
       "blob:https://example.com/uuid"},
  };

  for (const auto& test_case : kTestCases) {
    EXPECT_EQ(SerializeResponseUrlForReporting(GURL(test_case.input)).spec(),
              test_case.expected)
        << "For input: " << test_case.input;
  }
}

}  // namespace network
