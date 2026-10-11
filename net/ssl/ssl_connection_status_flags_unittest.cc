// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_connection_status_flags.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

TEST(SSLConnectionStatusTest, SetCipherSuite) {
  int connection_status = 0xDEADBEEF;
  int expected_version = SSLConnectionStatusToVersion(connection_status);

  SSLConnectionStatusSetCipherSuite(12345, &connection_status);
  EXPECT_EQ(12345U, SSLConnectionStatusToCipherSuite(connection_status));
  EXPECT_EQ(expected_version, SSLConnectionStatusToVersion(connection_status));
}

TEST(SSLConnectionStatusTest, SetVersion) {
  int connection_status = 0xDEADBEEF;
  uint16_t expected_cipher_suite =
      SSLConnectionStatusToCipherSuite(connection_status);

  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_2,
                                &connection_status);
  EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_2,
            SSLConnectionStatusToVersion(connection_status));
  EXPECT_EQ(expected_cipher_suite,
            SSLConnectionStatusToCipherSuite(connection_status));
}

TEST(SSLConnectionStatusTest, HttppsMarkerIsIndependentOfTlsVersion) {
  int status = SSL_CONNECTION_HTTPPS;
  SSLConnectionStatusSetCipherSuite(0x1302, &status);
  EXPECT_TRUE(SSLConnectionStatusIsHttpps(status));
  EXPECT_EQ(SSL_CONNECTION_VERSION_UNKNOWN, SSLConnectionStatusToVersion(status));
  EXPECT_EQ(0x1302, SSLConnectionStatusToCipherSuite(status));
  EXPECT_GE(status, 0);

  int ordinary = 0;
  SSLConnectionStatusSetCipherSuite(0x1302, &ordinary);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_3, &ordinary);
  EXPECT_FALSE(SSLConnectionStatusIsHttpps(ordinary));
  EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3, SSLConnectionStatusToVersion(ordinary));
}

}  // namespace

}  // namespace net
