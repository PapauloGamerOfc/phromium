// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_session_key.h"

#include "base/test/scoped_feature_list.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_handle.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/schemeful_site.h"
#include "net/base/session_usage.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/socket/socket_tag.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

TEST(SpdySessionKeyTest, HttppsNeverAliasesHttpsEvenAtSameAuthority) {
  auto key = [](bool httpps) {
    return SpdySessionKey(HostPortPair("same.example", 343),
                         PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                         SessionUsage::kDestination, SocketTag(),
                         NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                         false, handles::kInvalidNetworkHandle, httpps);
  };
  const auto https = key(false);
  const auto httpps = key(true);
  EXPECT_NE(https, httpps);
  EXPECT_NE(https < httpps, httpps < https);
  EXPECT_FALSE(https.CompareForAliasing(httpps).is_potentially_aliasable);
  EXPECT_FALSE(httpps.CompareForAliasing(https).is_potentially_aliasable);
  EXPECT_TRUE(httpps.CompareForAliasing(key(true)).is_potentially_aliasable);
  EXPECT_TRUE(httpps.is_httpps());
  EXPECT_FALSE(https.is_httpps());
}

TEST(SpdySessionKeyTest, HttppsDoesNotAliasAnotherOrigin) {
  auto key = [](const char* host, uint16_t port, bool httpps) {
    return SpdySessionKey(HostPortPair(host, port), PRIVACY_MODE_DISABLED,
                         ProxyChain::Direct(), SessionUsage::kDestination,
                         SocketTag(), NetworkAnonymizationKey(),
                         SecureDnsPolicy::kAllow, true,
                         handles::kInvalidNetworkHandle, httpps);
  };
  const auto source = key("first.test", 343, true);
  EXPECT_TRUE(source.CompareForAliasing(key("first.test", 343, true))
                  .is_potentially_aliasable);
  EXPECT_FALSE(source.CompareForAliasing(key("second.test", 343, true))
                   .is_potentially_aliasable);
  EXPECT_FALSE(source.CompareForAliasing(key("first.test", 8443, true))
                   .is_potentially_aliasable);
  EXPECT_TRUE(key("first.test", 443, false)
                  .CompareForAliasing(key("second.test", 443, false))
                  .is_potentially_aliasable);
}

TEST(SpdySessionKeyTest, HttppsPartitionsWhenOrdinaryPartitioningIsDisabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  ASSERT_FALSE(NetworkAnonymizationKey::IsPartitioningEnabled());
  const auto first = NetworkAnonymizationKey::CreateSameSite(
      SchemefulSite(GURL("https://first.test")));
  const auto second = NetworkAnonymizationKey::CreateSameSite(
      SchemefulSite(GURL("https://second.test")));
  auto key = [](const NetworkAnonymizationKey& nak, bool httpps) {
    return SpdySessionKey(HostPortPair("same.test", 343), PRIVACY_MODE_DISABLED,
                         ProxyChain::Direct(), SessionUsage::kDestination,
                         SocketTag(), nak, SecureDnsPolicy::kAllow, true,
                         handles::kInvalidNetworkHandle, httpps);
  };
  EXPECT_EQ(key(first, true).network_anonymization_key(), first);
  EXPECT_NE(key(first, true), key(second, true));
  EXPECT_FALSE(key(first, true).CompareForAliasing(key(second, true))
                   .is_potentially_aliasable);
  EXPECT_EQ(key(first, false), key(second, false));
}

// Check for equality of session keys, and inequality when various pieces of the
// key differ. The SocketTag is only used on Android, and the NAK is only used
// when network partitioning is enabled.
TEST(SpdySessionKeyTest, Equality) {
  SpdySessionKey key(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle);
  EXPECT_EQ(key,
            SpdySessionKey(HostPortPair("www.example.org", 80),
                           PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           /*disable_cert_verification_network_fetches=*/true,
                           handles::kInvalidNetworkHandle));
  EXPECT_NE(
      key, SpdySessionKey(HostPortPair("otherproxy", 80), PRIVACY_MODE_DISABLED,
                          ProxyChain::Direct(), SessionUsage::kDestination,
                          SocketTag(), NetworkAnonymizationKey(),
                          SecureDnsPolicy::kAllow,
                          /*disable_cert_verification_network_fetches=*/true,
                          handles::kInvalidNetworkHandle));
  EXPECT_NE(key,
            SpdySessionKey(HostPortPair("www.example.org", 80),
                           PRIVACY_MODE_ENABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           /*disable_cert_verification_network_fetches=*/true,
                           handles::kInvalidNetworkHandle));
  EXPECT_NE(key, SpdySessionKey(
                     HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::FromSchemeHostAndPort(
                         ProxyServer::Scheme::SCHEME_HTTPS, "otherproxy", 443),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle));
  EXPECT_NE(key, SpdySessionKey(
                     HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kProxy, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle));
#if BUILDFLAG(IS_ANDROID)
  EXPECT_NE(key,
            SpdySessionKey(HostPortPair("www.example.org", 80),
                           PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(999, 999),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           /*disable_cert_verification_network_fetches=*/true,
                           handles::kInvalidNetworkHandle));
#endif  // BUILDFLAG(IS_ANDROID)
  if (NetworkAnonymizationKey::IsPartitioningEnabled()) {
    EXPECT_NE(key,
              SpdySessionKey(HostPortPair("www.example.org", 80),
                             PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                             SessionUsage::kDestination, SocketTag(),
                             NetworkAnonymizationKey::CreateSameSite(
                                 SchemefulSite(GURL("http://a.test/"))),
                             SecureDnsPolicy::kAllow,
                             /*disable_cert_verification_network_fetches=*/true,
                             handles::kInvalidNetworkHandle));
  }
  EXPECT_NE(key,
            SpdySessionKey(HostPortPair("www.example.org", 80),
                           PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kDisable,
                           /*disable_cert_verification_network_fetches=*/true,
                           handles::kInvalidNetworkHandle));
  EXPECT_NE(key,
            SpdySessionKey(HostPortPair("www.example.org", 80),
                           PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           /*disable_cert_verification_network_fetches=*/false,
                           handles::kInvalidNetworkHandle));
  EXPECT_NE(key,
            SpdySessionKey(HostPortPair("www.example.org", 80),
                           PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           /*disable_cert_verification_network_fetches=*/true,
                           /*target_network=*/1));
  EXPECT_NE(SpdySessionKey(HostPortPair("www.example.org", 80),
                           PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           /*disable_cert_verification_network_fetches=*/true,
                           /*target_network=*/1),
            SpdySessionKey(HostPortPair("www.example.org", 80),
                           PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                           SessionUsage::kDestination, SocketTag(),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           /*disable_cert_verification_network_fetches=*/true,
                           /*target_network=*/2));
}

// The operator< implementation is suitable for storing distinct keys in a set.
TEST(SpdySessionKeyTest, Set) {
  std::vector<SpdySessionKey> session_keys = {
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle),
      SpdySessionKey(HostPortPair("otherproxy", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle),
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_ENABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle),
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::FromSchemeHostAndPort(
                         ProxyServer::Scheme::SCHEME_HTTPS, "otherproxy", 443),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle),
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain({
                         ProxyServer::FromSchemeHostAndPort(
                             ProxyServer::Scheme::SCHEME_HTTPS, "proxy1", 443),
                         ProxyServer::FromSchemeHostAndPort(
                             ProxyServer::Scheme::SCHEME_HTTPS, "proxy2", 443),
                     }),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle),
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kProxy, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle),
#if BUILDFLAG(IS_ANDROID)
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(999, 999), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle),
#endif  // BUILDFLAG(IS_ANDROID)
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kDisable,
                     /*disable_cert_verification_network_fetches=*/true,
                     handles::kInvalidNetworkHandle),
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false,
                     handles::kInvalidNetworkHandle),
      // Confirm that keys are not equal if target_network differs.
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     /*target_network=*/1),
      // Additional test to confirm that the target_network behavior does not
      // rely on the special value kInvalidNetworkHandle, but that also
      // that different handles make the session key differ.
      SpdySessionKey(HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true,
                     /*target_network=*/2),
  };
  if (NetworkAnonymizationKey::IsPartitioningEnabled()) {
    session_keys.emplace_back(
        HostPortPair("www.example.org", 80), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        NetworkAnonymizationKey::CreateSameSite(
            SchemefulSite(GURL("http://a.test/"))),
        SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/true,
        handles::kInvalidNetworkHandle);
  }
  std::set<SpdySessionKey> key_set(session_keys.begin(), session_keys.end());
  ASSERT_EQ(session_keys.size(), key_set.size());
}

}  // namespace

}  // namespace net
