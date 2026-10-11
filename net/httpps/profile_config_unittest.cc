// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/httpps/profile_config.h"

#include "base/base64.h"
#include "base/json/json_writer.h"
#include "base/strings/string_number_conversions.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/proxy_server.h"
#include "net/httpps/transparency.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/curve25519.h"
#include "url/gurl.h"

namespace net::httpps {
namespace {
std::string Config(base::DictValue options, int privacy = 0) {
  auto profile = base::DictValue()
                     .Set("origin", "httpps://example.test")
                     .Set("top_frame_site", "httpps://example.test")
                     .Set("cross_site", false)
                     .Set("privacy_mode", privacy)
                     .Set("route", "direct")
                     .Set("options", std::move(options));
  return *base::WriteJson(
      base::DictValue()
          .Set("format", 1)
          .Set("profiles", base::ListValue().Append(std::move(profile))));
}
SSLConfig Context() {
  SSLConfig config;
  config.is_httpps = true;
  config.network_anonymization_key = NetworkAnonymizationKey::CreateSameSite(
      SchemefulSite(GURL("httpps://example.test")));
  return config;
}
std::optional<bool> Apply(
    const SSLClientContext::HttppsProfileProvider& provider,
    const SSLConfig& config,
    ClientOptions* options,
    std::optional<ClientCredential>* credential,
    const HostPortPair& server = HostPortPair("example.test", 343)) {
  std::vector<std::string> roots;
  return provider.Run(server, config, options, credential, &roots);
}

TEST(HttppsProfileConfigTest, ExplicitOptionsAndPartition) {
  auto provider = CreateProfileProvider(
      Config(base::DictValue()
                 .Set("no_alpn_http11", true)
                 .Set("continuity_pinning", true)
                 .Set("record_size_limit", 4096)
                 .Set("groups", base::ListValue().Append(29))));
  ClientOptions options;
  std::optional<ClientCredential> credential;
  EXPECT_EQ(Apply(provider, Context(), &options, &credential), true);
  EXPECT_TRUE(options.no_alpn_http11);
  EXPECT_TRUE(options.continuity_pinning);
  EXPECT_EQ(options.record_size_limit, 4096);
  EXPECT_EQ(options.groups, std::vector<uint16_t>({29}));
  EXPECT_FALSE(credential);
  auto config = Context();
  config.network_anonymization_key = NetworkAnonymizationKey();
  EXPECT_EQ(Apply(provider, config, &options, &credential), false);
  config = Context();
  config.network_anonymization_key = NetworkAnonymizationKey::CreateCrossSite(
      SchemefulSite(GURL("httpps://example.test")));
  EXPECT_EQ(Apply(provider, config, &options, &credential), false);
  config = Context();
  config.privacy_mode = PRIVACY_MODE_ENABLED;
  EXPECT_EQ(Apply(provider, config, &options, &credential), false);
  config = Context();
  config.proxy_chain =
      ProxyChain(ProxyServer::SCHEME_HTTP, HostPortPair("proxy.test", 80));
  EXPECT_EQ(Apply(provider, config, &options, &credential), false);
  EXPECT_EQ(Apply(provider, Context(), &options, &credential,
                  HostPortPair("example.test", 344)),
            std::nullopt);
  EXPECT_EQ(Apply(provider, Context(), &options, &credential,
                  HostPortPair("other.test", 343)),
            std::nullopt);
  for (const auto partition :
       {NetworkIsolationPartition::kProtectedAudienceSellerWorklet,
        NetworkIsolationPartition::kFedCmUncredentialedRequests,
        NetworkIsolationPartition::kDnsOverHttps,
        NetworkIsolationPartition::kSharedWorkerSameSiteCookiesNone}) {
    config = Context();
    config.network_anonymization_key = NetworkAnonymizationKey::CreateFromParts(
        SchemefulSite(GURL("httpps://example.test")), false, std::nullopt,
        partition);
    EXPECT_EQ(Apply(provider, config, &options, &credential), false);
  }
}

TEST(HttppsProfileConfigTest, NeverHttpsOrProxyRole) {
  auto provider = CreateProfileProvider("invalid");
  ClientOptions options;
  std::optional<ClientCredential> credential;
  auto config = Context();
  config.is_httpps = false;
  EXPECT_EQ(Apply(provider, config, &options, &credential), std::nullopt);
  config = Context();
  config.session_usage = SessionUsage::kProxy;
  EXPECT_EQ(Apply(provider, config, &options, &credential), std::nullopt);
  EXPECT_EQ(Apply(provider, Context(), &options, &credential), false);
}

TEST(HttppsProfileConfigTest, MultipleBootstrapCredentialsAndLegacyOption) {
  auto make_binding = [](uint8_t scalar, const char* scope) {
    Secret key{}, public_key{};
    key.fill(scalar);
    X25519_public_from_private(public_key.data(), key.data());
    Bytes spki{0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x6e, 3, 0x21, 0};
    spki.insert(spki.end(), public_key.begin(), public_key.end());
    return base::DictValue()
        .Set("spki", base::Base64Encode(spki))
        .Set("private_key", base::Base64Encode(key))
        .Set("service", "example.test")
        .Set("scope", scope)
        .Set("expires_unix_seconds", "4102444800");
  };
  const auto a = make_binding(4, "device-a");
  auto b = make_binding(7, "device-b");
  b.Remove("expires_unix_seconds");
  auto provider = CreateProfileProvider(Config(base::DictValue().Set(
      "bootstraps", base::ListValue().Append(a.Clone()).Append(b.Clone()))));
  ClientOptions options;
  std::optional<ClientCredential> credential;
  ASSERT_EQ(Apply(provider, Context(), &options, &credential), true);
  ASSERT_EQ(options.bootstraps.size(), 2u);
  EXPECT_FALSE(options.bootstrap);
  EXPECT_FALSE(credential);
  EXPECT_EQ(options.bootstraps[1].scope, "device-b");
  EXPECT_EQ(options.bootstraps[1].expires_unix_seconds, 0);
  ASSERT_TRUE(options.bootstraps[1].credential);
  EXPECT_EQ(options.bootstraps[1].credential->certificate_type, 2);
  EXPECT_EQ(options.bootstraps[1].credential->private_key.front(), 7);
  Client client("example.test", {}, true, options);
  EXPECT_TRUE(client.Start());
  provider = CreateProfileProvider(Config(base::DictValue().Set("bootstrap", a.Clone())));
  options = {};
  ASSERT_EQ(Apply(provider, Context(), &options, &credential), true);
  ASSERT_TRUE(options.bootstrap);
  EXPECT_TRUE(options.bootstraps.empty());
  Client legacy("example.test", {}, true, options);
  EXPECT_TRUE(legacy.Start());

  auto private_config = Context();
  private_config.privacy_mode = PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS;
  provider = CreateProfileProvider(Config(base::DictValue().Set(
      "bootstraps", base::ListValue().Append(a.Clone()).Append(b.Clone())),
      PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS));
  options = {};
  EXPECT_EQ(Apply(provider, private_config, &options, &credential), false);
  std::vector<base::ListValue> malformed;
  malformed.emplace_back();
  malformed.push_back(base::ListValue().Append("invalid"));
  malformed.push_back(base::ListValue().Append(base::DictValue().Set("spki", "AA==")));
  for (auto& invalid : malformed) {
    options = {};
    provider = CreateProfileProvider(Config(base::DictValue().Set("bootstraps", std::move(invalid))));
    EXPECT_EQ(Apply(provider, Context(), &options, &credential), false);
  }
  auto forbidden = a.Clone();
  forbidden.Set("provisioning_trust", true);
  provider = CreateProfileProvider(Config(base::DictValue().Set(
      "bootstraps", base::ListValue().Append(std::move(forbidden)))));
  options = {};
  EXPECT_EQ(Apply(provider, Context(), &options, &credential), false);
}

TEST(HttppsProfileConfigTest, CollectLibrariesWithoutLoadingCode) {
#if BUILDFLAG(IS_WIN)
  const std::string prefix = "C:/trusted/";
#else
  const std::string prefix = "/trusted/";
#endif
  const auto crypto = prefix + "crypto.dll";
  const auto helper = prefix + "helper.dll";
  const auto its = prefix + "its.dll";
  auto config = Config(
      base::DictValue()
          .Set("native_library", crypto)
          .Set("password", base::DictValue().Set("helper_library", helper))
          .Set("its", base::DictValue().Set("library", its))
          .Set("client_credential",
               base::DictValue().Set("its",
                                     base::DictValue().Set("library", its))));
  // No files exist at these paths: collection must not perform LoadLibrary.
  auto paths = CollectProfileLibraries(config);
  ASSERT_TRUE(paths);
  EXPECT_EQ(*paths, std::vector<std::string>({crypto, helper, its}));
  EXPECT_EQ(
      CollectProfileLibraries(Config(base::DictValue())),
      std::optional<std::vector<std::string>>(std::vector<std::string>()));
  EXPECT_FALSE(CollectProfileLibraries("invalid"));
  EXPECT_FALSE(
      CollectProfileLibraries("{\"format\":1,\"format\":1,\"profiles\":[]}"));
  for (const auto& path : {std::string("relative.dll"), prefix + "../evil.dll",
                           crypto + std::string(1, '\0')}) {
    EXPECT_FALSE(CollectProfileLibraries(
        Config(base::DictValue().Set("native_library", path))));
  }
  EXPECT_FALSE(CollectProfileLibraries(
      Config(base::DictValue().Set("native_library", 42))));
  EXPECT_FALSE(CollectProfileLibraries(
      Config(base::DictValue().Set("its", base::DictValue()))));
  EXPECT_FALSE(CollectProfileLibraries(
      Config(base::DictValue().Set("password", "not an object"))));
}

TEST(HttppsProfileConfigTest, RejectMalformedAndOversizedDocuments) {
  const std::string invalid[] = {
      "",
      "null",
      "[]",
      "{}",
      "{\"format\":2,\"profiles\":[]}",
      "{\"format\":1,\"profiles\":[],\"unexpected\":true}",
      std::string(kMaxProfileConfigBytes + 1, ' ')};
  for (const auto& json : invalid) {
    ClientOptions options;
    std::optional<ClientCredential> credential;
    EXPECT_EQ(
        Apply(CreateProfileProvider(json), Context(), &options, &credential),
        false);
  }
}

TEST(HttppsProfileConfigTest, NoSilentWeakeningOrNativeDiscovery) {
  const std::string invalid[] = {
      "{\"unknown\":true}",
      "{\"no_alpn_http11\":1}",
      "{\"record_size_limit\":65536}",
      "{\"groups\":[29,29]}",
      "{\"allow_unauthenticated\":true}",
      "{\"ordinary_httpps\":false}",
      "{\"allow_integrity_only\":true}",
      "{\"native_library\":\"libcrypto.dll\"}",
      "{\"gost_module\":\"provider.dll\"}",
      "{\"server_raw_public_keys\":[\"non-base64\"]}"};
  for (const auto& text : invalid) {
    auto json = Config(base::DictValue());
    json.replace(json.find("\"options\":{}"), 12, "\"options\":" + text);
    ClientOptions options;
    std::optional<ClientCredential> credential;
    EXPECT_EQ(
        Apply(CreateProfileProvider(json), Context(), &options, &credential),
        false)
        << text;
  }
}

TEST(HttppsProfileConfigTest, RejectDuplicateKeysBeforePolicyCanBeOverwritten) {
  auto valid = Config(base::DictValue().Set("continuity_pinning", true));
  std::vector<std::string> invalid;
  invalid.push_back(valid.substr(0, valid.size() - 1) + ",\"profiles\":[]}");
  auto duplicate_options = valid;
  auto pos = duplicate_options.find("\"options\":");
  duplicate_options.insert(pos, "\"options\":{\"continuity_pinning\":false},");
  invalid.push_back(duplicate_options);
  for (const auto& value :
       {R"({"continuity_pinning":true,"continuity_pinning":false})",
        R"({"continuity_pinning":true,"\u0063ontinuity_pinning":false})",
        R"({"dane":{"trust_anchors":"AQ==","trust_anchors":"Ag=="}})"}) {
    auto document = Config(base::DictValue());
    document.replace(document.find("\"options\":{}"), 12,
                     "\"options\":" + std::string(value));
    invalid.push_back(std::move(document));
  }
  for (const auto& document : invalid) {
    ClientOptions options;
    std::optional<ClientCredential> credential;
    EXPECT_EQ(Apply(CreateProfileProvider(document), Context(), &options,
                    &credential),
              false);
  }
  // Equal key names in distinct objects and escaped values are not duplicates.
  base::ListValue keys;
  for (const auto* identity : {"AQ==", "Ag=="}) {
    keys.Append(
        base::DictValue()
            .Set("identity", identity)
            .Set("secret", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .Set("alpn", "custom\\\"{[:]}"));
  }
  valid = Config(base::DictValue().Set("external_psks", std::move(keys)));
  ClientOptions options;
  std::optional<ClientCredential> credential;
  EXPECT_EQ(
      Apply(CreateProfileProvider(valid), Context(), &options, &credential),
      true);
  ASSERT_EQ(options.external_psks.size(), 2u);
  EXPECT_EQ(options.external_psks[0].alpn, "custom\\\"{[:]}");
}

TEST(HttppsProfileConfigTest, ExternalPskRequiresLocalSelectionAndExactScope) {
  auto key = base::DictValue()
                 .Set("identity", "dXNlcg==")
                 .Set("secret", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
  auto provider = CreateProfileProvider(Config(base::DictValue().Set(
      "external_psks", base::ListValue().Append(std::move(key)))));
  ClientOptions options;
  std::optional<ClientCredential> credential;
  ASSERT_EQ(Apply(provider, Context(), &options, &credential), true);
  ASSERT_EQ(options.external_psks.size(), 1u);
  EXPECT_EQ(options.external_psks[0].hostname, "example.test");
  EXPECT_EQ(options.external_psks[0].secret.size(), 32u);
  EXPECT_FALSE(options.external_psks[0].imported);
}

TEST(HttppsProfileConfigTest, RejectOriginNormalizationAmbiguities) {
  for (const auto& replacement :
       {"httpps://example.test/", "https://example.test",
        "httpps://user@example.test", "httpps://example.test/a"}) {
    auto json = Config(base::DictValue());
    auto pos = json.find("\"origin\":\"httpps://example.test\"");
    json.replace(pos,
                 std::string("\"origin\":\"httpps://example.test\"").size(),
                 "\"origin\":\"" + std::string(replacement) + "\"");
    ClientOptions options;
    std::optional<ClientCredential> credential;
    EXPECT_EQ(
        Apply(CreateProfileProvider(json), Context(), &options, &credential),
        false);
  }
}

TEST(HttppsProfileConfigTest, FetchOmitDoesNotDiscloseProvisionedIdentity) {
  auto key = base::DictValue()
                 .Set("identity", "dXNlcg==")
                 .Set("secret", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
  auto provider = CreateProfileProvider(
      Config(base::DictValue().Set("external_psks",
                                   base::ListValue().Append(std::move(key))),
             2));
  ClientOptions options;
  std::optional<ClientCredential> credential;
  auto config = Context();
  config.privacy_mode = PRIVACY_MODE_ENABLED_WITHOUT_CLIENT_CERTS;
  EXPECT_EQ(Apply(provider, config, &options, &credential), false);
}

TEST(HttppsProfileConfigTest, EvidenceAndControlOptionsRetainExactValues) {
  std::string key;
  ASSERT_TRUE(
      base::HexStringToString("302a300506032b6570032100d75a980182b10ab7d54bfed3"
                              "c964073a0ee172f3daa62325af021a68f707511a",
                              &key));
  auto log = base::DictValue()
                 .Set("id", "KwYBBAE=")
                 .Set("public_key_spki", base::Base64Encode(key))
                 .Set("signature_scheme", 2055)
                 .Set("valid_until_ms", "18446744073709551615");
  auto configured =
      base::DictValue()
          .Set("ct_v2", base::DictValue().Set(
                            "logs", base::ListValue().Append(std::move(log))))
          .Set("ticket_request", base::DictValue()
                                     .Set("new_session_count", 2)
                                     .Set("resumption_count", 0))
          .Set("signaling",
               base::DictValue()
                   .Set("local_hash",
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                   .Set("local_session_id",
                        base::Base64Encode(std::string(20, 'a')))
                   .Set("peer_session_id",
                        base::Base64Encode(std::string(20, 'b'))))
          .Set("record_padding_multiple", 64)
          .Set("client_hello_padding", 512)
          .Set("certificate_signature_algorithms",
               base::ListValue().Append(1027))
          .Set("grant_signature_algorithms", base::ListValue().Append(2055))
          .Set("certificate_authorities", base::ListValue().Append("MAMMAWE="));
  ClientOptions options;
  std::optional<ClientCredential> credential;
  ASSERT_EQ(Apply(CreateProfileProvider(Config(std::move(configured))),
                  Context(), &options, &credential),
            true);
  ASSERT_TRUE(options.ct_v2_policy);
  ASSERT_EQ(options.ct_v2_policy->logs.size(), 1u);
  EXPECT_EQ(options.ct_v2_policy->logs[0].valid_until_ms, UINT64_MAX);
  EXPECT_TRUE(options.request_ocsp);
  EXPECT_TRUE(options.request_scts);
  ASSERT_TRUE(options.ticket_request);
  EXPECT_EQ(options.ticket_request->resumption_count, 0);
  ASSERT_TRUE(options.signaling);
  EXPECT_EQ(options.signaling->local_hash.size(), 32u);
  EXPECT_EQ(options.record_padding_multiple, 64u);
  EXPECT_EQ(options.client_hello_padding, 512u);
  EXPECT_NE(options.certificate_signature_algorithms,
            options.grant_signature_algorithms);
}
}  // namespace
}  // namespace net::httpps
