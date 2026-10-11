// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_client_socket.h"

#include <algorithm>
#include <map>
#include <string>
#include <tuple>

#include "base/containers/flat_tree.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/observer_list.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/session_usage.h"
#include "net/cert/x509_certificate_net_log_param.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/httpps/dnssec.h"
#include "net/httpps/its_credentials.h"
#include "net/httpps/opaque_string.h"
#include "net/httpps/transparency.h"
#include "net/socket/httpps_client_socket.h"
#include "net/socket/ssl_client_socket_impl.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_client_session_cache.h"
#include "net/ssl/ssl_config.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_key_logger.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net {

namespace {

// Returns true if |first_cert| and |second_cert| represent the same certificate
// (with the same chain), or if they're both NULL.
bool AreCertificatesEqual(const scoped_refptr<X509Certificate>& first_cert,
                          const scoped_refptr<X509Certificate>& second_cert,
                          bool include_chain = true) {
  return (!first_cert && !second_cert) ||
         (first_cert && second_cert &&
          (include_chain
               ? first_cert->EqualsIncludingChain(second_cert.get())
               : first_cert->EqualsExcludingChain(second_cert.get())));
}

// Returns a base::DictValue value NetLog parameter with the expected format
// for events of type CLEAR_CACHED_CLIENT_CERT.
base::DictValue NetLogClearCachedClientCertParams(
    const net::HostPortPair& host,
    const scoped_refptr<net::X509Certificate>& cert,
    bool is_cleared) {
  return base::DictValue()
      .Set("host", host.ToString())
      .Set("certificates", cert ? net::NetLogX509CertificateList(cert.get())
                                : base::Value(base::ListValue()))
      .Set("is_cleared", is_cleared);
}

// Returns a base::DictValue value NetLog parameter with the expected format
// for events of type CLEAR_MATCHING_CACHED_CLIENT_CERT.
base::DictValue NetLogClearMatchingCachedClientCertParams(
    const base::flat_set<net::HostPortPair>& hosts,
    const scoped_refptr<net::X509Certificate>& cert) {
  base::ListValue hosts_values;
  for (const auto& host : hosts) {
    hosts_values.Append(host.ToString());
  }

  return base::DictValue()
      .Set("hosts", base::Value(std::move(hosts_values)))
      .Set("certificates", cert ? net::NetLogX509CertificateList(cert.get())
                                : base::Value(base::ListValue()));
}

}  // namespace

struct SSLClientContext::HttppsSessionCache {
  struct Key {
    SSLClientSessionCache::Key scope;
    int verification_flags = 0;
    NextProtoVector protocols;

    bool operator<(const Key& other) const {
      return std::tie(scope, verification_flags, protocols) <
             std::tie(other.scope, other.verification_flags, other.protocols);
    }
  };
  struct Entry {
    httpps::SessionTicket ticket;
    size_t bytes = 0;
    uint64_t order = 0;
  };
  static Key MakeKey(const HostPortPair& server, const SSLConfig& config) {
    Key key;
    key.scope.server = server;
    // Keep partitioning even when the ordinary TLS experiment is disabled.
    key.scope.network_anonymization_key = config.network_anonymization_key;
    key.scope.privacy_mode = config.privacy_mode;
    key.scope.proxy_chain = config.proxy_chain;
    key.scope.proxy_chain_index = config.proxy_chain_index;
    key.scope.session_usage = config.session_usage;
    key.verification_flags = config.GetCertVerifyFlags();
    key.protocols = config.alpn_protos;
    return key;
  }
  static bool Usable(const httpps::SessionTicket& ticket, int64_t now) {
    return ticket.lifetime > 0 && ticket.lifetime <= 604800 &&
           ticket.received_milliseconds >= 0 &&
           ticket.received_milliseconds <= now &&
           now - ticket.received_milliseconds <
               static_cast<int64_t>(ticket.lifetime) * 1000;
  }
  std::map<Key, Entry> entries;
  std::map<Key, httpps::ClientCredential> client_credentials;
  std::map<Key, httpps::ClientOptions> profiles;
  size_t bytes = 0;
  uint64_t next_order = 0;
  uint64_t ordinary_cache_generation = 0;
};

// static
void SSLClientSocket::RecordSSLConnectResult(
    SSLClientSocket* ssl_socket,
    int result,
    bool is_ech_capable,
    bool ech_enabled,
    const std::optional<std::vector<uint8_t>>& ech_retry_configs,
    bool trust_anchor_ids_from_dns,
    bool retried_with_trust_anchor_ids,
    bool trust_anchor_retry_used_mtc_fallback,
    const LoadTimingInfo::ConnectTiming& connect_timing) {
  const bool is_ok = result == OK;
  if (is_ech_capable && ech_enabled) {
    // These values are persisted to logs. Entries should not be renumbered
    // and numeric values should never be reused.
    enum class ECHResult {
      // The connection succeeded on the initial connection.
      kSuccessInitial = 0,
      // The connection failed on the initial connection, without providing
      // retry configs.
      kErrorInitial = 1,
      // The connection succeeded after getting retry configs.
      kSuccessRetry = 2,
      // The connection failed after getting retry configs.
      kErrorRetry = 3,
      // The connection succeeded after getting a rollback signal.
      kSuccessRollback = 4,
      // The connection failed after getting a rollback signal.
      kErrorRollback = 5,
      kMaxValue = kErrorRollback,
    };
    ECHResult ech_result;
    if (!ech_retry_configs.has_value()) {
      ech_result =
          is_ok ? ECHResult::kSuccessInitial : ECHResult::kErrorInitial;
    } else if (ech_retry_configs->empty()) {
      ech_result =
          is_ok ? ECHResult::kSuccessRollback : ECHResult::kErrorRollback;
    } else {
      ech_result = is_ok ? ECHResult::kSuccessRetry : ECHResult::kErrorRetry;
    }
    base::UmaHistogramEnumeration("Net.SSL.ECHResult", ech_result);
  }

  TrustAnchorIDsResult tai_result;
  if (trust_anchor_ids_from_dns) {
    if (retried_with_trust_anchor_ids && trust_anchor_retry_used_mtc_fallback) {
      tai_result = is_ok ? TrustAnchorIDsResult::kDnsSuccessRetryMtcFallback
                         : TrustAnchorIDsResult::kDnsErrorRetryMtcFallback;
    } else if (retried_with_trust_anchor_ids) {
      tai_result = is_ok ? TrustAnchorIDsResult::kDnsSuccessRetry
                         : TrustAnchorIDsResult::kDnsErrorRetry;
    } else {
      tai_result = is_ok ? TrustAnchorIDsResult::kDnsSuccessInitial
                         : TrustAnchorIDsResult::kDnsErrorInitial;
    }
  } else {
    if (retried_with_trust_anchor_ids && trust_anchor_retry_used_mtc_fallback) {
      tai_result = is_ok ? TrustAnchorIDsResult::kNoDnsSuccessRetryMtcFallback
                         : TrustAnchorIDsResult::kNoDnsErrorRetryMtcFallback;
    } else if (retried_with_trust_anchor_ids) {
      tai_result = is_ok ? TrustAnchorIDsResult::kNoDnsSuccessRetry
                         : TrustAnchorIDsResult::kNoDnsErrorRetry;
    } else {
      tai_result = is_ok ? TrustAnchorIDsResult::kNoDnsSuccessInitial
                         : TrustAnchorIDsResult::kNoDnsErrorInitial;
    }
  }
  base::UmaHistogramEnumeration("Net.SSL.TrustAnchorIDsResult", tai_result);

  if (result == OK) {
    DCHECK(!connect_timing.ssl_start.is_null());
    CHECK(ssl_socket);
    base::TimeDelta connect_duration =
        connect_timing.ssl_end - connect_timing.ssl_start;
    UMA_HISTOGRAM_CUSTOM_TIMES("Net.SSL_Connection_Latency_2", connect_duration,
                               base::Milliseconds(1), base::Minutes(1), 100);
    if (trust_anchor_ids_from_dns) {
      base::UmaHistogramCustomTimes("Net.SSL_Connection_Latency_TrustAnchorIDs",
                                    connect_duration, base::Milliseconds(1),
                                    base::Minutes(1), 100);
    }

    SSLInfo ssl_info;
    bool has_ssl_info = ssl_socket->GetSSLInfo(&ssl_info);
    DCHECK(has_ssl_info);

    SSLVersion version =
        SSLConnectionStatusToVersion(ssl_info.connection_status);
    UMA_HISTOGRAM_ENUMERATION("Net.SSLVersion", version,
                              SSL_CONNECTION_VERSION_MAX);

    uint16_t cipher_suite =
        SSLConnectionStatusToCipherSuite(ssl_info.connection_status);
    base::UmaHistogramSparse("Net.SSL_CipherSuite", cipher_suite);

    if (ssl_info.key_exchange_group != 0) {
      base::UmaHistogramSparse("Net.SSL_KeyExchange.ECDHE",
                               ssl_info.key_exchange_group);
    }

    if (ssl_info.server_padding_received) {
      base::UmaHistogramCustomTimes("Net.SSL_Connection_Latency_ServerPadding",
                                    connect_duration, base::Milliseconds(1),
                                    base::Minutes(1), 100);
    }
  }

  base::UmaHistogramSparse("Net.SSL_Connection_Error", std::abs(result));
  if (trust_anchor_ids_from_dns) {
    base::UmaHistogramSparse("Net.SSL_Connection_Error_TrustAnchorIDs",
                             std::abs(result));
  }
}

SSLClientSocket::SSLClientSocket() = default;

// static
void SSLClientSocket::SetSSLKeyLogger(std::unique_ptr<SSLKeyLogger> logger) {
  SSLClientSocketImpl::SetSSLKeyLogger(std::move(logger));
}

// static
std::vector<uint8_t> SSLClientSocket::SerializeNextProtos(
    const NextProtoVector& next_protos) {
  std::vector<uint8_t> wire_protos;
  for (const NextProto next_proto : next_protos) {
    const std::string proto = NextProtoToString(next_proto);
    if (proto.size() > 255) {
      LOG(WARNING) << "Ignoring overlong ALPN protocol: " << proto;
      continue;
    }
    if (proto.size() == 0) {
      LOG(WARNING) << "Ignoring empty ALPN protocol";
      continue;
    }
    wire_protos.push_back(proto.size());
    for (const char ch : proto) {
      wire_protos.push_back(static_cast<uint8_t>(ch));
    }
  }

  return wire_protos;
}

SSLClientContext::SSLClientContext(
    SSLConfigService* ssl_config_service,
    CertVerifier* cert_verifier,
    TransportSecurityState* transport_security_state,
    SSLClientSessionCache* ssl_client_session_cache,
    SCTAuditingDelegate* sct_auditing_delegate)
    : httpps_session_cache_(std::make_unique<HttppsSessionCache>()),
      ssl_config_service_(ssl_config_service),
      cert_verifier_(cert_verifier),
      transport_security_state_(transport_security_state),
      ssl_client_session_cache_(ssl_client_session_cache),
      sct_auditing_delegate_(sct_auditing_delegate) {
  CHECK(cert_verifier_);
  CHECK(transport_security_state_);

  if (ssl_config_service_) {
    config_ = ssl_config_service_->GetSSLContextConfig();
    ssl_config_service_->AddObserver(this);
  }
  cert_verifier_->AddObserver(this);
  CertDatabase::GetInstance()->AddObserver(this);
  if (ssl_client_session_cache_) {
    httpps_session_cache_->ordinary_cache_generation =
        ssl_client_session_cache_->generation_number();
  }
}

SSLClientContext::~SSLClientContext() {
  if (ssl_config_service_) {
    ssl_config_service_->RemoveObserver(this);
  }
  cert_verifier_->RemoveObserver(this);
  CertDatabase::GetInstance()->RemoveObserver(this);
}

EchMode SSLClientContext::GetEchMode(std::string_view hostname) const {
  if (ssl_config_service_) {
    return ssl_config_service_->GetEchMode(hostname);
  }
  return EchMode::kOpportunistic;
}

bool SSLClientContext::IsEchEnabled(std::string_view hostname) const {
  return GetEchMode(hostname) != EchMode::kDisabled;
}

void SSLClientContext::ClearHttppsSessions() {
  ++httpps_session_generation_;
  httpps_session_cache_->entries.clear();
  httpps_session_cache_->bytes = 0;
  if (ssl_client_session_cache_) {
    httpps_session_cache_->ordinary_cache_generation =
        ssl_client_session_cache_->generation_number();
  }
}

void SSLClientContext::SynchronizeHttppsSessionGeneration() {
  // HttpNetworkSession::ClearSSLSessionCache and memory-pressure flushes also
  // invalidate HTTPPS, without ever storing TLS 2.0 PSKs as SSL_SESSIONs.
  if (ssl_client_session_cache_ &&
      httpps_session_cache_->ordinary_cache_generation !=
          ssl_client_session_cache_->generation_number()) {
    ClearHttppsSessions();
  }
}

void SSLClientContext::SetHttppsTrustAnchors(
    const std::vector<std::string>& roots) {
  if (roots != httpps_trust_anchors_) {
    httpps_trust_anchors_ = roots;
    NotifySSLConfigChanged(SSLConfigChangeType::kCertDatabaseChanged);
  }
}

void SSLClientContext::SetHttppsProxyTrustAnchors(
    const std::vector<std::string>& roots) {
  if (roots != httpps_proxy_trust_anchors_) {
    httpps_proxy_trust_anchors_ = roots;
    NotifySSLConfigChanged(SSLConfigChangeType::kCertDatabaseChanged);
  }
}

bool SSLClientContext::SetHttppsClientCredential(
    const HostPortPair& server, const SSLConfig& config,
    const httpps::ClientCredential& credential) {
  if (!config.is_httpps || config.session_usage != SessionUsage::kDestination) {
    return false;
  }
  httpps::Client validator(server.host(), {}, true);
  if (!validator.SetClientCredential(credential)) {
    return false;
  }
  auto selected = credential;
  if (credential.its_policy) {
    selected.its_policy =
        std::make_shared<httpps::ITSPolicy>(*credential.its_policy);
  }
  // A selection may contain a private key; never log or persist this map.
  httpps_session_cache_->client_credentials.insert_or_assign(
      HttppsSessionCache::MakeKey(server, config), std::move(selected));
  NotifySSLConfigForServersChanged({server});
  return true;
}

bool SSLClientContext::ClearHttppsClientCredential(
    const HostPortPair& server, const SSLConfig& config) {
  if (!config.is_httpps || config.session_usage != SessionUsage::kDestination ||
      !httpps_session_cache_->client_credentials.erase(
          HttppsSessionCache::MakeKey(server, config))) {
    return false;
  }
  NotifySSLConfigForServersChanged({server});
  return true;
}

const httpps::ClientCredential* SSLClientContext::GetHttppsClientCredential(
    const HostPortPair& server, const SSLConfig& config) const {
  if (!config.is_httpps || config.session_usage != SessionUsage::kDestination) {
    return nullptr;
  }
  auto found = httpps_session_cache_->client_credentials.find(
      HttppsSessionCache::MakeKey(server, config));
  return found == httpps_session_cache_->client_credentials.end()
             ? nullptr : &found->second;
}

bool SSLClientContext::SetHttppsOptions(
    const HostPortPair& server, const SSLConfig& config,
    const httpps::ClientOptions& options) {
  if (!config.is_httpps || config.session_usage != SessionUsage::kDestination ||
      !options.ordinary_httpps || options.allow_integrity_only || options.pinning ||
      (options.bootstrap && options.bootstrap->provisioning_trust) ||
      (options.dane_policy && options.dane_policy->port != server.port())) {
    return false;
  }
  auto prepared = options;
  // Snapshot policy data: a caller may retain a mutable shared_ptr even when
  // our interface receives shared_ptr<const>. Updates must go through this
  // setter to invalidate old tickets and pooled connections. Providers remain
  // shared; external state captured by DANE callbacks obeys the same contract.
  if (options.ct_v2_policy) {
    prepared.ct_v2_policy =
        std::make_shared<httpps::CTv2Policy>(*options.ct_v2_policy);
  }
  if (options.dane_policy) {
    prepared.dane_policy =
        std::make_shared<httpps::DANEPolicy>(*options.dane_policy);
  }
  if (options.its_policy) {
    prepared.its_policy =
        std::make_shared<httpps::ITSPolicy>(*options.its_policy);
  }
  if (options.password) {
    if (options.password->service != server.host()) {
      return false;
    }
    auto password = std::make_shared<httpps::PasswordCredential>(*options.password);
    auto username = httpps::PrepareOpaqueString(password->username);
    if (!username || username->size() > 255) {
      return false;
    }
    auto secret = httpps::PrepareOpaqueString(password->password);
    if (!secret) {
      return false;
    }
    password->username = std::move(*username);
    // Do not overwrite the original password's allocation without wiping it.
    OPENSSL_cleanse(password->password.data(), password->password.size());
    password->password = std::move(*secret);
    password->prepare_text = httpps::PrepareOpaqueString;
    prepared.password = std::move(password);
  }
  httpps_session_cache_->profiles.insert_or_assign(
      HttppsSessionCache::MakeKey(server, config), std::move(prepared));
  NotifySSLConfigForServersChanged({server});
  return true;
}

bool SSLClientContext::ClearHttppsOptions(const HostPortPair& server,
                                       const SSLConfig& config) {
  if (!config.is_httpps || config.session_usage != SessionUsage::kDestination ||
      !httpps_session_cache_->profiles.erase(
          HttppsSessionCache::MakeKey(server, config))) {
    return false;
  }
  NotifySSLConfigForServersChanged({server});
  return true;
}

const httpps::ClientOptions* SSLClientContext::GetHttppsOptions(
    const HostPortPair& server, const SSLConfig& config) const {
  if (!config.is_httpps || config.session_usage != SessionUsage::kDestination) {
    return nullptr;
  }
  auto found = httpps_session_cache_->profiles.find(
      HttppsSessionCache::MakeKey(server, config));
  return found == httpps_session_cache_->profiles.end() ? nullptr : &found->second;
}

std::optional<httpps::SessionTicket> SSLClientContext::TakeHttppsSession(
    const HostPortPair& server, const SSLConfig& config) {
  SynchronizeHttppsSessionGeneration();
  if (!ssl_client_session_cache_ || !config.is_httpps) {
    return std::nullopt;
  }
  auto& cache = *httpps_session_cache_;
  auto found = cache.entries.find(HttppsSessionCache::MakeKey(server, config));
  if (found == cache.entries.end()) {
    return std::nullopt;
  }
  auto ticket = std::move(found->second.ticket);
  cache.bytes -= found->second.bytes;
  cache.entries.erase(found);
  // Removal happens before the handshake starts: concurrent sockets cannot
  // replay one ticket. A failed attempt does not put it back into the cache.
  if (!HttppsSessionCache::Usable(ticket, httpps::MonotonicMilliseconds())) {
    return std::nullopt;
  }
  return ticket;
}

void SSLClientContext::StoreHttppsSession(uint64_t generation,
                                        const HostPortPair& server,
                                        const SSLConfig& config,
                                        httpps::SessionTicket ticket) {
  SynchronizeHttppsSessionGeneration();
  if (!ssl_client_session_cache_ || !config.is_httpps ||
      generation != httpps_session_generation_ ||
      ticket.hostname != server.host() || ticket.identity.empty() ||
      ticket.identity.size() > 65535 ||
      (ticket.certificates.empty() &&
       ticket.authentication != httpps::Authentication::kExternalPsk &&
       ticket.authentication != httpps::Authentication::kPassword) ||
      httpps::SuiteHashLength(ticket.cipher_suite) == 0 ||
      ticket.psk.size() != httpps::SuiteHashLength(ticket.cipher_suite) ||
      ticket.alpn.empty() || ticket.alpn.size() > 255 ||
      (ticket.client_certificate_type != 0 && ticket.client_certificate_type != 2 &&
       ticket.client_certificate_type != 3) ||
      (!ticket.ct_policy_context.empty() && ticket.ct_policy_context.size() != 32) ||
      (!ticket.dane_policy_context.empty() && ticket.dane_policy_context.size() != 32) ||
      (!ticket.its_policy_context.empty() && ticket.its_policy_context.size() != 32) ||
      ticket.authentication == httpps::Authentication::kProvisioning ||
      (!ticket.certificate_extensions.empty() &&
       ticket.certificate_extensions.size() != ticket.certificates.size()) ||
      ticket.certificates.size() > 64 ||
      !HttppsSessionCache::Usable(ticket, httpps::MonotonicMilliseconds())) {
    return;
  }
  // Local memory budgets, not protocol limits. Do not persist PSKs to disk.
  constexpr size_t kMaxEntryBytes = 1024 * 1024;
  constexpr size_t kMaxCacheBytes = 16 * 1024 * 1024;
  constexpr size_t kMaxEntries = 256;
  size_t bytes = ticket.identity.size() + ticket.psk.size() +
                 ticket.ct_policy_context.size() + ticket.dane_policy_context.size() +
                 ticket.its_policy_context.size();
  if (ticket.delegation.size() > kMaxEntryBytes - bytes) {
    return;
  }
  bytes += ticket.delegation.size();
  for (const auto& entry : ticket.certificate_extensions) {
    for (const auto& [type, value] : entry) {
      // Account evidence and map-node overhead as well as certificates. A
      // peer cannot escape the cache byte budget with many empty extensions.
      constexpr size_t kExtensionOverhead = 64;
      if (kExtensionOverhead > kMaxEntryBytes - bytes) {
        return;
      }
      bytes += kExtensionOverhead;
      if (value.size() > kMaxEntryBytes - bytes) {
        return;
      }
      bytes += value.size();
    }
  }
  for (const auto& cert : ticket.certificates) {
    if (cert.empty() || cert.size() > kMaxEntryBytes - bytes) {
      return;
    }
    bytes += cert.size();
  }
  auto& cache = *httpps_session_cache_;
  const auto key = HttppsSessionCache::MakeKey(server, config);
  if (auto found = cache.entries.find(key); found != cache.entries.end()) {
    cache.bytes -= found->second.bytes;
    cache.entries.erase(found);
  }
  while (!cache.entries.empty() &&
         (cache.entries.size() >= kMaxEntries ||
          cache.bytes > kMaxCacheBytes - bytes)) {
    auto oldest = std::min_element(
        cache.entries.begin(), cache.entries.end(),
        [](const auto& a, const auto& b) {
          return a.second.order < b.second.order;
        });
    cache.bytes -= oldest->second.bytes;
    cache.entries.erase(oldest);
  }
  cache.entries.emplace(key, HttppsSessionCache::Entry{
                                 std::move(ticket), bytes, cache.next_order++});
  cache.bytes += bytes;
}

std::unique_ptr<SSLClientSocket> SSLClientContext::CreateSSLClientSocket(
    std::unique_ptr<StreamSocket> stream_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config) {
  if (ssl_config.is_httpps) {
    // A proxy and an origin can have the same hostname/port but must not share
    // trust authority. In particular, missing proxy roots stay empty.
    const auto& roots = ssl_config.session_usage == SessionUsage::kProxy
                            ? httpps_proxy_trust_anchors_
                            : httpps_trust_anchors_;
    auto ticket = TakeHttppsSession(host_and_port, ssl_config);
    httpps::ClientOptions options;
    // Ordinary browser optimizations need no identity disclosure: the codecs
    // are bounded and cached certificate bytes always receive fresh validation.
    options.certificate_compression = {1, 2, 3};
    options.delegated_credentials = true;
    if (const auto* selected = GetHttppsOptions(host_and_port, ssl_config)) {
      options = *selected;
    }
    if (ticket && !ticket->certificates.empty()) {
      options.cached_certificates.emplace_back(ticket->server_certificate_type,
                                               ticket->certificates);
    }
    options.alpn_protocols.clear();
    for (NextProto proto : ssl_config.alpn_protos) {
      if (proto == NextProto::kProtoHTTP11 || proto == NextProto::kProtoHTTP2) {
        options.alpn_protocols.emplace_back(NextProtoToString(proto));
      }
    }
    if (options.alpn_protocols.empty()) {
      options.alpn_protocols = {"http/1.1"};
    }
    std::optional<httpps::ClientCredential> credential;
    if (const auto* selected = GetHttppsClientCredential(host_and_port, ssl_config)) {
      credential = *selected;
      options.post_handshake_auth = true;
    }
    return std::make_unique<HttppsClientSocket>(
        std::move(stream_socket), host_and_port, roots, cert_verifier_.get(),
        std::move(ticket),
        base::BindRepeating(&SSLClientContext::StoreHttppsSession,
                            weak_factory_.GetWeakPtr(),
                            httpps_session_generation_, host_and_port,
                            ssl_config),
        ssl_config.early_data_enabled &&
            ssl_config.session_usage == SessionUsage::kDestination,
        std::move(options), std::move(credential));
  }
  return std::make_unique<SSLClientSocketImpl>(this, std::move(stream_socket),
                                               host_and_port, ssl_config);
}

bool SSLClientContext::GetClientCertificate(
    const HostPortPair& server,
    scoped_refptr<X509Certificate>* client_cert,
    scoped_refptr<SSLPrivateKey>* private_key) {
  return ssl_client_auth_cache_.Lookup(server, client_cert, private_key);
}

void SSLClientContext::SetClientCertificate(
    const HostPortPair& server,
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> private_key) {
  ssl_client_auth_cache_.Add(server, std::move(client_cert),
                             std::move(private_key));

  if (ssl_client_session_cache_) {
    // Session resumption bypasses client certificate negotiation, so flush all
    // associated sessions when preferences change.
    ssl_client_session_cache_->FlushForServers({server});
  }
  NotifySSLConfigForServersChanged({server});
}

bool SSLClientContext::ClearClientCertificate(const HostPortPair& server) {
  if (!ssl_client_auth_cache_.Remove(server)) {
    return false;
  }

  if (ssl_client_session_cache_) {
    // Session resumption bypasses client certificate negotiation, so flush all
    // associated sessions when preferences change.
    ssl_client_session_cache_->FlushForServers({server});
  }
  NotifySSLConfigForServersChanged({server});
  return true;
}

void SSLClientContext::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void SSLClientContext::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

void SSLClientContext::OnSSLContextConfigChanged() {
  config_ = ssl_config_service_->GetSSLContextConfig();
  if (ssl_client_session_cache_) {
    ssl_client_session_cache_->Flush();
  }
  NotifySSLConfigChanged(SSLConfigChangeType::kSSLConfigChanged);
}

void SSLClientContext::OnCertVerifierChanged() {
  NotifySSLConfigChanged(SSLConfigChangeType::kCertVerifierChanged);
}

void SSLClientContext::OnTrustStoreChanged() {
  NotifySSLConfigChanged(SSLConfigChangeType::kCertDatabaseChanged);
}

void SSLClientContext::OnClientCertStoreChanged() {
  base::flat_set<HostPortPair> servers =
      ssl_client_auth_cache_.GetCachedServers();
  for (const auto& [key, credential] : httpps_session_cache_->client_credentials) {
    servers.insert(key.scope.server);
  }
  httpps_session_cache_->client_credentials.clear();
  if (servers.empty()) {
    // HTTPPS tickets must also lose their pending generation when the client
    // credential store changes before any ordinary TLS preference was cached.
    ClearHttppsSessions();
    return;
  }
  ssl_client_auth_cache_.Clear();
  if (ssl_client_session_cache_) {
    ssl_client_session_cache_->FlushForServers(servers);
  }
  NotifySSLConfigForServersChanged(servers);
}

void SSLClientContext::ClearClientCertificateIfNeeded(
    const net::HostPortPair& host,
    const scoped_refptr<net::X509Certificate>& certificate) {
  scoped_refptr<X509Certificate> cached_certificate;
  scoped_refptr<SSLPrivateKey> cached_private_key;
  if (!ssl_client_auth_cache_.Lookup(host, &cached_certificate,
                                     &cached_private_key) ||
      AreCertificatesEqual(cached_certificate, certificate)) {
    // No cached client certificate preference for this host.
    net::NetLog::Get()->AddGlobalEntry(
        NetLogEventType::CLEAR_CACHED_CLIENT_CERT, [&]() {
          return NetLogClearCachedClientCertParams(host, certificate,
                                                   /*is_cleared=*/false);
        });
    return;
  }

  net::NetLog::Get()->AddGlobalEntry(
      NetLogEventType::CLEAR_CACHED_CLIENT_CERT, [&]() {
        return NetLogClearCachedClientCertParams(host, certificate,
                                                 /*is_cleared=*/true);
      });

  ssl_client_auth_cache_.Remove(host);

  if (ssl_client_session_cache_) {
    ssl_client_session_cache_->FlushForServers({host});
  }

  NotifySSLConfigForServersChanged({host});
}

void SSLClientContext::ClearMatchingClientCertificate(
    const scoped_refptr<net::X509Certificate>& certificate) {
  CHECK(certificate);

  base::flat_set<HostPortPair> cleared_servers;
  for (const auto& server : ssl_client_auth_cache_.GetCachedServers()) {
    scoped_refptr<X509Certificate> cached_certificate;
    scoped_refptr<SSLPrivateKey> cached_private_key;
    if (ssl_client_auth_cache_.Lookup(server, &cached_certificate,
                                      &cached_private_key) &&
        AreCertificatesEqual(cached_certificate, certificate,
                             /*include_chain=*/false)) {
      cleared_servers.insert(cleared_servers.end(), server);
    }
  }

  net::NetLog::Get()->AddGlobalEntry(
      NetLogEventType::CLEAR_MATCHING_CACHED_CLIENT_CERT, [&]() {
        return NetLogClearMatchingCachedClientCertParams(cleared_servers,
                                                         certificate);
      });

  if (cleared_servers.empty()) {
    return;
  }

  for (const auto& server_to_clear : cleared_servers) {
    ssl_client_auth_cache_.Remove(server_to_clear);
  }

  if (ssl_client_session_cache_) {
    ssl_client_session_cache_->FlushForServers(cleared_servers);
  }

  NotifySSLConfigForServersChanged(cleared_servers);
}

void SSLClientContext::NotifySSLConfigChanged(SSLConfigChangeType change_type) {
  ClearHttppsSessions();
  for (Observer& observer : observers_) {
    observer.OnSSLConfigChanged(change_type);
  }
}

void SSLClientContext::NotifySSLConfigForServersChanged(
    const base::flat_set<HostPortPair>& servers) {
  // Client-identity changes invalidate pending ticket callbacks as well as
  // existing entries. Clearing this small cache is deliberately conservative.
  ClearHttppsSessions();
  for (Observer& observer : observers_) {
    observer.OnSSLConfigForServersChanged(servers);
  }
}

}  // namespace net
