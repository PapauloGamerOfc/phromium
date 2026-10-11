// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/httpps_client_socket.h"

#include <algorithm>
#include <utility>

#include "base/check.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/task/sequenced_task_runner.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/httpps/dnssec.h"
#include "net/httpps/certificate_features.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net {
namespace {

constexpr NetworkTrafficAnnotationTag kHandshakeAnnotation =
    DefineNetworkTrafficAnnotation("httpps_experimental_handshake", R"(
      semantics {
        sender: "Phromium experimental HTTPPS transport"
        description:
          "Authenticates an explicitly requested httpps URL using TLS 2.0. "
          "Certificate trust uses the browser HTTPS verifier or an explicitly "
          "configured additional private CA."
        trigger: "A user or page requests an httpps URL."
        data: "Server name, ephemeral keys and authenticated protocol messages."
        destination: WEBSITE
      }
      policy {
        cookies_allowed: NO
        setting:
          "Only explicit httpps requests use this experimental transport. "
          "Additional private trust anchors can be configured independently "
          "for sites and proxies."
        policy_exception_justification:
          "Not implemented as an enterprise production feature."
      })");

scoped_refptr<DrainableIOBuffer> ReadBuffer(size_t length) {
  return base::MakeRefCounted<DrainableIOBuffer>(
      base::MakeRefCounted<IOBufferWithSize>(length), length);
}

std::string_view LeafEvidence(
    const std::vector<std::map<uint16_t, httpps::Bytes>>& entries,
    uint16_t kind) {
  if (entries.empty())
    return {};
  const auto found = entries.front().find(kind);
  if (found == entries.front().end())
    return {};
  auto value = base::span(found->second);
  if (kind == 5) {
    if (value.size() < 5 || value[0] != 1 ||
        ((size_t(value[1]) << 16) | (size_t(value[2]) << 8) | value[3]) != value.size() - 4)
      return {};
    value = value.subspan(4u);
  }
  return std::string_view(reinterpret_cast<const char*>(value.data()), value.size());
}

bool RequiredEvidenceVerified(const std::vector<std::string>& certificates,
                              const std::vector<std::map<uint16_t, httpps::Bytes>>& extensions,
                              const CertVerifyResult& result,
                              const httpps::ClientOptions& options) {
  if (certificates.empty())
    return false;
  const auto required = httpps::CertificateRequiresFeature(certificates.front(), 5);
  const auto scts = httpps::CertificateRequiresFeature(certificates.front(), 18);
  return required && scts && (!*required || !options.request_ocsp ||
      (!LeafEvidence(extensions, 5).empty() &&
       result.ocsp_result.response_status == bssl::OCSPVerifyResult::PROVIDED &&
       result.ocsp_result.revocation_status == bssl::OCSPRevocationStatus::GOOD)) &&
      (!*scts || !options.request_scts ||
       (!LeafEvidence(extensions, 18).empty() &&
        std::any_of(result.scts.begin(), result.scts.end(), [](const auto& value) {
          return value.sct && value.status == ct::SCT_STATUS_OK &&
                 value.sct->origin == ct::SignedCertificateTimestamp::SCT_FROM_TLS_EXTENSION;
        })));
}

std::string VerifiedIssuer(const CertVerifyResult& result) {
  if (!result.verified_cert || result.verified_cert->intermediate_buffers().empty())
    return {};
  return std::string(x509_util::CryptoBufferAsStringPiece(
      result.verified_cert->intermediate_buffers().front().get()));
}

std::vector<std::string> VerifiedPath(const CertVerifyResult& result) {
  std::vector<std::string> path;
  if (!result.verified_cert)
    return path;
  path.emplace_back(x509_util::CryptoBufferAsStringPiece(result.verified_cert->cert_buffer()));
  for (const auto& der : result.verified_cert->intermediate_buffers())
    path.emplace_back(x509_util::CryptoBufferAsStringPiece(der.get()));
  return path;
}

}  // namespace

HttppsClientSocket::HttppsClientSocket(std::unique_ptr<StreamSocket> transport,
                                       const HostPortPair& destination,
                                       std::vector<std::string> trust_anchors,
                                       CertVerifier* cert_verifier,
    std::optional<httpps::SessionTicket> session,
    base::RepeatingCallback<void(httpps::SessionTicket)> ticket_callback,
    bool early_data_enabled,
    httpps::ClientOptions options,
    std::optional<httpps::ClientCredential> credential)
    : transport_(std::move(transport)),
      destination_(destination),
      trust_anchors_(std::move(trust_anchors)),
      cert_verifier_(cert_verifier),
      session_(std::move(session)),
      ticket_callback_(std::move(ticket_callback)),
      early_data_enabled_(early_data_enabled),
      options_(std::move(options)),
      credential_(std::move(credential)),
      write_annotation_(kHandshakeAnnotation) {
  // Use exactly the browser's current CT/revocation policy. Neither received
  // evidence nor the request extensions themselves confer trust.
  if (cert_verifier_) {
    options_.request_ocsp = true;
    options_.request_scts = true;
  }
  if (!options_.ocsp_responder_ids.empty() || !options_.ocsp_request_extensions.empty())
    options_.request_ocsp = true;
}

HttppsClientSocket::~HttppsClientSocket() {
  Disconnect();
}

int HttppsClientSocket::Connect(CompletionOnceCallback callback) {
  if (connected_) {
    return OK;
  }
  if (client_ || !transport_->IsConnected()) {
    return ERR_SOCKET_NOT_CONNECTED;
  }
  handshake_timer_.Start(FROM_HERE, base::Seconds(30),
                         base::BindOnce(&HttppsClientSocket::OnTimeout,
                                        weak_factory_.GetWeakPtr()));
  int result = session_ ? VerifySessionCertificate() : BeginHandshake();
  if (result == ERR_IO_PENDING) {
    connect_callback_ = std::move(callback);
  }
  return result;
}

int HttppsClientSocket::BeginHandshake() {
  if (!options_.ordinary_httpps || options_.allow_unauthenticated || options_.allow_integrity_only ||
      (options_.dane_policy && options_.dane_policy->port != destination_.port()) ||
      (options_.bootstrap && options_.bootstrap->provisioning_trust))
    return Abort(ERR_SSL_PROTOCOL_ERROR);
  client_ = std::make_unique<httpps::Client>(
      destination_.host(), trust_anchors_, cert_verifier_ != nullptr, options_);
  if (credential_ && !client_->SetClientCredential(*credential_))
    return Abort(ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT);
  if (!client_->Start(session_ ? &*session_ : nullptr, {},
                      early_data_enabled_ && session_verified_))
    return Abort(ProtocolError());
  QueueWrite(client_->TakeOutput());
  return HandshakeLoop(OK);
}

int HttppsClientSocket::VerifySessionCertificate() {
  if (session_->server_certificate_type == 2 || session_->server_certificate_type == 3 ||
      session_->authentication == httpps::Authentication::kExternalPsk ||
      session_->authentication == httpps::Authentication::kPassword) {
    // Start rechecks the exact origin's current pins/provisioned secret before
    // emitting CH or early data. No CA exception is manufactured for raw keys.
    session_verified_ = true;
    return BeginHandshake();
  }
  httpps::Secret unused;
  const auto required_evidence = session_->certificates.empty() ? std::nullopt
      : httpps::CertificateRequiresBrowserEvidence(session_->certificates.front(),
                                                   options_.request_ocsp, options_.request_scts);
  session_validated_path_ = httpps::ValidatedPrivatePath(session_->certificates,
      trust_anchors_, destination_.host(), !session_->delegation.empty(), options_.native_provider.get());
  const auto dane = httpps::VerifyDNSSECPolicy(options_.dane_policy.get(), destination_.host(),
      session_->certificates, session_->server_certificate_type, session_->certificate_extensions,
      session_validated_path_);
  if (options_.dane_policy && dane && *dane >= 0 && !options_.ct_v2_policy &&
      required_evidence && !*required_evidence) {
    session_verified_ = true;
    return BeginHandshake();
  }
  if (required_evidence && !*required_evidence && !trust_anchors_.empty() &&
      httpps::VerifyLabChain(session_->certificates, trust_anchors_,
                             destination_.host(), &unused, !session_->delegation.empty(), options_.native_provider.get())) {
    session_validated_issuer_ = httpps::ValidatedPrivateIssuer(session_->certificates,
        trust_anchors_, destination_.host(), !session_->delegation.empty(), options_.native_provider.get());
    if (!dane || !httpps::CertificateTLSFeaturesAllowed(session_validated_path_) ||
        !httpps::CertificateAlgorithmsAllowed(session_validated_path_, options_.certificate_signature_algorithms) ||
        !httpps::VerifyCertificateTransparency(options_.ct_v2_policy.get(), session_->certificates,
          session_->certificate_extensions, session_validated_issuer_)) {
      session_.reset();
      session_validated_issuer_.clear();
      return BeginHandshake();
    }
    session_verified_ = true;
    return BeginHandshake();
  }
  std::vector<std::string_view> chain;
  for (const auto& der : session_->certificates)
    chain.push_back(der);
  auto certificate = X509Certificate::CreateFromDERCertChain(chain);
  if (!certificate || !cert_verifier_) {
    session_.reset();
    return BeginHandshake();
  }
  verifying_session_ = true;
  CertVerifier::RequestParams params(
      certificate, destination_.host(),
      (session_->delegation.empty() ? CertVerifier::VERIFY_HTTPPS_SERVER : 0) |
          CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES,
      LeafEvidence(session_->certificate_extensions, 5),
      LeafEvidence(session_->certificate_extensions, 18));
  int result = cert_verifier_->Verify(
      params, &cert_verify_result_,
      base::BindOnce(&HttppsClientSocket::OnCertificateVerified,
                     weak_factory_.GetWeakPtr()),
      &cert_verifier_request_, NetLog());
  return result == ERR_IO_PENDING ? result
                                  : CompleteCertificateVerification(result);
}

int HttppsClientSocket::ConfirmHandshake(CompletionOnceCallback callback) {
  CHECK(!connect_callback_);
  if (!connected_ || !client_)
    return fatal_error_ < 0 ? fatal_error_ : ERR_SOCKET_NOT_CONNECTED;
  if (client_->established())
    return OK;
  confirming_ = true;
  int result;
  if (raw_write_ || transport_read_pending_ || cert_verifier_request_) {
    handshake_waiting_for_write_ = raw_write_ != nullptr;
    result = ERR_IO_PENDING;
  } else {
    result = HandshakeLoop(OK);
  }
  if (result == ERR_IO_PENDING)
    connect_callback_ = std::move(callback);
  return result;
}

int HttppsClientSocket::PopulateSSLInfo() {
  const auto authentication = GetHttppsAuthentication();
  const bool x509 = authentication == httpps::Authentication::kCertificate ||
                    authentication == httpps::Authentication::kCertificateAndPsk;
  std::vector<std::string_view> certificates;
  const auto& chain = client_->established() ? client_->certificates()
                                            : session_->certificates;
  for (const auto& der : chain)
    certificates.push_back(der);
  if (x509) {
    ssl_info_.unverified_cert = X509Certificate::CreateFromDERCertChain(certificates);
    ssl_info_.cert = verified_with_browser_ ? cert_verify_result_.verified_cert
                                           : ssl_info_.unverified_cert;
    if (!ssl_info_.cert)
      return Abort(ERR_SSL_SERVER_CERT_BAD_FORMAT);
  } else {
    ssl_info_ = SSLInfo();
  }
  if (x509 && verified_with_browser_) {
    ssl_info_.cert_status = cert_verify_result_.cert_status;
    ssl_info_.is_issued_by_known_root = cert_verify_result_.is_issued_by_known_root;
    ssl_info_.public_key_hashes = cert_verify_result_.public_key_hashes;
    ssl_info_.signed_certificate_timestamps = cert_verify_result_.scts;
    ssl_info_.ct_policy_compliance = cert_verify_result_.policy_compliance;
#if BUILDFLAG(CHROME_ROOT_STORE_SUPPORTED)
    ssl_info_.crs_root_id = cert_verify_result_.crs_root_id;
#endif
  }
  ssl_info_.key_exchange_group = client_->traffic_group();
  ssl_info_.handshake_type = (client_->established() ? client_->resumed()
                                                   : early_connect_complete_)
                                ? SSLInfo::HANDSHAKE_RESUME
                                : SSLInfo::HANDSHAKE_FULL;
  ssl_info_.early_data_accepted = client_->early_data_accepted();
  ssl_info_.peer_signature_algorithm = authentication != httpps::Authentication::kExternalPsk &&
      authentication != httpps::Authentication::kPassword ? 0xfe00 : 0;
  // UNKNOWN standard version: this is not TLS 1.3 despite the AEAD identifier.
  SSLConnectionStatusSetCipherSuite(
      client_->negotiated_alpn().empty() && session_ ? session_->cipher_suite
                                                    : client_->cipher_suite(),
      &ssl_info_.connection_status);
  ssl_info_.connection_status |= SSL_CONNECTION_HTTPPS;
  if (authentication != httpps::Authentication::kCertificate || credential_)
    ssl_info_.connection_status |= SSL_CONNECTION_HTTPPS_EXPLICIT_IDENTITY;
  ssl_info_.client_cert_sent = client_->client_identity_authenticated();
  return OK;
}

void HttppsClientSocket::SaveTickets() {
  for (auto& ticket : client_->TakeTickets()) {
    if (ticket_callback_)
      ticket_callback_.Run(std::move(ticket));
  }
}

void HttppsClientSocket::QueueWrite(httpps::Bytes bytes) {
  size_t size = bytes.size();
  raw_write_ = base::MakeRefCounted<DrainableIOBuffer>(
      base::MakeRefCounted<VectorIOBuffer>(std::move(bytes)), size);
}

int HttppsClientSocket::WriteRecord(int result) {
  if (transport_write_pending_) {
    transport_write_pending_ = false;
    if (result <= 0) {
      return result == 0 ? ERR_CONNECTION_CLOSED : result;
    }
    raw_write_->DidConsume(result);
  }
  while (raw_write_->BytesRemaining()) {
    result = transport_->Write(raw_write_.get(), raw_write_->BytesRemaining(),
                               base::BindOnce(&HttppsClientSocket::OnWriteReady,
                                              weak_factory_.GetWeakPtr()),
                               NetworkTrafficAnnotationTag(write_annotation_));
    if (result == ERR_IO_PENDING) {
      transport_write_pending_ = true;
      return result;
    }
    if (result <= 0) {
      return result == 0 ? ERR_CONNECTION_CLOSED : result;
    }
    raw_write_->DidConsume(result);
  }
  raw_write_.reset();
  return OK;
}

int HttppsClientSocket::ReadOneRecord(int result) {
  if (transport_read_pending_) {
    transport_read_pending_ = false;
    if (result <= 0) {
      // EOF without authenticated close_notify is never clean closure.
      return result == 0 ? ERR_CONNECTION_CLOSED : result;
    }
    raw_read_->DidConsume(result);
  }
  for (;;) {
    if (!raw_read_) {
      reading_header_ = true;
      record_.clear();
      raw_read_ = ReadBuffer(5);
    }
    if (!raw_read_->BytesRemaining()) {
      int size = raw_read_->BytesConsumed();
      raw_read_->SetOffset(0);
      auto bytes = raw_read_->span().first(static_cast<size_t>(size));
      record_.insert(record_.end(), bytes.begin(), bytes.end());
      if (!reading_header_) {
        raw_read_.reset();
        return OK;
      }
      size_t length = (static_cast<size_t>(record_[3]) << 8) | record_[4];
      if ((record_[0] == 23 && (record_[1] != 3 || record_[2] != 3)) || length == 0 ||
          length > httpps::kMaxRecord - 5) {
        return ERR_SSL_PROTOCOL_ERROR;
      }
      reading_header_ = false;
      raw_read_ = ReadBuffer(length);
    }
    result = transport_->Read(raw_read_.get(), raw_read_->BytesRemaining(),
                              base::BindOnce(&HttppsClientSocket::OnReadReady,
                                             weak_factory_.GetWeakPtr()));
    if (result == ERR_IO_PENDING) {
      transport_read_pending_ = true;
      return result;
    }
    if (result <= 0) {
      return result == 0 ? ERR_CONNECTION_CLOSED : result;
    }
    raw_read_->DidConsume(result);
  }
}

int HttppsClientSocket::HandshakeLoop(int result) {
  for (;;) {
    if (handshake_writing_) {
      result = WriteRecord(result);
      if (result == ERR_IO_PENDING) {
        return result;
      }
      if (result < 0 || !client_->OutputFlushed()) {
        return Abort(result < 0 ? result : ProtocolError());
      }
      handshake_writing_ = false;
      if (client_->established()) {
        if (early_data_sent_ && !client_->early_data_accepted())
          return Abort(ERR_EARLY_DATA_REJECTED);
        if (int error = PopulateSSLInfo(); error != OK)
          return error;
        connected_ = true;
        confirming_ = false;
        handshake_waiting_for_write_ = false;
        handshake_timer_.Stop();
        return OK;
      }
      if (!confirming_ && !early_connect_complete_ &&
          client_->early_data_available()) {
        // Chromium's HTTP stream calls ConfirmHandshake before non-replay-safe
        // methods. Do not eagerly send a request or retry one in this layer.
        early_connect_complete_ = true;
        connected_ = true;
        return PopulateSSLInfo();
      }
    }
    result = ReadOneRecord(result);
    if (result == ERR_IO_PENDING) {
      return result;
    }
    httpps::Bytes unused;
    if (result < 0 || !client_->Receive(record_, &unused)) {
      return Abort(result < 0 ? result : ProtocolError());
    }
    if (session_ && !client_->resumed() && !client_->certificates().empty()) {
      // PSK rejection starts a new authenticated identity. Never expose cached
      // verifier metadata as if it described this fresh certificate chain.
      session_.reset();
      session_verified_ = verified_with_browser_ = false;
      cert_verify_result_.Reset();
    }
    if (client_->certificate_verification_pending()) {
      result = client_->resumed() && session_verified_
                   ? (client_->CompleteCertificateVerification(true, session_validated_issuer_, session_validated_path_)
                          ? OK : Abort(ProtocolError()))
                   : VerifyCertificate();
      if (result != OK) {
        return result;
      }
    }
    auto output = client_->TakeOutput();
    if (!output.empty()) {
      QueueWrite(std::move(output));
      handshake_writing_ = true;
    }
    result = OK;
  }
}

int HttppsClientSocket::VerifyCertificate() {
  CHECK(cert_verifier_);
  std::vector<std::string_view> certificates;
  for (const auto& der : client_->certificates()) {
    certificates.push_back(der);
  }
  auto certificate = X509Certificate::CreateFromDERCertChain(certificates);
  if (!certificate) {
    return Abort(ERR_SSL_SERVER_CERT_BAD_FORMAT);
  }
  // In particular proxy verification must never recursively fetch through the
  // connection currently being authenticated. Full chains are sent by peers.
  CertVerifier::RequestParams params(
      certificate, destination_.host(),
      (client_->delegated() ? 0 : CertVerifier::VERIFY_HTTPPS_SERVER) |
          CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES,
      LeafEvidence(client_->certificate_extensions(), 5),
      LeafEvidence(client_->certificate_extensions(), 18));
  const int result = cert_verifier_->Verify(
      params, &cert_verify_result_,
      base::BindOnce(&HttppsClientSocket::OnCertificateVerified,
                     weak_factory_.GetWeakPtr()),
      &cert_verifier_request_, NetLog());
  return result == ERR_IO_PENDING ? result
                                  : CompleteCertificateVerification(result);
}

int HttppsClientSocket::CompleteCertificateVerification(int result) {
  cert_verifier_request_.reset();
  if (verifying_session_) {
    verifying_session_ = false;
    session_validated_issuer_ = VerifiedIssuer(cert_verify_result_);
    session_validated_path_ = VerifiedPath(cert_verify_result_);
    session_verified_ = result == OK && cert_verify_result_.verified_cert &&
                        httpps::CertificateTLSFeaturesAllowed(session_validated_path_) &&
                        httpps::CertificateAlgorithmsAllowed(session_validated_path_, options_.certificate_signature_algorithms) &&
                        !IsCertStatusError(cert_verify_result_.cert_status) &&
                        RequiredEvidenceVerified(session_->certificates, session_->certificate_extensions,
                                                 cert_verify_result_, options_) &&
                        httpps::VerifyCertificateTransparency(options_.ct_v2_policy.get(),
                            session_->certificates, session_->certificate_extensions,
                            session_validated_issuer_) &&
                        httpps::VerifyDNSSECPolicy(options_.dane_policy.get(), destination_.host(),
                            session_->certificates, session_->server_certificate_type,
                            session_->certificate_extensions, session_validated_path_).has_value();
    verified_with_browser_ = session_verified_;
    // Rejected/stale cached credentials cannot authorize PSK/0-RTT. A fresh
    // certificate handshake may succeed after a legitimate certificate change.
    if (!session_verified_) {
      session_.reset();
      session_validated_issuer_.clear();
      cert_verify_result_.Reset();
    }
    return BeginHandshake();
  }
  if (result != OK || !cert_verify_result_.verified_cert ||
      IsCertStatusError(cert_verify_result_.cert_status) ||
      !RequiredEvidenceVerified(client_->certificates(), client_->certificate_extensions(),
                                cert_verify_result_, options_)) {
    // No certificate-error clickthrough, ignore-certificate-errors, fallback
    // to another trust path, or application traffic after a rejected decision.
    client_->CompleteCertificateVerification(false);
    return Abort(ERR_SSL_SERVER_CERT_BAD_FORMAT);
  }
  if (!client_->CompleteCertificateVerification(true, VerifiedIssuer(cert_verify_result_),
                                                 VerifiedPath(cert_verify_result_))) {
    return Abort(ProtocolError());
  }
  verified_with_browser_ = true;
  return OK;
}

void HttppsClientSocket::OnCertificateVerified(int result) {
  if (fatal_error_ != OK || (!client_ && !verifying_session_)) {
    return;
  }
  const bool session_decision = verifying_session_;
  result = CompleteCertificateVerification(result);
  if (result == OK && !session_decision) {
    auto output = client_->TakeOutput();
    if (!output.empty()) {
      QueueWrite(std::move(output));
      handshake_writing_ = true;
    }
    result = HandshakeLoop(OK);
  }
  FinishHandshakeOperation(result);
}

void HttppsClientSocket::FinishHandshakeOperation(int result) {
  if (result == ERR_IO_PENDING)
    return;
  auto weak = weak_factory_.GetWeakPtr();
  const bool finish_read = static_cast<bool>(read_callback_);
  const bool finish_write = write_waiting_for_handshake_ && write_callback_;
  if (connect_callback_) {
    std::move(connect_callback_).Run(result);
  }
  if (!weak)
    return;
  if (finish_write && write_waiting_for_handshake_ && write_callback_) {
    write_waiting_for_handshake_ = false;
    int written = result == OK ? StartUserWrite() : result;
    if (written != ERR_IO_PENDING) {
      user_write_buffer_.reset();
      std::move(write_callback_).Run(written);
    }
  }
  if (!weak)
    return;
  if (finish_read && read_callback_) {
    if (result == OK)
      result = ReadApplication(OK);
    if (result != ERR_IO_PENDING) {
      user_read_buffer_.reset();
      std::move(read_callback_).Run(result);
    }
  }
}

int HttppsClientSocket::ProtocolError() const {
  if (!client_) {
    return ERR_SSL_PROTOCOL_ERROR;
  }
  switch (client_->error()) {
    case httpps::Client::Error::kCertificate:
      // Return a fatal protocol error, not an overridable certificate error.
      // The certificate exception UI must never bypass HTTPPS trust checks.
      return ERR_SSL_SERVER_CERT_BAD_FORMAT;
    case httpps::Client::Error::kTimeout:
      return ERR_TIMED_OUT;
    default:
      return ERR_SSL_PROTOCOL_ERROR;
  }
}

int HttppsClientSocket::Abort(int error) {
  if (fatal_error_ == OK) {
    if (client_ && !raw_write_ && control_output_.empty()) {
      auto alert = client_->TakeFatalAlert();
      if (!alert.empty()) {
        auto buffer = base::MakeRefCounted<VectorIOBuffer>(std::move(alert));
        transport_->Write(buffer.get(), buffer->size(),
            base::BindOnce([](scoped_refptr<IOBuffer>, int) {}, buffer), kHandshakeAnnotation);
      }
    }
    fatal_error_ = error;
    connected_ = false;
    handshake_timer_.Stop();
    // Cancel queued empty-record continuations and transport completions before
    // clearing their state. Failure notifications below get a new generation.
    weak_factory_.InvalidateWeakPtrs();
    cert_verifier_request_.reset();
    transport_->Disconnect();
    transport_read_pending_ = transport_write_pending_ = false;
    raw_read_.reset();
    raw_write_.reset();
    user_write_buffer_.reset();
    client_.reset();
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&HttppsClientSocket::DeliverFatalCallbacks,
                                  weak_factory_.GetWeakPtr()));
  }
  return error;
}

void HttppsClientSocket::DeliverFatalCallbacks() {
  auto weak = weak_factory_.GetWeakPtr();
  if (connect_callback_) {
    std::move(connect_callback_).Run(fatal_error_);
  }
  if (!weak) {
    return;
  }
  if (read_callback_) {
    user_read_buffer_.reset();
    std::move(read_callback_).Run(fatal_error_);
  }
  if (!weak) {
    return;
  }
  if (write_callback_) {
    user_write_buffer_.reset();
    std::move(write_callback_).Run(fatal_error_);
  }
}

void HttppsClientSocket::OnTimeout() {
  Abort(ERR_TIMED_OUT);
}

void HttppsClientSocket::OnReadReady(int result) {
  if (fatal_error_ != OK || !client_) {
    return;
  }
  if (!client_->established()) {
    result = HandshakeLoop(result);
    FinishHandshakeOperation(result);
    return;
  }
  result = ReadApplication(result);
  if (result != ERR_IO_PENDING) {
    user_read_buffer_.reset();
    std::move(read_callback_).Run(result);
  }
}

void HttppsClientSocket::OnWriteReady(int result) {
  if (fatal_error_ != OK || !client_) {
    return;
  }
  if ((!early_connect_complete_ && !connected_) || handshake_writing_) {
    result = HandshakeLoop(result);
    FinishHandshakeOperation(result);
    return;
  }
  if (control_writing_) {
    result = FlushControlOutput(result);
    if (result != ERR_IO_PENDING)
      ResumeAfterControlOutput();
    return;
  }
  result = WriteRecord(result);
  if (result != ERR_IO_PENDING) {
    if (result < 0) {
      Abort(result);
    }
    user_write_buffer_.reset();
    auto weak = weak_factory_.GetWeakPtr();
    std::move(write_callback_).Run(result < 0 ? result : user_write_length_);
    if (weak && result == OK && !control_output_.empty()) {
      if (FlushControlOutput() != ERR_IO_PENDING)
        ResumeAfterControlOutput();
    }
    if (weak && result == OK && handshake_waiting_for_write_) {
      handshake_waiting_for_write_ = false;
      if (!transport_read_pending_ && !cert_verifier_request_)
        FinishHandshakeOperation(HandshakeLoop(OK));
    }
  }
}

int HttppsClientSocket::FlushControlOutput(int result) {
  if (raw_write_ && !control_writing_)
    return ERR_IO_PENDING;  // Never replace a partially emitted user record.
  if (control_writing_) {
    result = WriteRecord(result);
    if (result == ERR_IO_PENDING)
      return result;
    control_writing_ = false;
    if (result < 0)
      return Abort(result);
  }
  while (!control_output_.empty()) {
    QueueWrite(std::exchange(control_output_, {}));
    control_writing_ = true;
    result = WriteRecord(OK);
    if (result == ERR_IO_PENDING)
      return result;
    control_writing_ = false;
    if (result < 0)
      return Abort(result);
  }
  return OK;
}

void HttppsClientSocket::ResumeAfterControlOutput() {
  if (fatal_error_ != OK)
    return;
  auto weak = weak_factory_.GetWeakPtr();
  const bool resume_read = read_waiting_for_control_ && read_callback_;
  if (write_waiting_for_control_ && write_callback_) {
    write_waiting_for_control_ = false;
    int result = StartUserWrite();
    if (result != ERR_IO_PENDING) {
      user_write_buffer_.reset();
      std::move(write_callback_).Run(result);
    }
  }
  if (!weak)
    return;
  if (resume_read && read_waiting_for_control_ && read_callback_) {
    read_waiting_for_control_ = false;
    int result = ReadApplication(OK);
    if (result != ERR_IO_PENDING) {
      user_read_buffer_.reset();
      std::move(read_callback_).Run(result);
    }
  }
}

int HttppsClientSocket::CopyApplicationData() {
  size_t length = std::min(static_cast<size_t>(user_read_length_),
                           application_data_.size());
  user_read_buffer_->span().first(length).copy_from(
      base::span(application_data_).first(length));
  application_data_.erase(application_data_.begin(),
                          application_data_.begin() + length);
  received_bytes_ += length;
  return static_cast<int>(length);
}

int HttppsClientSocket::ReadApplication(int result) {
  if (!client_->established()) {
    confirming_ = true;
    if (raw_write_ || transport_read_pending_ || cert_verifier_request_) {
      handshake_waiting_for_write_ = raw_write_ != nullptr;
      return ERR_IO_PENDING;
    }
    result = HandshakeLoop(result);
    if (result != OK)
      return result;
  }
  if (!application_data_.empty()) {
    return CopyApplicationData();
  }
  if (client_->closed()) {
    return 0;
  }
  for (size_t count = 0; count < 64; ++count) {
    result = ReadOneRecord(result);
    if (result == ERR_IO_PENDING) {
      return result;
    }
    if (result < 0 || !client_->Receive(record_, &application_data_)) {
      return Abort(result < 0 ? result : ProtocolError());
    }
    SaveTickets();
    auto control = client_->TakeOutput();
    control_output_.insert(control_output_.end(), control.begin(), control.end());
    if (!control_output_.empty() || control_writing_) {
      result = FlushControlOutput();
      if (result == ERR_IO_PENDING) {
        read_waiting_for_control_ = true;
        return result;
      }
      if (result < 0)
        return result;
    }
    if (client_->closed()) {
      return 0;
    }
    if (!application_data_.empty()) {
      return CopyApplicationData();
    }
    result = OK;
  }
  // Valid empty records must not monopolize the network service's task runner.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&HttppsClientSocket::OnReadReady,
                                weak_factory_.GetWeakPtr(), OK));
  return ERR_IO_PENDING;
}

int HttppsClientSocket::Read(IOBuffer* buffer,
                             int length,
                             CompletionOnceCallback callback) {
  CHECK(!read_callback_);
  CHECK_GT(length, 0);
  if (!connected_) {
    return fatal_error_ < 0 ? fatal_error_ : ERR_SOCKET_NOT_CONNECTED;
  }
  was_ever_used_ = true;
  user_read_buffer_ = buffer;
  user_read_length_ = length;
  int result = ReadApplication(OK);
  if (result == ERR_IO_PENDING) {
    read_callback_ = std::move(callback);
  } else {
    user_read_buffer_.reset();
  }
  return result;
}

int HttppsClientSocket::Write(IOBuffer* buffer,
                              int length,
                              CompletionOnceCallback callback,
                              const NetworkTrafficAnnotationTag& annotation) {
  CHECK(!write_callback_);
  CHECK_GT(length, 0);
  if (!connected_) {
    return fatal_error_ < 0 ? fatal_error_ : ERR_SOCKET_NOT_CONNECTED;
  }
  was_ever_used_ = true;
  // Socket::Write retains the caller's buffer until completion/cancellation,
  // even though the record layer makes its own encrypted copy immediately.
  user_write_buffer_ = buffer;
  user_write_length_ =
      std::min(length, static_cast<int>(client_->max_send_content()));
  write_annotation_ = MutableNetworkTrafficAnnotationTag(annotation);
  if (control_writing_ || !control_output_.empty()) {
    write_waiting_for_control_ = true;
    write_callback_ = std::move(callback);
    return ERR_IO_PENDING;
  }
  if (!client_->established() &&
      (!client_->early_data_available() || raw_write_ || confirming_ ||
       transport_read_pending_ || cert_verifier_request_)) {
    // The peer flight/Finished may already be in progress on a simultaneous
    // Read or ConfirmHandshake. Preserve the caller's buffer and serialize this
    // application record after CF; never replace a partially written record.
    write_waiting_for_handshake_ = true;
    write_callback_ = std::move(callback);
    return ERR_IO_PENDING;
  }
  int result = StartUserWrite();
  if (result == ERR_IO_PENDING) {
    write_callback_ = std::move(callback);
    return result;
  }
  user_write_buffer_.reset();
  return result;
}

int HttppsClientSocket::StartUserWrite() {
  httpps::Bytes record;
  auto plaintext =
      user_write_buffer_->span().first(static_cast<size_t>(user_write_length_));
  const bool early = !client_->established();
  if (!(early ? client_->SendEarlyData(plaintext, &record)
               : client_->Send(plaintext, &record))) {
    return Abort(early ? ERR_EARLY_DATA_REJECTED : ProtocolError());
  }
  early_data_sent_ |= early;
  QueueWrite(std::move(record));
  int result = WriteRecord(OK);
  if (result == ERR_IO_PENDING)
    return result;
  return result < 0 ? Abort(result) : user_write_length_;
}

void HttppsClientSocket::BestEffortCloseNotify() {
  // StreamSocket::Disconnect is synchronous cancellation, not an asynchronous
  // TLS shutdown API. Send the authenticated alert only when no write is in
  // flight. Never interleave an alert into a partially written record.
  httpps::Bytes close;
  if (!raw_write_ && !control_writing_ && control_output_.empty() && client_ && client_->Close(&close)) {
    auto buffer = base::MakeRefCounted<VectorIOBuffer>(std::move(close));
    transport_->Write(
        buffer.get(), buffer->size(),
        base::BindOnce([](scoped_refptr<IOBuffer>, int) {}, buffer),
        kHandshakeAnnotation);
  }
}

void HttppsClientSocket::Disconnect() {
  BestEffortCloseNotify();
  transport_->Disconnect();
  handshake_timer_.Stop();
  weak_factory_.InvalidateWeakPtrs();
  cert_verifier_request_.reset();
  cert_verify_result_.Reset();
  verified_with_browser_ = false;
  session_.reset();
  early_connect_complete_ = early_data_sent_ = false;
  verifying_session_ = session_verified_ = confirming_ = false;
  session_validated_issuer_.clear();
  session_validated_path_.clear();
  handshake_waiting_for_write_ = false;
  write_waiting_for_handshake_ = false;
  control_output_.clear();
  control_writing_ = read_waiting_for_control_ = write_waiting_for_control_ = false;
  connected_ = false;
  connect_callback_.Reset();
  read_callback_.Reset();
  write_callback_.Reset();
  raw_read_.reset();
  raw_write_.reset();
  user_read_buffer_.reset();
  user_write_buffer_.reset();
  client_.reset();
  application_data_.clear();
  record_.clear();
  ssl_info_ = SSLInfo();
  received_bytes_ = 0;
  fatal_error_ = OK;
  reading_header_ = handshake_writing_ = true;
  transport_read_pending_ = transport_write_pending_ = false;
}

bool HttppsClientSocket::IsConnected() const {
  return connected_ && client_ &&
         (!application_data_.empty() ||
          (!client_->closed() && transport_->IsConnected()));
}
bool HttppsClientSocket::IsConnectedAndIdle() const {
  return IsConnected() && !read_callback_ && !write_callback_ &&
         application_data_.empty() && !raw_read_ && !raw_write_ &&
         (client_->early_data_available() || transport_->IsConnectedAndIdle());
}
int HttppsClientSocket::GetPeerAddress(IPEndPoint* address) const {
  return transport_->GetPeerAddress(address);
}
int HttppsClientSocket::GetLocalAddress(IPEndPoint* address) const {
  return transport_->GetLocalAddress(address);
}
const NetLogWithSource& HttppsClientSocket::NetLog() const {
  return transport_->NetLog();
}
bool HttppsClientSocket::WasEverUsed() const {
  return was_ever_used_;
}
NextProto HttppsClientSocket::GetNegotiatedProtocol() const {
  const std::string protocol = client_ && !client_->negotiated_alpn().empty()
      ? client_->negotiated_alpn() : session_ ? session_->alpn : "http/1.1";
  return protocol == "h2" ? NextProto::kProtoHTTP2 : NextProto::kProtoHTTP11;
}
bool HttppsClientSocket::GetSSLInfo(SSLInfo* info) {
  if (!SSLConnectionStatusIsHttpps(ssl_info_.connection_status)) {
    return false;
  }
  *info = ssl_info_;
  info->client_cert_sent = client_->client_identity_authenticated();
  return true;
}
httpps::Authentication HttppsClientSocket::GetHttppsAuthentication() const {
  return client_ && client_->established() ? client_->authentication()
      : session_ ? session_->authentication : httpps::Authentication::kCertificate;
}
int64_t HttppsClientSocket::GetTotalReceivedBytes() const {
  return received_bytes_;
}
void HttppsClientSocket::ApplySocketTag(const SocketTag& tag) {
  transport_->ApplySocketTag(tag);
}
int HttppsClientSocket::SetReceiveBufferSize(int32_t size) {
  return transport_->SetReceiveBufferSize(size);
}
int HttppsClientSocket::SetSendBufferSize(int32_t size) {
  return transport_->SetSendBufferSize(size);
}
int HttppsClientSocket::ExportKeyingMaterial(
    std::string_view label,
    std::optional<base::span<const uint8_t>> context,
    base::span<uint8_t> out) {
  httpps::Bytes bytes;
  if (!client_ || !client_->Export(label, context.value_or(base::span<const uint8_t>()),
                                  out.size(), &bytes))
    return ERR_SOCKET_NOT_CONNECTED;
  out.copy_from(bytes);
  OPENSSL_cleanse(bytes.data(), bytes.size());
  return OK;
}
int HttppsClientSocket::ExportEarlyKeyingMaterial(
    std::string_view label, base::span<const uint8_t> context,
    base::span<uint8_t> out) {
  httpps::Bytes bytes;
  if (!client_ || fatal_error_ != OK || !transport_->IsConnected() ||
      !client_->ExportEarly(label, context, out.size(), &bytes))
    return ERR_SOCKET_NOT_CONNECTED;
  out.copy_from(bytes);
  OPENSSL_cleanse(bytes.data(), bytes.size());
  return OK;
}
bool HttppsClientSocket::RequestHttppsServerAuthenticator(
    httpps::ByteSpan context,
    const std::map<uint16_t, httpps::Bytes>& extensions, httpps::Bytes* request) {
  return IsConnected() && client_ && client_->established() && request &&
      client_->RequestServerAuthenticator(context, extensions, request);
}
bool HttppsClientSocket::CancelHttppsAuthenticator(httpps::ByteSpan request) {
  return IsConnected() && client_ && client_->established() &&
      client_->CancelAuthenticator(request);
}
bool HttppsClientSocket::CreateHttppsClientAuthenticator(
    httpps::ByteSpan request, const httpps::ClientCredential* credential,
    httpps::Bytes* authenticator) {
  return IsConnected() && client_ && client_->established() && authenticator &&
      client_->AuthenticateClient(request, credential, authenticator);
}
bool HttppsClientSocket::ValidateHttppsServerAuthenticator(
    httpps::ByteSpan authenticator, const httpps::AuthenticatorValidator& validator,
    bool* authenticated, httpps::ByteSpan exact_request) {
  if (authenticated) *authenticated = false;
  return IsConnected() && client_ && client_->established() && authenticated &&
      validator && client_->ValidateServerAuthenticator(
          authenticator, validator, authenticated, exact_request);
}
std::vector<uint8_t> HttppsClientSocket::GetECHRetryConfigs() {
  return {};
}
std::vector<std::vector<uint8_t>>
HttppsClientSocket::GetServerTrustAnchorIDs() {
  return {};
}

}  // namespace net
