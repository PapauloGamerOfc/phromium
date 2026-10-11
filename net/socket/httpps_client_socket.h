// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_HTTPPS_CLIENT_SOCKET_H_
#define NET_SOCKET_HTTPPS_CLIENT_SOCKET_H_

#include <memory>
#include <string>
#include <vector>

#include "base/memory/weak_ptr.h"
#include "base/functional/callback.h"
#include "base/timer/timer.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verify_result.h"
#include "net/httpps/draft01.h"
#include "net/socket/ssl_client_socket.h"
#include "net/ssl/ssl_info.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

// Native TLS 2.0 client. The SSLClientSocket interface is reused solely
// for Chromium's encrypted-stream plumbing; this is NOT standard TLS. Protocol
// version remains unknown in legacy SSLInfo; the URL's httpps scheme identifies
// the experimental channel. Only HTTP/1.1, browser/private CA trust and a
// resumption and replay-policy-gated 0-RTT are supported. Certificate exceptions
// cannot bypass it. Ticket ownership and cache partitioning belong to context.
class NET_EXPORT_PRIVATE HttppsClientSocket final : public SSLClientSocket {
 public:
  HttppsClientSocket(std::unique_ptr<StreamSocket> transport,
                     const HostPortPair& destination,
                     std::vector<std::string> trust_anchors,
                     CertVerifier* cert_verifier = nullptr,
                     std::optional<httpps::SessionTicket> session = std::nullopt,
                     base::RepeatingCallback<void(httpps::SessionTicket)>
                         ticket_callback = {},
                     bool early_data_enabled = false,
                     httpps::ClientOptions options = {},
                     std::optional<httpps::ClientCredential> credential = std::nullopt);
  ~HttppsClientSocket() override;

  int Connect(CompletionOnceCallback callback) override;
  int ConfirmHandshake(CompletionOnceCallback callback) override;
  void Disconnect() override;
  bool IsConnected() const override;
  bool IsConnectedAndIdle() const override;
  int GetPeerAddress(IPEndPoint* address) const override;
  int GetLocalAddress(IPEndPoint* address) const override;
  const NetLogWithSource& NetLog() const override;
  bool WasEverUsed() const override;
  NextProto GetNegotiatedProtocol() const override;
  bool GetSSLInfo(SSLInfo* ssl_info) override;
  int64_t GetTotalReceivedBytes() const override;
  void ApplySocketTag(const SocketTag& tag) override;
  int Read(IOBuffer* buffer,
           int length,
           CompletionOnceCallback callback) override;
  int Write(IOBuffer* buffer,
            int length,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& annotation) override;
  int SetReceiveBufferSize(int32_t size) override;
  int SetSendBufferSize(int32_t size) override;
  int ExportKeyingMaterial(std::string_view label,
                           std::optional<base::span<const uint8_t>> context,
                           base::span<uint8_t> out) override;
  std::vector<uint8_t> GetECHRetryConfigs() override;
  std::vector<std::vector<uint8_t>> GetServerTrustAnchorIDs() override;
  httpps::Authentication GetHttppsAuthentication() const;
  int ExportEarlyKeyingMaterial(std::string_view label,
      base::span<const uint8_t> context, base::span<uint8_t> out) override;
  bool RequestHttppsServerAuthenticator(httpps::ByteSpan context,
      const std::map<uint16_t, httpps::Bytes>& extensions,
      httpps::Bytes* request) override;
  bool CancelHttppsAuthenticator(httpps::ByteSpan request) override;
  bool CreateHttppsClientAuthenticator(httpps::ByteSpan request,
      const httpps::ClientCredential* credential,
      httpps::Bytes* authenticator) override;
  bool ValidateHttppsServerAuthenticator(httpps::ByteSpan authenticator,
      const httpps::AuthenticatorValidator& validator, bool* authenticated,
      httpps::ByteSpan exact_request = {}) override;

 private:
  int HandshakeLoop(int result);
  int BeginHandshake();
  int VerifySessionCertificate();
  int PopulateSSLInfo();
  int StartUserWrite();
  int FlushControlOutput(int result = OK);
  void ResumeAfterControlOutput();
  void SaveTickets();
  void FinishHandshakeOperation(int result);
  int ReadOneRecord(int result);
  int WriteRecord(int result);
  int ReadApplication(int result);
  int CopyApplicationData();
  int ProtocolError() const;
  int VerifyCertificate();
  int CompleteCertificateVerification(int result);
  void OnCertificateVerified(int result);
  int Abort(int error);
  void QueueWrite(httpps::Bytes bytes);
  void OnReadReady(int result);
  void OnWriteReady(int result);
  void OnTimeout();
  void DeliverFatalCallbacks();
  void BestEffortCloseNotify();

  std::unique_ptr<StreamSocket> transport_;
  HostPortPair destination_;
  std::vector<std::string> trust_anchors_;
  // Same verifier as HTTPS; owned by SSLClientContext, which outlives sockets.
  raw_ptr<CertVerifier> cert_verifier_;
  CertVerifyResult cert_verify_result_;
  std::unique_ptr<CertVerifier::Request> cert_verifier_request_;
  bool verified_with_browser_ = false;
  std::optional<httpps::SessionTicket> session_;
  base::RepeatingCallback<void(httpps::SessionTicket)> ticket_callback_;
  bool early_data_enabled_ = false;
  httpps::ClientOptions options_;
  std::optional<httpps::ClientCredential> credential_;
  bool early_connect_complete_ = false;
  bool early_data_sent_ = false;
  bool verifying_session_ = false;
  bool session_verified_ = false;
  std::string session_validated_issuer_;
  std::vector<std::string> session_validated_path_;
  bool confirming_ = false;
  bool handshake_waiting_for_write_ = false;
  bool write_waiting_for_handshake_ = false;
  bool control_writing_ = false;
  bool read_waiting_for_control_ = false;
  bool write_waiting_for_control_ = false;
  std::unique_ptr<httpps::Client> client_;
  SSLInfo ssl_info_;
  base::OneShotTimer handshake_timer_;
  CompletionOnceCallback connect_callback_, read_callback_, write_callback_;
  scoped_refptr<DrainableIOBuffer> raw_read_, raw_write_;
  httpps::Bytes record_, application_data_;
  httpps::Bytes control_output_;
  scoped_refptr<IOBuffer> user_read_buffer_;
  scoped_refptr<IOBuffer> user_write_buffer_;
  int user_read_length_ = 0;
  int user_write_length_ = 0;
  int64_t received_bytes_ = 0;
  int fatal_error_ = OK;
  bool reading_header_ = true;
  bool transport_read_pending_ = false;
  bool transport_write_pending_ = false;
  bool handshake_writing_ = true;
  bool connected_ = false;
  bool was_ever_used_ = false;
  MutableNetworkTrafficAnnotationTag write_annotation_;
  base::WeakPtrFactory<HttppsClientSocket> weak_factory_{this};
};

}  // namespace net

#endif  // NET_SOCKET_HTTPPS_CLIENT_SOCKET_H_
