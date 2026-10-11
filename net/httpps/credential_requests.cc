// Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
#include "net/httpps/draft01.h"

#include <algorithm>
#include <set>

#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

namespace net::httpps {
namespace {
constexpr unsigned Explicit(unsigned tag) {
  return CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | tag;
}
ByteSpan BytesOf(const CBS& value) {
  return ByteSpan(static_cast<bssl::Span<const uint8_t>>(value));
}
bool Equal(ByteSpan a, ByteSpan b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}
bool NameValid(ByteSpan value) {
  if (value.empty() || value.size() > 65535) return false;
  const uint8_t* cursor = value.data();
  bssl::UniquePtr<X509_NAME> name(d2i_X509_NAME(nullptr, &cursor, value.size()));
  if (!name || cursor != value.subspan(value.size()).data()) return false;
  const int size = i2d_X509_NAME(name.get(), nullptr);
  if (size <= 0 || static_cast<size_t>(size) != value.size()) return false;
  Bytes canonical(size); auto* output = canonical.data();
  return i2d_X509_NAME(name.get(), &output) == size && Equal(value, canonical);
}
bool ResponderValid(ByteSpan value) {
  CBS input, content, key;
  CBS_init(&input, value.data(), value.size());
  if (CBS_peek_asn1_tag(&input, Explicit(1)))
    return CBS_get_asn1(&input, &content, Explicit(1)) && !CBS_len(&input) && NameValid(BytesOf(content));
  return CBS_get_asn1(&input, &content, Explicit(2)) && !CBS_len(&input) &&
      CBS_get_asn1(&content, &key, CBS_ASN1_OCTETSTRING) && !CBS_len(&content) && CBS_len(&key) == 20;
}
bool Extensions(ByteSpan value, std::optional<Bytes>* nonce) {
  nonce->reset();
  if (value.empty()) return true;
  CBS input, sequence;
  CBS_init(&input, value.data(), value.size());
  if (!CBS_get_asn1(&input, &sequence, CBS_ASN1_SEQUENCE) || CBS_len(&input) || !CBS_len(&sequence)) return false;
  std::set<Bytes> seen;
  const Bytes nonce_oid{0x2b, 6, 1, 5, 5, 7, 0x30, 1, 2};
  while (CBS_len(&sequence)) {
    CBS extension, oid, critical, encoded;
    if (!CBS_get_asn1(&sequence, &extension, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&extension, &oid, CBS_ASN1_OBJECT) ||
        !CBS_is_valid_asn1_oid(&oid)) return false;
    Bytes identifier(BytesOf(oid).begin(), BytesOf(oid).end());
    if (!seen.insert(identifier).second) return false;
    if (CBS_peek_asn1_tag(&extension, CBS_ASN1_BOOLEAN)) {
      if (!CBS_get_asn1(&extension, &critical, CBS_ASN1_BOOLEAN) ||
          CBS_len(&critical) != 1 || CBS_data(&critical)[0] != 0xff) return false;
    }
    if (!CBS_get_asn1(&extension, &encoded, CBS_ASN1_OCTETSTRING) || CBS_len(&extension)) return false;
    if (identifier == nonce_oid) {
      CBS bytes;
      if (!CBS_get_asn1(&encoded, &bytes, CBS_ASN1_OCTETSTRING) || CBS_len(&encoded) ||
          !CBS_len(&bytes) || CBS_len(&bytes) > 128) return false;
      *nonce = Bytes(BytesOf(bytes).begin(), BytesOf(bytes).end());
    }
  }
  return true;
}
}  // namespace

bool CredentialRequestOptionsValid(const ClientOptions& options) {
  size_t ids_size = 0, authorities_size = 0;
  for (const auto& id : options.ocsp_responder_ids) {
    if (!ResponderValid(id) || id.size() + 2 > 65530 - ids_size) return false;
    ids_size += id.size() + 2;
  }
  for (const auto& name : options.certificate_authorities) {
    if (!NameValid(name) || name.size() + 2 > 65533 - authorities_size) return false;
    authorities_size += name.size() + 2;
  }
  std::optional<Bytes> nonce;
  return options.ocsp_request_extensions.size() <= 65530 - ids_size &&
      Extensions(options.ocsp_request_extensions, &nonce);
}

bool OCSPRequestMatchesResponse(const ClientOptions& options, ByteSpan response) {
  if (options.ocsp_responder_ids.empty() && options.ocsp_request_extensions.empty()) return true;
  std::optional<Bytes> requested_nonce;
  if (!CredentialRequestOptionsValid(options) || !Extensions(options.ocsp_request_extensions, &requested_nonce)) return false;
  // A missing optional staple is not evidence. TLSFeature/current verifier
  // independently enforces any requirement that a response actually exist.
  if (response.empty()) return true;
  CBS input, outer, status, explicit_response, response_bytes, oid, basic_octets;
  CBS_init(&input, response.data(), response.size());
  const Bytes basic_oid{0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1};
  if (!CBS_get_asn1(&input, &outer, CBS_ASN1_SEQUENCE) || CBS_len(&input) ||
      !CBS_get_asn1(&outer, &status, CBS_ASN1_ENUMERATED) || CBS_len(&status) != 1 || CBS_data(&status)[0] ||
      !CBS_get_asn1(&outer, &explicit_response, Explicit(0)) || CBS_len(&outer) ||
      !CBS_get_asn1(&explicit_response, &response_bytes, CBS_ASN1_SEQUENCE) || CBS_len(&explicit_response) ||
      !CBS_get_asn1(&response_bytes, &oid, CBS_ASN1_OBJECT) || !Equal(BytesOf(oid), basic_oid) ||
      !CBS_get_asn1(&response_bytes, &basic_octets, CBS_ASN1_OCTETSTRING) || CBS_len(&response_bytes)) return false;
  CBS basic, data, ignored, responder, responses;
  if (!CBS_get_asn1(&basic_octets, &basic, CBS_ASN1_SEQUENCE) || CBS_len(&basic_octets) ||
      !CBS_get_asn1(&basic, &data, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&basic, &ignored, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&basic, &ignored, CBS_ASN1_BITSTRING)) return false;
  if (CBS_len(&basic) && !CBS_get_asn1(&basic, &ignored, Explicit(0))) return false;
  if (CBS_len(&basic)) return false;
  if (CBS_peek_asn1_tag(&data, Explicit(0)) && !CBS_get_asn1(&data, &ignored, Explicit(0))) return false;
  unsigned tag = 0;
  if (!CBS_get_any_asn1_element(&data, &responder, &tag, nullptr) ||
      !ResponderValid(BytesOf(responder)) ||
      !CBS_get_asn1(&data, &ignored, CBS_ASN1_GENERALIZEDTIME) ||
      !CBS_get_asn1(&data, &responses, CBS_ASN1_SEQUENCE)) return false;
  if (!options.ocsp_responder_ids.empty() && std::none_of(options.ocsp_responder_ids.begin(),
      options.ocsp_responder_ids.end(), [&](const Bytes& id) { return Equal(id, BytesOf(responder)); })) return false;
  std::optional<Bytes> actual_nonce;
  if (CBS_len(&data)) {
    if (!CBS_get_asn1(&data, &ignored, Explicit(1)) || CBS_len(&data) ||
        !Extensions(BytesOf(ignored), &actual_nonce)) return false;
  }
  return !requested_nonce || actual_nonce == requested_nonce;
}
}  // namespace net::httpps
