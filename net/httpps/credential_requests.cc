// Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
#include "net/httpps/draft01.h"
#include "net/httpps/credential_validation.h"

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
  // X509_NAME may retain its original encoding. Do not rely only on an
  // encode/decode round trip to reject BER lengths or noncanonical SET order.
  CBS input, sequence;
  CBS_init(&input, value.data(), value.size());
  if (!CBS_get_asn1(&input, &sequence, CBS_ASN1_SEQUENCE) || CBS_len(&input))
    return false;
  while (CBS_len(&sequence)) {
    CBS rdn;
    if (!CBS_get_asn1(&sequence, &rdn, CBS_ASN1_SET) || !CBS_len(&rdn))
      return false;
    ByteSpan previous;
    while (CBS_len(&rdn)) {
      CBS encoded, attribute, oid, attribute_value;
      if (!CBS_get_asn1_element(&rdn, &encoded, CBS_ASN1_SEQUENCE)) return false;
      const auto current = BytesOf(encoded);
      if (!previous.empty() && std::lexicographical_compare(
              current.begin(), current.end(), previous.begin(), previous.end()))
        return false;
      previous = current;
      if (!CBS_get_asn1(&encoded, &attribute, CBS_ASN1_SEQUENCE) ||
          !CBS_get_asn1(&attribute, &oid, CBS_ASN1_OBJECT) ||
          !CBS_is_valid_asn1_oid(&oid) ||
          !CBS_get_any_asn1_element(&attribute, &attribute_value, nullptr, nullptr) ||
          CBS_len(&attribute)) return false;
    }
  }
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
bool Extensions(ByteSpan value, std::optional<Bytes>* nonce,
                bool* unsupported_critical = nullptr) {
  nonce->reset();
  if (unsupported_critical) *unsupported_critical = false;
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
    bool is_critical = false;
    if (CBS_peek_asn1_tag(&extension, CBS_ASN1_BOOLEAN)) {
      if (!CBS_get_asn1(&extension, &critical, CBS_ASN1_BOOLEAN) ||
          CBS_len(&critical) != 1 || CBS_data(&critical)[0] != 0xff) return false;
      is_critical = true;
    }
    if (!CBS_get_asn1(&extension, &encoded, CBS_ASN1_OCTETSTRING) || CBS_len(&extension)) return false;
    if (identifier == nonce_oid) {
      CBS bytes;
      if (!CBS_get_asn1(&encoded, &bytes, CBS_ASN1_OCTETSTRING) || CBS_len(&encoded) ||
          !CBS_len(&bytes) || CBS_len(&bytes) > 128) return false;
      *nonce = Bytes(BytesOf(bytes).begin(), BytesOf(bytes).end());
    } else if (is_critical && unsupported_critical) {
      // Unknown requirements are well-framed, but this matcher cannot claim
      // that a generic response fulfilled their processing semantics.
      *unsupported_critical = true;
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

bool ParseCertificateAuthorities(ByteSpan encoded,
                                 std::vector<Bytes>* authorities) {
  authorities->clear();
  CBS input, names;
  CBS_init(&input, encoded.data(), encoded.size());
  if (!CBS_get_u16_length_prefixed(&input, &names) || CBS_len(&input) ||
      CBS_len(&names) < 3) return false;
  std::vector<Bytes> parsed;
  while (CBS_len(&names)) {
    CBS name;
    if (!CBS_get_u16_length_prefixed(&names, &name) ||
        !NameValid(BytesOf(name))) return false;
    parsed.emplace_back(BytesOf(name).begin(), BytesOf(name).end());
  }
  *authorities = std::move(parsed);
  return true;
}

bool ParseOidFilters(ByteSpan encoded,
                     std::vector<std::pair<Bytes, Bytes>>* filters,
                     uint8_t* alert) {
  filters->clear();
  *alert = 50;
  CBS input, entries;
  CBS_init(&input, encoded.data(), encoded.size());
  if (!CBS_get_u16_length_prefixed(&input, &entries) || CBS_len(&input))
    return false;
  std::set<Bytes> seen;
  std::vector<std::pair<Bytes, Bytes>> parsed;
  while (CBS_len(&entries)) {
    CBS identifier, values, oid;
    if (!CBS_get_u8_length_prefixed(&entries, &identifier) ||
        !CBS_get_u16_length_prefixed(&entries, &values))
      return false;
    const auto encoded_oid = BytesOf(identifier);
    const auto encoded_values = BytesOf(values);
    if (!CBS_get_asn1(&identifier, &oid, CBS_ASN1_OBJECT) || CBS_len(&identifier) ||
        !CBS_is_valid_asn1_oid(&oid))
      return false;
    if (!seen.emplace(encoded_oid.begin(), encoded_oid.end()).second) {
      *alert = 47;
      return false;
    }
    const auto oid_bytes = BytesOf(oid);
    // Empty values require only presence. Unknown OID semantics MUST remain
    // ignorable; validate their identifier, not an invented value grammar.
    if (CBS_len(&values) && Equal(oid_bytes, Bytes{0x55, 0x1d, 0x0f})) {
      CBS bits;
      if (!CBS_get_asn1(&values, &bits, CBS_ASN1_BITSTRING) || CBS_len(&values) ||
          !CBS_len(&bits) || CBS_len(&bits) > 3)
        return false;
      const auto encoded_bits = BytesOf(bits);
      const auto unused = encoded_bits[0];
      const auto count = encoded_bits.size() - 1;
      if (unused > 7 || (!count && unused))
        return false;
      if (count) {
        const auto last = encoded_bits[count];
        if ((last & ((1u << unused) - 1u)) || !(last & (1u << unused)))
          return false;  // Nonminimal named-bit DER or nonzero padding bits.
        if (count * 8 - unused > 9) {
          *alert = 47;  // Well-formed encoding of an undefined KeyUsage bit.
          return false;
        }
      }
    } else if (CBS_len(&values) && Equal(oid_bytes, Bytes{0x55, 0x1d, 0x25})) {
      CBS sequence;
      if (!CBS_get_asn1(&values, &sequence, CBS_ASN1_SEQUENCE) || CBS_len(&values) ||
          !CBS_len(&sequence))
        return false;
      while (CBS_len(&sequence)) {
        CBS purpose;
        if (!CBS_get_asn1(&sequence, &purpose, CBS_ASN1_OBJECT) ||
            !CBS_is_valid_asn1_oid(&purpose))
          return false;
        if (Equal(BytesOf(purpose), Bytes{0x55, 0x1d, 0x25, 0})) {
          *alert = 47;  // RFC9846 forbids anyExtendedKeyUsage in this request.
          return false;
        }
      }
    }
    parsed.emplace_back(Bytes(encoded_oid.begin(), encoded_oid.end()),
                        Bytes(encoded_values.begin(), encoded_values.end()));
  }
  *filters = std::move(parsed);
  return true;
}

bool OCSPRequestMatchesResponse(const ClientOptions& options, ByteSpan response) {
  if (options.ocsp_responder_ids.empty() && options.ocsp_request_extensions.empty()) return true;
  std::optional<Bytes> requested_nonce;
  bool unsupported_critical = false;
  if (!CredentialRequestOptionsValid(options) ||
      !Extensions(options.ocsp_request_extensions, &requested_nonce, &unsupported_critical)) return false;
  // A missing optional staple is not evidence. TLSFeature/current verifier
  // independently enforces any requirement that a response actually exist.
  if (response.empty()) return true;
  if (unsupported_critical) return false;
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
