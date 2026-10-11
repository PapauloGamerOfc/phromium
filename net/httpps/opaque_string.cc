// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/opaque_string.h"

#include <algorithm>
#include <vector>

#include "base/strings/utf_string_conversions.h"
#include "third_party/icu/source/common/unicode/normalizer2.h"
#include "third_party/icu/source/common/unicode/uchar.h"
#include "third_party/icu/source/common/unicode/unistr.h"
#include "third_party/icu/source/common/unicode/uscript.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net::httpps {
namespace {

bool Between(UChar32 value, UChar32 low, UChar32 high) {
  return low <= value && value <= high;
}

bool Script(UChar32 value, int32_t script) {
  return u_getIntPropertyValue(value, UCHAR_SCRIPT) == script;
}

struct ContextSummary {
  bool japanese = false;
  bool arabic_digits = false;
  bool extended_arabic_digits = false;
};

// Preparation handles passwords too. Wipe intermediate text instead of leaving
// normalized/decomposed copies in reusable heap allocations.
struct Buffers {
  std::u16string utf16;
  icu::UnicodeString source, mapped, normalized;
  std::vector<UChar32> codepoints;
  ~Buffers() {
    OPENSSL_cleanse(utf16.data(), utf16.size() * sizeof(char16_t));
    OPENSSL_cleanse(codepoints.data(), codepoints.size() * sizeof(UChar32));
    for (auto* value : {&source, &mapped, &normalized}) {
      const int32_t length = value->length();
      if (auto* buffer = value->getBuffer(length)) {
        OPENSSL_cleanse(buffer, static_cast<size_t>(length) * sizeof(char16_t));
        value->releaseBuffer(0);
      }
    }
  }
};

bool Context(const std::vector<UChar32>& text, size_t index,
             const ContextSummary& summary) {
  const UChar32 cp = text[index];
  const UChar32 before = index ? text[index - 1] : -1;
  const UChar32 after = index + 1 < text.size() ? text[index + 1] : -1;
  if (cp == 0x200c || cp == 0x200d) {
    if (before >= 0 && u_getCombiningClass(before) == 9) {
      return true;  // Virama.
    }
    if (cp == 0x200d) {
      return false;
    }
    int32_t left = U_JT_NON_JOINING;
    int32_t right = U_JT_NON_JOINING;
    for (size_t j = index; j > 0;) {
      left = u_getIntPropertyValue(text[--j], UCHAR_JOINING_TYPE);
      if (left != U_JT_TRANSPARENT) {
        break;
      }
    }
    for (size_t j = index + 1; j < text.size(); ++j) {
      right = u_getIntPropertyValue(text[j], UCHAR_JOINING_TYPE);
      if (right != U_JT_TRANSPARENT) {
        break;
      }
    }
    return (left == U_JT_LEFT_JOINING || left == U_JT_DUAL_JOINING) &&
           (right == U_JT_RIGHT_JOINING || right == U_JT_DUAL_JOINING);
  }
  if (cp == 0xb7) {
    return before == 'l' && after == 'l';
  }
  if (cp == 0x375) {
    return after >= 0 && Script(after, USCRIPT_GREEK);
  }
  if (cp == 0x5f3 || cp == 0x5f4) {
    return before >= 0 && Script(before, USCRIPT_HEBREW);
  }
  if (cp == 0x30fb) {
    return summary.japanese;
  }
  if (Between(cp, 0x660, 0x669)) {
    return !summary.extended_arabic_digits;
  }
  if (Between(cp, 0x6f0, 0x6f9)) {
    return !summary.arabic_digits;
  }
  return false;
}

bool Freeform(const std::vector<UChar32>& text, size_t index,
              const ContextSummary& summary) {
  const UChar32 cp = text[index];
  // RFC 8264 section 8 order matters: the Exceptions and JoinControl rules
  // precede ignorable/category checks. BackwardCompatible is currently empty.
  switch (cp) {
    case 0xdf:
    case 0x3c2:
    case 0x6fd:
    case 0x6fe:
    case 0xf0b:
    case 0x3007:
      return true;
    case 0xb7:
    case 0x375:
    case 0x5f3:
    case 0x5f4:
    case 0x30fb:
      return Context(text, index, summary);
    case 0x640:
    case 0x7fa:
    case 0x302e:
    case 0x302f:
    case 0x303b:
      return false;
  }
  if (Between(cp, 0x3031, 0x3035)) {
    return false;
  }
  if (Between(cp, 0x660, 0x669) || Between(cp, 0x6f0, 0x6f9)) {
    return Context(text, index, summary);
  }
  const int8_t category = u_charType(cp);
  if (category == U_UNASSIGNED) {
    return false;
  }
  if (Between(cp, 0x21, 0x7e)) {
    return true;
  }
  if (cp == 0x200c || cp == 0x200d) {
    return Context(text, index, summary);
  }
  const int32_t hangul = u_getIntPropertyValue(cp, UCHAR_HANGUL_SYLLABLE_TYPE);
  if (hangul == U_HST_LEADING_JAMO || hangul == U_HST_VOWEL_JAMO ||
      hangul == U_HST_TRAILING_JAMO ||
      u_hasBinaryProperty(cp, UCHAR_DEFAULT_IGNORABLE_CODE_POINT) ||
      u_hasBinaryProperty(cp, UCHAR_NONCHARACTER_CODE_POINT) ||
      category == U_CONTROL_CHAR) {
    return false;
  }
  // HasCompat, LetterDigits, OtherLetterDigits, Spaces, Symbols, Punctuation
  // are all permitted by Freeform (unlike IdentifierClass).
  if ((U_GET_GC_MASK(cp) & (U_GC_L_MASK | U_GC_M_MASK | U_GC_N_MASK |
                            U_GC_ZS_MASK | U_GC_S_MASK | U_GC_P_MASK)) != 0) {
    return true;
  }
  UErrorCode status = U_ZERO_ERROR;
  const auto* nfkc = icu::Normalizer2::getNFKCInstance(status);
  const bool normalized = U_SUCCESS(status) && nfkc &&
                          nfkc->isNormalized(icu::UnicodeString(cp), status);
  return U_SUCCESS(status) && nfkc && !normalized;
}

}  // namespace

std::optional<std::string> PrepareOpaqueString(std::string_view input) {
  // Bound work before decoding; TLS-PWD wire vectors are at most 65535 bytes.
  if (input.empty() || input.size() > 65535) {
    return std::nullopt;
  }
  Buffers buffers;
  auto& utf16 = buffers.utf16;
  if (!base::UTF8ToUTF16(input.data(), input.size(), &utf16)) {
    return std::nullopt;
  }
  auto& source = buffers.source;
  source.setTo(utf16.data(), static_cast<int32_t>(utf16.size()));
  auto& mapped = buffers.mapped;
  for (int32_t offset = 0; offset < source.length();) {
    const UChar32 cp = source.char32At(offset);
    offset += U16_LENGTH(cp);
    mapped.append(u_charType(cp) == U_SPACE_SEPARATOR ? UChar32{' '} : cp);
  }
  UErrorCode status = U_ZERO_ERROR;
  const auto* nfc = icu::Normalizer2::getNFCInstance(status);
  auto& normalized = buffers.normalized;
  if (U_FAILURE(status) || !nfc) {
    return std::nullopt;
  }
  nfc->normalize(mapped, normalized, status);
  if (U_FAILURE(status) || normalized.isEmpty()) {
    return std::nullopt;
  }
  auto& codepoints = buffers.codepoints;
  codepoints.reserve(static_cast<size_t>(normalized.length()));
  ContextSummary summary;
  for (int32_t offset = 0; offset < normalized.length();) {
    const UChar32 cp = normalized.char32At(offset);
    offset += U16_LENGTH(cp);
    codepoints.push_back(cp);
    summary.japanese |= Script(cp, USCRIPT_HIRAGANA) || Script(cp, USCRIPT_KATAKANA) ||
                        Script(cp, USCRIPT_HAN);
    summary.arabic_digits |= Between(cp, 0x660, 0x669);
    summary.extended_arabic_digits |= Between(cp, 0x6f0, 0x6f9);
  }
  for (size_t index = 0; index < codepoints.size(); ++index) {
    if (!Freeform(codepoints, index, summary)) {
      return std::nullopt;
    }
  }
  std::string output;
  normalized.toUTF8String(output);
  return output.empty() || output.size() > 65535
             ? std::nullopt
             : std::make_optional(std::move(output));
}

}  // namespace net::httpps
