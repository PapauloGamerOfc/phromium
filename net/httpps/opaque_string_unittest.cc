// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/httpps/opaque_string.h"

#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::httpps {
namespace {

TEST(HttppsOpaqueStringTest, MappingAndPreservation) {
  const std::pair<std::u16string, std::u16string> cases[] = {
      {u"Correct Horse!", u"Correct Horse!"},
      {u"  a  ", u"  a  "},
      {u"\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000", u"                "},
      {u"e\u0301", u"\u00e9"},
      {u"\u212b", u"\u00c5"},
      {u"\uff26\uff2f\uff2f", u"\uff26\uff2f\uff2f"},
      {u"\u00df\u03c2\u2163", u"\u00df\u03c2\u2163"},
      {u"\U0001f512\U0001f600", u"\U0001f512\U0001f600"},
      {u"abc\u05d0\u05d1", u"abc\u05d0\u05d1"},  // No bidi restriction.
      {u"l\u00b7l", u"l\u00b7l"},
      {u"\u0375\u03b1", u"\u0375\u03b1"},
      {u"\u05d0\u05f3\u05f4", u"\u05d0\u05f3\u05f4"},
      {u"\u30fb\u30ab", u"\u30fb\u30ab"},
      {u"\u30fb\u6f22", u"\u30fb\u6f22"},
      {u"\u0660\u0669", u"\u0660\u0669"},
      {u"\u06f0\u06f9", u"\u06f0\u06f9"},
      {u"\u0915\u094d\u200d\u0937", u"\u0915\u094d\u200d\u0937"},
      {u"\u0915\u094d\u200c\u0937", u"\u0915\u094d\u200c\u0937"},
      {u"\u0628\u064e\u200c\u064e\u0628", u"\u0628\u064e\u200c\u064e\u0628"},
  };
  for (const auto& [input, expected] : cases) {
    auto output = PrepareOpaqueString(base::UTF16ToUTF8(input));
    ASSERT_TRUE(output);
    EXPECT_EQ(*output, base::UTF16ToUTF8(expected));
    EXPECT_EQ(PrepareOpaqueString(*output), output);
  }
}

TEST(HttppsOpaqueStringTest, RejectsProhibitedAndInvalidContext) {
  for (std::u16string input : {
           u"", u"a\t", u"a\n", u"\u007f", u"\u009f", u"\u00ad", u"\u034f",
           u"\u0378", u"\u061c", u"\u0640", u"\u07fa", u"\u1100", u"\u1161",
           u"\u200b", u"\u2028", u"\u2029", u"\u202e", u"\u2060", u"\u2066",
           u"\u302e", u"\u3031", u"\u303b", u"\ue000", u"\ufdd0", u"\ufe0f",
           u"\ufffe", u"\U000f0000", u"\U0010ffff", u"a\u00b7a", u"L\u00b7L",
           u"\u0375a", u"\u0375", u"\u05f3\u05d0", u"\u30fbabc", u"\u30fb",
           u"\u0660\u06f0", u"\u06f9\u0669", u"a\u200db", u"a\u200cb",
           u"\u200c", u"\u200d", u"\u0628\u200c", u"\u200c\u0628"}) {
    EXPECT_FALSE(PrepareOpaqueString(base::UTF16ToUTF8(input)));
  }
  EXPECT_FALSE(PrepareOpaqueString(std::string("a\0b", 3)));
  for (const std::string input : {"\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80",
                                  "\x80", "\xc2", "\xf0\x80\x80\xaf"}) {
    EXPECT_FALSE(PrepareOpaqueString(input));
  }
  EXPECT_FALSE(PrepareOpaqueString(std::string(65536, 'a')));
}

}  // namespace
}  // namespace net::httpps
