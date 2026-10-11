// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef CHROME_COMMON_HTTPPS_PROFILES_H_
#define CHROME_COMMON_HTTPPS_PROFILES_H_
#include <optional>
#include <string>
namespace chrome {
// Browser startup only, before blocking I/O is disallowed. Never forwards the
// path or secrets through a child-process command line.
void LoadHttppsProfiles();
const std::optional<std::string>& GetHttppsProfiles();
}  // namespace chrome
#endif  // CHROME_COMMON_HTTPPS_PROFILES_H_
