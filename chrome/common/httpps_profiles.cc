// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "chrome/common/httpps_profiles.h"

#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/no_destructor.h"
namespace chrome {
namespace {
std::optional<std::string>& Profiles() {
  static base::NoDestructor<std::optional<std::string>> profiles;
  return *profiles;
}
}  // namespace
void LoadHttppsProfiles() {
  const auto& command = *base::CommandLine::ForCurrentProcess();
  if (!command.HasSwitch("httpps-profile-file")) {
    return;
  }
  auto path = command.GetSwitchValuePath("httpps-profile-file");
  // Empty means configured but unreadable/invalid: the network service must
  // reject HTTPPS, not silently continue under a less restrictive policy.
  Profiles().emplace();
  constexpr size_t kMaximum = 4 * 1024 * 1024;
  if (!path.IsAbsolute() || path.ReferencesParent() ||
      !base::ReadFileToStringWithMaxSize(path, &*Profiles(), kMaximum)) {
    Profiles()->clear();
  }
}
const std::optional<std::string>& GetHttppsProfiles() {
  return Profiles();
}
}  // namespace chrome
