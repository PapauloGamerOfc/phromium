// Copyright 2026 The Phromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_NETWORK_SERVICE_PRELOADS_H_
#define CONTENT_PUBLIC_BROWSER_NETWORK_SERVICE_PRELOADS_H_

#include <vector>

#include "base/files/file_path.h"
#include "build/build_config.h"
#include "content/common/content_export.h"

namespace content {

#if BUILDFLAG(IS_WIN)
// Browser startup only, before the network service is created. The owner may
// supply this immutable list once, from explicit trusted local configuration.
// Libraries are made available through the utility's pre-lockdown hook; this
// does not grant post-lockdown filesystem access or relax sandbox mitigations.
// Never populate it from a renderer, a remote response or per-request IPC.
CONTENT_EXPORT void SetNetworkServicePreloadLibraries(
    std::vector<base::FilePath> libraries);
#endif

}  // namespace content

#endif  // CONTENT_PUBLIC_BROWSER_NETWORK_SERVICE_PRELOADS_H_
