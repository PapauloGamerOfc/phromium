// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Brand-specific types and constants for Chromium.

#ifndef CHROME_INSTALL_STATIC_CHROMIUM_INSTALL_MODES_H_
#define CHROME_INSTALL_STATIC_CHROMIUM_INSTALL_MODES_H_

#include <array>

#include "chrome/app/chrome_dll_resource.h"
#include "chrome/common/chrome_icon_resources_win.h"
#include "chrome/install_static/install_constants.h"

namespace install_static {

// The brand-specific company name to be included as a component of the install
// and user data directory paths. May be empty if no such dir is to be used.
inline constexpr wchar_t kCompanyPathName[] = L"";

// The brand-specific product name to be included as a component of the install
// and user data directory paths.
inline constexpr wchar_t kProductPathName[] = L"Phromium";

// The brand-specific safe browsing client name.
inline constexpr char kSafeBrowsingName[] = "chromium";

// Note: This list of indices must be kept in sync with the brand-specific
// resource strings in chrome/installer/util/prebuild/create_string_rc.
enum InstallConstantIndex {
  CHROMIUM_INDEX,
  NUM_INSTALL_MODES,
};

inline constexpr auto kOldTracingServiceIids = std::to_array<IID>({
    // Replaced in 2026-09. Delete after 2028-09.
    // {A3FD580A-FFD4-4075-9174-75D0B199D3CB}
    {0xa3fd580a,
     0xffd4,
     0x4075,
     {0x91, 0x74, 0x75, 0xd0, 0xb1, 0x99, 0xd3, 0xcb}},
});

inline constexpr auto kInstallModes = std::to_array<InstallConstants>({
    // The primary (and only) install mode for Chromium.
    {
        .size = sizeof(InstallConstants),
        .index = CHROMIUM_INDEX,  // The one and only mode for Chromium.
        .install_switch =
            "",  // No install switch for the primary install mode.
        .install_suffix =
            L"",  // Empty install_suffix for the primary install mode.
        .logo_suffix = L"",  // No logo suffix for the primary install mode.
        .app_guid =
            L"",  // Empty app_guid since no integration with Google Update.
        .base_app_name = L"Phromium",              // A distinct base_app_name.
        .base_app_id = L"Phromium",                // A distinct base_app_id.
        .browser_prog_id_prefix = L"PhromiumHTM",  // Browser ProgID prefix.
        .browser_prog_id_description =
            L"Phromium HTML Document",  // Browser ProgID description.
        .direct_launch_url_scheme = "phromium",
        .pdf_prog_id_prefix = L"PhromiumPDF",  // PDF ProgID prefix.
        .pdf_prog_id_description =
            L"Phromium PDF Document",  // PDF ProgID description.
        .active_setup_guid =
            L"{15DB0A7D-A913-55D8-9728-4F1D322F7C27}",  // Active Setup
                                                        // GUID.
        .toast_activator_clsid = {0xd376dfae,
                                  0x36ac,
                                  0x537c,
                                  {0x9e, 0x89, 0x59, 0xd7, 0xbe, 0x7e, 0x8a,
                                   0x07}},  // Toast Activator CLSID.
        .elevator_clsid = {0x770905cf,
                           0x2e8a,
                           0x5deb,
                           {0x87, 0xea, 0x5b, 0xc2, 0xd2, 0xf1, 0xc4,
                            0xab}},  // Elevator CLSID.
        .elevator_iid = {0x51333cf0,
                         0xf660,
                         0x530e,
                         {0x82, 0x97, 0x96, 0x73, 0x7e, 0x1b, 0xa8,
                          0xe8}},  // IElevator IID and TypeLib
        // {51333CF0-F660-530E-8297-96737E1BA8E8}.
        .old_elevator_iids = {},
        .tracing_service_clsid = {0x71f276ea,
                                  0x98e3,
                                  0x5bfb,
                                  {0x84, 0xe7, 0x03, 0x4c, 0xe1, 0xc7, 0x0e,
                                   0x40}},  // SystemTraceSession CLSID.
        .tracing_service_iid = {0x61140b98,
                                0xd78f,
                                0x531f,
                                {0x8d, 0x88, 0x4a, 0xe9, 0x25, 0xee, 0xdd,
                                 0xad}},  // ISystemTraceSessionChromium IID and
                                          // TypeLib
        .old_tracing_service_iids = {},
        .default_channel_name =
            L"",  // Empty default channel name since no update integration.
        .channel_strategy = ChannelStrategy::UNSUPPORTED,
        .supports_system_level = true,  // Supports system-level installs.
        .supports_set_as_default_browser =
            true,  // Supports in-product set as default browser UX.
        .app_icon_resource_index =
            icon_resources::kApplicationIndex,  // App icon resource index.
        .app_icon_resource_id = IDR_MAINFRAME,  // App icon resource id.
        .html_doc_icon_resource_index =
            icon_resources::kHtmlDocIndex,  // HTML doc icon resource index.
        .pdf_doc_icon_resource_index =
            icon_resources::kPDFDocIndex,  // PDF doc icon resource index.
        .sandbox_sid_prefix =
            L"S-1-15-2-3251537155-1984446955-2931258699-841473695-"
            L"1938553385-"
            L"366676605-",  // Phromium app container sid prefix for sandbox.
    },
});

}  // namespace install_static

#endif  // CHROME_INSTALL_STATIC_CHROMIUM_INSTALL_MODES_H_
