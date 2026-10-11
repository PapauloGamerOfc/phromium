#!/usr/bin/env python3
"""Source/asset regression checks for Phromium branding; no browser build needed.

Run: python tools/phromium_branding_check.py
These checks complement (and do not replace) native installer/browser tests.
"""

import importlib.util
import argparse
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid
import warnings
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/grit"))
from grit import grd_reader
from grit.node.message import MessageNode
from phromium_rebrand_strings import SOURCES, MESSAGE, message_id


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


class BrandingChecks(unittest.TestCase):
    def test_product_metadata_and_attribution(self):
        branding = dict(line.split("=", 1) for line in
                        (ROOT / "chrome/app/theme/chromium/BRANDING")
                        .read_text(encoding="utf-8").splitlines())
        self.assertEqual(branding["PRODUCT_FULLNAME"], "Phromium")
        self.assertEqual(branding["MAC_BUNDLE_ID"],
                         "io.github.papaulogamerofc.Phromium")
        self.assertIn("The Chromium Authors", branding["COPYRIGHT"])

    def test_grit_message_ids_match_upstream_parser(self):
        parsed = grd_reader.Parse(
            str(ROOT / SOURCES[0]), skip_validation_checks=True)
        real_ids = {(node.attrs["name"], node.clique.GetMessage().GetId())
                    for node in parsed if isinstance(node, MessageNode)}
        checked = 0
        for source in SOURCES:
            for match in MESSAGE.finditer((ROOT / source).read_text(encoding="utf-8")):
                if "Phromium" not in match[2]:
                    continue
                element = ET.fromstring(match[0])
                self.assertTrue((element.attrib["name"], message_id(match[0])) in real_ids,
                                element.attrib["name"])
                checked += 1
        self.assertGreater(checked, 500)

    def test_translation_ids_and_placeholders(self):
        source_messages = {}
        for source in SOURCES:
            for match in MESSAGE.finditer((ROOT / source).read_text(encoding="utf-8")):
                element = ET.fromstring(match[0])
                if "Phromium" in match[2]:
                    source_messages[message_id(match[0])] = {
                        child.attrib["name"].upper() for child in element}
        checked = 0
        for path in (ROOT / "chrome/app/resources").glob("chromium_strings_*.xtb"):
            translations = ET.parse(path).getroot()
            ids = [item.attrib["id"] for item in translations]
            self.assertEqual(len(ids), len(set(ids)), path)
            for item in translations:
                if item.attrib["id"] not in source_messages:
                    continue
                self.assertEqual({child.attrib["name"] for child in item},
                                 source_messages[item.attrib["id"]], path)
                self.assertNotRegex("".join(item.itertext()), r"\bChromium\b(?! Authors|OS)")
                checked += 1
        self.assertGreater(checked, 20000)

    def test_profile_separation(self):
        required = {
            "chrome/install_static/chromium_install_modes.h": 'kProductPathName[] = L"Phromium"',
            "chrome/common/chrome_paths_linux.cc": 'data_dir_basename = "phromium"',
            "chrome/common/chrome_paths_mac.mm": 'product_dir_name = "Phromium"',
            "chrome/common/channel_info_posix.cc": 'return "phromium.desktop"',
        }
        for file, text in required.items():
            self.assertIn(text, (ROOT / file).read_text(encoding="utf-8"))

    def test_macos_schemes(self):
        tweak = module("phromium_tweak_plist", "build/apple/tweak_info_plist.py")
        def scheme_list(bundle):
            with (ROOT / "chrome/app/app-Info.plist").open("rb") as file:
                plist = plistlib.load(file)
            tweak._SetDirectLaunchUrlScheme(plist, bundle)
            return [scheme for entry in plist["CFBundleURLTypes"]
                    for scheme in entry["CFBundleURLSchemes"]]
        self.assertIn("httpps", scheme_list("io.github.papaulogamerofc.Phromium"))
        self.assertIn("phromium", scheme_list("io.github.papaulogamerofc.Phromium"))
        self.assertNotIn("httpps", scheme_list("com.google.Chrome"))
        self.assertIn("google-chrome", scheme_list("com.google.Chrome"))

    def test_linux_flatpak_brand(self):
        installer = module("phromium_installer", "chrome/installer/linux/common/installer.py")
        config = installer.InstallerConfig(
            ROOT, ROOT, "stable", "chromium", "amd64", "linux", False, 0o644)
        config.flatpak_init()
        self.assertEqual(config.app_id, "io.github.papaulogamerofc.Phromium")
        self.assertEqual(config.flatpak_command, "phromium")
        config.branding = "google_chrome"
        config.flatpak_init()
        self.assertEqual(config.app_id, "com.google.Chrome")

    def test_linux_update_repository_isolation(self):
        installer = module("phromium_installer_updates",
                           "chrome/installer/linux/common/installer.py")
        for brand, package in (("chromium", "phromium"),
                               ("google_chrome", "google-chrome")):
            for package_format in (installer.PackageFormat.DEB, installer.PackageFormat.RPM):
                args = argparse.Namespace(branding=brand, arch="amd64", channel="stable",
                                          target_os="linux", build_time="0", official=False,
                                          use_static_angle="false")
                if package_format == installer.PackageFormat.DEB:
                    args.sysroot = "unused-test-sysroot"
                data = {"channel": "stable", "package_orig": package,
                        "usr_bin_symlink_name": package + "-stable",
                        "info_vars": {"PACKAGE": package}}
                with mock.patch.object(installer.InstallerConfig,
                                       "_load_branding_and_version", return_value=data):
                    config = installer.InstallerConfig.from_args(args, ROOT, package_format)
                if brand == "chromium":
                    self.assertEqual(config.repoconfig, "")
                    self.assertEqual(config.repoconfigregex, "")
                    self.assertEqual(config.rpm_optional_repo_cron, "")
                else:
                    self.assertIn("dl.google.com", config.repoconfig)
                    self.assertEqual(config.rpm_optional_repo_cron,
                                     "/etc/cron.daily/google-chrome")

        # The explicit repo-package target must also fail before producing a
        # misleading Phromium package with another vendor's sources or keys.
        result = subprocess.run(
            [sys.executable, str(ROOT / "chrome/installer/linux/debian/build_repo_package.py"),
             "-a", "amd64", "-b", "0", "-c", "stable", "-d", "chromium",
             "-o", str(ROOT), "-s", "unused-test-sysroot", "-t", "linux"],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Phromium has no configured package update repository", result.stderr)

        postinst = (ROOT / "chrome/installer/linux/debian/postinst").read_text()
        self.assertIn('if [ "@@branding" = "google_chrome" ]; then\n  install_key', postinst)
        postrm = (ROOT / "chrome/installer/linux/debian/postrm").read_text()
        self.assertLess(postrm.index('if [ "@@branding" != "google_chrome" ]'),
                        postrm.index("clean_sources_lists"))
        spec = (ROOT / "chrome/installer/linux/rpm/chrome.spec.template").read_text()
        self.assertIn("@@rpm_optional_repo_cron", spec)
        self.assertNotIn("/etc/cron.daily/@@PACKAGE", spec)
        self.assertIn('if [ "@@branding" = "google_chrome" ]; then\n  if [ ! -e', spec)

        git_bash = Path("C:/Program Files/Git/bin/bash.exe")
        bash = str(git_bash) if git_bash.exists() else shutil.which("bash")
        if bash:
            # Execute only the isolated repository branch with harmless stubs,
            # never full privileged install scripts or filesystem operations.
            deb_main = postinst.split("## MAIN ##", 1)[1]
            rpm_main = spec.split('if [ "@@branding" = "google_chrome" ]; then', 1)[1]
            rpm_main = ('if [ "@@branding" = "google_chrome" ]; then' +
                        rpm_main.split("CHANNEL=", 1)[0])
            definitions = ("install_key() { echo key; }; "
                           "install_deb822_sources() { echo source; }; "
                           "remove_legacy_list() { echo list; }; "
                           "remove_legacy_key() { echo legacy-key; }; "
                           "determine_rpm_package_manager() { PACKAGEMANAGERS=(yum zypp); }; "
                           "install_yum() { echo yum; }; install_zypp() { echo zypp; }; "
                           "DEFAULTS_FILE=/dev/null; repo_add_once=true;\n")
            for brand in ("chromium", "google_chrome"):
                for script, lines in ((deb_main, 4), (rpm_main, 2)):
                    run = subprocess.run([bash, "--noprofile", "--norc", "-c",
                                          definitions + script.replace("@@branding", brand)],
                                         capture_output=True, text=True, check=False)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertEqual(len(run.stdout.splitlines()),
                                     lines if brand == "google_chrome" else 0)

    def test_native_icon_headers(self):
        theme = ROOT / "chrome/app/theme/chromium"
        data = (theme / "win/chromium.ico").read_bytes()
        self.assertEqual(struct.unpack("<HH", data[:4]), (0, 1))
        self.assertGreaterEqual(struct.unpack("<H", data[4:6])[0], 7)
        data = (theme / "mac/app.icns").read_bytes()
        self.assertEqual(data[:4], b"icns")
        self.assertEqual(struct.unpack(">I", data[4:8])[0], len(data))
        for size in (16, 24, 48, 64, 128, 256):
            data = (theme / f"product_logo_{size}.png").read_bytes()
            self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(struct.unpack(">II", data[16:24]), (size, size))

    def test_midl_brand_substitutions(self):
        midl = module("phromium_midl", "build/toolchain/win/midl.py")
        for target, stem in (("elevation_service", "elevation_service_idl"),
                             ("windows_services/elevated_tracing_service", "tracing_service_idl")):
            gn = (ROOT / "chrome" / target / "BUILD.gn").read_text(encoding="utf-8")
            setting = re.search(r'dynamic_guids = "([^"]+)"', gn)[1]
            self.assertTrue(setting.startswith("ignore_proxy_stub,"))
            pairs = dict(part.split("=", 1) for part in setting.split(",")[1:])
            substitutions = {k.encode(): v.encode() for k, v in pairs.items()}
            for architecture in ("x64", "x86", "arm64"):
                original = ROOT / "third_party/win_build_output/midl/chrome" / target / architecture
                if not original.exists():
                    self.fail(f"Missing checkout for MIDL test: {original}")
                with tempfile.TemporaryDirectory() as temp:
                    temp = Path(temp)
                    names = [stem + suffix for suffix in (".h", "_i.c", "_p.c", ".tlb")]
                    for name in names:
                        shutil.copyfile(original / name, temp / name)
                    # Upstream's MIDL helper opens files inline; it closes them
                    # through reference counting and emits ResourceWarnings.
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", ResourceWarning)
                        midl.overwrite_guids(*(str(temp / name) for name in names), substitutions)
                    header = (temp / names[0]).read_bytes().upper()
                    tlb = (temp / names[3]).read_bytes()
                    for old, new in pairs.items():
                        self.assertNotIn(old.encode(), header)
                        self.assertIn(new.encode(), header)
                        self.assertNotIn(uuid.UUID(old).bytes_le, tlb)
                        self.assertIn(uuid.UUID(new).bytes_le, tlb)


if __name__ == "__main__":
    unittest.main()
