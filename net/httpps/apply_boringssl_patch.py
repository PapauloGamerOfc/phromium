#!/usr/bin/env python3
# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Apply the pinned HTTPPS SPKI parser patch without discarding local edits.

Called by gclient runhooks and the portable test build. Acceptance of an X25519
certificate is still a caller policy decision, not a property of this parser.
"""

from pathlib import Path
import subprocess
import sys


REVISION = "3b39936f376ed568431fd3f95c3421f5b0726e70"


def main():
    root = Path(__file__).resolve().parents[2]
    source = root / "third_party/boringssl/src"
    patches = Path(__file__).resolve().parent / "patches"

    def git(*arguments):
        return subprocess.run(["git", "-C", str(source), *arguments],
                              capture_output=True, text=True, check=False)

    revision = git("rev-parse", "HEAD")
    if revision.returncode or revision.stdout.strip() != REVISION:
        raise RuntimeError("HTTPPS requires the pinned BoringSSL checkout; "
                           "sync dependencies before running this hook")
    for filename in ("boringssl-x25519-spki.patch", "boringssl-tls-ccm.patch"):
        patch = patches / filename
        if git("apply", "--reverse", "--check", str(patch)).returncode == 0:
            print(f"HTTPPS BoringSSL {filename} already present")
            continue
        check = git("apply", "--check", str(patch))
        if check.returncode:
            raise RuntimeError("HTTPPS patch conflicts with local BoringSSL edits; "
                               "no files were reset:\n" + check.stderr)
        result = git("apply", str(patch))
        if result.returncode:
            raise RuntimeError(result.stderr)
        print(f"Applied HTTPPS BoringSSL {filename}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
