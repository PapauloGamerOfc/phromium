#!/usr/bin/env python3
"""Mechanically rebrand browser messages and migrate their GRIT translation IDs.

This deliberately leaves source identifiers, upstream attribution, ChromiumOS,
and the Google Chrome branded resources alone. Run with --apply after merging
new Chromium branded UI strings from upstream; the default is a dry run.
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/grit"))
from grit.extern.tclib import GenerateMessageId

SOURCES = ("chrome/app/chromium_strings.grd",
           "chrome/app/settings_chromium_strings.grdp")
MESSAGE = re.compile(r"(<message\b[^>]*>)(.*?)(</message>)", re.DOTALL)
TRANSLATION = re.compile(r'(<translation\b[^>]*\bid=")(\d+)("[^>]*>)(.*?)(</translation>)', re.DOTALL)
BRAND = re.compile(r"\bChromium\b(?! Authors|OS)")


def replace_brand(text):
    # Modify text nodes, not XML attributes, placeholder identifiers, or URLs.
    return "".join(piece if piece.startswith("<") else BRAND.sub("Phromium", piece)
                   for piece in re.split(r"(<[^>]*>)", text))


def message_id(xml):
    message = ET.fromstring(xml)
    text = message.text or ""
    for child in message:
        if child.tag != "ph":
            raise ValueError(f"Unexpected child in {message.attrib['name']}")
        text += child.attrib["name"].upper() + (child.tail or "")
    text = text.strip()
    if text.startswith("'''"):
        text = text[3:]
    if text.endswith("'''"):
        text = text[:-3]
    return GenerateMessageId(text.strip(), message.attrib.get("meaning", ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    migrations = {}
    updates = {}
    for filename in SOURCES:
        path = ROOT / filename
        source = path.read_text(encoding="utf-8")

        def rebrand(match):
            body = replace_brand(match[2])
            result = match[1] + body + match[3]
            if result != match[0] or "Phromium" in body:
                previous = match[1] + body.replace("Phromium", "Chromium") + match[3]
                old, new = message_id(previous), message_id(result)
                if old in migrations and migrations[old] != new:
                    raise ValueError("Conflicting translation migration")
                migrations[old] = new
            return result

        replacement = MESSAGE.sub(rebrand, source)
        if replacement != source:
            updates[path] = replacement

    for path in sorted((ROOT / "chrome/app/resources").glob("chromium_strings_*.xtb")):
        source = path.read_text(encoding="utf-8")

        def translate(match):
            if match[2] not in migrations:
                return match[0]
            return (match[1] + migrations[match[2]] + match[3]
                    + replace_brand(match[4]) + match[5])

        replacement = TRANSLATION.sub(translate, source)
        # Reject ID collisions rather than silently choosing a translation.
        ids = [item.attrib["id"] for item in ET.fromstring(replacement)]
        if len(ids) != len(set(ids)):
            raise ValueError(f"Translation ID collision: {path}")
        if replacement != source:
            updates[path] = replacement

    if args.apply:
        for path, contents in updates.items():
            contents = re.sub(r"[ \t]+$", "", contents, flags=re.MULTILINE)
            path.write_text(contents, encoding="utf-8", newline="\n")
    print(f"{'Updated' if args.apply else 'Would update'} {len(updates)} files; "
          f"{len(migrations)} translated message IDs")


if __name__ == "__main__":
    main()
