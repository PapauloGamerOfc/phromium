# Copyright 2026 The Phromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import midl


class CompilerSettingsPathTest(unittest.TestCase):
    def setUp(self):
        self.source = '../../chrome/service/service.idl'
        self.generated = 'gen/chrome/service/service.idl'

    def normalize(self, contents):
        return midl.normalize_compiler_settings_path(
            contents, self.source, self.generated
        )

    def output(self, path):
        return (
            f'/* Compiler settings for {path}:\r\n'
            '    Oicf, W1, Zp8, env=Win64\r\n'
            ' */\r\n'
            'MIDL_DEFINE_GUID(IID, IID_IService, 0x12345678);\r\n'
        ).encode('utf-8')

    def test_source_and_generated_paths_are_equivalent(self):
        self.assertEqual(
            self.normalize(self.output(self.source)),
            self.normalize(self.output(self.generated)),
        )

    def test_already_generated_baseline_is_unchanged_in_comparison(self):
        self.assertEqual(
            self.normalize(self.output(self.generated)),
            self.normalize(self.output(self.generated)),
        )

    def test_guid_difference_is_preserved(self):
        changed = self.output(self.generated).replace(b'0x12345678', b'0x87654321')
        self.assertNotEqual(self.normalize(self.output(self.source)),
                            self.normalize(changed))

    def test_compiler_options_difference_is_preserved(self):
        changed = self.output(self.generated).replace(b'Zp8', b'Zp4')
        self.assertNotEqual(self.normalize(self.output(self.source)),
                            self.normalize(changed))

    def test_unrelated_input_path_is_not_normalized(self):
        changed = self.output('gen/chrome/other/service.idl')
        self.assertEqual(changed, self.normalize(changed))

    def test_path_outside_metadata_comment_is_not_normalized(self):
        contents = f'const char* input = "{self.source}";\r\n'.encode('utf-8')
        self.assertEqual(contents, self.normalize(contents))

    def test_metadata_comment_must_be_whole_line(self):
        contents = (
            f'/* Compiler settings for {self.source}: changed\r\n'
        ).encode('utf-8')
        self.assertEqual(contents, self.normalize(contents))

    def test_binary_output_is_never_normalized(self):
        self.assertTrue(midl.differs_beyond_input_path(
            'baseline.tlb', 'generated.tlb', self.source, self.generated))


if __name__ == '__main__':
    unittest.main()
