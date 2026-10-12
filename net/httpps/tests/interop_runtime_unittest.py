# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Transport-runtime regressions; no TLS or crypto-policy replacements."""
import asyncio
import contextlib
import io
import subprocess
import sys
import unittest
from unittest.mock import AsyncMock, Mock, patch

import interop_runtime as runtime


class RuntimeTests(unittest.TestCase):
    def test_success_and_expected_loop(self):
        async def task():
            if sys.platform == "win32":
                self.assertIsInstance(asyncio.get_running_loop(), asyncio.SelectorEventLoop)
            return 42
        self.assertEqual(runtime.run(task()), 42)

    def test_background_callback_error_fails_even_after_main_success(self):
        async def task():
            def fail():
                raise ValueError("callback-regression-marker")
            asyncio.get_running_loop().call_soon(fail)
            await asyncio.sleep(0)
            return "success"
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "callback-regression-marker"):
                runtime.run(task())

    def test_nonwindows_retains_asyncio_subprocess(self):
        async def task():
            marker = object()
            with patch.object(runtime.sys, "platform", "linux"), patch.object(
                    asyncio, "create_subprocess_exec", new=AsyncMock(return_value=marker)) as start:
                self.assertIs(await runtime.start_process("program", "arg", stdout=subprocess.PIPE), marker)
                start.assert_awaited_once_with("program", "arg", stdout=subprocess.PIPE)
        runtime.run(task())

    def test_real_child_output_and_returncode(self):
        async def task():
            child = await runtime.start_process(sys.executable, "-c", "print('child-ok')",
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                output, error = await asyncio.wait_for(child.communicate(), 5)
                self.assertEqual(output.strip(), b"child-ok")
                self.assertEqual(error, b"")
                self.assertEqual(child.returncode, 0)
            finally:
                if child.returncode is None:
                    child.kill()
                await child.wait()
        runtime.run(task())

    def test_owned_process_deadlines_report_timeout(self):
        async def task():
            process = Mock()
            process.communicate.side_effect = subprocess.TimeoutExpired("fixture", 120)
            process.wait.side_effect = subprocess.TimeoutExpired("fixture", 15)
            child = runtime.OwnedProcess(process)
            with self.assertRaisesRegex(TimeoutError, "120 seconds"):
                await child.communicate()
            with self.assertRaisesRegex(TimeoutError, "15 seconds"):
                await child.wait()
            process.communicate.assert_called_once_with(timeout=120)
            process.wait.assert_called_once_with(timeout=15)
        runtime.run(task())

    def test_outer_deadline_can_kill_and_reap_real_child(self):
        async def task():
            child = await runtime.start_process(sys.executable, "-c", "import time; time.sleep(60)",
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(child.communicate(), 0.05)
            finally:
                if child.returncode is None:
                    child.kill()
                await child.wait()
            self.assertIsNotNone(child.returncode)
        runtime.run(task())


if __name__ == "__main__":
    unittest.main()
