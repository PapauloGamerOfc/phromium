# Copyright 2026 The Phromium Authors. BSD-style license: see LICENSE.
"""Bounded subprocesses and strict loop errors for standalone interop tests."""
import asyncio
import subprocess
import sys


class OwnedProcess:
    """Popen avoids Proactor pipes when Windows uses selector networking."""

    def __init__(self, process):
        self.process = process

    @property
    def returncode(self):
        return self.process.poll()

    async def wait(self):
        try:
            return await asyncio.to_thread(self.process.wait, timeout=15)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Interop subprocess did not exit within 15 seconds") from error

    async def communicate(self):
        try:
            # Callers retain their tighter per-case wait_for deadlines. 120s
            # accommodates the existing 100/110s FFDHE/PAKE matrix deadlines.
            return await asyncio.to_thread(self.process.communicate, timeout=120)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Interop subprocess did not finish within 120 seconds") from error

    def kill(self):
        self.process.kill()


async def start_process(*arguments, **options):
    if sys.platform != "win32":
        return await asyncio.create_subprocess_exec(*arguments, **options)
    options.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
    return OwnedProcess(await asyncio.to_thread(subprocess.Popen, arguments, **options))


def run(coroutine):
    # Python's Windows Proactor socket shutdown can throw after a peer closes,
    # before detaching its transport; wait_closed then never completes. Use
    # selector sockets, not an exception filter that hides that runtime failure.
    factory = asyncio.SelectorEventLoop if sys.platform == "win32" else None
    errors = []
    with asyncio.Runner(loop_factory=factory) as runner:
        def loop_error(loop, context):
            errors.append(context)
            loop.default_exception_handler(context)
        runner.get_loop().set_exception_handler(loop_error)
        result = runner.run(coroutine)
    if errors:
        raise RuntimeError("Unexpected event-loop errors: " + repr(errors))
    return result
