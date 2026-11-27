# SPDX-License-Identifier: LGPL-3.0-only

"""Check attach without depending on where macOS stopped a running process."""

import json
import subprocess
import sys


def main():
    child = subprocess.Popen(
        ["bins/mach0/sleep-macos-arm64", "100"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        commands = []
        for _ in range(2):
            commands.extend([
                f"dpa {child.pid}",
                "%vi $P",
                "drj",
                "pxj 4 @ pc",
                "drj",
                "dp-",
            ])
        result = subprocess.run(
            ["rizin", "-N", "-e", "scr.interactive=false", "-e", "scr.color=0",
             "-e", "scr.utf8=0", "-qc", "\n".join(commands), "="],
            capture_output=True, text=True, timeout=15,
        )
        try:
            if result.returncode != 0 or result.stderr:
                raise ValueError("attach reported an error")
            records = [json.loads(line) for line in result.stdout.splitlines()]
            if len(records) != 8:
                raise ValueError("missing attach results")
            for index in (0, 4):
                pid, registers, code, after = records[index:index + 4]
                if pid != child.pid:
                    raise ValueError("attached to the wrong process")
                pc = registers["pc"]
                if pc <= 0 or pc >= (1 << 64) - 1 or pc % 4:
                    raise ValueError("invalid ARM64 program counter")
                if after["pc"] != pc:
                    raise ValueError("target was not stopped")
                if len(code) != 4 or code in ([0] * 4, [255] * 4):
                    raise ValueError("could not read the instruction at PC")
        except (ValueError, KeyError, TypeError) as error:
            sys.stderr.write(f"{error}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
            return 1
        print("attach, read registers and memory, reattach: OK")
        return 0
    finally:
        # Only this test's child is eligible, including on parse errors and timeouts.
        if child.poll() is None:
            child.kill()
        child.wait()


if __name__ == "__main__":
    sys.exit(main())
