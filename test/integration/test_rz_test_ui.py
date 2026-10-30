#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

"""Exercise the actual CLI, child process lifecycle and snapshot transactions."""

import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import time


def check_early_exit_and_timeout(run):
    """A worker must consume the script and obey its whole-test deadline."""
    early = 'NAME=early\nBROKEN=1\nARGS=-q -c "q"\nSTEPS=<<E\nQUIT\nE\n'
    run(early, expected=1)
    slow = 'NAME=timeout\nBROKEN=1\nTIMEOUT=1\nARGS=-c "sleep 5"\nSTEPS=<<E\nQUIT\nE\n'
    started = time.monotonic()
    run(slow, expected=1)
    assert time.monotonic() - started < 4, "parent must enforce the whole-test deadline"


def check_worker_lookup(executable, path, directory):
    """A runner may launch an absolute executable with an unusable argv[0]."""
    path.write_text("NAME=worker lookup\nSTEPS=<<E\nQUIT\nE\n", encoding="utf-8")
    result = subprocess.run(
        [
            str(pathlib.Path("missing-build-dir") / pathlib.Path(executable).name),
            "-r",
            str(pathlib.Path(executable).parent),
            str(path),
        ],
        executable=executable,
        cwd=directory,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stdout.decode("utf-8", "replace")
    return 1


def check_accepted_snapshot(path, prefix, original):
    """Replacement preserves fixture framing and permissions without leftovers."""
    accepted = path.read_bytes()
    assert accepted != original.encode("utf-8")
    assert accepted.startswith(prefix.replace("\n", "\r\n").encode("utf-8"))
    assert b"\n" not in accepted.replace(b"\r\n", b"")
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert not list(path.parent.glob("*.tmp")), "acceptance must remove temporary files"
    return accepted


def main():
    executable = str(pathlib.Path(sys.argv[1]).resolve())
    checks = 0
    with tempfile.TemporaryDirectory(prefix="rz ui ") as directory:
        root = pathlib.Path(directory)
        path = root / "screen with spaces.rzt-ui"

        def run(text=None, accept=False, expected=None):
            nonlocal checks
            if text is not None:
                path.write_bytes(text.encode("utf-8"))
                if os.name != "nt":
                    path.chmod(0o640)
            args = [executable, "-t", "2"]
            if accept:
                args.append("-a")
            args.append(str(path))
            result = subprocess.run(
                args,
                cwd=directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=10,
                check=False,
            )
            checks += 1
            if expected is not None:
                assert (
                    result.returncode == expected
                ), "expected exit {}, got {} ({:#x})\n{}".format(
                    expected,
                    result.returncode,
                    result.returncode & 0xFFFFFFFF,
                    result.stdout.decode("utf-8", "replace"),
                )
            return result

        prefix = (
            "NAME=snapshot\nFILE=malloc://128\n"
            'ARGS=-a x86 -b 64 -c "wx 554889e5897dfc8b07c3"\n'
            "STEPS=<<END\nKEYS V<ENTER>\n"
        )
        snapshots = "EXPECT_SCREEN <<SCREEN\nSCREEN\nKEY j\nEXPECT_SCREEN <<NEXT\nNEXT\nQUIT\nEND\n"
        text = (prefix + snapshots).replace("\n", "\r\n")
        run(text, accept=True, expected=1)
        accepted = check_accepted_snapshot(path, prefix, text)
        run(expected=0)
        run(accept=True, expected=0)
        assert path.read_bytes() == accepted, "acceptance must be idempotent"

        # A later non-snapshot failure prevents accepting earlier captures.
        unsafe = (
            prefix
            + "EXPECT_SCREEN <<SCREEN\nSCREEN\nEXPECT_LINE 0 never_present\nQUIT\nEND\n"
        )
        run(unsafe, accept=True, expected=1)
        assert path.read_bytes() == unsafe.encode("utf-8")

        # A failure in another record also prevents the file-wide replacement.
        mixed = (
            prefix
            + snapshots
            + "RUN\nNAME=bad\nSTEPS=<<E\nEXPECT_NOLINE 999 absent\nQUIT\nE\n"
        )
        run(mixed, accept=True, expected=1)
        assert path.read_bytes() == mixed.encode("utf-8")

        for invalid in (
            "EXPECT_LIEN 0 x",
            "EXPECT_NOREGEX [",
            "WAIT -1",
            "EXPECT_HLINE 0 4 2 -",
            "RESIZE 100x20junk",
        ):
            original = prefix + invalid + "\nQUIT\nEND\n"
            run(original, accept=True, expected=1)
            assert path.read_bytes() == original.encode("utf-8")

        run(prefix + "EXPECT_LINE 0 never_present\nQUIT\nEND\n", expected=1)
        run(
            prefix.replace("NAME=snapshot", "NAME=snapshot\nBROKEN=1")
            + "EXPECT_LINE 0 never_present\nQUIT\nEND\n",
            expected=0,
        )
        run(
            prefix.replace("NAME=snapshot", "NAME=snapshot\nBROKEN=1")
            + "EXPECT_LINE 0 malloc://128\nQUIT\nEND\n",
            expected=1,
        )

        check_early_exit_and_timeout(run)
        checks += check_worker_lookup(executable, path, root)

        # Reject the entire byte stream, including a hidden suffix after a NUL.
        run("NAME=nul\nSTEPS=<<E\nQUIT\nE\n\0ignored", accept=True, expected=1)
        run("#" * (16 * 1024 * 1024 + 1), expected=1)

        # Missing paths must be reported, not ignored.
        result = subprocess.run(
            [executable, str(root / "missing")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
        assert result.returncode != 0
        checks += 1
    print("{} UI lifecycle/acceptance checks passed".format(checks))


if __name__ == "__main__":
    main()
