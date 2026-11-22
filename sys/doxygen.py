#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

"""Build the Rizin API documentation with the Doxygen Awesome theme.

The checked-in Doxyfile holds every setting that does not depend on a path.
Everything that only the build system knows (where the theme was unpacked,
where the output goes, which version is being built) is appended here, so that
the Doxyfile stays free of build directory references and keeps working when
`doxygen` is invoked directly from the repository root.
"""

import argparse
import os
import subprocess
import sys

# Relative to the theme directory. The sidebar-only layout needs both.
THEME_STYLESHEETS = [
    "doxygen-awesome.css",
    "doxygen-awesome-sidebar-only.css",
]


def doxyfile_overrides(args):
    """Build the config lines that override the checked-in Doxyfile."""
    lines = []
    if args.output_dir:
        lines.append("OUTPUT_DIRECTORY = %s" % args.output_dir)
    if args.project_number:
        lines.append("PROJECT_NUMBER = %s" % args.project_number)
    if args.warnings_as_errors:
        lines.append("WARN_AS_ERROR = FAIL_ON_WARNINGS")
    if args.theme_dir:
        sheets = [os.path.join(args.theme_dir, name) for name in THEME_STYLESHEETS]
        missing = [sheet for sheet in sheets if not os.path.isfile(sheet)]
        if missing:
            raise SystemExit("missing theme file(s): %s" % ", ".join(missing))
        lines.append("HTML_EXTRA_STYLESHEET = %s" % " \\\n    ".join(sheets))
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--doxygen", default="doxygen", help="doxygen executable")
    parser.add_argument("--source-dir", default=".", help="repository root")
    parser.add_argument("--output-dir", help="where the generated docs are written")
    parser.add_argument("--theme-dir", help="doxygen-awesome-css checkout")
    parser.add_argument("--project-number", help="version shown in the docs")
    parser.add_argument(
        "--warnings-as-errors",
        action="store_true",
        help="fail on any Doxygen diagnostic (needs a pinned Doxygen version)",
    )
    args = parser.parse_args()

    doxyfile = os.path.join(args.source_dir, "Doxyfile")
    if not os.path.isfile(doxyfile):
        raise SystemExit("no Doxyfile in %s" % args.source_dir)

    with open(doxyfile, encoding="utf-8") as fd:
        config = fd.read()
    config += "\n" + "\n".join(doxyfile_overrides(args)) + "\n"

    # Doxygen resolves the relative paths of the Doxyfile against the current
    # directory, so it has to run from the repository root.
    proc = subprocess.run(
        [args.doxygen, "-"],
        cwd=args.source_dir,
        input=config,
        encoding="utf-8",
        check=False,
    )
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
