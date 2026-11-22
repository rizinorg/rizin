#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only
"""
check_outdated_subprojects.py

Check whether Rizin's Meson subproject wraps (subprojects/*.wrap) are outdated.

It understands the three ways a wrap can pin an upstream:

  * [wrap-file]            -> a versioned tarball (e.g. zstd-1.5.7). The current
                             version is read from the wrap and compared against
                             the newest upstream tag.
  * [wrap-git] + tag       -> e.g. revision = v1.11. Compared against newest tag.
  * [wrap-git] + commit    -> a 40-char SHA. Compared against the tip of the
                             tracked branch (newer commits == "behind").
  * [wrap-git] + branch    -> e.g. revision = main. Always builds the branch tip,
                             so it is reported as "tracking" (never "outdated").

Exit status is 1 if any wrap is OUTDATED (a newer release exists), else 0,
which makes it usable as a CI check. "behind"/"tracking"/"unknown" do not fail.

Usage:
    python3 check_outdated_subprojects.py [PATH] [options]

    PATH may be a rizin checkout, its subprojects/ dir, or omitted (auto-detect).

Options:
    --json                 Emit machine-readable JSON instead of a report.
    --include-prerelease   Flag newer pre-releases (alpha/beta/rc) as updates
                           even when the current pin is a stable release.
    --jobs N               Parallel ls-remote workers (default 8).
    --timeout S            Per-repo ls-remote timeout in seconds (default 30).
    --no-color             Disable ANSI colors.
    --self-test            Run the built-in unit tests (no network) and exit.
"""

import argparse
import concurrent.futures
import configparser
import json
import os
import re
import subprocess
import sys

GIT = "git"

# Upstreams whose wrap does not reference a git host we can ls-remote
# (e.g. zlib points only at tarball mirrors). Map wrap stem -> git URL.
UPSTREAM_OVERRIDES = {
    "zlib": "https://github.com/madler/zlib.git",
}

HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
GITHUB_RE = re.compile(r"github\.com[/:]+([^/]+)/([^/#?]+?)(?:\.git)?(?:[/#?]|$)")

# Matches the leading numeric, dot-separated part of a version string, e.g.
# the "5.8.1" in "5.8.1-Alpha9". It is anchored at the start of the (already
# prefix-stripped) core and has no nested or overlapping quantifiers, so it
# always runs in linear time.
_REL_RE = re.compile(r"\d+(?:\.\d+)*")
_ARCHIVE_EXTS = (
    ".tar.gz",
    ".tar.xz",
    ".tar.bz2",
    ".tar.zst",
    ".tgz",
    ".txz",
    ".tbz2",
    ".zip",
    ".gz",
    ".xz",
    ".bz2",
)


# --------------------------------------------------------------------------- #
# Version parsing & comparison
# --------------------------------------------------------------------------- #
def _chunks(s):
    """Split a pre-release string into comparable (is_alpha, num, text) units."""
    out = []
    for part in re.findall(r"\d+|[^\d]+", s):
        if part.isdigit():
            out.append((0, int(part), ""))
        else:
            out.append((1, 0, part))
    return tuple(out)


def _version_core(tag):
    """Return the version core of *tag* with any name prefix and leading "v"
    removed, e.g. "xz-5.8.1" -> "5.8.1", "v1.3" -> "1.3", "6.0.0-Alpha9"
    unchanged. Returns None if *tag* has no version core.

    The name prefix is stripped with a plain left-to-right string scan rather
    than a regular expression, so this is guaranteed to run in linear time and
    cannot suffer from catastrophic backtracking (ReDoS).
    """
    if not tag:
        return None
    s = tag.strip()
    start = 0
    if not (s[:1].isdigit() or (s[:1] in "vV" and s[1:2].isdigit())):
        # There is a name prefix. The version begins right after the first
        # "-"/"_" that is followed by an optional "v" and a digit; everything
        # before it (e.g. "tree-sitter-") is the name. Stopping at the *first*
        # such separator mirrors the original regex, whose name segments each
        # had to start with a letter -- so a dash-separated numeric tail like
        # "rel-0-11-18" keeps its leading "0" rather than collapsing to "18".
        boundary = -1
        for i, ch in enumerate(s):
            if ch in "-_":
                j = i + 1
                if j < len(s) and s[j] in "vV":
                    j += 1
                if j < len(s) and s[j].isdigit():
                    boundary = i
                    break
        if boundary < 0:
            return None
        start = boundary + 1
    core = s[start:]
    if core[:1] in "vV" and core[1:2].isdigit():
        core = core[1:]
    return core if core[:1].isdigit() else None


def parse_version(tag):
    """Return (release_tuple, is_final, prerelease_chunks) or None if not a version."""
    core = _version_core(tag)
    if core is None:
        return None
    m = _REL_RE.match(core)
    if not m:
        return None
    release = tuple(int(x) for x in m.group(0).split("."))
    pre = core[m.end() :].lstrip("-._").lower()
    return (release, pre == "", _chunks(pre) if pre else ())


def version_key(parsed):
    """Sort key: higher == newer. A final release outranks its pre-releases."""
    release, is_final, pre = parsed
    return (release, 1 if is_final else 0, pre)


def version_display(tag):
    """Human-friendly version core (drops name prefixes / leading v)."""
    core = _version_core(tag)
    return core if core is not None else tag


def best_tag(tags, include_pre):
    """Return (raw_tag, key) for the newest version-like tag, or (None, None)."""
    best, best_key = None, None
    for t in tags:
        p = parse_version(t)
        if p is None:
            continue
        if not include_pre and not p[1]:  # skip pre-releases unless asked
            continue
        k = version_key(p)
        if best_key is None or k > best_key:
            best, best_key = t, k
    return best, best_key


def compare_to_tags(current_raw, tags, include_pre):
    """Compare a current version string against a set of upstream tags."""
    cur = parse_version(current_raw)
    if cur is None:
        return "unknown", None, "could not parse current version %r" % current_raw
    inc = (not cur[1]) or include_pre  # if current is a pre-release, consider all
    best, best_key = best_tag(tags, inc)
    if best is None:  # no stable tags? fall back to anything parseable
        best, best_key = best_tag(tags, True)
    if best is None:
        return "unknown", None, "no version-like tags found upstream"
    if best_key > version_key(cur):
        return "outdated", best, None
    return "up-to-date", best, None


# --------------------------------------------------------------------------- #
# git ls-remote
# --------------------------------------------------------------------------- #
def remote_refs(url, timeout):
    """Return {'heads':{}, 'tags':{}, 'default':str, 'head':sha} or {'error':...}."""
    try:
        p = subprocess.run(
            [GIT, "ls-remote", "--symref", url],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": "timeout after %ss" % timeout}
    except FileNotFoundError:
        return {"error": "the `git` binary was not found"}
    if p.returncode != 0:
        tail = (p.stderr or "").strip().splitlines()
        return {"error": tail[-1] if tail else "git ls-remote rc=%d" % p.returncode}

    heads, tags, default, head = {}, {}, None, None
    for line in p.stdout.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("ref: "):
            try:
                ref, name = line[5:].split("\t", 1)
            except ValueError:
                continue
            if name == "HEAD" and ref.startswith("refs/heads/"):
                default = ref[len("refs/heads/") :]
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        sha, ref = parts
        if ref == "HEAD":
            head = sha
        elif ref.startswith("refs/heads/"):
            heads[ref[len("refs/heads/") :]] = sha
        elif ref.startswith("refs/tags/"):
            name = ref[len("refs/tags/") :]
            peeled = name.endswith("^{}")
            if peeled:
                name = name[:-3]
            if peeled or name not in tags:  # prefer the dereferenced commit
                tags[name] = sha
    if default is None and head is not None:
        for n, s in heads.items():
            if s == head:
                default = n
                break
    return {"heads": heads, "tags": tags, "default": default, "head": head}


# --------------------------------------------------------------------------- #
# Wrap parsing & analysis
# --------------------------------------------------------------------------- #
def load_wrap(path):
    cp = configparser.ConfigParser(strict=False, delimiters=("=",), interpolation=None)
    cp.optionxform = str  # keep key case as-is
    cp.read(path, encoding="utf-8")
    return cp


def strip_archive_ext(name):
    low = name.lower()
    for ext in _ARCHIVE_EXTS:
        if low.endswith(ext):
            return name[: -len(ext)]
    return name


def github_url(urls):
    for u in urls:
        if not u:
            continue
        m = GITHUB_RE.search(u)
        if m:
            return "https://github.com/%s/%s.git" % (
                m.group(1),
                m.group(2),
            ), "%s/%s" % (m.group(1), m.group(2))
    return None, None


def current_version_from_file(sec):
    """Best-effort current version for a [wrap-file]."""
    candidates = [
        sec.get("directory", ""),
        strip_archive_ext(sec.get("source_filename", "")),
    ]
    for c in candidates:
        if parse_version(c):
            return c
    # Fall back to a version-looking path segment in the URLs
    # (e.g. zydis: .../download/v4.1.0/zydis-amalgamated.tar.gz).
    for key in ("source_url", "source_fallback_url"):
        for part in sec.get(key, "").split("/"):
            if parse_version(part):
                return part
    return ""


def preferred_branch(stem, heads, default):
    """Pick the branch a commit-pinned wrap most likely tracks."""
    chosen = default
    for seg in re.split(r"[-_]", stem):
        if seg in heads:
            chosen = seg  # last matching segment wins (e.g. capstone-"next")
    if chosen in heads:
        return chosen
    return default if default in heads else None


def short(sha):
    return sha[:10] if sha else sha


def analyze(path, args):
    """Return a result dict for a single wrap file."""
    stem = os.path.basename(path)[:-5]  # drop ".wrap"
    res = {
        "name": stem,
        "repo": None,
        "category": None,
        "current": None,
        "latest": None,
        "status": "unknown",
        "detail": None,
    }
    try:
        cp = load_wrap(path)
    except configparser.Error as e:
        res["detail"] = "failed to parse wrap: %s" % e
        return res

    if cp.has_section("wrap-file"):
        sec = cp["wrap-file"]
        res["category"] = "version"
        res["current"] = version_display(current_version_from_file(sec))
        url, repo = github_url(
            [sec.get("source_url", ""), sec.get("source_fallback_url", "")]
        )
        if url is None and stem in UPSTREAM_OVERRIDES:
            url = UPSTREAM_OVERRIDES[stem]
            repo = re.sub(r"^https?://github\.com/|\.git$", "", url)
        res["repo"] = repo or "(unknown upstream)"
        if url is None:
            res["detail"] = "no upstream git repo found in wrap"
            return res
        refs = remote_refs(url, args.timeout)
        if "error" in refs:
            res["detail"] = refs["error"]
            return res
        status, best, detail = compare_to_tags(
            current_version_from_file(sec), set(refs["tags"]), args.include_prerelease
        )
        res["status"] = status
        res["detail"] = detail
        if best is not None:
            res["latest"] = version_display(best)
        return res

    if cp.has_section("wrap-git"):
        sec = cp["wrap-git"]
        url = sec.get("url", "").strip()
        revision = sec.get("revision", "").strip()
        res["repo"] = re.sub(r"^https?://(?:github\.com/)?|\.git$", "", url) or url
        if not url or not revision:
            res["detail"] = "wrap-git missing url or revision"
            return res
        refs = remote_refs(url, args.timeout)
        if "error" in refs:
            res["detail"] = refs["error"]
            return res

        if HEX40.match(revision):  # pinned commit
            res["category"] = "commit"
            res["current"] = short(revision)
            branch = preferred_branch(stem, refs["heads"], refs["default"])
            if branch is None:
                res["detail"] = "could not determine a branch to compare against"
                return res
            tip = refs["heads"][branch]
            res["latest"] = short(tip)
            if tip.lower() == revision.lower():
                res["status"] = "up-to-date"
                res["detail"] = "at tip of %s" % branch
            else:
                res["status"] = "behind"
                res["detail"] = "pinned %s, %s tip is %s" % (
                    short(revision),
                    branch,
                    short(tip),
                )
            return res

        if revision in refs["heads"]:  # tracks a moving branch
            res["category"] = "branch"
            res["current"] = revision
            res["latest"] = short(refs["heads"][revision])
            res["status"] = "tracking"
            res["detail"] = "builds latest commit of branch %r" % revision
            return res

        # otherwise treat as a tag (it is in refs/tags, or just looks like a version)
        res["category"] = "tag"
        res["current"] = version_display(revision)
        if revision not in refs["tags"] and parse_version(revision) is None:
            res["detail"] = "revision %r is not a known tag/branch/commit" % revision
            return res
        status, best, detail = compare_to_tags(
            revision, set(refs["tags"]), args.include_prerelease
        )
        res["status"] = status
        res["detail"] = detail
        if best is not None:
            res["latest"] = version_display(best)
        return res

    res["detail"] = "no [wrap-file] or [wrap-git] section"
    return res


# --------------------------------------------------------------------------- #
# Discovery, reporting, CLI
# --------------------------------------------------------------------------- #
def find_subprojects_dir(path):
    if path is None:
        for cand in ("subprojects", "."):
            if os.path.isdir(cand) and any(
                f.endswith(".wrap") for f in os.listdir(cand)
            ):
                return cand
        return None
    sub = os.path.join(path, "subprojects")
    if os.path.isdir(sub):
        return sub
    if os.path.isdir(path) and any(f.endswith(".wrap") for f in os.listdir(path)):
        return path
    return None


# status -> (symbol, label, color)
_STATUS = {
    "outdated": ("[!]", "OUTDATED", "\033[31m"),  # red
    "behind": ("[~]", "BEHIND", "\033[33m"),  # yellow
    "tracking": ("[>]", "TRACKING", "\033[36m"),  # cyan
    "up-to-date": ("[+]", "UP TO DATE", "\033[32m"),  # green
    "unknown": ("[?]", "UNKNOWN", "\033[35m"),  # magenta
}
_ORDER = ["outdated", "behind", "unknown", "tracking", "up-to-date"]
_RESET = "\033[0m"


def render(results, use_color):
    def c(text, code):
        return "%s%s%s" % (code, text, _RESET) if use_color else text

    width = max((len(r["name"]) for r in results), default=4)
    by_status = {}
    for r in results:
        by_status.setdefault(r["status"], []).append(r)

    lines = []
    for status in _ORDER:
        group = by_status.get(status)
        if not group:
            continue
        sym, label, color = _STATUS[status]
        lines.append("")
        lines.append(c("%s %s" % (sym, label), color))
        for r in sorted(group, key=lambda x: x["name"]):
            cur = r["current"] or "?"
            if r["status"] in ("outdated",):
                ver = "%s -> %s" % (cur, r["latest"] or "?")
            elif r["status"] == "behind":
                ver = "%s -> %s" % (cur, r["latest"] or "?")
            elif r["status"] in ("up-to-date", "tracking"):
                ver = cur
            else:
                ver = cur
            detail = " (%s)" % r["detail"] if r["detail"] else ""
            lines.append(
                "    %-*s  %-22s %s%s"
                % (width, r["name"], ver, r["repo"] or "", c(detail, "\033[90m"))
            )

    n_out = len(by_status.get("outdated", []))
    n_behind = len(by_status.get("behind", []))
    n_unknown = len(by_status.get("unknown", []))
    lines.append("")
    lines.append("-" * 60)
    summary = "%d outdated, %d behind, %d tracking, %d up-to-date, %d unknown" % (
        n_out,
        n_behind,
        len(by_status.get("tracking", [])),
        len(by_status.get("up-to-date", [])),
        n_unknown,
    )
    lines.append(c(summary, "\033[1m") if use_color else summary)
    return "\n".join(lines), n_out


# --------------------------------------------------------------------------- #
# Built-in unit tests (run with --self-test; no network required)
# --------------------------------------------------------------------------- #
def run_self_tests():
    """Exercise the offline version/wrap logic with inline unit tests.

    Only the pure helpers are covered (parsing, comparison, classification,
    URL/version extraction); the ls-remote layer needs the network and is left
    out. Returns 0 if every check passes and 1 otherwise, so it can be wired
    into CI as ``check_outdated_subprojects.py --self-test``.
    """
    import time

    checks = []

    def eq(label, got, want):
        checks.append(got == want)
        if got != want:
            print("FAIL  %s" % label)
            print("        got:  %r" % (got,))
            print("        want: %r" % (want,))

    def ok(label, cond):
        checks.append(bool(cond))
        if not cond:
            print("FAIL  %s" % label)

    # -- parse_version: name prefixes, leading "v", pre-releases, non-versions --
    eq("parse xz-5.8.1", parse_version("xz-5.8.1"), ((5, 8, 1), True, ()))
    eq("parse v1.3.1", parse_version("v1.3.1"), ((1, 3, 1), True, ()))
    eq("parse zstd-1.5.7", parse_version("zstd-1.5.7"), ((1, 5, 7), True, ()))
    eq(
        "parse tree-sitter-0.25.3",
        parse_version("tree-sitter-0.25.3"),
        ((0, 25, 3), True, ()),
    )
    eq("parse pcre2-10.47", parse_version("pcre2-10.47"), ((10, 47), True, ()))
    eq("parse v1.11", parse_version("v1.11"), ((1, 11), True, ()))
    eq(
        "parse capstone-6.0.0-Alpha9",
        parse_version("capstone-6.0.0-Alpha9"),
        ((6, 0, 0), False, ((1, 0, "alpha"), (0, 9, ""))),
    )
    # A dash-separated numeric tail (libzip's rel-* tags) must keep its leading
    # number instead of collapsing to the last one -- regression guard.
    eq(
        "parse rel-0-11-18",
        parse_version("rel-0-11-18"),
        ((0,), False, ((0, 11, ""), (1, 0, "-"), (0, 18, ""))),
    )
    ok("1.0.0 is final", parse_version("1.0.0")[1] is True)
    ok("1.0.0-rc1 is not final", parse_version("1.0.0-rc1")[1] is False)
    for nonver in ("main", "dev", "master", "", None, "zydis-amalgamated.tar.gz"):
        eq("parse %r -> None" % (nonver,), parse_version(nonver), None)

    # -- version_display --
    eq("display xz-5.8.1", version_display("xz-5.8.1"), "5.8.1")
    eq("display v5.8.3", version_display("v5.8.3"), "5.8.3")
    eq(
        "display capstone-6.0.0-Alpha9",
        version_display("capstone-6.0.0-Alpha9"),
        "6.0.0-Alpha9",
    )
    eq("display passthrough", version_display("main"), "main")

    # -- ordering: numeric (not lexical) and final outranks pre-release --
    def newer(a, b):
        return version_key(parse_version(a)) > version_key(parse_version(b))

    ok("5.8.3 > 5.8.1", newer("5.8.3", "5.8.1"))
    ok("1.10.0 > 1.9.2 (numeric, not string)", newer("1.10.0", "1.9.2"))
    ok("1.0.1 > 1.0", newer("1.0.1", "1.0"))
    ok("6.0.0 > 6.0.0-Alpha9 (final beats pre-release)", newer("6.0.0", "6.0.0-Alpha9"))
    ok("Alpha9 > Alpha2", newer("6.0.0-Alpha9", "6.0.0-Alpha2"))

    # -- best_tag --
    eq(
        "best_tag newest",
        best_tag(["v1.0.0", "v1.2.0", "v1.10.0", "main"], False)[0],
        "v1.10.0",
    )
    eq(
        "best_tag skips pre-release by default",
        best_tag(["1.0.0", "2.0.0-rc1"], False)[0],
        "1.0.0",
    )
    eq(
        "best_tag includes pre-release on request",
        best_tag(["1.0.0", "2.0.0-rc1"], True)[0],
        "2.0.0-rc1",
    )
    eq("best_tag no version-like tags", best_tag(["main", "dev"], True), (None, None))

    # -- compare_to_tags: the OUTDATED / UP-TO-DATE / UNKNOWN decision --
    def status(cur, tags, inc=False):
        return compare_to_tags(cur, set(tags), inc)[0]

    eq("compare outdated", status("5.8.1", ["v5.8.1", "v5.8.3"]), "outdated")
    eq(
        "compare reports newest tag",
        compare_to_tags("5.8.1", {"v5.8.1", "v5.8.3"}, False)[1],
        "v5.8.3",
    )
    eq(
        "compare up-to-date (numeric)",
        status("1.10.0", ["v1.9.2", "v1.10.0"]),
        "up-to-date",
    )
    eq("compare unparseable current -> unknown", status("main", ["v1.0.0"]), "unknown")
    eq("compare no upstream tags -> unknown", status("1.0.0", []), "unknown")
    eq(
        "compare stable pin ignores newer pre-release",
        status("1.0.0", ["1.0.0", "2.0.0-rc1"], False),
        "up-to-date",
    )
    eq(
        "compare --include-prerelease flags it",
        status("1.0.0", ["1.0.0", "2.0.0-rc1"], True),
        "outdated",
    )
    eq(
        "compare pre-release pin sees newer pre-release",
        status("6.0.0-Alpha2", ["6.0.0-Alpha2", "6.0.0-Alpha9"]),
        "outdated",
    )

    # -- github_url: owner/repo extraction from assorted URL shapes --
    eq(
        "github_url release tarball",
        github_url(
            ["https://github.com/tukaani-project/xz/releases/download/v5.8.1/xz.tar.gz"]
        )[1],
        "tukaani-project/xz",
    )
    eq(
        "github_url .git suffix",
        github_url(["https://github.com/zyantific/zydis.git"])[1],
        "zyantific/zydis",
    )
    eq(
        "github_url scp syntax",
        github_url(["git@github.com:foo/bar.git"])[1],
        "foo/bar",
    )
    eq("github_url skips empties", github_url(["", "https://github.com/a/b"])[1], "a/b")
    eq(
        "github_url non-github",
        github_url(["https://zlib.net/zlib.tar.gz"]),
        (None, None),
    )

    # -- strip_archive_ext --
    eq("strip .tar.gz", strip_archive_ext("xz-5.8.1.tar.gz"), "xz-5.8.1")
    eq("strip .zip", strip_archive_ext("zydis-amalgamated.zip"), "zydis-amalgamated")
    eq("strip .tar.xz", strip_archive_ext("file.tar.xz"), "file")
    eq("strip none", strip_archive_ext("plain"), "plain")

    # -- current_version_from_file (a plain dict stands in for a wrap section) --
    eq(
        "cvff directory",
        current_version_from_file({"directory": "xz-5.8.1"}),
        "xz-5.8.1",
    )
    eq(
        "cvff filename fallback",
        current_version_from_file(
            {"directory": "", "source_filename": "lz4-1.10.0.tgz"}
        ),
        "lz4-1.10.0",
    )
    eq(
        "cvff url fallback (zydis amalgamated)",
        current_version_from_file(
            {
                "directory": "zydis",
                "source_filename": "zydis-amalgamated.tar.gz",
                "source_url": "https://github.com/zyantific/zydis/releases/download/v4.1.0/zydis-amalgamated.tar.gz",
            }
        ),
        "v4.1.0",
    )

    # -- preferred_branch --
    heads = {"master": "a", "next": "b", "main": "c"}
    eq(
        "branch segment match",
        preferred_branch("capstone-next", heads, "master"),
        "next",
    )
    eq("branch default fallback", preferred_branch("blake3", heads, "master"), "master")
    eq("branch none available", preferred_branch("foo", {"main": "c"}, "master"), None)

    # -- ReDoS guard: adversarial input must still parse in linear time --
    evil = "a" + "_a" * 10000
    t0 = time.perf_counter()
    parsed_evil = parse_version(evil)
    dt = time.perf_counter() - t0
    eq("adversarial input -> None", parsed_evil, None)
    ok("adversarial input parsed in <1s (took %.4fs)" % dt, dt < 1.0)

    total = len(checks)
    failed = sum(1 for c in checks if not c)
    print("")
    if failed:
        print("self-test: %d of %d checks FAILED" % (failed, total))
        return 1
    print("self-test: all %d checks passed" % total)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Check whether Rizin's Meson subproject wraps are outdated.",
        epilog="Exit code is 1 if any wrap is OUTDATED, else 0. "
        "BEHIND/TRACKING/UNKNOWN do not affect the exit code.",
    )
    ap.add_argument(
        "path",
        nargs="?",
        default=None,
        help="rizin checkout or its subprojects/ dir (auto-detected if omitted)",
    )
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument(
        "--include-prerelease",
        action="store_true",
        help="flag newer alpha/beta/rc releases even for stable pins",
    )
    ap.add_argument("--jobs", type=int, default=8, help="parallel workers (default 8)")
    ap.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="per-repo ls-remote timeout in seconds (default 30)",
    )
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the built-in unit tests (no network) and exit",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_tests()

    sub = find_subprojects_dir(args.path)
    if sub is None:
        sys.stderr.write(
            "error: could not find a subprojects/ directory with "
            "*.wrap files. Pass the rizin path explicitly.\n"
        )
        return 2
    wraps = sorted(os.path.join(sub, f) for f in os.listdir(sub) if f.endswith(".wrap"))
    if not wraps:
        sys.stderr.write("error: no *.wrap files in %s\n" % sub)
        return 2

    if not args.json:
        sys.stderr.write("Checking %d wraps in %s ...\n" % (len(wraps), sub))

    workers = max(1, min(args.jobs, len(wraps)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda p: analyze(p, args), wraps))

    if args.json:
        print(json.dumps(results, indent=2))
        return 1 if any(r["status"] == "outdated" for r in results) else 0

    use_color = (not args.no_color) and sys.stdout.isatty()
    report, n_out = render(results, use_color)
    print(report)
    return 1 if n_out else 0


if __name__ == "__main__":
    sys.exit(main())
