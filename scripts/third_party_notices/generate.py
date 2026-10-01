#!/usr/bin/env python3
"""Generate THIRD-PARTY-NOTICES.txt for a Rust release build.

The notices cover every package `cargo tree` resolves for the build (normal and
build dependencies, for the given targets and features), so they over-cover
rather than miss: build tools are listed too. For each package:

- its declared licence must be allowed by the config's policy, and the text of
  the licence it is redistributed under must be in one of its crate-level
  licence files (licence files of bundled components do not count);
  for a choice of licences (`OR`) the notices record which one applies;
- every licence, copyright, notice and authors file it ships, at any depth, is
  reproduced unaltered, identical texts once;
- when a package ships no such files, or none containing the licence it is
  redistributed under, its repository is searched at the exact commit
  recorded in its `.cargo_vcs_info.json` (or, for a git dependency, Cargo's
  checkout at the locked commit), and failing that a reviewed config entry
  may supply the canonical text for that one version;
- a package that may contain native code (it ships C, C++ or assembly sources
  or prebuilt libraries, has a cc/cmake/nasm build dependency, a `links` key,
  or is a `*-src` crate) needs a reviewed config entry saying what it bundles.

Any gap fails generation. Requires Python 3.11+, cargo and a Cargo.lock. Set
GITHUB_TOKEN to raise the GitHub API rate limit.
"""

import argparse
import glob
import hashlib
import http.client
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request

LICENCE_FILE = re.compile(
    r"^(LICEN[CS]ES?|COPYING|COPYRIGHT|NOTICES?|UNLICENSE|AUTHORS|PATENTS?|CREDITS"
    r"|ATTRIBUTIONS?|THIRD[-_ ]?PARTY[-_ A-Z]*)([-._ ].*)?$",
    re.I,
)
NATIVE_BUILD_DEPS = {"cc", "cmake", "nasm-rs", "autotools"}
NATIVE_FILE = re.compile(
    r"\.(c|cc|cpp|cxx|c\+\+|m|mm|cu|s|asm|a|lib|o|obj|so|dylib|dll)$", re.I
)
# Phrases that identify a licence text, compared case-insensitively with
# whitespace collapsed: a text must contain every `has` phrase and none of the
# `lacks` phrases. A licence a crate is redistributed under must be identified
# in one of its reproduced files; for `X WITH Y` both parts must be.
LICENCE_MARKERS = {
    "MIT": {"has": ["permission is hereby granted, free of charge",
                    "the above copyright notice and this permission notice shall be included"]},
    "MIT-0": {"has": ["permission is hereby granted, free of charge"],
              "lacks": ["the above copyright notice and this permission notice shall be included"]},
    "Apache-2.0": {"has": ["apache license", "version 2.0",
                           "terms and conditions for use, reproduction, and distribution"]},
    "BSD-2-Clause": {"has": ["redistribution and use in source and binary forms",
                             "redistributions in binary form must reproduce"],
                     "lacks": ["neither the name"]},
    "BSD-3-Clause": {"has": ["redistribution and use in source and binary forms",
                             "redistributions in binary form must reproduce", "neither the name"]},
    "ISC": {"has": ["permission to use, copy, modify, and",
                    "provided that the above copyright notice and this permission notice appear"]},
    "0BSD": {"has": ["permission to use, copy, modify, and/or distribute this software for any purpose"],
             "lacks": ["provided that the above copyright notice"]},
    "Zlib": {"has": ["without any express or implied warranty",
                     "altered source versions must be plainly marked"]},
    "CC0-1.0": {"has": ["cc0 1.0 universal"]},
    "Unlicense": {"has": ["free and unencumbered software released into the public domain"]},
    "BSL-1.0": {"has": ["boost software license - version 1.0"]},
    "Unicode-3.0": {"has": ["unicode license v3"]},
    "Unicode-DFS-2016": {"has": ["unicode, inc. license agreement - data files and software"]},
    "CDLA-Permissive-2.0": {"has": ["community data license agreement - permissive - version 2.0"]},
    "MPL-2.0": {"has": ["mozilla public license version 2.0"]},
    "GPL-3.0": {"has": ["gnu general public license", "version 3, 29 june 2007"]},
    "GPL-3.0-only": {"has": ["gnu general public license", "version 3, 29 june 2007"]},
    "LLVM-exception": {"has": ["llvm exceptions to the apache 2.0 license"]},
}
CRATES_IO = ("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")
TREE_LINE = re.compile(r"^(\S+) v(\S+)(?: \((.+)\))?$")
GITHUB_REPO = re.compile(r"github\.com[/:]([^/]+)/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$")
SPDX_TOKEN = re.compile(r"\(|\)|[^\s()]+")
RULE = "=" * 80
THIN_RULE = "-" * 80


class Gap(Exception):
    """A missing or ambiguous input that would make the notices incomplete."""


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise Gap(f"{' '.join(cmd)} failed:\n{result.stderr}")
    return result.stdout


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def decode(data, where):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Gap(f"{where} is not UTF-8 ({error}); add it by hand") from error


# --- dependency graph -------------------------------------------------------

def cargo_selection(args):
    # Colour is off so CARGO_TERM_COLOR=always in CI cannot corrupt the output.
    selection = ["--manifest-path", args.manifest_path, "--locked", "--color", "never"]
    if args.package:
        selection += ["-p", args.package]
    if args.no_default_features:
        selection.append("--no-default-features")
    if args.features:
        selection += ["--features", args.features]
    return selection


def release_graph(args):
    """(name, version, annotation) of every package in the build, per cargo tree."""
    nodes = set()
    for target in args.target:
        out = run(["cargo", "tree", "-e", "normal,build", "--target", target,
                   "--prefix", "none", "--format", "{p}"] + cargo_selection(args))
        for raw in out.splitlines():
            line = raw.strip().removesuffix(" (*)").removesuffix(" (proc-macro)")
            if not line:
                continue
            match = TREE_LINE.match(line)
            if not match:
                raise Gap(f"cannot parse cargo tree line: {raw!r}")
            nodes.add((match.group(1), match.group(2), match.group(3) or ""))
    return nodes


def resolve_package(name, version, annotation, by_name_version):
    """Match a cargo tree node to exactly one cargo metadata package."""
    candidates = by_name_version.get((name, version), [])
    if not annotation:
        matches = [p for p in candidates if (p["source"] or "").startswith(CRATES_IO)]
    elif annotation.startswith("registry "):
        raise Gap(f"{name} {version} comes from {annotation}; only crates.io is supported")
    elif "://" in annotation:
        matches = [p for p in candidates if (p["source"] or "").startswith("git+" + annotation)]
    else:
        wanted = os.path.realpath(annotation)
        matches = [p for p in candidates if p["source"] is None
                   and os.path.realpath(os.path.dirname(p["manifest_path"])) == wanted]
    if len(matches) != 1:
        raise Gap(f"{name} {version} ({annotation or 'crates.io'}) matches "
                  f"{len(matches)} packages in cargo metadata")
    return matches[0]


def source_url(package):
    source = package["source"] or ""
    name, version = package["name"], package["version"]
    if source.startswith(CRATES_IO):
        return f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
    if source.startswith("git+"):
        url, _, rev = source[4:].partition("#")
        return f"{url.split('?')[0]} at commit {rev}"
    return os.path.dirname(package["manifest_path"])


# --- licence policy ---------------------------------------------------------

def parse_spdx(expression):
    """Parse an SPDX expression (plus the legacy `/` for OR) into a tree."""
    tokens = SPDX_TOKEN.findall(expression.replace("/", " OR "))
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def take():
        nonlocal position
        if position >= len(tokens):
            raise Gap(f"malformed licence expression {expression!r}")
        position += 1
        return tokens[position - 1]

    def parse_or():
        node = parse_and()
        while peek() == "OR":
            take()
            node = ("OR", node, parse_and())
        return node

    def parse_and():
        node = parse_atom()
        while peek() == "AND":
            take()
            node = ("AND", node, parse_atom())
        return node

    def parse_atom():
        token = take()
        if token == "(":
            node = parse_or()
            if take() != ")":
                raise Gap(f"unbalanced licence expression {expression!r}")
            return node
        if token in (")", "AND", "OR", "WITH"):
            raise Gap(f"malformed licence expression {expression!r}")
        if peek() == "WITH":
            take()
            return ("LEAF", f"{token} WITH {take()}")
        return ("LEAF", token)

    tree = parse_or()
    if peek() is not None:
        raise Gap(f"malformed licence expression {expression!r}")
    return tree


def branches(tree):
    """The expression as alternatives, each a tuple of licences that all apply."""
    kind = tree[0]
    if kind == "LEAF":
        return [(tree[1],)]
    left, right = branches(tree[1]), branches(tree[2])
    if kind == "OR":
        return left + right
    return [a + b for a in left for b in right]


def identifies(licence, text):
    markers = LICENCE_MARKERS.get(licence)
    if markers is None:
        return False
    return (all(phrase in text for phrase in markers["has"])
            and not any(phrase in text for phrase in markers.get("lacks", [])))


COMMENT_PREFIX = re.compile(r"^\s*(//+|#+|\*+|/\*+|--|;+)?\s?", re.M)


def normalise(text):
    """Lower-cased text with comment prefixes removed and whitespace collapsed,
    so licence texts written as source comments are still recognised."""
    return re.sub(r"\s+", " ", COMMENT_PREFIX.sub("", text).lower())


def has_text(licence, texts):
    """Whether some text identifies the licence; `X WITH Y` needs both parts."""
    parts = licence.split(" WITH ")
    return all(any(identifies(part, text) for text in texts) for part in parts)


def elect(declared, rank, texts):
    """The licence terms we redistribute under: the most preferred allowed
    alternative whose every licence text is among the crate-level files."""
    normalised = [normalise(text) for text in texts]
    allowed = sorted((max(rank[licence] for licence in branch), branch)
                     for branch in branches(parse_spdx(declared))
                     if all(licence in rank for licence in branch))
    if not allowed:
        return None, "the policy allows none of its licences"
    for _, branch in allowed:
        if all(has_text(licence, normalised) for licence in branch):
            return " AND ".join(dict.fromkeys(branch)), None
    return None, "no crate-level licence file contains the text of an allowed option"


# --- licence texts ----------------------------------------------------------

def crate_licence_files(package):
    """Licence-like files anywhere in the crate, plus its declared license-file,
    as (label, bytes, governs). A file governs the crate itself when it sits at
    the crate root, under a top-level LICENSES directory, or is the declared
    license-file; deeper files belong to bundled components."""
    root = os.path.dirname(package["manifest_path"])
    found = {}
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d != "target")
        parts = [] if directory == root else os.path.relpath(directory, root).split(os.sep)
        inside_licenses = "licenses" in (part.lower() for part in parts)
        governs = not parts or parts[0].lower() == "licenses"
        for name in sorted(files):
            if inside_licenses or LICENCE_FILE.match(name):
                path = os.path.join(directory, name)
                found[os.path.relpath(path, root)] = (path, governs)
    declared = package.get("license_file")
    if declared:
        path = os.path.normpath(os.path.join(root, declared))
        if not os.path.isfile(path):
            raise Gap(f"{package['name']} {package['version']} declares license-file "
                      f"{declared!r}, which is missing")
        found[os.path.relpath(path, root)] = (path, True)
    return [(label, read_bytes(path), governs) for label, (path, governs) in sorted(found.items())]


def checkout_licence_files(package):
    """For a git dependency, licence files from the crate directory up to the
    root of Cargo's checkout of that repository at the locked commit."""
    directory = os.path.realpath(os.path.dirname(package["manifest_path"]))
    files = []
    while True:
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if os.path.isfile(path) and LICENCE_FILE.match(name):
                files.append((path, read_bytes(path)))
            elif os.path.isdir(path) and name.lower() == "licenses":
                for inner, _, inner_files in os.walk(path):
                    files += [(os.path.join(inner, f), read_bytes(os.path.join(inner, f)))
                              for f in sorted(inner_files)]
        if os.path.exists(os.path.join(directory, ".cargo-ok")) or os.path.exists(os.path.join(directory, ".git")):
            root = directory
            break
        parent = os.path.dirname(directory)
        if parent == directory:
            return []
        directory = parent
    rev = (package["source"] or "").partition("#")[2]
    return [(f"{os.path.relpath(path, root)} at {rev[:12]}", data, True) for path, data in files]


def ships_native_files(package):
    root = os.path.dirname(package["manifest_path"])
    for _, subdirs, files in os.walk(root):
        subdirs[:] = [d for d in subdirs if d != "target"]
        if any(NATIVE_FILE.search(name) for name in files):
            return True
    return False


def bundled_files(package, patterns, governs=False):
    """Extra licence files a config entry names: by default for bundled code,
    or, with `files_govern = true`, the crate's own unusually named licence."""
    root = os.path.realpath(os.path.dirname(package["manifest_path"]))
    files = []
    for pattern in patterns:
        matches = sorted(p for p in glob.glob(os.path.join(root, pattern), recursive=True)
                         if os.path.isfile(p))
        if not matches:
            raise Gap(f"{package['name']} {package['version']}: bundled licence file "
                      f"{pattern!r} not found")
        for path in matches:
            if os.path.commonpath([root, os.path.realpath(path)]) != root:
                raise Gap(f"{package['name']}: {pattern!r} escapes the crate")
            files.append((os.path.relpath(path, root), read_bytes(path), governs))
    return files


class GitHub:
    def __init__(self):
        self.token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.cache = {}

    def get(self, url, raw=False):
        if url in self.cache:
            return self.cache[url]
        headers = {"User-Agent": "third-party-notices"}
        if self.token and url.startswith("https://api.github.com/"):
            headers["Authorization"] = f"Bearer {self.token}"
        last_error = None
        for attempt in range(6):
            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=30) as response:
                    body = response.read()
                value = body if raw else json.loads(body)
                self.cache[url] = value
                return value
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    self.cache[url] = None
                    return None
                last_error = error
            except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
                # Covers timeouts and dropped connections as well as DNS errors.
                last_error = error
            time.sleep(2 ** attempt)
        raise Gap(f"request failed after retries: {url}: {last_error}")

    def licence_files(self, package):
        """Licence-like files from the crate's directory up to its repository
        root, at the commit the crate was published from."""
        match = GITHUB_REPO.search(package.get("repository") or "")
        vcs_path = os.path.join(os.path.dirname(package["manifest_path"]), ".cargo_vcs_info.json")
        if not match or not os.path.isfile(vcs_path):
            return []
        owner, repo = match.group(1), match.group(2)
        with open(vcs_path) as handle:
            vcs = json.load(handle)
        sha = vcs.get("git", {}).get("sha1")
        if not sha:
            return []
        files = []
        directory = vcs.get("path_in_vcs", "")
        while True:
            for entry in self.listing(owner, repo, sha, directory):
                if entry["type"] == "file" and LICENCE_FILE.match(entry["name"]):
                    files.append(entry)
                elif entry["type"] == "dir" and entry["name"].lower() == "licenses":
                    files += self.all_files(owner, repo, sha, entry["path"])
            if not directory:
                break
            directory = os.path.dirname(directory)
        where = f"{owner}/{repo}@{sha[:12]}"
        return [(f"{where}/{entry['path']}", self.get(entry["download_url"], raw=True), True)
                for entry in sorted(files, key=lambda entry: entry["path"])]

    def all_files(self, owner, repo, sha, directory):
        files = []
        for entry in self.listing(owner, repo, sha, directory):
            if entry["type"] == "file":
                files.append(entry)
            elif entry["type"] == "dir":
                files += self.all_files(owner, repo, sha, entry["path"])
        return files

    def listing(self, owner, repo, sha, directory):
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{directory}?ref={sha}"
        listing = self.get(url)
        return sorted(listing, key=lambda entry: entry["name"]) if isinstance(listing, list) else []


# --- generation -------------------------------------------------------------

def entry_for(table, package, required_version=False):
    """The config entry for a package. Entries may name a `version`; exception
    and missing-text entries must, because their conclusions are per release."""
    entry = table.get(package["name"])
    if entry is None:
        return None
    if "version" in entry:
        return entry if entry["version"] == package["version"] else None
    if required_version:
        raise Gap(f"config entry for {package['name']} must name the reviewed `version`")
    return entry


def generate(args, config, github):
    rank = {licence: index for index, licence in enumerate(config["allowed"])}
    exceptions = config.get("exception", {})
    native_config = config.get("native", {})
    remarks = config.get("remark", {})
    missing_config = config.get("missing", {})
    used = set()

    # The same feature selection as the graph, so packages that only the
    # requested features pull in are present.
    selection = ["--no-default-features"] if args.no_default_features else []
    if args.features:
        selection += ["--features", args.features]
    metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--color", "never",
                               "--manifest-path", args.manifest_path, "--locked"] + selection))
    by_name_version = {}
    for package in metadata["packages"]:
        by_name_version.setdefault((package["name"], package["version"]), []).append(package)
    workspace = set(metadata["workspace_members"])

    gaps, index, notes, texts = [], [], [], {}
    for name, version, annotation in sorted(release_graph(args)):
        crate = f"{name} {version}"
        try:
            package = resolve_package(name, version, annotation, by_name_version)
            if package["id"] in workspace:
                continue  # first-party code, covered by the project's own licence

            declared = package.get("license")
            files = crate_licence_files(package)
            origins = {"crate"} if files else set()

            def repository_files():
                if (package["source"] or "").startswith("git+"):
                    return checkout_licence_files(package)
                return github.licence_files(package)

            if not files:
                files = repository_files()
                origins = {"repository"} if files else set()

            # Code the crate bundles: its licence files are reproduced, but they
            # never stand in for the crate's own licence.
            build_deps = {dep["name"] for dep in package["dependencies"] if dep.get("kind") == "build"}
            builds_native = bool(build_deps & NATIVE_BUILD_DEPS or package.get("links")
                                 or name.endswith("-src") or ships_native_files(package))
            native = entry_for(native_config, package) if builds_native else None
            if builds_native and native is None:
                raise Gap(f"{crate} may contain native code; review what it bundles and "
                          f"add [native.{name}] to the config")
            if native is not None:
                used.add(("native", name))
                labels = {label for label, _, _ in files}
                files += [extra for extra in bundled_files(package, native.get("files", []),
                                                            native.get("files_govern", False))
                          if extra[0] not in labels]

            exception = entry_for(exceptions, package, required_version=True)
            missing = entry_for(missing_config, package, required_version=True)
            if exception is None and not declared:
                raise Gap(f"{crate} declares no SPDX licence; review it and add [exception.{name}]")

            def decide():
                governing = [decode(data, f"{crate}: {label}") for label, data, governs in files if governs]
                if exception is None:
                    return elect(declared, rank, governing)
                licence = exception["licence"]
                if declared and (licence,) not in branches(parse_spdx(declared)):
                    raise Gap(f"{crate}: [exception.{name}] licence {licence!r} is not one "
                              f"of {declared!r}")
                if has_text(licence, [normalise(text) for text in governing]):
                    return licence, None
                return None, f"no crate-level licence file contains the {licence} text"

            # When the chosen licence's text is not among the crate-level files,
            # look in its repository, then in a reviewed supplement from the config.
            elected, problem = decide()
            if elected is None and "repository" not in origins:
                known = {hashlib.sha256(data).hexdigest() for _, data, governs in files if governs}
                extra = [item for item in repository_files()
                         if hashlib.sha256(item[1]).hexdigest() not in known]
                if extra:
                    files += extra
                    origins.add("repository")
                    elected, problem = decide()
            if elected is None and missing is not None:
                used.add(("missing", name))
                text = github.get(missing["text_url"], raw=True)
                if text is None or hashlib.sha256(text).hexdigest() != missing["text_sha256"]:
                    raise Gap(f"{crate}: {missing['text_url']} does not match text_sha256")
                files.append((missing["text_url"], text, True))
                origins.add("config")
                notes.append((crate, missing["note"]))
                elected, problem = decide()
            if elected is None:
                raise Gap(f"{crate} ({declared or 'no licence declared'}): {problem}; review it "
                          f"and add [missing.{name}] or [exception.{name}]")
            if exception is not None:
                used.add(("exception", name))
                notes.append((crate, exception["reason"]))
            if native is not None:
                notes.append((crate, native["note"]))
            remark = entry_for(remarks, package)
            if remark is not None:
                used.add(("remark", name))
                notes.append((crate, remark["note"]))

            ids = []
            for label, data, _ in files:
                digest = hashlib.sha256(data).hexdigest()
                if digest not in texts:
                    texts[digest] = {"text": decode(data, f"{crate}: {label}"), "shipped_by": []}
                texts[digest]["shipped_by"].append((crate, label))
                ids.append(digest)
        except Gap as gap:
            gaps.append(str(gap))
            continue
        index.append((crate, declared or "(none declared)", elected, source_url(package), origins, ids))

    for kind, table in (("native", native_config), ("missing", missing_config),
                        ("exception", exceptions), ("remark", remarks)):
        for name in sorted(table):
            if (kind, name) not in used:
                print(f"note: [{kind}.{name}] is not used by this build", file=sys.stderr)
    if gaps:
        raise Gap("cannot produce complete notices:\n  " + "\n  ".join(gaps))
    return index, notes, texts


def musl_copyright(github):
    """musl's COPYRIGHT for the release the active rustc's musl targets use.

    Rust records the musl version it builds those targets from in
    src/ci/docker/scripts/musl.sh; the COPYRIGHT comes from that musl release
    tarball."""
    info = run(["rustc", "-vV"])
    commit = re.search(r"^commit-hash: (\S+)$", info, re.M)
    release = re.search(r"^release: (\S+)$", info, re.M)
    if not commit or not release:
        raise Gap(f"cannot read rustc's commit hash from:\n{info}")
    script = github.get("https://raw.githubusercontent.com/rust-lang/rust/"
                        f"{commit.group(1)}/src/ci/docker/scripts/musl.sh", raw=True)
    match = re.search(rb"^MUSL=musl-(\S+)$", script or b"", re.M)
    if not match:
        raise Gap(f"cannot find the musl version for rustc {release.group(1)}")
    version = match.group(1).decode()
    archive = github.get(f"https://musl.libc.org/releases/musl-{version}.tar.gz", raw=True)
    if archive is None:
        raise Gap(f"musl {version} release tarball not found")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        member = tar.extractfile(f"musl-{version}/COPYRIGHT")
        if member is None:
            raise Gap(f"musl {version} tarball has no COPYRIGHT")
        text = decode(member.read(), f"musl {version} COPYRIGHT")
    return version, f"Rust {release.group(1)}", text


def render(args, config, config_dir, index, notes, texts, github):
    numbers = {}
    for digest, _ in sorted(texts.items(), key=lambda item: item[1]["shipped_by"][0]):
        numbers[digest] = len(numbers) + 1
    if args.no_default_features:
        features = f"{args.features or 'none'} (default features off)"
    else:
        features = "default" + (f" plus {args.features}" if args.features else "")

    out = ["THIRD-PARTY SOFTWARE NOTICES", "", config["header"].strip(), ""]
    out += [
        "The crates below are compiled into this build or used to build it, unmodified",
        "from the source each entry names. Every licence, copyright, notice and",
        "authors file they ship is reproduced unaltered in the TEXTS section,",
        "identical texts once. Where a crate offers a choice of licences, it is",
        "redistributed under the terms named. Each Source link is the exact,",
        "unmodified source of that crate as used for this build, which is also how",
        "source is made available where a licence requires it (for example MPL-2.0).",
        "",
        f"Targets: {', '.join(args.target)}",
        f"Features: {features}",
        "",
        RULE, "CRATES", RULE,
    ]
    for crate, declared, elected, url, origins, ids in index:
        refs = ", ".join(f"[{numbers[digest]}]" for digest in dict.fromkeys(ids))
        where = ""
        if "repository" in origins:
            where += " (from the crate's repository)" if origins == {"repository"} else \
                " (some from the crate's repository)"
        if "config" in origins:
            where += " (see NOTES)"
        out.append(crate)
        out.append(f"    Licence: {declared}")
        if elected != declared:
            out.append(f"    Redistributed under: {elected}")
        out.append(f"    Source: {url}")
        out.append(f"    Texts: {refs}{where}")
    if notes:
        out += ["", RULE, "NOTES", RULE]
        out += [f"{crate}: {note}" for crate, note in notes]
    out += ["", RULE, "TEXTS", RULE]
    for digest, number in numbers.items():
        entry = texts[digest]
        shipped = ", ".join(f"{crate} ({label})" for crate, label in entry["shipped_by"])
        out += ["", THIN_RULE, f"[{number}] Shipped by: {shipped}", THIN_RULE, "",
                framed(entry["text"])]
    for appendix in config.get("appendix", []):
        wanted = appendix.get("targets")
        if wanted and not set(wanted) & set(args.target):
            continue
        out += ["", RULE, appendix["title"].upper(), RULE, "", appendix["intro"].strip()]
        if "file" in appendix:
            path = os.path.join(config_dir, appendix["file"])
            out += ["", framed(decode(read_bytes(path), path))]
        if appendix.get("musl_from_rustc"):
            version, rust, text = musl_copyright(github)
            out += ["", f"musl {version}, the release {rust} builds its musl targets from:",
                    "", framed(text)]
    return "\n".join(out) + "\n"


def framed(text):
    """A text exactly as shipped, minus the final newline the join adds back."""
    return text[:-1] if text.endswith("\n") else text


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest-path", default="Cargo.toml")
    parser.add_argument("--package")
    parser.add_argument("--features")
    parser.add_argument("--no-default-features", action="store_true")
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config_dir = os.path.dirname(os.path.abspath(args.config))
    with open(args.config, "rb") as handle:
        config = tomllib.load(handle)
    try:
        github = GitHub()
        index, notes, texts = generate(args, config, github)
        document = render(args, config, config_dir, index, notes, texts, github)
    except Gap as gap:
        sys.exit(f"error: {gap}")
    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(document)
    print(f"{len(index)} crates, {len(texts)} distinct texts -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
