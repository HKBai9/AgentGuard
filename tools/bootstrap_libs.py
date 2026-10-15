#!/usr/bin/env python
"""Workspace-local wheel bootstrapper.

The DSH Windows sandbox denies access to directories created by Python's
``tempfile`` module, which breaks ``pip install`` (it unpacks every wheel into
such a directory).  This script avoids pip's temp machinery completely:

  1. resolve the requirement closure against a PEP 503 simple index
  2. download each wheel straight into ``.wheelhouse/``
  3. extract it into ``libs/``
  4. repeat until no new requirements appear

Usage:
    python tools/bootstrap_libs.py streamlit
"""

from __future__ import annotations

import argparse
import html.parser
import io
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WHEELHOUSE = os.path.join(ROOT, ".wheelhouse")
LIBS = os.path.join(ROOT, "libs")
INDEX_URL = os.environ.get(
    "PROBE_INDEX_URL", "https://pypi.tuna.tsinghua.edu.cn/simple"
)
USER_AGENT = "workspace-wheel-bootstrapper/1.0"

_TAG_RE = re.compile(r"<a\s+([^>]*)>", re.I)
_ATTR_RE = re.compile(r'([a-zA-Z0-9_:-]+)\s*=\s*"([^"]*)"')


class _LinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: D102
        if tag.lower() == "a":
            self.links.append({k.lower(): v for k, v in attrs})


def _fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


def _candidates(package: str) -> list[tuple[str, str]]:
    """Return [(filename, url)] wheel candidates for a project name."""
    url = f"{INDEX_URL.rstrip('/')}/{package}/"
    try:
        raw = _fetch(url).decode("utf-8", "replace")
    except Exception as exc:  # pragma: no cover - network dependent
        raise RuntimeError(f"index lookup failed for {package}: {exc}") from exc
    parser = _LinkParser()
    parser.feed(raw)
    out: list[tuple[str, str]] = []
    for attrs in parser.links:
        href = attrs.get("href", "")
        if not href:
            continue
        clean = href.split("#", 1)[0]
        if not clean.endswith(".whl"):
            continue
        name = urllib.parse.unquote(clean.rsplit("/", 1)[-1])
        out.append((name, urllib.parse.urljoin(url, href)))
    return out


def _parse_wheel_name(filename: str) -> tuple[str, str, str, str]:
    """Split a wheel filename into (name, version, build_tag, tags)."""
    stem = filename[: -len(".whl")]
    parts = stem.split("-")
    if len(parts) < 5:
        return stem, "0", "", ""
    name, version = parts[0], parts[1]
    rest = parts[2:]
    build = ""
    if len(rest) == 4:  # name-ver-buildtag-pytag-abitag-plattag
        build, rest = rest[0], rest[1:]
    return name, version, build, "-".join(rest)


def _version_key(version: str) -> tuple:
    chunks = re.split(r"[._+-]", version)
    key = []
    for chunk in chunks:
        if chunk.isdigit():
            key.append((1, int(chunk), ""))
        else:
            key.append((0, 0, chunk.lower()))
    return tuple(key)


CPY = f"cp{sys.version_info.major}{sys.version_info.minor}"


def _host_platforms() -> tuple[str, ...]:
    """Best-first list of wheel platform tags valid for this interpreter."""
    import platform as _platform

    machine = (_platform.machine() or "").lower()
    if machine in ("amd64", "x86_64", "x64"):
        return ("win_amd64",)
    if machine in ("arm64", "aarch64"):
        return ("win_arm64",)
    if machine in ("x86", "i386", "i686"):
        return ("win32",)
    return ()


HOST_PLATFORMS = _host_platforms()


def _tag_rank(tags: str) -> int | None:
    """Rank a wheel tag; lower is better. None means unusable here."""
    bits = tags.split("-")
    if len(bits) < 3:
        return None
    py_tag, abi_tag, platform = bits[0], bits[1], "-".join(bits[2:])

    py_ok = py_tag == CPY or py_tag in ("py3", "py2.py3") or py_tag.startswith("py3")
    if not py_ok:
        return None

    # --- pure python wheels: best, usable anywhere -------------------------
    if platform == "any":
        if abi_tag == "none":
            return 0 if py_tag in ("py3", "py2.py3") else 3
        return 6

    # --- platform specific wheels: must match this CPU ---------------------
    # Expand compressed tag sets such as "win_amd64.win32".
    platforms = platform.split(".")
    if not any(p in HOST_PLATFORMS for p in platforms):
        return None

    if abi_tag == "abi3":
        return 10
    if abi_tag == "none":
        return 12
    if abi_tag == CPY:
        return 11
    return None


def _pick(package: str) -> tuple[str, str] | None:
    """Choose the best compatible wheel for this interpreter."""
    cands = _candidates(package)
    if not cands:
        return None
    scored = []
    for filename, url in cands:
        _, version, _, tags = _parse_wheel_name(filename)
        rank = _tag_rank(tags)
        if rank is None:
            continue
        scored.append((_version_key(version), -rank, filename, url))
    if not scored:
        return None
    scored.sort(reverse=True)
    _, _, filename, url = scored[0]
    return filename, url


def _read_metadata(wheel_path: str) -> tuple[str, list[str]]:
    """Return (canonical_name, requirement strings) from a wheel."""
    with zipfile.ZipFile(wheel_path) as zf:
        meta_name = None
        for n in zf.namelist():
            if n.endswith(".dist-info/METADATA"):
                meta_name = n
                break
        if meta_name is None:
            return "", []
        text = zf.read(meta_name).decode("utf-8", "replace")
    name = ""
    requires: list[str] = []
    for line in text.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Requires-Dist:"):
            requires.append(line.split(":", 1)[1].strip())
    return name, requires


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


SKIP = {
    "pip",
    "setuptools",
    "wheel",
    "distribute",
    "python",
    "typing-extensions",
}


def _installed() -> set[str]:
    got = set()
    if os.path.isdir(LIBS):
        for entry in os.listdir(LIBS):
            if entry.endswith(".dist-info"):
                got.add(_canon(entry[: -len(".dist-info")].split("-")[0]))
    return got


def _extract(wheel_path: str) -> str:
    os.makedirs(LIBS, exist_ok=True)
    with zipfile.ZipFile(wheel_path) as zf:
        zf.extractall(LIBS)
    return wheel_path


def main() -> int:
    global INDEX_URL

    ap = argparse.ArgumentParser()
    ap.add_argument("requirements", nargs="*", default=["streamlit"])
    ap.add_argument("--index", default=INDEX_URL)
    ap.add_argument(
        "--clean",
        action="store_true",
        help="wipe libs/ and .wheelhouse/ first for a from-scratch build",
    )
    args = ap.parse_args()

    INDEX_URL = args.index

    if args.clean:
        import shutil

        for target in (LIBS, WHEELHOUSE):
            full = os.path.abspath(target)
            if not full.startswith(os.path.abspath(ROOT)):
                raise SystemExit(f"refusing to delete outside workspace: {full}")
            if os.path.isdir(full):
                try:
                    shutil.rmtree(full)
                    print(f"[clean]  removed {full}")
                except Exception as exc:
                    print(f"[clean]  partial {full}: {exc}")
    os.makedirs(WHEELHOUSE, exist_ok=True)
    os.makedirs(LIBS, exist_ok=True)

    queue = [_canon(r.split("[")[0].split("=")[0].split(">")[0].split("<")[0].strip())
             for r in args.requirements]
    seen: set[str] = set()
    installed = _installed()
    print(f"[bootstrap] index={INDEX_URL}")
    print(f"[bootstrap] libs={LIBS}")

    failures: list[str] = []
    while queue:
        pkg = queue.pop(0)
        if not pkg or pkg in seen or pkg in SKIP:
            continue
        seen.add(pkg)
        if pkg in installed:
            continue
        picked = _pick(pkg)
        if not picked:
            failures.append(pkg)
            print(f"[skip]   {pkg}: no compatible wheel")
            continue
        filename, url = picked
        dest = os.path.join(WHEELHOUSE, filename)
        if not os.path.exists(dest):
            print(f"[down]   {pkg} <- {filename}")
            data = _fetch(url, timeout=180)
            with open(dest, "wb") as fh:
                fh.write(data)
        else:
            print(f"[cache]  {pkg} <- {filename}")
        _extract(dest)
        installed.add(pkg)
        dist_name, requires = _read_metadata(dest)
        for base in _iter_runtime_requirements(requires):
            if base and base not in seen:
                queue.append(base)

    print(f"[bootstrap] done. installed={len(installed)} unresolved={failures}")
    _write_lockfile()
    return 1 if failures else 0


def _iter_runtime_requirements(requires: list[str]) -> list[str]:
    """Yield dependency names, skipping optional (``extra ==``) requirements.

    Uses PEP 508 marker evaluation so that expressions such as
    ``extra == "all" or extra == "plot"`` are correctly rejected instead of
    dragging in optional dependency closures.
    """
    out: list[str] = []
    for req in requires:
        if ";" in req:
            base, marker = req.split(";", 1)
            if not _marker_applies(marker):
                continue
        else:
            base = req
        base = base.split("[")[0]
        base = re.split(r"[<>=!~\s(]", base)[0].strip()
        base = _canon(base)
        if base:
            out.append(base)
    return out


_MARKER_ENV = None
_REQUIREMENT_CLS = None
_HAVE_PACKAGING = False


def _init_markers() -> None:
    """Load ``packaging`` if it is reachable (host or workspace libs)."""
    global _MARKER_ENV, _REQUIREMENT_CLS, _HAVE_PACKAGING
    if _HAVE_PACKAGING:
        return
    try:  # prefer workspace libs, then the interpreter's own env
        from packaging.markers import default_environment
        from packaging.requirements import Requirement

        _MARKER_ENV = default_environment()
        _REQUIREMENT_CLS = Requirement
        _HAVE_PACKAGING = True
    except Exception:
        sys.path.insert(0, LIBS)
        try:
            from packaging.markers import default_environment
            from packaging.requirements import Requirement

            _MARKER_ENV = default_environment()
            _REQUIREMENT_CLS = Requirement
            _HAVE_PACKAGING = True
        except Exception:
            _HAVE_PACKAGING = False


def _marker_applies(marker: str) -> bool:
    """True when an environment marker holds for a default (no-extra) install."""
    _init_markers()
    if _HAVE_PACKAGING and _REQUIREMENT_CLS is not None:
        try:
            req = _REQUIREMENT_CLS(f"probe; {marker}")
            if req.marker is None:
                return True
            return bool(req.marker.evaluate(_MARKER_ENV))
        except Exception:
            pass
    # Conservative fallback: reject anything that could be optional.
    low = marker.lower()
    return not (("extra" in low) or ("optional" in low))


def _write_lockfile() -> None:
    """Record exactly which wheel versions were installed (reproducibility)."""
    if not os.path.isdir(LIBS):
        return
    rows: list[tuple[str, str]] = []
    for entry in sorted(os.listdir(LIBS)):
        if not entry.endswith(".dist-info"):
            continue
        stem = entry[: -len(".dist-info")]
        parts = stem.split("-")
        if len(parts) >= 2:
            rows.append((parts[0], parts[1]))
    out = os.path.join(ROOT, "requirements.lock.txt")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# 自动生成：libs/ 中已安装依赖的精确版本\n")
        fh.write("# 生成方式: python tools/bootstrap_libs.py --index <镜像> <包名...>\n")
        for name, version in rows:
            fh.write(f"{name}=={version}\n")
    print(f"[bootstrap] lockfile -> {out} ({len(rows)} packages)")


if __name__ == "__main__":
    sys.exit(main())
