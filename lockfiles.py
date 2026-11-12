"""
Exact dependency versions from lockfiles.

A manifest (package.json, Gemfile, ...) lists ranges such as "^1.2.0" and only the
direct dependencies. A lockfile lists what is actually installed, exactly, transitive
dependencies included, which is what a vulnerability lookup needs.

Every parser returns a LockResult:
- dependencies: one record per installed registry package:
    {"name", "version", "type", "scope", "source", "exact": True}
  `type` is Tyr's ecosystem key (npm, pypi, gem, composer, cargo, go); `scope` is
  "prod", "dev" or None when the lockfile does not say.
- skipped: names of entries that do not come from a registry (git, local paths,
  workspaces, patches). Looking them up by name would check an unrelated package.

A lockfile that cannot be read raises LockfileError: the caller then falls back to
the manifest instead of silently scanning nothing.
"""

import json
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

try:  # Python 3.11+
    import tomllib
except ImportError:  # pragma: no cover - exercised only on older interpreters
    tomllib = None


# Far above any real lockfile (large monorepo pnpm locks are a few MB), and low enough
# that a hostile repository cannot make the scanner read without end.
MAX_LOCKFILE_BYTES = 64 * 1024 * 1024


class LockfileError(Exception):
    """The lockfile exists but could not be parsed."""


@dataclass
class LockResult:
    dependencies: List[Dict] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)


_SEMVER_START = re.compile(r"^\d")


def _dep(name: str, version: str, ecosystem: str, scope: Optional[str], path: Path) -> Dict:
    return {"name": name, "version": version, "type": ecosystem, "scope": scope, "source": str(path), "exact": True}


def _split_name_version(spec: str):
    """
    'name@1.2.3' or '@scope/name@1.2.3' -> (name, rest). The name ends at the first '@'
    after a scope's own: what follows may contain more ('git@github.com', 'patch:x@npm:1').
    """
    at = spec.find("@", 1)
    if at < 0:
        return spec, ""
    return spec[:at], spec[at + 1:]


def _read_text(path: Path) -> str:
    """
    The file's text, refusing anything but a regular file of bounded size: a FIFO
    would block the read forever and a device such as /dev/zero would never end.
    """
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise LockfileError(f"{path}: not a regular file")
        if info.st_size > MAX_LOCKFILE_BYTES:
            raise LockfileError(f"{path}: larger than {MAX_LOCKFILE_BYTES} bytes")
        with open(path, "rb") as handle:
            data = handle.read(MAX_LOCKFILE_BYTES + 1)
    except OSError as error:
        raise LockfileError(f"{path}: {error}") from error
    if len(data) > MAX_LOCKFILE_BYTES:
        raise LockfileError(f"{path}: larger than {MAX_LOCKFILE_BYTES} bytes")
    try:
        return data.decode("utf-8-sig").replace("\r\n", "\n")  # Windows: BOM and CRLF
    except UnicodeDecodeError as error:
        raise LockfileError(f"{path}: not UTF-8 text ({error.reason})") from error


def _load_json(path: Path):
    try:
        return json.loads(_read_text(path))
    except (OSError, ValueError) as error:
        raise LockfileError(f"{path}: {error}") from error


def _load_toml(path: Path):
    if tomllib is None:
        raise LockfileError(f"{path}: reading TOML lockfiles needs Python 3.11+ (tomllib)")
    try:
        return tomllib.loads(_read_text(path))
    except (OSError, ValueError) as error:
        raise LockfileError(f"{path}: {error}") from error


# --- npm family -----------------------------------------------------------------

def _npm_package_lock(path: Path) -> LockResult:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise LockfileError(f"{path}: not a package-lock document")
    result = LockResult()

    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 and 3
        for key, entry in packages.items():
            if not key or "node_modules/" not in key:
                continue  # the root project and workspace sources
            name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
            version = entry.get("version", "")
            resolved = entry.get("resolved", "")
            if entry.get("link") or not _SEMVER_START.match(version) or resolved.startswith(("git", "file:")):
                result.skipped.append(name)
                continue
            dev = entry.get("dev") or entry.get("devOptional")
            result.dependencies.append(_dep(name, version, "npm", "dev" if dev else "prod", path))
        return result

    def walk(tree):  # lockfileVersion 1: a nested dependencies tree
        for name, entry in (tree or {}).items():
            version = entry.get("version", "")
            if not _SEMVER_START.match(version):
                result.skipped.append(name)
            else:
                result.dependencies.append(_dep(name, version, "npm", "dev" if entry.get("dev") else "prod", path))
            walk(entry.get("dependencies"))

    if "dependencies" not in data:
        raise LockfileError(f"{path}: neither 'packages' nor 'dependencies'")
    walk(data["dependencies"])
    return result


def _pnpm_key(key: str):
    """(name, version) of a pnpm packages key in lockfile v5, v6 or v9, or None for non-registry."""
    key = key.strip().strip("'\"")
    if key.startswith("/"):
        key = key[1:]
        v5 = re.match(r"^((?:@[^/]+/)?[^/@]+)/(\d[^/]*)$", key)  # /name/1.2.3_peer
        if v5:
            return v5.group(1), v5.group(2).split("_")[0]
    elif not re.match(r"^(?:@[^/]+/)?[^/@]+@", key):
        return None  # v5 non-registry keys such as github.com/owner/repo/sha
    return _split_name_version(re.sub(r"\(.*\)$", "", key))  # v6/v9, minus the peer suffix


def _npm_pnpm(path: Path) -> LockResult:
    lines = _read_text(path).splitlines()
    if not any(line.startswith("lockfileVersion:") for line in lines):
        raise LockfileError(f"{path}: no lockfileVersion")

    result = LockResult()
    in_packages = False
    current = None  # [name, version, scope] of the entry being read
    entries = []
    for line in lines:
        if line and not line.startswith(" "):
            in_packages = line.rstrip() == "packages:"
            continue
        if not in_packages or not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 2 and line.rstrip().endswith(":"):
            parsed = _pnpm_key(line.rstrip()[:-1])
            if parsed is None:
                entries.append((line.strip().strip("':\""), None, None))
                current = None
                continue
            current = [parsed[0], parsed[1], None]
            entries.append(current)
        elif indent == 4 and current is not None and line.strip().startswith("dev:"):
            current[2] = "dev" if line.split(":", 1)[1].strip() == "true" else "prod"

    for name, version, scope in entries:
        if version is None or not _SEMVER_START.match(version):
            result.skipped.append(_split_name_version(name)[0] if version is None else name)
        else:
            result.dependencies.append(_dep(name, version, "npm", scope, path))
    return result


def _npm_yarn(path: Path) -> LockResult:
    text = _read_text(path)
    berry = "\n__metadata:" in "\n" + text
    result = LockResult()
    seen = set()

    for block in re.split(r"\n(?=\S)", text):
        header, _, body = block.partition("\n")
        header = header.strip()
        if not header or header.startswith("#") or header.startswith("__metadata") or not header.endswith(":"):
            continue
        first = header[:-1].split(",")[0].strip().strip('"')
        name, descriptor = _split_name_version(first)
        if berry:
            resolution = re.search(r'^[ \t]+resolution: "?([^"\n]+)"?', body, re.M)
            target = resolution.group(1) if resolution else first
            name, protocol = _split_name_version(target)
            version = re.search(r"^[ \t]+version: (\S+)", body, re.M)
            if not protocol.startswith("npm:") or not version:
                result.skipped.append(name)
                continue
            version = version.group(1)
        else:
            version = re.search(r'^[ \t]+version "([^"]+)"', body, re.M)
            if not version or re.match(r"^(git|github:|file:|link:|https?:|ssh:)", descriptor):
                result.skipped.append(name)
                continue
            version = version.group(1)
        if (name, version) not in seen:
            seen.add((name, version))
            result.dependencies.append(_dep(name, version, "npm", None, path))
    if not result.dependencies and not result.skipped:
        raise LockfileError(f"{path}: no entries")
    return result


# --- Python -----------------------------------------------------------------------

def _pypi_poetry(path: Path) -> LockResult:
    data = _load_toml(path)
    result = LockResult()
    for pkg in data.get("package", []):
        source = pkg.get("source") or {}
        if source.get("type") in ("git", "directory", "file", "url"):
            result.skipped.append(pkg["name"])
            continue
        category = pkg.get("category")  # only in lockfiles written by Poetry < 1.5
        scope = {"main": "prod", "dev": "dev"}.get(category)
        result.dependencies.append(_dep(pkg["name"], pkg["version"], "pypi", scope, path))
    if "metadata" not in data:
        raise LockfileError(f"{path}: no [metadata]")
    return result


def _pypi_uv(path: Path) -> LockResult:
    data = _load_toml(path)
    if "package" not in data:
        raise LockfileError(f"{path}: no [[package]]")
    result = LockResult()
    for pkg in data["package"]:
        if "registry" not in (pkg.get("source") or {}) or "version" not in pkg:
            result.skipped.append(pkg["name"])
            continue
        result.dependencies.append(_dep(pkg["name"], pkg["version"], "pypi", None, path))
    return result


def _pypi_pipfile(path: Path) -> LockResult:
    data = _load_json(path)
    if not isinstance(data, dict) or "default" not in data:
        raise LockfileError(f"{path}: no 'default' section")
    result = LockResult()
    for section, scope in (("default", "prod"), ("develop", "dev")):
        for name, entry in (data.get(section) or {}).items():
            version = (entry.get("version") or "").lstrip("=")
            if not version or any(k in entry for k in ("git", "path", "file")):
                result.skipped.append(name)
                continue
            result.dependencies.append(_dep(name, version, "pypi", scope, path))
    return result


def parse_requirements(path: Path) -> LockResult:
    """Exact pins (==, ===) from a requirements file, pip-compile output included."""
    text = _read_text(path)
    result = LockResult()
    for line in text.replace("\\\n", " ").splitlines():
        line = line.split(" #", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s,]+)", line)
        if match:
            result.dependencies.append(_dep(match.group(1), match.group(2), "pypi", None, path))
    return result


# --- Other ecosystems -------------------------------------------------------------

def _composer(path: Path) -> LockResult:
    data = _load_json(path)
    if not isinstance(data, dict) or "packages" not in data:
        raise LockfileError(f"{path}: no 'packages'")
    result = LockResult()
    for section, scope in (("packages", "prod"), ("packages-dev", "dev")):
        for pkg in data.get(section) or []:
            version = pkg.get("version", "")
            if (pkg.get("dist") or {}).get("type") == "path" or version.startswith("dev-") or version.endswith("-dev"):
                result.skipped.append(pkg["name"])
                continue
            result.dependencies.append(_dep(pkg["name"], version[1:] if version[:1] == "v" else version, "composer", scope, path))
    return result


def _gem(path: Path) -> LockResult:
    lines = _read_text(path).splitlines()
    result = LockResult()
    section, in_specs, seen = None, False, set()
    for line in lines:
        if line and not line.startswith(" "):
            section, in_specs = line.strip(), False
            continue
        if line.strip() == "specs:":
            in_specs = True
            continue
        match = re.match(r"^    ([^\s(]+) \(([^)]+)\)$", line)
        if not in_specs or not match:
            continue
        name = match.group(1)
        if section != "GEM":  # GIT and PATH sources
            result.skipped.append(name)
            continue
        version = match.group(2).split("-", 1)[0]  # platform builds: 1.18.8-x86_64-linux
        if (name, version) not in seen:
            seen.add((name, version))
            result.dependencies.append(_dep(name, version, "gem", None, path))
    if section is None:
        raise LockfileError(f"{path}: no sections")
    return result


def _cargo(path: Path) -> LockResult:
    data = _load_toml(path)
    if "package" not in data:
        raise LockfileError(f"{path}: no [[package]]")
    result = LockResult()
    for pkg in data["package"]:
        if not str(pkg.get("source", "")).startswith("registry+"):
            result.skipped.append(pkg["name"])
            continue
        result.dependencies.append(_dep(pkg["name"], pkg["version"], "cargo", None, path))
    return result


def _go_mod(path: Path) -> LockResult:
    text = _read_text(path)
    if not re.search(r"^module\s", text, re.M):
        raise LockfileError(f"{path}: no module directive")

    def directive_lines(keyword):
        lines = re.findall(rf"^{keyword}\s+\(\n(.*?)^\)", text, re.M | re.S)
        lines = [line for block in lines for line in block.splitlines()]
        lines += re.findall(rf"^{keyword}\s+([^(\n][^\n]*)$", text, re.M)
        return [line.split("//", 1)[0].strip() for line in lines if line.split("//", 1)[0].strip()]

    local = set()
    replaced = {}
    for line in directive_lines("replace"):
        old, _, new = line.partition("=>")
        old_module, new = old.split()[0], new.split()
        if new and new[0].startswith((".", "/")):
            local.add(old_module)
        elif len(new) == 2:
            replaced[old_module] = (new[0], new[1])

    result = LockResult()
    for line in directive_lines("require"):
        parts = line.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        if module in local:
            result.skipped.append(module)
            continue
        module, version = replaced.get(module, (module, version))
        result.dependencies.append(_dep(module, version, "go", None, path))
    return result


_PARSERS: Dict[str, Callable[[Path], LockResult]] = {
    "package-lock.json": _npm_package_lock,
    "npm-shrinkwrap.json": _npm_package_lock,
    "pnpm-lock.yaml": _npm_pnpm,
    "yarn.lock": _npm_yarn,
    "poetry.lock": _pypi_poetry,
    "uv.lock": _pypi_uv,
    "Pipfile.lock": _pypi_pipfile,
    "composer.lock": _composer,
    "Gemfile.lock": _gem,
    "Cargo.lock": _cargo,
    "go.mod": _go_mod,
}

LOCKFILE_ECOSYSTEM = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "pnpm-lock.yaml": "npm", "yarn.lock": "npm",
    "poetry.lock": "pypi", "uv.lock": "pypi", "Pipfile.lock": "pypi",
    "composer.lock": "composer", "Gemfile.lock": "gem", "Cargo.lock": "cargo", "go.mod": "go",
}


def is_lockfile(path: Path) -> bool:
    return path.name in _PARSERS


def parse_lockfile(path: Path) -> LockResult:
    """Parses a lockfile (or a requirements file) by name. Raises LockfileError when unreadable."""
    parser = parse_requirements if path.name == "requirements.txt" else _PARSERS.get(path.name)
    if parser is None:
        raise LockfileError(f"{path}: not a known lockfile")
    try:
        return parser(path)
    except LockfileError:
        raise
    except RecursionError as error:
        raise LockfileError(f"{path}: nested too deeply") from error
    except Exception as error:  # a hostile or odd file must never abort the whole scan
        raise LockfileError(f"{path}: unexpected structure ({type(error).__name__}: {error})") from error
