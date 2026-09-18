#!/usr/bin/env python3
"""Audit the recovered QI pip freeze as a portable frozen replay layer.

This script performs no package installation, dependency resolution, provider
authentication, backend query, or hardware access.  It reads the recovered
lock, classifies each non-comment entry, and writes the two audit reports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


PROTOCOL_ID = "QCEC Stage 2R4A — QI Frozen Pip-Layer Replay Audit"
ANCESTRY = "STOP_QCEC_STAGE2R3_QI_FROZEN_RUNTIME_REPLAY_FAILED"
SOURCE_REPOSITORY = "tajjali40/UPCT_QFM_CLOUD_EXECUTION"
SOURCE_PATH = "runtime/qi/vendor/pip-freeze.txt"
SOURCE_FILE_GIT_COMMIT = "ccaf9fc42d233cf8d08b8ff6089c967acad3372e"
STAGE2R3_EXECUTION_COMMIT = "36499b26980a63b544c9c01e4874e69d9e0a0997"
QI_ORIGINAL_EXPLICIT_LOCK_SHA256 = (
    "7899ecaada6b1621ac66675761de62e6f63ef61453c608654362ad28c5f860fa"
)
QI_REPLAY_LOCK_SHA256 = (
    "5fc020152a58f2f48853d6700eb629ef991f1e26820bbb37d6e9b8dab6f27780"
)

PASS_VERDICT = "PASS_QCEC_STAGE2R4A_QI_FROZEN_PIP_LAYER_REPLAYABLE"
NOT_PORTABLE_VERDICT = "STOP_QCEC_STAGE2R4A_QI_PIP_LAYER_NOT_PORTABLE"
RECOVERY_FAILED_VERDICT = "STOP_QCEC_STAGE2R4A_ORIGINAL_PIP_FREEZE_RECOVERY_FAILED"

CATEGORIES = (
    "exact pinned PyPI requirement",
    "immutable direct URL",
    "VCS reference",
    "editable install",
    "local absolute path",
    "local relative path",
    "unpinned requirement",
    "environment-dependent reference",
)

COUNT_KEYS = {
    "exact pinned PyPI requirement": "EXACT_PIN_COUNT",
    "immutable direct URL": "DIRECT_URL_COUNT",
    "VCS reference": "VCS_COUNT",
    "editable install": "EDITABLE_COUNT",
    "local absolute path": "LOCAL_ABSOLUTE_PATH_COUNT",
    "local relative path": "LOCAL_RELATIVE_PATH_COUNT",
    "unpinned requirement": "UNPINNED_COUNT",
    "environment-dependent reference": "ENVIRONMENT_DEPENDENT_COUNT",
}

REQUIRED_PACKAGES = {
    "qiskit": "2.3.1",
    "qiskit-quantuminspire": "0.18.4",
    "quantuminspire": "4.0.0",
    "opensquirrel": "0.9.1",
    "qi-compute-api-client": "0.63.0",
}

SAFETY_ASSERTIONS = {
    "PACKAGES_INSTALLED": 0,
    "RESOLVER_INVOKED": 0,
    "PROVIDER_AUTH_ATTEMPTED": 0,
    "BACKEND_QUERY_ATTEMPTED": 0,
    "HARDWARE_JOBS_CREATED": 0,
    "SECRETS_READ": 0,
    "SECRETS_ADDED": 0,
    "STAGE2R4B_STARTED": False,
    "STAGE3A_RESTARTED": False,
}

_EXACT_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._-]+\])?"
    r"(?P<operator>===|==)(?P<version>[^\s,;*]+)$"
)
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_UNC_RE = re.compile(r"^(?:\\\\|//)[^/\\]+[/\\][^/\\]+")
_ENV_REFERENCE_RE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|%[^%]+%")
_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_target(entry: str) -> str:
    if " @ " in entry:
        return entry.split(" @ ", 1)[1].strip()
    return entry.strip()


def is_environment_dependent(entry: str) -> bool:
    target = requirement_target(entry)
    return bool(
        _ENV_REFERENCE_RE.search(entry)
        or ";" in entry
        or target == "~"
        or target.startswith(("~/", "~\\"))
    )


def is_absolute_local(target: str) -> bool:
    decoded = unquote(target)
    if decoded.lower().startswith("file:"):
        parsed = urlsplit(decoded)
        path = unquote(parsed.path)
        return bool(parsed.netloc or path.startswith("/") or _WINDOWS_ABSOLUTE_RE.match(path.lstrip("/")))
    return bool(
        decoded.startswith("/")
        or _WINDOWS_ABSOLUTE_RE.match(decoded)
        or _UNC_RE.match(decoded)
    )


def is_relative_local(target: str) -> bool:
    lowered = target.lower()
    return bool(
        lowered.startswith(("./", ".\\", "../", "..\\", "file:"))
        or lowered.endswith((".whl", ".zip", ".tar.gz", ".tgz"))
    )


def is_immutable_https_url(target: str) -> bool:
    parsed = urlsplit(target)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        return False
    if re.search(r"(?:^|[&#])sha256=[0-9a-fA-F]{64}(?:$|[&#])", parsed.fragment):
        return True
    if re.search(r"/(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?:/|$)", parsed.path):
        return True
    if parsed.netloc.lower().endswith(("pypi.org", "pythonhosted.org")) and "/packages/" in parsed.path:
        return True
    filename = Path(unquote(parsed.path)).name
    return bool(
        re.search(r"-[0-9][A-Za-z0-9.!+_-]*-(?:py\d|cp\d|pp\d|none)", filename)
        and filename.lower().endswith(".whl")
    )


def classify_entry(entry: str) -> tuple[str, dict[str, str]]:
    stripped = entry.strip()
    lowered = stripped.lower()
    target = requirement_target(stripped)
    target_lower = target.lower()

    if lowered.startswith(("-e ", "--editable ", "--editable=")):
        return "editable install", {}
    if is_environment_dependent(stripped):
        return "environment-dependent reference", {}
    if target_lower.startswith(_VCS_PREFIXES):
        return "VCS reference", {}
    if is_absolute_local(target):
        return "local absolute path", {}
    if target_lower.startswith(("http://", "https://")):
        if is_immutable_https_url(target):
            return "immutable direct URL", {}
        return "environment-dependent reference", {}
    if is_relative_local(target):
        return "local relative path", {}

    match = _EXACT_PIN_RE.fullmatch(stripped)
    if match:
        return "exact pinned PyPI requirement", {
            "normalized_name": normalize_name(match.group("name")),
            "version": match.group("version"),
        }
    return "unpinned requirement", {}


def classify_lock(data: bytes) -> tuple[list[dict[str, object]], dict[str, int], dict[str, object]]:
    text = data.decode("utf-8")
    entries: list[dict[str, object]] = []
    versions: dict[str, list[str]] = {}

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        category, metadata = classify_entry(stripped)
        item: dict[str, object] = {
            "line_number": line_number,
            "entry": stripped,
            "category": category,
        }
        item.update(metadata)
        entries.append(item)
        if category == "exact pinned PyPI requirement":
            name = str(metadata["normalized_name"])
            versions.setdefault(name, []).append(str(metadata["version"]))

    counts = {key: 0 for key in COUNT_KEYS.values()}
    for item in entries:
        counts[COUNT_KEYS[str(item["category"])]] += 1
    counts["LOCAL_PATH_COUNT"] = (
        counts["LOCAL_ABSOLUTE_PATH_COUNT"] + counts["LOCAL_RELATIVE_PATH_COUNT"]
    )
    counts["TOTAL_ENTRY_COUNT"] = len(entries)

    required_results: dict[str, object] = {}
    for name, required_version in REQUIRED_PACKAGES.items():
        observed = versions.get(normalize_name(name), [])
        required_results[name] = {
            "required_version": required_version,
            "observed_versions": observed,
            "present": bool(observed),
            "exact_match": observed == [required_version],
        }

    return entries, counts, required_results


def determine_verdict(counts: dict[str, int], package_results: dict[str, object]) -> str:
    portable_counts = all(
        counts[key] == 0
        for key in (
            "LOCAL_PATH_COUNT",
            "EDITABLE_COUNT",
            "UNPINNED_COUNT",
            "ENVIRONMENT_DEPENDENT_COUNT",
        )
    )
    packages_exact = all(
        bool(result["exact_match"])
        for result in package_results.values()
        if isinstance(result, dict)
    )
    return PASS_VERDICT if portable_counts and packages_exact else NOT_PORTABLE_VERDICT


def package_version(package_results: dict[str, object], name: str) -> str:
    result = package_results[name]
    assert isinstance(result, dict)
    observed = result["observed_versions"]
    assert isinstance(observed, list)
    return observed[0] if len(observed) == 1 else "MISSING_OR_AMBIGUOUS"


def text_report(report: dict[str, object]) -> str:
    counts = report["counts"]
    packages = report["required_packages"]
    safety = report["safety_assertions"]
    assert isinstance(counts, dict) and isinstance(packages, dict) and isinstance(safety, dict)
    lines = [
        f"PROTOCOL_ID={report['PROTOCOL_ID']}",
        f"ANCESTRY={report['ancestry']}",
        f"SOURCE_REPOSITORY={report['source_repository']}",
        f"SOURCE_PATH={report['source_path']}",
        f"SOURCE_FILE_GIT_COMMIT={report['source_file_git_commit']}",
        f"STAGE2R3_EXECUTION_COMMIT={report['stage2r3_execution_commit']}",
        f"AUDIT_GIT_COMMIT={report['audit_git_commit'] or 'UNAVAILABLE'}",
        f"GITHUB_RUN_ID={report['github_run_id'] or 'UNAVAILABLE'}",
        f"QI_ORIGINAL_PIP_FREEZE_SHA256={report['QI_ORIGINAL_PIP_FREEZE_SHA256']}",
    ]
    for key in (
        "TOTAL_ENTRY_COUNT",
        "EXACT_PIN_COUNT",
        "DIRECT_URL_COUNT",
        "VCS_COUNT",
        "EDITABLE_COUNT",
        "LOCAL_PATH_COUNT",
        "UNPINNED_COUNT",
        "ENVIRONMENT_DEPENDENT_COUNT",
    ):
        lines.append(f"{key}={counts[key]}")
    lines.extend(
        [
            f"QISKIT_VERSION={package_version(packages, 'qiskit')}",
            f"QISKIT_QUANTUMINSPIRE_VERSION={package_version(packages, 'qiskit-quantuminspire')}",
            f"QUANTUMINSPIRE_VERSION={package_version(packages, 'quantuminspire')}",
            f"OPENSQUIRREL_VERSION={package_version(packages, 'opensquirrel')}",
            f"QI_COMPUTE_API_CLIENT_VERSION={package_version(packages, 'qi-compute-api-client')}",
        ]
    )
    for key, value in safety.items():
        rendered = str(value).upper() if isinstance(value, bool) else str(value)
        lines.append(f"{key}={rendered}")
    lines.append(f"VERDICT={report['verdict']}")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lock",
        type=Path,
        default=repo_root / SOURCE_PATH,
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=repo_root / "runtime/qi/vendor/QCEC_STAGE2R4A_PIP_LAYER_AUDIT.json",
    )
    parser.add_argument(
        "--text-output",
        type=Path,
        default=repo_root / "runtime/qi/vendor/QCEC_STAGE2R4A_PIP_LAYER_AUDIT.txt",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.lock.is_file():
        print(f"VERDICT={RECOVERY_FAILED_VERDICT}")
        return 3

    data = args.lock.read_bytes()
    entries, counts, package_results = classify_lock(data)
    verdict = determine_verdict(counts, package_results)
    report: dict[str, object] = {
        "PROTOCOL_ID": PROTOCOL_ID,
        "ancestry": ANCESTRY,
        "source_repository": SOURCE_REPOSITORY,
        "source_path": SOURCE_PATH,
        "source_file_git_commit": SOURCE_FILE_GIT_COMMIT,
        "stage2r3_execution_commit": STAGE2R3_EXECUTION_COMMIT,
        "QI_ORIGINAL_EXPLICIT_LOCK_SHA256": QI_ORIGINAL_EXPLICIT_LOCK_SHA256,
        "QI_REPLAY_LOCK_SHA256": QI_REPLAY_LOCK_SHA256,
        "audit_git_commit": os.environ.get("QCEC_AUDIT_GIT_COMMIT"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "QI_ORIGINAL_PIP_FREEZE_SHA256": hashlib.sha256(data).hexdigest(),
        "counts": counts,
        "required_packages": package_results,
        "entries": entries,
        "safety_assertions": SAFETY_ASSERTIONS,
        "verdict": verdict,
    }

    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.text_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.text_output.write_text(text_report(report), encoding="utf-8", newline="\n")
    print(text_report(report), end="")
    return 0 if verdict == PASS_VERDICT else 2


if __name__ == "__main__":
    raise SystemExit(main())
