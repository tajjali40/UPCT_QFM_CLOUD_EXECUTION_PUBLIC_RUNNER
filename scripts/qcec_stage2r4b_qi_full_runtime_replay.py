#!/usr/bin/env python3
"""QCEC Stage 2R4B frozen two-layer QI runtime replay audit.

The script never resolves or installs packages.  GitHub Actions performs the
two explicitly authorized installation commands; this script verifies inputs,
captures the frozen Conda base, and audits the completed runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


PROTOCOL_ID = "QCEC Stage 2R4B — QI Full Frozen Two-Layer Runtime Replay"
STAGE2R3_VERDICT = "STOP_QCEC_STAGE2R3_QI_FROZEN_RUNTIME_REPLAY_FAILED"
STAGE2R3_COMMIT = "36499b26980a63b544c9c01e4874e69d9e0a0997"
STAGE2R4A_VERDICT = "PASS_QCEC_STAGE2R4A_QI_FROZEN_PIP_LAYER_REPLAYABLE"
STAGE2R4A_COMMIT = "a9b2c8295715ea3590fbd24f3bbdcb58e6592d52"
STAGE2R4A_RUN_ID = "35400941957"
PIP_SOURCE_COMMIT = "ccaf9fc42d233cf8d08b8ff6089c967acad3372e"

EXPECTED_CONDA_LOCK_SHA256 = (
    "5fc020152a58f2f48853d6700eb629ef991f1e26820bbb37d6e9b8dab6f27780"
)
EXPECTED_PIP_FREEZE_SHA256 = (
    "497bbbd4c3f05a2df7c34d2b2c637038ab2e43ecde2a05d3cef32c45eec20586"
)
EXPECTED_ORIGINAL_ENTRY_COUNT = 45
EXPECTED_PYTHON_VERSION = "3.13.15"
EXPECTED_BASE_PIP_VERSION = "26.2.1"

REQUIRED_PACKAGES = {
    "qiskit": "2.3.1",
    "qiskit-quantuminspire": "0.18.4",
    "quantuminspire": "4.0.0",
    "opensquirrel": "0.9.1",
    "qi-compute-api-client": "0.63.0",
}
IMPORT_PROBES = {
    "QISKIT_IMPORT": "qiskit",
    "QISKIT_QUANTUMINSPIRE_IMPORT": "qiskit_quantuminspire",
    "QUANTUMINSPIRE_IMPORT": "quantuminspire",
}

PASS_VERDICT = "PASS_QCEC_STAGE2R4B_QI_FULL_FROZEN_RUNTIME_REPLAY"
STOP_RECOVERY = "STOP_QCEC_STAGE2R4B_QI_CONDA_REPLAY_LOCK_RECOVERY_FAILED"
STOP_PIP_HASH = "STOP_QCEC_STAGE2R4B_QI_PIP_LOCK_HASH_MISMATCH"
STOP_CONDA_REPLAY = "STOP_QCEC_STAGE2R4B_QI_CONDA_FROZEN_BASE_REPLAY_FAILED"
STOP_PIP_INSTALL = "STOP_QCEC_STAGE2R4B_QI_FROZEN_PIP_ARTIFACT_INSTALL_FAILED"
STOP_IDENTITY = "STOP_QCEC_STAGE2R4B_QI_RUNTIME_IDENTITY_FAILED"
STOP_PIP_CHECK = "STOP_QCEC_STAGE2R4B_QI_PIP_CHECK_FAILED"
STOP_IMPORT = "STOP_QCEC_STAGE2R4B_QI_IMPORT_PROBE_FAILED"

SAFETY_COUNTERS: dict[str, int | bool] = {
    "DEPENDENCY_RESOLUTION_PERFORMED": 0,
    "VERSION_RESELECTION_PERFORMED": 0,
    "PROVIDER_AUTH_ATTEMPTED": 0,
    "BACKEND_QUERY_ATTEMPTED": 0,
    "SIMULATOR_JOBS_CREATED": 0,
    "HARDWARE_JOBS_CREATED": 0,
    "SECRETS_READ": 0,
    "SECRETS_ADDED": 0,
    "STAGE3A_STARTED": False,
}

_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._-]+\])?"
    r"==(?P<version>[^\s,;*]+)$"
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def exact_pin_multiset(text: str) -> tuple[Counter[tuple[str, str]], list[str]]:
    result: Counter[tuple[str, str]] = Counter()
    invalid: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIN_RE.fullmatch(line)
        if not match:
            invalid.append(line)
            continue
        result[(normalize_name(match.group("name")), match.group("version"))] += 1
    return result, invalid


def explicit_urls(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip().lower().startswith(("https://", "http://"))
    ]


def artifact_name(url: str) -> str:
    return unquote(Path(urlsplit(url).path).name)


def run_checked(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def replay_dir() -> Path:
    return repo_root() / "runtime/qi/replay"


def conda_lock_path() -> Path:
    return repo_root() / "runtime/qi/vendor/conda-explicit-replay.lock.txt"


def pip_freeze_path() -> Path:
    return repo_root() / "runtime/qi/vendor/pip-freeze.txt"


def ancestry() -> dict[str, str]:
    return {
        "stage2r3_verdict": STAGE2R3_VERDICT,
        "stage2r3_execution_commit": STAGE2R3_COMMIT,
        "stage2r4a_verdict": STAGE2R4A_VERDICT,
        "stage2r4a_commit": STAGE2R4A_COMMIT,
        "stage2r4a_github_actions_run": STAGE2R4A_RUN_ID,
        "original_pip_freeze_source_commit": PIP_SOURCE_COMMIT,
    }


def empty_report(verdict: str, stop_reason: str) -> dict[str, Any]:
    conda_hash = sha256_file(conda_lock_path()) if conda_lock_path().is_file() else None
    pip_hash = sha256_file(pip_freeze_path()) if pip_freeze_path().is_file() else None
    original_count = 0
    if pip_freeze_path().is_file():
        pins, _ = exact_pin_multiset(pip_freeze_path().read_text(encoding="utf-8"))
        original_count = sum(pins.values())
    return {
        "protocol_id": PROTOCOL_ID,
        "ancestry": ancestry(),
        "github_commit": os.environ.get("GITHUB_SHA"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "conda_replay_lock_sha256": conda_hash,
        "pip_freeze_sha256": pip_hash,
        "post_replay_pip_freeze_sha256": None,
        "python_version": None,
        "base_pip_version": None,
        "required_package_versions": {name: None for name in REQUIRED_PACKAGES},
        "base_conda_packages": [],
        "conda_explicit_url_identity": False,
        "conda_package_identity": False,
        "CONDA_FROZEN_BASE_REPLAY": "NOT_RUN",
        "PYTHON_VERSION_IDENTITY": "NOT_RUN",
        "PIP_FROZEN_LAYER_REPLAY": "NOT_RUN",
        "PIP_CHECK": "NOT_RUN",
        "pip_check_output": "",
        "ORIGINAL_ENTRY_COUNT": original_count,
        "REPLAY_ENTRY_COUNT": 0,
        "CANONICAL_PACKAGE_VERSION_MULTISET_IDENTITY": False,
        "REQUIRED_VERSION_IDENTITY": "NOT_RUN",
        "import_results": {key: "NOT_RUN" for key in IMPORT_PROBES},
        "import_errors": {},
        "safety_counters": SAFETY_COUNTERS,
        "stop_reason": stop_reason,
        "verdict": verdict,
    }


def report_text(report: dict[str, Any]) -> str:
    versions = report["required_package_versions"]
    imports = report["import_results"]
    safety = report["safety_counters"]
    lines = [
        f"PROTOCOL_ID={report['protocol_id']}",
        f"EXECUTION_COMMIT={report['github_commit'] or 'UNAVAILABLE'}",
        f"RUN_ID={report['github_run_id'] or 'UNAVAILABLE'}",
        f"CONDA_REPLAY_LOCK_SHA256={report['conda_replay_lock_sha256'] or 'UNAVAILABLE'}",
        f"PIP_FREEZE_SHA256={report['pip_freeze_sha256'] or 'UNAVAILABLE'}",
        f"POST_REPLAY_PIP_FREEZE_SHA256={report['post_replay_pip_freeze_sha256'] or 'UNAVAILABLE'}",
        f"CONDA_FROZEN_BASE_REPLAY={report['CONDA_FROZEN_BASE_REPLAY']}",
        f"PYTHON_VERSION={report['python_version'] or 'UNAVAILABLE'}",
        f"PYTHON_VERSION_IDENTITY={report['PYTHON_VERSION_IDENTITY']}",
        f"PIP_FROZEN_LAYER_REPLAY={report['PIP_FROZEN_LAYER_REPLAY']}",
        f"PIP_CHECK={report['PIP_CHECK']}",
        f"ORIGINAL_ENTRY_COUNT={report['ORIGINAL_ENTRY_COUNT']}",
        f"REPLAY_ENTRY_COUNT={report['REPLAY_ENTRY_COUNT']}",
        "CANONICAL_PACKAGE_VERSION_MULTISET_IDENTITY="
        + str(report["CANONICAL_PACKAGE_VERSION_MULTISET_IDENTITY"]).upper(),
        f"CONDA_PACKAGE_IDENTITY={str(report['conda_package_identity']).upper()}",
        f"CONDA_EXPLICIT_URL_IDENTITY={str(report['conda_explicit_url_identity']).upper()}",
        f"QISKIT_VERSION={versions['qiskit'] or 'UNAVAILABLE'}",
        f"QISKIT_QUANTUMINSPIRE_VERSION={versions['qiskit-quantuminspire'] or 'UNAVAILABLE'}",
        f"QUANTUMINSPIRE_VERSION={versions['quantuminspire'] or 'UNAVAILABLE'}",
        f"OPENSQUIRREL_VERSION={versions['opensquirrel'] or 'UNAVAILABLE'}",
        f"QI_COMPUTE_API_CLIENT_VERSION={versions['qi-compute-api-client'] or 'UNAVAILABLE'}",
        f"REQUIRED_VERSION_IDENTITY={report['REQUIRED_VERSION_IDENTITY']}",
        f"QISKIT_IMPORT={imports['QISKIT_IMPORT']}",
        f"QISKIT_QUANTUMINSPIRE_IMPORT={imports['QISKIT_QUANTUMINSPIRE_IMPORT']}",
        f"QUANTUMINSPIRE_IMPORT={imports['QUANTUMINSPIRE_IMPORT']}",
    ]
    for key, value in safety.items():
        rendered = str(value).upper() if isinstance(value, bool) else str(value)
        lines.append(f"{key}={rendered}")
    if report.get("stop_reason"):
        lines.append(f"STOP_REASON={report['stop_reason']}")
    lines.append(f"VERDICT={report['verdict']}")
    return "\n".join(lines) + "\n"


def write_report(report: dict[str, Any]) -> None:
    output_dir = replay_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "QCEC_STAGE2R4B_REPLAY_RESULT.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (output_dir / "QCEC_STAGE2R4B_REPLAY_RESULT.txt").write_text(
        report_text(report), encoding="utf-8", newline="\n"
    )


def ensure_placeholder_outputs(verdict: str) -> None:
    output_dir = replay_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    for name in ("post-replay-pip-freeze.txt", "post-replay-conda-explicit.txt"):
        path = output_dir / name
        if not path.exists():
            path.write_text(f"# Not produced: {verdict}\n", encoding="utf-8", newline="\n")


def emit_stop(verdict: str, reason: str) -> int:
    report = empty_report(verdict, reason)
    ensure_placeholder_outputs(verdict)
    write_report(report)
    print(report_text(report), end="")
    return 2


def preflight() -> int:
    conda_path = conda_lock_path()
    pip_path = pip_freeze_path()
    if not conda_path.is_file():
        return emit_stop(STOP_RECOVERY, "The recovered Conda replay lock is absent.")
    conda_hash = sha256_file(conda_path)
    if conda_hash != EXPECTED_CONDA_LOCK_SHA256:
        return emit_stop(
            STOP_RECOVERY,
            f"Conda replay lock SHA256 mismatch: {conda_hash}",
        )
    if not pip_path.is_file():
        return emit_stop(STOP_PIP_HASH, "The committed pip freeze is absent.")
    pip_hash = sha256_file(pip_path)
    if pip_hash != EXPECTED_PIP_FREEZE_SHA256:
        return emit_stop(STOP_PIP_HASH, f"pip-freeze SHA256 mismatch: {pip_hash}")
    pins, invalid = exact_pin_multiset(pip_path.read_text(encoding="utf-8"))
    if invalid or sum(pins.values()) != EXPECTED_ORIGINAL_ENTRY_COUNT:
        return emit_stop(
            STOP_IDENTITY,
            "The original pip layer is not exactly 45 canonical exact pins.",
        )
    print(f"CONDA_REPLAY_LOCK_SHA256={conda_hash}")
    print(f"PIP_FREEZE_SHA256={pip_hash}")
    print(f"ORIGINAL_ENTRY_COUNT={sum(pins.values())}")
    print("PREFLIGHT=PASS")
    return 0


def normalized_conda_packages(payload: Any) -> list[dict[str, Any]]:
    records = payload if isinstance(payload, list) else payload.get("packages", [])
    if not isinstance(records, list):
        raise ValueError("Unexpected micromamba list --json payload")
    keep = ("name", "version", "build_string", "build_number", "channel", "url")
    return [
        {key: record.get(key) for key in keep if key in record}
        for record in records
        if isinstance(record, dict)
    ]


def package_version_from_conda(packages: list[dict[str, Any]], name: str) -> str | None:
    wanted = normalize_name(name)
    matches = [str(item.get("version")) for item in packages if normalize_name(str(item.get("name", ""))) == wanted]
    return matches[0] if len(matches) == 1 else None


def snapshot_base(prefix: Path, snapshot: Path) -> int:
    explicit = run_checked(["micromamba", "list", "--explicit", "--prefix", str(prefix)])
    listing = run_checked(["micromamba", "list", "--json", "--prefix", str(prefix)])
    if explicit.returncode != 0 or listing.returncode != 0:
        return emit_stop(
            STOP_CONDA_REPLAY,
            "Unable to record the freshly replayed Conda base.",
        )
    try:
        packages = normalized_conda_packages(json.loads(listing.stdout))
    except (ValueError, json.JSONDecodeError) as exc:
        return emit_stop(STOP_CONDA_REPLAY, f"Invalid Conda base package listing: {exc}")

    original_urls = explicit_urls(conda_lock_path().read_text(encoding="utf-8"))
    base_urls = explicit_urls(explicit.stdout)
    url_identity = Counter(original_urls) == Counter(base_urls)
    package_identity = Counter(map(artifact_name, original_urls)) == Counter(
        map(artifact_name, base_urls)
    )
    python_version = package_version_from_conda(packages, "python")
    pip_version = package_version_from_conda(packages, "pip")
    payload = {
        "explicit_text": explicit.stdout,
        "packages": packages,
        "conda_explicit_url_identity": url_identity,
        "conda_package_identity": package_identity,
        "python_version": python_version,
        "pip_version": pip_version,
    }
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not url_identity or not package_identity:
        return emit_stop(STOP_CONDA_REPLAY, "Fresh Conda base differs from the frozen explicit lock.")
    if python_version != EXPECTED_PYTHON_VERSION or pip_version != EXPECTED_BASE_PIP_VERSION:
        return emit_stop(
            STOP_CONDA_REPLAY,
            f"Base versions differ: Python={python_version}, pip={pip_version}",
        )
    print("CONDA_FROZEN_BASE_REPLAY=PASS")
    print(f"PYTHON_VERSION={python_version}")
    print(f"BASE_PIP_VERSION={pip_version}")
    return 0


def finalize(prefix: Path, snapshot: Path) -> int:
    try:
        base = json.loads(snapshot.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return emit_stop(STOP_CONDA_REPLAY, f"Base snapshot unavailable: {exc}")

    output_dir = replay_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    original_text = pip_freeze_path().read_text(encoding="utf-8")
    original_pins, original_invalid = exact_pin_multiset(original_text)

    pip_check = run_checked([sys.executable, "-m", "pip", "check"])
    replay_freeze = run_checked([sys.executable, "-m", "pip", "freeze"])
    replay_text = replay_freeze.stdout.replace("\r\n", "\n")
    if replay_text and not replay_text.endswith("\n"):
        replay_text += "\n"
    post_pip_path = output_dir / "post-replay-pip-freeze.txt"
    post_pip_path.write_text(replay_text, encoding="utf-8", newline="\n")
    replay_pins, replay_invalid = exact_pin_multiset(replay_text)

    conda_explicit = run_checked(
        ["micromamba", "list", "--explicit", "--prefix", str(prefix)]
    )
    post_conda_path = output_dir / "post-replay-conda-explicit.txt"
    conda_text = conda_explicit.stdout.replace("\r\n", "\n")
    if conda_text and not conda_text.endswith("\n"):
        conda_text += "\n"
    post_conda_path.write_text(conda_text, encoding="utf-8", newline="\n")

    original_urls = explicit_urls(conda_lock_path().read_text(encoding="utf-8"))
    base_urls = explicit_urls(str(base.get("explicit_text", "")))
    post_urls = explicit_urls(conda_text)
    conda_url_identity = (
        Counter(original_urls) == Counter(base_urls) == Counter(post_urls)
    )
    conda_package_identity = (
        Counter(map(artifact_name, original_urls))
        == Counter(map(artifact_name, base_urls))
        == Counter(map(artifact_name, post_urls))
    )

    python_version = platform.python_version()
    versions: dict[str, str | None] = {}
    for package in REQUIRED_PACKAGES:
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    required_identity = all(versions[name] == version for name, version in REQUIRED_PACKAGES.items())

    import_results: dict[str, str] = {}
    import_errors: dict[str, str] = {}
    for result_key, module_name in IMPORT_PROBES.items():
        try:
            importlib.import_module(module_name)
            import_results[result_key] = "PASS"
        except Exception as exc:  # an import failure is recorded, never repaired
            import_results[result_key] = "FAIL"
            import_errors[result_key] = f"{type(exc).__name__}: {exc}"

    pip_identity = (
        not original_invalid
        and not replay_invalid
        and original_pins == replay_pins
        and sum(original_pins.values()) == EXPECTED_ORIGINAL_ENTRY_COUNT
        and sum(replay_pins.values()) == EXPECTED_ORIGINAL_ENTRY_COUNT
    )
    pip_check_pass = pip_check.returncode == 0
    python_identity = python_version == EXPECTED_PYTHON_VERSION
    imports_pass = all(value == "PASS" for value in import_results.values())
    conda_pass = (
        conda_explicit.returncode == 0
        and bool(base.get("conda_explicit_url_identity"))
        and bool(base.get("conda_package_identity"))
        and conda_url_identity
        and conda_package_identity
    )

    if not conda_pass or not python_identity or not pip_identity or not required_identity:
        verdict = STOP_IDENTITY
    elif not pip_check_pass:
        verdict = STOP_PIP_CHECK
    elif not imports_pass:
        verdict = STOP_IMPORT
    else:
        verdict = PASS_VERDICT

    report: dict[str, Any] = {
        "protocol_id": PROTOCOL_ID,
        "ancestry": ancestry(),
        "github_commit": os.environ.get("GITHUB_SHA"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "conda_replay_lock_sha256": sha256_file(conda_lock_path()),
        "pip_freeze_sha256": sha256_file(pip_freeze_path()),
        "post_replay_pip_freeze_sha256": sha256_file(post_pip_path),
        "python_version": python_version,
        "base_pip_version": base.get("pip_version"),
        "required_package_versions": versions,
        "base_conda_packages": base.get("packages", []),
        "conda_explicit_url_identity": conda_url_identity,
        "conda_package_identity": conda_package_identity,
        "CONDA_FROZEN_BASE_REPLAY": "PASS" if conda_pass else "FAIL",
        "PYTHON_VERSION_IDENTITY": "PASS" if python_identity else "FAIL",
        "PIP_FROZEN_LAYER_REPLAY": "PASS" if replay_freeze.returncode == 0 else "FAIL",
        "PIP_CHECK": "PASS" if pip_check_pass else "FAIL",
        "pip_check_output": (pip_check.stdout + pip_check.stderr).strip(),
        "ORIGINAL_ENTRY_COUNT": sum(original_pins.values()),
        "REPLAY_ENTRY_COUNT": sum(replay_pins.values()),
        "CANONICAL_PACKAGE_VERSION_MULTISET_IDENTITY": pip_identity,
        "REQUIRED_VERSION_IDENTITY": "PASS" if required_identity else "FAIL",
        "import_results": import_results,
        "import_errors": import_errors,
        "safety_counters": SAFETY_COUNTERS,
        "stop_reason": None if verdict == PASS_VERDICT else "A frozen replay identity gate failed.",
        "verdict": verdict,
    }
    write_report(report)
    print(report_text(report), end="")
    return 0 if verdict == PASS_VERDICT else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("preflight")

    snapshot_parser = subparsers.add_parser("snapshot-base")
    snapshot_parser.add_argument("--conda-prefix", type=Path, required=True)
    snapshot_parser.add_argument("--snapshot", type=Path, required=True)

    final_parser = subparsers.add_parser("finalize")
    final_parser.add_argument("--conda-prefix", type=Path, required=True)
    final_parser.add_argument("--snapshot", type=Path, required=True)

    stop_parser = subparsers.add_parser("emit-stop")
    stop_parser.add_argument("--verdict", required=True)
    stop_parser.add_argument("--reason", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "preflight":
        return preflight()
    if args.command == "snapshot-base":
        return snapshot_base(args.conda_prefix, args.snapshot)
    if args.command == "finalize":
        return finalize(args.conda_prefix, args.snapshot)
    if args.command == "emit-stop":
        return emit_stop(args.verdict, args.reason)
    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
