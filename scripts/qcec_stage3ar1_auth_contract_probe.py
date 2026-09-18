#!/usr/bin/env python3
"""Zero-secret authentication-contract discovery for frozen IBM and QI SDKs."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import importlib.metadata
import inspect
import json
import os
import platform
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROTOCOL_ID = "QCEC Stage 3A-R1 — Zero-Secret Provider Authentication Contract Discovery"
IBM_REQ_SHA = "2a8c3e7231c6b1b21cf17ce0d52ad541f96f376e84f219986794388e0b98fa25"
IBM_RUNTIME_SHA = "082e7241ad0348fe1ab89ebc178f52a5d53fc95e26051312a8903e08826c9987"
QI_CONDA_SHA = "5fc020152a58f2f48853d6700eb629ef991f1e26820bbb37d6e9b8dab6f27780"
QI_PIP_SHA = "497bbbd4c3f05a2df7c34d2b2c637038ab2e43ecde2a05d3cef32c45eec20586"

ANCESTRY = {
    "ORIGINAL_STAGE3A_STOP": "STOP_QCEC_STAGE3A_FROZEN_RUNTIME_REPLAY_PRECONDITION_FAILED",
    "STAGE3A_EXECUTION_COMMIT": "5675dca4464584f6aaead026200a0a17892c2b09",
    "STAGE2R4C_VERDICT": "PASS_QCEC_STAGE2R4C_RUNNER_CONTEXT_REPAIR_AND_AUTHORITATIVE_REPLAY",
    "STAGE2R4C_EXECUTION_COMMIT": "d54880245f2dea67b1e1319d52a7a7e2577aa8be",
    "STAGE2R4C_RUN_ID": "35403163482",
    "STAGE2R4C_ARTIFACT_SHA256": "f819f8c5a150628f6fda920defd8049b8127bdb5e42ebac33839b621adb6577f",
}

SAFETY = {
    "SECRETS_READ": 0,
    "SECRETS_ADDED": 0,
    "PROVIDER_AUTH_ATTEMPTED": 0,
    "PROVIDER_API_REQUEST_ATTEMPTED": 0,
    "BACKEND_QUERY_ATTEMPTED": 0,
    "SIMULATOR_JOBS_CREATED": 0,
    "HARDWARE_JOBS_CREATED": 0,
    "STAGE3B_STARTED": False,
}

IBM_REQUIRED = {
    "qiskit": "2.5.2",
    "qiskit-aer": "0.17.2",
    "qiskit-ibm-runtime": "0.47.0",
}
QI_REQUIRED = {
    "qiskit": "2.3.1",
    "qiskit-quantuminspire": "0.18.4",
    "quantuminspire": "4.0.0",
    "opensquirrel": "0.9.1",
    "qi-compute-api-client": "0.63.0",
}

PASS_VERDICT = "PASS_QCEC_STAGE3AR1_ZERO_SECRET_AUTH_CONTRACT_LOCK"
STOP_IBM = "STOP_QCEC_STAGE3AR1_IBM_NONINTERACTIVE_AUTH_CONTRACT_UNAVAILABLE"
STOP_QI = "STOP_QCEC_STAGE3AR1_QI_NONINTERACTIVE_AUTH_CONTRACT_UNAVAILABLE"
STOP_UNRESOLVED = "STOP_QCEC_STAGE3AR1_AUTH_CONTRACT_UNRESOLVED"

_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?==(?P<version>[^\s,;*]+)$"
)
_ENV_RE = re.compile(r"\b(?:QISKIT_IBM|QI_|QUANTUM_INSPIRE)[A-Z0-9_]+\b")
_CONFIG_RE = re.compile(r"[^\"']*(?:\.json|\.toml|\.yaml|\.yml|/config|\\config)[^\"']*", re.I)


def root() -> Path:
    return Path(__file__).resolve().parents[1]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pin_multiset(text: str) -> tuple[Counter[tuple[str, str]], list[str]]:
    pins: Counter[tuple[str, str]] = Counter()
    invalid: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIN_RE.fullmatch(line)
        if match:
            pins[(normalize_name(match.group("name")), match.group("version"))] += 1
        else:
            invalid.append(line)
    return pins, invalid


def run_local(command: list[str]) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.update({"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "120"})
    return subprocess.run(command, capture_output=True, text=True, check=False, env=environment)


def evidence(kind: str, reference: str, excerpt: str) -> dict[str, str]:
    return {
        "source_type": kind,
        "reference": reference,
        "excerpt": excerpt.strip()[:4000],
    }


def package_roots(module_names: list[str]) -> list[Path]:
    roots: list[Path] = []
    for name in module_names:
        module = importlib.import_module(name)
        location = Path(str(module.__file__)).resolve().parent
        if location not in roots:
            roots.append(location)
    return roots


def scan_sources(roots: list[Path], keywords: tuple[str, ...]) -> tuple[list[dict[str, str]], set[str], set[str], list[dict[str, Any]]]:
    snippets: list[dict[str, str]] = []
    env_vars: set[str] = set()
    config_paths: set[str] = set()
    interfaces: list[dict[str, Any]] = []
    lowered_keywords = tuple(word.lower() for word in keywords)
    for package_root in roots:
        for path in sorted(package_root.rglob("*.py")):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            relative = f"{package_root.name}/{path.relative_to(package_root).as_posix()}"
            for number, line in enumerate(text.splitlines(), start=1):
                lowered = line.lower()
                if any(word in lowered for word in lowered_keywords):
                    env_vars.update(_ENV_RE.findall(line))
                    for found in _CONFIG_RE.findall(line):
                        candidate = found.strip(" \t\"'(),")
                        if candidate and len(candidate) < 240:
                            config_paths.add(candidate)
                    if len(snippets) < 160:
                        snippets.append(evidence("local installed source file", f"{relative}:{number}", line))
            try:
                tree = ast.parse(text, filename=str(path))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if not any(word in node.name.lower() for word in lowered_keywords):
                    continue
                if isinstance(node, ast.ClassDef):
                    interfaces.append({"name": node.name, "kind": "class", "source": f"{relative}:{node.lineno}"})
                    continue
                args = [arg.arg for arg in node.args.args + node.args.kwonlyargs if arg.arg not in {"self", "cls"}]
                interfaces.append(
                    {
                        "name": node.name,
                        "kind": "function",
                        "parameters": args,
                        "source": f"{relative}:{node.lineno}",
                    }
                )
    return snippets, env_vars, config_paths, interfaces


def versions(names: dict[str, str]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for name in names:
        try:
            result[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            result[name] = None
    return result


def runtime_identity(lock: Path, required: dict[str, str], python_version: str) -> tuple[str, dict[str, Any]]:
    original, original_bad = pin_multiset(lock.read_text(encoding="utf-8"))
    frozen = run_local([sys.executable, "-m", "pip", "freeze"])
    replay, replay_bad = pin_multiset(frozen.stdout)
    installed_versions = versions(required)
    passed = (
        frozen.returncode == 0
        and not original_bad
        and not replay_bad
        and original == replay
        and platform.python_version() == python_version
        and all(installed_versions[name] == value for name, value in required.items())
    )
    return ("PASS" if passed else "FAIL"), {
        "python_version": platform.python_version(),
        "required_versions": installed_versions,
        "original_entry_count": sum(original.values()),
        "replay_entry_count": sum(replay.values()),
        "canonical_identity": original == replay,
        "invalid_original_entries": original_bad,
        "invalid_replay_entries": replay_bad,
    }


def preflight() -> int:
    checks = {
        root() / "runtime/ibm/requirements.lock.txt": IBM_REQ_SHA,
        root() / "runtime/ibm/runtime_lock.json": IBM_RUNTIME_SHA,
        root() / "runtime/qi/vendor/conda-explicit-replay.lock.txt": QI_CONDA_SHA,
        root() / "runtime/qi/vendor/pip-freeze.txt": QI_PIP_SHA,
    }
    for path, expected in checks.items():
        if not path.is_file() or sha(path) != expected:
            print(f"FROZEN_INPUT_MISMATCH={path.as_posix()}")
            return 2
        print(f"{path.name.upper().replace('.', '_')}_SHA256={expected}")
    print("FROZEN_INPUT_PREFLIGHT=PASS")
    return 0


def probe_ibm(output: Path) -> int:
    replay, replay_details = runtime_identity(
        root() / "runtime/ibm/requirements.lock.txt", IBM_REQUIRED, "3.11.16"
    )
    from qiskit_ibm_runtime import QiskitRuntimeService

    constructor_signature = str(inspect.signature(QiskitRuntimeService.__init__))
    save_signature = str(inspect.signature(QiskitRuntimeService.save_account))
    constructor_doc = inspect.getdoc(QiskitRuntimeService) or ""
    save_doc = inspect.getdoc(QiskitRuntimeService.save_account) or ""
    source_file = inspect.getsourcefile(QiskitRuntimeService) or "UNAVAILABLE"
    source_text = inspect.getsource(QiskitRuntimeService)
    roots = package_roots(["qiskit_ibm_runtime"])
    snippets, env_vars, config_paths, interfaces = scan_sources(
        roots, ("token", "channel", "account", "credential", "config", "qiskit_ibm")
    )

    combined = "\n".join((constructor_signature, save_signature, constructor_doc, save_doc, source_text))
    channels = sorted(set(re.findall(r"\bibm_(?:cloud|quantum_platform)\b", combined)))
    constructor = inspect.signature(QiskitRuntimeService.__init__)
    credential_names = {
        "channel", "token", "url", "filename", "name", "instance", "proxies", "verify",
        "channel_strategy", "private_endpoint", "url_resolver", "region", "plans_preference", "tags"
    }
    required_fields = [
        name for name, item in constructor.parameters.items()
        if name in credential_names and item.default is inspect.Parameter.empty
    ]
    optional_fields = [name for name in constructor.parameters if name in credential_names and name not in required_fields]
    token_documented = "token" in constructor.parameters and "token" in constructor_doc.lower()
    noninteractive = "PASS" if token_documented else "STOP"
    config_candidates = sorted(path for path in config_paths if "qiskit" in path.lower() or ".json" in path.lower())

    contract = {
        "SDK_NAME": "qiskit-ibm-runtime",
        "SDK_VERSION": importlib.metadata.version("qiskit-ibm-runtime"),
        "AUTH_CLASS_OR_INTERFACE": "qiskit_ibm_runtime.QiskitRuntimeService",
        "SUPPORTED_CHANNELS": channels,
        "REQUIRED_CREDENTIAL_FIELDS": required_fields or ["token (required for non-local authentication)"],
        "OPTIONAL_CREDENTIAL_FIELDS": optional_fields,
        "ENVIRONMENT_VARIABLE_SUPPORT": "TRUE" if env_vars else "UNRESOLVED",
        "ENVIRONMENT_VARIABLES": sorted(env_vars),
        "CONFIG_FILE_SUPPORT": "TRUE" if ("filename" in constructor.parameters or config_candidates) else "UNRESOLVED",
        "CONFIG_PATH_IF_DEFINED": config_candidates or ["$HOME/.qiskit/qiskit-ibm.json" if "qiskit-ibm.json" in combined else "UNRESOLVED"],
        "NONINTERACTIVE_CI_PATH": noninteractive,
        "NONINTERACTIVE_CI_INTERFACE": "QiskitRuntimeService(channel=..., token=..., instance=...)" if noninteractive == "PASS" else "UNRESOLVED",
        "AUTH_MECHANISM": "IBM Cloud API token",
        "NETWORK_AUTH_ATTEMPTED": False,
        "FROZEN_RUNTIME_REPLAY": replay,
        "CONTRACT_DISCOVERED": "PASS" if token_documented and channels else "FAIL",
        "RUNTIME_IDENTITY": replay_details,
        "EVIDENCE": {
            "inspect.signature": [
                evidence("inspect.signature", "QiskitRuntimeService.__init__", constructor_signature),
                evidence("inspect.signature", "QiskitRuntimeService.save_account", save_signature),
            ],
            "local docstring": [
                evidence("local docstring", "QiskitRuntimeService", constructor_doc),
                evidence("local docstring", "QiskitRuntimeService.save_account", save_doc),
            ],
            "local installed source file": [
                evidence("local installed source file", source_file, source_text[:4000]),
                *snippets,
            ],
            "discovered_interfaces": interfaces,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"IBM_FROZEN_RUNTIME_REPLAY={replay}")
    print(f"IBM_AUTH_CONTRACT_DISCOVERED={'PASS' if token_documented and channels else 'FAIL'}")
    print(f"IBM_NONINTERACTIVE_CI_PATH={noninteractive}")
    return 0


def probe_qi(output: Path) -> int:
    replay, replay_details = runtime_identity(
        root() / "runtime/qi/vendor/pip-freeze.txt", QI_REQUIRED, "3.13.15"
    )
    help_main = run_local(["qi", "--help"])
    help_login = run_local(["qi", "login", "--help"])
    main_help = help_main.stdout + help_main.stderr
    login_help = help_login.stdout + help_login.stderr
    roots = package_roots(["quantuminspire", "qiskit_quantuminspire"])
    snippets, env_vars, config_paths, interfaces = scan_sources(
        roots, ("login", "oauth", "device", "browser", "token", "credential", "config", "auth")
    )
    source_combined = "\n".join(item["excerpt"] for item in snippets)
    combined = f"{main_help}\n{login_help}\n{source_combined}"
    options = sorted(set(re.findall(r"--[a-z0-9][a-z0-9-]*", login_help.lower())))
    credential_options = [
        option for option in options if any(word in option for word in ("token", "api-key", "secret", "password", "credential"))
    ]
    browser_evidence = bool(re.search(r"\b(browser|webbrowser|authorization url)\b", combined, re.I))
    device_evidence = bool(re.search(r"\b(device[_ -]?(?:code|flow|authorization)|oauth.*device)\b", combined, re.I))
    direct_env = sorted(name for name in env_vars if "TOKEN" in name or "KEY" in name or "SECRET" in name)
    direct_interfaces = [
        item for item in interfaces
        if item.get("kind") == "function"
        and any(word in item.get("name", "").lower() for word in ("login", "auth", "token", "config"))
        and any(param.lower() in {"token", "api_key", "apikey", "secret", "password"} for param in item.get("parameters", []))
    ]
    noninteractive_supported = bool(credential_options or direct_env or direct_interfaces)
    noninteractive = "PASS" if noninteractive_supported else "STOP"
    mechanisms: list[str] = []
    if device_evidence:
        mechanisms.append("OAuth device authorization flow")
    if browser_evidence:
        mechanisms.append("Browser-mediated OAuth login")
    if credential_options:
        mechanisms.append("Direct CLI credential option")
    if direct_env:
        mechanisms.append("Environment credential")
    if direct_interfaces:
        mechanisms.append("Direct Python credential interface")
    auth_mechanism = "; ".join(mechanisms) if mechanisms else "UNRESOLVED"
    discovered = help_main.returncode == 0 and help_login.returncode == 0 and bool(login_help.strip())

    contract = {
        "SDK_NAME": "quantuminspire",
        "SDK_VERSION": importlib.metadata.version("quantuminspire"),
        "AUTH_CLASS_OR_INTERFACE": [item for item in interfaces if any(word in item.get("name", "").lower() for word in ("login", "auth", "token"))],
        "SUPPORTED_CHANNELS": [],
        "REQUIRED_CREDENTIAL_FIELDS": [option.lstrip("-") for option in credential_options],
        "OPTIONAL_CREDENTIAL_FIELDS": [option.lstrip("-") for option in options if option not in credential_options],
        "ENVIRONMENT_VARIABLE_SUPPORT": "TRUE" if env_vars else "UNRESOLVED",
        "ENVIRONMENT_VARIABLES": sorted(env_vars),
        "CONFIG_FILE_SUPPORT": "TRUE" if config_paths else "UNRESOLVED",
        "CONFIG_PATH_IF_DEFINED": sorted(config_paths) or ["UNRESOLVED"],
        "NONINTERACTIVE_CI_PATH": noninteractive,
        "NONINTERACTIVE_CI_INTERFACE": credential_options or direct_env or direct_interfaces or ["UNRESOLVED"],
        "CLI_LOGIN_INTERFACE": options,
        "BROWSER_FLOW_REQUIRED": "TRUE" if browser_evidence and not noninteractive_supported else ("FALSE" if noninteractive_supported else "UNRESOLVED"),
        "DEVICE_FLOW_REQUIRED": "TRUE" if device_evidence and not noninteractive_supported else ("FALSE" if noninteractive_supported else "UNRESOLVED"),
        "AUTH_MECHANISM": auth_mechanism,
        "NETWORK_AUTH_ATTEMPTED": False,
        "FROZEN_RUNTIME_REPLAY": replay,
        "RUNTIME_IDENTITY": replay_details,
        "CONTRACT_DISCOVERED": "PASS" if discovered else "FAIL",
        "EVIDENCE": {
            "local --help output": [
                evidence("local --help output", "qi --help", main_help),
                evidence("local --help output", "qi login --help", login_help),
            ],
            "local installed source file": snippets,
            "python_api_signatures_from_ast": interfaces,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"QI_FROZEN_RUNTIME_REPLAY={replay}")
    print(f"QI_AUTH_CONTRACT_DISCOVERED={'PASS' if discovered else 'FAIL'}")
    print(f"QI_NONINTERACTIVE_CI_PATH={noninteractive}")
    return 0


def unresolved_contract(provider: str, reason: str, output: Path) -> int:
    contract = {
        "SDK_NAME": provider,
        "SDK_VERSION": "UNRESOLVED",
        "AUTH_CLASS_OR_INTERFACE": "UNRESOLVED",
        "SUPPORTED_CHANNELS": [],
        "REQUIRED_CREDENTIAL_FIELDS": [],
        "OPTIONAL_CREDENTIAL_FIELDS": [],
        "ENVIRONMENT_VARIABLE_SUPPORT": "UNRESOLVED",
        "CONFIG_FILE_SUPPORT": "UNRESOLVED",
        "CONFIG_PATH_IF_DEFINED": ["UNRESOLVED"],
        "NONINTERACTIVE_CI_PATH": "STOP",
        "AUTH_MECHANISM": "UNRESOLVED",
        "NETWORK_AUTH_ATTEMPTED": False,
        "FROZEN_RUNTIME_REPLAY": "FAIL",
        "STOP_REASON": reason,
        "EVIDENCE": {},
    }
    if provider.lower() == "quantuminspire":
        contract.update({"CLI_LOGIN_INTERFACE": [], "BROWSER_FLOW_REQUIRED": "UNRESOLVED", "DEVICE_FLOW_REQUIRED": "UNRESOLVED"})
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return 0


def manifest(ibm_path: Path, qi_path: Path, output: Path) -> int:
    try:
        ibm = json.loads(ibm_path.read_text(encoding="utf-8"))
        qi = json.loads(qi_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        ibm = ibm if "ibm" in locals() else {}
        qi = qi if "qi" in locals() else {}
        read_error = str(exc)
    else:
        read_error = None

    ibm_replay = ibm.get("FROZEN_RUNTIME_REPLAY", "FAIL")
    qi_replay = qi.get("FROZEN_RUNTIME_REPLAY", "FAIL")
    ibm_contract = ibm.get("CONTRACT_DISCOVERED", "FAIL")
    qi_contract = qi.get("CONTRACT_DISCOVERED", "FAIL")
    ibm_ci = ibm.get("NONINTERACTIVE_CI_PATH", "STOP")
    qi_ci = qi.get("NONINTERACTIVE_CI_PATH", "STOP")
    if read_error or "UNRESOLVED" in (ibm.get("AUTH_MECHANISM"), qi.get("AUTH_MECHANISM")):
        verdict = STOP_UNRESOLVED
    elif ibm_ci != "PASS":
        verdict = STOP_IBM
    elif qi_ci != "PASS":
        verdict = STOP_QI
    elif all(value == "PASS" for value in (ibm_replay, qi_replay, ibm_contract, qi_contract)):
        verdict = PASS_VERDICT
    else:
        verdict = STOP_UNRESOLVED

    result = {
        "PROTOCOL_ID": PROTOCOL_ID,
        "ANCESTRY": ANCESTRY,
        "EXECUTION_COMMIT": os.environ.get("GITHUB_SHA"),
        "RUN_ID": os.environ.get("GITHUB_RUN_ID"),
        "IBM_FROZEN_RUNTIME_REPLAY": ibm_replay,
        "QI_FROZEN_RUNTIME_REPLAY": qi_replay,
        "IBM_AUTH_CONTRACT_DISCOVERED": ibm_contract,
        "QI_AUTH_CONTRACT_DISCOVERED": qi_contract,
        "IBM_NONINTERACTIVE_CI_PATH": ibm_ci,
        "QI_NONINTERACTIVE_CI_PATH": qi_ci,
        "SAFETY_COUNTERS": SAFETY,
        "READ_ERROR": read_error,
        "VERDICT": verdict,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if verdict == PASS_VERDICT else 2


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("preflight")
    for name in ("probe-ibm", "probe-qi"):
        sub = commands.add_parser(name)
        sub.add_argument("--output", type=Path, required=True)
    stop = commands.add_parser("emit-stop")
    stop.add_argument("--provider", choices=("ibm", "qi"), required=True)
    stop.add_argument("--reason", required=True)
    stop.add_argument("--output", type=Path, required=True)
    final = commands.add_parser("manifest")
    final.add_argument("--ibm", type=Path, required=True)
    final.add_argument("--qi", type=Path, required=True)
    final.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "preflight":
        return preflight()
    if args.command == "probe-ibm":
        return probe_ibm(args.output)
    if args.command == "probe-qi":
        return probe_qi(args.output)
    if args.command == "emit-stop":
        name = "qiskit-ibm-runtime" if args.provider == "ibm" else "quantuminspire"
        return unresolved_contract(name, args.reason, args.output)
    if args.command == "manifest":
        return manifest(args.ibm, args.qi, args.output)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
