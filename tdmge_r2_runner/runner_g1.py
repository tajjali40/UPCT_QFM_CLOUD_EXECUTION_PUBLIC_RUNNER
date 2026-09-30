from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import os
import shutil
import sys
import urllib.request
import zipfile
from dataclasses import asdict
from pathlib import Path

from tdmge_market_r2.acquire import planned_specs
from tdmge_market_r2.audit import audit_archive_receipts, audit_candidate_missingness, audit_spot_clock
from tdmge_market_r2.evidence_io import write_evidence
from tdmge_market_r2.fusion import build_minute_evidence
from tdmge_market_r2.independent import verify_keys
from tdmge_market_r2.parsers import (
    read_aggtrades,
    read_bookdepth,
    read_funding,
    read_metrics,
    read_premium_klines,
    read_spot_klines,
)
from tdmge_market_r2.pipeline import prepare, score_val, prepare_fresh, score_fresh, sha256_file


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def download(url: str, path: Path, attempts: int = 4) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    last = None
    for i in range(attempts):
        tmp = path.with_suffix(path.suffix + f".part{i}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Tajalli-TDMGE1-R2-G1/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r, tmp.open("wb") as f:
                shutil.copyfileobj(r, f, length=1 << 20)
            tmp.replace(path)
            return
        except Exception as exc:
            last = exc
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
    raise RuntimeError(f"download failed after {attempts} attempts: {url}: {last}")


def acquire_one(spec, root: Path) -> dict:
    fam = root / spec.family
    z = fam / Path(spec.url).name
    c = fam / (z.name + ".CHECKSUM")
    download(spec.checksum_url, c)
    download(spec.url, z)
    expected = c.read_text(encoding="utf-8").strip().split()[0].lower()
    actual = sha256(z)
    if actual != expected:
        raise RuntimeError(f"checksum mismatch {z.name}: {actual} != {expected}")
    extract = fam / "extracted"
    extract.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(z) as zh:
        zh.extractall(extract)
    return {**asdict(spec), "zip_sha256": actual, "checksum_verified": True, "zip_bytes": z.stat().st_size}


def acquire_parallel(specs, root: Path, workers: int = 12) -> list[dict]:
    root.mkdir(parents=True, exist_ok=True)
    receipts = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(acquire_one, s, root): s for s in specs}
        for fut in cf.as_completed(futs):
            s = futs[fut]
            rec = fut.result()
            receipts.append(rec)
            print(f"ACQUIRED {s.family} {s.date_tag} {rec['zip_bytes']} bytes", flush=True)
    receipts.sort(key=lambda r: (r["family"], r["date_tag"], r["url"]))
    return receipts


def glob(root: Path, family: str):
    return sorted((root / family / "extracted").glob("*.csv"))


def fuse_and_audit(data_root: Path, evidence_path: Path, audit_path: Path) -> dict:
    bars = read_spot_klines(glob(data_root, "spot_klines"))
    spot = read_aggtrades(glob(data_root, "spot_aggTrades"), False)
    fut = read_aggtrades(glob(data_root, "um_aggTrades"), True)
    metrics = read_metrics(glob(data_root, "um_metrics"))
    depth = read_bookdepth(glob(data_root, "um_bookDepth"))
    prem = read_premium_klines(glob(data_root, "um_premiumIndexKlines"))
    funding = read_funding(glob(data_root, "um_fundingRate"))

    clock = audit_spot_clock(bars)
    if clock["gaps"] or clock["duplicates"] or clock["nonmonotonic"]:
        raise RuntimeError(f"spot clock gate failed: {clock}")

    ev = build_minute_evidence(bars, spot, fut, metrics, depth, prem, funding)
    write_evidence(evidence_path, ev)
    audit = {
        "spot_clock": clock,
        "source_rows": {
            "spot_bars": len(bars),
            "spot_aggTrades": len(spot),
            "um_aggTrades": len(fut),
            "um_metrics": len(metrics),
            "um_bookDepth_snapshots": len(depth),
            "um_premiumIndexKlines": len(prem),
            "um_fundingRate": len(funding),
            "minute_evidence": len(ev),
        },
        "candidate_missingness": audit_candidate_missingness(ev),
        "evidence_sha256": sha256_file(evidence_path),
    }
    audit_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return audit


def verify_pre_target(evidence: Path, prep: Path) -> dict:
    cp = json.loads((prep / "R2_PRE_TARGET_CHECKPOINT.json").read_text())
    sel = json.loads((prep / "R2_CAL_CANDIDATE_SELECTION.json").read_text())
    pred = json.loads((prep / "R2_VAL_PREDICTIONS_PRE_TARGET.json").read_text())
    expected = {int(p["open_time"]): p["key"] for p in pred["predictions"]}
    replay = verify_keys(str(evidence), pred["candidate_id"], expected)
    out = {
        "checkpoint": cp,
        "selected_candidate": sel["selected_candidate"],
        "candidate_table": sel["candidates"],
        "prediction_sha256": sha256(prep / "R2_VAL_PREDICTIONS_PRE_TARGET.json"),
        "independent_replay": replay,
    }
    if not replay["exact_match"]:
        raise RuntimeError("independent replay mismatch before VAL unblind")
    return out


def main() -> int:
    root = Path(os.environ.get("TDMGE_RUN_ROOT", "R2_G1_RUN")).resolve()
    root.mkdir(parents=True, exist_ok=True)
    caldata = root / "data_calval"
    evidence = root / "CALVAL_EVIDENCE.csv"
    prep = root / "prep"

    specs = planned_specs()["cal_val"]
    receipts = acquire_parallel(specs, caldata, workers=int(os.environ.get("TDMGE_WORKERS", "12")))
    receipt_audit = audit_archive_receipts(receipts, len(specs))
    (root / "CALVAL_ACQUISITION_RECEIPTS.json").write_text(json.dumps(receipts, indent=2, sort_keys=True) + "\n")
    (root / "CALVAL_ACQUISITION_AUDIT.json").write_text(json.dumps(receipt_audit, indent=2, sort_keys=True) + "\n")
    if not receipt_audit["all_checksums_verified"] or not receipt_audit["count_exact"]:
        raise RuntimeError(f"acquisition receipt gate failed: {receipt_audit}")

    fusion_audit = fuse_and_audit(caldata, evidence, root / "CALVAL_FUSION_AUDIT.json")
    cp = prepare(evidence, prep)
    pre = verify_pre_target(evidence, prep)
    (root / "G1_PRE_TARGET_VERIFICATION.json").write_text(json.dumps(pre, indent=2, sort_keys=True) + "\n")

    g1 = {
        "stage": "R2-G1_OFFICIAL_PRIMARY_SOURCE_ACQUISITION_AND_PRETARGET",
        "official_archive_count": len(receipts),
        "all_checksums_verified": receipt_audit["all_checksums_verified"],
        "spot_clock": fusion_audit["spot_clock"],
        "selected_candidate": pre["selected_candidate"],
        "val_prediction_count": cp["prediction_count"],
        "val_target_read": False,
        "fresh_opened": False,
        "status": cp["status"],
        "independent_replay_exact": pre["independent_replay"]["exact_match"],
    }
    (root / "R2_G1_GOVERNING_RECEIPT.json").write_text(json.dumps(g1, indent=2, sort_keys=True) + "\n")
    print(json.dumps(g1, indent=2, sort_keys=True), flush=True)

    if cp["status"] != "READY_FOR_SEPARATE_VAL_UNBLIND":
        return 20

    valdir = root / "val_score"
    val = score_val(evidence, prep / "R2_VAL_PREDICTIONS_PRE_TARGET.json", valdir)
    print(json.dumps(val, indent=2, sort_keys=True), flush=True)
    if val["verdict"] != "PASS_TDMGE1_R2_VAL_DETERMINISTIC_PHASE_CLOSURE":
        return 21

    freshdata = root / "data_fresh"
    fspecs = planned_specs()["fresh"]
    freceipts = acquire_parallel(fspecs, freshdata, workers=int(os.environ.get("TDMGE_WORKERS", "12")))
    faudit = audit_archive_receipts(freceipts, len(fspecs))
    (root / "FRESH_ACQUISITION_RECEIPTS.json").write_text(json.dumps(freceipts, indent=2, sort_keys=True) + "\n")
    (root / "FRESH_ACQUISITION_AUDIT.json").write_text(json.dumps(faudit, indent=2, sort_keys=True) + "\n")
    if not faudit["all_checksums_verified"] or not faudit["count_exact"]:
        raise RuntimeError(f"fresh acquisition receipt gate failed: {faudit}")

    freshev = root / "FRESH_EVIDENCE.csv"
    fuse_and_audit(freshdata, freshev, root / "FRESH_FUSION_AUDIT.json")
    freshprep = root / "fresh_prep"
    fcp = prepare_fresh(freshev, prep / "R2_CAL_LAWBOOK.json", valdir / "R2_VAL_SCORE_AFTER_UNBLIND.json", freshprep)
    print(json.dumps(fcp, indent=2, sort_keys=True), flush=True)
    if fcp["status"] != "READY_FOR_SEPARATE_FRESH_UNBLIND":
        return 22
    fscore = score_fresh(freshev, freshprep / "R2_FRESH_PREDICTIONS_PRE_TARGET.json", root / "fresh_score")
    print(json.dumps(fscore, indent=2, sort_keys=True), flush=True)
    return 0 if fscore["verdict"] == "PASS_TDMGE1_R2_FRESH_DETERMINISTIC_PHASE_CLOSURE" else 23


if __name__ == "__main__":
    raise SystemExit(main())
