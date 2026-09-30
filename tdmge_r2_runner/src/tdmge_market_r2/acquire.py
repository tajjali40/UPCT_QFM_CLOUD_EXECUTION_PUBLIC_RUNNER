from __future__ import annotations

import hashlib, json, os, urllib.request, zipfile
from dataclasses import dataclass, asdict
from datetime import date, timedelta
from pathlib import Path

BASE="https://data.binance.vision/data"

@dataclass(frozen=True)
class ArchiveSpec:
    family:str; date_tag:str; url:str; checksum_url:str


def _days(a:date,b:date):
    d=a
    while d<b:
        yield d; d+=timedelta(days=1)


def daily_specs(start:date,end:date)->list[ArchiveSpec]:
    out=[]
    for d in _days(start,end):
        ds=d.isoformat()
        defs=[
          ("spot_klines",f"{BASE}/spot/daily/klines/BTCUSDT/1m/BTCUSDT-1m-{ds}.zip"),
          ("spot_aggTrades",f"{BASE}/spot/daily/aggTrades/BTCUSDT/BTCUSDT-aggTrades-{ds}.zip"),
          ("um_aggTrades",f"{BASE}/futures/um/daily/aggTrades/BTCUSDT/BTCUSDT-aggTrades-{ds}.zip"),
          ("um_metrics",f"{BASE}/futures/um/daily/metrics/BTCUSDT/BTCUSDT-metrics-{ds}.zip"),
          ("um_bookDepth",f"{BASE}/futures/um/daily/bookDepth/BTCUSDT/BTCUSDT-bookDepth-{ds}.zip"),
          ("um_premiumIndexKlines",f"{BASE}/futures/um/daily/premiumIndexKlines/BTCUSDT/1m/BTCUSDT-1m-{ds}.zip"),
        ]
        for fam,url in defs: out.append(ArchiveSpec(fam,ds,url,url+".CHECKSUM"))
    months=sorted({d.strftime("%Y-%m") for d in _days(start,end)})
    for m in months:
        url=f"{BASE}/futures/um/monthly/fundingRate/BTCUSDT/BTCUSDT-fundingRate-{m}.zip"
        out.append(ArchiveSpec("um_fundingRate",m,url,url+".CHECKSUM"))
    return out


def planned_specs()->dict[str,list[ArchiveSpec]]:
    return {
      "cal_val":daily_specs(date(2025,8,1),date(2025,9,1)),
      "fresh":daily_specs(date(2025,9,1),date(2025,9,11)),
    }


def write_plan(path:str|Path):
    obj={k:[asdict(x) for x in v] for k,v in planned_specs().items()}
    Path(path).write_text(json.dumps(obj,indent=2,sort_keys=True)+"
",encoding="utf-8")


def _sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""): h.update(b)
    return h.hexdigest()


def acquire(specs:list[ArchiveSpec],root:str|Path)->list[dict]:
    root=Path(root); receipts=[]
    for s in specs:
        fam=root/s.family; fam.mkdir(parents=True,exist_ok=True)
        z=fam/Path(s.url).name; c=fam/(z.name+".CHECKSUM")
        urllib.request.urlretrieve(s.checksum_url,c)
        urllib.request.urlretrieve(s.url,z)
        checksum_text=c.read_text(encoding="utf-8").strip().split()[0].lower()
        actual=_sha256(z)
        if actual!=checksum_text: raise RuntimeError(f"checksum mismatch {z.name}: {actual} != {checksum_text}")
        extract=fam/"extracted"; extract.mkdir(exist_ok=True)
        with zipfile.ZipFile(z) as zh: zh.extractall(extract)
        receipts.append({**asdict(s),"zip_sha256":actual,"checksum_verified":True,"zip_bytes":z.stat().st_size})
    return receipts
