from __future__ import annotations

import csv
from decimal import Decimal
from pathlib import Path
from .models import MinuteEvidence

FIELDS=(
"open_time","close","r1","r3","bar_taker","spot_flow","fut_flow","depth1","depth5","oi","taker_ls","premium","premium_d","fund","legacy_key",
"r1_value","r3_value","bar_taker_value","spot_flow_value","fut_flow_value","depth1_value","depth5_value","oi_value_delta","taker_ls_centered","premium_value","premium_delta_value","fund_value"
)


def write_evidence(path:str|Path, rows:list[MinuteEvidence]):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=FIELDS); w.writeheader()
        for e in rows:
            d=e.to_jsonable(); w.writerow({k:("" if d.get(k) is None else d.get(k)) for k in FIELDS})


def read_evidence(path:str|Path)->list[MinuteEvidence]:
    out=[]
    with open(path,"r",encoding="utf-8",newline="") as f:
        for row in csv.DictReader(f):
            def opt(k): return row.get(k) if row.get(k,"") != "" else None
            def decopt(k):
                v=opt(k); return Decimal(v) if v is not None else None
            out.append(MinuteEvidence(
                open_time=int(row["open_time"]), close=Decimal(row["close"]),
                r1=row["r1"],r3=row["r3"],bar_taker=row["bar_taker"],
                spot_flow=opt("spot_flow"),fut_flow=opt("fut_flow"),depth1=opt("depth1"),depth5=opt("depth5"),
                oi=opt("oi"),taker_ls=opt("taker_ls"),premium=opt("premium"),premium_d=opt("premium_d"),fund=opt("fund"),
                legacy_key=row["legacy_key"],
                r1_value=decopt("r1_value"),r3_value=decopt("r3_value"),bar_taker_value=decopt("bar_taker_value"),
                spot_flow_value=decopt("spot_flow_value"),fut_flow_value=decopt("fut_flow_value"),
                depth1_value=decopt("depth1_value"),depth5_value=decopt("depth5_value"),oi_value_delta=decopt("oi_value_delta"),
                taker_ls_centered=decopt("taker_ls_centered"),premium_value=decopt("premium_value"),
                premium_delta_value=decopt("premium_delta_value"),fund_value=decopt("fund_value"),
            ))
    return out
