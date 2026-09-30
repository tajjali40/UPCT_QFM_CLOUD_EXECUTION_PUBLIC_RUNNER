from __future__ import annotations

import csv
from .constants import CANDIDATE_FIELDS
from .exact import decimal_to_fraction, sign_fraction, sign_int, sign_to_int


def _vote(*xs): return sign_int(sum(sign_to_int(x) for x in xs))

NUMERIC_TO_SIGN={
    "R1":"r1_value","R3":"r3_value","BAR_TAKER":"bar_taker_value","SPOT_FLOW":"spot_flow_value","FUT_FLOW":"fut_flow_value",
    "DEPTH1":"depth1_value","DEPTH5":"depth5_value","OI":"oi_value_delta","TAKER_LS":"taker_ls_centered",
    "PREMIUM":"premium_value","PREMIUM_D":"premium_delta_value","FUND":"fund_value",
}


def _sign_from_numeric(row:dict,name:str):
    v=row.get(NUMERIC_TO_SIGN[name],"")
    return None if v in (None,"") else sign_fraction(decimal_to_fraction(v))


def independent_key(row:dict,candidate_id:str)->str|None:
    d={name:_sign_from_numeric(row,name) for name in NUMERIC_TO_SIGN}
    # Exact numeric values are authoritative; this intentionally ignores stored sign columns.
    d["PRICE"] = None if None in (d["R1"],d["R3"]) else _vote(d["R1"],d["R3"])
    d["FLOW"] = None if None in (d["SPOT_FLOW"],d["FUT_FLOW"],d["BAR_TAKER"]) else _vote(d["SPOT_FLOW"],d["FUT_FLOW"],d["BAR_TAKER"])
    d["LIQ"] = None if None in (d["DEPTH1"],d["DEPTH5"]) else _vote(d["DEPTH1"],d["DEPTH5"])
    d["LEV"] = None if None in (d["OI"],d["TAKER_LS"],d["FUND"]) else _vote(d["OI"],d["TAKER_LS"],d["FUND"])
    d["BAS"] = None if None in (d["PREMIUM"],d["PREMIUM_D"]) else _vote(d["PREMIUM"],d["PREMIUM_D"])
    fields=CANDIDATE_FIELDS[candidate_id]; vals=[d[f] for f in fields]
    return None if any(v is None for v in vals) else "".join(vals)


def verify_keys(evidence_csv:str,candidate_id:str, expected:dict[int,str])->dict:
    checked=0; mismatches=[]
    with open(evidence_csv,"r",encoding="utf-8",newline="") as f:
        for row in csv.DictReader(f):
            t=int(row["open_time"])
            if t not in expected: continue
            k=independent_key(row,candidate_id); checked+=1
            if k!=expected[t]: mismatches.append({"open_time":t,"expected":expected[t],"actual":k})
    return {"checked":checked,"mismatch_count":len(mismatches),"mismatches":mismatches[:20],"exact_match":not mismatches}
