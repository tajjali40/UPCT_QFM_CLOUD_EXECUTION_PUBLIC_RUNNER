from __future__ import annotations
from collections import Counter
from .constants import MINUTE_MS, CANDIDATE_FIELDS
from .state import candidate_key


def audit_spot_clock(bars)->dict:
    gaps=duplicates=nonmonotonic=0; max_gap=0
    for a,b in zip(bars,bars[1:]):
        d=b.open_time-a.open_time; max_gap=max(max_gap,d)
        if d==0: duplicates+=1
        if d<0: nonmonotonic+=1
        if d!=MINUTE_MS: gaps+=1
    return {"rows":len(bars),"gaps":gaps,"duplicates":duplicates,"nonmonotonic":nonmonotonic,"max_gap_ms":max_gap,"expected_ms":MINUTE_MS}


def audit_candidate_missingness(evidence)->dict:
    out={}
    for cid in sorted(CANDIDATE_FIELDS):
        ok=sum(candidate_key(e,cid) is not None for e in evidence)
        out[cid]={"eligible":ok,"total":len(evidence),"missing":len(evidence)-ok,"coverage":(ok/len(evidence) if evidence else 0.0)}
    return out


def audit_archive_receipts(receipts:list[dict], expected_count:int)->dict:
    families=Counter(x.get("family") for x in receipts)
    bad=[x for x in receipts if not x.get("checksum_verified")]
    return {"receipt_count":len(receipts),"expected_count":expected_count,"all_checksums_verified":not bad,"bad_count":len(bad),"families":dict(sorted(families.items())),"count_exact":len(receipts)==expected_count}
