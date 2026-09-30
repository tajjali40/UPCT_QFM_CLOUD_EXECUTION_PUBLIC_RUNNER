from __future__ import annotations

from .constants import CANDIDATE_FIELDS
from .exact import vote_sign
from .models import MinuteEvidence


def derived_channels(e: MinuteEvidence) -> dict[str,str|None]:
    d = {
        "R1": e.r1, "R3": e.r3, "BAR_TAKER": e.bar_taker,
        "SPOT_FLOW": e.spot_flow, "FUT_FLOW": e.fut_flow,
        "DEPTH1": e.depth1, "DEPTH5": e.depth5, "OI": e.oi,
        "TAKER_LS": e.taker_ls, "PREMIUM": e.premium,
        "PREMIUM_D": e.premium_d, "FUND": e.fund,
    }
    d["PRICE"] = vote_sign(e.r1, e.r3)
    d["FLOW"] = None if None in (e.spot_flow,e.fut_flow) else vote_sign(e.spot_flow,e.fut_flow,e.bar_taker)
    d["LIQ"] = None if None in (e.depth1,e.depth5) else vote_sign(e.depth1,e.depth5)
    d["LEV"] = None if None in (e.oi,e.taker_ls,e.fund) else vote_sign(e.oi,e.taker_ls,e.fund)
    d["BAS"] = None if None in (e.premium,e.premium_d) else vote_sign(e.premium,e.premium_d)
    return d


def candidate_key(e: MinuteEvidence, candidate_id: str) -> str | None:
    fields=CANDIDATE_FIELDS[candidate_id]
    d=derived_channels(e)
    vals=[d[f] for f in fields]
    if any(v is None for v in vals):
        return None
    return "".join(vals)  # fixed field order is frozen by protocol
