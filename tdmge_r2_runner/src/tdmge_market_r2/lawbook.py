from __future__ import annotations

from collections import defaultdict
from .constants import CANDIDATE_FIELDS, MIN_SUPPORT, TARGETS
from .state import candidate_key


def evaluate_candidate(evidence, targets:dict[int,str], candidate_id:str, start_ms:int, state_end_ms:int)->dict:
    support=defaultdict(int); counts=defaultdict(lambda:{"UP":0,"DOWN":0,"FLAT":0}); eligible=0
    for e in evidence:
        if not (start_ms <= e.open_time < state_end_ms): continue
        k=candidate_key(e,candidate_id)
        if k is None: continue
        # A missing t+H close makes this state ineligible; never bridge gaps or partition boundaries.
        if e.open_time not in targets: continue
        eligible+=1; support[k]+=1; counts[k][targets[e.open_time]]+=1
    rules={}; closed_rows=0
    for k in sorted(support):
        active=[y for y in TARGETS if counts[k][y]>0]
        if support[k]>=MIN_SUPPORT and len(active)==1:
            rules[k]={"manifestation":active[0],"support":support[k],"counts":counts[k],"status":"DETERMINATE_IN_CAL"}
            closed_rows+=support[k]
    return {
        "candidate_id":candidate_id,"fields":list(CANDIDATE_FIELDS[candidate_id]),"width":len(CANDIDATE_FIELDS[candidate_id]),
        "eligible_rows":eligible,"distinct_keys":len(support),"determinate_rules":len(rules),"closed_rows":closed_rows,"rules":rules
    }


def select_candidate(results:list[dict])->dict:
    if not results: raise ValueError("no candidate results")
    # max closed rows, max eligible, min distinct keys, min width, lexicographic id
    ranked=sorted(results,key=lambda r:(-r["closed_rows"],-r["eligible_rows"],r["distinct_keys"],r["width"],r["candidate_id"]))
    return ranked[0]
