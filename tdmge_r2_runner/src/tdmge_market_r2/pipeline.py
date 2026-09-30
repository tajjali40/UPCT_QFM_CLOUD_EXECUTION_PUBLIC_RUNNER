from __future__ import annotations

import hashlib, json
from pathlib import Path

from .constants import *
from .evidence_io import read_evidence
from .lawbook import evaluate_candidate, select_candidate
from .state import candidate_key


def _write_json(path:Path,obj)->str:
    path.parent.mkdir(parents=True,exist_ok=True)
    raw=(json.dumps(obj,indent=2,sort_keys=True)+"\n").encode(); path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path:str|Path)->str:
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(1<<20),b""): h.update(b)
    return h.hexdigest()


def compile_targets(evidence)->dict[int,str]:
    close={e.open_time:e.close for e in evidence}
    out={}
    for e in evidence:
        future=e.open_time+HORIZON*MINUTE_MS
        if future not in close: continue
        d=close[future]-e.close
        out[e.open_time]="DOWN" if d<0 else "UP" if d>0 else "FLAT"
    return out


def prepare(evidence_path:str|Path,out_dir:str|Path)->dict:
    evidence_path=Path(evidence_path); out_dir=Path(out_dir)
    ev=read_evidence(evidence_path); targets=compile_targets(ev)
    results=[evaluate_candidate(ev,targets,c,CAL_START_MS,CAL_STATE_END_MS) for c in sorted(CANDIDATE_FIELDS)]
    selected=select_candidate(results)
    selection={"protocol_id":PROTOCOL_ID,"source_evidence_sha256":sha256_file(evidence_path),"candidates":[{k:v for k,v in r.items() if k!="rules"} for r in results],"selected_candidate":selected["candidate_id"]}
    sel_hash=_write_json(out_dir/"R2_CAL_CANDIDATE_SELECTION.json",selection)
    law={"protocol_id":PROTOCOL_ID,"selection_sha256":sel_hash,**selected}
    law_hash=_write_json(out_dir/"R2_CAL_LAWBOOK.json",law)

    preds=[]
    cid=selected["candidate_id"]
    available_times={e.open_time for e in ev}
    for e in ev:
        if not (VAL_START_MS <= e.open_time < VAL_STATE_END_MS): continue
        # Coverage check is target-blind: require only that the future close timestamp exists.
        if e.open_time + HORIZON * MINUTE_MS not in available_times: continue
        k=candidate_key(e,cid)
        if k is None: continue
        rule=selected["rules"].get(k)
        if rule: preds.append({"open_time":e.open_time,"key":k,"prediction":rule["manifestation"],"support":rule["support"]})
    pred_obj={"protocol_id":PROTOCOL_ID,"candidate_id":cid,"lawbook_sha256":law_hash,"source_evidence_sha256":sha256_file(evidence_path),"val_target_read":False,"prediction_count":len(preds),"predictions":preds}
    pred_hash=_write_json(out_dir/"R2_VAL_PREDICTIONS_PRE_TARGET.json",pred_obj)
    status="READY_FOR_SEPARATE_VAL_UNBLIND" if len(preds)>=MIN_VAL_PREDICTIONS else "STOP_TDMGE1_R2_VAL_INSUFFICIENT_DETERMINATE_COVERAGE"
    cp={"protocol_id":PROTOCOL_ID,"stage":"R2_PRE_TARGET_PREDICTION_PERSISTED","candidate_id":cid,"prediction_count":len(preds),"prediction_sha256":pred_hash,"val_target_read":False,"fresh_opened":False,"status":status}
    _write_json(out_dir/"R2_PRE_TARGET_CHECKPOINT.json",cp)
    return cp


def score_val(evidence_path:str|Path,prediction_path:str|Path,out_dir:str|Path)->dict:
    evidence_path=Path(evidence_path); prediction_path=Path(prediction_path); out_dir=Path(out_dir)
    raw=prediction_path.read_bytes(); pobj=json.loads(raw); preds=pobj["predictions"]
    if len(preds)<MIN_VAL_PREDICTIONS: raise RuntimeError("protocol forbids VAL target unblind below coverage gate")
    ev=read_evidence(evidence_path); targets=compile_targets(ev)
    mismatches=[]
    for p in preds:
        t=int(p["open_time"])
        if not (VAL_START_MS <= t < VAL_STATE_END_MS): raise ValueError(f"prediction outside VAL: {t}")
        actual=targets[t]
        if actual!=p["prediction"]: mismatches.append({"open_time":t,"predicted":p["prediction"],"actual":actual})
    verdict="PASS_TDMGE1_R2_VAL_DETERMINISTIC_PHASE_CLOSURE" if not mismatches else "STOP_TDMGE1_R2_VAL_DETERMINISTIC_PHASE_CLOSURE_NOT_GENERALIZED"
    receipt={"protocol_id":PROTOCOL_ID,"prediction_sha256_verified":hashlib.sha256(raw).hexdigest(),"target_unblind":True,"prediction_count":len(preds),"mismatch_count":len(mismatches),"mismatches":mismatches[:20],"verdict":verdict}
    _write_json(out_dir/"R2_VAL_SCORE_AFTER_UNBLIND.json",receipt)
    return receipt


def prepare_fresh(evidence_path:str|Path, lawbook_path:str|Path, val_receipt_path:str|Path, out_dir:str|Path)->dict:
    evidence_path=Path(evidence_path); lawbook_path=Path(lawbook_path); val_receipt_path=Path(val_receipt_path); out_dir=Path(out_dir)
    val=json.loads(val_receipt_path.read_text(encoding="utf-8"))
    if val.get("verdict") != "PASS_TDMGE1_R2_VAL_DETERMINISTIC_PHASE_CLOSURE":
        raise RuntimeError("protocol forbids Fresh opening before VAL PASS")
    law_raw=lawbook_path.read_bytes(); law=json.loads(law_raw)
    ev=read_evidence(evidence_path); available_times={e.open_time for e in ev}
    cid=law["candidate_id"]; rules=law["rules"]; preds=[]
    for e in ev:
        if not (FRESH_START_MS <= e.open_time < FRESH_STATE_END_MS): continue
        if e.open_time + HORIZON * MINUTE_MS not in available_times: continue
        k=candidate_key(e,cid)
        if k is None: continue
        rule=rules.get(k)
        if rule: preds.append({"open_time":e.open_time,"key":k,"prediction":rule["manifestation"],"support":rule["support"]})
    obj={"protocol_id":PROTOCOL_ID,"candidate_id":cid,"lawbook_sha256":hashlib.sha256(law_raw).hexdigest(),"source_evidence_sha256":sha256_file(evidence_path),"fresh_target_read":False,"prediction_count":len(preds),"predictions":preds}
    ph=_write_json(out_dir/"R2_FRESH_PREDICTIONS_PRE_TARGET.json",obj)
    status="READY_FOR_SEPARATE_FRESH_UNBLIND" if len(preds)>=MIN_VAL_PREDICTIONS else "STOP_TDMGE1_R2_FRESH_INSUFFICIENT_DETERMINATE_COVERAGE"
    cp={"protocol_id":PROTOCOL_ID,"stage":"R2_FRESH_PRE_TARGET_PREDICTION_PERSISTED","prediction_count":len(preds),"prediction_sha256":ph,"fresh_target_read":False,"status":status}
    _write_json(out_dir/"R2_FRESH_PRE_TARGET_CHECKPOINT.json",cp)
    return cp


def score_fresh(evidence_path:str|Path,prediction_path:str|Path,out_dir:str|Path)->dict:
    evidence_path=Path(evidence_path); prediction_path=Path(prediction_path); out_dir=Path(out_dir)
    raw=prediction_path.read_bytes(); pobj=json.loads(raw); preds=pobj["predictions"]
    if len(preds)<MIN_VAL_PREDICTIONS: raise RuntimeError("protocol forbids Fresh target unblind below coverage gate")
    ev=read_evidence(evidence_path); targets=compile_targets(ev); mismatches=[]
    for p in preds:
        t=int(p["open_time"])
        if not (FRESH_START_MS <= t < FRESH_STATE_END_MS): raise ValueError(f"prediction outside Fresh: {t}")
        actual=targets[t]
        if actual!=p["prediction"]: mismatches.append({"open_time":t,"predicted":p["prediction"],"actual":actual})
    verdict="PASS_TDMGE1_R2_FRESH_DETERMINISTIC_PHASE_CLOSURE" if not mismatches else "STOP_TDMGE1_R2_FRESH_DETERMINISTIC_PHASE_CLOSURE_NOT_GENERALIZED"
    receipt={"protocol_id":PROTOCOL_ID,"prediction_sha256_verified":hashlib.sha256(raw).hexdigest(),"target_unblind":True,"prediction_count":len(preds),"mismatch_count":len(mismatches),"mismatches":mismatches[:20],"verdict":verdict}
    _write_json(out_dir/"R2_FRESH_SCORE_AFTER_UNBLIND.json",receipt)
    return receipt
