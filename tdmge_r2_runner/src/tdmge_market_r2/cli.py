from __future__ import annotations

import argparse, json
from pathlib import Path
from datetime import date

from .acquire import write_plan, planned_specs, acquire
from .parsers import read_spot_klines, read_aggtrades, read_metrics, read_bookdepth, read_premium_klines, read_funding
from .fusion import build_minute_evidence
from .evidence_io import write_evidence
from .pipeline import prepare, score_val, prepare_fresh, score_fresh


def _glob(root:Path,family:str): return sorted((root/family/"extracted").glob("*.csv"))

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("write-acquisition-plan"); a.add_argument("out")
    a=sub.add_parser("acquire-calval"); a.add_argument("root")
    a=sub.add_parser("acquire-fresh"); a.add_argument("root")
    a=sub.add_parser("fuse"); a.add_argument("root"); a.add_argument("out")
    a=sub.add_parser("prepare"); a.add_argument("evidence"); a.add_argument("out_dir")
    a=sub.add_parser("score-val"); a.add_argument("evidence"); a.add_argument("predictions"); a.add_argument("out_dir")
    a=sub.add_parser("prepare-fresh"); a.add_argument("evidence"); a.add_argument("lawbook"); a.add_argument("val_receipt"); a.add_argument("out_dir")
    a=sub.add_parser("score-fresh"); a.add_argument("evidence"); a.add_argument("predictions"); a.add_argument("out_dir")
    args=p.parse_args()
    if args.cmd=="write-acquisition-plan": write_plan(args.out); return
    if args.cmd=="acquire-calval":
        r=acquire(planned_specs()["cal_val"],args.root); print(json.dumps(r,indent=2)); return
    if args.cmd=="acquire-fresh":
        r=acquire(planned_specs()["fresh"],args.root); print(json.dumps(r,indent=2)); return
    if args.cmd=="fuse":
        root=Path(args.root)
        bars=read_spot_klines(_glob(root,"spot_klines"))
        st=read_aggtrades(_glob(root,"spot_aggTrades"),False)
        ft=read_aggtrades(_glob(root,"um_aggTrades"),True)
        m=read_metrics(_glob(root,"um_metrics")); d=read_bookdepth(_glob(root,"um_bookDepth"))
        pk=read_premium_klines(_glob(root,"um_premiumIndexKlines")); fr=read_funding(_glob(root,"um_fundingRate"))
        ev=build_minute_evidence(bars,st,ft,m,d,pk,fr); write_evidence(args.out,ev); print(len(ev)); return
    if args.cmd=="prepare": print(json.dumps(prepare(args.evidence,args.out_dir),indent=2)); return
    if args.cmd=="score-val": print(json.dumps(score_val(args.evidence,args.predictions,args.out_dir),indent=2)); return
    if args.cmd=="prepare-fresh": print(json.dumps(prepare_fresh(args.evidence,args.lawbook,args.val_receipt,args.out_dir),indent=2)); return
    if args.cmd=="score-fresh": print(json.dumps(score_fresh(args.evidence,args.predictions,args.out_dir),indent=2)); return

if __name__=="__main__": main()
