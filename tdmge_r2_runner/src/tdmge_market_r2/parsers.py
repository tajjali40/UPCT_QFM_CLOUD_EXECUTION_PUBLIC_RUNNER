from __future__ import annotations

import csv
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Iterable

from .exact import parse_time_ms
from .models import SpotBar

KLINE_COLS = ("open_time","open","high","low","close","volume","close_time","quote_volume","trades","taker_buy_base_volume","taker_buy_quote_volume","ignore")
SPOT_AGG_COLS = ("agg_trade_id","price","qty","first_trade_id","last_trade_id","transact_time","is_buyer_maker","is_best_match")
FUT_AGG_COLS = ("agg_trade_id","price","qty","first_trade_id","last_trade_id","transact_time","is_buyer_maker")


def _rows(path: str | Path, fixed_cols: tuple[str, ...] | None = None):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        first = f.readline()
        if not first:
            return
        f.seek(0)
        cells = next(csv.reader([first]))
        has_header = any(any(ch.isalpha() for ch in c) for c in cells)
        if has_header:
            yield from csv.DictReader(f)
        else:
            if fixed_cols is None:
                raise ValueError(f"headerless source unsupported without fixed schema: {path}")
            for row in csv.reader(f):
                if not row:
                    continue
                if len(row) < len(fixed_cols):
                    raise ValueError(f"short row in {path}: {row[:3]}")
                yield dict(zip(fixed_cols, row))


def _pick(row: dict, *names: str, required: bool = True, default=None):
    lower = {str(k).strip().lower(): v for k,v in row.items() if k is not None}
    for name in names:
        if name.lower() in lower:
            return lower[name.lower()]
    if required:
        raise KeyError(f"none of {names} in columns {list(row)}")
    return default


def _bool(v) -> bool:
    return str(v).strip().lower() in {"true","1","t","yes"}


def read_spot_klines(paths: Iterable[str | Path]) -> list[SpotBar]:
    out=[]
    for path in paths:
        for n,row in enumerate(_rows(path, KLINE_COLS), start=1):
            try:
                out.append(SpotBar(
                    open_time=parse_time_ms(_pick(row,"open_time","opentime")),
                    open=Decimal(_pick(row,"open")), high=Decimal(_pick(row,"high")),
                    low=Decimal(_pick(row,"low")), close=Decimal(_pick(row,"close")),
                    volume=Decimal(_pick(row,"volume")),
                    count=int(_pick(row,"trades","count","number_of_trades")),
                    taker_buy_volume=Decimal(_pick(row,"taker_buy_base_volume","taker_buy_volume")),
                ))
            except (InvalidOperation, ValueError, KeyError) as exc:
                raise ValueError(f"invalid kline {path}:{n}: {exc}") from exc
    out.sort(key=lambda x:x.open_time)
    return out


def read_aggtrades(paths: Iterable[str | Path], futures: bool=False) -> list[dict]:
    fixed = FUT_AGG_COLS if futures else SPOT_AGG_COLS
    out=[]
    seen=set()
    for path in paths:
        for n,row in enumerate(_rows(path, fixed), start=1):
            try:
                aid=int(_pick(row,"agg_trade_id","agg_tradeid","aggregate tradeid","a"))
                key=(str(path),aid)
                if key in seen:
                    raise ValueError(f"duplicate aggregate trade id {aid}")
                seen.add(key)
                p=Decimal(_pick(row,"price","p")); q=Decimal(_pick(row,"qty","quantity","q"))
                out.append({
                    "id":aid, "time":parse_time_ms(_pick(row,"transact_time","timestamp","time","t")),
                    "price":p, "qty":q, "buyer_maker":_bool(_pick(row,"is_buyer_maker","was the buyer the maker","m")),
                })
            except (InvalidOperation, ValueError, KeyError) as exc:
                raise ValueError(f"invalid aggTrade {path}:{n}: {exc}") from exc
    out.sort(key=lambda x:(x["time"],x["id"]))
    return out


def read_metrics(paths: Iterable[str | Path]) -> list[dict]:
    out=[]; by_t={}
    for path in paths:
        for n,row in enumerate(_rows(path), start=1):
            try:
                t=parse_time_ms(_pick(row,"create_time","timestamp","time"))
                rec={
                    "time":t,
                    "oi_value":Decimal(_pick(row,"sum_open_interest_value")),
                    "taker_ls":Decimal(_pick(row,"sum_taker_long_short_vol_ratio")),
                }
                old=by_t.get(t)
                if old is not None and old != rec:
                    raise ValueError(f"conflicting duplicate metric timestamp {t}")
                by_t[t]=rec
            except (InvalidOperation, ValueError, KeyError) as exc:
                raise ValueError(f"invalid metrics {path}:{n}: {exc}") from exc
    out=sorted(by_t.values(), key=lambda x:x["time"])
    return out


def read_bookdepth(paths: Iterable[str | Path]) -> list[dict]:
    groups={}
    for path in paths:
        for n,row in enumerate(_rows(path), start=1):
            try:
                t=parse_time_ms(_pick(row,"timestamp","time"))
                pct=int(Decimal(_pick(row,"percentage","percent")))
                notional=Decimal(_pick(row,"notional"))
                groups.setdefault(t,{})[pct]=notional
            except (InvalidOperation, ValueError, KeyError) as exc:
                raise ValueError(f"invalid bookDepth {path}:{n}: {exc}") from exc
    return [{"time":t,"levels":groups[t]} for t in sorted(groups)]


def read_premium_klines(paths: Iterable[str | Path]) -> list[dict]:
    out=[]
    for path in paths:
        for n,row in enumerate(_rows(path, KLINE_COLS), start=1):
            try:
                out.append({"time":parse_time_ms(_pick(row,"open_time")), "close":Decimal(_pick(row,"close"))})
            except (InvalidOperation, ValueError, KeyError) as exc:
                raise ValueError(f"invalid premium kline {path}:{n}: {exc}") from exc
    out.sort(key=lambda x:x["time"])
    return out


def read_funding(paths: Iterable[str | Path]) -> list[dict]:
    out=[]
    for path in paths:
        for n,row in enumerate(_rows(path), start=1):
            try:
                out.append({
                    "time":parse_time_ms(_pick(row,"calc_time","funding_time","time")),
                    "rate":Decimal(_pick(row,"last_funding_rate","funding_rate","fundingrate")),
                })
            except (InvalidOperation, ValueError, KeyError) as exc:
                raise ValueError(f"invalid funding {path}:{n}: {exc}") from exc
    out.sort(key=lambda x:x["time"])
    return out
