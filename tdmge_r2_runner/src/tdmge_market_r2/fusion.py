from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from decimal import Decimal

from .constants import MINUTE_MS
from .exact import sign_decimal
from .models import MinuteEvidence, SpotBar


def _legacy_key(bars:list[SpotBar], i:int) -> str:
    r=bars[i]; r1=bars[i-1]; r2=bars[i-2]; r3=bars[i-3]
    vals=(
        r.close-r1.close,
        r.close-r3.close,
        Decimal(2)*r.taker_buy_volume-r.volume,
        r.volume-r1.volume,
        Decimal(r.count-r1.count),
        (r.high-r.low)-(r1.high-r1.low),
        r.close-r.open,
        (Decimal(2)*r.taker_buy_volume-r.volume)+(Decimal(2)*r1.taker_buy_volume-r1.volume)+(Decimal(2)*r2.taker_buy_volume-r2.volume),
    )
    return "".join(sign_decimal(x) for x in vals)


def _flow_by_minute(trades:list[dict]) -> dict[int,Decimal]:
    out=defaultdict(lambda:Decimal(0))
    for x in trades:
        minute=(x["time"]//MINUTE_MS)*MINUTE_MS
        signed=x["price"]*x["qty"]*(-1 if x["buyer_maker"] else 1)
        out[minute]+=signed
    return dict(out)


def _latest_index(times:list[int], cutoff:int) -> int|None:
    j=bisect_right(times,cutoff)-1
    return j if j>=0 else None


def build_minute_evidence(
    bars:list[SpotBar], spot_trades:list[dict], fut_trades:list[dict], metrics:list[dict],
    depth:list[dict], premium:list[dict], funding:list[dict]
) -> list[MinuteEvidence]:
    sf=_flow_by_minute(spot_trades); ff=_flow_by_minute(fut_trades)
    mt=[x["time"] for x in metrics]; dt=[x["time"] for x in depth]; ft=[x["time"] for x in funding]
    pmap={x["time"]:x["close"] for x in premium}
    out=[]
    for i in range(3,len(bars)):
        b=bars[i]; close_cut=b.open_time+MINUTE_MS-1
        r1v=b.close-bars[i-1].close; r3v=b.close-bars[i-3].close; btv=Decimal(2)*b.taker_buy_volume-b.volume
        r1=sign_decimal(r1v); r3=sign_decimal(r3v); bt=sign_decimal(btv)
        sfv=sf.get(b.open_time,Decimal(0)); ffv=ff.get(b.open_time,Decimal(0))
        sfs=sign_decimal(sfv); ffs=sign_decimal(ffv)

        depth1=depth5=None; d1v=d5v=None
        j=_latest_index(dt,close_cut)
        if j is not None:
            lv=depth[j]["levels"]
            if -1 in lv and 1 in lv:
                d1v=lv[-1]-lv[1]; depth1=sign_decimal(d1v)
            if -5 in lv and 5 in lv:
                d5v=lv[-5]-lv[5]; depth5=sign_decimal(d5v)

        oi=taker_ls=None; oiv=tlsv=None
        j=_latest_index(mt,close_cut)
        if j is not None:
            tlsv=metrics[j]["taker_ls"]-Decimal(1); taker_ls=sign_decimal(tlsv)
            if j>0:
                oiv=metrics[j]["oi_value"]-metrics[j-1]["oi_value"]; oi=sign_decimal(oiv)

        prem=premd=None; premv=premdv=None
        if b.open_time in pmap:
            premv=pmap[b.open_time]; prem=sign_decimal(premv)
            pv=pmap.get(b.open_time-MINUTE_MS)
            if pv is not None:
                premdv=premv-pv; premd=sign_decimal(premdv)

        fund=None; fundv=None
        j=_latest_index(ft,close_cut)
        if j is not None:
            fundv=funding[j]["rate"]; fund=sign_decimal(fundv)

        out.append(MinuteEvidence(
            open_time=b.open_time, close=b.close, r1=r1, r3=r3, bar_taker=bt,
            spot_flow=sfs, fut_flow=ffs, depth1=depth1, depth5=depth5,
            oi=oi, taker_ls=taker_ls, premium=prem, premium_d=premd, fund=fund,
            legacy_key=_legacy_key(bars,i),
            r1_value=r1v,r3_value=r3v,bar_taker_value=btv,spot_flow_value=sfv,fut_flow_value=ffv,
            depth1_value=d1v,depth5_value=d5v,oi_value_delta=oiv,taker_ls_centered=tlsv,
            premium_value=premv,premium_delta_value=premdv,fund_value=fundv,
        ))
    return out
