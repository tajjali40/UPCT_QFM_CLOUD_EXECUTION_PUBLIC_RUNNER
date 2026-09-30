from __future__ import annotations

from dataclasses import dataclass, asdict
from decimal import Decimal
from typing import Optional


@dataclass(frozen=True)
class SpotBar:
    open_time: int
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal
    volume: Decimal
    count: int
    taker_buy_volume: Decimal


@dataclass(frozen=True)
class MinuteEvidence:
    open_time: int
    close: Decimal
    r1: str
    r3: str
    bar_taker: str
    spot_flow: Optional[str]
    fut_flow: Optional[str]
    depth1: Optional[str]
    depth5: Optional[str]
    oi: Optional[str]
    taker_ls: Optional[str]
    premium: Optional[str]
    premium_d: Optional[str]
    fund: Optional[str]
    legacy_key: str
    # Exact primitive values retained for independent rational replay.
    r1_value: Optional[Decimal] = None
    r3_value: Optional[Decimal] = None
    bar_taker_value: Optional[Decimal] = None
    spot_flow_value: Optional[Decimal] = None
    fut_flow_value: Optional[Decimal] = None
    depth1_value: Optional[Decimal] = None
    depth5_value: Optional[Decimal] = None
    oi_value_delta: Optional[Decimal] = None
    taker_ls_centered: Optional[Decimal] = None
    premium_value: Optional[Decimal] = None
    premium_delta_value: Optional[Decimal] = None
    fund_value: Optional[Decimal] = None

    def to_jsonable(self) -> dict:
        x = asdict(self)
        for k,v in list(x.items()):
            if isinstance(v, Decimal): x[k]=str(v)
        return x
