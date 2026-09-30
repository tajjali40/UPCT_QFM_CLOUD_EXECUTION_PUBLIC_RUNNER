from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction


def sign_decimal(x: Decimal) -> str:
    return "N" if x < 0 else "P" if x > 0 else "Z"


def sign_fraction(x: Fraction) -> str:
    return "N" if x < 0 else "P" if x > 0 else "Z"


def sign_int(x: int) -> str:
    return "N" if x < 0 else "P" if x > 0 else "Z"


def sign_to_int(s: str) -> int:
    if s == "N": return -1
    if s == "Z": return 0
    if s == "P": return 1
    raise ValueError(f"invalid sign: {s}")


def vote_sign(*signs: str) -> str:
    return sign_int(sum(sign_to_int(s) for s in signs))


def decimal_to_fraction(s: str | Decimal) -> Fraction:
    d = Decimal(str(s))
    tup = d.as_tuple()
    n = 0
    for digit in tup.digits:
        n = n * 10 + digit
    if tup.sign:
        n = -n
    if tup.exponent >= 0:
        return Fraction(n * (10 ** tup.exponent), 1)
    return Fraction(n, 10 ** (-tup.exponent))


def normalize_epoch_ms(v: int | str) -> int:
    n = int(v)
    # Binance spot archive timestamps from 2025 onward are microseconds.
    if abs(n) >= 100_000_000_000_000:
        return n // 1000
    return n


def parse_time_ms(v: str | int) -> int:
    s = str(v).strip()
    if s.lstrip("-").isdigit():
        return normalize_epoch_ms(int(s))
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)
