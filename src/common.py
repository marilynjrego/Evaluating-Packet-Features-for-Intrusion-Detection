from __future__ import annotations
import math
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
import numpy as np

Flowkey = Tuple[str, str, int,  int, int] #src_ip, dst_ip, src_port, dst_port, proto

@dataclass
class Flowstats:
    # Header oriented stats
    first_ts: float
    last_ts: float
    last_ts: float
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    ttl_sum: int = 0
    ttl_sq_sum: int = 0
    ttl_n: int = 0
    ip_len_sum: int = 0
    ip_len_sq_sum: int = 0
    ip_len_n: int = 0
    tcp_syn: int = 0
    tcp_ack: int = 0
    tcp_fin: int = 0
    tcp_rst: int = 0
    tcp_psh: int = 0
    tcp_urg: int = 0
    tcp_ece: int = 0
    tcp_cwr: int = 0
    tcp_win_sum: int = 0
    tcp_win_sq_sum: int = 0
    tcp_win_n: int = 0
    iat_prev_ts: Optional[float] = None
    iat_sum: float = 0.0
    iat_sq_sum: float = 0.0
    iat_n: int = 0

    # Payload-oriented stats (computed in payload extractor)
    payload_pkts: int = 0
    payload_bytes: int = 0
    payload_len_sum: int = 0
    payload_len_sq_sum: int = 0
    payload_len_n: int = 0
    payload_entropy_sum: float = 0.0
    payload_entropy_sq_sum: float = 0.0
    payload_entropy_n: int = 0
    printable_bytes: int = 0
    total_payload_bytes_for_printable: int = 0

    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

def safe_mean(sum_v: float, n: int) -> float:
    return float(sum_v)/n if n > 0 else 0.0

def safe_std(sum_v: float, sq_sum_v: float, n: int) -> float:
    if n <= 1:
        return 0.0
    mean = sum_v / n
    var = max(0.0, (sq_sum_v / n) - mean * mean)
    return float(math.sqrt(var))

def shannon_entropy(payload: bytes) -> float:
    """Shannon entropy (0..8 for bytes)."""
    if not payload:
        return 0.0
    counts = np.bincount(np.frombuffer(payload, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0].astype(np.float64)
    probs /= probs.sum()
    return float(-(probs * np.log2(probs)).sum())

def is_printable_byte(b: int) -> bool:
    # ASCII printable + whitespace (tab/newline/carriage return)
    return (32 <= b <= 126) or b in (9, 10, 13)

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)