from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import pandas as pd
from scapy.all import IP, TCP, UDP, PcapReader  # type: ignore
from tqdm import tqdm

from common import FlowKey, FlowStats, ensure_dir, safe_mean, safe_std


def packet_flow_key(pkt) -> Optional[FlowKey]:
    ip = pkt.getlayer(IP)
    if ip is None:
        return None

    proto = int(ip.proto)
    src_ip = str(ip.src)
    dst_ip = str(ip.dst)

    if pkt.haslayer(TCP):
        tcp = pkt.getlayer(TCP)
        return (src_ip, dst_ip, int(tcp.sport), int(tcp.dport), proto)
    if pkt.haslayer(UDP):
        udp = pkt.getlayer(UDP)
        return (src_ip, dst_ip, int(udp.sport), int(udp.dport), proto)

    # Ignore non-TCP/UDP in this assignment (simplifies student workload)
    return None


def reverse_key(k: FlowKey) -> FlowKey:
    src, dst, sport, dport, proto = k
    return (dst, src, dport, sport, proto)


def update_header_stats(stats: FlowStats, pkt, is_fwd: bool) -> None:
    ts = float(pkt.time)
    stats.last_ts = max(stats.last_ts, ts)

    # Directional counts
    pkt_len = int(len(pkt))
    if is_fwd:
        stats.fwd_pkts += 1
        stats.fwd_bytes += pkt_len
    else:
        stats.bwd_pkts += 1
        stats.bwd_bytes += pkt_len

    # TTL, IP total length
    ip = pkt.getlayer(IP)
    ttl = int(ip.ttl)
    ip_len = int(ip.len) if getattr(ip, "len", None) is not None else pkt_len

    stats.ttl_sum += ttl
    stats.ttl_sq_sum += ttl * ttl
    stats.ttl_n += 1

    stats.ip_len_sum += ip_len
    stats.ip_len_sq_sum += ip_len * ip_len
    stats.ip_len_n += 1

    # TCP flags / window (if TCP)
    if pkt.haslayer(TCP):
        tcp = pkt.getlayer(TCP)
        flags = int(tcp.flags)

        # Bit checks: FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20, ECE 0x40, CWR 0x80
        stats.tcp_fin += 1 if (flags & 0x01) else 0
        stats.tcp_syn += 1 if (flags & 0x02) else 0
        stats.tcp_rst += 1 if (flags & 0x04) else 0
        stats.tcp_psh += 1 if (flags & 0x08) else 0
        stats.tcp_ack += 1 if (flags & 0x10) else 0
        stats.tcp_urg += 1 if (flags & 0x20) else 0
        stats.tcp_ece += 1 if (flags & 0x40) else 0
        stats.tcp_cwr += 1 if (flags & 0x80) else 0

        win = int(getattr(tcp, "window", 0) or 0)
        stats.tcp_win_sum += win
        stats.tcp_win_sq_sum += win * win
        stats.tcp_win_n += 1

    # Inter-arrival time across all packets in this flow
    if stats.iat_prev_ts is not None:
        iat = ts - stats.iat_prev_ts
        if iat >= 0:
            stats.iat_sum += iat
            stats.iat_sq_sum += iat * iat
            stats.iat_n += 1
    stats.iat_prev_ts = ts


def pcap_to_header_rows(pcap_path: str, label: str, max_flows: Optional[int] = None) -> List[dict]:
    flows: Dict[FlowKey, FlowStats] = {}
    canonical: Dict[FlowKey, FlowKey] = {}  # map either dir -> canonical dir

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            k = packet_flow_key(pkt)
            if k is None:
                continue

            # Direction normalization:
            # The first time we see a flow, we pick that direction as canonical.
            if k in canonical:
                canon = canonical[k]
                is_fwd = (k == canon)
            else:
                rk = reverse_key(k)
                if rk in canonical:
                    canon = canonical[rk]
                    is_fwd = (rk != canon)  # current k is reverse of canonical
                    canonical[k] = canon
                else:
                    canonical[k] = k
                    canonical[rk] = k
                    canon = k
                    is_fwd = True

            if canon not in flows:
                ts = float(pkt.time)
                flows[canon] = FlowStats(first_ts=ts, last_ts=ts)

            update_header_stats(flows[canon], pkt, is_fwd=is_fwd)

            if max_flows is not None and len(flows) >= max_flows:
                # soft cap to keep student runtime manageable
                pass

    rows: List[dict] = []
    for fk, st in flows.items():
        src, dst, sport, dport, proto = fk
        rows.append(
            {
                "flow_id": f"{src}-{dst}-{sport}-{dport}-{proto}",
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "proto": proto,
                "duration": st.duration(),
                "fwd_pkts": st.fwd_pkts,
                "bwd_pkts": st.bwd_pkts,
                "fwd_bytes": st.fwd_bytes,
                "bwd_bytes": st.bwd_bytes,
                "ttl_mean": safe_mean(st.ttl_sum, st.ttl_n),
                "ttl_std": safe_std(st.ttl_sum, st.ttl_sq_sum, st.ttl_n),
                "ip_len_mean": safe_mean(st.ip_len_sum, st.ip_len_n),
                "ip_len_std": safe_std(st.ip_len_sum, st.ip_len_sq_sum, st.ip_len_n),
                "iat_mean": safe_mean(st.iat_sum, st.iat_n),
                "iat_std": safe_std(st.iat_sum, st.iat_sq_sum, st.iat_n),
                "tcp_syn": st.tcp_syn,
                "tcp_ack": st.tcp_ack,
                "tcp_fin": st.tcp_fin,
                "tcp_rst": st.tcp_rst,
                "tcp_psh": st.tcp_psh,
                "tcp_urg": st.tcp_urg,
                "tcp_ece": st.tcp_ece,
                "tcp_cwr": st.tcp_cwr,
                "tcp_win_mean": safe_mean(st.tcp_win_sum, st.tcp_win_n),
                "tcp_win_std": safe_std(st.tcp_win_sum, st.tcp_win_sq_sum, st.tcp_win_n),
                "label": label,
                "pcap_path": pcap_path,
            }
        )
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcaps", nargs="+", required=True, help="List of pcap paths")
    ap.add_argument("--label", required=True, help="Label for all pcaps passed (e.g., DDoS or Benign)")
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument("--workers", type=int, default=4, help="Process workers (parallel over PCAP files)")
    args = ap.parse_args()

    ensure_dir(str(pd.Path(args.out).parent) if hasattr(pd, "Path") else ".")

    all_rows: List[dict] = []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(pcap_to_header_rows, p, args.label) for p in args.pcaps]
        for fut in tqdm(as_completed(futs), total=len(futs), desc="Extract header features"):
            all_rows.extend(fut.result())

    df = pd.DataFrame(all_rows)
    df.to_csv(args.out, index=False)
    print(f"[OK] Wrote {len(df):,} flow rows to {args.out}")


if __name__ == "__main__":
    main()
