from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Optional

import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, PcapReader  # type: ignore
from tqdm import tqdm

from common import FlowKey, FlowStats, ensure_dir, is_printable_byte, safe_mean, safe_std, shannon_entropy


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
    return None


def reverse_key(k: FlowKey) -> FlowKey:
    src, dst, sport, dport, proto = k
    return (dst, src, dport, sport, proto)


def pcap_to_payload_rows(pcap_path: str, label: str) -> List[dict]:
    flows: Dict[FlowKey, FlowStats] = {}
    canonical: Dict[FlowKey, FlowKey] = {}

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            k = packet_flow_key(pkt)
            if k is None:
                continue

            if k in canonical:
                canon = canonical[k]
            else:
                rk = reverse_key(k)
                if rk in canonical:
                    canon = canonical[rk]
                    canonical[k] = canon
                else:
                    canonical[k] = k
                    canonical[rk] = k
                    canon = k

            if canon not in flows:
                ts = float(pkt.time)
                flows[canon] = FlowStats(first_ts=ts, last_ts=ts)
            flows[canon].last_ts = max(flows[canon].last_ts, float(pkt.time))

            # Raw payload bytes (TCP/UDP)
            raw = pkt.getlayer(Raw)
            if raw is None:
                continue
            payload: bytes = bytes(raw.load) if getattr(raw, "load", None) is not None else b""
            if not payload:
                continue

            st = flows[canon]
            st.payload_pkts += 1
            st.payload_bytes += len(payload)

            L = len(payload)
            st.payload_len_sum += L
            st.payload_len_sq_sum += L * L
            st.payload_len_n += 1

            ent = shannon_entropy(payload)
            st.payload_entropy_sum += ent
            st.payload_entropy_sq_sum += ent * ent
            st.payload_entropy_n += 1

            # Printable ratio
            st.total_payload_bytes_for_printable += L
            st.printable_bytes += sum(1 for b in payload if is_printable_byte(b))

    rows: List[dict] = []
    for fk, st in flows.items():
        src, dst, sport, dport, proto = fk
        rows.append(
            {
                "flow_id": f"{src}-{dst}-{sport}-{dport}-{proto}",
                "payload_pkts": st.payload_pkts,
                "payload_bytes": st.payload_bytes,
                "payload_len_mean": safe_mean(st.payload_len_sum, st.payload_len_n),
                "payload_len_std": safe_std(st.payload_len_sum, st.payload_len_sq_sum, st.payload_len_n),
                "payload_entropy_mean": safe_mean(st.payload_entropy_sum, st.payload_entropy_n),
                "payload_entropy_std": safe_std(st.payload_entropy_sum, st.payload_entropy_sq_sum, st.payload_entropy_n),
                "payload_printable_ratio": (
                    st.printable_bytes / st.total_payload_bytes_for_printable
                    if st.total_payload_bytes_for_printable > 0
                    else 0.0
                ),
                "label": label,
                "pcap_path": pcap_path,
            }
        )
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcaps", nargs="+", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    ensure_dir(str(pd.Path(args.out).parent) if hasattr(pd, "Path") else ".")

    all_rows: List[dict] = []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(pcap_to_payload_rows, p, args.label) for p in args.pcaps]
        for fut in tqdm(as_completed(futs), total=len(futs), desc="Extract payload features"):
            all_rows.extend(fut.result())

    df = pd.DataFrame(all_rows)
    df.to_csv(args.out, index=False)
    print(f"[OK] Wrote {len(df):,} flow rows to {args.out}")


if __name__ == "__main__":
    main()
