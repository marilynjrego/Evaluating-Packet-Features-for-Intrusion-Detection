from __future__ import annotations

import argparse
import pandas as pd


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--header_csv", required=True)
    ap.add_argument("--payload_csv", required=True)
    ap.add_argument("--out_merged", required=True)
    args = ap.parse_args()

    h = pd.read_csv(args.header_csv)
    p = pd.read_csv(args.payload_csv)

    # Merge by flow_id + label (keeps it honest; avoids accidental cross-label merges)
    df = h.merge(p.drop(columns=["pcap_path"], errors="ignore"), on=["flow_id", "label"], how="left")

    # Fill missing payload features with zeros (flows with no Raw layer / no payload)
    payload_cols = [c for c in df.columns if c.startswith("payload_")]
    df[payload_cols] = df[payload_cols].fillna(0.0)

    df.to_csv(args.out_merged, index=False)
    print(f"[OK] merged rows={len(df):,}, columns={len(df.columns):,} -> {args.out_merged}")


if __name__ == "__main__":
    main()
