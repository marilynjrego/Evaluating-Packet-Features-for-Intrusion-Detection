from __future__ import annotations

import argparse

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train_csv", required=True)
    ap.add_argument("--test_csv", required=True)
    ap.add_argument("--n_estimators", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    train_df = pd.read_csv(args.train_csv)
    test_df = pd.read_csv(args.test_csv)

    drop_cols = [c for c in ["flow_id", "src_ip", "dst_ip", "pcap_path"] if c in train_df.columns]
    Xtr = train_df.drop(columns=drop_cols + ["label"], errors="ignore")
    ytr = train_df["label"].astype(str)

    drop_cols2 = [c for c in ["flow_id", "src_ip", "dst_ip", "pcap_path"] if c in test_df.columns]
    Xte = test_df.drop(columns=drop_cols2 + ["label"], errors="ignore")
    yte = test_df["label"].astype(str)

    pipe = Pipeline(
        steps=[
            ("scale", StandardScaler(with_mean=False)),
            (
                "rf",
                RandomForestClassifier(
                    n_estimators=args.n_estimators,
                    random_state=args.seed,
                    n_jobs=-1,
                    class_weight="balanced",
                ),
            ),
        ]
    )

    pipe.fit(Xtr, ytr)
    pred = pipe.predict(Xte)

    print("\n=== Transfer test ===")
    print(f"Weighted F1: {f1_score(yte, pred, average='weighted', zero_division=0):.4f}")
    print(classification_report(yte, pred, zero_division=0))


if __name__ == "__main__":
    main()
