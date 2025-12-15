from __future__ import annotations

import argparse

import pandas as pd
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test_size", type=float, default=0.25)
    ap.add_argument("--model", choices=["svm", "mlp"], required=True)
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    drop_cols = [c for c in ["flow_id", "src_ip", "dst_ip", "pcap_path"] if c in df.columns]
    X = df.drop(columns=drop_cols + ["label"], errors="ignore")
    y = df["label"].astype(str)

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=args.test_size, random_state=args.seed, stratify=y)

    if args.model == "svm":
        clf = LinearSVC(class_weight="balanced", random_state=args.seed)
    else:
        clf = MLPClassifier(
            hidden_layer_sizes=(128, 64),
            activation="relu",
            max_iter=30,
            random_state=args.seed,
        )

    pipe = Pipeline(steps=[("scale", StandardScaler(with_mean=False)), ("model", clf)])
    pipe.fit(Xtr, ytr)
    pred = pipe.predict(Xte)

    print(f"\n=== {args.model.upper()} results ===")
    print(f"Weighted F1: {f1_score(yte, pred, average='weighted', zero_division=0):.4f}")
    print(classification_report(yte, pred, zero_division=0))


if __name__ == "__main__":
    main()
