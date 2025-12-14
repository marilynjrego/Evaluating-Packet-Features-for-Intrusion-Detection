from __future__ import annotations

import argparse
from typing import List, Tuple

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DROP_COLS = {"flow_id", "src_ip", "dst_ip", "pcap_path"}


def split_xy(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    y = df["label"].astype(str)
    X = df.drop(columns=[c for c in DROP_COLS if c in df.columns] + ["label"], errors="ignore")
    return X, y


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Features CSV (header-only or merged header+payload)")
    ap.add_argument("--test_size", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n_estimators", type=int, default=300)
    ap.add_argument("--max_depth", type=int, default=None)
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    X, y = split_xy(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y
    )

    num_cols: List[str] = list(X.columns)

    model = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        random_state=args.seed,
        n_jobs=-1,
        class_weight="balanced",
    )

    pipe = Pipeline(
        steps=[
            ("scale", ColumnTransformer([("num", StandardScaler(with_mean=False), num_cols)], remainder="drop")),
            ("rf", model),
        ]
    )

    pipe.fit(X_train, y_train)
    pred = pipe.predict(X_test)

    print("\n=== Metrics ===")
    print(f"Accuracy:  {accuracy_score(y_test, pred):.4f}")
    print(f"Precision: {precision_score(y_test, pred, average='weighted', zero_division=0):.4f}")
    print(f"Recall:    {recall_score(y_test, pred, average='weighted', zero_division=0):.4f}")
    print(f"F1:        {f1_score(y_test, pred, average='weighted', zero_division=0):.4f}")

    print("\n=== Classification report ===")
    print(classification_report(y_test, pred, zero_division=0))


if __name__ == "__main__":
    main()
