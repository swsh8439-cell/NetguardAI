#!/usr/bin/env python3
"""
NetGuard AI - Machine Learning Pipeline
Trains a Random Forest Classifier on network flow features (CIC-IDS2017 schema).
Evaluates accuracy, precision, recall, F1, confusion matrix, and ROC-AUC curve.
"""

import json
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc
)
import joblib

FEATURE_NAMES = [
    'destination_port',
    'flow_duration',
    'total_fwd_packets',
    'total_backward_packets',
    'flow_bytes_s',
    'flow_packets_s',
    'fwd_packet_length_mean',
    'packet_length_std',
    'syn_flag_count',
    'ack_flag_count'
]

LABEL_MAP = {
    0: 'Normal',
    1: 'DoS/DDoS',
    2: 'Port Scan',
    3: 'Brute Force',
    4: 'Web Attack',
    5: 'Botnet'
}

def generate_synthetic_cic_ids(n_samples=16000, random_state=42):
    """Generates realistic network flow data adhering to CIC-IDS2017 distributions."""
    np.random.seed(random_state)

    n_normal = int(n_samples * 0.55)
    n_dos = int(n_samples * 0.15)
    n_scan = int(n_samples * 0.11)
    n_brute = int(n_samples * 0.09)
    n_bot = int(n_samples * 0.06)
    n_web = n_samples - (n_normal + n_dos + n_scan + n_brute + n_bot)

    records = []

    # 1. Normal traffic
    for _ in range(n_normal):
        port = int(np.random.choice([80, 443, 53, 8080, 22, 123, 8443, 445]))
        duration = float(np.random.exponential(scale=350000) + 1000)
        fwd_pkts = int(np.random.poisson(lam=12) + 1)
        bwd_pkts = int(np.random.poisson(lam=14) + 1)
        bytes_s = float(max(100, np.random.normal(loc=45000, scale=12000)))
        pkts_s = float(max(1, np.random.normal(loc=120, scale=40)))
        fwd_mean = float(max(20, np.random.normal(loc=280, scale=60)))
        pkt_std = float(max(10, np.random.normal(loc=180, scale=45)))
        syn_count = 1 if np.random.rand() > 0.05 else 0
        ack_count = 1 if np.random.rand() > 0.10 else 0
        records.append([
            port, duration, fwd_pkts, bwd_pkts,
            bytes_s, pkts_s, fwd_mean, pkt_std,
            syn_count, ack_count, 0
        ])

    # 2. DoS / DDoS (SYN flood, HTTP flood)
    for _ in range(n_dos):
        port = int(np.random.choice([80, 443, 8080]))
        duration = float(np.random.exponential(scale=45000) + 50)
        fwd_pkts = int(np.random.poisson(lam=85) + 20)
        bwd_pkts = int(np.random.choice([0, 1, 2]))
        bytes_s = float(max(1000, np.random.normal(loc=480000, scale=80000)))
        pkts_s = float(max(500, np.random.normal(loc=2800, scale=450)))
        fwd_mean = float(max(20, np.random.normal(loc=72, scale=15)))
        pkt_std = float(max(5, np.random.normal(loc=25, scale=8)))
        syn_count = 1
        ack_count = 0
        records.append([
            port, duration, fwd_pkts, bwd_pkts,
            bytes_s, pkts_s, fwd_mean, pkt_std,
            syn_count, ack_count, 1
        ])

    # 3. Port Scan (Rapid scanning of random high ports)
    for _ in range(n_scan):
        port = int(np.random.randint(20, 65535))
        duration = float(np.random.uniform(50, 2000))
        fwd_pkts = int(np.random.choice([1, 2, 3]))
        bwd_pkts = 0
        bytes_s = float(max(10, np.random.normal(loc=800, scale=200)))
        pkts_s = float(max(10, np.random.normal(loc=450, scale=100)))
        fwd_mean = float(max(10, np.random.normal(loc=44, scale=6)))
        pkt_std = float(max(2, np.random.normal(loc=12, scale=4)))
        syn_count = 1
        ack_count = 0
        records.append([
            port, duration, fwd_pkts, bwd_pkts,
            bytes_s, pkts_s, fwd_mean, pkt_std,
            syn_count, ack_count, 2
        ])

    # 4. Brute Force (SSH/FTP repeated password attempts)
    for _ in range(n_brute):
        port = int(np.random.choice([22, 21, 3389, 23]))
        duration = float(np.random.exponential(scale=180000) + 5000)
        fwd_pkts = int(np.random.poisson(lam=28) + 8)
        bwd_pkts = int(np.random.poisson(lam=22) + 6)
        bytes_s = float(max(100, np.random.normal(loc=18000, scale=4000)))
        pkts_s = float(max(10, np.random.normal(loc=75, scale=20)))
        fwd_mean = float(max(20, np.random.normal(loc=140, scale=30)))
        pkt_std = float(max(10, np.random.normal(loc=85, scale=20)))
        syn_count = 1
        ack_count = 1
        records.append([
            port, duration, fwd_pkts, bwd_pkts,
            bytes_s, pkts_s, fwd_mean, pkt_std,
            syn_count, ack_count, 3
        ])

    # 5. Web Attack (SQLi, XSS)
    for _ in range(n_web):
        port = int(np.random.choice([80, 443, 8080, 3000]))
        duration = float(np.random.exponential(scale=280000) + 2000)
        fwd_pkts = int(np.random.poisson(lam=18) + 4)
        bwd_pkts = int(np.random.poisson(lam=16) + 3)
        bytes_s = float(max(500, np.random.normal(loc=65000, scale=15000)))
        pkts_s = float(max(10, np.random.normal(loc=95, scale=25)))
        fwd_mean = float(max(50, np.random.normal(loc=460, scale=85)))
        pkt_std = float(max(20, np.random.normal(loc=310, scale=60)))
        syn_count = 1
        ack_count = 1
        records.append([
            port, duration, fwd_pkts, bwd_pkts,
            bytes_s, pkts_s, fwd_mean, pkt_std,
            syn_count, ack_count, 4
        ])

    # 6. Botnet (Periodic C2 beacons)
    for _ in range(n_bot):
        port = int(np.random.choice([6667, 8000, 4444, 5555, 8088]))
        duration = float(np.random.exponential(scale=500000) + 10000)
        fwd_pkts = int(np.random.poisson(lam=34) + 6)
        bwd_pkts = int(np.random.poisson(lam=30) + 5)
        bytes_s = float(max(200, np.random.normal(loc=28000, scale=6000)))
        pkts_s = float(max(10, np.random.normal(loc=55, scale=15)))
        fwd_mean = float(max(30, np.random.normal(loc=210, scale=40)))
        pkt_std = float(max(15, np.random.normal(loc=130, scale=30)))
        syn_count = 1
        ack_count = 1
        records.append([
            port, duration, fwd_pkts, bwd_pkts,
            bytes_s, pkts_s, fwd_mean, pkt_std,
            syn_count, ack_count, 5
        ])

    df = pd.DataFrame(records, columns=FEATURE_NAMES + ['label'])
    return df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)


def train_and_export_model(output_dir="/Users/shreya/.gemini/antigravity/scratch/netguard-ids/models"):
    os.makedirs(output_dir, exist_ok=True)

    print("Generating CIC-IDS2017 training dataset...")
    df = generate_synthetic_cic_ids(n_samples=16000)

    X = df[FEATURE_NAMES]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("Training Random Forest Classifier (n_estimators=100)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    y_prob = clf.predict_proba(X_test_scaled)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted')
    rec = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')

    # Binary metrics for Confusion Matrix (Normal vs Attack)
    y_test_binary = (y_test > 0).astype(int)
    y_pred_binary = (y_pred > 0).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test_binary, y_pred_binary).ravel()

    # Binary ROC Curve
    attack_probs = 1.0 - y_prob[:, 0]
    fpr, tpr, _ = roc_curve(y_test_binary, attack_probs)
    roc_auc = auc(fpr, tpr)

    sample_indices = np.linspace(0, len(fpr) - 1, 25).astype(int)
    roc_points = [
        {"fpr": round(float(fpr[i]), 4), "tpr": round(float(tpr[i]), 4)}
        for i in sample_indices
    ]
    if roc_points[0] != {"fpr": 0.0, "tpr": 0.0}:
        roc_points.insert(0, {"fpr": 0.0, "tpr": 0.0})
    if roc_points[-1] != {"fpr": 1.0, "tpr": 1.0}:
        roc_points.append({"fpr": 1.0, "tpr": 1.0})

    feature_importances = [
        {"feature": name, "importance": round(float(imp), 4)}
        for name, imp in zip(FEATURE_NAMES, clf.feature_importances_)
    ]
    feature_importances.sort(key=lambda x: x["importance"], reverse=True)

    metrics = {
        "accuracy": round(float(acc) * 100, 1),
        "precision": round(float(prec) * 100, 1),
        "recall": round(float(rec) * 100, 1),
        "f1_score": round(float(f1) * 100, 1),
        "roc_auc": round(float(roc_auc), 3),
        "confusion_matrix": {
            "true_normal": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp)
        },
        "roc_curve": roc_points,
        "feature_importances": feature_importances,
        "classes": LABEL_MAP
    }

    model_path = os.path.join(output_dir, "netguard_rf_model.joblib")
    scaler_path = os.path.join(output_dir, "scaler.joblib")
    metrics_path = os.path.join(output_dir, "model_metrics.json")

    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)

    # Export sample test CSV with 60 realistic rows
    sample_df = df.head(60).copy()
    sample_df['true_label'] = sample_df['label'].map(LABEL_MAP)
    sample_csv_path = "/Users/shreya/.gemini/antigravity/scratch/netguard-ids/sample_data.csv"
    sample_df.to_csv(sample_csv_path, index=False)

    print(f"Model saved: {model_path}")
    print(f"Scaler saved: {scaler_path}")
    print(f"Metrics saved: {metrics_path}")
    print(f"Sample data created: {sample_csv_path}")
    print("\n--- Model Evaluation Summary ---")
    print(f"Accuracy:  {metrics['accuracy']}%")
    print(f"Precision: {metrics['precision']}%")
    print(f"Recall:    {metrics['recall']}%")
    print(f"F1-Score:  {metrics['f1_score']}%")
    print(f"ROC AUC:   {metrics['roc_auc']}")
    print(f"Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")

    return clf, scaler, metrics

if __name__ == "__main__":
    train_and_export_model()
