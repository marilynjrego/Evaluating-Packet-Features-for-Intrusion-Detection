# Evaluating-Packet-Features-for-Intrusion-Detection

## Course Use Only

This repository contains materials for **CSE 598: In-Network Machine Learning**.

The contents of this repository are provided **exclusively for students enrolled in CSE 598**.  
**Redistribution, public sharing, reuse, or derivative use is strictly prohibited** without
explicit written permission from the course staff.

This includes (but is not limited to):
- Forking this repository
- Publishing the code or assignment publicly
- Reusing the code in other courses, research projects, or commercial settings

---

# Project introduction

**Goal:** Build a small traffic-classification pipeline and empirically test:
1) how well **header-only** packet/flow features classify attacks, and  
2) whether adding **payload-derived** features improves performance  
3) whether payload features generalize across **different attack types**

You will use the **CSE-CIC-IDS2018** dataset (PCAPs on AWS Open Data).

---

## Dataset notes (CSE-CIC-IDS2018)

UNB provides the dataset on AWS S3 and recommends downloading with `aws s3 sync`. The dataset is organized by day and includes raw network traffic PCAPs.  
See the official dataset page for download + license details.  
(Any redistribution must cite the dataset and link to the AWS registry page.)  

---

## What you will implement

### Part A — Header features (separate file)
- Use **Scapy** to parse PCAPs and build **flow-level** features from headers only.
- Add **parallelism**: speed up extraction by processing multiple PCAP files concurrently.

**Output:** `data/features/header_*.csv`

### Part B — Payload features (separate file)
- Extract payload-derived statistics using the `Raw` layer:
  - payload length stats, entropy stats, printable ratio, etc.
- Again add parallelism.

**Output:** `data/features/payload_*.csv`

### Part C — Train a black-box model (Random Forest)
- Train/evaluate on **header-only** features.
- Train/evaluate on **header + payload** merged features.
- Report Accuracy, Precision, Recall, F1.

### Part D — Transfer test (generalization across attacks)
- Train on **one attack type** (e.g., DDoS) vs Benign.
- Test on a **different attack type** (e.g., DoS / Web Attack / Botnet) vs Benign.
- Compare whether payload features help or hurt generalization.

### Extra credit
- Add another black-box model (SVM or NN) and compare to Random Forest.

---

## Environment setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
