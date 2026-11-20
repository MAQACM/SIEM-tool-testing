#!/usr/bin/env python3
# 10_score_detections.py — Detection scoring: TP/FP/FN/TN, accuracy, FPR, F1, latency
#
# Combines the ground-truth CSV from 09_attack_runner.sh with the alerts CSV
# from 03_wazuh_alert_extractor.py or 06_kibana_alert_extractor.py to compute
# the paper's §10.5.1 detection-efficacy metrics per SIEM.
#
# Matching: an attack is a TRUE POSITIVE if at least one alert
#   (a) carries the same MITRE technique (sub-techniques fold to their base,
#       e.g. T1110.001 -> T1110), and
#   (b) occurs within [exec_epoch - PRE, exec_epoch + WINDOW].
# Detection latency = earliest matching alert time - attack execution time.
#
# False positives come from a benign-baseline alert CSV (no attacks ran, so every
# alert there is an FP). True negatives are approximated from the benign event
# count (from 08_event_generator.py) so FPR = FP / (FP + TN) is reportable.
#
# Usage:
#   python3 10_score_detections.py \
#       --ground_truth ground_truth_wazuh_tier1.csv \
#       --alerts wazuh_alerts.csv \
#       --benign_alerts wazuh_benign_alerts.csv \
#       --benign_events 180000 \
#       --label "Wazuh v4.8 - Tier 1" --out wazuh_tier1_scores.csv
import argparse, csv, statistics
from datetime import datetime


def parse_epoch(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s or s in ("N/A", "NaN"):
        return None
    s = s.replace("Z", "+00:00").replace(" ", "T", 1)
    # normalise +0000 -> +00:00
    if len(s) > 5 and s[-5] in "+-" and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    for fmt in (None,):  # try fromisoformat first
        try:
            return datetime.fromisoformat(s).timestamp()
        except Exception:
            pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except Exception:
            continue
    return None


def base_techs(field):
    """'T1110.001, T1190' -> {'T1110', 'T1190'} (sub-techniques folded to base)."""
    out = set()
    for tok in str(field or "").replace(";", ",").split(","):
        tok = tok.strip().upper()
        if tok.startswith("T") and tok[1:].split(".")[0].isdigit():
            out.add(tok.split(".")[0])
    return out


def load_alerts(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            ts = r.get("Timestamp") or r.get("@timestamp") or ""
            rows.append({
                "epoch": parse_epoch(ts),
                "techs": base_techs(r.get("MITRE_Technique", "")),
                "raw": r,
            })
    return rows


def load_ground_truth(path):
    gt = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            gt.append({
                "scenario": r.get("Scenario", ""),
                "vector": r.get("Vector", ""),
                "tech": base_techs(r.get("MITRE_Technique", "")),
                "epoch": float(r["Exec_Epoch"]) if r.get("Exec_Epoch") else parse_epoch(r.get("Exec_ISO")),
                "target": r.get("Target", ""),
            })
    return gt


def score(gt, alerts, window, pre):
    per_attack, latencies = [], []
    attributed = set()  # indices of alerts matched to an attack
    tp = fn = 0
    for a in gt:
        if a["epoch"] is None:
            continue
        lo, hi = a["epoch"] - pre, a["epoch"] + window
        matches = [(i, al) for i, al in enumerate(alerts)
                   if al["epoch"] is not None and lo <= al["epoch"] <= hi
                   and (a["tech"] & al["techs"])]
        # lenient: any alert in the window from anywhere (time-only detection)
        any_in_window = [al for al in alerts
                         if al["epoch"] is not None and lo <= al["epoch"] <= hi]
        if matches:
            tp += 1
            first = min(al["epoch"] for _, al in matches)
            lat_ms = round((first - a["epoch"]) * 1000, 1)
            latencies.append(lat_ms)
            for i, _ in matches:
                attributed.add(i)
            status, lat = "TP", lat_ms
        else:
            fn += 1
            status = "FN"
            lat = "no technique-matched alert" + (f" ({len(any_in_window)} untyped alerts in window)"
                                                  if any_in_window else "")
        per_attack.append({
            "Scenario": a["scenario"], "Vector": a["vector"],
            "Technique": ",".join(sorted(a["tech"])), "Target": a["target"],
            "Status": status, "Latency_ms": lat,
        })
    return per_attack, tp, fn, latencies, attributed


def main():
    p = argparse.ArgumentParser(description="Score SIEM detections vs ground truth")
    p.add_argument("--ground_truth", required=True)
    p.add_argument("--alerts", required=True, help="alerts CSV from the ATTACK run")
    p.add_argument("--benign_alerts", default=None,
                   help="alerts CSV from the BENIGN baseline run (all count as FP)")
    p.add_argument("--benign_events", type=int, default=None,
                   help="benign events generated (approx TN for FPR)")
    p.add_argument("--window", type=float, default=300.0, help="detection window seconds after exec")
    p.add_argument("--pre", type=float, default=5.0, help="allowance seconds before exec (clock skew)")
    p.add_argument("--label", default="SIEM run")
    p.add_argument("--out", default=None, help="write per-attack results CSV")
    args = p.parse_args()

    gt = load_ground_truth(args.ground_truth)
    alerts = load_alerts(args.alerts)
    per_attack, tp, fn, lats, attributed = score(gt, alerts, args.window, args.pre)

    # False positives: prefer the benign baseline; else unattributed attack-run alerts.
    if args.benign_alerts:
        fp = len(load_alerts(args.benign_alerts))
        fp_src = "benign baseline"
    else:
        fp = sum(1 for i, _ in enumerate(alerts) if i not in attributed)
        fp_src = "unattributed attack-run alerts (no benign baseline given)"

    tn = max(0, (args.benign_events - fp)) if args.benign_events else None

    denom_acc = tp + fn + fp + (tn or 0)
    accuracy = 100.0 * (tp + (tn or 0)) / denom_acc if denom_acc else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = (100.0 * fp / (fp + tn)) if tn is not None and (fp + tn) else None

    print("\n================ DETECTION SCORE: {} ================".format(args.label))
    print(f"{'Scenario':<34}{'Technique':<14}{'Status':<6}Latency(ms)")
    print("-" * 72)
    for r in per_attack:
        print(f"{r['Scenario'][:33]:<34}{r['Technique']:<14}{r['Status']:<6}{r['Latency_ms']}")
    print("-" * 72)
    print(f"Attacks (TP+FN)     : {tp + fn}   TP={tp}  FN={fn}")
    print(f"False Positives     : {fp}   (source: {fp_src})")
    print(f"True Negatives      : {tn if tn is not None else 'n/a (pass --benign_events)'}")
    print()
    print(f"Detection Accuracy  : {accuracy:6.2f} %")
    print(f"Precision           : {precision:6.3f}")
    print(f"Recall (TPR)        : {recall:6.3f}")
    print(f"F1-Score            : {f1:6.3f}")
    print(f"False Positive Rate : {('%6.2f %%' % fpr) if fpr is not None else 'n/a'}")
    if lats:
        print(f"Detection Latency   : min {min(lats):.0f} ms | mean {statistics.mean(lats):.0f} ms | "
              f"median {statistics.median(lats):.0f} ms | max {max(lats):.0f} ms")
    print("=" * 72 + "\n")

    if args.out:
        with open(args.out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Scenario", "Vector", "Technique", "Target", "Status", "Latency_ms"])
            for r in per_attack:
                w.writerow([r["Scenario"], r["Vector"], r["Technique"], r["Target"],
                            r["Status"], r["Latency_ms"]])
            w.writerow([])
            w.writerow(["Label", args.label])
            w.writerow(["TP", tp]); w.writerow(["FN", fn]); w.writerow(["FP", fp])
            w.writerow(["TN", tn if tn is not None else ""])
            w.writerow(["Accuracy_%", round(accuracy, 2)])
            w.writerow(["Precision", round(precision, 3)])
            w.writerow(["Recall", round(recall, 3)])
            w.writerow(["F1", round(f1, 3)])
            w.writerow(["FPR_%", round(fpr, 2) if fpr is not None else ""])
            if lats:
                w.writerow(["Latency_min_ms", round(min(lats), 1)])
                w.writerow(["Latency_mean_ms", round(statistics.mean(lats), 1)])
                w.writerow(["Latency_median_ms", round(statistics.median(lats), 1)])
                w.writerow(["Latency_max_ms", round(max(lats), 1)])
        print(f"[✓] Per-attack results + summary written to {args.out}")


if __name__ == "__main__":
    main()
