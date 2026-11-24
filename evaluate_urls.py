"""Evaluate ScamShield against a labelled CSV file using only Python stdlib.

CSV columns required: url,label (label is malicious or benign).
Prediction threshold defaults to risk_score >= 30; tune on a development set,
then freeze it before evaluating a hidden test set.
"""
import argparse
import csv
from security_engine import analyze_url


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", help="CSV with url,label columns")
    parser.add_argument("--threshold", type=int, default=30)
    args = parser.parse_args()

    tp = fp = tn = fn = skipped = 0
    with open(args.csv_file, newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip().lower()
            if label not in {"malicious", "benign"} or not url:
                skipped += 1
                continue
            try:
                result = analyze_url(url, enable_rdap=False)
            except ValueError:
                skipped += 1
                continue
            predicted_malicious = result["risk_score"] >= args.threshold
            actual_malicious = label == "malicious"
            if predicted_malicious and actual_malicious:
                tp += 1
            elif predicted_malicious and not actual_malicious:
                fp += 1
            elif not predicted_malicious and not actual_malicious:
                tn += 1
            else:
                fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    print("Confusion matrix counts:")
    print("TP:", tp, "FP:", fp, "TN:", tn, "FN:", fn, "Skipped:", skipped)
    print("Precision: {:.4f}".format(precision))
    print("Recall:    {:.4f}".format(recall))
    print("F1:        {:.4f}".format(f1))
    print("FPR:       {:.4f}".format(fpr))
    print("Threshold: risk_score >= {}".format(args.threshold))


if __name__ == "__main__":
    main()
