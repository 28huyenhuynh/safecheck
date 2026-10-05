"""Train and evaluate the scam classifier.

Usage:  python train.py

Training data: our own examples (data/messages.csv) + the training split of the public
Vietnamese SMS Dataset (Tran et al., 2026, CC BY 4.0; see data/external/vietnamese_sms_dataset/SOURCE.md).
Test data: that dataset's official test split of real messages, never used for training.
"""
import csv
import re
import sys
from pathlib import Path

from sklearn.metrics import classification_report, confusion_matrix

from safecheck.detector import Detector
from safecheck.model import MODEL_PATH, build_pipeline, save, top_terms
from safecheck.rules import BRANDS, normalize

DATA = Path(__file__).resolve().parent / "data"
OWN = DATA / "messages.csv"
PUBLIC = DATA / "external" / "vietnamese_sms_dataset"

BANK_RE = re.compile(r"\b(ngan hang|so du|sd|tk|vcb|" + "|".join(BRANDS) + r")\b")


def load_own(path: Path = OWN) -> tuple[list[str], list[str]]:
    """Our CSV: columns text,label where label is scam or safe."""
    texts, labels = [], []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            label = row["label"].strip().lower()
            if label in {"scam", "safe"} and row["text"].strip():
                texts.append(row["text"].strip())
                labels.append(label)
    return texts, labels


def load_public(split: str) -> tuple[list[str], list[str]]:
    """The public dataset: columns message,label where 1 = spam/scam and 0 = legitimate."""
    texts, labels = [], []
    with open(PUBLIC / f"{split}.csv", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row["label"].strip() in {"0", "1"} and row["message"].strip():
                texts.append(row["message"].strip())
                labels.append("scam" if row["label"].strip() == "1" else "safe")
    return texts, labels


def evaluate(name: str, pipeline, texts: list[str], labels: list[str]) -> list[str]:
    """Print ML-only and full-system (ML + rules) results; return full-system predictions."""
    ml = list(pipeline.predict(texts))
    det = Detector(pipeline)
    system = ["safe" if det.check(t)["level"] == "low" else "scam" for t in texts]

    print(f"=== {name} ===")
    print("ML model only:")
    print(classification_report(labels, ml, digits=3))
    print("Full system (ML + rules; medium/high = scam):")
    print(classification_report(labels, system, digits=3))
    print("Confusion matrix [rows = true safe/scam, cols = predicted safe/scam]:")
    print(confusion_matrix(labels, system, labels=["safe", "scam"]), "\n")

    bank = [i for i, t in enumerate(texts) if BANK_RE.search(normalize(t))]
    right = sum(system[i] == labels[i] for i in bank)
    false_alarms = sum(labels[i] == "safe" and system[i] == "scam" for i in bank)
    print(f"Bank/service messages: {right}/{len(bank)} correct, {false_alarms} safe ones wrongly flagged\n")
    return system


def main() -> None:
    # Windows consoles default to a code page that can't print Vietnamese
    sys.stdout.reconfigure(encoding="utf-8")

    own_x, own_y = load_own()
    pub_x, pub_y = load_public("train")
    test_x, test_y = load_public("test")

    # the official split has some messages in both train and test; drop them from training
    test_keys = {normalize(t) for t in test_x}
    kept = [(t, y) for t, y in zip(pub_x, pub_y) if normalize(t) not in test_keys]
    print(f"Own examples: {len(own_x)} ({own_y.count('scam')} scam, {own_y.count('safe')} safe)")
    print(f"Public train: {len(kept)} (dropped {len(pub_x) - len(kept)} that also appear in the test set)")
    print(f"Public test:  {len(test_x)} real messages ({test_y.count('scam')} scam/spam, "
          f"{test_y.count('safe')} safe), never used for training\n")
    pub_x, pub_y = [t for t, _ in kept], [y for _, y in kept]

    # Before: trained only on our hand-written examples. How well does that carry over to real messages?
    own_only = build_pipeline().fit(own_x, own_y)
    evaluate("Trained on our examples only, tested on real messages", own_only, test_x, test_y)

    # After: our examples + real public data
    train_x, train_y = own_x + pub_x, own_y + pub_y
    pipeline = build_pipeline().fit(train_x, train_y)
    system = evaluate("Trained on our examples + public dataset, tested on real messages",
                      pipeline, test_x, test_y)

    wrong = [(t, y) for t, y, p in zip(test_x, test_y, system) if y != p]
    print(f"Full-system mistakes on the test set ({len(wrong)}), first 15:")
    for t, y in wrong[:15]:
        print(f"  [true: {y}] {t[:100]!r}")
    print()

    save(pipeline)
    print(f"Saved model to {MODEL_PATH} (trained on {len(train_x)} messages)")
    print("Top words pointing to 'scam':", ", ".join(w for w, _ in top_terms(pipeline, 12)))


if __name__ == "__main__":
    main()
