"""Add a clinic sample to the training data, anonymized and only with consent.

Usage:  python add_sample.py              (asks for the message, then the label)
        python add_sample.py scam         (label given up front)

Steps: paste the message -> personal numbers/emails are removed automatically ->
you check the result for names and other details -> confirm consent -> it is appended to data/messages.csv.
Run `python train.py` afterwards to retrain the model.
"""
import sys
from pathlib import Path

from safecheck.anonymize import redact

DATA = Path(__file__).resolve().parent / "data" / "messages.csv"


def ask(prompt: str) -> str:
    return input(prompt).strip()


def yes(prompt: str) -> bool:
    return ask(prompt + " (y/n): ").lower() in {"y", "yes", "c", "co", "có"}


def read_message() -> str:
    print("Paste the message. Finish with an empty line:")
    lines = []
    while (line := input()) != "":
        lines.append(line)
    return " ".join(l.strip() for l in lines).strip()


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stdin.reconfigure(encoding="utf-8")

    if not yes("Did the visitor agree to share this message to improve the detector?"):
        print("Not saved. Only save messages people agreed to share.")
        return

    text = read_message()
    if not text:
        print("Empty message, nothing saved.")
        return

    label = sys.argv[1] if len(sys.argv) > 1 else ask("Label (scam/safe): ")
    label = label.lower()
    if label not in {"scam", "safe"}:
        print("Label must be 'scam' or 'safe'. Nothing saved.")
        return

    clean = redact(text)
    print("\nAfter automatic redaction:\n\n  " + clean + "\n")
    print("Automatic redaction does NOT remove names, addresses, workplaces or school names.")
    if not yes("Is it free of names and anything else that could identify the visitor?"):
        edited = ask("Type the corrected message (or press Enter to cancel): ")
        if not edited:
            print("Cancelled, nothing saved.")
            return
        clean = redact(edited)

    # same format as the existing rows: "text",label
    with open(DATA, "a", encoding="utf-8", newline="") as f:
        f.write('"' + clean.replace('"', '""') + '",' + label + "\n")
    print(f"Saved to {DATA.name} as '{label}'. Run `python train.py` to retrain.")


if __name__ == "__main__":
    main()
