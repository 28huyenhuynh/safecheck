"""Remove personal details from a scam message before it is saved as training data.

Automatic redaction catches numbers, emails and link tracking codes. It cannot reliably
find people's names, so a volunteer must still read the result before saving it.
"""
import re

# Order matters: emails and phones first, so their digits aren't caught by the number rules.
REDACTIONS = [
    # emails
    (re.compile(r"\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b"), "[EMAIL]"),
    # Vietnamese phone numbers: 0912345678, 0912 345 678, 0912.345.678, +84 912 345 678, 84912345678
    (re.compile(r"(?<![\w])(\+?84|0)[ .-]?[35789]\d(?:[ .-]?\d){7}(?!\d)"), "[SĐT]"),
    # partly masked phones like 0987xxxxxx
    (re.compile(r"(?<![\w])0[35789]\d{2}[x*]{6}(?![\w])", re.IGNORECASE), "[SĐT]"),
    # card numbers: 16 digits in groups of 4
    (re.compile(r"(?<!\d)\d{4}([ -]\d{4}){3}(?!\d)"), "[SỐ THẺ]"),
    # long digit runs: account numbers (8-19 digits), CCCD (12 digits)
    (re.compile(r"(?<!\d[.,])(?<!\d)\d{8,19}(?![.,]\d|\d)"), "[SỐ TK]"),
    # partly masked account numbers like 1023xxxx789
    (re.compile(r"(?<![\w])\d{2,}[x*]{3,}\d*(?![\w])", re.IGNORECASE), "[SỐ TK]"),
    # one-time codes: 4-7 digit runs not part of a money amount, time, date, plate number or year
    (re.compile(r"(?<!\d[.,])(?<![\d/-])(?!(?:19|20)\d\d(?!\d))\d{4,7}(?![.,]\d|[\d:/]|\s?(?:k|đ|d|vnd|vnđ|nghìn|nghin|triệu|trieu)\b)",
                re.IGNORECASE), "[MÃ]"),
]

# Query strings (?id=...&token=...) in links can carry personal tracking IDs; the domain is what matters.
URL_QUERY = re.compile(r"((?:https?://)?[\w.-]+\.[a-z]{2,}(?:/[^\s?]*)?)\?\S+", re.IGNORECASE)


def redact(text: str) -> str:
    text = URL_QUERY.sub(r"\1", text)
    for pattern, placeholder in REDACTIONS:
        text = pattern.sub(placeholder, text)
    return text.strip()
