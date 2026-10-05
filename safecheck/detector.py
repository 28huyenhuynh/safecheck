"""Combine the ML model and the red-flag rules into one result for the user."""
from dataclasses import asdict

from . import model as model_mod
from .rules import extract_urls, find_flags, is_official

ML_WEIGHT = 0.6     # share of the final score from the ML model
RULE_WEIGHT = 0.4   # share from the explainable rules
# Flags so serious that the score never goes below "high risk"
CRITICAL_FLAGS = {"sextortion", "brand_lookalike"}
# Weak hints that add a little to the score but don't count toward the "3+ red flags" rule
WEAK_FLAGS = {"no_https"}

LEVELS = [
    (70, "high", "Nguy cơ cao", "Rất có thể là lừa đảo. Không bấm link, không chuyển tiền, không cung cấp thông tin."),
    (40, "medium", "Đáng ngờ", "Có dấu hiệu đáng ngờ. Hãy xác minh qua kênh chính thức trước khi làm theo."),
    (0, "low", "Ít rủi ro", "Chưa thấy dấu hiệu lừa đảo rõ ràng, nhưng vẫn nên cẩn thận với link và yêu cầu chuyển tiền."),
]


class Detector:
    def __init__(self, pipeline=None):
        self.pipeline = pipeline or model_mod.load()

    def check(self, text: str) -> dict:
        text = (text or "").strip()
        if not text:
            raise ValueError("Empty message")

        # Links to known official sites are checked by the rules; hide them from the model, which learned
        # from real SMS data that almost any link is suspicious
        urls = extract_urls(text)
        ml_text = text
        for url in urls:
            if is_official(url):
                ml_text = ml_text.replace(url, " ")

        classes = list(self.pipeline.classes_)
        ml_prob = float(self.pipeline.predict_proba([ml_text])[0][classes.index("scam")])

        flags = find_flags(text)
        rule_score = min(100, sum(f.weight for f in flags))
        score = round(ML_WEIGHT * ml_prob * 100 + RULE_WEIGHT * rule_score)
        if any(f.id in CRITICAL_FLAGS for f in flags):
            score = max(score, 75)
        elif sum(f.id not in WEAK_FLAGS for f in flags) >= 3:   # several independent red flags together = high risk
            score = max(score, 70)
        score = max(0, min(100, score))

        _, level, label_vi, advice_vi = next(lv for lv in LEVELS if score >= lv[0])
        return {
            "score": score,
            "level": level,
            "label_vi": label_vi,
            "advice_vi": advice_vi,
            "ml_probability": round(ml_prob, 3),
            "rule_score": rule_score,
            "flags": [asdict(f) for f in sorted(flags, key=lambda f: -f.weight)],
            "urls": urls,
        }
