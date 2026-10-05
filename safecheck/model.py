"""The machine-learning part: TF-IDF features + logistic regression.

Simple on purpose. It trains in seconds, works on small data, and is easy to explain:
the model learns which words and character patterns appear more in scams than in normal messages.
"""
import re
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from .rules import normalize

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model.joblib"

# The public dataset replaces numbers with tokens like [MONEY] and [DATE]. Users paste real numbers,
# so we turn numbers into the same tokens before the model sees any text, training or live.
_UNIT = r"(?:vnd|vnđ|đ|d|k|nghìn|nghin|ngàn|ngan|triệu|trieu|tr|tỷ|ty|usd)"
NUMBER_TOKENS = [
    (re.compile(r"\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b"), "[DATE]"),
    (re.compile(r"\b\d{1,2}(?::\d{2}|h\d{2}|h)\b", re.IGNORECASE), "[TIME]"),
    (re.compile(rf"(?:\$ ?)?\b\d[\d.,]*\s?{_UNIT}\b|\$ ?\d[\d.,]*|\b\d{{1,3}}(?:[.,]\d{{3}})+\b", re.IGNORECASE),
     "[MONEY]"),
    (re.compile(r"\b\d+\b"), "[NUMBER]"),
]
PLACEHOLDER = re.compile(r"\[([A-Z_]+)\]")
# "https://www." says nothing about whether a link is safe, but almost every link in real SMS data is spam,
# so without this the model learns "http" itself = scam. The domain after it is what matters.
URL_SCHEME = re.compile(r"\bhttps?://(?:www\.)?", re.IGNORECASE)


def prepare(text: str) -> str:
    """Numbers -> [MONEY]/[DATE]/[TIME]/[NUMBER], then placeholders -> words like tok_money, then normalize."""
    text = URL_SCHEME.sub("", text)
    for pattern, token in NUMBER_TOKENS:
        text = pattern.sub(token, text)
    text = PLACEHOLDER.sub(lambda m: f" tok_{m.group(1).lower()} ", text)
    return normalize(text)


def build_pipeline() -> Pipeline:
    features = FeatureUnion([
        # whole words and word pairs, e.g. "chuyen tien", "ma otp"
        ("words", TfidfVectorizer(preprocessor=prepare, ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
        # character pieces, robust to typos and missing accents, e.g. "khoa", ".top"
        ("chars", TfidfVectorizer(preprocessor=prepare, analyzer="char_wb", ngram_range=(2, 5),
                                  min_df=2, sublinear_tf=True)),
    ])
    clf = LogisticRegression(C=4.0, class_weight="balanced", max_iter=2000)
    return Pipeline([("features", features), ("clf", clf)])


def save(pipeline: Pipeline, path: Path = MODEL_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)


def load(path: Path = MODEL_PATH) -> Pipeline:
    if not path.exists():
        raise FileNotFoundError(f"No model at {path}. Run: python train.py")
    return joblib.load(path)


def top_terms(pipeline: Pipeline, n: int = 15) -> list[tuple[str, float]]:
    """The word-level features that push most strongly toward 'scam' (useful for your report)."""
    words = pipeline.named_steps["features"].transformer_list[0][1]
    coefs = pipeline.named_steps["clf"].coef_[0][: len(words.vocabulary_)]
    vocab = words.get_feature_names_out()
    order = coefs.argsort()[::-1][:n]
    return [(vocab[i], round(float(coefs[i]), 3)) for i in order]
