---
title: SafeCheck
emoji: 🛡️
colorFrom: green
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
---

# SafeCheck: Vietnamese scam message checker (prototype v0.3)

Paste a suspicious message or link and get a 0–100 risk score plus a plain-Vietnamese explanation of the red flags. This is the AI detector half of the SafeCheck Clinic project.

## Run it

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python train.py               # trains the model, tests it on real messages, saves models/model.joblib
python tests/test_detector.py # 10 quick tests
uvicorn app:app --reload      # then open http://127.0.0.1:8000
```

## Put it online

The `Dockerfile` installs everything, retrains the model, runs the tests and starts the server.

- **Render** (easiest): push this folder to a GitHub repo, then on render.com choose *New → Web Service*, pick the repo and choose *Docker*. Free instances sleep when unused, so the first visit can take ~30 seconds.
- **Hugging Face Spaces**: create a Space with the *Docker* SDK and upload these files. Add this to the top of the Space's README.md:
  ```
  ---
  title: SafeCheck
  sdk: docker
  app_port: 7860
  ---
  ```

## User feedback

Under every result, users can answer "Kết quả này có đúng không?" (only the verdict and score are saved, never the message). At the bottom of the page, a short survey (*Góp ý cho SafeCheck*) asks about accuracy, clarity of the explanations, whether they'd use a site connecting scam victims with experts, which scam signs they run into most, and their own ideas for fighting scams.

- **On your computer**, answers are added to `data/feedback.csv`.
- **Online**, free hosts erase files on restart, so send answers to a Google Sheet instead:
  1. Create a Google Sheet, then *Extensions → Apps Script*, and paste:
     ```js
     const FIELDS = ["time","kind","level","score","correct","accuracy","wrong_example",
                     "clarity","would_use","signs","signs_other","ideas"];
     function doPost(e) {
       const sheet = SpreadsheetApp.getActiveSheet();
       if (sheet.getLastRow() === 0) sheet.appendRow(FIELDS);
       const row = JSON.parse(e.postData.contents);
       sheet.appendRow(FIELDS.map((f) => row[f] ?? ""));
       return ContentService.createTextOutput("ok");
     }
     ```
  2. *Deploy → New deployment → Web app*, execute as **Me**, access **Anyone**. Copy the URL.
  3. Set it as the secret `FEEDBACK_WEBHOOK_URL` on your host (Hugging Face: *Settings → Variables and secrets*; Render/Vercel: *Environment*).

Keep that URL private: anyone who has it can add rows to the sheet.

## Adding clinic samples

```bash
python add_sample.py      # asks for consent, removes personal details, then saves to data/messages.csv
python train.py           # retrain with the new sample
```

`safecheck/anonymize.py` automatically replaces phone numbers, account and card numbers, one-time codes, emails and link tracking codes with placeholders such as `[SĐT]` and `[SỐ TK]`. It **cannot find names, addresses or school names**, so the volunteer must read the result and confirm before it is saved.

## How it works

```
message ──► ML model (TF-IDF + logistic regression) ──► scam probability ──┐
       └──► red-flag rules (keywords + link checks) ──► flags + rule score ─┴─► final score + explanations
```

1. **Normalization** (`safecheck/rules.py`): lowercase and strip accents, so "Tài khoản" and "Tai khoan" match.
2. **ML model** (`safecheck/model.py`): numbers become tokens like `[MONEY]`, then TF-IDF on words, word pairs and character pieces, then logistic regression. Character pieces help with typos and missing accents.
3. **Red-flag rules** (`safecheck/rules.py`): 12 scam patterns common in Vietnam (OTP requests, fake police, prize scams, "việc nhẹ lương cao", fake relatives, sextortion, remote-control apps, ID card requests, etc.), plus link checks: shortened links, risky domain endings (.top, .xyz...), and look-alike bank or brand domains. Warnings such as "không cung cấp mã OTP" are not counted as requests.
4. **Scoring** (`safecheck/detector.py`): final score = 60% ML + 40% rules. Sextortion and fake brand domains are always high risk; three or more red flags together are high risk.
   - 70–100: Nguy cơ cao · 40–69: Đáng ngờ · 0–39: Ít rủi ro

The explanations matter more than the score: every check teaches the user a red flag they can recognize next time.

## Data

| Source | Messages | Used for |
|---|---|---|
| **Vietnamese SMS Dataset** (Tran et al., 2026), `train.csv` | 2,339 real messages | training |
| **Vietnamese SMS Dataset** (Tran et al., 2026), `test.csv` | 597 real messages | testing only |
| Our own examples, `data/messages.csv` | 168 (written for this prototype) | training |

The public dataset contains real Vietnamese SMS messages, collected with contributors' consent and anonymized by its authors. Label `1` means spam *or* scam (it includes gambling and lending ads), so on those messages SafeCheck's "scam" means "spam or scam". The official split has 55 messages in both train and test; `train.py` removes them from training so the test score isn't inflated. Details: [data/external/vietnamese_sms_dataset/SOURCE.md](data/external/vietnamese_sms_dataset/SOURCE.md).

Because that dataset replaces numbers with tokens (`[MONEY]`, `[DATE]`, `[TIME]`, `[NUMBER]`), the model does the same to every message before reading it (`prepare()` in `safecheck/model.py`), so a pasted "2.000.000đ" looks the same as the dataset's `[MONEY]`.

## Current results

Tested on the dataset's official test set: **597 real messages the model never saw** (158 scam/spam, 439 safe).

| Trained on | Accuracy | Scam/spam caught | Safe messages wrongly flagged |
|---|---|---|---|
| Our 168 examples only (full system) | 56.8% | 62.7% | 199 of 439 |
| Our examples + public dataset, ML alone | 92.8% | 93.0% | 32 of 439 |
| **Our examples + public dataset, full system** | **92.6%** | **91.8%** | **31 of 439** |

What this shows:

- **Hand-written examples don't carry over to real messages.** The v0.2 model scored 94% in cross-validation on its own examples but only 57% on real ones. Testing on real data was the most important change.
- **The rules don't add accuracy on real data**, but they produce the explanations users see. They over-fire on legitimate carrier promotions ("tri ân", "tặng", "nạp tiền").
- For comparison, the dataset authors report 93.96% accuracy for logistic regression and 97.28% for PhoBERT (5-fold cross-validation on their deduplicated benchmark, so not exactly the same test).

Bank and service messages in the test set: 179/197 correct, 16 safe ones wrongly flagged.

## Limitations (be honest about these)

- About 1 in 14 safe messages is still flagged, mostly carrier ads and promotions.
- One test message labeled safe asks the reader to log in at `vletcombank.com` (a look-alike of Vietcombank). It may be a labeling error in the dataset; we left the data unchanged.
- "Scam" and "spam" share one label in the public data, so the model can't tell a gambling ad from a bank phishing message. The rules' explanations help tell them apart.
- Our own 168 examples are still written for this prototype, not collected.
- Rules only catch patterns someone has written down; new scam styles need new rules or more data.
- It checks text only. It does not open links or check whether a domain is newly registered.
- The result is advice, not a guarantee. When in doubt, don't click.

## Next steps

1. Check the reporting channels shown on the results page (5656, 156, canhbao.khonggianmang.vn, tinnhiemmang.vn) against current official sources.
2. Add consented, anonymized samples from the clinic (`add_sample.py`).
3. Fine-tune PhoBERT on the same data and compare on the same test set.
4. Reduce false alarms on carrier promotions; consider separate "spam" and "scam" levels.
5. Add domain-age lookup and a browser extension or Zalo/Messenger chatbot.

## Citation and license

The public data is the **Vietnamese SMS Dataset with Quality Assurance** used under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Source: https://github.com/trannguyenthaituan251209/vietnamese_sms_dataset (commit `464a028`). The files are included unmodified; how SafeCheck processes them is described above and in `SOURCE.md`.

```bibtex
@article{tuan2026vietnamese_sms_phishing,
  title={Vietnamese SMS Dataset with Quality Assurance},
  author={Tran, Nguyen Thai Tuan and Le, Hoang Khang and Nguyen, Minh Tai and Nguyen, Van Thang and Mai, Hoang Dinh},
  journal={IEEE Access},
  year={2026}
}
```

## Privacy

The web app checks messages in memory and does not store or log them. Feedback saves only the answers, the verdict and the score. Add real messages only through `add_sample.py`, only with the person's consent, and always read the redacted text for names before saving.

## Project layout

```
app.py                  FastAPI server (POST /api/check, POST /api/feedback, GET /)
train.py                training + evaluation on the real test set
add_sample.py           add a consented, anonymized clinic sample to the data
Dockerfile              for putting the app online
data/messages.csv       our labeled examples (text,label = scam|safe)
data/external/          public Vietnamese SMS Dataset (CC BY 4.0) + SOURCE.md
safecheck/rules.py      normalization, red-flag rules, link checks
safecheck/model.py      ML pipeline
safecheck/detector.py   combines model + rules into the final result
safecheck/anonymize.py  removes phone/account/card numbers, codes and emails
safecheck/feedback.py   saves user feedback (CSV locally, or a Google Sheet webhook)
static/index.html       web page (Vietnamese)
tests/test_detector.py  tests
```
