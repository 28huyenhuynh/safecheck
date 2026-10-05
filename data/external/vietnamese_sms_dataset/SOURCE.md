# Source and license

`train.csv`, `test.csv` and `README.md` in this folder are unmodified copies from:

- **Dataset:** Vietnamese SMS Dataset with Quality Assurance (Vietnamese Quality-Assured SMS Scam Dataset)
- **Authors:** Tran Nguyen Thai Tuan, Le Hoang Khang, Nguyen Minh Tai, Nguyen Van Thang, Mai Hoang Dinh
- **Repository:** https://github.com/trannguyenthaituan251209/vietnamese_sms_dataset
- **Version used:** commit `464a028878023598e16f2f344ee36f7d5d74257f` (Aug 7, 2026), downloaded Oct 5, 2026
- **License:** Creative Commons Attribution 4.0 International (CC BY 4.0), https://creativecommons.org/licenses/by/4.0/

## Citation (as requested by the authors)

```bibtex
@article{tuan2026vietnamese_sms_phishing,
  title={Vietnamese SMS Dataset with Quality Assurance},
  author={Tran, Nguyen Thai Tuan and Le, Hoang Khang and Nguyen, Minh Tai and Nguyen, Van Thang and Mai, Hoang Dinh},
  journal={IEEE Access},
  year={2026}
}
```

## How SafeCheck uses it

The files are not edited. At training time, `train.py`:

- maps labels `1` (spam/scam) → `scam` and `0` (legitimate) → `safe`. Label `1` also covers spam such as gambling ads, so SafeCheck's "scam" score means "spam or scam" for these examples;
- drops the training messages that also appear in `test.csv` (55 after ignoring case, accents and spacing), so the test score is not inflated;
- uses `train.csv` (with SafeCheck's own examples) to train, and `test.csv` only to measure accuracy.
