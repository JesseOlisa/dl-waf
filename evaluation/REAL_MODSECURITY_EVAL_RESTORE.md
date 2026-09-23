# Restoring the Real-ModSecurity Evaluation Stack

Cleaned from the machine on 2026-09-23 to save disk (~2.5 GB freed). Results
are **not** affected: they live in `model/results/modsecurity_lib_metrics.json`
and `evaluation/DL_WAF_vs_ModSecurity_Report.md`, which do not require the engine.

## What was removed

| Item | Version | Size | Reinstall |
|---|---|---|---|
| `libmodsecurity` (brew, ModSecurity v3 C engine) | 3.0.16 | ~5 MB | `brew install modsecurity` |
| `pkgconf` (brew; only used to test the binding build) | 3.0.7 | ~1 MB | not needed — the wheel is prebuilt |
| `libmodsecurity` (PyPI binding, macOS arm64 wheel) | 3.0.15.post2 | ~8 MB | see below |
| OWASP CRS clone | v3.3.9 | ~4 MB | `git clone` below |
| Orphaned brew deps (lua, libmaxminddb, yajl) | — | small | come back with `modsecurity` |
| `scikit-learn` / `scipy` / `pandas` / `joblib` / `threadpoolctl` (venv) | 1.9.1 / 1.17.1 / 3.0.6 | ~215 MB | only needed for ML training/eval re-runs |
| Homebrew download cache | — | ~1.9 GB | `brew cleanup` reclaims next time; repopulates on install |
| pip cache | — | ~340 MB | repopulates on install |

Kept: TensorFlow + Keras (needed by `backend.inference`), the ML model
checkpoints in `model/saved/`, `data/processed/*.npy`, frontend `node_modules`,
and every results JSON / PNG.

## One-shot restore

```bash
# 1. Real ModSecurity engine + C binding
brew install modsecurity                # installs libmodsecurity 3.x + deps
./venv/bin/pip install libmodsecurity   # pulls 3.0.15.post2 macOS-arm64 wheel

# 2. OWASP CRS rules (must be cloned where the eval script expects it)
git clone --depth 1 --branch v3.3.9 https://github.com/coreruleset/coreruleset.git /tmp/coreruleset

# 3. Re-run the 9,160-request evaluation
./venv/bin/python -m evaluation.modsecurity_lib_eval --crs /tmp/coreruleset
```

Only if re-running the **ML pipeline** (preprocess / train / evaluate):
```bash
./venv/bin/pip install "scikit-learn==1.9.1" "scipy==1.17.1" "pandas==3.0.6"
```
(`model/evaluate.py`, `model/train_*.py`, `data/preprocess.py` need them; the
robustness scripts `obfuscation_eval.py` / `adversarial_eval.py` and
`compare_results.py` do **not**.)

## Reproduce-correctness notes (do these or the numbers are wrong)

- **Strip the trailing ` HTTP/1.1`** from the CSIC `URL` column before
  `urlparse` (else CRS 920-protocol rules block ~everything). Done in
  `modsecurity_lib_eval.py::_clean_path`, mirroring `data/preprocess.py`.
- **Send realistic headers**: `Accept` present, `Content-Type` only when a body
  exists, `Content-Length` on POSTs — otherwise rule 920210/920300 reject
  nearly every replay for carriage reasons, not attack content.
- **Blocking must be enabled**: CRS 3.3.9 ships detection-only. The script
  re-asserts `SecDefaultAction "phase:2,log,auditlog,deny,status:403"` after
  loading `crs-setup.conf.example` (last-wins).
- Expected outcome on the test split: acc ≈ 72.3%, recall ≈ 32.6%, FPR = 0.0
  (CRS default paranoia level 1) — see `model/results/modsecurity_lib_metrics.json`.

## Notes

- `evaluation/modsecurity_eval.py` (the older python-modsecurity-based script)
  was already non-functional (that PyPI package does not exist); it is retained
  as reference only.
- Default `--mode dlwaf` runs of `obfuscation_eval.py` / `adversarial_eval.py`
  do not touch the ModSecurity stack; their optional `--mode binding` variants
  need the restore above.