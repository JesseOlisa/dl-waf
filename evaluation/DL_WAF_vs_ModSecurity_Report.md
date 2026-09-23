# DL-WAF vs ModSecurity — Technical Evaluation Report

**For:** Chapter 5 (Results & Discussion) drafting — this document gives the AI
writer the full, honest evidence base to choose its wording.

**Data sources:** every number here is read from `model/results/*.json`,
`data/processed/dataset_stats.json`, and the evaluation scripts in `evaluation/`.
Nothing below is invented; where a claim is interpretive, it is flagged as such.

---

## 1. Systems under test

### 1.1 DL-WAF (this project)

Three distinct detection surfaces — keep them apart when writing:

| Surface | Where it lives | Decision rule | URL-decoding? |
|---|---|---|---|
| **Layer 1 — standalone LSTM** | `backend/inference.py` + enforced by reverse-proxy middleware `backend/middleware.py` | block if model confidence ≥ 0.5 | **No** (sees raw text) |
| **Layer 2 — signature scan** | `backend/simulation/detection.py` | block if a signature regex fires | **Yes** — double `unquote(unquote())` before matching |
| **Simulation-engine final** | `detection.py` `final_label` | block only if a signature confirms (model is advisory) | Yes |

Notes on what the model actually sees (from `inference._serialize`): the full URL
(**including query string**), the method, the URI path, Content-Type, User-Agent,
Cookie, and body — joined with newlines. So a payload hidden in the query string
is visible to the model. Vocabulary = 97 tokens (ASCII 32–126 + newline + pad),
sequence length 1024 (keep-first-1024, i.e. anything after char ~1024 is ignored).

**Deployed behavior nuance (important for honest wording):** the real
reverse-proxy WAF (`middleware.py`) blocks on the **model alone** and only uses
regexes to *label* the attack type. The regex-confirmation gate exists in the
two-layer **simulation engine**, not the live proxy path. So "the DL-WAF blocks"
and "the two-layer engine blocks" are **not** the same decision surface, and the
paper should say which one it means.

### 1.2 ModSecurity baseline — two artifacts, keep them apart

**Artifact A — real engine (NEW, use this for the paper).** `model/results/modsecurity_lib_metrics.json`
was produced by running the **actual ModSecurity v3 C engine (libmodsecurity)** with
**OWASP CRS v3.3.9** against the same 9,160-request CSIC test split
(`evaluation/modsecurity_lib_eval.py`, `python -m evaluation.modsecurity_lib_eval --crs /tmp/coreruleset`).

Setup used: `brew install modsecurity libmodsecurity` (v3.x C engine) + the
`libmodsecurity` PyPI binding (v3.0.15.post2 + `pkg-config`); CRS cloned to
`/tmp/coreruleset` (tag v3.3.9); 877 rules parsed (1 file fatal — REQUEST-910
IP-reputation GeoIF). Blocking was enabled (CRS ships detection-only) by
re-asserting `SecDefaultAction "phase:2,log,auditlog,deny,status:403"` **after**
loading `crs-setup.conf.example`; classification threshold = whether the
transaction's `intervention()` produced a disruptive action (403).

Replay notes (important for the numbers): each row is replayed with a clean
request line (trailing ` HTTP/1.1` stripped, mirroring `data/preprocess.py`),
plus realistic headers (`Accept`, `Content-Type` only where a body exists,
`Content-Length` on POST bodies). Otherwise CRS 920-protocol rules reject nearly
every honest request for carriage reasons, not attack content.

**Artifact B — recorded `model/results/modsecurity_metrics.json`.** This one is
**not** a real engine run. It was produced by a **pure-Python emulation of OWASP
CRS v3 rule groups** (`evaluation/kaggle_modsecurity_eval.ipynb`), which:

- implements 6 rule groups (SQLi, XSS, LFI, RFI, CMDi, PHPi) as Python regexes,
- normalises with a **single** `unquote_plus()` (no double-decoding, no
  t:urlDecode/t:cssDecode multi-step transformations real CRS applies),
- skips MCU/JS-decoding, response inspection, anomaly scoring, paranoia-level
  escalation, and the ~2,000-rule full CRS config,
- and (latent bug) evaluated the URL column **without** stripping the trailing
  ` HTTP/1.1`, which inflates its false-positive count.

Evidence: the file is stamped `"model": "modsecurity_crs"`; mean latency 0.107 ms
is consistent with in-process regex matching, not `libmodsecurity`.

**Consequence for the paper:** prefer Artifact A for any claim containing the
word "ModSecurity". If you use Artifact B too, label it exactly "OWASP CRS v3
rule-pattern emulation".

---

## 2. Dataset & experimental protocol

CSIC 2010 (HTTP traffic of an e-commerce app; attacks = SQLi, XSS, LDAP
injection, path traversal, "other" fuzzing, malformed requests).

| Property | Value |
|---|---|
| Total records | 61,065 (after dedupe/cleanup) |
| Train / Val / Test | 42,745 / 9,160 / 9,160 (70/15/15 stratified, `random_state=42`) |
| Test class balance | 5,400 legitimate / 3,760 malicious |
| Sequence stats | mean 322 chars, p95 722, max 1,890 (truncate to 1,024) |
| Class weights (train) | legit 0.848, malicious 1.218 |
| Models | LSTM + CNN (see AGENTS.md for exact architecture); Adam lr=1e-3, batch 64, max 50 epochs, early-stop patience 5, ReduceLROnPlateau, best-val checkpoint; threshold 0.5 |

**Same test split for all three systems** (reconstructed deterministically in
`modsecurity_eval.py` / the notebook with the identical 70/15/15 code), so the
head-to-head comparison is apples-to-apples at the dataset level.

---

## 3. Head-to-head benchmark — CSIC 2010 test split (9,160 requests)

| Metric | LSTM (selected) | CNN | ModSecurity real engine (CRS 3.3.9) | CRS-pattern emulation |
|---|---|---|---|---|
| Accuracy | **99.498%** | 99.247% | 72.336% | 65.491% |
| Precision | **99.679%** | 99.597% | 100.000% | 66.911% |
| Recall (TPR) | **99.096%** | 98.564% | 32.606% | 31.516% |
| F1 | **99.387%** | 99.078% | 49.178% | 42.849% |
| False-positive rate | **0.222%** | 0.278% | 0.000% | 10.852% |
| Confusion matrix | TP 3726 / FN 34 / FP 12 / TN 5388 | TP 3706 / FN 54 / FP 15 / TN 5385 | TP 1226 / FN 2534 / FP 0 / TN 5400 | TP 1185 / FN 2575 / FP 586 / TN 4814 |

Selected model = LSTM (criterion F1 − FPR: 0.9916 vs CNN 0.9880), because a WAF
that blocks legit traffic is the worst failure mode.

**Reading the real-engine ModSec row honestly:**
- Default CRS 3.3.9 (paranoia level 1, blocking enabled) caught **1,226 of 3,760**
  malicious requests (≈32.6% recall) and **false-blocked nothing** (0% FPR) on
  this traffic. On CSIC 2010 it *misses most attacks but never disturbs
  legitimate e-commerce flows* — the opposite failure profile of the emulation,
  which showed 10.9% FPR.
- Interpret with context, do not extrapolate: (a) zero FP is against one
  homogeneous 2010 e-commerce dataset, not the wider web; (b) low recall reflects
  default-PL1 CRS, not the full rule set at higher paranoia levels; (c) the
  replay normalises request carriage but does not exercise ModSecurity's full
  real-HTTP pipeline (responses, persistent connections, multipart parsing).

**Training-curve context (for the discussion):**
- LSTM: 50 epochs, train loss 0.684→0.004, val loss 0.654→0.027 (val best 0.0219;
  LR decayed 1e-3→1e-4).
- CNN: stopped at epoch 12, train loss 0.178→0.001, val loss 0.045→0.025.
- Both essentially saturated; the LSTM converged slower and was retained on the
  selection criterion.

---

## 4. Latency

Per-request, single inference (warm-up excluded, 1,000 timed runs, CPU).

| System | Mean | p95 | p99 |
|---|---|---|---|
| LSTM | 79.2 ms | 88.4 ms | 94.9 ms |
| CNN | 76.7 ms | 82.8 ms | 87.5 ms |
| ModSecurity real engine (9,160-request replay) | 0.72 ms | 1.52 ms | 1.71 ms |
| CRS-pattern emulation | 0.107 ms | 0.257 ms | — |

**Honest framing:** the DL models are ~110x slower than the real
`libmodsecurity` transaction and ~700x slower than the regex emulation. ~80 ms
per request is acceptable for a foreground login form but not for high-QPS public
endpoints; headroom exists (batch the TensorFlow call, reduce seq length, or
adopt a faster runtime like ONNX/TFLite — none of the measured numbers assume
these). The deployed WAF also adds HTTPX forwarding time on allowed requests.

---

## 5. Robustness evaluation (beyond the clean test split)

These are the results of the two new experiment scripts
(`evaluation/obfuscation_eval.py`, `evaluation/adversarial_eval.py`) — saved to
`model/results/obfuscation_results.json` and `adversarial_results.json`.

### 5.1 Obfuscation suite — 17 payloads (14 SQLi/XSS attacks + 3 legit probes)

Techniques: plain controls, URL-encoded, double-percent-encoded, inline-comment
`/**/` whitespace-breaking, tab separators, mixed-case keywords, no-whitespace
`UNION/**/SELECT`, SVG-onload filter evasion, img-onerror, nested `<scr<script>`,
hex HTML-entities (`&#x3c;script`), obfuscated `javascript:` URIs.

| Detection surface | Attacks caught | Legit blocked (FP) |
|---|---|---|
| Layer 1 model (live middleware policy) | 12/14 = 85.7% | 0/3 |
| Layer 2 signature (double-decoded scan) | 14/14 = 100% | 0/3 |
| Simulation-engine final | 14/14 = 100% | 0/3 |

What the model missed alone: **mixed-case** keywords (`AdMiN' oR '1'='1' --`)
and **img-onerror** XSS — both caught by Layer 2. Encoded, comment-obfuscated,
and whitespace-obfuscated SQLi/XSS were all caught by **both** layers.

### 5.2 Adversarial evasion — black-box character-level search vs the model

Method: greedy edit search (fillers, newline/tab separators, char duplication /
swap, case-flips, benign context-stuffing). Each accepted edit must strictly
lower the model's confidence **and** leave the payload recognisable to the
double-decoded signature layer (semantic guard: "evaded" ≠ "mangled beyond
recognition"). Budget ≤120 attempts/seed.

| Outcome | Value |
|---|---|
| Seed payloads (SQLi 5, XSS 4; 1 already-missed seed excluded — `xss_img_onerror`) | 9 valid |
| **Driven below 0.5 threshold (model bypassed)** | **9/9 = 100%** |
| Mean attempts to evict | ~27 (range 5–104) |
| Mean confidence drop | −0.970 |
| Of the evaded payloads, still caught by double-decoded signature gate | 9/9 |
| Typical success | `admIn' OR '1'='1' --` → 0.000; `x' NAD unicode(...password...)` → 0.001; `password=changeme<script>alert('XSS')</script>` → 0.255 |

**The single most important interpretive finding** — write this gracefully:
the standalone model (which is what the live proxy enforces) is **trivially
bypassable** by a handful of byte-level perturbations, but every bypassed
payload is still caught by the normalised signature-confirmation gate. So the
two-layer design is not only an XSS-recall fix; it is the project's answer to
adversarial evasion. This is the strongest justification of the architecture in
the report.

**Caveats to preserve honesty:** (a) "still an attack" is operationalised as
*still detectable by the normalised signature layer* — we did NOT verify
executability against a live vulnerable app; (b) the search was greedy/random,
so 100% means "no seed survived in ≤120 attempts", not a theoretical guarantee;
(c) we perturbed the payload, not the URI, headers, or attack semantics at the
protocol level.

### 5.3 Zero-day

**Not evaluated.** No unseen attack families, no cross-dataset test, no
family-holdout training. Keep as stated limitation + future work. Suggested
future-work sentence: *"generalisation to never-before-seen attack families
(e.g., a family hold-out or a second, temporally newer dataset) was not
measured."*

---

## 6. Capability matrix (qualitative — for discussion, not numbers)

| Capability | DL-WAF | ModSecurity CRS (real engine, as known / not measured here) |
|---|---|---|
| Detection paradigm | learned, char-level sequence LM | curated rule set, anomaly scoring |
| Missed on CSIC test set | ~0.9% malicious, ~0.2% blocked legit | ~67% malicious missed, 0% legit blocked (real engine, PL1) |
| Encoded/obfuscated input | Layer 2 double-decodes → strong against %-encoding, comment/whitespace tricks; weak on mixed-case at Layer 1 alone | strong across many encodings by design (t:urlDecode chain), but only if enabled/normalised |
| Adversarial robustness | Layer-1 model poor (100% evadable in our search); Layer-2 gate robust | rule-based — immune to confidence-threshold attacks but never learns |
| Attack coverage | SQLi + XSS (model); same via signatures | broad: SQLi, XSS, LFI, RFI, CMDi, PHPi, etc. in emulation |
| Adaptability | retrainable on new data | requires rule authoring (CRS v4 ongoing) |
| Latency | ~80 ms/request (measured) | sub-ms regex / low-ms engine (typical) |
| Operational complexity | Python + TF model, memory ~few MB | full engine + rule packs |
| Failure policy | fail-open on inference error (by design) | configurable (traditionally fail-closed) |

---

## 7. Known limitations / things you must not over-claim

1. **`model/results/modsecurity_metrics.json` is a CRS-pattern emulation, not
   the engine** (§1.2). Use `modsecurity_lib_metrics.json` for any unqualified
   "ModSecurity" claim.
2. **85.7% on one %-encoding nuance is not Layer-1's real-world robustness.**
   Mixed-case is one perturbation family; a determined attacker has many more.
3. **Adversarial "still-an-attack" ≈ signature-detectable**, not executable
   against a real app.
4. **XSS is the model's known blind spot** (2010-era training); the engine's
   answer is the signature confirm-gate. Keep this asymmetry visible.
5. **Latency comparison favours ModSecurity/regex massively** — never present DL
   latency as competitive without context.
6. **No HTTPS, no response-side inspection, no stateful session tracking**, and
   the middleware skips `/api/*`, `/demo/*`, localhost (§`middleware.py`) — the
   protected perimeter is the demo banking simulation, not arbitrary apps.
7. **Single dataset, single split, single threshold.** No cross-validation
   variance reported; add CI if the examiner asks.
8. **Real-engine ModSec numbers are configuration-dependent**: zero FP and
   ~32.6% recall are for CRS 3.3.9 at default paranoia level with blocking
   enabled; wording should name this config, and higher PLs / tuned rules would
   move recall (likely trading FP).

---

## 8. Paper-wording guidance (draft, for the AI to adapt)

Safe to claim:
- On the CSIC-2010 test split, the selected LSTM achieved 99.50% accuracy /
  99.68% precision / 99.10% recall / 0.22% FPR, outperforming the CNN and, on
  that benchmark, a **real ModSecurity v3 engine with OWASP CRS 3.3.9 (default
  paranoia level, blocking enabled)** which scored 72.34% accuracy / 100%
  precision / 32.61% recall / 0.00% FPR — i.e. both catch the DL-WAF's recall
  gap, but ModSecurity's recall on CSIC is itself low (32.6%) while the DL-WAF
  trades 0.22% FPR for ~66 points of recall. Quote the emulation row too only if
  labelled "OWASP CRS rule-pattern emulation".
- A 17-payload obfuscation suite showed the double-decoded signature layer
  catching 14/14 encoded/obfuscated SQLi & XSS with zero legit blocks, where the
  model alone missed 2/14 (mixed-case SQLi, img-onerror XSS).
- A greedy character-level adversarial search bypassed the model-only decision
  on 9/9 payloads (mean ~27 perturbations) while all 9 remained detectable to
  the normalised signature confirm-gate — evidence that a **confidence-threshold
  deep model alone is not adversarially robust, motivating the layered design**.

Do NOT claim:
- "Robust against obfuscated attacks" broadly (only the tested families).
- "Defeats adversarial attacks" (Layer 2 resisted *our* search; that's it).
- "ModSecurity had zero false positives" as a general property — only "on this
  CSIC-2010 test set under CRS 3.3.9 default configuration did ModSecurity block
  none of the 5,400 legitimate requests".
- "Zero-day robustness" (future work).

Suggested limitation paragraph skeleton:

> The DL-WAF's robustness was assessed on a 2010-era single-vendor benchmark and
> on a small hand-built obfuscation/adversarial suite targeting SQL injection and
> cross-site scripting; generalisation to never-before-seen attack families
> (zero-day) was not measured and is left to future work. The ModSecurity
> baseline used the same test split replayed through the real ModSecurity v3
> engine with OWASP CRS 3.3.9 at default paranoia level with blocking enabled;
> its false-positive rate of zero is specific to this dataset and configuration.
> Adversarial "still-an-attack" was verified by signature recognisability rather
> than execution against a vulnerable service.

---

## 9. Reproducibility & commands

| Artifact | Command |
|---|---|
| Preprocess → `.npy` | `python -m data.preprocess` |
| Train LSTM / CNN | `python -m model.train_lstm` / `python -m model.train_cnn` |
| Test-set eval + latency + selection | `python -m model.evaluate` |
| Obfuscation eval (local) | `python -m evaluation.obfuscation_eval` |
| Adversarial eval (local) | `python -m evaluation.adversarial_eval --max-attempts 120` |
| ModSecurity real engine (done) | `python -m evaluation.modsecurity_lib_eval --crs /tmp/coreruleset` (needs `brew install libmodsecurity` + `libmodsecurity` pip wheel; CRS at `/tmp/coreruleset`) |
| ModSecurity HTTP mode (optional) | `python -m evaluation.modsecurity_eval --mode http --url http://localhost:8081` (docker) |
| Compare table | `python -m evaluation.compare_results` |

Result files: `model/results/{lstm,cnn,modsecurity,modsecurity_lib,latency,
selected_model,comparison_table,final_comparison,obfuscation,adversarial}_*`.

---

## 10. Appendix — raw sources

- LSTM metrics: `model/results/lstm_metrics.json`; CNN: `cnn_metrics.json`
- Baseline: `modsecurity_metrics.json` (pure-Python CRS v3 emulation, §1.2);
  `modsecurity_lib_metrics.json` (real libmodsecurity + CRS 3.3.9, use for paper)
- Selection: `selected_model.json`, `comparison_table.json`
- Obfuscation: `obfuscation_results.json` (17 payloads, 3 surfaces)
- Adversarial: `adversarial_results.json` (10 seeds, 9 valid, 9 evaded)
- Dataset: `data/processed/dataset_stats.json`, `class_weights.json`
- Training curves: `lstm_training_history.json` (50 ep), `cnn_training_history.json` (12 ep); PNGs in `model/results/`