# DL-WAF Project — Claude Code Context

## Project Identity
This is an MSc Computer Science thesis project at Alex Ekwueme Federal University
Ndufu-Alike (AE-FUNAI), Nigeria. The student is Jesse Ogbonna (PG/M.Sc/2024/405),
supervised by Dr. Ugochukwu Onwudebelu.

**Thesis title:** Design and Implementation of a Deep Learning-Enabled Web Application
Firewall for Intelligent Detection and Prevention of Web Attacks.

---

## What This System Is
A fully functional WAF prototype that:
1. Intercepts HTTP requests in real time (FastAPI reverse proxy middleware)
2. Classifies each request as legitimate or malicious using a trained deep learning model
3. Blocks malicious requests (HTTP 403) and forwards legitimate ones (HTTPX)
4. Logs every event to a SQLite database
5. Displays real-time traffic analytics on an administrative dashboard (Next.js + React)

---

## Project Folder Structure
```
dl-waf/
├── CLAUDE.md               ← this file (always read first)
├── INSTRUCTIONS.md         ← full build brief
├── data/
│   ├── raw/                ← CSIC 2010 dataset files go here (student places manually)
│   └── processed/          ← .npy arrays + vocab.json written by preprocess.py
├── model/
│   ├── preprocess.py       ← preprocessing pipeline
│   ├── train_lstm.py       ← LSTM training script
│   ├── train_cnn.py        ← CNN training script
│   ├── evaluate.py         ← test-set evaluation + confusion matrix
│   ├── saved/              ← best model checkpoints saved here
│   └── results/            ← metrics CSVs, training curve plots
├── backend/
│   ├── main.py             ← FastAPI app entry point
│   ├── middleware.py       ← WAF interception middleware
│   ├── inference.py        ← model loading + preprocessing + inference
│   ├── database.py         ← SQLite setup + event logging
│   ├── routes/
│   │   ├── auth.py         ← /api/auth/login
│   │   ├── stats.py        ← /api/stats/*
│   │   └── events.py       ← /api/events
│   ├── schemas.py          ← Pydantic models
│   ├── config.py           ← externalised config (model path, DB path, threshold, etc.)
│   └── requirements.txt
├── frontend/
│   ├── app/                ← Next.js App Router pages
│   ├── components/         ← React dashboard components
│   ├── lib/
│   │   ├── api.ts          ← Fetch-based query functions
│   │   └── auth.ts         ← JWT session storage helpers
│   ├── hooks/              ← custom React Query hooks (useStats, useEvents, etc.)
│   └── package.json
└── evaluation/
    ├── modsecurity_eval.py ← replay test set against ModSecurity, parse audit log
    ├── compare_results.py  ← side-by-side metrics table (DL-WAF vs ModSecurity)
    └── latency_test.py     ← inference latency measurement (1000 requests)
```

---

## Technology Stack — Non-Negotiable

| Component | Technology | Notes |
|---|---|---|
| WAF Backend | Python 3.11+, FastAPI | Async middleware, reverse proxy |
| Deep Learning | TensorFlow 2.x, Keras | LSTM + CNN |
| HTTP Forwarding | HTTPX (async) | Forward allowed requests |
| Database | SQLite (stdlib sqlite3) | WAL mode enabled |
| Auth | JWT (python-jose), bcrypt (passlib) | Dashboard endpoints protected |
| Frontend Framework | Next.js 16+ (App Router) | React 19+ |pnpm | shadcn 
| Server State | TanStack Query v5 (React Query) | All API calls via useQuery |
| HTTP Client (FE) | Native Fetch API | No Axios |
| Charts | Recharts | Responsive, shadcn|
| Styling | Tailwind CSS | |

---

## Model Architecture — Exact Specifications

### Shared Input
- Vocabulary: 97 tokens (ASCII codes 32–126 = 95 chars + newline + padding index 0)
- Max sequence length: 1,024 characters
- Embedding: dim=64, trainable, random init

### LSTM
```
Embedding(97, 64, input_length=1024)
LSTM(128, return_sequences=True)
Dropout(0.3)
LSTM(64, return_sequences=False)
Dropout(0.3)
Dense(32, activation='relu')
Dense(1, activation='sigmoid')
```

### CNN
```
Embedding(97, 64, input_length=1024)
Conv1D(64, kernel_size=5, activation='relu')
MaxPooling1D(pool_size=2)
Conv1D(128, kernel_size=3, activation='relu')
GlobalMaxPooling1D()
Dropout(0.3)
Dense(32, activation='relu')
Dense(1, activation='sigmoid')
```

### Training Protocol
- Optimiser: Adam (lr=0.001)
- Loss: binary_crossentropy
- Batch size: 64
- Max epochs: 50
- Early stopping: patience=5, monitor=val_loss
- LR reduction: ReduceLROnPlateau(factor=0.5, patience=3)
- Class weights: inverse frequency
- Checkpoint: save best val_f1 (custom callback or val_loss proxy)
- Classification threshold: 0.5

---

## Preprocessing Pipeline — Exact Steps
1. Load raw CSIC 2010 files, assign labels (0=legitimate, 1=malicious)
2. Remove duplicates and malformed records
3. Serialise each request: request_line + '\n' + selected headers + '\n' + body
   - Include: Method, URI, Content-Type, User-Agent, Cookie, body
   - Exclude: Host (constant), Accept-Encoding (no payload relevance)
4. Build vocabulary from training set only (97 tokens), save as vocab.json
5. Tokenise: map each char to int index; unknown chars → 0
6. Pad/truncate to 1,024 (post-pad zeros, pre-truncate from end)
7. Stratified split: 70% train / 15% val / 15% test
8. Save as: X_train.npy, X_val.npy, X_test.npy, y_train.npy, y_val.npy, y_test.npy
9. Compute and save class_weights.json

---

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS events (
    event_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT NOT NULL,
    source_ip         TEXT,
    http_method       TEXT,
    request_uri       TEXT,
    classification    INTEGER NOT NULL,   -- 0=legitimate, 1=malicious
    confidence_score  REAL NOT NULL,
    attack_type       TEXT,
    action_taken      TEXT NOT NULL,      -- 'ALLOWED' or 'BLOCKED'
    payload_fragment  TEXT
);

CREATE INDEX IF NOT EXISTS idx_timestamp      ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_classification ON events(classification);
```

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /api/auth/login | No | Returns JWT |
| GET | /api/stats/summary | Yes | Total/blocked/allowed counts + detection rate |
| GET | /api/stats/traffic | Yes | Time-series request volume by classification |
| GET | /api/stats/attacks | Yes | Attack frequency by type |
| GET | /api/events | Yes | Paginated, filterable event log |
| GET | /api/events/{id} | Yes | Single event detail |

Query params for /api/events: page, page_size, classification, attack_type,
start_time, end_time, source_ip

---

## Evaluation Outputs Required (for Chapter 5)
The following must be recorded and saved in model/results/:

**Per model (LSTM and CNN):**
- accuracy, precision, recall, f1_score, false_positive_rate (test set)
- confusion matrix (as PNG)
- training loss curve (as PNG)
- validation loss curve (as PNG)
- mean inference latency (ms), p95 latency (ms), p99 latency (ms)

**ModSecurity baseline (same test set):**
- accuracy, precision, recall, f1_score, false_positive_rate

**Saved as:** model/results/lstm_metrics.json, cnn_metrics.json,
modsecurity_metrics.json, latency_results.json

---

## Critical Rules
- Never use Axios in the frontend — use native Fetch only
- Never use useState + useEffect for server data — use TanStack Query useQuery
- Never hardcode credentials — use config.py / .env
- Never load the model on every request — load once at startup, hold in memory
- Always use parameterised queries for SQLite — never string interpolation
- WAL mode must be enabled on the SQLite connection
- All dashboard API routes require JWT Bearer token in Authorization header
- Fail-open on inference errors: forward request, log error, never crash the WAF
- Classification threshold is 0.5 — externalise in config.py
- Use Shadcn components heavily, include tables, forms, charts etc

---

## Build Order
1. data/preprocess.py  → verify output .npy files exist
2. model/train_lstm.py → verify saved checkpoint + metrics
3. model/train_cnn.py  → verify saved checkpoint + metrics
4. model/evaluate.py   → verify metrics JSON files written
5. backend/            → verify WAF starts and classifies a test request
6. frontend/           → verify dashboard renders with live data
7. evaluation/         → verify ModSecurity metrics JSON written
