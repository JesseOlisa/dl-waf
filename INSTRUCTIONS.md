# DL-WAF Build Instructions for Claude Code

## Context
This is the software component of an MSc thesis at AE-FUNAI, Nigeria.
The thesis is titled: "Design and Implementation of a Deep Learning-Enabled
Web Application Firewall for Intelligent Detection and Prevention of Web Attacks."

The system has already been fully designed in the thesis (Chapter 3) and the
methodology has been documented (Chapter 4). This file is the implementation
brief. Build exactly what is described — do not deviate from the specifications
in CLAUDE.md.

---

## Before You Begin — Checklist

Before writing any code, confirm the following with the user:

1. Is the CSIC 2010 dataset downloaded and placed in `data/raw/`?
   - The dataset must be at: https://www.isi.csic.es/dataset/
   - Expected files: normalTrafficTraining.txt, normalTrafficTest.txt,
     anomalousTrafficTest.txt (or equivalent .csv/.arff files)
   - Do NOT proceed to preprocessing until the user confirms this.

2. Is Python 3.11+ installed?
3. Is Node.js 18+ installed?

---

## Phase 1 — Data Preprocessing

**File to create:** `data/preprocess.py`

### What it must do:
1. Detect and load whatever file format the CSIC 2010 dataset uses
   (inspect the raw files first before assuming format)
2. Parse each HTTP request — preserve the full raw structure:
   request line + headers + body
3. Assign binary labels: 0 = legitimate, 1 = malicious
4. Serialise each request into a single string:
   - Concatenate: request_line + '\n' + method + '\n' + uri + '\n' +
     content_type + '\n' + user_agent + '\n' + cookie + '\n' + body
   - Skip headers that carry no payload signal (Host, Accept-Encoding, etc.)
5. Build vocabulary from training set only:
   - 95 printable ASCII chars (codes 32–126) + newline + padding token (index 0)
   - Total: 97 tokens
   - Save vocabulary mapping as data/processed/vocab.json
6. Tokenise each serialised string using the vocabulary
   - Unknown characters → index 0
7. Pad (post-pad) or truncate (from end) to fixed length of 1,024
8. Stratified split: 70% train / 15% validation / 15% test
9. Save outputs to data/processed/:
   - X_train.npy, X_val.npy, X_test.npy
   - y_train.npy, y_val.npy, y_test.npy
   - vocab.json
   - class_weights.json  ← computed from training set only
   - dataset_stats.json  ← record total counts, split sizes, class distribution
10. Print a summary to console: total records, split sizes, class distribution,
    sequence length distribution (min, mean, p95, max)

### Verification step:
After running preprocess.py, confirm with the user:
- All .npy files exist in data/processed/
- dataset_stats.json shows expected counts
- Ask user to share the printed summary before proceeding to Phase 2

---

## Phase 2 — LSTM Model Training

**File to create:** `model/train_lstm.py`

### Architecture (exact — do not modify):
```python
model = Sequential([
    Embedding(input_dim=97, output_dim=64, input_length=1024),
    LSTM(128, return_sequences=True),
    Dropout(0.3),
    LSTM(64, return_sequences=False),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])
```

### Training configuration:
- Optimiser: Adam(learning_rate=0.001)
- Loss: binary_crossentropy
- Metrics: accuracy
- Batch size: 64
- Max epochs: 50
- Callbacks:
  - EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
  - ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3)
  - ModelCheckpoint: save best model by val_loss to model/saved/lstm_best.keras
- Class weights: load from data/processed/class_weights.json

### Outputs to save in model/results/:
- lstm_training_history.json  ← epoch-by-epoch loss and accuracy
- lstm_train_curve.png        ← training vs validation loss plot
- lstm_metrics.json           ← test set: accuracy, precision, recall,
                                 f1_score, false_positive_rate, confusion matrix values

### Evaluation on test set:
Use threshold 0.5 on sigmoid output.
Compute: accuracy, precision, recall, f1_score, false_positive_rate
Print full classification report and confusion matrix to console.
Save confusion matrix as lstm_confusion_matrix.png

---

## Phase 3 — CNN Model Training

**File to create:** `model/train_cnn.py`

### Architecture (exact — do not modify):
```python
model = Sequential([
    Embedding(input_dim=97, output_dim=64, input_length=1024),
    Conv1D(filters=64, kernel_size=5, activation='relu'),
    MaxPooling1D(pool_size=2),
    Conv1D(filters=128, kernel_size=3, activation='relu'),
    GlobalMaxPooling1D(),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])
```

### Training configuration:
Identical to LSTM training configuration above.
Save best model to model/saved/cnn_best.keras
Save outputs to model/results/ with prefix cnn_*

---

## Phase 4 — Model Comparison

**File to create:** `model/evaluate.py`

### What it must do:
1. Load both saved models (lstm_best.keras and cnn_best.keras)
2. Load X_test.npy and y_test.npy
3. Run inference on the full test set for each model
4. Compute all five metrics for each model:
   accuracy, precision, recall, f1_score, false_positive_rate
5. Measure inference latency:
   - Submit 1,000 requests sequentially (warm-up 100 first, exclude from timing)
   - Record mean, p95, p99 latency per request in milliseconds
   - Use time.perf_counter()
6. Print a side-by-side comparison table
7. Save model/results/comparison_table.json with both models' metrics
8. Save model/results/latency_results.json

### Selection output:
Print which model wins based on F1-score + false_positive_rate
and record the winner in model/results/selected_model.json:
{ "selected": "lstm" or "cnn", "reason": "..." }

---

## Phase 5 — WAF Backend

**Directory:** `backend/`

### Files to create:
- requirements.txt
- config.py          ← all configurable values (model path, DB path, threshold,
                       JWT secret, token expiry, protected app URL)
- database.py        ← SQLite connection, WAL mode, table creation, insert/query helpers
- inference.py       ← load model + vocab at startup, preprocess function, predict function
- schemas.py         ← Pydantic models for API requests/responses
- main.py            ← FastAPI app, middleware registration, startup event
- middleware.py      ← WAF interception middleware
- routes/auth.py     ← POST /api/auth/login
- routes/stats.py    ← GET /api/stats/summary, /traffic, /attacks
- routes/events.py   ← GET /api/events, /api/events/{id}

### Middleware logic (middleware.py):
```
for every request:
  1. extract: method, url, headers, body
  2. call preprocess(request) → input tensor
  3. call predict(tensor) → probability score
  4. if score >= 0.5:
       log_event(result=1, action='BLOCKED')
       return Response(status_code=403, content='Forbidden')
  5. else:
       log_event(result=0, action='ALLOWED')
       forward request to PROTECTED_APP_URL via HTTPX
       return upstream response
  6. on any exception:
       log error
       forward request (fail-open)
       return upstream response
```

### WAF startup (main.py):
- Load model and vocab ONCE at startup using @app.on_event("startup")
- Store in app.state so middleware can access without reloading
- Create SQLite tables if they do not exist
- Enable WAL mode: PRAGMA journal_mode=WAL

### JWT Authentication:
- POST /api/auth/login accepts { username, password }
- Password verified against bcrypt hash stored in config or a users table
- Returns { access_token, token_type: "bearer" }
- All /api/* routes (except /api/auth/login) require Authorization: Bearer <token>
- Use a FastAPI Depends() function for JWT verification

### requirements.txt must include:
```
fastapi
uvicorn[standard]
httpx
tensorflow
numpy
python-jose[cryptography]
passlib[bcrypt]
pydantic
python-multipart
```

### Verification step:
After building the backend:
1. Run: uvicorn backend.main:app --reload
2. Test with a sample malicious request (SQL injection in query param)
3. Confirm: 403 returned, event logged in SQLite
4. Test with a normal request: confirm forwarded, event logged
5. Show the user the console output before proceeding to Phase 6

---

## Phase 6 — Dashboard Frontend

**Directory:** `frontend/`

### Setup:
```bash
npx create-next-app@latest frontend --typescript --tailwind --app --no-src-dir
cd frontend
npm install @tanstack/react-query recharts
```

### Files to create:

**lib/api.ts**
- All fetch query functions (no Axios)
- Each function: takes optional params, attaches JWT from sessionStorage,
  calls the appropriate backend endpoint, returns parsed JSON
- Functions: fetchSummary(), fetchTraffic(window), fetchAttacks(),
  fetchEvents(filters), fetchEventById(id)

**lib/auth.ts**
- login(username, password): calls /api/auth/login, stores token in sessionStorage
- logout(): clears sessionStorage, redirects to /login
- getToken(): returns stored token or null
- isAuthenticated(): returns boolean

**hooks/useDashboard.ts**
- useQuery hooks wrapping each api.ts function
- refetchInterval: 10000 (10 seconds) for live panels
- Global error handler in QueryClient: on 401, call logout()

**app/login/page.tsx**
- Simple login form
- On submit: calls auth.login(), on success redirect to /dashboard

**app/dashboard/page.tsx**
- Protected route: redirect to /login if not authenticated
- Renders four panels in a responsive grid

**components/SummaryCards.tsx**
- Four stat cards: Total Requests, Blocked, Allowed, Detection Rate %
- Data from useQuery → fetchSummary()

**components/TrafficChart.tsx**
- Recharts LineChart
- Two lines: legitimate traffic (green) and attack traffic (red)
- Time window selector: Last Hour / Last 24h / Last 7 Days
- Data from useQuery → fetchTraffic(window)

**components/AttackDistribution.tsx**
- Recharts BarChart
- X-axis: attack types, Y-axis: count
- Data from useQuery → fetchAttacks()

**components/EventLog.tsx**
- Table with columns: Timestamp, Method, URI, Classification, Confidence, Attack Type, Action
- Pagination controls
- Filter inputs: classification (All/Blocked/Allowed), attack type, date range
- Data from useQuery → fetchEvents(filters)

### Verification step:
1. Run: npm run dev
2. Navigate to http://localhost:3000
3. Log in with admin credentials
4. Confirm all four panels render and update every 10 seconds
5. Show user a screenshot before proceeding to Phase 7

---

## Phase 7 — ModSecurity Evaluation

**File to create:** `evaluation/modsecurity_eval.py`

### What it must do:
1. Check that ModSecurity + OWASP CRS is installed (provide installation
   instructions if not)
2. Start a lightweight Python HTTP test server on a configurable port
3. Configure ModSecurity to sit in front of it at paranoia level 1
4. Replay all requests from X_test.npy + y_test.npy through the
   ModSecurity-protected server one by one
5. Parse ModSecurity's audit log to extract allow/block decision per request
6. Compare decisions against ground truth labels
7. Compute: accuracy, precision, recall, f1_score, false_positive_rate
8. Save to evaluation/results/modsecurity_metrics.json
9. Print results to console

**File to create:** `evaluation/compare_results.py`
- Load: lstm_metrics.json, cnn_metrics.json, modsecurity_metrics.json
- Print a formatted comparison table: all five metrics for all three systems
- Identify best system per metric
- Save comparison table as evaluation/results/final_comparison.json

---

## Final Deliverables — What the Student Needs for Chapter 5

After all phases are complete, the following files must exist:

```
model/results/
├── lstm_metrics.json
├── lstm_confusion_matrix.png
├── lstm_train_curve.png
├── cnn_metrics.json
├── cnn_confusion_matrix.png
├── cnn_train_curve.png
├── comparison_table.json
├── latency_results.json
└── selected_model.json

evaluation/results/
├── modsecurity_metrics.json
└── final_comparison.json
```

These files contain the real experimental data needed to write Chapter 5 of the thesis.

---

## Important Rules — Always Follow

1. **Ask before assuming** — if dataset file format is unclear, inspect first and ask
2. **One phase at a time** — complete and verify each phase before starting the next
3. **Never modify the model architecture** — it is fixed by the thesis design
4. **Never use Axios** — Fetch API only in the frontend
5. **Never use useState/useEffect for server data** — TanStack Query only
6. **Never load the model on every request** — startup only, hold in app.state
7. **Always use parameterised SQL** — never string concatenation
8. **Save every metric** — Chapter 5 depends on these real numbers
9. **Print clear progress** — student needs to see what is happening at each step
10. **Fail-open on WAF errors** — never let an exception crash the WAF or block
    legitimate traffic silently
