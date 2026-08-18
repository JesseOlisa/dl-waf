# DL-WAF Live Demo — Quick Start

## How to run

```bash
# 1. From the project root (dl-waf/)
uvicorn backend.main:app --reload --port 8000

# 2. Open the demo page
http://localhost:8000/demo

# 3. Open the admin dashboard (optional — shows live updates)
http://localhost:3000

# 4. Place both browser windows side-by-side
```

## Demo flow (≈ 2 minutes)

| Step | Action | Expected result |
|------|--------|-----------------|
| 1 | Click **Normal Login** | Raw request shows a clean POST body. Submit → ✅ green banner. |
| 2 | Click **SQL Injection** | Raw request shows `admin' OR '1'='1' --`. Submit → 🚨 red banner, SQL_INJECTION. |
| 3 | Click **XSS Attack** | Raw request shows `<script>alert('XSS')</script>`. Submit → 🚨 red banner, XSS. |
| 4 | Watch live log | Panel updates every 3 s — all 3 rows appear (green / red / red). |
| 5 | Switch to dashboard | Total requests +3, attack breakdown updated in real time. |

## What happens under the hood

1. The form POSTs to `/demo/login` on the FastAPI backend.
2. The backend calls `inference.classify()` — the **real** LSTM model performs inference.
3. The result (label + confidence score) is returned in JSON **and** logged to SQLite.
4. The dashboard reads from the same SQLite database, so it updates live.
5. The `/demo/status` endpoint is polled every 3 s by the demo page for the live log.

## Notes

- No internet connection required — all styles are inline in `demo/demo.html`.
- The WAF middleware skips `/demo/*` paths so the proxy step is bypassed; inference
  is invoked directly inside the demo route instead.
- Every request appears in the main dashboard's event log and statistics.
