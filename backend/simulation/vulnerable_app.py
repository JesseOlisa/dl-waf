"""
Deliberately vulnerable banking operations — the "victim" application.

Every function here is INSECURE ON PURPOSE (string-interpolated SQL, unescaped
HTML) so that, when the WAF lets a payload through, the attack genuinely
executes and produces a real consequence to show the examiners. These run only
against the sandboxed ``bank.db`` (see bank_db.py) and are reachable only via
the authenticated ``/api/sim/run`` endpoint — never as a live network surface.
"""

import sqlite3
from urllib.parse import unquote

from backend.simulation import bank_db


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(bank_db.BANK_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _consequence(kind, title, **kw):
    return {"kind": kind, "title": title, **kw}


# ── SQL injection sinks ────────────────────────────────────────────────────────

def vuln_login(username: str, password: str) -> dict:
    """Authentication with string-interpolated SQL (SQLi L1 / L5 sink)."""
    sql = (
        "SELECT username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    conn = _connect()
    try:
        rows = conn.execute(sql).fetchall()
    finally:
        conn.close()

    if not rows:
        return _consequence(
            "none", "Login failed",
            summary="Credentials rejected — no matching user.",
            detail=sql,
            detail_label="Executed query",
        )
    admin_hit = any(r["role"] == "admin" for r in rows)
    return _consequence(
        "rows",
        "Authentication bypassed" if admin_hit else "Logged in",
        summary=(
            f"Injected SQL returned {len(rows)} user row(s) with no valid password — "
            "attacker is now authenticated"
            + (" as ADMIN." if admin_hit else ".")
        ),
        columns=["username", "role"],
        rows=[[r["username"], r["role"]] for r in rows],
        detail=sql,
        detail_label="Executed query",
    )


def vuln_account_lookup(term: str, benign: bool = False) -> dict:
    """
    Account search with interpolated SQL — UNION-injectable (SQLi L2 sink).

    ``benign=True`` is the legitimate baseline: the same vulnerable statement is
    built and run, but the search term is an ordinary account number, so the
    result is reported as a normal lookup rather than a breach. Running it keeps
    the executed query visible for side-by-side comparison with the injected one.
    """
    sql = (
        "SELECT a.account_no, a.account_type, c.bvn "
        "FROM accounts a JOIN customers c ON c.id = a.customer_id "
        f"WHERE a.account_no LIKE '%{term}%'"
    )
    conn = _connect()
    try:
        cur = conn.execute(sql)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    finally:
        conn.close()
    if benign:
        return _consequence(
            "rows",
            "Account search completed",
            severity="benign",
            summary=(
                f"A normal staff lookup. The term stayed inside the quoted LIKE "
                f"clause, so the query returned {len(rows)} matching account row(s)."
            ),
            columns=cols,
            rows=[list(r) for r in rows],
            detail=sql,
            detail_label="Executed query",
        )
    return _consequence(
        "rows",
        "Customer data exfiltrated",
        summary=(
            f"UNION-based injection returned {len(rows)} row(s). The term broke out "
            "of the LIKE clause and appended a UNION, so the query now returns every "
            "customer's name, email and BVN instead of one account."
        ),
        columns=cols,
        rows=[list(r) for r in rows],
        detail=sql,
        detail_label="Executed query",
    )


def vuln_blind_password(_payload: str) -> dict:
    """
    Blind boolean SQLi (SQLi L3). Simulate the classic oracle: reconstruct the
    admin password one character at a time using boolean sub-queries that each
    return a row (true) or nothing (false). This mirrors what sqlmap automates.
    """
    conn = _connect()
    recovered = ""
    queries_sent = 0
    try:
        # Length probe (bounded).
        length = 0
        for n in range(1, 41):
            q = f"SELECT 1 FROM users WHERE username='admin' AND length(password)={n}"
            queries_sent += 1
            if conn.execute(q).fetchone():
                length = n
                break
        # Character-by-character extraction over the printable ASCII range.
        for pos in range(1, length + 1):
            for code in range(32, 127):
                q = (
                    "SELECT 1 FROM users WHERE username='admin' AND "
                    f"unicode(substr(password,{pos},1))={code}"
                )
                queries_sent += 1
                if conn.execute(q).fetchone():
                    recovered += chr(code)
                    break
    finally:
        conn.close()
    return _consequence(
        "boolean_leak",
        "Admin password recovered (blind SQLi)",
        summary=(
            f"Sent {queries_sent} boolean queries; each true/false response leaked "
            "one bit of the secret. Full admin password reconstructed:"
        ),
        detail=recovered,
    )


def vuln_destructive(payload: str) -> dict:
    """
    Stacked-query SQLi (SQLi L4). sqlite3.execute() refuses multiple statements,
    so we use executescript() to actually fire the stacked UPDATE/DROP.
    """
    # Balance snapshot before.
    conn = _connect()
    try:
        before = conn.execute(
            "SELECT COUNT(*) c, COALESCE(SUM(balance),0) s FROM accounts"
        ).fetchone()
        n_accounts, total_before = before["c"], before["s"]

        # The attacker controls a value spliced straight into a statement; the
        # payload closes the string and appends its own stacked statements.
        script = f"UPDATE accounts SET account_type = account_type WHERE account_no = '{payload}';"
        conn.executescript(script)
        conn.commit()

        after = conn.execute(
            "SELECT COALESCE(SUM(balance),0) s FROM accounts"
        ).fetchone()
        total_after = after["s"]

        try:
            tx_left = conn.execute("SELECT COUNT(*) c FROM transactions").fetchone()["c"]
            tx_note = f"{tx_left} transaction rows remain"
        except sqlite3.OperationalError:
            tx_note = "transactions table DROPPED"
    finally:
        conn.close()

    return _consequence(
        "rows",
        "Records tampered / destroyed",
        summary=(
            f"Stacked query executed against {n_accounts} accounts. "
            f"Total balances: ₦{total_before:,.2f} → ₦{total_after:,.2f}. {tx_note}."
        ),
        columns=["metric", "before", "after"],
        rows=[
            ["Total balance (NGN)", f"{total_before:,.2f}", f"{total_after:,.2f}"],
            ["Transactions table", "intact", tx_note],
        ],
        detail=script,
        detail_label="Executed statements",
    )


# ── XSS sinks ──────────────────────────────────────────────────────────────────

def vuln_reflect(term: str) -> dict:
    """Reflected XSS (XSS L1 / L4) — the search term is echoed unescaped."""
    page = (
        "<div class='search-results'>"
        f"<h3>Results for: {term}</h3>"
        "<p>No accounts matched your query.</p></div>"
    )
    return _consequence(
        "defacement",
        "Reflected XSS — script executes in victim's browser",
        summary=(
            "The search term was reflected into the page without escaping. The "
            "browser parses the injected markup and runs the attacker's script."
        ),
        defaced_html=page,
        detail=term,
        detail_label="Injected markup",
    )


def vuln_transfer(source_account: str, beneficiary: str, amount: str) -> dict:
    """
    Funds transfer with interpolated, stacked-query-capable SQL (fund-theft sink).
    A malicious beneficiary field injects an extra UPDATE that credits the
    attacker's mule account. Uses executescript so stacked statements fire.
    """
    atk = bank_db.ATTACKER_ACCOUNT_NO
    conn = _connect()
    try:
        def balance(acc: str):
            row = conn.execute(
                f"SELECT balance FROM accounts WHERE account_no = '{acc}'"
            ).fetchone()
            return row["balance"] if row else None

        atk_before = balance(atk) or 0.0
        src_before = balance(source_account)

        # Deliberately vulnerable — beneficiary and amount are spliced straight in.
        script = (
            f"UPDATE accounts SET balance = balance - {amount} "
            f"WHERE account_no = '{source_account}';"
            f"UPDATE accounts SET balance = balance + {amount} "
            f"WHERE account_no = '{beneficiary}';"
        )
        conn.executescript(script)
        conn.commit()

        atk_after = balance(atk) or 0.0
    finally:
        conn.close()

    diverted = atk_after - atk_before
    if diverted > 0:
        return _consequence(
            "rows",
            "Funds stolen",
            summary=(
                f"An injected transfer diverted ₦{diverted:,.2f} to unknown account "
                f"{atk} (Kelvin Malore). The staff member believed they were making "
                "a routine transfer."
            ),
            columns=["Attacker account", "Holder", "Balance before", "Balance after"],
            rows=[[atk, "Kelvin Malore", f"₦{atk_before:,.2f}", f"₦{atk_after:,.2f}"]],
            detail=script,
            detail_label="Executed statements",
        )
    return _consequence(
        "none",
        "Transfer completed",
        summary=f"₦{amount} transfer to {beneficiary} processed normally.",
    )


def vuln_store_and_view(author: str, body: str) -> dict:
    """
    Stored XSS (XSS L2 / L3). The payload is saved raw into the support-ticket
    queue; when the admin opens the queue it "fires" and exfiltrates the admin's
    live session token. We surface the stolen token as the consequence.
    """
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO messages (author, body, created_at) VALUES (?,?,datetime('now'))",
            (author, body),
        )
        conn.commit()
        # Admin opens the queue: scan stored messages for active script/handlers.
        malicious = conn.execute(
            "SELECT COUNT(*) c FROM messages "
            "WHERE body LIKE '%<script%' OR body LIKE '%onerror%' "
            "OR body LIKE '%onload%' OR body LIKE '%<img%'"
        ).fetchone()["c"]
        token_row = conn.execute(
            "SELECT session_token FROM sessions WHERE username='admin'"
        ).fetchone()
    finally:
        conn.close()

    if not malicious or not token_row:
        return _consequence(
            "none", "Comment stored",
            summary="Message saved. Nothing fired.",
        )
    token = token_row["session_token"]
    return _consequence(
        "cookie",
        "Admin session hijacked (stored XSS)",
        summary=(
            "The stored payload executed when the administrator opened the support "
            "queue, exfiltrating their session cookie to the attacker."
        ),
        cookie=f"session={token}",
        detail=body,
        detail_label="Stored payload",
    )


def execute_op(op_name: str, fields: dict, benign: bool = False) -> dict:
    """
    Run the vulnerable op for a scenario. `fields` is the form's fields; values
    are URL-decoded first (GET payloads arrive percent-encoded on the wire, but
    the application decodes them before use — where the real vulnerability bites).

    `benign` marks the legitimate baseline, whose payload carries no injection;
    only read-only ops are dispatched in that mode.
    """
    f = {k: unquote(str(v)) for k, v in fields.items()}

    if benign:
        # Never run a mutating sink for a request we classified as legitimate.
        if op_name == "vuln_account_lookup":
            return vuln_account_lookup(f.get("q", ""), benign=True)
        return _consequence(
            "none", "Request served",
            summary="Legitimate request — handled normally.",
        )

    if op_name == "vuln_login":
        username = f.get("username") or next(iter(f.values()), "")
        return vuln_login(username, f.get("password", "x"))
    if op_name == "vuln_account_lookup":
        return vuln_account_lookup(f.get("q", ""))
    if op_name == "vuln_blind_password":
        return vuln_blind_password(f.get("q", ""))
    if op_name == "vuln_destructive":
        return vuln_destructive(f.get("account_no", ""))
    if op_name == "vuln_reflect":
        return vuln_reflect(f.get("q", ""))
    if op_name == "vuln_store_and_view":
        return vuln_store_and_view(f.get("author", "attacker@evil.test"), f.get("message", ""))
    if op_name == "vuln_transfer":
        return vuln_transfer(
            f.get("source_account", ""), f.get("beneficiary", ""), f.get("amount", "0")
        )
    return _consequence("none", "No-op", summary="Legitimate request — nothing executed.")
