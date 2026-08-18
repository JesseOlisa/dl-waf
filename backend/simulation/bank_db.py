"""
Sandboxed, deliberately-vulnerable bank datastore for the attack simulation.

SECURITY BOUNDARY: everything here operates on a THROWAWAY sqlite file
(``bank.db``) that lives beside this module and holds only fake data. It is
NEVER the WAF's own ``waf.db`` and never touches real information. Exploit
payloads (DROP/UPDATE/defacement) can only ever damage this file, and
``reset()`` rebuilds it from scratch. The path is a hardcoded module constant
so it cannot be repointed at a real database.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Hardcoded — do not make this configurable.
BANK_DB_PATH = Path(__file__).resolve().parent / "bank.db"

# A "live" admin session token that cookie-theft / stored-XSS scenarios exfiltrate.
ADMIN_SESSION_TOKEN = "sess_9f2c1ab7e4d8_admin_STB"

# Pristine homepage HTML that defacement scenarios overwrite; reset restores it.
_PRISTINE_HOMEPAGE = (
    "<div class='stb-home'><h1>Sterling Trust Bank</h1>"
    "<p>Welcome to secure online banking.</p></div>"
)

# ── Seed data — fictional Nigerian bank customers ──────────────────────────────
_CUSTOMERS = [
    # full_name, email, phone, bvn, address, state
    ("Chinedu Okafor",     "chinedu.okafor@gmail.com",   "+2348031234501", "22181500901", "14 Awolowo Rd",       "Lagos"),
    ("Aisha Bello",        "aisha.bello@yahoo.com",      "+2348062345602", "22181500902", "9 Ahmadu Bello Way",  "Abuja"),
    ("Emeka Nwosu",        "emeka.nwosu@gmail.com",      "+2348073456703", "22181500903", "3 Ogui Rd",           "Enugu"),
    ("Funmilayo Adeyemi",  "funmi.adeyemi@outlook.com",  "+2348084567804", "22181500904", "27 Ring Rd",          "Oyo"),
    ("Ibrahim Musa",       "ibrahim.musa@gmail.com",     "+2348095678905", "22181500905", "5 Murtala Way",       "Kano"),
    ("Ngozi Eze",          "ngozi.eze@gmail.com",        "+2348106789006", "22181500906", "18 Zik Ave",          "Anambra"),
    ("Tunde Bakare",       "tunde.bakare@yahoo.com",     "+2348117890107", "22181500907", "2 Marina",            "Lagos"),
    ("Halima Sani",        "halima.sani@gmail.com",      "+2348128901208", "22181500908", "11 Yakubu Gowon Cr",  "Kaduna"),
    # Index 8 — mule/attacker account funds get diverted to (starts empty).
    ("Kelvin Malore",      "k.malore@protonmail.com",    "+2347000000000", "00000000000", "Unknown",             "—"),
]

# Account number funds are fraudulently diverted to in the theft scenario.
ATTACKER_ACCOUNT_NO = "9099000111"

# customer_index (0-based), account_no, account_type, balance (NGN)
_ACCOUNTS = [
    (0, "0123456701", "Savings",  842500.75),
    (0, "0123456702", "Current", 1560000.00),
    (1, "0123456703", "Savings",  237800.50),
    (2, "0123456704", "Current", 4920000.00),
    (3, "0123456705", "Savings",   58900.25),
    (4, "0123456706", "Current", 12750000.00),
    (5, "0123456707", "Savings",  333100.00),
    (6, "0123456708", "Current",  899450.90),
    (7, "0123456709", "Savings",  145600.00),
    (8, ATTACKER_ACCOUNT_NO, "Current", 0.00),  # attacker mule account
]

# account_index (0-based into _ACCOUNTS), description, amount, direction
_TRANSACTIONS = [
    (0, "POS purchase — Shoprite Ikeja",       -18500.00, "debit"),
    (0, "Salary — Dangote Group",              450000.00, "credit"),
    (1, "Transfer to 0123456704",             -250000.00, "debit"),
    (3, "Inflow — GTBank",                      920000.00, "credit"),
    (5, "Airtime — MTN",                         -5000.00, "debit"),
    (5, "Contract payment — NNPC",             3200000.00, "credit"),
    (7, "ATM withdrawal — Lagos",               -40000.00, "debit"),
]

# username, password, role
_USERS = [
    ("admin",         "Str0ngAdminP@ss",  "admin"),
    ("chinedu.okafor", "chinedu2024",     "customer"),
    ("aisha.bello",    "aisha2024",       "customer"),
]


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(BANK_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def seed() -> str:
    """Build (or fully rebuild) the vulnerable bank database from scratch."""
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            DROP TABLE IF EXISTS customers;
            DROP TABLE IF EXISTS accounts;
            DROP TABLE IF EXISTS transactions;
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS sessions;
            DROP TABLE IF EXISTS messages;
            DROP TABLE IF EXISTS defacement;

            CREATE TABLE customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT, email TEXT, phone TEXT,
                bvn TEXT, address TEXT, state TEXT
            );
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER,
                account_no TEXT, account_type TEXT,
                balance REAL, currency TEXT DEFAULT 'NGN'
            );
            CREATE TABLE transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER, ts TEXT,
                description TEXT, amount REAL, direction TEXT
            );
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT, password TEXT, role TEXT
            );
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT, session_token TEXT, created_at TEXT
            );
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author TEXT, body TEXT, created_at TEXT
            );
            CREATE TABLE defacement (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                page TEXT, html TEXT
            );
            """
        )

        cur.executemany(
            "INSERT INTO customers (full_name,email,phone,bvn,address,state) VALUES (?,?,?,?,?,?)",
            _CUSTOMERS,
        )
        cur.executemany(
            "INSERT INTO accounts (customer_id,account_no,account_type,balance) VALUES (?,?,?,?)",
            [(c + 1, no, typ, bal) for (c, no, typ, bal) in _ACCOUNTS],
        )
        cur.executemany(
            "INSERT INTO transactions (account_id,ts,description,amount,direction) VALUES (?,?,?,?,?)",
            [(a + 1, _now(), desc, amt, d) for (a, desc, amt, d) in _TRANSACTIONS],
        )
        cur.executemany(
            "INSERT INTO users (username,password,role) VALUES (?,?,?)",
            _USERS,
        )
        cur.execute(
            "INSERT INTO sessions (username,session_token,created_at) VALUES (?,?,?)",
            ("admin", ADMIN_SESSION_TOKEN, _now()),
        )
        cur.execute(
            "INSERT INTO defacement (id,page,html) VALUES (1,'home',?)",
            (_PRISTINE_HOMEPAGE,),
        )
        conn.commit()
        return _now()
    finally:
        conn.close()


def reset() -> str:
    """Alias for seed() — restores dropped tables / undoes defacement."""
    return seed()


def ensure_seeded() -> None:
    """Seed on first run (or if a scenario dropped a core table)."""
    if not BANK_DB_PATH.exists():
        seed()
        return
    conn = _connect()
    try:
        try:
            conn.execute("SELECT 1 FROM customers LIMIT 1")
            conn.execute("SELECT 1 FROM accounts LIMIT 1")
        except sqlite3.OperationalError:
            conn.close()
            seed()
    finally:
        try:
            conn.close()
        except Exception:
            pass
