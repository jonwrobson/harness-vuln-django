# vulndjango — Intentionally-Vulnerable Django Test Fixture

WARNING: This is a **deliberately vulnerable** web application created solely as
a test target for a defensive security scanner (authorized security testing).
It contains real, exploitable security bugs by design. **Do NOT deploy this
application, expose it to a network, or run it against untrusted clients.**

## Setup

```bash
pip install -r requirements.txt
python manage.py migrate          # creates db.sqlite3 incl. the auth_user table
python manage.py runserver
```

## Planted Vulnerabilities

### (A) SCA — Vulnerable dependency reachable from a handler
- **Dependency:** `PyYAML==5.1`
- **CVE:** CVE-2020-1747 — `yaml.load()` with the default/unsafe Loader allows
  arbitrary code execution.
- **Endpoint:** `POST /api/config`
- **Sink:** `yaml.load(request.body)` in `core/views.py` (`config` view) — the
  attacker-controlled raw request body is passed to the unsafe loader.

### (B) CHAIN — SSRF flowing into insecure deserialization (RCE)
- **Endpoint:** `GET /api/proxy?url=<attacker-url>`
- **Step 1 (source, SSRF):** `requests.get(url)` in the `proxy` view fetches an
  attacker-controlled URL.
- **Step 2 (sink, insecure deserialization):** the fetched response bytes
  (`r.content`) flow into `_ingest()`, which calls `pickle.loads(content)`.
- **Dataflow:** attacker controls `url` → controls the fetched bytes → those
  bytes reach `pickle.loads`, yielding remote code execution.

### (C) NORMAL — SQL injection
- **Endpoint:** `GET /api/user?name=<value>`
- **Sink:** `cursor.execute("... WHERE username = '%s'" % name)` in the `user`
  view — request input is concatenated directly into the SQL string.

## Endpoint summary

| Vuln | Method | Path | Parameter |
|------|--------|------|-----------|
| A — SCA (PyYAML unsafe load) | POST | `/api/config` | request body (YAML) |
| B — CHAIN (SSRF → pickle RCE) | GET | `/api/proxy` | `url` |
| C — NORMAL (SQL injection) | GET | `/api/user` | `name` |
