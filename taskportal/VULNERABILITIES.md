# TaskPortal — Intentional Vulnerabilities & Attack Map

This app is **deliberately insecure**. Every flaw below is planted so you can
run the SOC cycle: **Attack → Detect → Investigate → Report → Fix → Retest**.
Each one is tagged in `app.py` with a matching `V#` comment.

Login accounts (all weak on purpose):

| Username    | Password    | Role     | Who they are            |
|-------------|-------------|----------|-------------------------|
| `admin`     | `admin123`  | manager  | Hospital Administrator  |
| `jchen`     | `Password1` | employee | Dr. Jane Chen           |
| `rsingh`    | `letmein`   | employee | Nurse Raj Singh         |
| `itsupport` | `changeme`  | it       | Sam Osei (IT)           |

---

### V1 — SQL Injection (login bypass)
- **Where:** `login()` builds the auth query with an f-string.
- **Attack:** username `admin' -- ` with any password logs you in as admin.
  Also try `' OR '1'='1` in either field.
- **MITRE:** T1190 Exploit Public-Facing Application.
- **Log to detect:** `login_success` immediately after `login_failed` bursts, or
  a `login_success` whose `username` field contains quotes/`--`/`OR`.
- **Fix:** use a parameterised query (`db.execute("... WHERE username=? AND password=?", (u, p))`).

### V2 — No brute-force protection
- **Where:** `login()` has no lockout, delay, or rate limit.
- **Attack:** `hydra` / a Python loop against `/login`.
- **MITRE:** T1110 Brute Force.
- **Log to detect:** many `login_failed` from one IP in a short window → Wazuh
  rule with a frequency threshold.
- **Fix:** lockout after N failures, add a delay, log + alert on threshold.

### V3 — IDOR (read) & V3b — Broken object-level auth (write)
- **Where:** `/tasks?user_id=<id>` trusts the query string; `/tasks/<id>/complete`
  never checks the task is yours.
- **Attack:** `/tasks?user_id=3` to read another clinician's tasks; POST to
  `/tasks/99/complete` to close someone else's task.
- **MITRE:** T1083 File & Directory Discovery / T1565 Data Manipulation.
- **Log to detect:** a user hitting `/tasks` with a `user_id` that isn't theirs;
  `task_completed` on a task not assigned to that user.
- **Fix:** ignore client-supplied `user_id`; verify ownership before any write.

### V4 — Broken access control on File X
- **Where:** `/filex` uses `@login_required` but never checks `role == 'it'`.
- **Attack:** log in as any user and browse to `/filex` — the sensitive export
  (patient PII, leftover creds) is served.
- **MITRE:** T1005 Data from Local System / T1552 Unsecured Credentials.
- **Log to detect:** `filex_accessed` by a `role` other than `it`.
- **Fix:** change the decorator to `@role_required('it')`.

### V5 — Privilege escalation via leftover dev route
- **Where:** `/setrole/<role>` sets your session role with no auth at all.
- **Attack:** `/setrole/manager` as a nurse, then open `/admin`.
- **MITRE:** T1068 Privilege Escalation.
- **Log to detect:** `role_self_assigned` (should never happen in normal use).
- **Fix:** delete the route entirely.

### V6 — Weak secret & plaintext passwords
- **Where:** hardcoded `app.secret_key`; passwords stored in cleartext.
- **MITRE:** T1552 Unsecured Credentials / T1003 Credential Dumping.
- **Log to detect:** N/A at app layer — this is a code/config review finding,
  and a File X read (V4) exposes the leftover creds.
- **Fix:** random secret from env; hash passwords (e.g. `werkzeug` `generate_password_hash`).

### V7 — Debug mode / verbose errors
- **Where:** `app.run(debug=True)` — the Werkzeug debugger exposes a console.
- **MITRE:** T1190 / T1059 Command Execution (if the console PIN is bypassed).
- **Log to detect:** stack traces / `/console` requests in the web server log.
- **Fix:** `debug=False` in anything network-reachable.

---

## Suggested run order for a demo
1. Recon: browse the site, note roles and the nav differences.
2. Brute force `/login` (V2), then bypass with SQLi (V1).
3. Escalate with `/setrole/manager` (V5).
4. Pull File X (V4) and read another clinician's tasks (V3).
5. Show the events landing in **IT Panel → System logs** and in `app.log`.
6. Point Wazuh at `app.log`, write rules for each `action`, map to MITRE.
7. Apply the fixes above, restart, and re-run steps 2–4 to confirm they fail.
