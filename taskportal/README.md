# TaskPortal — Wazuh SOC Detection Lab (hospital scenario)

A deliberately vulnerable Flask task portal for a hospital, built as the attack
surface for a SOC detection lab. Three roles:

- **Employee** (doctor / nurse) — sees only their own patients and daily tasks.
- **Manager** (hospital administrator) — manages staff, patients, assignments, tasks.
- **IT** — support tickets + the system log stream. No clinical data access.

The point of the project: simulate an attack, detect it in Wazuh, investigate,
report, fix, and re-attack. See `VULNERABILITIES.md` for the full attack map.

## Run it

```bash
cd taskportal
pip install flask
python init_db.py     # build/reset taskportal.db with sample data
python app.py         # serves on http://127.0.0.1:5000  (0.0.0.0 for the lab network)
```

Log in with any account from the table in `VULNERABILITIES.md`
(e.g. `jchen` / `Password1`).

Reset the lab to a clean state at any time by re-running `python init_db.py`.

## Structure

```
taskportal/
├── app.py               # routes, auth, and the planted vulnerabilities (tagged V1–V7)
├── init_db.py           # creates + seeds the SQLite DB
├── schema.sql           # DB schema (users, patients, tasks, file_x, logs)
├── taskportal.db        # generated
├── app.log              # flat audit log — point the Wazuh agent here
├── static/style.css
├── templates/
│   ├── base.html        # shared layout + role-aware nav
│   ├── login.html
│   ├── dashboard.html   # one dynamic dashboard, branches by role
│   ├── tasks.html
│   ├── admin.html
│   ├── it.html
│   ├── filex.html
│   └── error.html
├── VULNERABILITIES.md   # attack map + MITRE mapping + fixes
└── README.md
```

## Logging for Wazuh

Every meaningful action is written to both the `logs` DB table and `app.log`
in a fixed, parseable format:

```
<iso-timestamp> | user=<name> | role=<role> | ip=<ip> | action=<action> | details=<...>
```

Actions worth alerting on: `login_failed`, `access_denied`, `role_self_assigned`,
`filex_accessed`. Point your Wazuh agent's `localfile` config at `app.log` and
write decoders/rules against the `action=` field.
