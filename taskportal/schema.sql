-- TaskPortal schema
-- Matches the ERD in "Final Personal Project/ERD DB.docx", extended with a
-- `patients` table so the app can carry the hospital scenario (doctors/nurses
-- have patients with a condition and a last checkup date).

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,              -- intentionally plaintext, see VULNERABILITIES.md (V6)
    role TEXT NOT NULL CHECK(role IN ('employee', 'manager', 'it')),
    full_name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    dob TEXT,
    condition TEXT,
    last_checkup TEXT,
    assigned_doctor_id INTEGER,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (assigned_doctor_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    patient_id INTEGER,
    assigned_to INTEGER NOT NULL,
    created_by INTEGER NOT NULL,
    status TEXT DEFAULT 'open',          -- open | in_progress | completed
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Sensitive export, meant to be IT-only. Deliberately exposed — see V4.
CREATE TABLE IF NOT EXISTS file_x (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

-- App-level audit trail. Mirrored to app.log so Wazuh can tail it later.
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    timestamp TEXT DEFAULT (datetime('now')),
    details TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
