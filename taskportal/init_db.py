"""
Builds taskportal.db from schema.sql and loads sample data.

Run this once before starting the app, and again any time you want to
reset the lab back to a clean state (e.g. after an attack run):

    python init_db.py
"""

import os
import sqlite3

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "taskportal.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())

    cur = conn.cursor()

    # --- Users -----------------------------------------------------------
    # Passwords are plaintext and weak on purpose (see VULNERABILITIES.md V6).
    cur.executemany(
        "INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)",
        [
            ("admin", "admin123", "manager", "Hospital Administrator"),
            ("jchen", "Password1", "employee", "Dr. Jane Chen"),
            ("rsingh", "letmein", "employee", "Nurse Raj Singh"),
            ("itsupport", "changeme", "it", "Sam Osei"),
        ],
    )
    cur.execute("SELECT id, username FROM users")
    uid = {username: id_ for id_, username in cur.fetchall()}

    # --- Patients ----------------------------------------------------------
    cur.executemany(
        "INSERT INTO patients (name, dob, condition, last_checkup, assigned_doctor_id) "
        "VALUES (?, ?, ?, ?, ?)",
        [
            ("Mary Wallace", "1985-03-12", "Type 2 Diabetes - stable", "2026-09-15", uid["jchen"]),
            ("Tom Reyes", "1972-11-02", "Post-op recovery - hip replacement", "2026-09-20", uid["jchen"]),
            ("Ella Osman", "1990-07-19", "Hypertension - monitoring", "2026-09-18", uid["rsingh"]),
            ("George Novak", "1968-01-30", "Pneumonia - respiratory therapy", "2026-09-21", uid["rsingh"]),
        ],
    )

    # --- Tasks (clinical tasks + a couple of IT "tickets") -----------------
    cur.executemany(
        "INSERT INTO tasks (title, description, patient_id, assigned_to, created_by, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("Check morning vitals", "Blood pressure + glucose check", 1, uid["jchen"], uid["admin"], "open"),
            ("Post-op wound check", "Inspect incision site, change dressing", 2, uid["jchen"], uid["admin"], "open"),
            ("Medication round", "Administer scheduled hypertension meds", 3, uid["rsingh"], uid["admin"], "open"),
            ("Respiratory therapy session", "Assist with nebulizer treatment", 4, uid["rsingh"], uid["admin"], "in_progress"),
            ("Fix Ward 3 vitals monitor", "Monitor in room 304 not powering on", None, uid["itsupport"], uid["jchen"], "open"),
            ("Reset password for nurse station PC", "Nurse Singh locked out", None, uid["itsupport"], uid["rsingh"], "completed"),
        ],
    )

    # --- File X: the sensitive export IT is meant to be the only one to see.
    # Synthetic data only — not real patient records.
    cur.execute(
        "INSERT INTO file_x (filename, content) VALUES (?, ?)",
        (
            "master_patient_export_2026.csv",
            "MRN,PatientName,DOB,Condition,InsuranceID,SSN(TEST),AttendingPhysician\n"
            "100234,Mary Wallace,1985-03-12,Type 2 Diabetes,INS-88213,000-11-2222,Dr. Jane Chen\n"
            "100235,Tom Reyes,1972-11-02,Post-op hip replacement,INS-44120,000-11-2223,Dr. Jane Chen\n"
            "100236,Ella Osman,1990-07-19,Hypertension,INS-90441,000-11-2224,Nurse Raj Singh\n"
            "100237,George Novak,1968-01-30,Pneumonia,INS-10233,000-11-2225,Nurse Raj Singh\n\n"
            "# Synthetic test data generated for the Wazuh SOC Detection Lab. Not real patient records.",
        ),
    )
    cur.execute(
        "INSERT INTO file_x (filename, content) VALUES (?, ?)",
        (
            "admin_notes.txt",
            "Reminder: temp admin password still set to admin123, change before go-live.\n"
            "Old backup DB creds (decommission this box): postgres / hospital2024\n",
        ),
    )

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")


if __name__ == "__main__":
    main()
