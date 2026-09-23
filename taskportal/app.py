import datetime
import os
from functools import wraps

from flask import Flask, request, redirect, url_for, session, g, flash, render_template

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "taskportal.db")
LOG_PATH = os.path.join(BASE_DIR, "app.log")

import sqlite3

app = Flask(__name__)

# --- V6: hardcoded, weak session secret. Anyone who reads this source (or
# guesses it) can forge a valid session cookie. See VULNERABILITIES.md. ---
app.secret_key = "taskportal-dev-2026"


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def log_action(action, details=""):
    """Write an audit event to the `logs` table AND to a flat file.
    The flat file is what Wazuh will tail once the agent is wired up."""
    user_id = session.get("user_id")
    username = session.get("username", "anonymous")
    role = session.get("role", "-")
    ip = request.remote_addr
    ts = datetime.datetime.utcnow().isoformat()

    db = get_db()
    db.execute(
        "INSERT INTO logs (user_id, action, timestamp, details) VALUES (?, ?, ?, ?)",
        (user_id, action, ts, details),
    )
    db.commit()

    line = f"{ts} | user={username} | role={role} | ip={ip} | action={action} | details={details}\n"
    with open(LOG_PATH, "a") as f:
        f.write(line)


# ---------------------------------------------------------------------------
# Access control helpers
# ---------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                log_action("access_denied", f"tried to reach {request.path}")
                return render_template("error.html", message="You don't have permission to view that page."), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # --- V1: SQL INJECTION. The query is built with an f-string
        # instead of a parameterised query, so input like
        #   ' OR '1'='1
        # in either field bypasses the check entirely. ---
        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            user = db.execute(query).fetchone()
        except sqlite3.OperationalError:
            user = None

        # --- V2: no lockout / rate limiting, so the login form is a clean
        # brute-force target (e.g. with hydra or a simple script). ---
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            log_action("login_success")
            return redirect(url_for("dashboard"))

        log_action("login_failed", f"username={username}")
        flash("Invalid username or password.")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    log_action("logout")
    session.clear()
    return redirect(url_for("login"))


# --- V5: PRIVILEGE ESCALATION. Leftover dev route with zero authentication —
# hitting this directly sets your session role to whatever you ask for. ---
@app.route("/setrole/<role>")
def setrole(role):
    session["role"] = role
    log_action("role_self_assigned", f"new_role={role}")
    return f"Role set to {role}. <a href='/dashboard'>Go to dashboard</a>"


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    role = session["role"]
    context = {}

    if role == "employee":
        patients = db.execute(
            "SELECT * FROM patients WHERE assigned_doctor_id = ?", (session["user_id"],)
        ).fetchall()
        tasks = db.execute(
            "SELECT * FROM tasks WHERE assigned_to = ? AND status != 'completed'",
            (session["user_id"],),
        ).fetchall()
        context = {"patients": patients, "tasks": tasks}

    elif role == "manager":
        patient_count = db.execute("SELECT COUNT(*) c FROM patients").fetchone()["c"]
        staff_count = db.execute("SELECT COUNT(*) c FROM users WHERE role='employee'").fetchone()["c"]
        open_tasks = db.execute("SELECT COUNT(*) c FROM tasks WHERE status != 'completed'").fetchone()["c"]
        context = {"patient_count": patient_count, "staff_count": staff_count, "open_tasks": open_tasks}

    elif role == "it":
        open_tickets = db.execute(
            "SELECT COUNT(*) c FROM tasks WHERE assigned_to = ? AND status != 'completed'",
            (session["user_id"],),
        ).fetchone()["c"]
        recent_logs = db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 5").fetchall()
        context = {"open_tickets": open_tickets, "recent_logs": recent_logs}

    return render_template("dashboard.html", role=role, **context)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

@app.route("/tasks")
@login_required
def tasks():
    db = get_db()
    role = session["role"]

    if role == "manager":
        all_tasks = db.execute(
            "SELECT tasks.*, u.full_name AS assignee, p.name AS patient_name "
            "FROM tasks JOIN users u ON tasks.assigned_to = u.id "
            "LEFT JOIN patients p ON tasks.patient_id = p.id "
            "ORDER BY tasks.created_at DESC"
        ).fetchall()
        staff = db.execute("SELECT * FROM users WHERE role='employee'").fetchall()
        patients = db.execute("SELECT * FROM patients").fetchall()
        return render_template("tasks.html", role=role, tasks=all_tasks, staff=staff, patients=patients)

    # --- V3: IDOR. `user_id` is taken straight from the query string with no
    # check that it belongs to the person asking — any logged-in user can
    # read anyone else's task list via /tasks?user_id=<id>. ---
    target_user_id = request.args.get("user_id", session["user_id"])
    my_tasks = db.execute(
        "SELECT tasks.*, p.name AS patient_name FROM tasks "
        "LEFT JOIN patients p ON tasks.patient_id = p.id "
        "WHERE assigned_to = ? ORDER BY tasks.created_at DESC",
        (target_user_id,),
    ).fetchall()
    return render_template("tasks.html", role=role, tasks=my_tasks)


@app.route("/tasks/new", methods=["POST"])
@role_required("manager")
def new_task():
    db = get_db()
    db.execute(
        "INSERT INTO tasks (title, description, patient_id, assigned_to, created_by, status) "
        "VALUES (?, ?, ?, ?, ?, 'open')",
        (
            request.form.get("title"),
            request.form.get("description"),
            request.form.get("patient_id") or None,
            request.form.get("assigned_to"),
            session["user_id"],
        ),
    )
    db.commit()
    log_action("task_created", f"title={request.form.get('title')}")
    return redirect(url_for("tasks"))


# --- V3b: same missing-ownership-check issue as V3, but as a write: nothing
# here checks that the task is actually assigned to you before letting you
# flip its status, so any logged-in user can complete anyone's task. ---
@app.route("/tasks/<int:task_id>/complete", methods=["POST"])
@login_required
def complete_task(task_id):
    db = get_db()
    db.execute("UPDATE tasks SET status='completed' WHERE id=?", (task_id,))
    db.commit()
    log_action("task_completed", f"task_id={task_id}")
    return redirect(request.referrer or url_for("tasks"))


# ---------------------------------------------------------------------------
# Admin (Hospital Administrator)
# ---------------------------------------------------------------------------

@app.route("/admin")
@role_required("manager")
def admin():
    db = get_db()
    staff = db.execute("SELECT * FROM users WHERE role != 'manager'").fetchall()
    patients = db.execute(
        "SELECT patients.*, u.full_name AS doctor_name FROM patients "
        "LEFT JOIN users u ON patients.assigned_doctor_id = u.id"
    ).fetchall()
    doctors = db.execute("SELECT * FROM users WHERE role='employee'").fetchall()
    return render_template("admin.html", staff=staff, patients=patients, doctors=doctors)


@app.route("/admin/patients/new", methods=["POST"])
@role_required("manager")
def new_patient():
    db = get_db()
    db.execute(
        "INSERT INTO patients (name, dob, condition, last_checkup, assigned_doctor_id) "
        "VALUES (?, ?, ?, date('now'), ?)",
        (
            request.form.get("name"),
            request.form.get("dob"),
            request.form.get("condition"),
            request.form.get("assigned_doctor_id") or None,
        ),
    )
    db.commit()
    log_action("patient_added", f"name={request.form.get('name')}")
    return redirect(url_for("admin"))


@app.route("/admin/patients/<int:patient_id>/assign", methods=["POST"])
@role_required("manager")
def assign_patient(patient_id):
    db = get_db()
    doctor_id = request.form.get("assigned_doctor_id")
    db.execute("UPDATE patients SET assigned_doctor_id=? WHERE id=?", (doctor_id, patient_id))
    db.commit()
    log_action("patient_reassigned", f"patient_id={patient_id} doctor_id={doctor_id}")
    return redirect(url_for("admin"))


# ---------------------------------------------------------------------------
# IT panel
# ---------------------------------------------------------------------------

@app.route("/it")
@role_required("it")
def it_panel():
    db = get_db()
    tickets = db.execute(
        "SELECT tasks.*, u.full_name AS requested_by FROM tasks "
        "JOIN users u ON tasks.created_by = u.id "
        "WHERE tasks.assigned_to = ? ORDER BY tasks.created_at DESC",
        (session["user_id"],),
    ).fetchall()
    recent_logs = db.execute(
        "SELECT logs.*, users.username FROM logs "
        "LEFT JOIN users ON logs.user_id = users.id "
        "ORDER BY logs.id DESC LIMIT 25"
    ).fetchall()
    return render_template("it.html", tickets=tickets, logs=recent_logs)


# --- V4: BROKEN ACCESS CONTROL. This only checks that *someone* is logged
# in — it never checks role == 'it'. It's not linked from the nav for other
# roles, but the URL is entirely guessable/discoverable. ---
@app.route("/filex")
@login_required
def filex():
    db = get_db()
    files = db.execute("SELECT * FROM file_x ORDER BY id DESC").fetchall()
    log_action("filex_accessed")
    return render_template("filex.html", files=files)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("No database found — run `python init_db.py` first.")
    # host="0.0.0.0" so the Kali VM on the lab network can reach this box,
    # not just localhost. debug=True is left on intentionally — see V7.
    app.run(host="0.0.0.0", port=5000, debug=True)
