from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = "student-safety-hackathon-secret-key"

DATABASE = "safety.db"


# ---------------- DATABASE ----------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'student'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            alert_type TEXT NOT NULL,
            latitude TEXT,
            longitude TEXT,
            message TEXT,
            status TEXT DEFAULT 'ACTIVE',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


# ---------------- LOGIN PROTECTION ----------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)

    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        if session.get("role") != "admin":
            return "Access denied", 403

        return function(*args, **kwargs)

    return wrapper


# ---------------- HOME ----------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            return "Please fill all fields."

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db()

            conn.execute(
                """
                INSERT INTO users (name, email, password)
                VALUES (?, ?, ?)
                """,
                (name, email, hashed_password)
            )

            conn.commit()
            conn.close()

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            return "Email already registered."

    return render_template("register.html")


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):

            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]

            return redirect(url_for("dashboard"))

        return "Invalid email or password."

    return render_template("login.html")


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ---------------- STUDENT DASHBOARD ----------------

@app.route("/dashboard")
@login_required
def dashboard():

    conn = get_db()

    alerts = conn.execute(
        """
        SELECT *
        FROM alerts
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],)
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        name=session["name"]
    )


# ---------------- SOS ALERT ----------------

@app.route("/sos", methods=["POST"])
@login_required
def sos():

    data = request.get_json(silent=True) or {}

    latitude = data.get("latitude", "")
    longitude = data.get("longitude", "")

    message = data.get(
        "message",
        "Emergency SOS activated by student."
    )

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = get_db()

    conn.execute(
        """
        INSERT INTO alerts
        (user_id, alert_type, latitude, longitude, message, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            "SOS",
            latitude,
            longitude,
            message,
            "ACTIVE",
            current_time
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Emergency alert created successfully."
    })


# ---------------- ADMIN DASHBOARD ----------------

@app.route("/admin")
@admin_required
def admin():

    conn = get_db()

    alerts = conn.execute(
        """
        SELECT
            alerts.*,
            users.name,
            users.email
        FROM alerts
        JOIN users ON alerts.user_id = users.id
        ORDER BY alerts.id DESC
        """
    ).fetchall()

    students = conn.execute(
        """
        SELECT id, name, email
        FROM users
        WHERE role = 'student'
        ORDER BY name
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        alerts=alerts,
        students=students
    )


# ---------------- RESOLVE ALERT ----------------

@app.route("/resolve/<int:alert_id>", methods=["POST"])
@admin_required
def resolve_alert(alert_id):

    conn = get_db()

    conn.execute(
        """
        UPDATE alerts
        SET status = 'RESOLVED'
        WHERE id = ?
        """,
        (alert_id,)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin"))


# ---------------- HEALTH CHECK ----------------

@app.route("/health")
def health():

    return jsonify({
        "status": "online",
        "project": "Smart Student Safety & Emergency Alert System"
    })
    # ---------------- MAKE ADMIN ----------------

def make_admin(email):
    conn = get_db()

    conn.execute(
        "UPDATE users SET role = 'admin' WHERE email = ?",
        (email,)
    )

    conn.commit()
    conn.close()
    



# ---------------- START APPLICATION ----------------

if __name__ == "__main__":

    init_db()
    make_admin("pp183910@gmail.com")


    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )