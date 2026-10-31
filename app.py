
import os
import json
import hashlib
import hmac
from datetime import datetime, date, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, abort, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import func

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///restorative_tracker.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "SESSION_COOKIE_SECURE", "false"
).lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["WTF_CSRF_TIME_LIMIT"] = 3600

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set FLASK_SECRET_KEY in your .env file.")

encryption_key = os.getenv("DATA_ENCRYPTION_KEY", "")

if not encryption_key:
    raise RuntimeError("Set DATA_ENCRYPTION_KEY in your .env file.")

try:
    cipher = Fernet(encryption_key.encode())
except Exception as exc:
    raise RuntimeError(
        "DATA_ENCRYPTION_KEY is invalid. Generate one with the README instructions."
    ) from exc

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
password_hasher = PasswordHasher()

ROLES = ("Administrator", "OSA Personnel", "Restorative Supervisor")


def now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# =========================
# DATABASE MODELS
# =========================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(140), nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="OSA Personnel")
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_number = db.Column(db.String(40), unique=True, nullable=False)
    full_name = db.Column(db.String(140), nullable=False)
    program = db.Column(db.String(120), nullable=False)
    year_level = db.Column(db.String(30), nullable=False)
    section = db.Column(db.String(40), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(40), unique=True, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey("student.id"), nullable=False)
    incident_date = db.Column(db.Date, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    classification = db.Column(db.String(40), nullable=False)
    description_encrypted = db.Column(db.LargeBinary, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Open")
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    student = db.relationship("Student")
    creator = db.relationship("User")


class Commitment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("case.id"), nullable=False)
    action_type = db.Column(db.String(60), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    required_hours = db.Column(db.Float, nullable=False, default=0)
    verified_hours = db.Column(db.Float, nullable=False, default=0)
    due_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Pending")
    verification_note = db.Column(db.String(500), nullable=True)
    verified_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    case = db.relationship("Case", backref="commitments")
    verifier = db.relationship("User", foreign_keys=[verified_by])


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(180), nullable=False)
    record_type = db.Column(db.String(60), nullable=False)
    record_id = db.Column(db.String(60), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    previous_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)
    user = db.relationship("User")


# =========================
# SECURITY AND HELPER FUNCTIONS
# =========================

def audit(action, record_type="System", record_id=None):
    previous = AuditLog.query.order_by(AuditLog.id.desc()).first()
    previous_hash = previous.entry_hash if previous else "GENESIS"

    payload = "|".join([
        str(session.get("user_id", "system")),
        action,
        record_type,
        str(record_id or ""),
        now_utc().isoformat(),
        previous_hash
    ])

    entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    db.session.add(AuditLog(
        user_id=session.get("user_id"),
        action=action,
        record_type=record_type,
        record_id=str(record_id) if record_id is not None else None,
        previous_hash=previous_hash,
        entry_hash=entry_hash
    ))


def encrypt_text(value):
    return cipher.encrypt(value.encode("utf-8"))


def decrypt_text(value):
    try:
        return cipher.decrypt(value).decode("utf-8")
    except InvalidToken:
        return "[Unable to decrypt: key mismatch or data integrity failure]"


def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user or not user.active:
            session.clear()
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))

        session.permanent = True
        return fn(*args, **kwargs)

    return wrapper


def roles_required(*allowed):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            user = current_user()

            if user.role not in allowed:
                abort(403)

            return fn(*args, **kwargs)

        return wrapper

    return decorator


def refresh_commitment_status(item):
    if item.status == "Completed":
        return "Completed"

    if item.due_date < date.today():
        return "Overdue"

    if item.verified_hours > 0:
        return "In Progress"

    return "Pending"


@app.context_processor
def inject_globals():
    return {
        "logged_in_user": current_user(),
        "today": date.today()
    }


# =========================
# DASHBOARD
# =========================

@app.route("/")
@login_required
def dashboard():
    total_cases = Case.query.count()
    open_cases = Case.query.filter(Case.status == "Open").count()

    all_items = Commitment.query.all()

    for item in all_items:
        item.status = refresh_commitment_status(item)

    db.session.commit()

    pending = sum(1 for x in all_items if x.status == "Pending")
    progress = sum(1 for x in all_items if x.status == "In Progress")
    completed = sum(1 for x in all_items if x.status == "Completed")
    overdue = sum(1 for x in all_items if x.status == "Overdue")

    recent = Case.query.order_by(
        Case.created_at.desc()
    ).limit(6).all()

    return render_template(
        "dashboard.html",
        total_cases=total_cases,
        open_cases=open_cases,
        pending=pending,
        progress=progress,
        completed=completed,
        overdue=overdue,
        recent=recent
    )


# =========================
# LOGIN AND LOGOUT
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(
            username=username,
            active=True
        ).first()

        if user:
            try:
                password_hasher.verify(user.password_hash, password)

                if password_hasher.check_needs_rehash(user.password_hash):
                    user.password_hash = password_hasher.hash(password)

                session.clear()
                session["user_id"] = user.id
                session.permanent = True

                audit("Successful login", "User", user.id)
                db.session.commit()

                return redirect(url_for("dashboard"))

            except (VerifyMismatchError, InvalidHashError):
                pass

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("Logout", "User", session.get("user_id"))
    db.session.commit()

    session.clear()

    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# =========================
# STUDENT MANAGEMENT
# =========================

@app.route("/students", methods=["GET", "POST"])
@roles_required("Administrator", "OSA Personnel")
def students():
    if request.method == "POST":
        student_number = request.form.get("student_number", "").strip()
        full_name = request.form.get("full_name", "").strip()
        program = request.form.get("program", "").strip()
        year_level = request.form.get("year_level", "").strip()
        section = request.form.get("section", "").strip()

        if not all([student_number, full_name, program, year_level]):
            flash("Complete all required student fields.", "danger")

        elif Student.query.filter_by(student_number=student_number).first():
            flash("That student number already exists.", "danger")

        else:
            obj = Student(
                student_number=student_number,
                full_name=full_name,
                program=program,
                year_level=year_level,
                section=section
            )

            db.session.add(obj)
            db.session.flush()

            audit("Created student record", "Student", obj.id)
            db.session.commit()

            flash("Student record added.", "success")
            return redirect(url_for("students"))

    q = request.args.get("q", "").strip()
    query = Student.query

    if q:
        query = query.filter(
            db.or_(
                Student.student_number.ilike(f"%{q}%"),
                Student.full_name.ilike(f"%{q}%")
            )
        )

    records = query.order_by(Student.full_name).all()

    return render_template(
        "students.html",
        records=records,
        q=q
    )


# =========================
# DISCIPLINARY CASE MANAGEMENT
# =========================


@app.route("/cases", methods=["GET", "POST"])
@roles_required("Administrator", "OSA Personnel")
def cases():
    if request.method == "POST":
        student_id = request.form.get("student_id", type=int)
        incident_date = request.form.get("incident_date", "")
        category = request.form.get("category", "").strip()
        classification = request.form.get("classification", "For Review")
        description = request.form.get("description", "").strip()

        if category == "Other":
            other_category = request.form.get("other_category", "").strip()

            if not other_category:
                flash("Please specify the other incident category.", "danger")
                return redirect(url_for("cases"))

            category = f"Other: {other_category}"

        student = db.session.get(Student, student_id) if student_id else None

        try:
            parsed_date = date.fromisoformat(incident_date)
        except ValueError:
            parsed_date = None

        if not student or not parsed_date or not category or not description:
            flash("Provide a valid student, date, category, and incident description.", "danger")
        else:
            number = f"OSA-{date.today().year}-{(Case.query.count()+1):04d}"

            while Case.query.filter_by(case_number=number).first():
                number = f"OSA-{date.today().year}-{(Case.query.count()+1):04d}"

            obj = Case(
                case_number=number,
                student_id=student.id,
                incident_date=parsed_date,
                category=category,
                classification=classification,
                description_encrypted=encrypt_text(description),
                created_by=current_user().id
            )

            db.session.add(obj)
            db.session.flush()
            audit("Created disciplinary case", "Case", obj.id)
            db.session.commit()

            flash(f"Case {number} created.", "success")
            return redirect(url_for("cases"))

    # Search and filter
    q = request.args.get("q", "").strip()
    action_status = request.args.get("action_status", "").strip()

    query = Case.query.join(Student)

    if q:
        search_term = f"%{q}%"
        query = query.filter(
            db.or_(
                Student.full_name.ilike(search_term),
                Student.student_number.ilike(search_term),
                Case.case_number.ilike(search_term),
                Case.category.ilike(search_term)
            )
        )

    records = query.order_by(Case.created_at.desc()).all()

    # Calculate commitment statuses
    for item in records:
        item.safe_description = decrypt_text(item.description_encrypted)

        for commitment in item.commitments:
            commitment.status = refresh_commitment_status(commitment)

    # Filter cases by restorative commitment status
    if action_status:
        records = [
            case for case in records
            if any(
                commitment.status == action_status
                for commitment in case.commitments
            )
        ]

    student_records = Student.query.order_by(Student.full_name).all()

    return render_template(
        "cases.html",
        records=records,
        students=student_records,
        q=q,
        action_status=action_status
    )



# =========================
# RESTORATIVE COMMITMENTS
# =========================

@app.route("/cases/<int:case_id>/commitments", methods=["POST"])
@roles_required("Administrator", "OSA Personnel")
def add_commitment(case_id):
    case = db.session.get(Case, case_id) or abort(404)

    action_type = request.form.get("action_type", "").strip()
    description = request.form.get("description", "").strip()
    due_raw = request.form.get("due_date", "")

    required_hours = request.form.get(
        "required_hours",
        type=float,
        default=0
    )

    try:
        due_date = date.fromisoformat(due_raw)
    except ValueError:
        due_date = None

    if (
        not action_type
        or not description
        or not due_date
        or required_hours < 0
    ):
        flash(
            "Enter a valid action, description, deadline, and non-negative hours.",
            "danger"
        )

    else:
        item = Commitment(
            case_id=case.id,
            action_type=action_type,
            description=description,
            due_date=due_date,
            required_hours=required_hours,
            created_by=current_user().id
        )

        db.session.add(item)
        db.session.flush()

        audit("Added restorative commitment", "Commitment", item.id)
        db.session.commit()

        flash("Restorative commitment added.", "success")

    return redirect(url_for("cases"))


@app.route("/commitments/<int:item_id>/progress", methods=["POST"])
@roles_required(
    "Administrator",
    "OSA Personnel",
    "Restorative Supervisor"
)
def update_progress(item_id):
    item = db.session.get(Commitment, item_id) or abort(404)

    hours = request.form.get("verified_hours", type=float)

    if hours is None or hours < 0 or hours > item.required_hours:
        flash(
            "Hours must be between zero and the required total.",
            "danger"
        )

    else:
        item.verified_hours = hours
        item.status = refresh_commitment_status(item)

        audit("Updated restorative progress", "Commitment", item.id)
        db.session.commit()

        flash("Commitment progress updated.", "success")

    return redirect(url_for("cases"))


@app.route("/commitments/<int:item_id>/verify", methods=["POST"])
@roles_required("Administrator", "Restorative Supervisor")
def verify_commitment(item_id):
    item = db.session.get(Commitment, item_id) or abort(404)

    if (
        item.required_hours > 0
        and item.verified_hours < item.required_hours
    ):
        flash(
            "Required service hours are not yet complete.",
            "warning"
        )

    else:
        item.status = "Completed"
        item.verified_by = current_user().id

        item.verification_note = request.form.get(
            "verification_note", ""
        ).strip()

        audit("Verified restorative commitment", "Commitment", item.id)
        db.session.commit()

        flash(
            "Commitment marked as completed after verification.",
            "success"
        )

    return redirect(url_for("cases"))


# =========================
# REPORTS
# =========================

@app.route("/reports")
@roles_required(
    "Administrator",
    "OSA Personnel",
    "Restorative Supervisor"
)
def reports():
    all_items = Commitment.query.all()
    counts = {}

    for item in all_items:
        status = refresh_commitment_status(item)
        counts[status] = counts.get(status, 0) + 1

    return render_template(
        "reports.html",
        counts=counts,
        cases_count=Case.query.count(),
        students_count=Student.query.count(),
        items_count=len(all_items)
    )


# =========================
# USER ACCOUNT MANAGEMENT
# =========================

@app.route("/users", methods=["GET", "POST"])
@roles_required("Administrator")
def users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        if (
            not username
            or not full_name
            or len(password) < 12
            or role not in ROLES
        ):
            flash(
                "Enter a username, name, valid role, and password of at least 12 characters.",
                "danger"
            )

        elif User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")

        else:
            user = User(
                username=username,
                full_name=full_name,
                password_hash=password_hasher.hash(password),
                role=role
            )

            db.session.add(user)
            db.session.flush()

            audit("Created user account", "User", user.id)
            db.session.commit()

            flash("User account created.", "success")
            return redirect(url_for("users"))

    return render_template(
        "users.html",
        records=User.query.order_by(User.username).all(),
        roles=ROLES
    )


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
@roles_required("Administrator")
def toggle_user(user_id):
    user = db.session.get(User, user_id) or abort(404)

    if user.id == current_user().id:
        flash("You cannot deactivate your own account.", "warning")

    else:
        user.active = not user.active

        audit("Changed user active status", "User", user.id)
        db.session.commit()

        flash("Account status updated.", "success")

    return redirect(url_for("users"))


# =========================
# ACTIVITY LOGS
# =========================

@app.route("/activity")
@roles_required("Administrator")
def activity():
    records = AuditLog.query.order_by(
        AuditLog.id.desc()
    ).limit(200).all()

    return render_template(
        "activity.html",
        records=records
    )


# =========================
# ERROR HANDLERS
# =========================

@app.errorhandler(403)
def forbidden(_):
    return render_template(
        "error.html",
        code=403,
        message="You do not have permission to access this page."
    ), 403


@app.errorhandler(404)
def not_found(_):
    return render_template(
        "error.html",
        code=404,
        message="The requested record was not found."
    ), 404


# =========================
# AUDIT VERIFICATION
# =========================

def verify_audit_chain():
    rows = AuditLog.query.order_by(AuditLog.id.asc()).all()
    previous = "GENESIS"

    for row in rows:
        payload = "|".join([
            str(row.user_id or "system"),
            row.action,
            row.record_type,
            str(row.record_id or ""),
            row.created_at.isoformat(),
            row.previous_hash
        ])

        expected = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

        if (
            row.previous_hash != previous
            or not hmac.compare_digest(expected, row.entry_hash)
        ):
            return False

        previous = row.entry_hash

    return True


# =========================
# DATABASE INITIALIZATION
# =========================

@app.cli.command("init-db")
def init_db():
    """Create tables and bootstrap the first administrator from .env."""

    db.create_all()

    username = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")

    if not password or len(password) < 12:
        raise RuntimeError(
            "Set BOOTSTRAP_ADMIN_PASSWORD to at least 12 characters in .env."
        )

    if not User.query.filter_by(username=username).first():
        admin = User(
            username=username,
            full_name="System Administrator",
            password_hash=password_hasher.hash(password),
            role="Administrator"
        )

        db.session.add(admin)
        db.session.commit()

        print(f"Administrator created: {username}")

    else:
        print("Administrator already exists; no account changed.")

    print("Database initialized.")


@app.cli.command("verify-audit")
def verify_audit():
    db.create_all()

    if verify_audit_chain():
        print("Audit chain valid.")
    else:
        print("WARNING: audit chain verification failed.")


if __name__ == "__main__":
    app.run(debug=False)
