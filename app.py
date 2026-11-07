import os
import json
import hashlib
import hmac
import math
import re
from datetime import datetime, date, timedelta, timezone
from functools import wraps
import base64

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set FLASK_SECRET_KEY in your .env file.")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///restorative_tracker.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# =========================
# SESSION AND SECURITY CONFIGURATION
# =========================

# Prevent JavaScript from accessing session cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Help protect against cross-site request attacks
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable secure cookies when running on HTTPS
# Keep false for local HTTP development
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "SESSION_COOKIE_SECURE", "false"
).lower() == "true"

# Session expires after 30 minutes
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# Refresh the expiration time when the session is used
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

# CSRF token expiration
app.config["WTF_CSRF_TIME_LIMIT"] = 3600

# Keep the existing Fernet key for previously encrypted records
fernet_key = os.getenv("DATA_ENCRYPTION_KEY", "")

if not fernet_key:
    raise RuntimeError("Set DATA_ENCRYPTION_KEY in your .env file.")

try:
    fernet_cipher = Fernet(fernet_key.encode())
except Exception as exc:
    raise RuntimeError("DATA_ENCRYPTION_KEY is invalid.") from exc


# AES-256-GCM key for new encrypted records
aes_key_text = os.getenv("AES256_GCM_KEY", "")

if not aes_key_text:
    raise RuntimeError("Set AES256_GCM_KEY in your .env file.")

try:
    aes_key = base64.urlsafe_b64decode(aes_key_text.encode("ascii"))

    if len(aes_key) != 32:
        raise ValueError("AES-256-GCM key must be 32 bytes.")

    aesgcm_cipher = AESGCM(aes_key)

except Exception as exc:
    raise RuntimeError(
        "AES256_GCM_KEY is invalid. It must be a base64-encoded 32-byte key."
    ) from exc

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
password_hasher = PasswordHasher()

ROLES = ("Administrator", "OSA Personnel", "Restorative Supervisor")


def now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)

    
def is_valid_text(value, max_length, required=True):
    if not isinstance(value, str):
        return False

    value = value.strip()

    if required and not value:
        return False

    if len(value) > max_length:
        return False

    # Reject unexpected control characters
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        return False

    return True


def is_valid_number(value):
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False



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

    assigned_supervisor_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )

    assigned_supervisor = db.relationship(
        "User",
        foreign_keys=[assigned_supervisor_id]
    )

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

    created_at = now_utc()
    user_id = session.get("user_id")

    payload = "|".join([
        str(user_id if user_id is not None else "system"),
        action,
        record_type,
        str(record_id or ""),
        created_at.isoformat(),
        previous_hash
    ])

    entry_hash = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()

    db.session.add(AuditLog(
        user_id=user_id,
        action=action,
        record_type=record_type,
        record_id=str(record_id) if record_id is not None else None,
        created_at=created_at,
        previous_hash=previous_hash,
        entry_hash=entry_hash
    ))


AESGCM_PREFIX = b"AESGCM1:"
AESGCM_AAD = b"OSA-Tracker-Case-Description-v1"


def encrypt_text(value):
    # Generate a new 12-byte nonce for every encryption
    nonce = os.urandom(12)

    # Encrypt using AES-256-GCM
    encrypted = aesgcm_cipher.encrypt(
        nonce,
        value.encode("utf-8"),
        AESGCM_AAD
    )

    # Add a version prefix so we can identify AES-GCM records
    return AESGCM_PREFIX + nonce + encrypted


def decrypt_text(value):
    try:
        # Check whether the record uses AES-256-GCM
        if value.startswith(AESGCM_PREFIX):
            payload = value[len(AESGCM_PREFIX):]

            nonce = payload[:12]
            encrypted = payload[12:]

            if len(nonce) != 12 or len(encrypted) < 16:
                raise InvalidTag

            return aesgcm_cipher.decrypt(
                nonce,
                encrypted,
                AESGCM_AAD
            ).decode("utf-8")

        # Otherwise, decrypt using the old Fernet key
        return fernet_cipher.decrypt(value).decode("utf-8")

    except (InvalidToken, InvalidTag, ValueError, UnicodeDecodeError):
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

    today = date.today()
    warning_date = today + timedelta(days=7)

    # Upcoming deadlines
    due_soon_items = [
        item for item in all_items
        if item.status != "Completed"
        and today <= item.due_date <= warning_date
    ]

    # Overdue commitments
    overdue_items = [
        item for item in all_items
        if item.status == "Overdue"
    ]

    # General commitment statistics
    pending = sum(1 for x in all_items if x.status == "Pending")
    progress = sum(1 for x in all_items if x.status == "In Progress")
    completed = sum(1 for x in all_items if x.status == "Completed")
    overdue = sum(1 for x in all_items if x.status == "Overdue")

    # Community Service Monitoring
    service_items = [
        item for item in all_items
        if item.action_type == "Community Service"
    ]

    service_required_hours = sum(
        item.required_hours for item in service_items
    )

    service_verified_hours = sum(
        item.verified_hours for item in service_items
    )

    service_remaining_hours = max(
        0, service_required_hours - service_verified_hours
    )

    service_completed = sum(
        1 for item in service_items
        if item.status == "Completed"
    )

    db.session.commit()

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
        due_soon=len(due_soon_items),
        due_soon_items=due_soon_items,
        overdue_items=overdue_items,
        service_items=service_items,
        service_required_hours=round(service_required_hours, 2),
        service_verified_hours=round(service_verified_hours, 2),
        service_remaining_hours=round(service_remaining_hours, 2),
        service_completed=service_completed,
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


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Verify current password
        try:
            password_hasher.verify(
                user.password_hash,
                current_password
            )
        except (VerifyMismatchError, InvalidHashError):
            flash("Your current password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        # Validate new password
        if (
            len(new_password) < 12
            or len(new_password.encode("utf-8")) > 1024
        ):
            flash(
                "Your new password must be at least 12 characters.",
                "danger"
            )
            return redirect(url_for("change_password"))

        # Check password confirmation
        if new_password != confirm_password:
            flash("The new passwords do not match.", "danger")
            return redirect(url_for("change_password"))

        # Prevent using the same password
        if new_password == current_password:
            flash(
                "Your new password must be different from your current password.",
                "danger"
            )
            return redirect(url_for("change_password"))

        # Save new Argon2id password hash
        user.password_hash = password_hasher.hash(new_password)

        audit("Changed account password", "User", user.id)
        db.session.commit()

        # End current session and require fresh login
        session.clear()

        flash(
            "Password changed successfully. Please sign in again.",
            "success"
        )
        return redirect(url_for("login"))

    return render_template("change_password.html")


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

        # Input validation
        if not all([
            is_valid_text(student_number, 40),
            is_valid_text(full_name, 140),
            is_valid_text(program, 120),
            is_valid_text(year_level, 30),
            is_valid_text(section, 40, required=False)
        ]):
            flash(
                "Check the student information. Required fields must be complete and within the allowed character limits.",
                "danger"
            )

        elif Student.query.filter(
          func.lower(Student.student_number) == student_number.lower()
        ).first():
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
# STUDENT DISCIPLINARY HISTORY
# =========================


@app.route("/students/<int:student_id>/history")
@roles_required("Administrator", "OSA Personnel", "Restorative Supervisor")
def student_history(student_id):
    student = db.session.get(Student, student_id) or abort(404)

    records = Case.query.filter_by(
        student_id=student.id
    ).order_by(
        Case.incident_date.asc(),
        Case.created_at.asc(),
        Case.id.asc()
    ).all()

    occurrence_counts = {}

    for case in records:
        key = case.category
        occurrence_counts[key] = occurrence_counts.get(key, 0) + 1

        case.occurrence_number = occurrence_counts[key]
        case.safe_description = decrypt_text(
            case.description_encrypted
        )

        for commitment in case.commitments:
            commitment.status = refresh_commitment_status(commitment)

    # Record access to confidential student history
    audit(
        "Viewed confidential student disciplinary history",
        "Student",
        student.id
    )

    db.session.commit()

    return render_template(
        "student_history.html",
        student=student,
        records=records
    )



# =========================
# DISCIPLINARY CASE MANAGEMENT
# =========================




@app.route("/cases", methods=["GET", "POST"])
@roles_required("Administrator", "OSA Personnel")
def cases():
    if request.method == "POST":
        student_id = request.form.get("student_id", type=int)
        incident_date = request.form.get("incident_date", "").strip()
        category = request.form.get("category", "").strip()
        classification = request.form.get("classification", "For Review").strip()
        description = request.form.get("description", "").strip()

        # Handle Other category
        if category == "Other":
            other_category = request.form.get("other_category", "").strip()

            if not is_valid_text(other_category, 90):
                flash("Please provide a valid other incident category.", "danger")
                return redirect(url_for("cases"))

            category = f"Other: {other_category}"

        student = db.session.get(Student, student_id) if student_id else None

        # Validate incident date
        try:
            parsed_date = date.fromisoformat(incident_date)
        except (ValueError, TypeError):
            parsed_date = None

        # Validate classification
        allowed_classifications = [
            "For Review",
            "Minor",
            "Major",
            "Other"
        ]

        # Validate case information
        if (
            not student
            or not parsed_date
            or parsed_date > date.today()
            or not is_valid_text(category, 100)
            or classification not in allowed_classifications
            or not is_valid_text(description, 5000)
        ):
            flash(
                "Check the case information. Provide a valid student, incident date, category, classification, and description.",
                "danger"
            )

        else:
            sequence = Case.query.count() + 1
            number = f"OSA-{date.today().year}-{sequence:04d}"

            while Case.query.filter_by(case_number=number).first():
                sequence += 1
                number = f"OSA-{date.today().year}-{sequence:04d}"

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

    # Read search and filter values
    q = request.args.get("q", "").strip()
    action_status = request.args.get("action_status", "").strip()
    assignment_status = request.args.get("assignment_status", "").strip()
    incident_date_filter = request.args.get("incident_date", "").strip()
    category_filter = request.args.get("category_filter", "").strip()
    case_status = request.args.get("case_status", "").strip()
    created_by = request.args.get("created_by", type=int)

    # Start the case query
    query = Case.query.join(Student).outerjoin(
        User, Case.created_by == User.id
    )

    # Search student, case number, category, or creator name
    if q:
        search_term = f"%{q}%"
        query = query.filter(
            db.or_(
                Student.full_name.ilike(search_term),
                Student.student_number.ilike(search_term),
                Case.case_number.ilike(search_term),
                Case.category.ilike(search_term),
                User.full_name.ilike(search_term)
            )
        )

    # Filter by incident date
    if incident_date_filter:
        try:
            selected_date = date.fromisoformat(incident_date_filter)
            query = query.filter(Case.incident_date == selected_date)
        except ValueError:
            flash("Invalid incident date filter.", "warning")

    # Filter by category
    if category_filter:
        query = query.filter(Case.category == category_filter)

    # Filter by case status
    if case_status:
        query = query.filter(Case.status == case_status)

    # Filter by personnel who created the case
    if created_by:
        query = query.filter(Case.created_by == created_by)

    records = query.order_by(Case.created_at.desc()).all()

    # Repeat violation counting
    all_cases = Case.query.order_by(
        Case.incident_date.asc(),
        Case.created_at.asc(),
        Case.id.asc()
    ).all()

    occurrence_counts = {}

    for historical_case in all_cases:
        key = (
            historical_case.student_id,
            historical_case.category
        )

        occurrence_counts[key] = occurrence_counts.get(key, 0) + 1

    # Assign occurrence numbers to displayed records
    for case in records:
        case.occurrence_number = occurrence_counts.get(
            (case.student_id, case.category),
            0
        )

    # Refresh commitment statuses and decrypt descriptions
    for case in records:
        case.safe_description = decrypt_text(case.description_encrypted)

        for commitment in case.commitments:
            commitment.status = refresh_commitment_status(commitment)

    db.session.commit()

    # Filter by restorative commitment status
    if action_status:
        records = [
            case for case in records
            if any(c.status == action_status for c in case.commitments)
        ]

    # Filter by assignment status
    if assignment_status == "Assigned":
        records = [
            case for case in records
            if len(case.commitments) > 0
        ]

    elif assignment_status == "Unassigned":
        records = [
            case for case in records
            if len(case.commitments) == 0
        ]

    # Data for dropdowns
    student_records = Student.query.order_by(Student.full_name).all()

    categories = [
        row[0] for row in db.session.query(Case.category)
        .distinct()
        .order_by(Case.category)
        .all()
    ]

    personnel = User.query.filter_by(active=True).order_by(
        User.full_name
    ).all()

    # Active accounts that can be assigned to restorative commitments
    supervisors = User.query.filter_by(
        role="Restorative Supervisor",
        active=True
    ).order_by(User.full_name).all()

    case_statuses = ["Open", "Closed"]

    return render_template(
        "cases.html",
        records=records,
        students=student_records,
        q=q,
        action_status=action_status,
        assignment_status=assignment_status,
        incident_date_filter=incident_date_filter,
        category_filter=category_filter,
        case_status=case_status,
        created_by=created_by,
        categories=categories,
        personnel=personnel,
        supervisors=supervisors,
        case_statuses=case_statuses,
        today=date.today()
    )




# =========================
# RESTORATIVE COMMITMENTS
# =========================



@app.route("/cases/<int:case_id>/commitments", methods=["POST"])
@roles_required("Administrator", "OSA Personnel")
def add_commitment(case_id):
    case = db.session.get(Case, case_id) or abort(404)

    if case.status == "Closed":
        flash("Cannot add a commitment to a closed case.", "danger")
        return redirect(url_for("cases") + "#case-list")

    action_type = request.form.get("action_type", "").strip()
    due_date_text = request.form.get("due_date", "").strip()
    description = request.form.get("description", "").strip()
    required_hours_text = request.form.get("required_hours", "").strip()
    assigned_supervisor_text = request.form.get(
        "assigned_supervisor_id", ""
    ).strip()

    allowed_action_types = [
        "Reflection Activity",
        "Community Service",
        "Mediation / Dialogue",
        "Other Approved Action"
    ]

    if action_type not in allowed_action_types:
        flash("Please select a valid restorative action type.", "danger")
        return redirect(url_for("cases") + "#case-list")

    if not is_valid_text(description, 500):
        flash("Please enter a valid commitment description.", "danger")
        return redirect(url_for("cases") + "#case-list")

    try:
        due_date = date.fromisoformat(due_date_text)
    except (ValueError, TypeError):
        flash("Please enter a valid commitment deadline.", "danger")
        return redirect(url_for("cases") + "#case-list")

    if due_date < date.today():
        flash("The commitment deadline cannot be in the past.", "danger")
        return redirect(url_for("cases") + "#case-list")

    if not is_valid_number(required_hours_text):
        flash("Please enter a valid number of required hours.", "danger")
        return redirect(url_for("cases") + "#case-list")

    required_hours = float(required_hours_text)

    if required_hours < 0 or required_hours > 10000:
        flash("Required hours must be between 0 and 10,000.", "danger")
        return redirect(url_for("cases") + "#case-list")

    # Validate the assigned restorative supervisor.
    assigned_supervisor_id = None

    if assigned_supervisor_text:
        try:
            assigned_supervisor_id = int(assigned_supervisor_text)
        except ValueError:
            flash("Please select a valid supervisor.", "danger")
            return redirect(url_for("cases") + "#case-list")

        supervisor = db.session.get(User, assigned_supervisor_id)

        if (
            not supervisor
            or not supervisor.active
            or supervisor.role != "Restorative Supervisor"
        ):
            flash("The selected supervisor is invalid or inactive.", "danger")
            return redirect(url_for("cases") + "#case-list")

    item = Commitment(
        case_id=case.id,
        action_type=action_type,
        description=description,
        required_hours=required_hours,
        verified_hours=0,
        due_date=due_date,
        status="Pending",
        created_by=current_user().id,
        assigned_supervisor_id=assigned_supervisor_id
    )

    db.session.add(item)
    db.session.flush()

    audit("Created restorative commitment", "Commitment", item.id)
    db.session.commit()

    flash("Commitment added successfully.", "success")
    return redirect(url_for("cases") + "#case-list")




@app.route("/my-commitments")
@roles_required("Restorative Supervisor")
def my_commitments():
    supervisor_id = current_user().id

    commitments = Commitment.query.filter_by(
        assigned_supervisor_id=supervisor_id
    ).join(Case).order_by(Commitment.due_date.asc()).all()

    for item in commitments:
        item.status = refresh_commitment_status(item)

    db.session.commit()

    return render_template(
        "my_commitments.html",
        commitments=commitments
    )


@app.route("/commitments/<int:item_id>/progress", methods=["POST"])
@roles_required("Administrator", "OSA Personnel", "Restorative Supervisor")
def update_progress(item_id):
    item = db.session.get(Commitment, item_id) or abort(404)
    user = current_user()
    return_to_supervisor_page = user.role == "Restorative Supervisor"
    destination = url_for("my_commitments") if return_to_supervisor_page else url_for("cases") + "#case-list"

    # Supervisors may update only commitments assigned to their own account.
    if return_to_supervisor_page and item.assigned_supervisor_id != user.id:
        abort(403)

    if item.case.status == "Closed":
        flash("Cannot update a commitment under a closed case.", "danger")
        return redirect(destination)

    if item.status == "Completed":
        flash(
            "This commitment has already been verified and completed. Its progress cannot be changed.",
            "warning"
        )
        return redirect(destination)

    hours_text = request.form.get("verified_hours", "").strip()

    if not is_valid_number(hours_text):
        flash("Please enter a valid number of hours.", "danger")
        return redirect(destination)

    hours = float(hours_text)

    if hours < 0 or hours > item.required_hours:
        flash(
            "Hours must be between zero and the required total.",
            "danger"
        )
        return redirect(destination)

    item.verified_hours = hours
    item.status = refresh_commitment_status(item)

    audit("Updated restorative progress", "Commitment", item.id)
    db.session.commit()

    flash("Commitment progress updated.", "success")
    return redirect(destination)


@app.route("/cases/<int:case_id>/status", methods=["POST"])
@roles_required("Administrator", "OSA Personnel")
def update_case_status(case_id):
    case = db.session.get(Case, case_id) or abort(404)

    new_status = request.form.get("status", "").strip()

    if new_status not in ["Open", "Closed"]:
        flash("Invalid case status.", "danger")
        return redirect(url_for("cases") + "#case-list")

    if new_status == case.status:
        flash(f"Case is already {new_status}.", "info")
        return redirect(url_for("cases") + "#case-list")

    if new_status == "Closed":
        for item in case.commitments:
            item.status = refresh_commitment_status(item)

        unfinished = [
            item for item in case.commitments
            if item.status != "Completed"
        ]

        if unfinished:
            flash(
                "This case cannot be closed because it has unfinished restorative commitments.",
                "warning"
            )
            return redirect(url_for("cases") + "#case-list")

    old_status = case.status
    case.status = new_status

    audit(
        f"Changed case status from {old_status} to {new_status}",
        "Case",
        case.id
    )

    db.session.commit()

    flash(
        f"Case {case.case_number} is now {new_status}.",
        "success"
    )

    return redirect(url_for("cases") + "#case-list")


@app.route("/commitments/<int:item_id>/verify", methods=["POST"])
@roles_required("Administrator", "Restorative Supervisor")
def verify_commitment(item_id):
    item = db.session.get(Commitment, item_id) or abort(404)
    user = current_user()
    return_to_supervisor_page = user.role == "Restorative Supervisor"
    destination = url_for("my_commitments") if return_to_supervisor_page else url_for("cases") + "#case-list"

    # Supervisors may verify only commitments assigned to their own account.
    if return_to_supervisor_page and item.assigned_supervisor_id != user.id:
        abort(403)

    if item.case.status == "Closed":
        flash("Cannot verify a commitment under a closed case.", "danger")
        return redirect(destination)

    if item.status == "Completed":
        flash("This commitment has already been verified.", "warning")
        return redirect(destination)

    verification_note = request.form.get(
        "verification_note", ""
    ).strip()

    if not verification_note:
        flash("A verification note is required before completing this commitment.", "danger")

    elif len(verification_note) > 500:
        flash("The verification note must not exceed 500 characters.", "danger")

    elif (
        item.required_hours > 0
        and item.verified_hours < item.required_hours
    ):
        flash("Required service hours are not yet complete.", "warning")

    else:
        item.status = "Completed"
        item.verified_by = current_user().id
        item.verification_note = verification_note

        audit("Verified restorative commitment", "Commitment", item.id)
        db.session.commit()

        flash("Commitment marked as completed after verification.", "success")

    return redirect(destination)


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
    all_cases = Case.query.all()
    all_students = Student.query.all()
    all_items = Commitment.query.all()

    today = date.today()

    # Commitment status counts
    counts = {}

    for item in all_items:
        item.status = refresh_commitment_status(item)
        counts[item.status] = counts.get(item.status, 0) + 1

    # Cases grouped by status
    case_status_counts = {}

    for case in all_cases:
        case_status_counts[case.status] = (
            case_status_counts.get(case.status, 0) + 1
        )

    # Cases grouped by category
    category_counts = {}

    for case in all_cases:
        category_counts[case.category] = (
            category_counts.get(case.category, 0) + 1
        )

    # Cases grouped by classification
    classification_counts = {}

    for case in all_cases:
        classification_counts[case.classification] = (
            classification_counts.get(case.classification, 0) + 1
        )

    # Commitments grouped by action type
    action_type_counts = {}

    for item in all_items:
        action_type_counts[item.action_type] = (
            action_type_counts.get(item.action_type, 0) + 1
        )

    # Community service hours
    service_items = [
        item for item in all_items
        if item.action_type == "Community Service"
    ]

    service_required_hours = sum(
        item.required_hours for item in service_items
    )

    service_completed_hours = sum(
        item.verified_hours for item in service_items
    )

    service_remaining_hours = max(
        0, service_required_hours - service_completed_hours
    )

    # Overall completion percentage
    completion_percentage = (
        counts.get("Completed", 0) / len(all_items) * 100
        if all_items else 0
    )

    db.session.commit()

    return render_template(
        "reports.html",
        counts=counts,
        case_status_counts=case_status_counts,
        category_counts=category_counts,
        classification_counts=classification_counts,
        action_type_counts=action_type_counts,
        cases_count=len(all_cases),
        students_count=len(all_students),
        items_count=len(all_items),
        service_required_hours=round(service_required_hours, 2),
        service_completed_hours=round(service_completed_hours, 2),
        service_remaining_hours=round(service_remaining_hours, 2),
        completion_percentage=round(completion_percentage, 1)
    )




# =========================
# USER ACCOUNT MANAGEMENT
# =========================

@app.route("/users", methods=["GET", "POST"])
@roles_required("Administrator")
def users():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()

        # Validate username
        if not is_valid_text(username, 40):
            flash(
                "Username is required and must not exceed 40 characters.",
                "danger"
            )

        # Validate full name
        elif not is_valid_text(full_name, 140):
            flash(
                "Full name is required and must not exceed 140 characters.",
                "danger"
            )

        # Validate password
        elif (
            not password
            or len(password) < 12
            or len(password.encode("utf-8")) > 1024
        ):
            flash(
                "Password must be at least 12 characters and within the allowed length.",
                "danger"
            )

        # Validate role
        elif role not in ROLES:
            flash("Please select a valid user role.", "danger")

        # Check duplicate username
        elif User.query.filter(
            func.lower(User.username) == username
        ).first():
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

    # Prevent administrators from deactivating themselves
    if user.id == current_user().id:
        flash(
            "You cannot deactivate your own account.",
            "warning"
        )

    # Prevent deactivating the last active administrator
    elif user.active and user.role == "Administrator":
        active_admins = User.query.filter_by(
            role="Administrator",
            active=True
        ).count()

        if active_admins <= 1:
            flash(
                "You cannot deactivate the last active Administrator account.",
                "warning"
            )
        else:
            user.active = False

            audit("Deactivated user account", "User", user.id)
            db.session.commit()

            flash("Account deactivated.", "success")

    else:
        user.active = not user.active

        action = (
            "Activated user account"
            if user.active
            else "Deactivated user account"
        )

        audit(action, "User", user.id)
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
