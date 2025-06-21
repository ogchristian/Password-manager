import os
import subprocess
import atexit
import secrets
import base64
from datetime import datetime, timedelta, timezone
from functools import wraps
import csv, io
from flask import Response

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    g,
    send_file,
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required as flask_login_required,
    UserMixin,
    current_user,
)
from flask_dance.contrib.google import make_google_blueprint, google
from flask_talisman import Talisman
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.engine import make_url
from cryptography.fernet import Fernet
import bcrypt
import pyotp
import qrcode

# ------------------------------------------------------------------------------
# App Initialization
# ------------------------------------------------------------------------------

app = Flask(__name__)
load_dotenv()

app.secret_key = os.getenv("SECRET_KEY")
fernet_key = os.getenv("FERNET_KEY")
if not fernet_key:
    raise ValueError("FERNET_KEY is missing from .env")
cipher_suite = Fernet(fernet_key)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# OAuth transport (insecure for debugging)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

#app.config.update({
 #   "SESSION_COOKIE_SECURE": True,
  #  "SESSION_COOKIE_HTTPONLY": True,
  #  "SESSION_COOKIE_SAMESITE": "Lax",
# secure prodution version

# ------------------------------------------------------------------------------
# Mail Configuration
# ------------------------------------------------------------------------------

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")
mail = Mail(app)

# ------------------------------------------------------------------------------
# Extensions Initialization
# ------------------------------------------------------------------------------

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
csrf.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.session_protection = "strong"

# Uncomment and configure Talisman for production CSP
# Talisman(app, content_security_policy={
#     "default-src": "'self'",
#     "script-src": "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.datatables.net",
#     "style-src": "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.datatables.net",
#     "font-src": "'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
#     "img-src": "* data:",
#     "connect-src": "'self'"
# })

brand_name = "Password manager"

# ------------------------------------------------------------------------------
# Google OAuth Configuration
# ------------------------------------------------------------------------------

app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
    ],
    redirect_to="google_login_success",
)
app.register_blueprint(google_bp, url_prefix="/login")

# ------------------------------------------------------------------------------
# Models
# ------------------------------------------------------------------------------

class Notes(db.Model, UserMixin):
    __tablename__ = "notes"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.String(35), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "created_at": self.created_at,
            "created_by": decrypt_value(self.created_by),
            "title": decrypt_value(self.title),
            "content": decrypt_value(self.content)
            
        }

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    subscription_end_date = db.Column(db.DateTime, nullable=True)
    online_status = db.Column(db.Boolean, default=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean, default=False)
    disabled = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(32), nullable=True)
    google_id = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def set_email(self, email):
        normalized = email.strip().lower()
        self.email = encrypt_value(normalized)

    def get_decrypted_email(self):
        try:
            return decrypt_value(self.email)
        except Exception:
            return "[Invalid or Unreadable Email]"
        
    def set_google_id(self, google_id):
        normalized = google_id.strip().lower()
        self.google_id = encrypt_value(normalized)

    def get_decrypted_google_id(self):
        try:
            return decrypt_value(self.google_id)
        except Exception:
            return "[Invalid or Unreadable google_id]"
        
    def check_password(self, password):
        return bcrypt.checkpw(password.encode("utf-8"), self.password.encode("utf-8"))


class Password(db.Model):
    __tablename__ = "passwords"

    id = db.Column(db.Integer, primary_key=True)
    servicename = db.Column(db.String(100), nullable=False)
    webaddress = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "servicename": decrypt_value(self.servicename),
            "webaddress": decrypt_value(self.webaddress),
            "username": decrypt_value(self.username),
            "password": decrypt_value(self.password),
            "created_at": self.created_at,
            "user_id": self.user_id,
        }


class SupportTicket(db.Model):
    __tablename__ = "support_tickets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    _subject = db.Column("subject", db.Text, nullable=False)
    status = db.Column(db.String(20), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="tickets")
    messages = db.relationship("TicketMessage", backref="ticket", cascade="all, delete-orphan")

    @property
    def subject(self):
        return decrypt_value(self._subject)

    @subject.setter
    def subject(self, val):
        self._subject = encrypt_value(val)


class TicketMessage(db.Model):
    __tablename__ = "ticket_messages"

    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("support_tickets.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    _message = db.Column("message", db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User")

    @property
    def message(self):
        return decrypt_value(self._message)

    @message.setter
    def message(self, val):
        self._message = encrypt_value(val)

# ------------------------------------------------------------------------------
# Utility Functions
# ------------------------------------------------------------------------------


def encrypt_value(value: str) -> str:
    return cipher_suite.encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    return cipher_suite.decrypt(value.encode()).decode()


def format_subscription_date(date_obj):
    if date_obj:
        return date_obj.strftime("%Y-%m-%d")
    return "No Subscription"


def send_email(to: str, subject: str, body: str):
    msg = Message(subject=subject, recipients=[to], body=body, sender=app.config["MAIL_USERNAME"])
    try:
        mail.send(msg)
    except Exception as e:
        import traceback

        traceback.print_exc()
        app.logger.error(f"Error sending email to {to}: {e}", exc_info=True)
        print(f"Error sending email to {to}: {e}")  # No exc_info here
        raise

@app.route("/test_email")
def test_email():
    try:
        send_email(app.config["MAIL_USERNAME"], "Test Email", "This is a test from Flask.")
        return "Email sent!"
    except Exception as e:
        return f"Failed to send: {str(e)}", 500


# ------------------------------------------------------------------------------
# Authentication & Authorization Decorators
# ------------------------------------------------------------------------------


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("You need to log in first.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def email_confirmed_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get("user_id"))
        if not user or not user.email_confirmed:
            flash("Please confirm your email to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.admin or current_user.disabled:
            flash("Admin access is required to view this page.", "error")
            return redirect(url_for("passmgr"))
        return f(*args, **kwargs)

    return decorated_function


def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.endpoint == "pricing":
            return f(*args, **kwargs)
        if not current_user.is_authenticated or not check_and_update_subscription():
            flash("A valid subscription is required to access this page.", "error")
            return redirect(url_for("pricing"))
        return f(*args, **kwargs)

    return decorated_function


def check_and_update_subscription():
    if current_user.is_authenticated and not current_user.disabled:
        if current_user.subscription_end_date:
            sub_end = current_user.subscription_end_date
            if sub_end.tzinfo is None:
                sub_end = sub_end.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > sub_end:
                flash("Your subscription has expired. Please renew to access subscription-only features.", "warning")
                return False
        else:
            flash("Subscription information is missing.", "warning")
            return False
    return True


# ------------------------------------------------------------------------------
# Session & User Status Checks
# ------------------------------------------------------------------------------


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_request
def session_timeout_check():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=40)

    last_activity = session.get("last_login")
    try:
        if last_activity:
            if isinstance(last_activity, str):
                last_activity = datetime.fromisoformat(last_activity)
            if datetime.now(timezone.utc) > last_activity + timedelta(minutes=40):
                logout_user()
                session.clear()
                flash("Your session has expired. Please log in again.", "info")
                return redirect(url_for("login"))
        else:
            if "last_login" not in session:
                session["last_login"] = datetime.now(timezone.utc).isoformat()

        if "last_login" not in session:
            session["last_login"] = datetime.now(timezone.utc).isoformat()
    except Exception:
        session.clear()
        flash("An error occurred with session management. Please log in again.", "error")
        return redirect(url_for("login"))


@app.before_request
def log_routes():
    print(f"Visiting: {request.path}")


@app.before_request
def check_user_status():
    if current_user.is_authenticated:
        user = User.query.get(current_user.id)
        if not user or user.disabled:
            flash("Your account has been disabled or deleted. You have been logged out.", "warning")
            logout_user()
            session.clear()
            return redirect(url_for("login"))


@app.before_request
def inject_admin_status():
    g.is_admin = current_user.is_authenticated and current_user.admin


@app.context_processor
def inject_email():
    if current_user.is_authenticated:
        try:
            user = User.query.get(current_user.id)
            return {"email": user.get_decrypted_email()}
        except Exception:
            return {"email": None}
    return {"email": None}


@app.context_processor
def inject_subscription_status():
    if current_user.is_authenticated:
        sub_end = current_user.subscription_end_date
        if sub_end:
            if sub_end.tzinfo is None:
                sub_end = sub_end.replace(tzinfo=timezone.utc)
            return {"has_subscription": sub_end >= datetime.now(timezone.utc)}
    return {"has_subscription": False}


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Invalid CSRF token. Please try again.", "error")
    return redirect(url_for("login")), 400


# ------------------------------------------------------------------------------
# User & Auth Routes
# ------------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("login.html", brand_name=brand_name)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        existing_user = next(
            (u for u in User.query.all() if decrypt_value(u.email) == email), None
        )
        if existing_user:
            flash("An account with this email already exists.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        new_user = User()
        new_user.set_email(email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        session["user_id"] = new_user.id
        session["email"] = new_user.email
        session.permanent = True
        new_user.last_login = datetime.now(timezone.utc)
        new_user.online_status = True
        db.session.commit()

        return redirect(url_for("twofa_setup"))

    return render_template("register.html", brand_name=brand_name)


@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        email = decrypt_value(token)
        user = next((u for u in User.query.all() if decrypt_value(u.email) == email), None)
        if user:
            user.email_confirmed = True
            db.session.commit()
            flash("Email confirmed successfully.", "success")
        else:
            flash("Invalid confirmation link.", "error")
    except Exception:
        flash("Invalid confirmation link.", "error")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = next((u for u in User.query.all() if decrypt_value(u.email) == email), None)

        if user and user.check_password(password):
            if not user.totp_secret:
                login_user(user)
                session["user_id"] = user.id
                session["email"] = user.email
                session.permanent = True
                user.last_login = datetime.now(timezone.utc)
                user.online_status = True
                db.session.commit()
                return redirect(url_for("twofa_setup"))

            session["pre_2fa_user_id"] = user.id
            flash("Login successful, redirecting!", "success")
            return redirect(url_for("twofa_challenge"))

        flash("Invalid email or password.", "error")

    return render_template("login.html", brand_name=brand_name)


@app.route("/logout")
def logout():
    user = User.query.get(session.get("user_id"))
    if user:
        user.online_status = False
        db.session.commit()
        logout_user()
    session.clear()
    flash("You have been logged out for inactivity!", "info")
    return redirect(url_for("login"))


# ------------------------------------------------------------------------------
# Password Reset Routes
# ------------------------------------------------------------------------------


@app.route("/reset_pass", methods=["GET", "POST"])
def reset_pass():
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            flash("Please enter your email address.", "error")
            return redirect(url_for("reset_pass"))

        user = next((u for u in User.query.all() if decrypt_value(u.email) == email), None)
        if user:
            token = encrypt_value(email)
            reset_url = url_for("reset_pass_confirm", token=token, _external=True)
            try:
                send_email(email, "Reset Your Password", f"Click here to reset: {reset_url}")
                flash("Password reset link sent to your email.", "success")
            except Exception:
                flash("Could not send reset email. Try again later!", "error")
        else:
            flash("Email not found!", "error")

        return redirect(url_for("reset_pass"))

    return render_template("reset.html", brand_name=brand_name)


@app.route("/reset_pass_confirm/<token>", methods=["GET", "POST"])
def reset_pass_confirm(token):
    try:
        email = decrypt_value(token)
        user = next((u for u in User.query.all() 
      if decrypt_value(u.email) == email), None)
        if request.method == "POST":
            password = request.form["password"]
            confirm_password = request.form["confirm_password"]

            if password != confirm_password:
                flash("Passwords do not match.", "error")
                return redirect(request.url)

            user.set_password(password)
            db.session.commit()
            flash("Password reset successfully.", "success")
            return redirect(url_for("login"))
    except Exception:
        flash("Invalid reset link.", "error")
        return redirect(url_for("reset_pass"))

    return render_template("changepass.html", brand_name=brand_name)


@app.route("/changepass")
def changepass():
    user = User.query.get(current_user.id)
    if user.get_decrypted_google_id():
        flash("Password changes must be made through your Google Account.", "warning")
        return redirect(url_for("settings"))
    return render_template("changepass.html", brand_name=brand_name)


# ------------------------------------------------------------------------------
# Two-Factor Authentication Routes
# ------------------------------------------------------------------------------


def generate_qr_code_base64(uri: str) -> str:
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")


@app.route("/2fa/setup")
@login_required
def twofa_setup():
    if not current_user.totp_secret:
        secret = pyotp.random_base32()
        current_user.totp_secret = secret
        db.session.commit()
    else:
        secret = current_user.totp_secret

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.email, issuer_name="PasswordManager")
    qr_code = generate_qr_code_base64(uri)
    return render_template("twofa_setup.html", qr_code=qr_code, secret=secret)


@app.route("/2fa/challenge", methods=["GET", "POST"])
def twofa_challenge():
    user_id = session.get("pre_2fa_user_id")
    if not user_id:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if request.method == "POST":
        token = request.form.get("token")
        if user and pyotp.TOTP(user.totp_secret).verify(token):
            login_user(user)
            session["user_id"] = user.id
            session["email"] = user.email
            session["last_login"] = user.last_login
            session.permanent = True
            user.last_login = datetime.now(timezone.utc)
            user.online_status = True
            db.session.commit()
            session.pop("pre_2fa_user_id", None)
            return redirect(url_for("passmgr"))
        else:
            flash("Invalid 2FA token. Try again.", "error")

    return render_template("twofa_challenge.html", brand_name=brand_name)


@app.route("/google-login-success")
def google_login_success():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "error")
        return redirect(url_for("login"))

    user_info = resp.json()
    email = user_info["email"]
    google_id = user_info["id"]

    user = next((u for u in User.query.all() if decrypt_value(u.email) == email), None)
    if not user:
        random_password = secrets.token_hex(16)
        user = User(email=email, email_confirmed=True, google_id=google_id)
        user.set_google_id(google_id)
        user.set_email(email)
        user.set_password(random_password)
        db.session.add(user)
        db.session.commit()

    else:
        user.google_id = google_id
        db.session.commit()

    login_user(user)
    session["user_id"] = user.id
    session["email"] = user.email
    session.permanent = True
    user.last_login = datetime.now(timezone.utc)
    user.online_status = True
    db.session.commit()

    flash("Login successful!", "success")
    return redirect(url_for("passmgr"))

# ------------------------------------------------------------------------------
# User Settings & Profile Routes
# ------------------------------------------------------------------------------


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = User.query.get(current_user.id)

    if request.method == "POST":
        
        email = request.form["email"].strip().lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if user.get_decrypted_google_id():
            flash("Google login users cannot change email or password through this form.", "error")
            return redirect(url_for("settings"))

        if not (password and password.strip() or confirm_password and confirm_password.strip()):
            flash("Password cannot be empty!", "error")
            return redirect(url_for("settings"))

        if email.endswith("@gmail.com"):
            flash("Gmail addresses cannot be changed.", "warning")
            return redirect(url_for("settings"))

        if email != decrypt_value(user.email):
            if User.query.filter_by(email=encrypt_value(email)).first():
                flash("Email is already in use.", "error")
                return redirect(url_for("settings"))

            code = secrets.token_hex(3)
            session["pending_email"] = email
            session["verification_code"] = code
            send_email(email, "Verify Your New Email", f"Your verification code is: {code}")
            flash("A verification code has been sent to your new email.", "success")
            return redirect(url_for("verify_email"))

        if password and password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for("settings"))

        if email:
            user.set_email(email)
        if password:
            user.set_password(password)

        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", brand_name=brand_name, email=user.get_decrypted_email())


@app.route("/verify_email", methods=["GET", "POST"])
@login_required
def verify_email():
    if request.method == "POST":
        entered_code = request.form.get("verification_code")
        if entered_code == session.get("verification_code"):
            user = User.query.get(current_user.id)
            user.set_email(session.get("pending_email"))
            db.session.commit()
            session.pop("pending_email", None)
            session.pop("verification_code", None)
            flash("Email updated successfully.", "success")
            return redirect(url_for("settings"))
        else:
            flash("Invalid verification code.", "error")

    return render_template("verify_email.html", brand_name=brand_name)


@app.route("/resend_verification", methods=["POST"])
@login_required
@csrf.exempt
def resend_verification():
    email = session.get("pending_email")
    code = session.get("verification_code")
    if email and code:
        send_email(email, "Verify Your New Email", f"Your verification code is: {code}")
        return jsonify({"message": "Code resent"}), 200
    return jsonify({})


# ------------------------------------------------------------------------------
# Public Pages
# ------------------------------------------------------------------------------


@app.route("/tos")
def tos():
    return render_template("tos.html", brand_name=brand_name)


@app.route("/pricing")
@login_required
def pricing():
    return render_template("pricing.html", brand_name=brand_name)


@app.route("/export", methods=["GET"])
@login_required
@subscription_required
def export_csv():
    # Query all passwords
    pwds = Password.query.all()

    # Write CSV into an in-memory string buffer
    buf = io.StringIO()
    writer = csv.writer(buf)
    # Header row — adjust to your field names
    writer.writerow(["servicename", "webaddress", "username", "password"])
    # Data rows
    for p in pwds:
        writer.writerow([p.servicename, p.webaddress, p.username, p.password])

    # Build response
    buf.seek(0)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=passwords.csv"
        }
    )

@app.route("/passmgr")
@login_required
@subscription_required
def passmgr():
    return render_template("passmgr.html", brand_name=brand_name)


@app.route("/notesmgr")
@login_required
@subscription_required
def notesmgr():
    return render_template("notesmgr.html", brand_name=brand_name)


@app.route("/reset")
def reset():
    return render_template("reset.html", brand_name=brand_name)


# ------------------------------------------------------------------------------
# API: User Management (Admin)
# ------------------------------------------------------------------------------


@app.route("/mgusers")
@login_required
@admin_required
def mgusers():
    return render_template("mgusers.html", brand_name=brand_name)


@app.route("/api/mgusers", methods=["GET"])
@login_required
@admin_required
def api_mgusers():
    users = User.query.all()
    return jsonify(
        [
            {
                "id": user.id,
                "email": user.get_decrypted_email(),
                "subscription_end_date": format_subscription_date(user.subscription_end_date),
                "email_confirmed": user.email_confirmed,
                "admin": user.admin,
                "disabled": user.disabled,
            }
            for user in users
        ]
    )


@app.route("/api/mgusers/extend/<int:user_id>", methods=["POST"])
@csrf.exempt
@login_required
@admin_required
def extend_subscription(user_id):
    days = request.json.get("days")
    if not days:
        return jsonify({"error": "Missing 'days' parameter"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    sub_end = user.subscription_end_date
    now = datetime.now(timezone.utc)
    if sub_end:
        if sub_end.tzinfo is None:
            sub_end = sub_end.replace(tzinfo=timezone.utc)
        if sub_end > now:
            user.subscription_end_date = sub_end + timedelta(days=int(days))
        else:
            user.subscription_end_date = now + timedelta(days=int(days))
    else:
        user.subscription_end_date = now + timedelta(days=int(days))

    db.session.commit()
    return jsonify({"message": "Subscription extended successfully"})


@app.route("/admin/users", methods=["GET"])
@login_required
@admin_required
def api_get_users():
    users = User.query.all()
    return jsonify(
        [
            {
                "id": user.id,
                "email": user.email,
                "subscription_end_date": format_subscription_date(user.subscription_end_date),
                "email_confirmed": user.email_confirmed,
                "admin": user.admin,
            }
            for user in users
        ]
    )


@app.route("/admin/users", methods=["POST"])
@login_required
@admin_required
def api_add_user():
    data = request.get_json()
    email = data["email"]
    password = data["password"]
    confirm_password = data["confirm_password"]
    admin = data.get("admin", False)
    duration_days = int(data.get("duration", 0))

    if password != confirm_password:
        flash("Passwords do not match!", "error")
        return jsonify({"error": "Passwords do not match"}), 400

    subscription_end_date = datetime.now(timezone.utc) + timedelta(days=duration_days)
    new_user = User(email=email, admin=admin, subscription_end_date=subscription_end_date)
    new_user.set_email(email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    flash("User added successfully!", "success")
    return jsonify({"message": "User added successfully"}), 201


@app.route("/admin/users/<int:user_id>", methods=["GET"])
@login_required
@admin_required
def api_get_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.subscription_end_date:
        today = datetime.now(timezone.utc).date()
        if today > user.subscription_end_date.date():
            subscription_status = "Expired"
        else:
            subscription_status = user.subscription_end_date.strftime("%Y-%m-%d")
    else:
        subscription_status = "No subscription"

    return jsonify(
        {
            "id": user.id,
            "email": user.email,
            "subscription_expiry": subscription_status,
            "admin": user.admin,
        }
    )


@app.route("/admin/users/<int:user_id>", methods=["PUT"])
@login_required
@admin_required
def api_update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    if "email" in data:
        user.email = data["email"]
    if "admin" in data:
        user.admin = data["admin"]
    if "duration" in data and int(data["duration"]) > 0:
        duration_days = int(data["duration"])
        user.subscription_end_date = datetime.now(timezone.utc) + timedelta(days=duration_days)
    db.session.commit()
    flash("User updated successfully!", "success")
    return jsonify({"message": "User updated successfully"})


@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
@admin_required
def api_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully!", "success")
    return jsonify({"message": "User deleted successfully"})


@app.route("/admin/users/<int:user_id>/toggle_disable", methods=["POST"])
@csrf.exempt
@login_required
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    user.disabled = not user.disabled
    db.session.commit()
    status = "disabled" if user.disabled else "enabled"
    flash("User has been {status}.", "success")
    return jsonify({"message": f"User has been {status}."})


@app.route("/admin/users/<int:user_id>/send_reset_link", methods=["POST"])
@csrf.exempt
@login_required
@admin_required
def send_admin_reset_link(user_id):
    user = User.query.get_or_404(user_id)
    token = encrypt_value(user.email)
    reset_url = url_for("changepass", token=token, _external=True)
    try:
        if user:
            decrypted_email = user.get_decrypted_email()
            send_email(decrypted_email, "Admin-Initiated Password Reset", 
                       f"Click here to reset: {reset_url}")
            flash("Reset link sent to user email.", "success")
            return jsonify({"message": "Reset link sent to user email."}), 200
        else: 
            return jsonify({"message": "Error user not found!"}), 500
        
    except Exception as e:
        flash("Error:", "error")
        return jsonify({"error": str(e)}), 500
    
# ------------------------------------------------------------------------------
# API: Notes Management
# ------------------------------------------------------------------------------



@app.route("/api/notes", methods=["GET"])
@csrf.exempt
@login_required
def get_notes():
    notes = Notes.query.all()
    return jsonify([n.to_dict() for n in notes])


@app.route("/api/notes/<int:note_id>", methods=["GET"])
@login_required
def get_note(note_id):
    with Session(db.engine) as session:
        note = session.get(Notes, note_id)
        if not note:
            flash("Notes not found!", "error")
            return jsonify({"error": "Notes not found"}), 404
        return jsonify(note.to_dict())


@app.route("/api/notes", methods=["POST"])
@csrf.exempt
@login_required
def create_note():
    data = request.json
    if not all(k in data for k in ("title", "created_at", "created_by", "content")):
        flash("Missing required fields.", "error")
        return jsonify({"error": "Missing required fields."}), 400

    new_note = Notes(
        title = encrypt_value(data["title"]),
        created_at = data["created_at"],
        created_by = data["created_by"],
        content = encrypt_value(data["content"]),
        user_id=current_user.id,
    )
    db.session.add(new_note)
    db.session.commit()

    flash("Note created successfully.", "success")
    return jsonify({"message": "Note created successfully.", "note": new_note.to_dict()}), 201


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
@csrf.exempt
@login_required
def update_note(note_id):
    with Session(db.engine) as session:
        note_obj = session.get(Notes, note_id)
        if not note_obj:
            flash("Note not found!", "error")
            return jsonify({"error": "Note not found!"}), 404

        data = request.json
        if not all(k in data for k in ("title", "created_at", "created_by", "content")):
            flash("Missing required fields!", "error")
            return jsonify({"error": "Missing required fields!"}), 400

        note_obj.title = encrypt_value(data["title"])
        note_obj.created_at = data["created_at"]
        note_obj.created_by = data["created_by"]
        note_obj.content = encrypt_value(data["content"])
        session.commit()

        flash("Note updated successfully.", "success")
        return jsonify({"message": "Note updated successfully", "content": note_obj.to_dict()})


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@login_required
@csrf.exempt
def delete_note(note_id):
    with Session(db.engine) as session:
        note_obj = session.get(Notes, note_id)
        if not note_obj:
            flash("Note not found!", "error")
            return jsonify({"error": "Note not found!"}), 404

        session.delete(note_obj)
        session.commit()
        flash("Note deleted successfully.", "success")
        return jsonify({"message": "Note deleted successfully"})

# ------------------------------------------------------------------------------
# API: Password Management
# ------------------------------------------------------------------------------

@app.route("/api/passwords", methods=["GET"])
@csrf.exempt
@login_required
def get_passwords():
    passwords = Password.query.all()
    return jsonify([p.to_dict() for p in passwords])


@app.route("/api/passwords/<int:password_id>", methods=["GET"])
@login_required
def get_password(password_id):
    with Session(db.engine) as session:
        password = session.get(Password, password_id)
        if not password:
            flash("Passwords not found!", "error")
            return jsonify({"error": "Password not found"}), 404
        return jsonify(password.to_dict())


@app.route("/api/passwords", methods=["POST"])
@csrf.exempt
@login_required
def create_password():
    data = request.json
    if not all(k in data for k in ("servicename", "webaddress", "username", "password")):
        flash("Missing required fields.", "error")
        return jsonify({"error": "Missing required fields."}), 400

    new_password = Password(
        servicename=encrypt_value(data["servicename"]),
        webaddress=encrypt_value(data["webaddress"]),
        username=encrypt_value(data["username"]),
        password=encrypt_value(data["password"]),
        user_id=current_user.id,
    )
    db.session.add(new_password)
    db.session.commit()

    flash("Password created successfully.", "success")
    return jsonify({"message": "Password created successfully.", "password": new_password.to_dict()}), 201


@app.route("/api/passwords/<int:password_id>", methods=["PUT"])
@csrf.exempt
@login_required
def update_password(password_id):
    with Session(db.engine) as session:
        password_obj = session.get(Password, password_id)
        if not password_obj:
            flash("Password not found!", "error")
            return jsonify({"error": "Password not found!"}), 404

        data = request.json
        if not all(k in data for k in ("servicename", "webaddress", "username", "password")):
            flash("Missing required fields!", "error")
            return jsonify({"error": "Missing required fields!"}), 400

        password_obj.servicename = encrypt_value(data["servicename"])
        password_obj.webaddress = encrypt_value(data["webaddress"])
        password_obj.username = encrypt_value(data["username"])
        password_obj.password = encrypt_value(data["password"])
        session.commit()

        flash("Password updated successfully.", "success")
        return jsonify({"message": "Password updated successfully", "password": password_obj.to_dict()})


@app.route("/api/passwords/<int:password_id>", methods=["DELETE"])
@login_required
@csrf.exempt
def delete_password(password_id):
    with Session(db.engine) as session:
        password_obj = session.get(Password, password_id)
        if not password_obj:
            flash("Password not found!", "error")
            return jsonify({"error": "Password not found!"}), 404

        session.delete(password_obj)
        session.commit()
        flash("Password deleted successfully.", "success")
        return jsonify({"message": "Password deleted successfully"})


# ------------------------------------------------------------------------------
# Support Ticket Routes (User)
# ------------------------------------------------------------------------------


@app.route("/support", methods=["GET", "POST"])
@login_required
def view_tickets():
    if request.method == "POST":
        last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_ticket_count = SupportTicket.query.filter(
            SupportTicket.user_id == current_user.id,
            SupportTicket.created_at >= last_24h,
        ).count()

        if recent_ticket_count >= 2:
            flash("You can only create 2 support tickets every 24 hours.", "warning")
            return redirect(url_for("view_tickets"))

        subject = request.form.get("subject", "").strip()
        message = request.form.get("message", "").strip()

        if not subject or not message:
            flash("Subject and message are required.", "error")
            return redirect(url_for("view_tickets"))

        if len(subject) > 100:
            flash("Subject must be 100 characters or fewer.", "error")
            return redirect(url_for("view_tickets"))

        if len(message) > 1000:
            flash("Message must be 1000 characters or fewer.", "error")
            return redirect(url_for("view_tickets"))

        new_ticket = SupportTicket(user_id=current_user.id, subject=subject)
        db.session.add(new_ticket)
        db.session.commit()

        msg = TicketMessage(ticket_id=new_ticket.id, user_id=current_user.id, message=message)
        db.session.add(msg)
        db.session.commit()

        flash("Your ticket has been submitted.", "success")
        return redirect(url_for("view_tickets"))

    tickets = SupportTicket.query.filter_by(user_id=current_user.id).order_by(SupportTicket.created_at.desc()).all()
    return render_template("tickets.html", tickets=tickets, brand_name=brand_name)


@app.route("/ticket/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def view_ticket_thread(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)

    if current_user.id != ticket.user_id and not current_user.admin:
        flash("You are not authorized to view this ticket.", "error")
        return redirect(url_for("view_tickets"))

    if request.method == "POST":
        if ticket.status == "Closed":
            flash("This ticket is closed and cannot be replied to.", "warning")
            return redirect(url_for("view_ticket_thread", ticket_id=ticket.id))

        message = request.form.get("message")
        if message:
            new_msg = TicketMessage(ticket_id=ticket.id, user_id=current_user.id, message=message)
            db.session.add(new_msg)
            db.session.commit()
            flash("Message sent!", "success")
            return redirect(url_for("view_ticket_thread", ticket_id=ticket.id))

    return render_template("ticket_thread.html", ticket=ticket, brand_name=brand_name)


# ------------------------------------------------------------------------------
# Support Ticket Routes (Admin)
# ------------------------------------------------------------------------------


@app.route("/admin/tickets")
@login_required
@admin_required
def admin_tickets():
    tickets = SupportTicket.query.order_by(SupportTicket.created_at.desc()).all()
    return render_template("admin_tickets.html", tickets=tickets, brand_name=brand_name)


@app.route("/admin/tickets/<int:ticket_id>", methods=["GET", "POST"])
@login_required
@admin_required
def respond_ticket(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)

    if request.method == "POST":
        ticket.response = request.form["response"]
        db.session.commit()
        flash("Response submitted.", "success")
        return redirect(url_for("admin_tickets"))

    return render_template("respond_ticket.html", ticket=ticket, brand_name=brand_name)


@app.route("/admin/tickets/<int:ticket_id>/close", methods=["POST"])
@login_required
@admin_required
def close_ticket(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    ticket.status = "Closed"
    db.session.commit()
    flash("Ticket marked as closed.", "info")
    return redirect(url_for("admin_tickets"))


@app.route("/admin/tickets/<int:ticket_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_ticket(ticket_id):
    ticket = SupportTicket.query.get_or_404(ticket_id)
    db.session.delete(ticket)
    db.session.commit()
    flash("Ticket deleted.", "success")
    return redirect(url_for("admin_tickets"))


@login_required 
@admin_required
@app.route("/mglogs", methods=["GET"])
def mglogs():
    logs = TicketMessage.query.order_by(TicketMessage.timestamp.desc()).all()
    return render_template("mglogs.html", brand_name=brand_name, logs=logs)


@app.route("/test", methods=["GET"])
def test():
    return render_template("test.html", brand_name=brand_name)


@app.route("/home", methods=["GET"])
def home():
    return render_template("home.html", brand_name=brand_name)


# ------------------------------------------------------------------------------
# Run Application
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)