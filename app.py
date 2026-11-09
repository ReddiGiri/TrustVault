
import os

from sqlalchemy.engine import URL
from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask_wtf.csrf import CSRFProtect

from extensions import db, login_manager

from models.user import User
from models.document import Document
from models.permission import Permission
from models.audit_log import AuditLog

from routes.admin import admin_bp
from routes.documents import documents_bp


# --------------------------------------------------
# LOAD ENVIRONMENT VARIABLES
# --------------------------------------------------

load_dotenv()


# --------------------------------------------------
# INITIALIZE FLASK APPLICATION
# --------------------------------------------------

app = Flask(__name__)


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "SECRET_KEY is missing. Configure it in Render Environment."
    )


# DATABASE CONFIGURATION

db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT", "3306")
db_name = os.getenv("DB_NAME")

if not all([db_user, db_password, db_host, db_name]):
    raise RuntimeError(
        "Database configuration missing. Check Render Environment variables."
    )

app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
    drivername="mysql+pymysql",
    username=db_user,
    password=db_password,
    host=db_host,
    port=int(db_port),
    database=db_name
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# --------------------------------------------------
# FILE UPLOAD CONFIGURATION
# --------------------------------------------------

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(
    app.root_path,
    "private_uploads"
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# --------------------------------------------------
# SESSION SECURITY
# --------------------------------------------------

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("COOKIE_SECURE", "true").lower() == "true"
)


# --------------------------------------------------
# CSRF PROTECTION
# --------------------------------------------------

csrf = CSRFProtect(app)


# --------------------------------------------------
# INITIALIZE EXTENSIONS
# --------------------------------------------------

db.init_app(app)

login_manager.init_app(app)
login_manager.login_view = "login"


# --------------------------------------------------
# REGISTER BLUEPRINTS
# --------------------------------------------------

app.register_blueprint(documents_bp)
app.register_blueprint(admin_bp)


# --------------------------------------------------
# CREATE MISSING DATABASE TABLES
# --------------------------------------------------

with app.app_context():
    try:
        db.create_all()
        app.logger.info(
            "Database tables checked/created successfully."
        )
    except Exception:
        db.session.rollback()
        app.logger.exception(
            "Database table initialization failed."
        )


# --------------------------------------------------
# LOAD LOGGED-IN USER
# --------------------------------------------------

@login_manager.user_loader
def load_user(user_id):

    try:
        return db.session.get(User, int(user_id))

    except (ValueError, TypeError):
        return None


# --------------------------------------------------
# HOME ROUTE
# --------------------------------------------------

@app.route("/")
def home():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# --------------------------------------------------
# REGISTRATION ROUTE
# --------------------------------------------------


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "").upper()

        if not name or not email or not password or not role:
            flash("Please fill all required fields.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        # Only OWNER and VIEWER registration allowed
        if role not in ("OWNER", "VIEWER"):
            flash("Invalid role selected.")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:
            flash("Email already registered.")
            return redirect(url_for("register"))

        new_user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            role=role
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            flash("Registration successful. Please login.")
            return redirect(url_for("login"))

        except Exception:
            db.session.rollback()
            app.logger.exception("Registration failed.")
            flash("Registration failed. Please try again.")
            return redirect(url_for("register"))

    return render_template("register.html")

# --------------------------------------------------
# LOGIN ROUTE
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        try:
            user = User.query.filter_by(email=email).first()

            if user and check_password_hash(
                user.password_hash,
                password
            ):
                login_user(user)
                flash("Login successful.")
                return redirect(url_for("dashboard"))

            flash("Invalid email or password.")

        except Exception:
            db.session.rollback()
            app.logger.exception("Login database error.")
            flash("Login failed. Please try again later.")

    return render_template("login.html")


# --------------------------------------------------
# DASHBOARD ROUTE
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    if current_user.role == "ADMIN":

        documents = Document.query.order_by(
            Document.created_at.desc()
        ).all()

    else:

        documents = Document.query.filter_by(
            owner_id=current_user.id
        ).order_by(
            Document.created_at.desc()
        ).all()

    return render_template(
        "dashboard.html",
        documents=documents,
        user=current_user
    )


# --------------------------------------------------
# LOGOUT ROUTE
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    logout_user()

    flash("You have been logged out.")

    return redirect(url_for("login"))


# --------------------------------------------------
# DATABASE CONNECTION TEST
# --------------------------------------------------

@app.route("/db-test")
@login_required
def db_test():

    if current_user.role != "ADMIN":
        return "Access denied", 403

    try:
        db.session.execute(db.text("SELECT 1"))

        return "TrustVault database connected successfully!"

    except Exception:
        app.logger.exception("Database connection test failed.")
        return "Database connection failed.", 500


# --------------------------------------------------
# FILE SIZE ERROR HANDLER
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(error):

    flash("File is too large. Maximum allowed size is 10 MB.")

    return redirect(url_for("documents.my_documents"))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )
