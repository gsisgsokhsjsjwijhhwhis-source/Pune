import os
import re
import time
import hmac
import secrets
from urllib.parse import urlsplit
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, g
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ==========================================
# 1. ENVIRONMENT & SECURITY HEADERS
# ==========================================
is_production = bool(os.environ.get('RENDER'))

configured_secret_key = os.environ.get('SECRET_KEY')
if is_production and (
    not configured_secret_key or len(configured_secret_key) < 32
):
    raise RuntimeError(
        "A stable SECRET_KEY of at least 32 characters must be configured in Render."
    )

# Local development may generate an ephemeral key; production must use a stable secret.
app.secret_key = configured_secret_key or secrets.token_hex(32)

# Production data must live in the server-side PostgreSQL database.
# SQLite is allowed only for local development, never as a production fallback.
raw_db_url = os.environ.get('DATABASE_URL', '').strip()
if not raw_db_url:
    if is_production:
        raise RuntimeError("DATABASE_URL must be configured in Render; production SQLite is disabled.")
    raw_db_url = 'sqlite:///registry.db'

if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

# When correcting a Supabase shared-pooler endpoint, this optional override lets
# Render change only the hostname while retaining the password already stored
# in DATABASE_URL. Copy the hostname from Supabase Dashboard > Connect; never
# guess it from the region. We do not log the URL or its credentials.
pooler_host_override = os.environ.get('SUPABASE_POOLER_HOST', '').strip()
if pooler_host_override:
    from sqlalchemy.engine import make_url
    parsed_db_url = make_url(raw_db_url)
    if parsed_db_url.get_backend_name() != 'postgresql':
        raise RuntimeError("SUPABASE_POOLER_HOST requires a PostgreSQL DATABASE_URL.")
    query_params = dict(parsed_db_url.query)
    query_params.setdefault('sslmode', 'require')
    override_port = int(os.environ.get('SUPABASE_DB_PORT', parsed_db_url.port or 5432))
    raw_db_url = parsed_db_url.set(
        host=pooler_host_override,
        port=override_port,
        query=query_params
    ).render_as_string(hide_password=False)
    app.logger.info("Applied configured Supabase pooler hostname override.")

if is_production and not raw_db_url.startswith(('postgresql://', 'postgresql+psycopg2://')):
    raise RuntimeError("Production DATABASE_URL must point to a server-side PostgreSQL database.")

app.config.update(
    SESSION_COOKIE_SECURE=is_production,       # HTTPS only in production
    SESSION_COOKIE_HTTPONLY=True,              # Guard against JavaScript cookie theft
    SESSION_COOKIE_SAMESITE='Lax',             # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=45),
    SQLALCHEMY_DATABASE_URI=raw_db_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=16 * 1024,
    SQLALCHEMY_ENGINE_OPTIONS={'pool_pre_ping': True, 'pool_recycle': 300}
)

# Use shared Redis/Valkey storage in production when configured. The in-memory
# fallback is useful for local development but is not shared between workers.
rate_limit_storage = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://').strip() or 'memory://'
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=rate_limit_storage,
    strategy='fixed-window',
    headers_enabled=True,
    default_limits=[]
)
if is_production and rate_limit_storage == 'memory://':
    app.logger.warning(
        "RATELIMIT_STORAGE_URI is using per-process memory storage. "
        "Configure shared Redis/Valkey storage for consistent limits across workers."
    )

# Enforce OAuth transport security in production
if is_production:
    os.environ.pop('OAUTHLIB_INSECURE_TRANSPORT', None)
else:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

db = SQLAlchemy(app)
oauth = OAuth(app)

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    google = oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )
else:
    google = None

# ==========================================
# 2. DATABASE MODELS
# ==========================================
class AdminSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), default='admin', nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(25), nullable=True)
    is_profile_completed = db.Column(db.Boolean, default=False)
    devices = db.relationship('Device', backref='owner', lazy=True)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(15), unique=True, nullable=False)
    brand = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='NOT_FOR_SALE', nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Database initialization is retried after transient connection failures.
# Do not make Gunicorn exit just because the database is temporarily unavailable.
_DB_INITIALIZED = False
_DB_RETRY_AFTER = 0.0
_DB_RETRY_SECONDS = 10


def initialize_database():
    """Initialize schema and seed an admin only when secure credentials are configured."""
    global _DB_INITIALIZED, _DB_RETRY_AFTER

    if _DB_INITIALIZED:
        return True

    now = time.time()
    if now < _DB_RETRY_AFTER:
        return False

    try:
        with app.app_context():
            db.create_all()
            admin_row = AdminSetting.query.first()
            if not admin_row:
                initial_admin_pass = os.environ.get('INITIAL_ADMIN_PASSWORD')
                initial_admin_user = os.environ.get('INITIAL_ADMIN_USER', 'admin').strip().lower()
                if initial_admin_pass:
                    db.session.add(AdminSetting(
                        username=initial_admin_user,
                        password_hash=generate_password_hash(initial_admin_pass)
                    ))
                    db.session.commit()
                else:
                    # Never create a publicly-known default administrator password.
                    app.logger.warning(
                        "No admin account exists and INITIAL_ADMIN_PASSWORD is not set; "
                        "skipping initial admin creation."
                    )

        _DB_INITIALIZED = True
        _DB_RETRY_AFTER = 0.0
        app.logger.info("Database schema initialization completed.")
        return True
    except SQLAlchemyError:
        _DB_RETRY_AFTER = time.time() + _DB_RETRY_SECONDS
        app.logger.exception(
            "Database initialization failed. The app will serve a temporary 503 "
            "and retry database initialization."
        )
        return False


# Attempt initialization at process startup, but let Gunicorn stay alive if the
# database is unreachable. Requests will retry initialization after a short delay.
initialize_database()


@app.before_request
def set_csp_nonce():
    """Create a fresh nonce for inline scripts on this response."""
    g.csp_nonce = secrets.token_urlsafe(18)


@app.before_request
def ensure_database_is_ready():
    if request.endpoint == 'static':
        return None
    if initialize_database():
        return None
    return (
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Temporarily unavailable</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070709;color:#f5f5f7;font:16px system-ui,sans-serif}
main{max-width:620px;margin:24px;padding:32px;border:1px solid #333;border-radius:16px;background:#111217}
h1{margin-top:0}p{line-height:1.6;color:#c6c7cc}.small{font-size:13px;color:#92949e}
</style></head><body><main>
<h1>Service temporarily unavailable</h1>
<p>The application is running, but its database connection could not be established. No data has been switched or reset.</p>
<p>Please retry shortly. The service will automatically retry the database connection.</p>
<p class="small">If this persists, the deployment administrator must verify the production DATABASE_URL using the database provider's connection settings.</p>
</main></body></html>""",
        503,
        {"Retry-After": str(_DB_RETRY_SECONDS), "Cache-Control": "no-store"}
    )


@app.context_processor
def inject_csrf_token():
    def csrf_token():
        return session.setdefault('_csrf_token', secrets.token_urlsafe(32))

    def csp_nonce():
        return getattr(g, 'csp_nonce', '')

    return {'csrf_token': csrf_token, 'csp_nonce': csp_nonce}


@app.before_request
def protect_state_changing_requests():
    if request.method not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return None

    expected = session.get('_csrf_token')
    submitted = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
    if (
        not isinstance(expected, str)
        or not isinstance(submitted, str)
        or not hmac.compare_digest(expected, submitted)
    ):
        abort(400, description="The form token is missing or expired. Refresh the page and try again.")
    return None


@app.route('/healthz')
def healthz():
    """Dependency-aware readiness endpoint for deployment diagnostics."""
    try:
        db.session.execute(text("SELECT 1"))
        return {"status": "ok"}, 200
    except OperationalError:
        db.session.rollback()
        app.logger.exception("Database health check failed.")
        return {"status": "database_unavailable"}, 503, {"Cache-Control": "no-store"}


@app.errorhandler(OperationalError)
def handle_database_operational_error(error):
    db.session.rollback()
    app.logger.error("Database operation failed; returning 503.", exc_info=True)
    return (
        "The database is temporarily unavailable. Please retry shortly.",
        503,
        {"Retry-After": str(_DB_RETRY_SECONDS), "Cache-Control": "no-store"}
    )


# ==========================================
# 3. RATE LIMITING & INPUT SANITIZATION
# ==========================================
FAILED_LOGIN_LOG = {}

def is_ip_rate_limited(ip):
    record = FAILED_LOGIN_LOG.get(ip)
    if not record:
        return False, 0
    if time.time() < record.get('locked_until', 0):
        remaining_secs = int(record['locked_until'] - time.time())
        return True, remaining_secs
    return False, 0

def record_failed_attempt(ip):
    now = time.time()
    if ip not in FAILED_LOGIN_LOG:
        FAILED_LOGIN_LOG[ip] = {'attempts': 1, 'locked_until': 0}
    else:
        FAILED_LOGIN_LOG[ip]['attempts'] += 1
        if FAILED_LOGIN_LOG[ip]['attempts'] >= 5:
            FAILED_LOGIN_LOG[ip]['locked_until'] = now + 300  # 5-minute lockout

def reset_attempts(ip):
    FAILED_LOGIN_LOG.pop(ip, None)

def get_current_user():
    uid = session.get('user_id')
    return db.session.get(User, uid) if uid else None

def sanitize_text(value, max_len=100):
    """Normalize user text without corrupting legitimate punctuation.

    Jinja auto-escapes template output; input validation is handled by each
    endpoint rather than deleting characters such as apostrophes or ampersands.
    """
    if value is None:
        return ""
    cleaned = "".join(char for char in str(value).strip() if char.isprintable())
    return cleaned[:max_len]


def is_valid_imei(value):
    """Return True only for a 15-digit IMEI with a valid Luhn check digit."""
    if not isinstance(value, str) or not re.fullmatch(r"\d{15}", value):
        return False

    total = 0
    for position, char in enumerate(reversed(value)):
        digit = int(char)
        if position % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def safe_return_url():
    """Accept only same-host referrers so redirects cannot be sent off-site."""
    referrer = request.referrer
    if not referrer:
        return url_for("home")
    parsed = urlsplit(referrer)
    if parsed.scheme not in {"http", "https"} or parsed.netloc != request.host:
        return url_for("home")
    return referrer

# ==========================================
# 4. APPLICATION ROUTES
# ==========================================
@app.route('/')
@limiter.limit('60 per minute')
def home():
    current_user = get_current_user()
    if current_user and not current_user.is_profile_completed:
        return redirect(url_for('edit_profile'))

    raw_imei = request.args.get('search_imei', '').strip()
    search_imei = re.sub(r'[^0-9]', '', raw_imei)[:15]
    search_result = None

    if search_imei:
        search_result = Device.query.filter_by(imei=search_imei).first()

    my_devices = Device.query.filter_by(user_id=current_user.id).all() if current_user else []

    return render_template(
        'index.html',
        current_user=current_user,
        search_result=search_result,
        search_imei=search_imei,
        devices=my_devices
    )

@app.route('/login/google')
@limiter.limit('10 per minute')
def google_login():
    if not google:
        flash("Google OAuth credentials are not configured on this server.", "warning")
        return redirect(url_for('home'))
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
@limiter.limit('20 per minute')
def google_callback():
    if not google:
        abort(400)
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo') or {}
        google_id = user_info.get('sub')
        google_email = (user_info.get('email') or '').strip().lower()
        google_name = user_info.get('name') or 'Operator'

        # Only link accounts using an email Google explicitly marks as verified.
        if not google_id or not google_email or user_info.get('email_verified') is not True:
            raise ValueError("Google did not return a verified identity.")

        google_user = User.query.filter_by(google_id=google_id).first()
        email_user = User.query.filter(db.func.lower(User.email) == google_email).first()
        if google_user and email_user and google_user.id != email_user.id:
            raise ValueError("Google identity and email resolve to different accounts.")

        user = google_user or email_user
        if user and user.google_id and user.google_id != google_id:
            raise ValueError("Email is already linked to another Google identity.")

        if user:
            # Attach the Google subject to a matching legacy email account once.
            if not user.google_id:
                user.google_id = google_id
        else:
            user = User(
                google_id=google_id,
                full_name=sanitize_text(google_name, 100) or "Operator",
                email=google_email,
                phone="",
                is_profile_completed=False
            )
            db.session.add(user)

        db.session.commit()
        user_id = user.id
        profile_completed = user.is_profile_completed
        session.clear()  # Rotate the session contents after authentication.
        session['user_id'] = user_id

        if not profile_completed:
            flash("Sign-in successful. Please complete your profile.", "info")
            return redirect(url_for('edit_profile'))

        flash("Signed in successfully.", "success")
    except Exception:
        db.session.rollback()
        app.logger.warning("Google sign-in failed; identity was not linked.")
        flash("Google sign-in could not be completed. Please retry or contact support.", "danger")

    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def edit_profile():
    current_user = get_current_user()
    if not current_user:
        flash("Authentication required.", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_name = sanitize_text(request.form.get('full_name', ''), 100)
        new_email = request.form.get('email', '').strip().lower()
        new_phone = re.sub(r'[^0-9+]', '', request.form.get('phone', '').strip())
        phone_digits = re.sub(r'\D', '', new_phone)

        if not new_name:
            flash("Display name is required.", "danger")
            return render_template('profile.html', user=current_user)

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
            flash("Invalid email format.", "danger")
            return render_template('profile.html', user=current_user)

        if len(phone_digits) < 10 or len(phone_digits) > 15 or new_phone.count('+') > 1 or ('+' in new_phone[1:]):
            flash("Enter a valid emergency phone number with 10 to 15 digits.", "danger")
            return render_template('profile.html', user=current_user)

        existing = User.query.filter(
            db.func.lower(User.email) == new_email,
            User.id != current_user.id
        ).first()
        if existing:
            flash("That email address is already registered to another account.", "danger")
            return render_template('profile.html', user=current_user)

        current_user.full_name = new_name
        current_user.email = new_email
        current_user.phone = new_phone
        current_user.is_profile_completed = True
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That email address is already registered to another account.", "danger")
            return render_template('profile.html', user=current_user)

        flash("Profile updated successfully.", "success")
        return redirect(url_for('home'))

    return render_template('profile.html', user=current_user)

# ==========================================
# 5. ADMIN AUTHENTICATION
# ==========================================
@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit('5 per 5 minutes')
def admin_login():
    if session.get('admin_authenticated'):
        return redirect(url_for('admin_panel'))

    # Do not trust a caller-supplied X-Forwarded-For value for authentication controls.
    client_ip = request.remote_addr or "unknown"
    is_blocked, remaining_sec = is_ip_rate_limited(client_ip)
    if is_blocked:
        flash(f"SECURITY LOCKOUT: Too many attempts. Retry in {remaining_sec} seconds.", "danger")
        return render_template('admin_login.html')

    if request.method == 'POST':
        username = sanitize_text(request.form.get('admin_username', '').strip().lower())
        password = request.form.get('admin_password', '')

        admin_data = AdminSetting.query.first()
        is_user_match = admin_data and (username == admin_data.username.lower())
        is_pass_match = admin_data and check_password_hash(admin_data.password_hash, password)

        if is_user_match and is_pass_match:
            reset_attempts(client_ip)
            session.clear()
            session['admin_authenticated'] = True
            session.permanent = True
            flash("Administrator sign-in successful.", "success")
            return redirect(url_for('admin_panel'))
        else:
            record_failed_attempt(client_ip)
            flash("Access Denied: Invalid credentials or authorization signature.", "danger")

    return render_template('admin_login.html')

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    flash("Admin session terminated.", "info")
    return redirect(url_for('home'))

@app.route('/admin')
def admin_panel():
    if not session.get('admin_authenticated'):
        flash("Root session authentication required.", "warning")
        return redirect(url_for('admin_login'))

    admin_data = AdminSetting.query.first()
    all_users = User.query.all()
    all_devices = Device.query.all()
    stolen_count = Device.query.filter_by(status='LOST_OR_STOLEN').count()
    sale_count = Device.query.filter_by(status='FOR_SALE').count()

    return render_template(
        'admin.html',
        users=all_users,
        devices=all_devices,
        stolen_count=stolen_count,
        sale_count=sale_count,
        admin_username=admin_data.username
    )

@app.route('/admin/update-credentials', methods=['POST'])
@limiter.limit('5 per 10 minutes')
def update_admin_credentials():
    if not session.get('admin_authenticated'):
        abort(403)

    new_username = sanitize_text(request.form.get('new_username', '').strip().lower())
    new_password = request.form.get('new_password', '')

    if not new_username or len(new_password) < 8:
        flash("Password must be at least 8 characters in length.", "danger")
        return redirect(url_for('admin_panel'))

    admin_data = AdminSetting.query.first()
    if not admin_data:
        abort(409)

    admin_data.username = new_username
    admin_data.password_hash = generate_password_hash(new_password)
    db.session.commit()

    session.clear()
    flash("Administrator credentials updated. Sign in again with the new credentials.", "success")
    return redirect(url_for('admin_login'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash("Session terminated securely.", "info")
    return redirect(url_for('home'))

# ==========================================
# 6. HARDWARE ENROLLMENT & CONTROL
# ==========================================
@app.route('/register-device', methods=['POST'])
@limiter.limit('10 per minute')
def register_device():
    current_user = get_current_user()
    if not current_user:
        flash("Authorization required.", "danger")
        return redirect(url_for('home'))

    raw_imei = request.form.get('imei', '').strip()
    imei = raw_imei
    brand = sanitize_text(request.form.get('brand', ''), 50)
    model = sanitize_text(request.form.get('model', ''), 50)
    status = request.form.get('status')

    if not is_valid_imei(imei):
        flash("Invalid IMEI. Enter a valid 15-digit IMEI, including its check digit.", "danger")
        return redirect(url_for('home'))

    if not brand or not model:
        flash("Manufacturer and model are required.", "danger")
        return redirect(url_for('home'))

    if status not in ['NOT_FOR_SALE', 'FOR_SALE', 'LOST_OR_STOLEN']:
        flash("Invalid device status flag.", "danger")
        return redirect(url_for('home'))

    if Device.query.filter_by(imei=imei).first():
        flash("A device with this IMEI is already registered in the system.", "danger")
        return redirect(url_for('home'))

    new_device = Device(imei=imei, brand=brand, model=model, status=status, user_id=current_user.id)
    db.session.add(new_device)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("A device with this IMEI is already registered in the system.", "danger")
        return redirect(url_for('home'))

    flash(f"Hardware unit {brand} {model} registered securely under your account.", "success")
    return redirect(url_for('home'))

@app.route('/update-status/<int:device_id>', methods=['POST'])
@limiter.limit('30 per minute')
def update_status(device_id):
    current_user = get_current_user()
    device = db.session.get(Device, device_id)
    if not device:
        abort(404)

    is_admin = session.get('admin_authenticated')
    if not is_admin and (not current_user or device.user_id != current_user.id):
        flash("Security alert: Unauthorized modification attempt logged.", "danger")
        return redirect(url_for('home'))

    new_status = request.form.get('status')
    if new_status not in ['NOT_FOR_SALE', 'FOR_SALE', 'LOST_OR_STOLEN']:
        flash("Invalid device status flag.", "danger")
        return redirect(safe_return_url())

    device.status = new_status
    db.session.commit()
    flash(f"Hardware status flag updated to '{new_status}'.", "info")
    return redirect(safe_return_url())

@app.route('/delete-device/<int:device_id>', methods=['POST'])
@limiter.limit('10 per minute')
def delete_device(device_id):
    """Delete one registered device only for its owner or an authenticated admin."""
    current_user = get_current_user()
    device = db.session.get(Device, device_id)
    if not device:
        abort(404)

    is_admin = bool(session.get('admin_authenticated'))
    if not is_admin and (not current_user or device.user_id != current_user.id):
        abort(403)

    deleted_imei = device.imei
    db.session.delete(device)
    db.session.commit()
    app.logger.info("Device complaint deleted by %s; record id=%s", "admin" if is_admin else "owner", device_id)
    flash(f"Registered complaint for IMEI {deleted_imei} was deleted.", "success")
    return redirect(url_for('admin_panel') if is_admin else url_for('home'))

# ==========================================
# 7. SECURITY HEADERS
# ==========================================
@app.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; "
        f"script-src 'self' 'nonce-{getattr(g, 'csp_nonce', '')}' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
        "img-src 'self' data:; connect-src 'self'; upgrade-insecure-requests"
    )
    if is_production:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    # Production servers use gunicorn (e.g. gunicorn app:app)
    app.run(debug=False, port=5000)