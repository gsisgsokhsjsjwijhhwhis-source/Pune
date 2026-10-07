import os
import re
import time
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ==========================================
# 1. ENVIRONMENT & SECURITY HEADERS
# ==========================================
is_production = bool(os.environ.get('RENDER'))

app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32).hex()

# Database URI sanitization for Render PostgreSQL
raw_db_url = os.environ.get('DATABASE_URL', 'sqlite:///registry.db')
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

app.config.update(
    SESSION_COOKIE_SECURE=is_production,       # HTTPS only in production
    SESSION_COOKIE_HTTPONLY=True,              # Guard against JavaScript cookie theft
    SESSION_COOKIE_SAMESITE='Lax',             # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=45),
    SQLALCHEMY_DATABASE_URI=raw_db_url,
    SQLALCHEMY_TRACK_MODIFICATIONS=False
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

# Initialize database and default admin credentials securely
with app.app_context():
    db.create_all()
    admin_row = AdminSetting.query.first()
    if not admin_row:
        initial_admin_pass = os.environ.get('INITIAL_ADMIN_PASSWORD', 'Admin@SafeDevice2026')
        default_admin = AdminSetting(
            username=os.environ.get('INITIAL_ADMIN_USER', 'admin').lower(),
            password_hash=generate_password_hash(initial_admin_pass)
        )
        db.session.add(default_admin)
        db.session.commit()

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

def sanitize_text(text, max_len=100):
    if not text:
        return ""
    cleaned = re.sub(r'[<>&"\'/]', '', str(text).strip())
    return cleaned[:max_len]

# ==========================================
# 4. APPLICATION ROUTES
# ==========================================
@app.route('/')
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
def google_login():
    if not google:
        flash("Google OAuth credentials are not configured on this server.", "warning")
        return redirect(url_for('home'))
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def google_callback():
    if not google:
        abort(400)
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        google_id = user_info.get('sub')
        google_email = user_info.get('email')
        google_name = user_info.get('name', 'Operator')

        user = User.query.filter((User.google_id == google_id) | (User.email == google_email)).first()

        if not user:
            user = User(
                google_id=google_id,
                full_name=sanitize_text(google_name),
                email=google_email.lower().strip(),
                phone="",
                is_profile_completed=False
            )
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            flash("OAuth link established. Please submit an emergency contact number.", "info")
            return redirect(url_for('edit_profile'))

        session['user_id'] = user.id
        if not user.is_profile_completed:
            return redirect(url_for('edit_profile'))

        flash(f"Session established: {user.full_name}", "success")
    except Exception as e:
        flash("OAuth Authentication Failure. Please verify your provider settings.", "danger")

    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
def edit_profile():
    current_user = get_current_user()
    if not current_user:
        flash("Authentication required.", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_name = sanitize_text(request.form.get('full_name', ''))
        new_email = request.form.get('email', '').strip().lower()
        new_phone = re.sub(r'[^0-9+ -]', '', request.form.get('phone', '').strip())

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
            flash("Invalid email format.", "danger")
            return render_template('profile.html', user=current_user)

        if len(re.sub(r'\D', '', new_phone)) < 10:
            flash("Emergency contact phone number must be at least 10 digits.", "danger")
            return render_template('profile.html', user=current_user)

        existing = User.query.filter(User.email == new_email, User.id != current_user.id).first()
        if existing:
            flash("That email address is already registered to another account.", "danger")
            return render_template('profile.html', user=current_user)

        current_user.full_name = new_name
        current_user.email = new_email
        current_user.phone = new_phone
        current_user.is_profile_completed = True
        db.session.commit()

        flash("Profile and emergency beacon telemetry updated successfully.", "success")
        return redirect(url_for('home'))

    return render_template('profile.html', user=current_user)

# ==========================================
# 5. ADMIN AUTHENTICATION
# ==========================================
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_authenticated'):
        return redirect(url_for('admin_panel'))

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    is_blocked, remaining_sec = is_ip_rate_limited(client_ip)
    if is_blocked:
        flash(f"SECURITY LOCKOUT: Too many attempts. Retry in {remaining_sec} seconds.", "danger")
        return render_template('admin_login.html')

    if request.method == 'POST':
        username = sanitize_text(request.form.get('admin_username', '').strip().lower())
        password = request.form.get('admin_password', '').strip()

        admin_data = AdminSetting.query.first()
        is_user_match = admin_data and (username == admin_data.username.lower())
        is_pass_match = admin_data and check_password_hash(admin_data.password_hash, password)

        if is_user_match and is_pass_match:
            reset_attempts(client_ip)
            session['admin_authenticated'] = True
            session.permanent = True
            flash("Root terminal access authorized. Security level: High.", "success")
            return redirect(url_for('admin_panel'))
        else:
            record_failed_attempt(client_ip)
            flash("Access Denied: Invalid credentials or authorization signature.", "danger")

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_authenticated', None)
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
def update_admin_credentials():
    if not session.get('admin_authenticated'):
        abort(403)

    new_username = sanitize_text(request.form.get('new_username', '').strip().lower())
    new_password = request.form.get('new_password', '').strip()

    if not new_username or len(new_password) < 8:
        flash("Password must be at least 8 characters in length.", "danger")
        return redirect(url_for('admin_panel'))

    admin_data = AdminSetting.query.first()
    admin_data.username = new_username
    admin_data.password_hash = generate_password_hash(new_password)
    db.session.commit()

    flash(f"Root credentials updated. Active Operator: '{new_username}'.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Session terminated securely.", "info")
    return redirect(url_for('home'))

# ==========================================
# 6. HARDWARE ENROLLMENT & CONTROL
# ==========================================
@app.route('/register-device', methods=['POST'])
def register_device():
    current_user = get_current_user()
    if not current_user:
        flash("Authorization required.", "danger")
        return redirect(url_for('home'))

    raw_imei = request.form.get('imei', '').strip()
    imei = re.sub(r'[^0-9]', '', raw_imei)
    brand = sanitize_text(request.form.get('brand', ''))
    model = sanitize_text(request.form.get('model', ''))
    status = request.form.get('status')

    if len(imei) != 15:
        flash("Invalid IMEI format: Must be exactly 15 numeric digits.", "danger")
        return redirect(url_for('home'))

    if status not in ['NOT_FOR_SALE', 'FOR_SALE', 'LOST_OR_STOLEN']:
        flash("Invalid device status flag.", "danger")
        return redirect(url_for('home'))

    if Device.query.filter_by(imei=imei).first():
        flash("A device with this IMEI is already registered in the system.", "danger")
        return redirect(url_for('home'))

    new_device = Device(imei=imei, brand=brand, model=model, status=status, user_id=current_user.id)
    db.session.add(new_device)
    db.session.commit()

    flash(f"Hardware unit {brand} {model} registered securely under your account.", "success")
    return redirect(url_for('home'))

@app.route('/update-status/<int:device_id>', methods=['POST'])
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
    if new_status in ['NOT_FOR_SALE', 'FOR_SALE', 'LOST_OR_STOLEN']:
        device.status = new_status
        db.session.commit()
        flash(f"Hardware status flag updated to '{new_status}'.", "info")

    return redirect(request.referrer or url_for('home'))

# ==========================================
# 7. SECURITY HEADERS
# ==========================================
@app.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    return response

if __name__ == '__main__':
    # Production servers use gunicorn (e.g. gunicorn app:app)
    app.run(debug=False, port=5000)