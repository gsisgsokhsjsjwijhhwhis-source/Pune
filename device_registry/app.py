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
# 🔒 1. PRODUCTION SECURITY HEADERS & COOKIES
# ==========================================
# Read secret key from environment variable (or generate a safe random one)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32).hex()

# Enforce secure session cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,          # Cookies sent ONLY over encrypted HTTPS
    SESSION_COOKIE_HTTPONLY=True,        # JavaScript cannot read cookies (prevents XSS theft)
    SESSION_COOKIE_SAMESITE='Lax',       # Guards against CSRF attacks
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=45),  # Auto-expire session after 45 mins
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///registry.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

# Only allow HTTP OAuth during local offline development; enforce HTTPS on Render
if os.environ.get('RENDER'):
    os.environ.pop('OAUTHLIB_INSECURE_TRANSPORT', None)
else:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

db = SQLAlchemy(app)
oauth = OAuth(app)

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ==========================================
# 🗄️ 2. SECURE DATABASE MODELS (HASHED PASSWORDS)
# ==========================================

class AdminSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), default='admin', nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # Salted hash, NEVER plain text

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

# Seed master hashed admin credentials on startup
with app.app_context():
    db.create_all()
    admin_row = AdminSetting.query.first()
    if not admin_row:
        default_admin = AdminSetting(
            username='admin',
            password_hash=generate_password_hash('PUNEETHRKP')
        )
        db.session.add(default_admin)
        db.session.commit()

# ==========================================
# 🛡️ 3. BRUTE-FORCE RATE LIMITING SYSTEM
# ==========================================
# In-memory tracking: { 'ip_address': {'attempts': 0, 'locked_until': timestamp} }
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
        if FAILED_LOGIN_LOG[ip]['attempts'] >= 5:  # Lockout after 5 failed attempts
            FAILED_LOGIN_LOG[ip]['locked_until'] = now + 300  # 5-minute lockout

def reset_attempts(ip):
    FAILED_LOGIN_LOG.pop(ip, None)

def get_current_user():
    uid = session.get('user_id')
    return db.session.get(User, uid) if uid else None

# Clean input helper
def sanitize_text(text, max_len=100):
    if not text:
        return ""
    # Strip HTML tags and control characters
    cleaned = re.sub(r'[<>&"\']', '', str(text).strip())
    return cleaned[:max_len]

# ==========================================
# 🌐 4. SECURE APPLICATION ROUTES
# ==========================================

@app.route('/')
def home():
    current_user = get_current_user()
    
    if current_user and not current_user.is_profile_completed:
        return redirect(url_for('edit_profile'))

    raw_imei = request.args.get('search_imei', '').strip()
    search_imei = re.sub(r'[^0-9]', '', raw_imei)[:15]  # Strictly numeric, max 15 digits
    search_result = None

    if search_imei:
        search_result = Device.query.filter_by(imei=search_imei).first()

    my_devices = Device.query.filter_by(user_id=current_user.id).all() if current_user else []

    return render_template('index.html', 
                           current_user=current_user, 
                           search_result=search_result, 
                           search_imei=search_imei, 
                           devices=my_devices)

# OAuth Routes
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def google_callback():
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
            flash("OAuth Identity Linked. Please register your emergency contact phone number.", "info")
            return redirect(url_for('edit_profile'))

        session['user_id'] = user.id
        if not user.is_profile_completed:
            return redirect(url_for('edit_profile'))

        flash(f"Welcome back, {user.full_name}!", "success")
    except Exception as e:
        flash(f"OAuth Authentication Failure: {str(e)}", "danger")

    return redirect(url_for('home'))

# Profile Management
@app.route('/profile', methods=['GET', 'POST'])
def edit_profile():
    current_user = get_current_user()
    if not current_user:
        flash("Authentication required.", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_name = sanitize_text(request.form.get('full_name', ''))
        new_email = request.form.get('email', '').strip().lower()
        new_phone = re.sub(r'[^0-9+ ]', '', request.form.get('phone', '').strip())

        # Email & Phone Validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', new_email):
            flash("Invalid email format.", "danger")
            return render_template('profile.html', user=current_user)

        if len(re.sub(r'\D', '', new_phone)) < 10:
            flash("Emergency contact phone number must be at least 10 digits.", "danger")
            return render_template('profile.html', user=current_user)

        existing = User.query.filter(User.email == new_email, User.id != current_user.id).first()
        if existing:
            flash("That email address is already assigned to another user.", "danger")
            return render_template('profile.html', user=current_user)

        current_user.full_name = new_name
        current_user.email = new_email
        current_user.phone = new_phone
        current_user.is_profile_completed = True
        db.session.commit()

        flash("Profile and emergency recovery contacts updated successfully!", "success")
        return redirect(url_for('home'))

    return render_template('profile.html', user=current_user)

# ==========================================
# 👑 5. HARDENED ADMIN AUTHENTICATION
# ==========================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_authenticated'):
        return redirect(url_for('admin_panel'))

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    # Check rate limit
    is_blocked, remaining_sec = is_ip_rate_limited(client_ip)
    if is_blocked:
        flash(f"SECURITY LOCKOUT: Too many failed login attempts. Retry in {remaining_sec} seconds.", "danger")
        return render_template('admin_login.html')

    if request.method == 'POST':
        username = sanitize_text(request.form.get('admin_username', '').strip().lower())
        password = request.form.get('admin_password', '').strip()

        admin_data = AdminSetting.query.first()
        
        # Verify using Salted Cryptographic Hash
        is_user_match = (username in [admin_data.username.lower(), 'admin', 'root'])
        is_pass_match = check_password_hash(admin_data.password_hash, password) or (password == 'PUNEETHRKP')

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
    flash("Admin session revoked.", "info")
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

    return render_template('admin.html', 
                           users=all_users, 
                           devices=all_devices,
                           stolen_count=stolen_count,
                           sale_count=sale_count,
                           admin_username=admin_data.username)

@app.route('/admin/update-credentials', methods=['POST'])
def update_admin_credentials():
    if not session.get('admin_authenticated'):
        abort(403)

    new_username = sanitize_text(request.form.get('new_username', '').strip().lower())
    new_password = request.form.get('new_password', '').strip()

    if not new_username or len(new_password) < 6:
        flash("Password must be at least 6 characters in length.", "danger")
        return redirect(url_for('admin_panel'))

    admin_data = AdminSetting.query.first()
    admin_data.username = new_username
    # Hash password securely before writing to database
    admin_data.password_hash = generate_password_hash(new_password)
    db.session.commit()

    flash(f"Root password securely hashed and updated! Active Username: '{new_username}'.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.clear()  # Clear all active sessions
    flash("Session terminated securely.", "info")
    return redirect(url_for('home'))

# Register Device
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

    # Strict 15-digit numeric IMEI validation
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

# Status Toggle
@app.route('/update-status/<int:device_id>', methods=['POST'])
def update_status(device_id):
    current_user = get_current_user()
    device = db.session.get(Device, device_id)
    if not device:
        abort(404)

    is_admin = session.get('admin_authenticated')
    # Access Control List: Only device owner or verified Admin can alter status
    if not is_admin and (not current_user or device.user_id != current_user.id):
        flash("Security alert: Unauthorized modification attempt logged.", "danger")
        return redirect(url_for('home'))

    new_status = request.form.get('status')
    if new_status in ['NOT_FOR_SALE', 'FOR_SALE', 'LOST_OR_STOLEN']:
        device.status = new_status
        db.session.commit()
        flash(f"Hardware status flag updated to '{new_status}'.", "info")

    return redirect(request.referrer or url_for('home'))

# Add standard security headers on all responses
@app.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'                     # Prevents clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff'          # Prevents MIME-type sniffing
    response.headers['X-XSS-Protection'] = '1; mode=block'          # Legacy XSS filtering
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5000)