import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth

# Allow OAuth to run over HTTP for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

# --- SECRETS & ENVIRONMENT CONFIGURATION ---
# Render sets these automatically via the "Environment" tab, or falls back to defaults
app.secret_key = os.environ.get('SECRET_KEY', 'safedevice-cyber-secret-key-2026')
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET')

# Database Setup (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///registry.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ==========================================
# 🗄️ DATABASE MODELS
# ==========================================

class AdminSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), default='admin', nullable=False)
    password = db.Column(db.String(100), default='PUNEETHRKP', nullable=False)

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

# Initialize database tables and seed default admin credentials
with app.app_context():
    db.create_all()
    if not AdminSetting.query.first():
        default_admin = AdminSetting(username='admin', password='PUNEETHRKP')
        db.session.add(default_admin)
        db.session.commit()

# --- HELPER FUNCTIONS ---

def get_admin_creds():
    creds = AdminSetting.query.first()
    if not creds:
        creds = AdminSetting(username='admin', password='PUNEETHRKP')
        db.session.add(creds)
        db.session.commit()
    return creds

def get_current_user():
    uid = session.get('user_id')
    return db.session.get(User, uid) if uid else None

# ==========================================
# 🌐 ROUTES
# ==========================================

@app.route('/')
def home():
    current_user = get_current_user()
    
    if current_user and not current_user.is_profile_completed:
        return redirect(url_for('edit_profile'))

    search_imei = request.args.get('search_imei', '').strip()
    search_result = None

    if search_imei:
        search_result = Device.query.filter_by(imei=search_imei).first()

    my_devices = Device.query.filter_by(user_id=current_user.id).all() if current_user else []

    return render_template('index.html', 
                           current_user=current_user, 
                           search_result=search_result, 
                           search_imei=search_imei, 
                           devices=my_devices)

# Google Login
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

# Google Callback
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
                full_name=google_name,
                email=google_email,
                phone="",
                is_profile_completed=False
            )
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            flash("Identity linked. Set your recovery phone number.", "info")
            return redirect(url_for('edit_profile'))

        session['user_id'] = user.id
        if not user.is_profile_completed:
            return redirect(url_for('edit_profile'))

        flash(f"Welcome back, {user.full_name}!", "success")
    except Exception as e:
        flash(f"OAuth Handshake Error: {str(e)}", "danger")

    return redirect(url_for('home'))

# Profile Update
@app.route('/profile', methods=['GET', 'POST'])
def edit_profile():
    current_user = get_current_user()
    if not current_user:
        flash("Authorization required.", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_name = request.form.get('full_name', '').strip()
        new_email = request.form.get('email', '').strip()
        new_phone = request.form.get('phone', '').strip()

        if not new_phone or len(new_phone) < 10:
            flash("Enter a valid emergency recovery phone number.", "danger")
            return render_template('profile.html', user=current_user)

        existing = User.query.filter(User.email == new_email, User.id != current_user.id).first()
        if existing:
            flash("Comms email belongs to an existing node.", "danger")
            return render_template('profile.html', user=current_user)

        current_user.full_name = new_name
        current_user.email = new_email
        current_user.phone = new_phone
        current_user.is_profile_completed = True
        db.session.commit()

        flash("Operator identity committed to registry.", "success")
        return redirect(url_for('home'))

    return render_template('profile.html', user=current_user)

# ----------------------------------------------------
# 👑 ADMIN AUTHENTICATION & MANAGEMENT
# ----------------------------------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_authenticated'):
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        username = request.form.get('admin_username', '').strip()
        password = request.form.get('admin_password', '').strip()
        
        creds = get_admin_creds()
        if username == creds.username and password == creds.password:
            session['admin_authenticated'] = True
            flash("Root access granted.", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("Access Denied: Invalid credentials.", "danger")

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_authenticated', None)
    flash("Root terminal session closed.", "info")
    return redirect(url_for('home'))

@app.route('/admin')
def admin_panel():
    if not session.get('admin_authenticated'):
        flash("Root session required.", "warning")
        return redirect(url_for('admin_login'))

    creds = get_admin_creds()
    all_users = User.query.all()
    all_devices = Device.query.all()
    stolen_count = Device.query.filter_by(status='LOST_OR_STOLEN').count()
    sale_count = Device.query.filter_by(status='FOR_SALE').count()

    return render_template('admin.html', 
                           users=all_users, 
                           devices=all_devices,
                           stolen_count=stolen_count,
                           sale_count=sale_count,
                           admin_username=creds.username)

@app.route('/admin/update-credentials', methods=['POST'])
def update_admin_credentials():
    if not session.get('admin_authenticated'):
        abort(403)

    new_username = request.form.get('new_username', '').strip()
    new_password = request.form.get('new_password', '').strip()

    if not new_username or not new_password:
        flash("Username and password cannot be empty.", "danger")
        return redirect(url_for('admin_panel'))

    creds = get_admin_creds()
    creds.username = new_username
    creds.password = new_password
    db.session.commit()

    flash(f"Root credentials updated in database! Active Username: '{new_username}'.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('admin_authenticated', None)
    flash("Session terminated.", "info")
    return redirect(url_for('home'))

# Register Device
@app.route('/register-device', methods=['POST'])
def register_device():
    current_user = get_current_user()
    if not current_user:
        flash("Authorization required.", "danger")
        return redirect(url_for('home'))

    imei = request.form.get('imei', '').strip()
    brand = request.form.get('brand', '').strip()
    model = request.form.get('model', '').strip()
    status = request.form.get('status')

    if Device.query.filter_by(imei=imei).first():
        flash("Hardware unit with this IMEI code is already registered.", "danger")
        return redirect(url_for('home'))

    new_device = Device(imei=imei, brand=brand, model=model, status=status, user_id=current_user.id)
    db.session.add(new_device)
    db.session.commit()

    flash(f"Hardware {brand} {model} enrolled successfully.", "success")
    return redirect(url_for('home'))

# Update Device State
@app.route('/update-status/<int:device_id>', methods=['POST'])
def update_status(device_id):
    current_user = get_current_user()
    device = db.session.get(Device, device_id)
    if not device:
        abort(404)

    is_admin = session.get('admin_authenticated')
    if not is_admin and (not current_user or device.user_id != current_user.id):
        flash("Unauthorized modification request.", "danger")
        return redirect(url_for('home'))

    new_status = request.form.get('status')
    if new_status in ['NOT_FOR_SALE', 'FOR_SALE', 'LOST_OR_STOLEN']:
        device.status = new_status
        db.session.commit()
        flash(f"Status for {device.brand} {device.model} set to '{new_status}'.", "info")

    return redirect(request.referrer or url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)