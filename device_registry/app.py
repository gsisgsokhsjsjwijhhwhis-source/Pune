import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
import config

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///registry.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=config.GOOGLE_CLIENT_ID,
    client_secret=config.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- DATABASE MODELS ---
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

with app.app_context():
    db.create_all()

def get_current_user():
    uid = session.get('user_id')
    return db.session.get(User, uid) if uid else None

# --- PUBLIC ROUTES ---

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

# Google Login Routes
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
        google_name = user_info.get('name', 'Owner')

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
            flash("Account linked! Please verify your name, email, and emergency contact number.", "info")
            return redirect(url_for('edit_profile'))

        session['user_id'] = user.id
        if not user.is_profile_completed:
            return redirect(url_for('edit_profile'))

        flash(f"Welcome back, {user.full_name}!", "success")
    except Exception as e:
        flash(f"Login failed: {str(e)}", "danger")

    return redirect(url_for('home'))

# Profile Update Route (for regular users)
@app.route('/profile', methods=['GET', 'POST'])
def edit_profile():
    current_user = get_current_user()
    if not current_user:
        flash("Please log in first.", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_name = request.form.get('full_name', '').strip()
        new_email = request.form.get('email', '').strip()
        new_phone = request.form.get('phone', '').strip()

        if not new_phone or len(new_phone) < 10:
            flash("Please enter a valid emergency recovery phone number.", "danger")
            return render_template('profile.html', user=current_user)

        existing = User.query.filter(User.email == new_email, User.id != current_user.id).first()
        if existing:
            flash("That email address is already in use by another user.", "danger")
            return render_template('profile.html', user=current_user)

        current_user.full_name = new_name
        current_user.email = new_email
        current_user.phone = new_phone
        current_user.is_profile_completed = True
        db.session.commit()

        flash("Your profile and emergency contact details have been updated!", "success")
        return redirect(url_for('home'))

    return render_template('profile.html', user=current_user)

# ----------------------------------------------------
# 👑 ADMIN AUTHENTICATION & DASHBOARD
# ----------------------------------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_authenticated'):
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        username = request.form.get('admin_username', '').strip()
        password = request.form.get('admin_password', '').strip()

        # Validates against config.py values
        if username == config.ADMIN_USERNAME and password == config.ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            flash("Admin authorization successful!", "success")
            return redirect(url_for('admin_panel'))
        else:
            flash("Invalid administrator username or password. Access denied.", "danger")

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_authenticated', None)
    flash("Admin session closed.", "info")
    return redirect(url_for('home'))

@app.route('/admin')
def admin_panel():
    if not session.get('admin_authenticated'):
        flash("Login required to access administrator records.", "warning")
        return redirect(url_for('admin_login'))

    all_users = User.query.all()
    all_devices = Device.query.all()
    stolen_count = Device.query.filter_by(status='LOST_OR_STOLEN').count()
    sale_count = Device.query.filter_by(status='FOR_SALE').count()

    return render_template('admin.html', 
                           users=all_users, 
                           devices=all_devices,
                           stolen_count=stolen_count,
                           sale_count=sale_count,
                           admin_username=config.ADMIN_USERNAME)

# EDIT ADMIN USERNAME & PASSWORD
@app.route('/admin/update-credentials', methods=['POST'])
def update_admin_credentials():
    if not session.get('admin_authenticated'):
        abort(403)

    new_username = request.form.get('new_username', '').strip()
    new_password = request.form.get('new_password', '').strip()

    if not new_username or not new_password:
        flash("Username and password cannot be empty.", "danger")
        return redirect(url_for('admin_panel'))

    # Update in-memory values
    config.ADMIN_USERNAME = new_username
    config.ADMIN_PASSWORD = new_password

    # Write changes permanently back to config.py
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'config.py')
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Safely replace existing assignments using regex
        content = re.sub(r'ADMIN_USERNAME\s*=\s*.*', f'ADMIN_USERNAME = "{new_username}"', content)
        content = re.sub(r'ADMIN_PASSWORD\s*=\s*.*', f'ADMIN_PASSWORD = "{new_password}"', content)

        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(content)

        flash(f"Admin credentials updated! New Username: '{new_username}'.", "success")
    except Exception as e:
        flash(f"Credentials updated in memory, but could not write to file: {str(e)}", "warning")

    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('admin_authenticated', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('home'))

# Register Device
@app.route('/register-device', methods=['POST'])
def register_device():
    current_user = get_current_user()
    if not current_user:
        flash("Please sign in first.", "danger")
        return redirect(url_for('home'))

    imei = request.form.get('imei', '').strip()
    brand = request.form.get('brand', '').strip()
    model = request.form.get('model', '').strip()
    status = request.form.get('status')

    if Device.query.filter_by(imei=imei).first():
        flash("A device with this IMEI is already registered!", "danger")
        return redirect(url_for('home'))

    new_device = Device(imei=imei, brand=brand, model=model, status=status, user_id=current_user.id)
    db.session.add(new_device)
    db.session.commit()

    flash(f"Device {brand} {model} registered successfully.", "success")
    return redirect(url_for('home'))

# Update Status (by owner or admin)
@app.route('/update-status/<int:device_id>', methods=['POST'])
def update_status(device_id):
    current_user = get_current_user()
    device = db.session.get(Device, device_id)
    if not device:
        abort(404)

    is_admin = session.get('admin_authenticated')
    if not is_admin and (not current_user or device.user_id != current_user.id):
        flash("Unauthorized modification.", "danger")
        return redirect(url_for('home'))

    new_status = request.form.get('status')
    if new_status in ['NOT_FOR_SALE', 'FOR_SALE', 'LOST_OR_STOLEN']:
        device.status = new_status
        db.session.commit()
        flash(f"Status for {device.brand} {device.model} updated to '{new_status}'!", "info")

    return redirect(request.referrer or url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)