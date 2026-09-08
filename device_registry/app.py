import os
from flask import Flask, render_template, request, redirect, url_for, flash, session ,g
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask_cors import CORS


app = Flask(__name__)
CORS(app)


@app.context_processor
def inject_global_vars():
    return {
        'website_name': os.getenv('WEBSITE_NAME', 'SafeDevice'),
        'current_user': getattr(g, 'user', None)  # Or session user reference
    }  # Enables Cross-Origin Resource Sharing

# Load environment variables from .env file
load_dotenv()

# Allow OAuth over standard HTTP for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
# Set fallback if not defined in .env
app.config['WEBSITE_NAME'] = os.getenv('WEBSITE_NAME', 'Device Registry')

# Automatically passes website_name to EVERY render_template() call
@app.context_processor
def inject_website_name():
    return dict(website_name=app.config['WEBSITE_NAME'])
app.secret_key = os.getenv('SECRET_KEY')

# SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///registry.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(25), nullable=True)  # Filled manually by user
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

# --- ROUTES ---

@app.route('/')
def home():
    current_user = get_current_user()
    
    # If user just logged in with Google but hasn't entered their phone number yet, force profile step
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
        google_name = user_info.get('name', 'Owner')

        # Check existing user
        user = User.query.filter((User.google_id == google_id) | (User.email == google_email)).first()

        if not user:
            # Create user pulling initial details from Google, phone left blank for user input
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
            flash("Google account linked! Please verify your name, email, and enter your emergency contact number.", "info")
            return redirect(url_for('edit_profile'))
        
        session['user_id'] = user.id
        if not user.is_profile_completed:
            return redirect(url_for('edit_profile'))

        flash(f"Welcome back, {user.full_name}!", "success")
    except Exception as e:
        flash(f"Login failed: {str(e)}", "danger")

    return redirect(url_for('home'))

# Profile Edit Page (Prompts user to rename name/email and enter recovery phone)
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
            flash("Please enter a valid emergency recovery contact number.", "danger")
            return render_template('profile.html', user=current_user)

        # Check if email belongs to someone else
        existing = User.query.filter(User.email == new_email, User.id != current_user.id).first()
        if existing:
            flash("That email address is already in use by another user.", "danger")
            return render_template('profile.html', user=current_user)

        current_user.full_name = new_name
        current_user.email = new_email
        current_user.phone = new_phone
        current_user.is_profile_completed = True
        db.session.commit()

        flash("Your profile details and recovery phone number are saved!", "success")
        return redirect(url_for('home'))

    return render_template('profile.html', user=current_user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('home'))

# Register a Device
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

    flash(f"Device {brand} {model} registered under your ownership.", "success")
    return redirect(url_for('home'))

# Toggle Device Status
@app.route('/update-status/<int:device_id>', methods=['POST'])
def update_status(device_id):
    current_user = get_current_user()
    device = Device.query.get_or_404(device_id)

    if not current_user or device.user_id != current_user.id:
        flash("Unauthorized modification.", "danger")
        return redirect(url_for('home'))

    new_status = request.form.get('status')
    if new_status in ['NOT_FOR_SALE', 'FOR_SALE', 'LOST_OR_STOLEN']:
        device.status = new_status
        db.session.commit()
        flash(f"Updated status of {device.brand} {device.model} to '{new_status}'!", "info")

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)