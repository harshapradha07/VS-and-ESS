from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from datetime import datetime
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import os

# Initialize Extensions
from models import db, User

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Init DB
db.init_app(app)
#login manager starts here 
# Init Login Manager
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Init OAuth (Google)
# NOTE: Replace with actual credentials for production
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only for OpenID Connect compliant, may need custom fetch
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

from modules.scanner import Scanner
from modules.exploit import ExploitSimulator
from modules.risk import RiskAnalyzer

scanner = Scanner()
exploit_sim = ExploitSimulator()
risk_analyzer = RiskAnalyzer()

# --- Auth Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered')
            return redirect(url_for('register'))

        username_exists = User.query.filter_by(username=username).first()
        if username_exists:
            flash('Username already taken')
            return redirect(url_for('register'))
            
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('index'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/callback')
def google_authorize():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        email = user_info['email']
        
        user = User.query.filter_by(email=email).first()
        if not user:
            # Create a new user from Google info
            user = User(
                username=user_info['name'],
                email=email,
                auth_type='google'
            )
            db.session.add(user)
            db.session.commit()
            
        login_user(user)
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Google Login Failed: {str(e)}')
        return redirect(url_for('login'))


# --- App Routes ---

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/api/scan', methods=['POST'])
@login_required
def scan():
    target = request.json.get('target', '127.0.0.1')
    
    # 1. Perform Scan
    scan_results = scanner.scan_target(target)
    
    # 2. Simulate Exploits based on findings
    exploit_results = exploit_sim.simulate_exploits(scan_results)
    
    # 3. Calculate Risk
    risk_assessment = risk_analyzer.calculate_risk_score(scan_results, exploit_results)
    
    # Save to session for report generation
    session['last_scan'] = {
        "target": target,
        "scan_data": scan_results,
        "exploits": exploit_results,
        "risk": risk_assessment
    }
    
    return jsonify({
        "status": "complete",
        "target": target,
        "scan_data": scan_results,
        "exploits": exploit_results,
        "risk": risk_assessment
    })

@app.route('/report', methods=['GET'])
@login_required
def view_report():
    data = session.get('last_scan')
    if not data:
        flash("No scan data available to generate report. Please run a scan first.")
        return redirect(url_for('index'))
        
    return render_template('report.html', 
                          data=data, 
                          user=current_user,
                          generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/api/report', methods=['GET'])
@login_required
def generate_report():
    # JSON endpoint if needed later
    data = session.get('last_scan')
    if not data:
        return jsonify({"message": "No scan data found"}), 404
    return jsonify(data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
