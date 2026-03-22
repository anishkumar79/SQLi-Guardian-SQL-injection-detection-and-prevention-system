from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import sqlite3
from utils.detector import check_sqli, get_explanation
from utils.validator import sanitize_input

app = Flask(__name__)
app.secret_key = "secure_sqli_detector_key"

# Database Configuration (SQLite)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database', 'sqli_project.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False) # In real app, hash this!

class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    payload = db.Column(db.Text)
    attack_type = db.Column(db.String(100))
    is_blocked = db.Column(db.Boolean, default=False)

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True)
    reason = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Database Initialization
with app.app_context():
    db.create_all()
    # Seeding database
    if not AttackLog.query.first():
        sample1 = AttackLog(ip_address='192.168.1.10', payload="' OR 1=1 --", attack_type="Logical Tautology", timestamp=datetime.utcnow() - timedelta(minutes=15))
        sample2 = AttackLog(ip_address='10.0.0.5', payload="UNION SELECT * FROM user", attack_type="Union-Based Injection", timestamp=datetime.utcnow() - timedelta(hours=1))
        sample3 = AttackLog(ip_address='45.33.22.11', payload="'; DROP TABLE logs; --", attack_type="Stacked Query Attack", timestamp=datetime.utcnow() - timedelta(minutes=5))
        db.session.add_all([sample1, sample2, sample3])
        db.session.commit()

    if not BlockedIP.query.first():
        block1 = BlockedIP(ip_address='45.33.22.11', reason='Repeated Stacked Query attacks', timestamp=datetime.utcnow() - timedelta(minutes=5))
        db.session.add(block1)
        db.session.commit()

    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@eventstar.sec', password='password123')
        test_user = User(username='johndoe', email='john@example.com', password='password456')
        db.session.add_all([admin, test_user])
        db.session.commit()

# Middleware: IP Blocking Check
@app.before_request
def check_blocked_ip():
    ip = request.remote_addr
    blocked = BlockedIP.query.filter_by(ip_address=ip).first()
    if blocked and "/admin" not in request.path: # Allow admin to see dashboard if they are on localhost for demo
        return f"<h1>ACCESS DENIED</h1><p>Your IP ({ip}) has been blocked due to multiple malicious attempts.</p><p>Reason: {blocked.reason}</p>", 403

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/demo/vulnerable", methods=["GET", "POST"])
def vulnerable_search():
    results = []
    error = None
    query_str = ""
    
    if request.method == "POST":
        user_input = request.form.get("search_query", "")
        query_str = f"SELECT * FROM user WHERE username = '{user_input}'"
        
        # INSECURE: Vulnerable to SQL Injection via direct execution
        try:
            conn = sqlite3.connect(os.path.join(basedir, 'database', 'sqli_project.db'))
            cursor = conn.cursor()
            # This is the vulnerable line: direct concatenation of user input
            cursor.execute(f"SELECT username, email FROM user WHERE username = '{user_input}'")
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            error = str(e)
            
    return render_template("vulnerable.html", results=results, error=error, query_str=query_str)

@app.route("/demo/secure", methods=["GET", "POST"])
def secure_search():
    results = []
    detection = []
    query_str = ""
    is_malicious = False
    
    if request.method == "POST":
        user_input = request.form.get("search_query", "")
        
        # 1. DETECT (The "Smart" part)
        is_malicious, patterns = check_sqli(user_input)
        
        if is_malicious:
            detection = get_explanation(patterns)
            # Log the attack
            log_entry = AttackLog(
                ip_address=request.remote_addr,
                payload=user_input,
                attack_type=", ".join(detection)
            )
            db.session.add(log_entry)
            
            # Check for repeated attacks from this IP
            recent_attacks = AttackLog.query.filter_by(ip_address=request.remote_addr).filter(AttackLog.timestamp > datetime.utcnow() - timedelta(minutes=10)).count()
            if recent_attacks >= 3:
                # Block the IP
                if not BlockedIP.query.filter_by(ip_address=request.remote_addr).first():
                    new_block = BlockedIP(ip_address=request.remote_addr, reason="Multiple SQLi attempts detected")
                    db.session.add(new_block)
                log_entry.is_blocked = True
            
            db.session.commit()
            
        # 2. SANITIZE & VALIDATE (Defense in Depth)
        sanitized_input = sanitize_input(user_input)
        
        # 3. USE PARAMETERIZED QUERY (PREVENTION)
        try:
            # Query string shown for educational purposes
            query_str = "SELECT username, email FROM user WHERE username = ?"
            # The database engine handles the parameter safely
            conn = sqlite3.connect(os.path.join(basedir, 'database', 'sqli_project.db'))
            cursor = conn.cursor()
            cursor.execute(query_str, (sanitized_input,))
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Error in secure query: {e}")
            
    return render_template("secure.html", results=results, detection=detection, is_malicious=is_malicious, query_str=query_str)

@app.route("/admin")
def admin_dashboard():
    # Fetch logs for visualization
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(50).all()
    blocked_ips = BlockedIP.query.all()
    
    # Simple stats for Chart.js
    attack_counts = db.session.query(AttackLog.attack_type, db.func.count(AttackLog.id)).group_by(AttackLog.attack_type).all()
    labels = [a[0] for a in attack_counts]
    data = [a[1] for a in attack_counts]
    
    return render_template("admin.html", logs=logs, blocked_ips=blocked_ips, labels=labels, data=data)

@app.route("/api/logs")
def get_logs_api():
    logs = AttackLog.query.order_by(AttackLog.timestamp.desc()).limit(10).all()
    log_data = [{
        "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": l.ip_address,
        "payload": l.payload[:30] + "..." if len(l.payload) > 30 else l.payload,
        "type": l.attack_type
    } for l in logs]
    return jsonify(log_data)

if __name__ == "__main__":
    app.run(debug=True, port=8000)
