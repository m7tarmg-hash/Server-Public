"""
License Server - Handles license verification and activation
Deploy this on your Windows VPS or free hosting
"""
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
# FIXED: Better session configuration
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
CORS(app)

# Database setup
DATABASE = 'licenses.db'

# Admin credentials - CHANGE THESE!
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "changeme123"  # CHANGE THIS!

def get_db():
    """Get database connection"""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database"""
    db = get_db()
    cursor = db.cursor()
    
    # Licenses table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            hwid TEXT,
            days INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            activated_at TIMESTAMP,
            expires_at TIMESTAMP,
            status TEXT DEFAULT 'unused',
            customer_email TEXT,
            customer_note TEXT
        )
    ''')
    
    # Activation logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            hwid TEXT,
            action TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    db.commit()
    db.close()

def generate_license_key():
    """Generate a unique license key"""
    # Format: XXXX-XXXX-XXXX-XXXX
    chars = string.ascii_uppercase + string.digits
    parts = []
    for _ in range(4):
        part = ''.join(secrets.choice(chars) for _ in range(4))
        parts.append(part)
    return '-'.join(parts)

def require_admin(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ============= API ENDPOINTS =============

@app.route('/api/verify', methods=['POST'])
def verify_license():
    """Verify license key and HWID"""
    try:
        data = request.json
        license_key = data.get('license_key')
        hwid = data.get('hwid')
        
        if not license_key or not hwid:
            return jsonify({
                'valid': False,
                'message': 'Missing license key or HWID'
            }), 400
        
        db = get_db()
        cursor = db.cursor()
        
        # Get license info
        cursor.execute(
            'SELECT * FROM licenses WHERE license_key = ?',
            (license_key,)
        )
        license_data = cursor.fetchone()
        
        if not license_data:
            # Log failed attempt
            cursor.execute(
                'INSERT INTO activation_logs (license_key, hwid, action, ip_address) VALUES (?, ?, ?, ?)',
                (license_key, hwid, 'verify_failed_invalid', request.remote_addr)
            )
            db.commit()
            db.close()
            
            return jsonify({
                'valid': False,
                'message': 'Invalid license key'
            })
        
        # Check status
        if license_data['status'] == 'unused':
            db.close()
            return jsonify({
                'valid': False,
                'message': 'License not activated. Please activate first.'
            })
        
        # Check HWID match
        if license_data['hwid'] != hwid:
            cursor.execute(
                'INSERT INTO activation_logs (license_key, hwid, action, ip_address) VALUES (?, ?, ?, ?)',
                (license_key, hwid, 'verify_failed_hwid_mismatch', request.remote_addr)
            )
            db.commit()
            db.close()
            
            return jsonify({
                'valid': False,
                'message': 'HWID mismatch. This license is bound to another computer.'
            })
        
        # Check expiration
        if license_data['expires_at']:
            expires_at = datetime.fromisoformat(license_data['expires_at'])
            if datetime.now() > expires_at:
                cursor.execute(
                    'UPDATE licenses SET status = ? WHERE license_key = ?',
                    ('expired', license_key)
                )
                cursor.execute(
                    'INSERT INTO activation_logs (license_key, hwid, action, ip_address) VALUES (?, ?, ?, ?)',
                    (license_key, hwid, 'verify_failed_expired', request.remote_addr)
                )
                db.commit()
                db.close()
                
                return jsonify({
                    'valid': False,
                    'message': 'License expired'
                })
            
            # Calculate days remaining
            days_remaining = (expires_at - datetime.now()).days
            
            cursor.execute(
                'INSERT INTO activation_logs (license_key, hwid, action, ip_address) VALUES (?, ?, ?, ?)',
                (license_key, hwid, 'verify_success', request.remote_addr)
            )
            db.commit()
            db.close()
            
            return jsonify({
                'valid': True,
                'message': f'License valid. {days_remaining} days remaining.',
                'days_remaining': days_remaining,
                'expires_at': license_data['expires_at']
            })
        
        # Should not reach here
        db.close()
        return jsonify({
            'valid': False,
            'message': 'Invalid license state'
        })
        
    except Exception as e:
        return jsonify({
            'valid': False,
            'message': f'Server error: {str(e)}'
        }), 500

@app.route('/api/activate', methods=['POST'])
def activate_license():
    """Activate a license key with HWID"""
    try:
        data = request.json
        license_key = data.get('license_key')
        hwid = data.get('hwid')
        
        if not license_key or not hwid:
            return jsonify({
                'success': False,
                'message': 'Missing license key or HWID'
            }), 400
        
        db = get_db()
        cursor = db.cursor()
        
        # Get license info
        cursor.execute(
            'SELECT * FROM licenses WHERE license_key = ?',
            (license_key,)
        )
        license_data = cursor.fetchone()
        
        if not license_data:
            cursor.execute(
                'INSERT INTO activation_logs (license_key, hwid, action, ip_address) VALUES (?, ?, ?, ?)',
                (license_key, hwid, 'activate_failed_invalid', request.remote_addr)
            )
            db.commit()
            db.close()
            
            return jsonify({
                'success': False,
                'message': 'Invalid license key'
            })
        
        # Check if already activated
        if license_data['status'] == 'active':
            # Check if HWID matches
            if license_data['hwid'] == hwid:
                db.close()
                return jsonify({
                    'success': True,
                    'message': 'License already activated on this computer'
                })
            else:
                db.close()
                return jsonify({
                    'success': False,
                    'message': 'License already activated on another computer. HWID locked.'
                })
        
        if license_data['status'] == 'expired':
            db.close()
            return jsonify({
                'success': False,
                'message': 'License has expired'
            })
        
        # Activate license
        activated_at = datetime.now()
        expires_at = activated_at + timedelta(days=license_data['days'])
        
        cursor.execute(
            '''UPDATE licenses 
               SET hwid = ?, activated_at = ?, expires_at = ?, status = ? 
               WHERE license_key = ?''',
            (hwid, activated_at.isoformat(), expires_at.isoformat(), 'active', license_key)
        )
        
        cursor.execute(
            'INSERT INTO activation_logs (license_key, hwid, action, ip_address) VALUES (?, ?, ?, ?)',
            (license_key, hwid, 'activate_success', request.remote_addr)
        )
        
        db.commit()
        db.close()
        
        return jsonify({
            'success': True,
            'message': f'License activated successfully! Valid for {license_data["days"]} days.',
            'expires_at': expires_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Server error: {str(e)}'
        }), 500

# ============= ADMIN PANEL =============

@app.route('/')
def index():
    """Home page"""
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session.permanent = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    """Admin dashboard"""
    db = get_db()
    cursor = db.cursor()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) FROM licenses')
    total_licenses = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('active',))
    active_licenses = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('unused',))
    unused_licenses = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('expired',))
    expired_licenses = cursor.fetchone()[0]
    
    # Get recent licenses
    cursor.execute(
        'SELECT * FROM licenses ORDER BY created_at DESC LIMIT 50'
    )
    licenses = cursor.fetchall()
    
    db.close()
    
    return render_template(
        'dashboard.html',
        total=total_licenses,
        active=active_licenses,
        unused=unused_licenses,
        expired=expired_licenses,
        licenses=licenses
    )

@app.route('/admin/generate', methods=['POST'])
@require_admin
def generate_license():
    """Generate new license keys"""
    try:
        days = int(request.form.get('days', 30))
        count = int(request.form.get('count', 1))
        customer_email = request.form.get('customer_email', '')
        customer_note = request.form.get('customer_note', '')
        
        if count > 100:
            return jsonify({'error': 'Maximum 100 keys at once'}), 400
        
        db = get_db()
        cursor = db.cursor()
        
        generated_keys = []
        for _ in range(count):
            license_key = generate_license_key()
            cursor.execute(
                '''INSERT INTO licenses (license_key, days, customer_email, customer_note)
                   VALUES (?, ?, ?, ?)''',
                (license_key, days, customer_email, customer_note)
            )
            generated_keys.append(license_key)
        
        db.commit()
        db.close()
        
        return jsonify({
            'success': True,
            'keys': generated_keys,
            'count': len(generated_keys)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete/<license_key>', methods=['POST'])
@require_admin
def delete_license(license_key):
    """Delete a license"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM licenses WHERE license_key = ?', (license_key,))
        db.commit()
        db.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# FIXED: New endpoint to get updated stats and licenses
@app.route('/admin/get_licenses', methods=['GET'])
@require_admin
def get_licenses():
    """Get updated license data without page reload"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Get statistics
        cursor.execute('SELECT COUNT(*) FROM licenses')
        total_licenses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('active',))
        active_licenses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('unused',))
        unused_licenses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('expired',))
        expired_licenses = cursor.fetchone()[0]
        
        # Get recent licenses
        cursor.execute(
            'SELECT * FROM licenses ORDER BY created_at DESC LIMIT 50'
        )
        licenses_data = cursor.fetchall()
        
        db.close()
        
        # Convert to dict
        licenses = []
        for lic in licenses_data:
            licenses.append({
                'license_key': lic['license_key'],
                'status': lic['status'],
                'days': lic['days'],
                'created_at': lic['created_at'][:10] if lic['created_at'] else '-',
                'activated_at': lic['activated_at'][:10] if lic['activated_at'] else '-',
                'expires_at': lic['expires_at'][:10] if lic['expires_at'] else '-',
                'customer_email': lic['customer_email'] or '-'
            })
        
        return jsonify({
            'success': True,
            'stats': {
                'total': total_licenses,
                'active': active_licenses,
                'unused': unused_licenses,
                'expired': expired_licenses
            },
            'licenses': licenses
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/logs')
@require_admin
def view_logs():
    """View activation logs"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM activation_logs ORDER BY timestamp DESC LIMIT 100')
    logs = cursor.fetchall()
    db.close()
    return render_template('logs.html', logs=logs)

if __name__ == '__main__':
    # Initialize database
    init_db()
    print("\n" + "="*50)
    print("License Server Starting...")
    print("="*50)
    print(f"Admin Username: {ADMIN_USERNAME}")
    print(f"Admin Password: {ADMIN_PASSWORD}")
    print("="*50)
    print("\nWARNING: Change the admin password before deploying!")
    print("\n")
    
    # Run server
    app.run(host='0.0.0.0', port=5000, debug=True)
