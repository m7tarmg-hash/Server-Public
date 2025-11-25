"""
License Server - COMPLETELY FIXED VERSION
Handles license verification and activation
"""
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, make_response
from flask_cors import CORS
import sqlite3
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps
import os
import csv
import io

app = Flask(__name__)

# CRITICAL FIX: Proper session configuration
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-to-random-secret-key-in-production')
app.config.update(
    SESSION_COOKIE_NAME='license_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),  # 7 days session
    SESSION_REFRESH_EACH_REQUEST=True  # Keep session alive
)
CORS(app, supports_credentials=True)

# Database setup
DATABASE = 'licenses.db'

# Admin credentials - CHANGE THESE!
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "changeme123"

def get_db():
    """Get database connection"""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database"""
    db = get_db()
    cursor = db.cursor()
    
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
            customer_note TEXT,
            license_type TEXT DEFAULT 'discord_vm',
            admin_notes TEXT
        )
    ''')
    
    # Check if license_type column exists, if not add it
    cursor.execute("PRAGMA table_info(licenses)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'license_type' not in columns:
        cursor.execute('ALTER TABLE licenses ADD COLUMN license_type TEXT DEFAULT "discord_vm"')
    if 'admin_notes' not in columns:
        cursor.execute('ALTER TABLE licenses ADD COLUMN admin_notes TEXT')
    
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
    chars = string.ascii_uppercase + string.digits
    parts = []
    for _ in range(4):
        part = ''.join(secrets.choice(chars) for _ in range(4))
        parts.append(part)
    return '-'.join(parts)

def require_admin(f):
    """Decorator to require admin authentication - FIXED for JSON responses"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            # CRITICAL FIX: Return JSON if it's an AJAX request
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'error': 'Not authenticated',
                    'redirect': '/admin/login'
                }), 401
            # Otherwise redirect normally
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
        
        cursor.execute(
            'SELECT * FROM licenses WHERE license_key = ?',
            (license_key,)
        )
        license_data = cursor.fetchone()
        
        if not license_data:
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
        
        if license_data['status'] == 'unused':
            db.close()
            return jsonify({
                'valid': False,
                'message': 'License not activated. Please activate first.'
            })
        
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
        
        if license_data['status'] == 'active':
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
            session.permanent = True  # CRITICAL: Make session permanent
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    # If already logged in, go to dashboard
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.clear()
    return redirect(url_for('admin_login'))

# CRITICAL FIX: Check session endpoint
@app.route('/admin/check_session', methods=['GET'])
def check_session():
    """Check if user is still logged in"""
    return jsonify({
        'logged_in': session.get('admin_logged_in', False)
    })

@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    """Admin dashboard"""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM licenses')
    total_licenses = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('active',))
    active_licenses = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('unused',))
    unused_licenses = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('expired',))
    expired_licenses = cursor.fetchone()[0]
    
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
        license_type = request.form.get('license_type', 'discord_vm')
        
        if count > 100:
            return jsonify({'success': False, 'error': 'Maximum 100 keys at once'}), 400
        
        db = get_db()
        cursor = db.cursor()
        
        generated_keys = []
        for _ in range(count):
            license_key = generate_license_key()
            cursor.execute(
                '''INSERT INTO licenses (license_key, days, customer_email, customer_note, license_type)
                   VALUES (?, ?, ?, ?, ?)''',
                (license_key, days, customer_email, customer_note, license_type)
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
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/delete/<license_key>', methods=['POST', 'DELETE'])
@require_admin
def delete_license(license_key):
    """Delete a license"""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('DELETE FROM licenses WHERE license_key = ?', (license_key,))
        deleted = cursor.rowcount > 0
        db.commit()
        db.close()
        
        return jsonify({
            'success': True,
            'deleted': deleted
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/update_notes', methods=['POST'])
@require_admin
def update_notes():
    """Update admin notes for a license"""
    try:
        data = request.json
        license_key = data.get('license_key')
        admin_notes = data.get('admin_notes', '')
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'UPDATE licenses SET admin_notes = ? WHERE license_key = ?',
            (admin_notes, license_key)
        )
        db.commit()
        db.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/get_license_details/<license_key>', methods=['GET'])
@require_admin
def get_license_details(license_key):
    """Get detailed information for a specific license"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('SELECT * FROM licenses WHERE license_key = ?', (license_key,))
        license_data = cursor.fetchone()
        
        if not license_data:
            db.close()
            return jsonify({'success': False, 'error': 'License not found'}), 404
        
        # Get activation logs for this license
        cursor.execute(
            'SELECT * FROM activation_logs WHERE license_key = ? ORDER BY timestamp DESC LIMIT 10',
            (license_key,)
        )
        logs = cursor.fetchall()
        
        db.close()
        
        license_info = {
            'license_key': license_data['license_key'],
            'status': license_data['status'],
            'days': license_data['days'],
            'hwid': license_data['hwid'] or '-',
            'created_at': license_data['created_at'],
            'activated_at': license_data['activated_at'] or '-',
            'expires_at': license_data['expires_at'] or '-',
            'customer_email': license_data['customer_email'] or '-',
            'customer_note': license_data['customer_note'] or '-',
            'license_type': license_data['license_type'] or 'discord_vm',
            'admin_notes': license_data['admin_notes'] or '',
            'logs': [dict(log) for log in logs]
        }
        
        return jsonify({'success': True, 'license': license_info})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/get_licenses', methods=['GET'])
@require_admin
def get_licenses():
    """Get updated license data without page reload"""
    try:
        license_type = request.args.get('type', 'all')
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM licenses')
        total_licenses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('active',))
        active_licenses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('unused',))
        unused_licenses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM licenses WHERE status = ?', ('expired',))
        expired_licenses = cursor.fetchone()[0]
        
        if license_type == 'all':
            cursor.execute(
                'SELECT * FROM licenses ORDER BY created_at DESC LIMIT 50'
            )
        else:
            cursor.execute(
                'SELECT * FROM licenses WHERE license_type = ? ORDER BY created_at DESC LIMIT 50',
                (license_type,)
            )
        licenses_data = cursor.fetchall()
        
        db.close()
        
        licenses = []
        for lic in licenses_data:
            licenses.append({
                'license_key': lic['license_key'],
                'status': lic['status'],
                'days': lic['days'],
                'created_at': lic['created_at'][:10] if lic['created_at'] else '-',
                'activated_at': lic['activated_at'][:10] if lic['activated_at'] else '-',
                'expires_at': lic['expires_at'][:10] if lic['expires_at'] else '-',
                'customer_email': lic['customer_email'] or '-',
                'license_type': lic['license_type'] or 'discord_vm',
                'admin_notes': lic['admin_notes'] or ''
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
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/export_licenses', methods=['GET'])
@require_admin
def export_licenses():
    """Export licenses as CSV"""
    try:
        status_filter = request.args.get('status', 'all')
        license_type = request.args.get('type', 'all')
        
        db = get_db()
        cursor = db.cursor()
        
        if status_filter == 'all' and license_type == 'all':
            cursor.execute('SELECT * FROM licenses ORDER BY created_at DESC')
        elif status_filter == 'all':
            cursor.execute('SELECT * FROM licenses WHERE license_type = ? ORDER BY created_at DESC', (license_type,))
        elif license_type == 'all':
            cursor.execute('SELECT * FROM licenses WHERE status = ? ORDER BY created_at DESC', (status_filter,))
        else:
            cursor.execute('SELECT * FROM licenses WHERE status = ? AND license_type = ? ORDER BY created_at DESC', 
                          (status_filter, license_type))
        
        licenses = cursor.fetchall()
        db.close()
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['License Key', 'Status', 'Type', 'Days', 'HWID', 'Created', 'Activated', 'Expires', 'Customer Email', 'Notes', 'Admin Notes'])
        
        # Write data
        for lic in licenses:
            writer.writerow([
                lic['license_key'],
                lic['status'],
                lic['license_type'] or 'discord_vm',
                lic['days'],
                lic['hwid'] or '-',
                lic['created_at'] or '-',
                lic['activated_at'] or '-',
                lic['expires_at'] or '-',
                lic['customer_email'] or '-',
                lic['customer_note'] or '-',
                lic['admin_notes'] or '-'
            ])
        
        # Create response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=licenses_{status_filter}_{license_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return response
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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
    init_db()
    print("\n" + "="*50)
    print("License Server Starting...")
    print("="*50)
    print(f"Admin Username: {ADMIN_USERNAME}")
    print(f"Admin Password: {ADMIN_PASSWORD}")
    print("="*50)
    print("\nWARNING: Change the admin password before deploying!")
    print("\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
