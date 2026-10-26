import os
import csv
import io
import sys
import platform
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort, Response
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
import db

app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database tables and demo seed data
with app.app_context():
    db.init_db()


# ---------------------------------------------------------------------
# Context Processors & Helpers
# ---------------------------------------------------------------------
@app.context_processor
def inject_global_data():
    return {
        'get_database_status': db.get_db_status,
        'app_name': Config.APP_NAME,
        'app_version': Config.APP_VERSION,
        'defcon_level': Config.DEFCON_LEVEL,
        'current_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Security clearance required. Please authenticate.", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_audit(action, details, user_id=None):
    try:
        ip = request.remote_addr or '127.0.0.1'
        u_id = user_id or session.get('user_id')
        user_agent = request.headers.get('User-Agent', '')[:250]
        db.execute_query("""
            INSERT INTO audit_logs (user_id, action, details, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s)
        """, (u_id, action, details, ip, user_agent), commit=True)
    except Exception as e:
        print(f"[Audit Log Error]: {e}")


# ---------------------------------------------------------------------
# Authentication Routes
# ---------------------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        login_input = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not login_input or not password:
            flash("Credentials missing. Enter username and password.", "danger")
            return render_template('auth/login.html')

        user = db.execute_query("""
            SELECT * FROM users WHERE username = %s OR email = %s
        """, (login_input, login_input), fetchone=True)

        if user and check_password_hash(user['password_hash'], password):
            if not user['is_active']:
                flash("Operator account suspended. Contact SOC Administrator.", "danger")
                return render_template('auth/login.html')

            # Populate session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['email'] = user['email']
            session['role'] = user['role']
            session['department'] = user['department']

            # Update last_login
            db.execute_query("""
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s
            """, (user['id'],), commit=True)

            log_audit("USER_LOGIN", f"Operator @{user['username']} ({user['role']}) authenticated successfully.", user['id'])
            flash(f"Welcome back, {user['full_name']}. SOC Terminal session active.", "success")
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash("Invalid authentication credentials. Check username/password.", "danger")
            log_audit("FAILED_LOGIN_ATTEMPT", f"Failed authentication attempt for identifier: {login_input}")

    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        department = request.form.get('department', '').strip()
        badge_id = request.form.get('badge_id', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not full_name or not username or not email or not password:
            flash("All mandatory fields must be completed.", "danger")
            return render_template('auth/register.html')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('auth/register.html')

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template('auth/register.html')

        # Check existing username or email
        existing = db.execute_query("""
            SELECT id FROM users WHERE username = %s OR email = %s
        """, (username, email), fetchone=True)

        if existing:
            flash("Username or Email already enrolled in SOC Directory.", "danger")
            return render_template('auth/register.html')

        pw_hash = generate_password_hash(password)
        new_id = db.execute_query("""
            INSERT INTO users (username, email, password_hash, full_name, role, department, badge_id, is_active)
            VALUES (%s, %s, %s, %s, 'reporter', %s, %s, 1)
        """, (username, email, pw_hash, full_name, department, badge_id), commit=True)

        log_audit("USER_REGISTRATION", f"New personnel enrolled: @{username} ({full_name})", new_id)
        flash("Personnel account enrolled successfully! You may now sign in.", "success")
        return redirect(url_for('login'))

    return render_template('auth/register.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    log_audit("USER_LOGOUT", f"Operator @{username} terminated session.")
    session.clear()
    flash("Session terminated securely.", "info")
    return redirect(url_for('login'))


# ---------------------------------------------------------------------
# Dashboard & Analytics Routes
# ---------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    # KPI 1: Total Incidents
    total_incidents = db.execute_query("SELECT COUNT(*) AS c FROM incidents", fetchone=True)['c']

    # KPI 2: Critical & High Threats
    crit_high = db.execute_query("""
        SELECT COUNT(*) AS c FROM incidents WHERE severity IN ('Critical', 'High')
    """, fetchone=True)['c']

    # KPI 3: Under Active Investigation
    investigating = db.execute_query("""
        SELECT COUNT(*) AS c FROM incidents WHERE status IN ('New', 'Under Investigation')
    """, fetchone=True)['c']

    # KPI 4: Mitigated & Resolved
    resolved = db.execute_query("""
        SELECT COUNT(*) AS c FROM incidents WHERE status IN ('Resolved', 'Closed')
    """, fetchone=True)['c']

    resolution_rate = round((resolved / total_incidents * 100), 1) if total_incidents > 0 else 100.0

    # Chart 1: Severities
    sev_rows = db.execute_query("""
        SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity
    """, fetchall=True)
    sev_map = {r['severity'].lower(): r['count'] for r in sev_rows}

    # Chart 2: Categories
    cat_rows = db.execute_query("""
        SELECT category, COUNT(*) AS count FROM incidents GROUP BY category ORDER BY count DESC
    """, fetchall=True)
    cat_dict = {r['category']: r['count'] for r in cat_rows}

    # Chart 3: Statuses
    stat_rows = db.execute_query("""
        SELECT status, COUNT(*) AS count FROM incidents GROUP BY status
    """, fetchall=True)
    stat_map = {r['status'].lower().replace(' ', ''): r['count'] for r in stat_rows}

    # Chart 4: Trends (Simulated or chronological grouping)
    trends = {
        'labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        'values': [2, 3, 1, 5, 4, 2, total_incidents]
    }

    # Priority Incident Stream (Recent alerts)
    recent_incidents = db.execute_query("""
        SELECT i.*, u.full_name AS analyst_name
        FROM incidents i
        LEFT JOIN users u ON i.assigned_to = u.id
        ORDER BY i.created_at DESC
        LIMIT 6
    """, fetchall=True)

    chart_metrics = {
        'severity': sev_map,
        'categories': cat_dict,
        'status': stat_map,
        'trends': trends
    }

    return render_template(
        'dashboard/index.html',
        active_page='dashboard',
        total_incidents=total_incidents,
        critical_high_count=crit_high,
        active_investigating_count=investigating,
        resolved_count=resolved,
        resolution_rate=resolution_rate,
        chart_metrics=chart_metrics,
        recent_incidents=recent_incidents
    )


# ---------------------------------------------------------------------
# Incident Management Routes
# ---------------------------------------------------------------------
@app.route('/incidents')
@login_required
def list_incidents():
    q = request.args.get('q', '').strip()
    severity = request.args.get('severity', '').strip()
    category = request.args.get('category', '').strip()
    status = request.args.get('status', '').strip()

    sql = """
        SELECT i.*, 
               r.full_name AS reporter_name,
               a.full_name AS analyst_name
        FROM incidents i
        LEFT JOIN users r ON i.reported_by = r.id
        LEFT JOIN users a ON i.assigned_to = a.id
        WHERE 1=1
    """
    params = []

    if q:
        sql += " AND (i.title LIKE %s OR i.incident_code LIKE %s OR i.affected_asset LIKE %s OR i.description LIKE %s)"
        wildcard = f"%{q}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    if severity:
        sql += " AND i.severity = %s"
        params.append(severity)

    if category:
        sql += " AND i.category = %s"
        params.append(category)

    if status:
        sql += " AND i.status = %s"
        params.append(status)

    sql += " ORDER BY i.created_at DESC"

    incidents = db.execute_query(sql, params, fetchall=True)
    return render_template('incidents/list.html', active_page='incidents', incidents=incidents)

@app.route('/incidents/my')
@login_required
def my_incidents():
    user_id = session['user_id']
    incidents = db.execute_query("""
        SELECT i.*, 
               r.full_name AS reporter_name,
               a.full_name AS analyst_name
        FROM incidents i
        LEFT JOIN users r ON i.reported_by = r.id
        LEFT JOIN users a ON i.assigned_to = a.id
        WHERE i.reported_by = %s
        ORDER BY i.created_at DESC
    """, (user_id,), fetchall=True)
    return render_template('incidents/list.html', active_page='my_incidents', incidents=incidents)

@app.route('/incidents/report', methods=['GET', 'POST'])
@login_required
def report_incident():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        category = request.form.get('category', '').strip()
        severity = request.form.get('severity', 'Medium').strip()
        affected_asset = request.form.get('affected_asset', '').strip()
        incident_time = request.form.get('incident_time', '').strip()
        description = request.form.get('description', '').strip()
        immediate_actions = request.form.get('immediate_actions', '').strip()

        if not title or not category or not affected_asset or not incident_time or not description:
            flash("All required fields must be supplied.", "danger")
            return render_template('incidents/report.html', active_page='report')

        # Handle attachment upload
        attachment_filename = None
        attachment_original = None
        if 'evidence' in request.files:
            file = request.files['evidence']
            if file and file.filename != '' and allowed_file(file.filename):
                original_safe = secure_filename(file.filename)
                attachment_original = original_safe
                timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
                attachment_filename = f"{timestamp_str}_{original_safe}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment_filename)
                file.save(file_path)

        # Generate unique Incident Code (e.g., CS-2026-0042)
        count_res = db.execute_query("SELECT COUNT(*) AS c FROM incidents", fetchone=True)
        next_seq = (count_res['c'] if count_res else 0) + 1
        year_str = datetime.now().strftime('%Y')
        incident_code = f"CS-{year_str}-{next_seq:04d}"

        # Insert Incident
        user_id = session['user_id']
        incident_id = db.execute_query("""
            INSERT INTO incidents (
                incident_code, title, category, severity, status, affected_asset,
                incident_time, reported_by, description, immediate_actions,
                attachment_filename, attachment_original_name
            ) VALUES (%s, %s, %s, %s, 'New', %s, %s, %s, %s, %s, %s, %s)
        """, (
            incident_code, title, category, severity, affected_asset,
            incident_time, user_id, description, immediate_actions,
            attachment_filename, attachment_original
        ), commit=True)

        # Insert initial Timeline Record
        db.execute_query("""
            INSERT INTO incident_timeline (incident_id, user_id, action_type, description)
            VALUES (%s, %s, 'REPORTED', %s)
        """, (incident_id, user_id, f"Incident submitted by {session.get('full_name')} ({session.get('department')})"), commit=True)

        # Log system audit
        log_audit("INCIDENT_CREATE", f"Submitted security incident {incident_code}: {title}", user_id)

        flash(f"Security Alert {incident_code} transmitted to SOC command. Triage initiated.", "success")
        return redirect(url_for('incident_detail', incident_id=incident_id))

    return render_template('incidents/report.html', active_page='report')

@app.route('/incidents/<int:incident_id>')
@login_required
def incident_detail(incident_id):
    incident = db.execute_query("""
        SELECT i.*, 
               r.full_name AS reporter_name,
               r.department AS reporter_dept,
               a.full_name AS analyst_name
        FROM incidents i
        LEFT JOIN users r ON i.reported_by = r.id
        LEFT JOIN users a ON i.assigned_to = a.id
        WHERE i.id = %s
    """, (incident_id,), fetchone=True)

    if not incident:
        abort(404)

    # Comments logic: Non-analysts cannot view is_internal = 1 notes
    role = session.get('role', 'reporter')
    if role in ['analyst', 'admin']:
        comments = db.execute_query("""
            SELECT c.*, u.full_name AS author_name, u.role
            FROM incident_comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.incident_id = %s
            ORDER BY c.created_at ASC
        """, (incident_id,), fetchall=True)
    else:
        comments = db.execute_query("""
            SELECT c.*, u.full_name AS author_name, u.role
            FROM incident_comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.incident_id = %s AND c.is_internal = 0
            ORDER BY c.created_at ASC
        """, (incident_id,), fetchall=True)

    timeline = db.execute_query("""
        SELECT t.*, u.full_name AS user_name
        FROM incident_timeline t
        LEFT JOIN users u ON t.user_id = u.id
        WHERE t.incident_id = %s
        ORDER BY t.created_at DESC
    """, (incident_id,), fetchall=True)

    analysts = db.execute_query("""
        SELECT id, full_name, role FROM users WHERE role IN ('analyst', 'admin') AND is_active = 1
    """, fetchall=True)

    return render_template(
        'incidents/detail.html',
        active_page='incidents',
        incident=incident,
        comments=comments,
        timeline=timeline,
        analysts=analysts
    )

@app.route('/incidents/<int:incident_id>/triage', methods=['POST'])
@login_required
@roles_required('analyst', 'admin')
def update_incident_triage(incident_id):
    incident = db.execute_query("SELECT * FROM incidents WHERE id = %s", (incident_id,), fetchone=True)
    if not incident:
        abort(404)

    new_status = request.form.get('status')
    new_severity = request.form.get('severity')
    assigned_to_raw = request.form.get('assigned_to')
    assigned_to = int(assigned_to_raw) if assigned_to_raw else None
    containment_strategy = request.form.get('containment_strategy', '').strip()
    resolution_notes = request.form.get('resolution_notes', '').strip()

    # Track changes for timeline
    changes = []
    if new_status and new_status != incident['status']:
        changes.append(f"Status changed from '{incident['status']}' to '{new_status}'")
    if new_severity and new_severity != incident['severity']:
        changes.append(f"Severity adjusted from '{incident['severity']}' to '{new_severity}'")
    if assigned_to != incident['assigned_to']:
        if assigned_to:
            new_a = db.execute_query("SELECT full_name FROM users WHERE id = %s", (assigned_to,), fetchone=True)
            changes.append(f"Assigned to {new_a['full_name']}")
        else:
            changes.append("Unassigned analyst")

    db.execute_query("""
        UPDATE incidents
        SET status = %s, severity = %s, assigned_to = %s,
            containment_strategy = %s, resolution_notes = %s,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
    """, (new_status, new_severity, assigned_to, containment_strategy, resolution_notes, incident_id), commit=True)

    user_id = session['user_id']
    for change in changes:
        db.execute_query("""
            INSERT INTO incident_timeline (incident_id, user_id, action_type, description)
            VALUES (%s, %s, 'TRIAGE_UPDATE', %s)
        """, (incident_id, user_id, change), commit=True)

    log_audit("INCIDENT_TRIAGE", f"Updated triage on {incident['incident_code']}: {', '.join(changes) or 'Notes modified'}")
    flash(f"Triage parameters updated for {incident['incident_code']}.", "success")
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/incidents/<int:incident_id>/comment', methods=['POST'])
@login_required
def add_incident_comment(incident_id):
    comment_text = request.form.get('comment', '').strip()
    if not comment_text:
        flash("Comment cannot be empty.", "warning")
        return redirect(url_for('incident_detail', incident_id=incident_id))

    is_internal = 1 if request.form.get('is_internal') and session.get('role') in ['analyst', 'admin'] else 0
    user_id = session['user_id']

    db.execute_query("""
        INSERT INTO incident_comments (incident_id, user_id, comment, is_internal)
        VALUES (%s, %s, %s, %s)
    """, (incident_id, user_id, comment_text, is_internal), commit=True)

    # Timeline note
    note_type = "Internal SOC Note" if is_internal else "Comment"
    db.execute_query("""
        INSERT INTO incident_timeline (incident_id, user_id, action_type, description)
        VALUES (%s, %s, 'COMMENT_ADDED', %s)
    """, (incident_id, user_id, f"{note_type} appended by {session.get('full_name')}"), commit=True)

    log_audit("COMMENT_ADDED", f"Appended note to incident ID #{incident_id}")
    flash("Investigation note successfully appended.", "success")
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/incidents/<int:incident_id>/report-view')
@login_required
def incident_print_report(incident_id):
    incident = db.execute_query("""
        SELECT i.*, 
               r.full_name AS reporter_name,
               r.department AS reporter_dept,
               a.full_name AS analyst_name
        FROM incidents i
        LEFT JOIN users r ON i.reported_by = r.id
        LEFT JOIN users a ON i.assigned_to = a.id
        WHERE i.id = %s
    """, (incident_id,), fetchone=True)

    if not incident:
        abort(404)

    timeline = db.execute_query("""
        SELECT * FROM incident_timeline WHERE incident_id = %s ORDER BY created_at ASC
    """, (incident_id,), fetchall=True)

    return render_template('incidents/report_view.html', incident=incident, timeline=timeline)

@app.route('/incidents/export/csv')
@login_required
def export_incidents_csv():
    incidents = db.execute_query("""
        SELECT i.incident_code, i.title, i.category, i.severity, i.status,
               i.affected_asset, i.incident_time, r.full_name AS reporter,
               a.full_name AS analyst, i.created_at
        FROM incidents i
        LEFT JOIN users r ON i.reported_by = r.id
        LEFT JOIN users a ON i.assigned_to = a.id
        ORDER BY i.created_at DESC
    """, fetchall=True)

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow([
        'Incident Code', 'Title', 'Category', 'Severity', 'Status',
        'Affected Asset', 'Incident Time', 'Reporter', 'Assigned Analyst', 'Logged At'
    ])

    for row in incidents:
        cw.writerow([
            row['incident_code'], row['title'], row['category'], row['severity'],
            row['status'], row['affected_asset'], row['incident_time'],
            row['reporter'] or 'N/A', row['analyst'] or 'Unassigned', row['created_at']
        ])

    output = si.getvalue()
    log_audit("INCIDENT_EXPORT_CSV", f"Exported {len(incidents)} telemetry records to CSV.")
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=cybershield_incidents_export.csv"}
    )


# ---------------------------------------------------------------------
# Admin & Audit Routes
# ---------------------------------------------------------------------
@app.route('/admin/users')
@login_required
@roles_required('analyst', 'admin')
def admin_users():
    users = db.execute_query("""
        SELECT * FROM users ORDER BY created_at DESC
    """, fetchall=True)
    return render_template('admin/users.html', active_page='admin_users', users=users)

@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
@roles_required('admin')
def admin_update_user_role(user_id):
    new_role = request.form.get('role')
    if new_role not in ['reporter', 'analyst', 'admin']:
        flash("Invalid role assignment.", "danger")
        return redirect(url_for('admin_users'))

    target_user = db.execute_query("SELECT username FROM users WHERE id = %s", (user_id,), fetchone=True)
    if not target_user:
        abort(404)

    db.execute_query("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id), commit=True)
    log_audit("USER_ROLE_CHANGE", f"Elevated/Modified role for @{target_user['username']} to {new_role}")
    flash(f"Role updated for @{target_user['username']} to {new_role.upper()}.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/audit-logs')
@login_required
@roles_required('analyst', 'admin')
def admin_audit_logs():
    logs = db.execute_query("""
        SELECT a.*, u.username, u.full_name
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 100
    """, fetchall=True)
    return render_template('admin/audit_logs.html', active_page='admin_audit', logs=logs)

@app.route('/admin/system')
@login_required
@roles_required('analyst', 'admin')
def admin_system():
    sys_info = {
        'python_version': platform.python_version(),
        'flask_version': '3.1.3',
        'platform': platform.platform()
    }
    db_info = db.get_db_status()
    return render_template('admin/system.html', active_page='admin_system', db_info=db_info, sys_info=sys_info)

@app.route('/admin/test-db', methods=['POST'])
@login_required
@roles_required('analyst', 'admin')
def admin_test_db_connection():
    # Force test probe
    conn = db.get_mysql_connection()
    if conn:
        conn.close()
        db.init_db()
        flash("Successfully connected to XAMPP MySQL database server!", "success")
        log_audit("MYSQL_PROBE_SUCCESS", "Probed and connected to XAMPP MySQL.")
    else:
        flash(f"Probe failed: {db.DB_LAST_ERROR or 'XAMPP MySQL is not reachable on localhost:3306'}. Continuing on local storage.", "warning")
        log_audit("MYSQL_PROBE_FAILED", f"Probe failed: {db.DB_LAST_ERROR}")
    return redirect(url_for('admin_system'))


# ---------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('errors/500.html'), 500


# ---------------------------------------------------------------------
# Application Entrypoint
# ---------------------------------------------------------------------
if __name__ == '__main__':
    # Print launch header
    print("=" * 65)
    print("  CYBERSHIELD - Cybersecurity Incident Reporting & SOC System")
    print(f"  Status: Operational | Engine: {db.get_db_status()['engine']}")
    print("  Access URL: http://127.0.0.1:5000")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5000, debug=True)
