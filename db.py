import os
import sqlite3
import pymysql
import pymysql.cursors
from werkzeug.security import generate_password_hash
from config import Config

# Module-level variable tracking active engine
ACTIVE_ENGINE = None  # 'mysql' or 'sqlite'
DB_LAST_ERROR = None

def get_mysql_connection(create_db_if_missing=True):
    """Attempt connection to MySQL (XAMPP)"""
    global DB_LAST_ERROR
    try:
        # First connect without db to ensure database exists if needed
        if create_db_if_missing:
            raw_conn = pymysql.connect(
                host=Config.MYSQL_HOST,
                port=Config.MYSQL_PORT,
                user=Config.MYSQL_USER,
                password=Config.MYSQL_PASSWORD,
                charset='utf8mb4',
                connect_timeout=3
            )
            with raw_conn.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{Config.MYSQL_DB}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            raw_conn.commit()
            raw_conn.close()

        # Connect to specific database
        conn = pymysql.connect(
            host=Config.MYSQL_HOST,
            port=Config.MYSQL_PORT,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=3,
            autocommit=False
        )
        DB_LAST_ERROR = None
        return conn
    except Exception as e:
        DB_LAST_ERROR = str(e)
        return None

def get_sqlite_connection():
    """Fallback connection to SQLite"""
    os.makedirs(os.path.dirname(Config.SQLITE_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_db():
    """Get an active database connection with automatic fallback"""
    global ACTIVE_ENGINE
    
    # Try MySQL first if configured or currently active
    mysql_conn = get_mysql_connection()
    if mysql_conn:
        ACTIVE_ENGINE = 'mysql'
        return mysql_conn, 'mysql'
    
    # Otherwise fallback to SQLite
    ACTIVE_ENGINE = 'sqlite'
    return get_sqlite_connection(), 'sqlite'

def execute_query(sql, params=None, fetchone=False, fetchall=False, commit=False):
    """
    Execute SQL query agnostic of backend (MySQL / SQLite).
    Automatically translates %s to ? when using SQLite.
    Returns row dictionaries or scalar values.
    """
    conn, engine = get_db()
    cursor = None
    try:
        if engine == 'mysql':
            cursor = conn.cursor()
            cursor.execute(sql, params or ())
            if commit:
                conn.commit()
                last_id = cursor.lastrowid
                return last_id
            if fetchone:
                return cursor.fetchone()
            if fetchall:
                return cursor.fetchall()
            return cursor.rowcount
            
        else:  # sqlite
            cursor = conn.cursor()
            # Convert %s placeholders to ? for SQLite
            sqlite_sql = sql.replace('%s', '?')
            # Handle standard MySQL functions/types in SQLite
            sqlite_sql = sqlite_sql.replace('NOW()', "datetime('now', 'localtime')")
            sqlite_sql = sqlite_sql.replace('CURRENT_TIMESTAMP', "datetime('now', 'localtime')")
            
            cursor.execute(sqlite_sql, params or ())
            if commit:
                conn.commit()
                last_id = cursor.lastrowid
                return last_id
            if fetchone:
                row = cursor.fetchone()
                return dict(row) if row else None
            if fetchall:
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            return cursor.rowcount
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def get_db_status():
    """Return diagnostic details of the active database engine"""
    conn, engine = get_db()
    try:
        if engine == 'mysql':
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS total_incidents FROM incidents")
                inc_count = cur.fetchone()['total_incidents']
                cur.execute("SELECT COUNT(*) AS total_users FROM users")
                usr_count = cur.fetchone()['total_users']
            return {
                'engine': 'MySQL (XAMPP)',
                'badge_class': 'bg-success',
                'is_mysql': True,
                'status': 'Connected & Active',
                'host': f"{Config.MYSQL_HOST}:{Config.MYSQL_PORT}",
                'database': Config.MYSQL_DB,
                'user': Config.MYSQL_USER,
                'total_incidents': inc_count,
                'total_users': usr_count,
                'error': None
            }
        else:
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM incidents")
                inc_count = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM users")
                usr_count = cur.fetchone()[0]
            return {
                'engine': 'SQLite (Local Engine)',
                'badge_class': 'bg-cyan text-dark',
                'is_mysql': False,
                'status': 'Active (Ready for XAMPP MySQL when started)',
                'host': 'Local Disk',
                'database': os.path.basename(Config.SQLITE_DB_PATH),
                'user': 'system',
                'total_incidents': inc_count,
                'total_users': usr_count,
                'error': DB_LAST_ERROR or "XAMPP MySQL is not currently running on port 3306."
            }
    except Exception as e:
        return {
            'engine': 'Unknown',
            'badge_class': 'bg-danger',
            'is_mysql': False,
            'status': 'Error',
            'host': 'N/A',
            'database': 'N/A',
            'user': 'N/A',
            'total_incidents': 0,
            'total_users': 0,
            'error': str(e)
        }
    finally:
        if conn:
            conn.close()

def init_db():
    """
    Initialize schema and seed initial data for the active database engine.
    Safe to run repeatedly; uses IF NOT EXISTS and checks existing records.
    """
    conn, engine = get_db()
    try:
        if engine == 'mysql':
            _init_mysql_schema(conn)
        else:
            _init_sqlite_schema(conn)
    finally:
        if conn:
            conn.close()

def _init_mysql_schema(conn):
    with conn.cursor() as cur:
        # Create users table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) NOT NULL UNIQUE,
            email VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(100) NOT NULL,
            role ENUM('reporter', 'analyst', 'admin') NOT NULL DEFAULT 'reporter',
            department VARCHAR(100) NOT NULL DEFAULT 'Corporate IT',
            badge_id VARCHAR(30) DEFAULT 'CS-SEC-01',
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP NULL DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        # Create incidents table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INT AUTO_INCREMENT PRIMARY KEY,
            incident_code VARCHAR(30) NOT NULL UNIQUE,
            title VARCHAR(255) NOT NULL,
            category VARCHAR(60) NOT NULL,
            severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL DEFAULT 'Medium',
            status ENUM('New', 'Under Investigation', 'Contained', 'Resolved', 'Closed', 'False Positive') NOT NULL DEFAULT 'New',
            affected_asset VARCHAR(255) NOT NULL,
            incident_time DATETIME NOT NULL,
            reported_by INT NOT NULL,
            assigned_to INT NULL DEFAULT NULL,
            description TEXT NOT NULL,
            immediate_actions TEXT NULL,
            containment_strategy TEXT NULL,
            resolution_notes TEXT NULL,
            attachment_filename VARCHAR(255) NULL DEFAULT NULL,
            attachment_original_name VARCHAR(255) NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_status (status),
            INDEX idx_severity (severity),
            INDEX idx_category (category),
            CONSTRAINT fk_inc_rep FOREIGN KEY (reported_by) REFERENCES users (id) ON DELETE CASCADE,
            CONSTRAINT fk_inc_ass FOREIGN KEY (assigned_to) REFERENCES users (id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        # Create incident_comments table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS incident_comments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            incident_id INT NOT NULL,
            user_id INT NOT NULL,
            comment TEXT NOT NULL,
            is_internal TINYINT(1) NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_com_inc FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE CASCADE,
            CONSTRAINT fk_com_usr FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        # Create incident_timeline table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS incident_timeline (
            id INT AUTO_INCREMENT PRIMARY KEY,
            incident_id INT NOT NULL,
            user_id INT NULL DEFAULT NULL,
            action_type VARCHAR(50) NOT NULL,
            description VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_tim_inc FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE CASCADE,
            CONSTRAINT fk_tim_usr FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        # Create audit_logs table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL DEFAULT NULL,
            action VARCHAR(100) NOT NULL,
            details TEXT NULL,
            ip_address VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
            user_agent VARCHAR(255) NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_aud_usr FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)

        conn.commit()

        # Seed data if users table is empty
        cur.execute("SELECT COUNT(*) AS count FROM users")
        if cur.fetchone()['count'] == 0:
            _seed_sample_data(conn, 'mysql')

def _init_sqlite_schema(conn):
    cur = conn.cursor()
    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'reporter',
        department TEXT NOT NULL DEFAULT 'Corporate IT',
        badge_id TEXT DEFAULT 'CS-SEC-01',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        last_login TEXT DEFAULT NULL
    );
    """)

    # Incidents table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_code TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'Medium',
        status TEXT NOT NULL DEFAULT 'New',
        affected_asset TEXT NOT NULL,
        incident_time TEXT NOT NULL,
        reported_by INTEGER NOT NULL,
        assigned_to INTEGER DEFAULT NULL,
        description TEXT NOT NULL,
        immediate_actions TEXT DEFAULT NULL,
        containment_strategy TEXT DEFAULT NULL,
        resolution_notes TEXT DEFAULT NULL,
        attachment_filename TEXT DEFAULT NULL,
        attachment_original_name TEXT DEFAULT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (reported_by) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
    );
    """)

    # Incident Comments
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        comment TEXT NOT NULL,
        is_internal INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    # Incident Timeline
    cur.execute("""
    CREATE TABLE IF NOT EXISTS incident_timeline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        user_id INTEGER DEFAULT NULL,
        action_type TEXT NOT NULL,
        description TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)

    # Audit Logs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER DEFAULT NULL,
        action TEXT NOT NULL,
        details TEXT DEFAULT NULL,
        ip_address TEXT NOT NULL DEFAULT '127.0.0.1',
        user_agent TEXT DEFAULT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    """)

    conn.commit()

    # Check if empty, seed if necessary
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        _seed_sample_data(conn, 'sqlite')

def _seed_sample_data(conn, engine):
    """Seed high-fidelity cybersecurity demo data"""
    admin_pw = generate_password_hash("Admin@123")
    analyst_pw = generate_password_hash("Analyst@123")
    user_pw = generate_password_hash("User@123")

    users_data = [
        ('admin', 'admin@cybershield.local', admin_pw, 'Alex Mercer (CSO)', 'admin', 'SOC Leadership', 'SOC-001-ADM', 1),
        ('analyst_sarah', 'sarah.chen@cybershield.local', analyst_pw, 'Sarah Chen, CISSP', 'analyst', 'Tier 2 Incident Response', 'SOC-042-ANA', 1),
        ('analyst_marcus', 'marcus.vance@cybershield.local', analyst_pw, 'Marcus Vance, CEH', 'analyst', 'Tier 1 Threat Hunting', 'SOC-089-ANA', 1),
        ('user_john', 'john.doe@cybershield.local', user_pw, 'John Doe', 'reporter', 'Finance & Treasury', 'EMP-104-FIN', 1),
        ('user_emily', 'emily.clark@cybershield.local', user_pw, 'Emily Clark', 'reporter', 'Human Resources', 'EMP-215-HR', 1),
    ]

    incidents_data = [
        (
            'CS-2026-0001',
            'Ransomware Canary Alert on Financial File Share',
            'Ransomware',
            'Critical',
            'Contained',
            'FIN-SRV-04 (192.168.10.45)',
            '2026-10-24 14:32:00',
            4, 2,
            'Detection of rapid encrypted file renaming (.locked extension) and high I/O spikes in the finance shared drive. Multiple decoy canary files triggered SIEM alert.',
            'Disconnected FIN-SRV-04 network cable immediately and revoked SMB network access tokens.',
            'Isolated subnet 192.168.10.0/24 on core firewall, terminated rogue process rundll32.exe matching hash SHA256: 8f9ba12c...',
            'Share restored from hourly snapshot. No ransom requested or paid.'
        ),
        (
            'CS-2026-0002',
            'Targeted Spear Phishing with Malicious PDF Dropper',
            'Phishing',
            'High',
            'Resolved',
            'Exchange Online / HR Department',
            '2026-10-25 09:15:00',
            5, 2,
            'Multiple HR employees received an email titled "Urgent: Q3 Bonus Review.pdf" originating from spoofed domain @cybershield-hr.co. PDF contained weaponized JavaScript macro.',
            'Sent organization-wide security alert and purged 42 emails from user mailboxes via M365 Security API.',
            'Blocked sender domain and IP range 198.51.100.24 on perimeter email gateway.',
            'Domain blacklisted globally in Proofpoint. Endpoint EDR quarantined the 2 workstations that previewed the document.'
        ),
        (
            'CS-2026-0003',
            'SYN Flood Distributed Denial of Service (DDoS) on API Gateway',
            'DDoS',
            'High',
            'Resolved',
            'api.cybershield.org (203.0.113.80)',
            '2026-10-25 18:40:00',
            1, 3,
            'Massive inbound traffic spike reaching 45 Gbps targeting TCP port 443. Legitimate customer requests dropped with HTTP 504 Gateway Timeout.',
            'Engaged Cloudflare Under-Attack Mode and enabled aggressive SYN cookie challenge rules.',
            'Routed traffic through Cloudflare Magic Transit and dropped traffic from non-whitelisted ASN blocks.',
            'Attack subsided after 42 minutes. Latency restored to nominal 38ms.'
        ),
        (
            'CS-2026-0004',
            'Repeated SSH Brute Force Attacks on Perimeter Bastion',
            'Unauthorized Access',
            'Medium',
            'Under Investigation',
            'bastion-ext.cybershield.net (198.51.100.12)',
            '2026-10-26 03:12:00',
            1, 3,
            'Over 14,000 failed SSH login attempts detected within 30 minutes targeting root and admin usernames from distributed foreign IP botnets.',
            'Fail2ban automatically blocked offending IP addresses for 24 hours.',
            'Enforcing IP allowlisting on port 22 and requiring Hardware MFA (FIDO2) for SSH sessions.',
            None
        ),
        (
            'CS-2026-0005',
            'Anomalous Outbound Data Transfer via DNS Tunneling',
            'Data Breach',
            'Critical',
            'Under Investigation',
            'DEV-WS-114 (10.0.5.88)',
            '2026-10-26 08:05:00',
            2, 2,
            'SIEM alert triggered for unusually high frequency of base64-encoded TXT record lookups to a dynamic DNS domain (*.xyz-cdn.me). Potential exfiltration of source code repository.',
            'Port-isolated DEV-WS-114 and memory dump captured for forensic analysis.',
            'DNS firewall sinkholed domain xyz-cdn.me and blocked outbound UDP/TCP 53 to unauthorized resolvers.',
            None
        ),
        (
            'CS-2026-0006',
            'SQL Injection Attempt on Customer Portal Login Endpoint',
            'Vulnerability Exploit',
            'Medium',
            'New',
            'Customer Auth Portal (login.php)',
            '2026-10-26 09:45:00',
            1, None,
            'ModSecurity WAF blocked HTTP POST payload containing UNION SELECT schema_name from information_schema.schemata in password parameter.',
            'WAF automatically dropped the HTTP request and issued 403 Forbidden.',
            None,
            None
        ),
        (
            'CS-2026-0007',
            'Unauthorized USB Mass Storage Device Insertion in Data Center',
            'Insider Threat',
            'Low',
            'Resolved',
            'DC-PROD-SQL01 (Physical Console)',
            '2026-10-23 11:20:00',
            1, 3,
            'Host intrusion detection system logged insertion of SanDisk 64GB USB device on production database server console.',
            'Device was auto-blocked by CrowdStrike Device Control policy.',
            'Interviewed contractor technician; confirmed accidental insertion during routine diagnostic backup.',
            'Security reminder issued to external vendor. Hardware scanned clean.'
        )
    ]

    comments_data = [
        (1, 2, 'Host memory dump acquired using LiME. Sandbox analysis confirms Ransom.Win32.LockBit variant.', 1),
        (1, 4, 'Thank you SOC team for the swift response. Can finance access our backup share yet?', 0),
        (1, 2, 'Backup share restored in read-only audit mode for verification. All clear.', 0),
        (5, 2, 'Memory forensics ongoing with Volatility 3. Identified infected PowerShell script invoked by scheduled task update_sync.', 1),
        (2, 2, 'Campaign appears tied to threat actor group TA505. Threat intel indicators pushed to MISP platform.', 1)
    ]

    timeline_data = [
        (1, 4, 'REPORTED', 'Incident submitted by John Doe (Finance & Treasury)'),
        (1, 1, 'ASSIGNED', 'Assigned to Sarah Chen (Lead Incident Responder)'),
        (1, 2, 'STATUS_CHANGE', 'Status changed from New to Under Investigation'),
        (1, 2, 'STATUS_CHANGE', 'Status changed from Under Investigation to Contained'),
        (2, 5, 'REPORTED', 'Incident submitted by Emily Clark (Human Resources)'),
        (2, 2, 'ASSIGNED', 'Claimed by Sarah Chen, CISSP'),
        (2, 2, 'RESOLVED', 'Threat mitigated and email campaign purged from mailboxes'),
        (5, 2, 'REPORTED', 'SIEM automated anomaly ticket generated and claimed by Sarah Chen')
    ]

    audit_data = [
        (1, 'SYSTEM_STARTUP', 'CyberShield SOC platform initialized successfully.', '127.0.0.1'),
        (1, 'USER_LOGIN', 'Administrator logged in to SOC Console.', '127.0.0.1'),
        (2, 'USER_LOGIN', 'Analyst Sarah Chen authenticated via 2FA.', '192.168.1.15'),
        (2, 'INCIDENT_TRIAGE', 'Claimed ticket CS-2026-0005: DNS Tunneling Anomaly.', '192.168.1.15'),
        (4, 'INCIDENT_CREATE', 'User John Doe submitted ticket CS-2026-0001: Ransomware Canary.', '192.168.10.45')
    ]

    if engine == 'mysql':
        with conn.cursor() as cur:
            cur.executemany("""
                INSERT INTO users (username, email, password_hash, full_name, role, department, badge_id, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, users_data)

            cur.executemany("""
                INSERT INTO incidents (incident_code, title, category, severity, status, affected_asset, incident_time, reported_by, assigned_to, description, immediate_actions, containment_strategy, resolution_notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, incidents_data)

            cur.executemany("""
                INSERT INTO incident_comments (incident_id, user_id, comment, is_internal)
                VALUES (%s, %s, %s, %s)
            """, comments_data)

            cur.executemany("""
                INSERT INTO incident_timeline (incident_id, user_id, action_type, description)
                VALUES (%s, %s, %s, %s)
            """, timeline_data)

            cur.executemany("""
                INSERT INTO audit_logs (user_id, action, details, ip_address)
                VALUES (%s, %s, %s, %s)
            """, audit_data)
            conn.commit()
    else:
        cur = conn.cursor()
        cur.executemany("""
            INSERT INTO users (username, email, password_hash, full_name, role, department, badge_id, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, users_data)

        cur.executemany("""
            INSERT INTO incidents (incident_code, title, category, severity, status, affected_asset, incident_time, reported_by, assigned_to, description, immediate_actions, containment_strategy, resolution_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, incidents_data)

        cur.executemany("""
            INSERT INTO incident_comments (incident_id, user_id, comment, is_internal)
            VALUES (?, ?, ?, ?)
        """, comments_data)

        cur.executemany("""
            INSERT INTO incident_timeline (incident_id, user_id, action_type, description)
            VALUES (?, ?, ?, ?)
        """, timeline_data)

        cur.executemany("""
            INSERT INTO audit_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        """, audit_data)
        conn.commit()
