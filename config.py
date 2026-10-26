import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybershield-soc-secret-key-2026-secure-token')
    
    # Base Directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # MySQL XAMPP Configuration (Default XAMPP credentials)
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', '')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'cybershield_db')
    
    # SQLite Fallback Path (if XAMPP MySQL service is offline)
    SQLITE_DB_PATH = os.path.join(BASE_DIR, 'database', 'cybershield.db')
    
    # Uploads Configuration
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload size
    ALLOWED_EXTENSIONS = {
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',
        'pdf', 'txt', 'log', 'pcap', 'json', 'csv', 'docx', 'zip'
    }
    
    # Application Info
    APP_NAME = "CyberShield"
    APP_TAGLINE = "Cybersecurity Incident Reporting & SOC Triage System"
    APP_VERSION = "2.4.0-SOC"
    DEFCON_LEVEL = "DEFCON 3 (ELEVATED)"
