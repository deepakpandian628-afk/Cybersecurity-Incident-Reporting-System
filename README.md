# CyberShield – Cybersecurity Incident Reporting & SOC Triage System

**CyberShield** is a Security Operations Center (SOC) incident reporting, threat triage, and response platform developed using **Python**, **Flask**, **MySQL (via XAMPP)**, **Bootstrap 5**, and **Chart.js**.

Designed specifically for college mini-project submissions, laboratory evaluations, live demonstrations, and viva voce examinations, CyberShield equips academic and enterprise users with a defense-grade triage console.

---

## 🛡️ Project Highlights & Features

- **Modern SOC Interface:**
  - Dark navy blue and space-black theme with neon cyan and cyber-blue accents.
  - Interactive KPI cards (Total Incidents, Critical/High Alerts, Under Investigation, Mitigated).
  - Dynamic **Chart.js** data visualizations: Severity distribution, Threat category breakdown, Velocity timeline, and Triage pipeline.
  - Real-time digital clock displaying both Local and UTC time zones with live DEFCON status pills.

- **Role-Based Access Control (RBAC):**
  - **Administrator (CSO):** Full system access, personnel role management (Reporter ↔ Analyst ↔ Admin), immutable audit trails, and database telemetry.
  - **SOC Analyst:** Full incident queue access, severity re-assessment, status transitions (New → Investigating → Contained → Resolved), containment strategy notes, and private internal investigation logs.
  - **Incident Reporter (Employee):** Submit new incident alerts with forensics attachments, track ticket lifecycle, and append public updates.

- **Incident Lifecycle & Forensics:**
  - Automated unique incident identifier formatting (e.g., `CS-2026-0001`).
  - Multi-vector threat classification: Phishing, Ransomware, DDoS, Unauthorized Access, Data Breach, Malware, Vulnerability Exploit, and Insider Threat.
  - Digital forensics file upload support (PCAP, LOG, TXT, PDF, PNG, JPG).
  - Chronological incident audit trail recording all triage actions and comments.
  - 1-Click formal printable **Incident Response Dossier** for examiners.
  - Telemetry export to CSV for data analysis.

- **Dual-Mode Database Architecture (XAMPP MySQL + Local Engine):**
  - Configured out-of-the-box for **XAMPP MySQL** (`localhost:3306`, user `root`, password `""`, database `cybershield_db`).
  - Includes full SQL schema dump file (`database/cybershield_db.sql`) for one-click phpMyAdmin import.
  - Built-in automatic database initialization and seeding.
  - Resilient local engine fallback prevents crashes if XAMPP MySQL is not yet started, with a 1-click reconnect button once Apache/MySQL is activated.

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| **Backend Framework** | Python 3.12 / Flask 3.1 |
| **Primary Database** | MySQL through XAMPP (PyMySQL driver) |
| **Frontend Framework** | Bootstrap 5.3 & Custom Cyber CSS |
| **Icons & Typography** | FontAwesome 6, Bootstrap Icons, Rajdhani & Inter |
| **Visualizations** | Chart.js 4.4 |
| **Security & Auth** | Werkzeug PBKDF2:SHA256 password hashing, RBAC |

---

## 🚀 Quick Start Guide (Windows Laptop)

### 1. Prerequisites
- Python 3.10+ installed
- XAMPP installed (with Apache & MySQL)

### 2. XAMPP MySQL Setup (phpMyAdmin)
1. Open the **XAMPP Control Panel**.
2. Click **Start** for **Apache** and **MySQL**.
3. Open your browser and navigate to:
   ```
   http://localhost/phpmyadmin
   ```
4. Click on **Import** in the top navigation bar.
5. Click **Choose File** and select:
   ```
   cybershield/database/cybershield_db.sql
   ```
6. Scroll down and click **Import** (or **Go**).
7. The `cybershield_db` database is now created and pre-populated with realistic cybersecurity incidents!

### 3. Running the CyberShield Application
Open PowerShell or Command Prompt in the project folder and run:

```powershell
# Navigate to the project directory
cd C:\Users\deepa\.gemini\antigravity\scratch\cybershield

# Run the application
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🔑 Pre-Seeded Demonstration Accounts

For viva examinations, 1-click credential selector buttons are built directly into the login screen:

| Role | Username | Password | Email | Purpose |
|---|---|---|---|---|
| **CSO Administrator** | `admin` | `Admin@123` | `admin@cybershield.local` | Full system control, role elevation, audit logs |
| **Tier 2 SOC Analyst** | `analyst_sarah` | `Analyst@123` | `sarah.chen@cybershield.local` | Incident triage, severity changes, forensic notes |
| **Incident Reporter** | `user_john` | `User@123` | `john.doe@cybershield.local` | Submit new tickets, track submitted alerts |

---

## 📂 Project Directory Structure

```
cybershield/
│
├── app.py                     # Main Flask application router & API endpoints
├── config.py                  # Database & upload configuration
├── db.py                      # Dual-mode database layer (MySQL + SQLite fallback)
├── requirements.txt           # Python dependency requirements
├── README.md                  # Comprehensive manual & viva prep
│
├── database/
│   └── cybershield_db.sql     # Standalone MySQL dump for phpMyAdmin
│
├── static/
│   ├── css/
│   │   ├── style.css          # Dark SOC cybersecurity stylesheet
│   │   └── print.css          # Printable formal incident dossier styles
│   ├── js/
│   │   ├── dashboard.js       # Chart.js charts & dynamic analytics
│   │   └── main.js            # General UI interactions & auto clock
│   └── uploads/               # Storage for incident evidence attachments
│
└── templates/
    ├── base.html              # Base layout with SOC topbar & navigation
    ├── auth/
    │   ├── login.html         # Login page with 1-click credential autofill
    │   └── register.html      # User registration form
    ├── dashboard/
    │   └── index.html         # Executive SOC dashboard with KPI cards & charts
    ├── incidents/
    │   ├── list.html          # Incident directory with multi-field search & filters
    │   ├── report.html        # New Incident submission form
    │   ├── detail.html        # Incident Dossier & triage control console
    │   └── report_view.html   # Printable formal incident response report
    ├── admin/
    │   ├── users.html         # User management & role elevation
    │   ├── audit_logs.html    # Immutable audit trail
    │   └── system.html        # System health & XAMPP MySQL probe
    └── errors/
        ├── 403.html           # 403 Forbidden intrusion notice
        ├── 404.html           # 404 Not Found notice
        └── 500.html           # 500 Server Anomaly notice
```

---

## 🎓 College Viva Voce Questions & Answers

**Q1: What is the main objective of CyberShield?**  
*A:* CyberShield provides a centralized Security Operations Center (SOC) incident reporting and triage platform. It enables employees to log cyber threats, while giving SOC analysts tools to contain, investigate, and mitigate incidents, maintaining a full audit trail.

**Q2: How does the application connect to MySQL via XAMPP?**  
*A:* The application uses `PyMySQL` to connect to `localhost:3306` with credentials configured in `config.py`. In addition, `db.py` contains automated schema verification that initializes tables and seeds records seamlessly.

**Q3: How are user passwords secured?**  
*A:* Passwords are never stored in plaintext. They are hashed using Werkzeug's `generate_password_hash` with the `scrypt` or `pbkdf2:sha256` hashing algorithm with cryptographic salt.

**Q4: How does CyberShield protect against SQL Injection?**  
*A:* All database queries use parameterized queries (prepared statements) with `%s` placeholders, separating executable SQL code from user inputs.

**Q5: What is the difference between an Internal Note and a Comment?**  
*A:* Internal Notes (`is_internal = 1`) are restricted strictly to SOC Analysts and Administrators for forensic details and threat intel indicators (IOCs). Standard comments are visible to the reporting employee.
