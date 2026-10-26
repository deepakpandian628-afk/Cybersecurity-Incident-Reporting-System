import unittest
import os
from werkzeug.security import generate_password_hash, check_password_hash

# Ensure test uses project path
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
import db

class CyberShieldTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

    def test_01_database_status(self):
        """Test database connection status and data availability"""
        status = db.get_db_status()
        self.assertIn('engine', status)
        self.assertGreater(status['total_incidents'], 0)
        self.assertGreater(status['total_users'], 0)
        print(f"\n[PASS] Database online: {status['engine']} with {status['total_incidents']} incidents and {status['total_users']} users.")

    def test_02_login_admin(self):
        """Test authentication as Administrator"""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'Admin@123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SOC Dashboard', response.data)
        self.assertIn(b'Alex Mercer', response.data)
        print("[PASS] Admin authentication verified.")

    def test_03_login_invalid_credentials(self):
        """Test rejected authentication on invalid password"""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'WrongPassword123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid authentication credentials', response.data)
        print("[PASS] Invalid login protection verified.")

    def test_04_user_registration(self):
        """Test enrolling new personnel"""
        new_username = f"test_sec_{os.urandom(3).hex()}"
        response = self.client.post('/register', data={
            'full_name': 'Test Security Officer',
            'username': new_username,
            'email': f"{new_username}@cybershield.local",
            'department': 'IT Operations',
            'badge_id': 'EMP-TEST-99',
            'password': 'UserPassword@123',
            'confirm_password': 'UserPassword@123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Personnel account enrolled successfully', response.data)

        # Verify user in database
        u = db.execute_query("SELECT * FROM users WHERE username = %s", (new_username,), fetchone=True)
        self.assertIsNotNone(u)
        self.assertEqual(u['role'], 'reporter')
        print(f"[PASS] User registration verified for @{new_username}.")

    def test_05_incident_reporting(self):
        """Test reporting a new security incident"""
        with self.client.session_transaction() as sess:
            sess['user_id'] = 4
            sess['username'] = 'user_john'
            sess['full_name'] = 'John Doe'
            sess['role'] = 'reporter'
            sess['department'] = 'Finance & Treasury'

        response = self.client.post('/incidents/report', data={
            'title': 'Automated Test Ransomware Outbreak Detection',
            'category': 'Ransomware',
            'severity': 'Critical',
            'affected_asset': '10.200.4.15 (Automated Test Node)',
            'incident_time': '2026-10-26T10:00',
            'description': 'Simulated unit testing telemetry payload for canary files alert.',
            'immediate_actions': 'Isolated test virtual machine.'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Automated Test Ransomware Outbreak Detection', response.data)
        self.assertIn(b'Critical', response.data)
        print("[PASS] Incident submission and triage redirection verified.")

    def test_06_analyst_triage_update(self):
        """Test analyst updating status, severity, and notes"""
        with self.client.session_transaction() as sess:
            sess['user_id'] = 2
            sess['username'] = 'analyst_sarah'
            sess['full_name'] = 'Sarah Chen, CISSP'
            sess['role'] = 'analyst'
            sess['department'] = 'Tier 2 Incident Response'

        # Fetch recent incident
        inc = db.execute_query("SELECT id FROM incidents ORDER BY id DESC LIMIT 1", fetchone=True)
        inc_id = inc['id']

        response = self.client.post(f'/incidents/{inc_id}/triage', data={
            'status': 'Contained',
            'severity': 'High',
            'assigned_to': '2',
            'containment_strategy': 'Automated quarantine VLAN applied.',
            'resolution_notes': 'Canary test confirmed neutral.'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Triage parameters updated', response.data)

        # Check updated record in DB
        updated = db.execute_query("SELECT * FROM incidents WHERE id = %s", (inc_id,), fetchone=True)
        self.assertEqual(updated['status'], 'Contained')
        self.assertEqual(updated['severity'], 'High')
        self.assertEqual(updated['assigned_to'], 2)
        print(f"[PASS] Analyst triage update verified on incident #{inc_id}.")

    def test_07_append_investigation_comment(self):
        """Test appending an internal analyst investigation note"""
        with self.client.session_transaction() as sess:
            sess['user_id'] = 2
            sess['username'] = 'analyst_sarah'
            sess['full_name'] = 'Sarah Chen, CISSP'
            sess['role'] = 'analyst'

        response = self.client.post('/incidents/1/comment', data={
            'comment': 'Forensic disk image verified. SHA256 integrity check matches baseline.',
            'is_internal': '1'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Forensic disk image verified', response.data)
        print("[PASS] Incident comment & investigation log verified.")

    def test_08_rbac_restriction(self):
        """Test role-based access control blocking unauthorized users"""
        with self.client.session_transaction() as sess:
            sess['user_id'] = 4
            sess['username'] = 'user_john'
            sess['role'] = 'reporter'

        # Reporter trying to access User Administration
        response = self.client.get('/admin/users')
        self.assertEqual(response.status_code, 403)
        print("[PASS] RBAC protection: 403 Forbidden verified for non-admin user.")

    def test_09_csv_telemetry_export(self):
        """Test CSV telemetry download endpoint"""
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'admin'
            sess['role'] = 'admin'

        response = self.client.get('/incidents/export/csv')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'text/csv')
        self.assertIn(b'Incident Code,Title,Category', response.data)
        print("[PASS] CSV telemetry export verified.")

    def test_10_printable_dossier_view(self):
        """Test formal printable incident report view"""
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'admin'
            sess['role'] = 'admin'

        response = self.client.get('/incidents/1/report-view')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'CONFIDENTIAL // SOC RESTRICTED', response.data)
        self.assertIn(b'CS-2026-0001', response.data)
        print("[PASS] Printable formal incident response report verified.")

if __name__ == '__main__':
    unittest.main()
