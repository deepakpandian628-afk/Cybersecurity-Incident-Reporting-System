-- ====================================================================
-- CyberShield: Cybersecurity Incident Reporting & SOC Triage System
-- Database Schema for MySQL / XAMPP (phpMyAdmin compatible)
-- Database Name: cybershield_db
-- ====================================================================

CREATE DATABASE IF NOT EXISTS `cybershield_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cybershield_db`;

-- --------------------------------------------------------------------
-- Table: users
-- Roles: 'reporter', 'analyst', 'admin'
-- --------------------------------------------------------------------
DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `incident_timeline`;
DROP TABLE IF EXISTS `incident_comments`;
DROP TABLE IF EXISTS `incidents`;
DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `email` VARCHAR(100) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `full_name` VARCHAR(100) NOT NULL,
  `role` ENUM('reporter', 'analyst', 'admin') NOT NULL DEFAULT 'reporter',
  `department` VARCHAR(100) NOT NULL DEFAULT 'Corporate IT',
  `badge_id` VARCHAR(30) DEFAULT 'CS-SEC-01',
  `is_active` TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` TIMESTAMP NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Table: incidents
-- Categories: Phishing, Ransomware, DDoS, Unauthorized Access,
--             Data Breach, Malware, Vulnerability Exploit, Insider Threat, Other
-- Severities: Low, Medium, High, Critical
-- Statuses: New, Under Investigation, Contained, Resolved, Closed, False Positive
-- --------------------------------------------------------------------
CREATE TABLE `incidents` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `incident_code` VARCHAR(30) NOT NULL UNIQUE,
  `title` VARCHAR(255) NOT NULL,
  `category` VARCHAR(60) NOT NULL,
  `severity` ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL DEFAULT 'Medium',
  `status` ENUM('New', 'Under Investigation', 'Contained', 'Resolved', 'Closed', 'False Positive') NOT NULL DEFAULT 'New',
  `affected_asset` VARCHAR(255) NOT NULL,
  `incident_time` DATETIME NOT NULL,
  `reported_by` INT NOT NULL,
  `assigned_to` INT NULL DEFAULT NULL,
  `description` TEXT NOT NULL,
  `immediate_actions` TEXT NULL,
  `containment_strategy` TEXT NULL,
  `resolution_notes` TEXT NULL,
  `attachment_filename` VARCHAR(255) NULL DEFAULT NULL,
  `attachment_original_name` VARCHAR(255) NULL DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_status` (`status`),
  INDEX `idx_severity` (`severity`),
  INDEX `idx_category` (`category`),
  INDEX `idx_incident_time` (`incident_time`),
  CONSTRAINT `fk_incident_reporter` FOREIGN KEY (`reported_by`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_incident_assigned` FOREIGN KEY (`assigned_to`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Table: incident_comments
-- --------------------------------------------------------------------
CREATE TABLE `incident_comments` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `incident_id` INT NOT NULL,
  `user_id` INT NOT NULL,
  `comment` TEXT NOT NULL,
  `is_internal` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_incident_comments` (`incident_id`),
  CONSTRAINT `fk_comment_incident` FOREIGN KEY (`incident_id`) REFERENCES `incidents` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_comment_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Table: incident_timeline
-- --------------------------------------------------------------------
CREATE TABLE `incident_timeline` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `incident_id` INT NOT NULL,
  `user_id` INT NULL DEFAULT NULL,
  `action_type` VARCHAR(50) NOT NULL,
  `description` VARCHAR(255) NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_timeline_incident` (`incident_id`),
  CONSTRAINT `fk_timeline_incident` FOREIGN KEY (`incident_id`) REFERENCES `incidents` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_timeline_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------------------
-- Table: audit_logs
-- --------------------------------------------------------------------
CREATE TABLE `audit_logs` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NULL DEFAULT NULL,
  `action` VARCHAR(100) NOT NULL,
  `details` TEXT NULL,
  `ip_address` VARCHAR(45) NOT NULL DEFAULT '127.0.0.1',
  `user_agent` VARCHAR(255) NULL DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_audit_user` (`user_id`),
  CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================================
-- SEED DATA
-- Default Passwords:
-- Admin:    Admin@123
-- Analyst:  Analyst@123
-- Reporter: User@123
-- (Hashed using Werkzeug pbkdf2:sha256)
-- ====================================================================

INSERT INTO `users` (`id`, `username`, `email`, `password_hash`, `full_name`, `role`, `department`, `badge_id`, `is_active`) VALUES
(1, 'admin', 'admin@cybershield.local', 'scrypt:32768:8:1$n4U0T58vGfK9w31A$c06c0aa5ea9c6a1bcefa6ec39d5718df8832a8ff248a34241d9bf6c1411516e83cbfeae4ceb188c9a35e86dcfd7620eb6a7c36a6e8b4eac89599d19a2e887cf4', 'Chief Security Officer (CSO)', 'admin', 'SOC Leadership', 'SOC-001-ADM', 1),
(2, 'analyst_sarah', 'sarah.chen@cybershield.local', 'scrypt:32768:8:1$k1j2h3k4l5m6n7o8$a5c7f8e1b2d34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd', 'Sarah Chen, CISSP', 'analyst', 'Tier 2 SOC Incident Response', 'SOC-042-ANA', 1),
(3, 'analyst_marcus', 'marcus.vance@cybershield.local', 'scrypt:32768:8:1$k1j2h3k4l5m6n7o8$a5c7f8e1b2d34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd', 'Marcus Vance, CEH', 'analyst', 'Tier 1 SOC Threat Hunter', 'SOC-089-ANA', 1),
(4, 'user_john', 'john.doe@cybershield.local', 'scrypt:32768:8:1$p1q2r3s4t5u6v7w8$b6d8a9f2c3e4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890bcde', 'John Doe', 'reporter', 'Finance & Accounting', 'EMP-104-FIN', 1),
(5, 'user_emily', 'emily.clark@cybershield.local', 'scrypt:32768:8:1$p1q2r3s4t5u6v7w8$b6d8a9f2c3e4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890bcde', 'Emily Clark', 'reporter', 'Human Resources', 'EMP-215-HR', 1);

INSERT INTO `incidents` (`id`, `incident_code`, `title`, `category`, `severity`, `status`, `affected_asset`, `incident_time`, `reported_by`, `assigned_to`, `description`, `immediate_actions`, `containment_strategy`, `resolution_notes`, `created_at`) VALUES
(1, 'CS-2026-0001', 'Ransomware Canary Alert on Financial File Share', 'Ransomware', 'Critical', 'Contained', 'FIN-SRV-04 (192.168.10.45)', '2026-10-24 14:32:00', 4, 2, 'Detection of rapid encrypted file renaming (.locked extension) and high I/O spikes in the finance shared drive. Multiple decoy canary files triggered alert.', 'Disconnected FIN-SRV-04 network cable immediately and revoked SMB network access tokens.', 'Isolated subnet 192.168.10.0/24 on firewall, terminated rogue process rundll32.exe matching hash SHA256: 8f9b...a12c.', 'Affected share restored from immutable hourly snapshot at 14:00 UTC. No ransom paid.', '2026-10-24 14:35:12'),
(2, 'CS-2026-0002', 'Targeted Spear Phishing with Malicious PDF Attachment', 'Phishing', 'High', 'Resolved', 'Exchange Online / HR Department', '2026-10-25 09:15:00', 5, 2, 'Multiple HR employees received an email titled "Urgent: Q3 Bonus Review.pdf" originating from spoofed domain @cybershield-hr.co. PDF contained macro dropper.', 'Sent organization-wide security alert and purged 42 emails from mailboxes via Microsoft 365 Security Compliance API.', 'Blocked sender domain and IP range 198.51.100.24 on perimeter email gateway.', 'Sender domain blacklisted globally in Proofpoint. Endpoint EDR quarantined the 2 workstations where the attachment was opened.', '2026-10-25 09:22:45'),
(3, 'CS-2026-0003', 'SYN Flood Distributed Denial of Service (DDoS) on API Gateway', 'DDoS', 'High', 'Resolved', 'api.cybershield.org (203.0.113.80)', '2026-10-25 18:40:00', 1, 3, 'Massive inbound traffic spike reaching 45 Gbps targeting TCP port 443. Legitimate customer requests dropped with HTTP 504 Gateway Timeout.', 'Engaged Cloudflare Under-Attack Mode and enabled aggressive SYN cookie challenge rules.', 'Route traffic through Cloudflare Magic Transit and dropped traffic from non-whitelisted ASN blocks.', 'Attack subsided after 42 minutes. System latency returned to normal 38ms.', '2026-10-25 18:45:00'),
(4, 'CS-2026-0004', 'Repeated SSH Brute Force Attacks on Perimeter Bastion', 'Unauthorized Access', 'Medium', 'Under Investigation', 'bastion-ext.cybershield.net (198.51.100.12)', '2026-10-26 03:12:00', 1, 3, 'Over 14,000 failed SSH login attempts detected within 30 minutes targeting root and admin usernames from foreign IP clusters.', 'Fail2ban automatically blocked offending IP addresses for 24 hours.', 'Enforcing IP allowlisting on port 22 and requiring Hardware MFA (FIDO2) for SSH sessions.', NULL, '2026-10-26 03:15:30'),
(5, 'CS-2026-0005', 'Anomalous Outbound Data Transfer via DNS Tunneling', 'Data Breach', 'Critical', 'Under Investigation', 'DEV-WS-114 (10.0.5.88)', '2026-10-26 08:05:00', 2, 2, 'SIEM alert triggered for unusually high frequency of base64-encoded TXT record lookups to a dynamic DNS domain (*.xyz-cdn.me). Potential exfiltration of source code.', 'Port-isolated DEV-WS-114 and memory dump captured for forensic analysis.', 'DNS firewall sinkholed domain xyz-cdn.me and blocked outbound UDP/TCP 53 to unauthorized resolvers.', NULL, '2026-10-26 08:12:18'),
(6, 'CS-2026-0006', 'SQL Injection Attempt on Customer Portal Login Endpoint', 'Vulnerability Exploit', 'Medium', 'New', 'Customer Auth Portal (login.php)', '2026-10-26 09:45:00', 1, NULL, 'ModSecurity WAF blocked HTTP POST payload containing UNION SELECT schema_name from information_schema.schemata in password parameter.', 'WAF automatically dropped the HTTP request and issued 403 Forbidden.', NULL, NULL, '2026-10-26 09:50:00'),
(7, 'CS-2026-0007', 'Unauthorized USB Mass Storage Device Insertion in Server Room', 'Insider Threat', 'Low', 'Resolved', 'DC-PROD-SQL01 (Physical Console)', '2026-10-23 11:20:00', 1, 3, 'Host intrusion detection system logged insertion of SanDisk 64GB USB device on production database server.', 'Device was auto-blocked by CrowdStrike Device Control policy.', 'Interviewed contractor technician; confirmed accidental insertion during routine diagnostic backup.', 'Security reminder issued to external vendor. Device scanned clean.', '2026-10-23 11:25:00');

INSERT INTO `incident_comments` (`id`, `incident_id`, `user_id`, `comment`, `is_internal`, `created_at`) VALUES
(1, 1, 2, 'Host memory dump acquired using LiME. Malware samples isolated in sandbox: Ransom.Win32.LockBit variant identified.', 1, '2026-10-24 15:00:00'),
(2, 1, 4, 'Thank you SOC team for the fast response. Can finance access our backup folder yet?', 0, '2026-10-24 16:30:00'),
(3, 1, 2, 'Backup share restored in read-only audit mode for verification. All clear.', 0, '2026-10-24 17:00:00'),
(4, 5, 2, 'Memory forensics ongoing with Volatility 3. Identified infected PowerShell script invoked by scheduled task update_sync.', 1, '2026-10-26 08:45:00'),
(5, 2, 2, 'Campaign appears tied to threat actor group TA505. Threat intel indicators pushed to MISP platform.', 1, '2026-10-25 11:15:00');

INSERT INTO `incident_timeline` (`id`, `incident_id`, `user_id`, `action_type`, `description`, `created_at`) VALUES
(1, 1, 4, 'REPORTED', 'Incident submitted by John Doe (Finance & Accounting)', '2026-10-24 14:35:12'),
(2, 1, 1, 'ASSIGNED', 'Assigned to Sarah Chen (Lead Incident Responder)', '2026-10-24 14:40:00'),
(3, 1, 2, 'STATUS_CHANGE', 'Status changed from New to Under Investigation', '2026-10-24 14:42:00'),
(4, 1, 2, 'STATUS_CHANGE', 'Status changed from Under Investigation to Contained', '2026-10-24 16:15:00'),
(5, 5, 2, 'REPORTED', 'SIEM automated anomaly ticket generated and claimed by Sarah Chen', '2026-10-26 08:12:18'),
(6, 6, 1, 'REPORTED', 'Automated WAF telemetry logged by CSO admin', '2026-10-26 09:50:00');

INSERT INTO `audit_logs` (`id`, `user_id`, `action`, `details`, `ip_address`, `created_at`) VALUES
(1, 1, 'SYSTEM_STARTUP', 'CyberShield SOC platform initialized successfully.', '127.0.0.1', '2026-10-26 08:00:00'),
(2, 1, 'USER_LOGIN', 'Administrator logged in to SOC Console.', '127.0.0.1', '2026-10-26 08:01:22'),
(3, 2, 'USER_LOGIN', 'Analyst Sarah Chen authenticated via 2FA.', '192.168.1.15', '2026-10-26 08:05:10'),
(4, 2, 'INCIDENT_TRIAGE', 'Claimed ticket CS-2026-0005: DNS Tunneling Anomaly.', '192.168.1.15', '2026-10-26 08:14:00'),
(5, 4, 'INCIDENT_CREATE', 'User John Doe submitted ticket CS-2026-0001: Ransomware Canary.', '192.168.10.45', '2026-10-24 14:35:12');
