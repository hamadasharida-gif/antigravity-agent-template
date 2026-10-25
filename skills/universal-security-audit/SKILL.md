---
name: security-audit
description: >-
  Comprehensive autonomous security audit, vulnerability scanning, active verification (PoC), 
  and zero-regression code remediation for the Newhouse NOC Monitoring System.
  Use whenever asked to perform a security audit, review codebase for vulnerabilities, verify OWASP compliance,
  inspect command injection, check SQL injection, audit authentication/ACL controls, or assess release package safety.
---

# Security Audit, Hardening & Zero-Regression Remediation Skill

This skill provides an autonomous, end-to-end DevSecOps runbook specifically designed for the **Newhouse NOC Monitoring System**. It combines static code analysis, dynamic safe verification (PoC), non-breaking code remediation, and production package sanitization.

---

## 1. Quick Automated Audit & Scanner

Execute the project's automated security audit scanner:
```powershell
node .agents/skills/security-audit/scripts/run-audit.mjs
```

The script autonomously tests:
1. **Repository Protection**: Ensures `.gitignore` prevents leaks of `.env`, `whatsapp_auth/`, and SQLite databases (`*.db`, `*.backup`).
2. **Command Injection**: Scans all `exec()`, `execAsync()`, and `spawn()` calls across `server/src/` for unsanitized string interpolations.
3. **SQL Injection**: Verifies that all database operations strictly use parameterized queries (`?`) or safe placeholder generation.
4. **Dependency Vulnerabilities**: Scans both Server and Client dependencies via `npm audit`.

---

## 2. Core Security Pillars & Hardening Guidelines

### Pillar 1: OS Command Injection Defense
* **Rule**: NEVER pass unvalidated input or variables into shell commands.
* **Standard**: Always sanitize and validate using [securityUtils.js](file:///d:/Dashboard%20Monitoring/server/src/utils/securityUtils.js):
  * `isValidHostnameOrIp(ip)`: Strict IPv4 / RFC 1123 hostname check for ping, traceroute, RPC, and SNMP.
  * `isValidSubnet(subnet)`: Strict subnet notation for network discovery.
  * `sanitizeServiceName(name)`: Strips non-alphanumeric characters for Windows Services (`sc.exe`).
  * Prefer `spawn(exe, args, { detached: true })` over `exec()` when launching processes to bypass shell execution entirely.

### Pillar 2: Database & SQL Injection Defense
* **Rule**: All database queries must strictly use parameterized queries (`?`).
* **Dynamic Arrays**: When using `IN (...)` queries, generate dynamic placeholders `nodes.map(() => '?').join(',')` and pass values as a parameter array.
* **Vacuuming & Cleanliness**: Maintain compact databases using WAL checkpointing and auto-vacuuming to avoid uncommitted bloat.

### Pillar 3: Access Control (ACL) & Authentication
* **Internal Firewall**: Verify that [aclMiddleware.js](file:///d:/Dashboard%20Monitoring/server/src/middleware/aclMiddleware.js) intercepts incoming requests and matches client IPs against `monitor_access_list` (unless request is to public telemetry endpoints).
* **Credential Storage**: Passwords must always be hashed with **Bcrypt (min 10 salt rounds)**. Plaintext passwords must never be stored in SQLite.
* **Brute-Force Rate Limiting**: Ensure IP-based rate limiting is active on `/api/auth/verify` and `/api/settings/verify-password` (5 failed attempts = 3 min block; 10 failed attempts = 15 min block).
* **Critical Action Authorization**: Remote operations (e.g. `reboot_server`, `kill_process`, `restoreBackup`) MUST require explicit admin password verification in the request body.

### Pillar 4: Path Traversal & Backup Security
* **Sanitization**: All file endpoints (e.g., in [backup.js](file:///d:/Dashboard%20Monitoring/server/src/routes/backup.js)) must apply `path.basename()` on filename parameters to block directory traversal sequences (`../`, `..\`).
* **Encryption**: Backups should support symmetric **AES-256** encryption when exported.

### Pillar 5: Production Release Sanitization
* **Rule**: Releases destined for deployment must NOT bundle transient historical logs.
* **Procedure**: When running [build-windows-package.mjs](file:///d:/Dashboard%20Monitoring/tools/build-windows-package.mjs), ensure transient tables are purged from the release database:
  * `monitor_samples = 0`, `monitor_incidents = 0`, `monitor_switch_logs = 0`, `monitor_veeam_events = 0`.
  * All 104 nodes, SNMP credentials, settings, and ACL rules MUST remain 100% intact.

---

## 3. Autonomous Remediation Lifecycle (Zero-Downtime Rule)

When fixing any discovered vulnerability, always follow this 4-step safety lifecycle:

1. **Verify (Dynamic PoC)**:
   * Perform a safe, isolated simulation to confirm the issue is a genuine vulnerability and not a false positive.
2. **Non-Breaking Remediation**:
   * Apply minimal, precise code diffs.
   * **CRITICAL**: Never alter node IDs, API response contracts, or telemetry ingest pipelines to prevent breaking active dashboard monitors.
3. **Regression Testing**:
   * Test the modified service by querying `/api/status` or probing affected endpoints to verify normal operation continues without errors.
4. **Repackage Production Suite**:
   * Once validated, recompile the frontend and bundle the updated clean release:
     ```powershell
     npm.cmd --prefix client run build
     node tools/build-windows-package.mjs
     ```

---

## 4. Output & Reporting Standards

After every audit or remediation, deliver a structured summary containing:
* **Verified Issues**: Any flaws identified (with file paths and line numbers).
* **Applied Fixes**: Exact changes made (Defense-in-Depth).
* **Dependency Health**: Audit results for Server and Client packages.
* **System Stability Status**: Confirmation that live monitoring on port 3001 remains active and operational.
