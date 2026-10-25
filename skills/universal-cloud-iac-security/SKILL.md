---
name: universal-cloud-iac-security
description: >-
  Autonomous security audit and hardening for Cloud infrastructure, Dockerfiles, 
  Kubernetes manifests, CI/CD pipelines (GitHub Actions/GitLab CI), and secret leakage prevention.
triggers:
  - on: pull_request
    action: automated_review
  - on: demand
    command: /cloud-security
---

# Universal Cloud & IaC Security Hardening Skill

This skill provides an autonomous, end-to-end security runbook designed to inspect, audit, and harden Cloud Infrastructure as Code (IaC), Container configurations, and CI/CD pipelines. It ensures your deployment environments follow modern DevSecOps least-privilege standards.

---

## 1. Dynamic Infrastructure Discovery & Scanning

Analyze the repository layout to identify Cloud configuration files and execute targeted static analysis or dynamic checks inside the isolated sandbox environment.

### 1.1 Stack Detection Checklist
* **Containers**: Search for `Dockerfile`, `docker-compose.yml`.
* **CI/CD Pipelines**: Search for `.github/workflows/*.yml` or `.gitlab-ci.yml`.
* **Infrastructure as Code (IaC)**: Search for Terraform (`*.tf`), Kubernetes (`k8s/*.yml`), or Ansible playbooks.

### 1.2 Automated Secret Scanning
* Scan the entire codebase, commit history, and active IaC files for accidentally hardcoded cloud credentials, API tokens, private SSH keys, or database connection strings.

---

## 2. Core Cloud Security Pillars & Hardening Guidelines

Evaluate the repository against these industry-standard cloud and pipeline infrastructure hardening principles:

### Pillar 1: Dockerfile & Container Hardening
* **Rule 1 (Root Access)**: NEVER run container processes as `root`. Verify that a non-root user is explicitly created and activated via the `USER` directive.
* **Rule 2 (Base Images)**: Ensure base images use specific, pinned version tags (e.g., `node:20-alpine`) rather than insecure mutable tags like `latest`. Multi-stage builds must be used to keep production images minimal.
* **Rule 3 (Leaked Secrets)**: Ensure `ENV` or `ARG` instructions are never used to pass sensitive keys or passwords into the image layer history.

### Pillar 2: CI/CD Pipeline & GitHub Actions Security
* **Rule 1 (Least Privilege Token)**: Verify that GitHub Actions workflows restrict the default `GITHUB_TOKEN` permissions to the absolute minimum required (e.g., `permissions: contents: read`).
* **Rule 2 (Untrusted Input)**: Audit actions that trigger on user-controlled inputs (like `pull_request_target` or `issue_comment`) to prevent Bash command injection via dynamic parameters like `${{ github.event.issue.body }}`.
* **Rule 3 (Third-Party Actions)**: Ensure third-party actions are pinned to a specific Git commit SHA (e.g., `uses: actions/checkout@v4.1.1` or equivalent SHA hash) rather than a mutable branch name like `@main` to prevent supply chain takeovers.

### Pillar 3: Infrastructure as Code (IaC) & Cloud Configurations
* **Rule 1 (Network Exposure)**: Scan security groups and firewall manifests to ensure critical management ports (e.g., SSH `22`, RDP `3389`, Database `5432`/`3306`) are never exposed to the public internet (`0.0.0.0/0`).
* **Rule 2 (State File Protection)**: For Terraform, verify that backend states are stored securely with encryption-at-rest enabled and are never committed to version control.

---

## 3. Autonomous Remediation Lifecycle (Non-Breaking Cloud Patches)

When vulnerabilities are found in the infrastructure files, CodeMender must follow this safety workflow:

1. **Static Linting Validation**:
   * Utilize available sandbox tools (like Hadolint for Dockerfiles or Checkov/Trivy patterns) to parse and validate structural security faults.
2. **Apply Non-Breaking Infrastructure Fixes**:
   * Generate precise diffs to switch container base images to secure/minimal variants, add missing `USER` boundaries, or fix loose CI/CD permissions.
   * **CRITICAL**: Never modify environment variable keys or deployment ports that are already bound to external production load balancers without documenting the override.
3. **Build Validation**:
   * Execute a dry-run or local container build inside the Antigravity Sandbox (e.g., `docker build`) to guarantee that the security fixes do not break compilation or disrupt runtime dependencies.

---

## 4. Output & Reporting Standards

After completing the cloud audit cycle, deliver a structured summary containing:
* **Infrastructure Risks Identified**: Security gaps discovered in containers, workflows, or cloud definitions.
* **Secret Scan Summary**: Status of token/credential leakage analysis (Confirming 100% clean or flagging leaked items).
* **Applied Infrastructure Diffs**: Precise modifications executed on configuration files.
* **Pipeline Build Status**: Confirmation that the modified environment builds and compiles successfully post-hardening.

*Note: Do not automatically merge or commit configuration changes directly to production environments without explicit infrastructure-team review.*
