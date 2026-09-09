# Axiom Security Platform — API Reference Manual

> **Base URLs:**
> - **Production:** `https://axiom-xjkc.onrender.com`
> - **Local Development:** `http://localhost:8000`
> - **OpenAPI JSON:** `/openapi.json`
> - **Swagger UI:** `/docs`
> - **ReDoc:** `/redoc`

---

## Table of Contents
1. [Authentication & Security](#1-authentication--security)
2. [Global Error Envelope & Headers](#2-global-error-envelope--headers)
3. [Operational Endpoints](#3-operational-endpoints)
   - `GET /` — Root Documentation Redirect
   - `GET /health` — Basic Health Check
   - `GET /health/live` — Kubernetes / Render Liveness Probe
   - `GET /health/ready` — Database Readiness Probe
4. [Target Management Endpoints](#4-target-management-endpoints)
   - `POST /v1/targets` — Register Authorized Target
   - `GET /v1/targets` — List Authorized Targets
   - `GET /v1/targets/{target_id}` — Get Target Details
5. [DAST Scans (Dynamic Application Security Testing)](#5-dast-scans-dynamic-application-security-testing)
   - `GET /v1/scans` — List DAST Scans
   - `POST /v1/scans` — Queue DAST Scan Job
   - `GET /v1/scans/{scan_id}` — Get DAST Scan Status
   - `POST /v1/scans/{scan_id}/cancel` — Cancel Running DAST Scan
   - `POST /v1/scans/{scan_id}/retry` — Retry Failed DAST Scan
   - `GET /v1/scans/{scan_id}/result` — Retrieve DAST Scan Results
6. [SAST Scans (Static Application Security Testing)](#6-sast-scans-static-application-security-testing)
   - `GET /v1/sast/scans` — List SAST Scans
   - `POST /v1/sast/scans` — Queue SAST Code Analysis Job
   - `GET /v1/sast/scans/{scan_id}` — Get SAST Scan Status
   - `POST /v1/sast/scans/{scan_id}/cancel` — Cancel Running SAST Scan
   - `POST /v1/sast/scans/{scan_id}/retry` — Retry Failed SAST Scan
   - `GET /v1/sast/scans/{scan_id}/result` — Retrieve Normalized SAST Findings
7. [Audit & Compliance Endpoints](#7-audit--compliance-endpoints)
   - `GET /v1/audit-events` — List Security Audit Events
8. [Dashboard & Statistics Endpoints](#8-dashboard--statistics-endpoints)
   - `GET /v1/stats` — Get Telemetry & Metric Counts
9. [Internal Controller Protocol (Private HMAC)](#9-internal-controller-protocol-private-hmac)
   - `POST /v1/internal/controller/jobs/claim` — Claim Next Job
   - `POST /v1/internal/controller/jobs/{scan_id}/complete` — Report Completion
   - `POST /v1/internal/controller/jobs/{scan_id}/fail` — Report Failure
   - `GET /v1/internal/controller/jobs/{scan_id}/status` — Check Job Status

---

## 1. Authentication & Security

Axiom supports two primary client authentication mechanisms depending on environment:

### A. Local / Staging (`AUTH_MODE=api_key`)
Send the API key via either header:
```http
X-API-Key: <your-api-key>
```
or
```http
Authorization: Bearer <your-api-key>
```
- **Admin Key:** Matches `ADMIN_API_KEY` (role: `admin`). Required for registering targets and viewing audit events.
- **Operator Key:** Matches `API_KEY` (role: `operator`). Allowed to queue, list, retry, cancel scans, and view results.

### B. Production (`AUTH_MODE=oidc`)
Requires valid signed RS256/ES256 OpenID Connect (OIDC) JWT Bearer token:
```http
Authorization: Bearer <jwt-token>
```
The token claims must include:
- `sub`: Unique subject / user identifier
- `roles` (configurable claim name): Array containing `"admin"` or `"operator"`.

---

## 2. Global Error Envelope & Headers

All non-2xx responses conform to a unified error format:

```json
{
  "error": {
    "type": "api_error",
    "detail": "Descriptive reason for failure",
    "status": 404
  }
}
```

Validation failures return `type: "validation_error"` with HTTP status `422`:
```json
{
  "error": {
    "type": "validation_error",
    "detail": "body.value: String should have at least 1 characters",
    "status": 422
  }
}
```

### Standard Response Headers
Every API response injects security and tracing headers:
| Header | Example Value | Description |
|---|---|---|
| `X-Request-ID` | `c683ad2e-8fa5-455b-9d41-d360fbc356c9` | Unique trace ID generated or forwarded per request |
| `X-Content-Type-Options` | `nosniff` | MIME-type sniffing protection |
| `X-Frame-Options` | `DENY` | Clickjacking prevention |
| `Referrer-Policy` | `no-referrer` | Privacy header |
| `Cache-Control` | `no-store` | Prevents intermediate proxy/browser caching |

---

## 3. Operational Endpoints

### `GET /`
- **Summary:** Root Documentation Redirect
- **Auth:** Public (None)
- **Status Code:** `307 Temporary Redirect`
- **Response Header:** `Location: /docs`
- **Description:** Redirects web browsers and consumers directly to the interactive Swagger UI.

---

### `GET /health`
- **Summary:** Basic Health Check
- **Auth:** Public (None)
- **Status Code:** `200 OK`
- **Response Body:**
```json
{
  "status": "ok"
}
```

---

### `GET /health/live`
- **Summary:** Liveness Probe
- **Auth:** Public (None)
- **Status Code:** `200 OK`
- **Response Body:**
```json
{
  "status": "alive"
}
```

---

### `GET /health/ready`
- **Summary:** Database Readiness Probe
- **Auth:** Public (None)
- **Status Code:** `200 OK` (when DB is reachable) or `503 Service Unavailable` (when unreachable)
- **Success Response Body (`200`):**
```json
{
  "status": "ready",
  "database": "ok"
}
```
- **Failure Response Body (`503`):**
```json
{
  "status": "not_ready",
  "database": "unreachable"
}
```

---

## 4. Target Management Endpoints

Targets represent authorized assets (domains, IPs, or repositories) for security scanning.

### `POST /v1/targets`
- **Summary:** Register Authorized Target
- **Role Required:** `admin`
- **Status Code:** `201 Created`

#### Request Body Schema
| Field | Type | Constraints | Description |
|---|---|---|---|
| `value` | string | `min: 1`, `max: 253` | Target domain, IP, or repo path (e.g. `example.com`, `198.51.100.25`, `my-org/web-service`) |
| `owner_reference` | string | `min: 3`, `max: 200` | Owner or team tag responsible for the target |
| `authorization_reference` | string | `min: 3`, `max: 200` | Formal testing authorization or compliance ticket ID |
| `target_type` | string | `"network"` \| `"source_code"` | `"network"` for DAST scans, `"source_code"` for SAST repository scans |

#### Request Example
```json
{
  "value": "api.example.com",
  "owner_reference": "SecOps-Team-Alpha",
  "authorization_reference": "SEC-AUTH-2026-0901",
  "target_type": "network"
}
```

#### Response Example (`201 Created`)
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "value": "api.example.com",
  "created_at": "2026-09-10T02:00:00Z"
}
```

---

### `GET /v1/targets`
- **Summary:** List Registered Targets
- **Role Required:** `admin`
- **Status Code:** `200 OK`

#### Query Parameters
| Parameter | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `skip` | integer | `0` | `>= 0` | Records to skip for pagination |
| `limit` | integer | `50` | `1` to `200` | Maximum records to return |

#### Response Example (`200 OK`)
```json
[
  {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "value": "api.example.com",
    "created_at": "2026-09-10T02:00:00Z"
  }
]
```

---

### `GET /v1/targets/{target_id}`
- **Summary:** Get Target Details
- **Role Required:** `admin`
- **Status Code:** `200 OK`
- **Path Parameter:** `target_id` (UUID)

#### Response Example (`200 OK`)
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "value": "api.example.com",
  "created_at": "2026-09-10T02:00:00Z"
}
```

---

## 5. DAST Scans (Dynamic Application Security Testing)

DAST scans execute network enumeration, port analysis, web fuzzing, and vulnerability scanning.

### Supported DAST Profiles
| Profile | Scanner | Purpose |
|---|---|---|
| `recon` | httpx | Fast HTTP service, security headers, and title discovery |
| `web-discovery` | httpx | Comprehensive HTTP/HTTPS port, tech, and service discovery |
| `network-portscan` | nmap | Detailed TCP service and version detection (`-sV -T4`) |
| `fast-portscan` | masscan | High-speed port availability scanning |
| `smart-portscan` | naabu | Fast reliable TCP port discovery via Naabu |
| `content-discovery` | ffuf | Web directory, route, and file fuzzing |
| `deep-content-discovery` | feroxbuster | Recursive high-speed content discovery |
| `web-crawl` | katana | Dynamic JS-aware spider and endpoint extraction |
| `vuln-assessment` | nuclei | Template-based vulnerability assessment |
| `xss-scan` | dalfox | Cross-Site Scripting (DOM, Reflected, Stored) analysis |
| `dast-zap` | zap | Automated web application vulnerability scan via OWASP ZAP |
| `oob-interaction` | interactsh | Out-of-band interaction & Blind SSRF verification |
| `dns-recon` | dnsx | DNS record resolution (A, CNAME, MX, TXT) |
| `subdomain-takeover` | subzy | Subdomain takeover detection via dangling CNAMEs |
| `waf-detect` | wafw00f | WAF & CDN vendor fingerprinting |
| `cors-audit` | corsy | CORS misconfiguration and credential theft testing |
| `crlf-scan` | crlfuzz | CRLF injection & HTTP response splitting detection |
| `ssti-scan` | sstimap | Server-Side Template Injection discovery |

---

### `POST /v1/scans`
- **Summary:** Queue DAST Scan Job
- **Role Required:** `operator` or `admin`
- **Status Code:** `202 Accepted`
- **Optional Header:** `Idempotency-Key: <unique-uuid>`

#### Request Body
```json
{
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "vuln-assessment"
}
```

#### Response Example (`202 Accepted`)
```json
{
  "id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "vuln-assessment",
  "status": "queued",
  "controller_job_id": null,
  "failure_reason": null,
  "created_at": "2026-09-10T02:05:00Z"
}
```

---

### `GET /v1/scans`
- **Summary:** List DAST Scans
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`

#### Query Parameters
| Parameter | Type | Default | Description |
|---|---|---|---|
| `status` | string | `null` | Filter by status: `queued`, `dispatching`, `running`, `completed`, `failed`, `cancelled` |
| `profile` | string | `null` | Filter by scan profile name |
| `target_id` | UUID | `null` | Filter by specific target ID |
| `skip` | integer | `0` | Offset pagination |
| `limit` | integer | `50` | Max items (`1` - `200`) |

#### Response Example (`200 OK`)
```json
[
  {
    "id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
    "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "profile": "vuln-assessment",
    "status": "completed",
    "controller_job_id": "job-81923",
    "failure_reason": null,
    "created_at": "2026-09-10T02:05:00Z"
  }
]
```

---

### `GET /v1/scans/{scan_id}`
- **Summary:** Get DAST Scan Status
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`
- **Path Parameter:** `scan_id` (UUID)

#### Response Example (`200 OK`)
```json
{
  "id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "vuln-assessment",
  "status": "completed",
  "controller_job_id": "job-81923",
  "failure_reason": null,
  "created_at": "2026-09-10T02:05:00Z"
}
```

---

### `POST /v1/scans/{scan_id}/cancel`
- **Summary:** Cancel DAST Scan
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`
- **Path Parameter:** `scan_id` (UUID)
- **Description:** Transitions scan from `queued`, `dispatching`, or `running` to `cancelled`.

#### Response Example (`200 OK`)
```json
{
  "id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "vuln-assessment",
  "status": "cancelled",
  "controller_job_id": null,
  "failure_reason": "Cancelled by operator request",
  "created_at": "2026-09-10T02:05:00Z"
}
```

---

### `POST /v1/scans/{scan_id}/retry`
- **Summary:** Retry Failed Scan
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`
- **Path Parameter:** `scan_id` (UUID)
- **Description:** Re-queues a failed or cancelled scan as a new job. Returns `409 Conflict` if the scan is currently active.

#### Response Example (`200 OK`)
```json
{
  "id": "7138b1f2-1082-4293-8472-1823901bce42",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "vuln-assessment",
  "status": "queued",
  "controller_job_id": null,
  "failure_reason": null,
  "created_at": "2026-09-10T02:10:00Z"
}
```

---

### `GET /v1/scans/{scan_id}/result`
- **Summary:** Get DAST Scan Results
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK` (or `409 Conflict` if still processing)
- **Path Parameter:** `scan_id` (UUID)

#### Response Example (`200 OK`)
```json
{
  "id": "21894bfa-7712-402a-9921-bcaf817293a1",
  "scan_job_id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
  "summary": {
    "profile": "vuln-assessment",
    "risk_summary": {
      "critical": 1,
      "high": 2,
      "medium": 0,
      "low": 1,
      "info": 4,
      "total": 8
    },
    "findings": [
      {
        "id": "SEC-001",
        "code": "NUCLEI_CVE_2024_27198",
        "severity": "CRITICAL",
        "title": "TeamCity Authentication Bypass (CVE-2024-27198)",
        "description": "JetBrains TeamCity allows an unauthenticated attacker to bypass auth and perform administrative actions.",
        "evidence": "Matched at: https://api.example.com/oauth/callback",
        "remediation": "Upgrade JetBrains TeamCity to version 2023.11.4 or higher."
      }
    ]
  },
  "created_at": "2026-09-10T02:08:00Z",
  "artifact": {
    "id": "993a4bc1-1209-432a-bc91-289301293812",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "byte_count": 4120,
    "expires_at": "2026-10-10T02:08:00Z",
    "deleted_at": null
  },
  "error_logs": null
}
```

---

## 6. SAST Scans (Static Application Security Testing)

SAST scans perform static code analysis, semantic AST query auditing, and secret scanning across source code repositories.

### Supported SAST Profiles
| Profile | Engine | Supported Languages | Purpose |
|---|---|---|---|
| `sast-joern` | Joern CPG | C, C++, Java, Kotlin, JS, TS, Python, Go, PHP | Code Property Graph inter-procedural taint flow analysis |
| `sast-semgrep` | Semgrep | Python, JS, TS, Java, Go, C, C++, Ruby, PHP, Rust, Dockerfile, Terraform | Fast semantic pattern matching and OWASP security audit |
| `sast-trufflehog` | TruffleHog | All Languages, Git History, `.env` files | Secret scanning & verified credential leak detection |
| `sast-codeql` | GitHub CodeQL | Python, JS, TS, Java, Go, C, C++, C#, Ruby, Swift | Deep Datalog semantic query analysis and SARIF v2.1.0 output |
| `sast-gitleaks` | Gitleaks | All Languages, Repositories | High-speed secret scanning with Shannon entropy validation |

---

### `POST /v1/sast/scans`
- **Summary:** Queue SAST Code Analysis Job
- **Role Required:** `operator` or `admin`
- **Status Code:** `202 Accepted`
- **Optional Header:** `Idempotency-Key: <unique-uuid>`

#### Request Body
| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target_id` | UUID | **Yes** | — | Target ID of type `source_code` |
| `profile` | string | No | `"sast-joern"` | `sast-joern`, `sast-semgrep`, `sast-trufflehog`, `sast-codeql`, `sast-gitleaks` |
| `rule_tags` | array[string] | No | `null` | Optional rule bundles (e.g. `["sqli", "rce", "default"]`) |

#### Request Example
```json
{
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "sast-semgrep",
  "rule_tags": ["owasp-top-10", "security-audit"]
}
```

#### Response Example (`202 Accepted`)
```json
{
  "id": "bb492019-3381-4209-a031-1029418293bc",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "sast-semgrep",
  "status": "queued",
  "controller_job_id": null,
  "failure_reason": null,
  "created_at": "2026-09-10T02:15:00Z"
}
```

---

### `GET /v1/sast/scans`
- **Summary:** List SAST Scans
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`

#### Query Parameters
| Parameter | Type | Default | Description |
|---|---|---|---|
| `status` | string | `null` | Filter by job status (`queued`, `running`, `completed`, `failed`) |
| `profile` | string | `null` | Filter by SAST profile |
| `skip` | integer | `0` | Pagination offset |
| `limit` | integer | `50` | Page limit (`1` - `200`) |

#### Response Example (`200 OK`)
```json
[
  {
    "id": "bb492019-3381-4209-a031-1029418293bc",
    "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "profile": "sast-semgrep",
    "status": "completed",
    "controller_job_id": "job-sast-1029",
    "failure_reason": null,
    "created_at": "2026-09-10T02:15:00Z"
  }
]
```

---

### `GET /v1/sast/scans/{scan_id}`
- **Summary:** Get SAST Scan Status
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`
- **Path Parameter:** `scan_id` (UUID)

#### Response Example (`200 OK`)
```json
{
  "id": "bb492019-3381-4209-a031-1029418293bc",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "sast-semgrep",
  "status": "completed",
  "controller_job_id": "job-sast-1029",
  "failure_reason": null,
  "created_at": "2026-09-10T02:15:00Z"
}
```

---

### `POST /v1/sast/scans/{scan_id}/cancel`
- **Summary:** Cancel SAST Scan
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`
- **Path Parameter:** `scan_id` (UUID)

#### Response Example (`200 OK`)
```json
{
  "id": "bb492019-3381-4209-a031-1029418293bc",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "sast-semgrep",
  "status": "cancelled",
  "controller_job_id": null,
  "failure_reason": "Cancelled by operator request",
  "created_at": "2026-09-10T02:15:00Z"
}
```

---

### `POST /v1/sast/scans/{scan_id}/retry`
- **Summary:** Retry Failed SAST Scan
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`
- **Path Parameter:** `scan_id` (UUID)

#### Response Example (`200 OK`)
```json
{
  "id": "cc910283-4921-4192-8012-4912903bcde1",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "sast-semgrep",
  "status": "queued",
  "controller_job_id": null,
  "failure_reason": null,
  "created_at": "2026-09-10T02:20:00Z"
}
```

---

### `GET /v1/sast/scans/{scan_id}/result`
- **Summary:** Retrieve Normalized SAST Findings
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK` (or `409 Conflict` if scan is still active)
- **Path Parameter:** `scan_id` (UUID)

#### Response Example (`200 OK`)
```json
{
  "id": "ff120938-4102-4912-ab34-102948192039",
  "scan_job_id": "bb492019-3381-4209-a031-1029418293bc",
  "summary": {
    "profile": "sast-semgrep",
    "scanned_files_count": 42,
    "total_rules_evaluated": 128,
    "risk_summary": {
      "critical": 1,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0,
      "total": 2
    },
    "findings": [
      {
        "id": "SEC-001",
        "code": "SEMGREP_PYTHON_LANG_SECURITY_AUDIT_SQL_INJECTION",
        "severity": "CRITICAL",
        "title": "SQL Injection in User Query Handler",
        "description": "Untrusted user request parameter concatenated into raw cursor.execute SQL call.",
        "evidence": {
          "file": "src/api/auth.py",
          "line": 42,
          "column": 5,
          "snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
          "cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"]
        },
        "remediation": "Use parameterized queries or ORM abstractions instead of string interpolation."
      }
    ]
  },
  "created_at": "2026-09-10T02:18:00Z",
  "artifact": {
    "id": "aa123456-7890-4abc-def1-234567890abc",
    "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "byte_count": 8920,
    "expires_at": "2026-10-10T02:18:00Z",
    "deleted_at": null
  },
  "error_logs": null
}
```

---

## 7. Audit & Compliance Endpoints

### `GET /v1/audit-events`
- **Summary:** List Security Audit Events
- **Role Required:** `admin`
- **Status Code:** `200 OK`
- **Description:** Returns the 100 most recent security audit logs (target creation, scans queued, cancellations, claims, completions).

#### Response Example (`200 OK`)
```json
[
  {
    "id": "e0291038-1293-4120-9912-bcde01928471",
    "action": "scan.queued",
    "resource_type": "scan",
    "resource_id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
    "detail": null,
    "created_at": "2026-09-10T02:05:00.123456"
  },
  {
    "id": "11928301-4921-4412-a102-ccba01928412",
    "action": "target.created",
    "resource_type": "target",
    "resource_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "detail": null,
    "created_at": "2026-09-10T02:00:00.654321"
  }
]
```

---

## 8. Dashboard & Statistics Endpoints

### `GET /v1/stats`
- **Summary:** Get Platform Dashboard Statistics
- **Role Required:** `operator` or `admin`
- **Status Code:** `200 OK`
- **Description:** Returns high-level metrics across targets, scans, results, status distribution, and profile usage.

#### Response Example (`200 OK`)
```json
{
  "targets_count": 12,
  "scans_count": 84,
  "results_count": 79,
  "scans_by_status": {
    "completed": 76,
    "failed": 3,
    "running": 2,
    "queued": 3
  },
  "scans_by_profile": {
    "recon": 22,
    "vuln-assessment": 18,
    "sast-semgrep": 24,
    "sast-codeql": 10,
    "sast-trufflehog": 10
  }
}
```

---

## 9. Internal Controller Protocol (Private HMAC)

These hidden endpoints allow the private worker or remote scan controller to claim jobs and report back results securely.

### Replay-Protected HMAC Authentication
Requests require four signed headers:
```http
X-Controller-Timestamp: <unix-timestamp-in-seconds>
X-Controller-Nonce: <unique-random-nonce-16-to-80-chars>
X-Controller-Signature: <hmac-sha256-signature>
Content-Type: application/json
```

**Signature Calculation:**
```python
message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{sha256(body).hexdigest()}".encode()
signature = hmac.new(CONTROLLER_SHARED_SECRET.encode(), message, hashlib.sha256).hexdigest()
```
- Maximum allowed clock skew: 300 seconds (5 minutes).
- Nonces are stored in PostgreSQL to detect and reject replay attacks.

---

### `POST /v1/internal/controller/jobs/claim`
- **Summary:** Claim Next Queued Job
- **Auth:** Controller HMAC
- **Status Code:** `200 OK`
- **Body:** Empty (`b""`)

#### Response Example (`200 OK` when job is available)
```json
{
  "id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
  "target": "api.example.com",
  "profile": "vuln-assessment",
  "authorization_reference": "SEC-AUTH-2026-0901"
}
```
*(Returns `null` if no queued jobs are currently pending).*

---

### `POST /v1/internal/controller/jobs/{scan_id}/complete`
- **Summary:** Report Controller Job Completion
- **Auth:** Controller HMAC
- **Status Code:** `200 OK` (or `409 Conflict` if scan is not in running state)
- **Path Parameter:** `scan_id` (UUID)

#### Request Body
```json
{
  "summary": {
    "risk_summary": {
      "critical": 0,
      "high": 1,
      "medium": 2,
      "low": 0,
      "info": 1,
      "total": 4
    },
    "findings": [
      {
        "id": "SEC-001",
        "code": "EXPOSED_DEBUG_PORT",
        "severity": "HIGH",
        "title": "Exposed Node.js Debugger Port",
        "description": "V8 inspector agent exposed on port 9229 without authentication."
      }
    ]
  }
}
```

#### Response Example (`200 OK`)
```json
{
  "id": "71a93812-4912-4019-9182-129038bcaf12",
  "scan_job_id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
  "summary": { ... },
  "created_at": "2026-09-10T02:22:00Z",
  "artifact": null,
  "error_logs": null
}
```

---

### `POST /v1/internal/controller/jobs/{scan_id}/fail`
- **Summary:** Report Controller Job Failure
- **Auth:** Controller HMAC
- **Status Code:** `200 OK`
- **Path Parameter:** `scan_id` (UUID)

#### Request Body
```json
{
  "reason": "Target host refused TCP connections on all requested ports (Connection Refused)"
}
```

#### Response Example (`200 OK`)
```json
{
  "id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
  "target_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "profile": "vuln-assessment",
  "status": "failed",
  "controller_job_id": null,
  "failure_reason": "Target host refused TCP connections on all requested ports (Connection Refused)",
  "created_at": "2026-09-10T02:05:00Z"
}
```

---

### `GET /v1/internal/controller/jobs/{scan_id}/status`
- **Summary:** Query Controller Job Status
- **Auth:** Controller HMAC
- **Status Code:** `200 OK`
- **Path Parameter:** `scan_id` (UUID)

#### Response Example (`200 OK`)
```json
{
  "id": "e93a61dc-492e-4b2a-a92c-5b9612c6a991",
  "status": "running"
}
```
