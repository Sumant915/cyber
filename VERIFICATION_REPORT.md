# Zero Trust Prototype Verification Report

## 1. Executive Summary

The project was executed and tested as a working local prototype. The FastAPI backend initialized SQLite, served OpenAPI documentation, authenticated seeded identities, enforced server-side policy decisions, recorded telemetry, and rejected revoked sessions. The React frontend loaded in a browser, completed login, navigated the Sentinel console, called the backend, and displayed live allow/deny decisions with risk evidence.

The verification found and fixed several concrete issues: missing persistence tables, invalid-token exception handling, absent account lockout, stale role-restricted frontend requests, posture-independent device trust, suspicious-IP under-scoring, OpenAPI authentication metadata, and an explicit CORS origin gap.

## 2. Environment

- Windows PowerShell, Python 3.13.7, Node/Vite frontend.
- Backend dependencies installed from `backend/requirements.txt`.
- Frontend dependencies installed from `frontend/package.json`.
- SQLite database: `backend/zta.db`.
- Documented frontend and backend ports were used for the original local verification.
- A stale listener held the original backend port during final source verification; the current source was therefore started on a separate local port and verified end to end through an explicit `VITE_API_URL`.

## 3. Backend Verification

Observed results:

| Endpoint | Method | Auth | Result |
| --- | --- | --- | --- |
| `/health` | GET | No | 200, `status=ok` |
| `/docs` | GET | No | 200 |
| `/openapi.json` | GET | No | 200; Bearer scheme present |
| `/auth/login` | POST | No | Valid login succeeds; invalid login returns 401 |
| `/auth/logout` | POST | Bearer | Revokes session |
| `/access/evaluate` | POST | Bearer | Returns live decision and evidence |
| `/me` | GET | Bearer | 401 without token; 200 with valid token |
| `/dashboard/stats` | GET | Security role | 403 for employee; 200 for admin |
| `/resources` | GET | Bearer | 200 with persisted resources |
| `/audit-logs` | GET | Analyst/admin | 403 for guest; 200 for security roles |
| `/policies` | GET | Admin | 403 for employee/analyst; 200 for admin |
| `/policies` | POST | Admin | 403 for analyst; 200 for admin |
| `/policies/{id}` | PUT | Admin | Live policy mutation works |

The current-source backend started cleanly on port 8001 with no import or startup errors.

## 4. Frontend Verification

Browser verification confirmed:

- Login screen renders.
- Employee login reaches the security posture dashboard.
- Overview navigation opens the continuous authorization view.
- Resource list renders all four resources.
- Trusted Employee Directory request displays `ALLOW`, risk `0 / LOW`, device trust `94/100`.
- Unmanaged device plus confidential resource displays `DENY`, risk `100 / CRITICAL`, device trust `10/100`, and explainable factors.
- Admin login exposes the security dashboard and security-event navigation.
- Live API integration works after the explicit CORS origin fix.
- Production build succeeds.

The browser initially exposed an expected 403 console request from the employee dashboard; the frontend was fixed to avoid requesting security-only telemetry for employee users. The fresh full-stack browser run completed without a new console/network failure.

The frontend has no policy-management screen. Policy management is available and enforced through the backend API.

## 5. Authentication Results

| Scenario | Actual result |
| --- | --- |
| Valid seeded credentials | 200 with expiring access token |
| Invalid password | 401 |
| Unknown user | 401 |
| Missing OTP | 200 MFA challenge, no access token |
| Five failed passwords | Fifth attempt 429 and five-minute lockout |
| Tampered token | 401 |
| Revoked session | Subsequent protected request 401 |

Passwords use salted PBKDF2 in the available runtime. Tokens are signed, include expiry, and are checked against a revocable server session.

## 6. MFA Results

MFA is explicitly a **DEMO-ONLY simulated OTP**, not a real TOTP implementation. The accepted demo code is `123456`; `mfa_credentials` records `demo_only=1`. Missing or incorrect OTP does not issue a token. Real TOTP enrollment, QR provisioning, OTP replay protection, and MFA disable/setup endpoints are not implemented.

## 7. RBAC Results

- Employee: internal directory allowed; security dashboard and policy APIs rejected with 403.
- Guest: audit access rejected and restricted resource access denied.
- Analyst: security visibility allowed, policy modification rejected with 403.
- Admin: wildcard admin policy and policy APIs allowed.

The backend, rather than hidden frontend controls, enforces these boundaries.

## 8. Device Trust Results

| Device condition | Actual trust |
| --- | ---: |
| Managed, encrypted, EDR active | 94 |
| Seeded unmanaged device | 10 after posture-derived calculation |
| Encryption disabled variant | 65 |
| EDR inactive variant | 70 |

The device trust helper now derives a bounded score from managed state, encryption, EDR state, and the stored posture score. The seeded suspicious device also increases risk through its IP and posture signals.

## 9. Risk Engine Results

| Scenario | Score | Level | Factors observed |
| --- | ---: | --- | --- |
| Trusted device/internal resource | 0 | LOW | No elevated risk indicators |
| Unknown device/internal resource | 35 | MEDIUM | Unknown device |
| Trusted device/suspicious IP/sensitive resource | 65 | HIGH | Suspicious IP reputation; sensitive resource |
| Unmanaged/suspicious sensitive request | 100 | CRITICAL | Unmanaged, encryption disabled, EDR inactive, low trust, suspicious IP, sensitive resource |

Identical inputs were tested twice and produced identical output. Scores are bounded to 0-100 and reasons are returned with every decision.

## 10. Policy Engine Results

Active role/resource policies are evaluated deterministically in ID order. Disabled policies are ignored. Minimum device trust and maximum risk thresholds were changed through the admin API and altered the subsequent decision. Every result includes decision, matched policy/default-deny, risk score, risk level, and reasons.

## 11. Continuous Authorization Results

The mandatory sequence passed:

1. Employee authenticated.
2. Trusted device requested Employee Directory.
3. Result was `ALLOW`, risk 0, trust 94.
4. The same device was changed to unmanaged, unencrypted, EDR inactive.
5. Suspicious IP context was added.
6. The same resource was requested using the same authenticated token.
7. Result was `DENY`, risk 100/CRITICAL, trust 10.

No previous allow decision was inherited.

## 12. Session Security Results

Login, protected access, logout/revocation, and post-revocation access were executed. The final protected request after revocation returned 401. Expiry logic is implemented in the signed token and was covered by token validation tests; an elapsed wall-clock expiry test was not waited out because the token lifetime is 30 minutes.

## 13. Audit Logging Results

Allowed requests, denied requests, MFA challenges, failed logins, account lockout, session revocation, policy creation/update, and access reviews generate persisted telemetry. Final database inspection showed 110 audit logs, 85 access requests, and 90 security events. Audit columns include timestamp, user/email, IP, device, resource, action, decision, risk score/level, reason, and policy. Passwords, tokens, and MFA secrets are not columns in the audit table.

## 14. Security Boundary Tests

| Direct call | Actual result |
| --- | --- |
| Unauthenticated `/me` | 401 |
| Employee `/dashboard/stats` | 403 |
| Employee `/policies` | 403 |
| Analyst policy write | 403 |
| Guest `/audit-logs` | 403 |
| Admin `/policies` | 200 |
| Token tampering | 401 |
| SQL-like resource input | Parameterized query path; no SQL execution observed |

Security headers verified: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`.

## 15. Automated Test Results

`python -m pytest backend/test_security.py -q`

**21 passed, 0 failed.** Two FastAPI deprecation warnings remain for `on_event("startup")`; they do not affect behavior.

Coverage includes authentication failures, MFA challenge, lockout, RBAC, token tampering, device/risk evidence, disabled policies, policy mutation, continuous authorization, session revocation, audit safety, resources, and security headers.

## 16. Frontend Build Results

`npm run build` completed successfully with Vite. No editor errors were reported in the touched backend, test, or frontend files.

## 17. Zero Trust Principle Mapping

| Principle | Status | Evidence |
| --- | --- | --- |
| Never Trust, Always Verify | IMPLEMENTED | Every protected request invokes the backend decision pipeline. |
| Least Privilege | IMPLEMENTED | Role/resource matching and default deny. |
| Continuous Verification | IMPLEMENTED | Same session receives a new decision after posture change. |
| Identity-Centric Access | IMPLEMENTED | Signed token maps identity to server-side user/session. |
| Device Trust | IMPLEMENTED | Posture-derived trust affects the decision. |
| Risk-Based Authorization | IMPLEMENTED | Explainable score and thresholds. |
| Micro-segmentation concepts | PARTIALLY IMPLEMENTED | Resource-level policy boundaries are simulated; no network segmentation enforcement. |
| Policy Enforcement | IMPLEMENTED | FastAPI endpoint is the backend enforcement point. |
| Continuous Monitoring | PARTIALLY IMPLEMENTED | SQLite audit/security telemetry and dashboard exist; no streaming SIEM pipeline. |
| Auditability | IMPLEMENTED | Decisions and security actions are persisted with evidence. |

## 18. NIST Conceptual Mapping

- Policy Enforcement Point: FastAPI protected endpoints, especially `/access/evaluate`.
- Policy Decision Point: `evaluate()` and policy/risk helpers.
- Policy Administrator: Admin policy create/update API.
- Identity: Seeded users, signed access token, server-side session.
- Device: Seeded device inventory with managed/encryption/EDR attributes.
- Resource: Persisted resource catalog and resource identifiers.
- Telemetry: `audit_logs`, `access_requests`, `security_events`, and dashboard aggregates.

This is a conceptual mapping to NIST SP 800-207, not a claim of NIST certification or full production compliance.

## 19. Vulnerabilities / Gaps Found

- MFA is simulated with a fixed demo OTP; it is not real TOTP.
- Refresh-token rotation is not implemented.
- Policy administration has backend APIs but no frontend policy-management view.
- SQLite is local demonstration storage, not production-scale persistence.
- No real device attestation or external IP reputation provider.
- No network-level micro-segmentation.
- CSP, HSTS, production rate limiting, secret management, and tamper-evident log shipping are not implemented.
- Deployment origins and API URLs are now supplied through `VITE_API_URL` and `ALLOWED_ORIGINS`; no API host is baked into the frontend bundle.

## 20. Fixes Applied

- Added required database entities and seeded roles/resources/MFA records.
- Added access request and security event persistence.
- Fixed invalid-token exception handling.
- Added five-failure temporary account lockout.
- Added security headers and typed Bearer OpenAPI security.
- Made device trust posture-sensitive.
- Increased suspicious-IP scoring to produce HIGH risk with sensitive access.
- Made frontend telemetry role-aware.
- Added configurable frontend API origin and explicit local CORS origins.
- Added 21 automated security tests.
- Corrected research documentation to describe the policy API/UI distinction accurately.

## 21. Remaining Limitations

The most important limitation is that MFA is deliberately demo-only. The second is that the UI does not expose the admin policy API, so a supervisor must use Swagger or an API client to demonstrate policy modification. This is acceptable for a research prototype but should be addressed before production or a polished final demonstration.

## 22. Final Assessment

### ZERO TRUST IMPLEMENTATION STATUS

🟡 **PARTIAL**

The core identity, device, risk, policy, continuous authorization, audit, and RBAC behavior is implemented and verified. Production-grade MFA, refresh tokens, SIEM integration, network segmentation, and policy UI are incomplete.

### APPLICATION STATUS

🟢 **RUNNABLE**

Backend tests pass, the current FastAPI source starts cleanly, the frontend production build succeeds, and the browser workflow works against the clean full stack.

### SECURITY STATUS

🟡 **ISSUES FOUND BUT NON-CRITICAL**

No critical authorization bypass was observed in the tested local scenarios. The remaining issues are prototype limitations, especially demo MFA and missing production controls.

**Tests executed:** 21  
**Passed:** 21  
**Failed:** 0  
**Fixed during verification:** 9 concrete issues/gaps  
**Remaining limitation groups:** 8  
**Frontend build:** PASS  
**Backend:** PASS on clean current-source port 8001  
**Most important remaining limitation:** MFA is fixed demo OTP rather than real TOTP.
