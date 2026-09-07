from __future__ import annotations

import os
import secrets
import sqlite3
import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("ZTA_DB_PATH", BASE_DIR / "zta.db"))
SECRET_KEY = os.getenv("ZTA_SECRET_KEY") or secrets.token_urlsafe(32)
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if origin.strip()]
ALGORITHM = "HS256"
app = FastAPI(title="ZTA Research API", version="1.0.0", description="Explainable Zero Trust Architecture research prototype")
bearer = HTTPBearer(auto_error=False)
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["GET", "POST", "PUT", "OPTIONS"], allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_hash(value: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, 240000)
    return base64.urlsafe_b64encode(salt + digest).decode()


def password_verify(value: str, encoded: str) -> bool:
    raw = base64.urlsafe_b64decode(encoded.encode())
    return hmac.compare_digest(raw[16:], hashlib.pbkdf2_hmac("sha256", value.encode(), raw[:16], 240000))


def encode_token(payload: dict[str, Any]) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def decode_token(value: str) -> dict[str, Any]:
    body, signature = value.split(".")
    expected = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest()
    provided = base64.urlsafe_b64decode(signature + "=")
    if not hmac.compare_digest(expected, provided):
        raise ValueError("Invalid signature")
    payload = json.loads(base64.urlsafe_b64decode(body + "=="))
    if payload["exp"] < datetime.now(timezone.utc).timestamp():
        raise ValueError("Expired token")
    return payload


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY, description TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT, role TEXT, password_hash TEXT, mfa_enabled INTEGER DEFAULT 1, failed_logins INTEGER DEFAULT 0, locked_until TEXT, department TEXT DEFAULT 'General');
        CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, user_id INTEGER, os TEXT, browser TEXT, ip TEXT, managed INTEGER, encrypted INTEGER, edr_active INTEGER, status TEXT, trust_score INTEGER, last_seen TEXT);
        CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER, device_id TEXT, created_at TEXT, last_seen TEXT, revoked INTEGER DEFAULT 0, mfa_verified INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS resources (id TEXT PRIMARY KEY, label TEXT, sensitivity TEXT, description TEXT, required_role TEXT DEFAULT 'Employee+', min_trust INTEGER DEFAULT 0, required_mfa INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS policies (id INTEGER PRIMARY KEY, name TEXT, description TEXT, role TEXT, resource TEXT, required_mfa INTEGER, min_device_trust INTEGER, max_risk INTEGER, action TEXT, enabled INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS access_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_id INTEGER, resource TEXT, decision TEXT, risk_score INTEGER, device_id TEXT);
        CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_id INTEGER, email TEXT, ip TEXT, device_id TEXT, resource TEXT, action TEXT, decision TEXT, risk_score INTEGER, risk_level TEXT, reason TEXT, policy TEXT);
        CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, user_id INTEGER, event_type TEXT, severity TEXT, details TEXT);
        CREATE TABLE IF NOT EXISTS mfa_credentials (user_id INTEGER PRIMARY KEY, provider TEXT, enabled INTEGER, demo_only INTEGER);
        """)
        user_columns = {row[1] for row in connection.execute("PRAGMA table_info(users)").fetchall()}
        if "department" not in user_columns:
            connection.execute("ALTER TABLE users ADD COLUMN department TEXT DEFAULT 'General'")
        resource_columns = {row[1] for row in connection.execute("PRAGMA table_info(resources)").fetchall()}
        if "required_role" not in resource_columns:
            connection.execute("ALTER TABLE resources ADD COLUMN required_role TEXT DEFAULT 'Employee+'"); connection.execute("ALTER TABLE resources ADD COLUMN min_trust INTEGER DEFAULT 0"); connection.execute("ALTER TABLE resources ADD COLUMN required_mfa INTEGER DEFAULT 1")
        roles = [("admin", "Full security administration"), ("analyst", "Security investigation"), ("employee", "Standard enterprise access"), ("developer", "Engineering access"), ("finance", "Finance access"), ("guest", "Minimal access")]
        connection.executemany("INSERT OR IGNORE INTO roles VALUES (?, ?)", roles)
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            users = [(1, "admin@acme.test", "Aarav Mehta", "admin"), (2, "analyst@acme.test", "Mira Shah", "analyst"), (3, "employee@acme.test", "Riya Kapoor", "employee"), (4, "guest@acme.test", "Guest User", "guest")]
            for user_id, email, name, role in users:
                connection.execute("INSERT INTO users(id,email,name,role,password_hash,mfa_enabled,failed_logins,locked_until,department) VALUES (?, ?, ?, ?, ?, 1, 0, NULL, ?)", (user_id, email, name, role, password_hash("Demo@123"), "IT Security" if role == "admin" else "General"))
            devices = [("dev-trusted-01", 3, "Windows 11", "Edge", "10.10.1.21", 1, 1, 1, "trusted", 94, now()), ("dev-admin-01", 1, "macOS", "Safari", "10.10.1.10", 1, 1, 1, "trusted", 98, now()), ("dev-unmanaged-01", 3, "Android", "Chrome", "203.0.113.44", 0, 0, 0, "untrusted", 22, now())]
            connection.executemany("INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", devices)
            policies = [(1, "Admin trusted access", "Admins need a managed, healthy device.", "admin", "*", 1, 70, 60, "ALLOW", 1), (2, "Employee internal access", "Employees may access internal resources from trusted devices.", "employee", "internal-directory", 1, 50, 60, "ALLOW", 1), (3, "Restricted data boundary", "Restricted resources are reserved for administrators.", "admin", "financial-reports", 1, 80, 40, "ALLOW", 1), (4, "Guest public boundary", "Guests are limited to public resources.", "guest", "employee-directory", 0, 0, 30, "DENY", 1)]
            connection.executemany("INSERT INTO policies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", policies)
        resources = [("internal-directory", "Employee Directory", "INTERNAL", "People, teams and reporting lines", "Employee+", 60, 1), ("development-repository", "Development Repository", "INTERNAL / DEVELOPMENT", "Source code and engineering documentation", "Developer+", 60, 1), ("financial-reports", "Financial Reports", "RESTRICTED", "Quarterly performance and forecasts", "Finance / Administrator", 80, 1), ("security-reports", "Security Reports", "CONFIDENTIAL", "Incident analysis and controls", "Administrator", 90, 1), ("strategic-documents", "Strategic Documents", "HIGHLY CONFIDENTIAL", "Strategy and executive planning material", "Administrator", 95, 1), ("confidential-documents", "Confidential Documents", "CONFIDENTIAL", "Strategy and legal material", "Administrator", 90, 1)]
        connection.executemany("INSERT OR IGNORE INTO resources VALUES (?, ?, ?, ?, ?, ?, ?)", resources)
        demo_users = [("admin@technorizen.com", "Admin User", "admin", "IT Security"), ("riya@technorizen.com", "Riya Kapoor", "employee", "Human Resources"), ("arjun@technorizen.com", "Arjun Sharma", "developer", "Engineering"), ("neha@technorizen.com", "Neha Singh", "finance", "Finance")]
        demo_user_ids = {}
        for email, name, role, department in demo_users:
            existing_user = connection.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if not existing_user:
                connection.execute("INSERT INTO users(email,name,role,password_hash,mfa_enabled,failed_logins,locked_until,department) VALUES (?,?,?,?,1,0,NULL,?)", (email, name, role, password_hash("Demo@123"), department))
                existing_user = connection.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            demo_user_ids[email] = existing_user["id"]
        new_devices = [("dev-riya-trusted", demo_user_ids["riya@technorizen.com"], "Windows 11", "Edge", "10.10.2.21", 1, 1, 1, "trusted", 95, now()), ("dev-arjun-trusted", demo_user_ids["arjun@technorizen.com"], "Ubuntu 24.04", "Chrome", "10.10.2.22", 1, 1, 1, "trusted", 92, now()), ("dev-neha-trusted", demo_user_ids["neha@technorizen.com"], "Windows 11", "Edge", "10.10.2.23", 1, 1, 1, "trusted", 96, now()), ("dev-trusted-laptop", demo_user_ids["riya@technorizen.com"], "Windows 11", "Edge", "10.10.2.24", 1, 1, 1, "trusted", 95, now()), ("dev-high-risk", demo_user_ids["neha@technorizen.com"], "Windows 11", "Chrome", "203.0.113.55", 0, 0, 0, "untrusted", 15, now())]
        connection.executemany("INSERT OR IGNORE INTO devices VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", new_devices)
        demo_policies = [(10, "ZT-001", "All users must authenticate using valid credentials and MFA.", "*", "*", 1, 0, 100, "ALLOW", 1), (11, "ZT-002", "Restricted resources require authorized roles.", "finance", "financial-reports", 1, 80, 65, "ALLOW", 1), (12, "ZT-003", "High-risk devices cannot access confidential resources.", "admin", "security-reports", 1, 90, 35, "ALLOW", 1), (13, "ZT-004", "Confidential resources require continuous authorization.", "admin", "strategic-documents", 1, 95, 25, "ALLOW", 1), (14, "ZT-005", "High-risk sessions require re-authentication or termination.", "developer", "development-repository", 1, 60, 60, "ALLOW", 1), (15, "Employee directory access", "Least-privilege internal directory access.", "employee", "internal-directory", 1, 60, 60, "ALLOW", 1), (16, "Developer repository access", "Engineering resources are limited to developers.", "developer", "development-repository", 1, 60, 60, "ALLOW", 1)]
        for policy_id, name, description, role, resource, required_mfa, min_trust, max_risk, action, enabled in demo_policies:
            existing_policy = connection.execute("SELECT id FROM policies WHERE name=? AND role=? AND resource=?", (name, role, resource)).fetchone()
            if not existing_policy:
                connection.execute("INSERT INTO policies(name,description,role,resource,required_mfa,min_device_trust,max_risk,action,enabled) VALUES (?,?,?,?,?,?,?,?,?)", (name, description, role, resource, required_mfa, min_trust, max_risk, action, enabled))
        user_ids = [row["id"] for row in connection.execute("SELECT id FROM users").fetchall()]
        connection.executemany("INSERT OR IGNORE INTO mfa_credentials VALUES (?, ?, ?, ?)", [(user_id, "demo-otp", 1, 1) for user_id in user_ids])
        connection.commit()


@app.on_event("startup")
def startup() -> None:
    init_db()


class LoginRequest(BaseModel):
    email: str
    password: str
    device_id: str = "dev-trusted-01"
    otp: str | None = None


class AccessRequest(BaseModel):
    resource: str
    method: str = "GET"
    device_id: str = "dev-trusted-01"
    ip: str | None = None


class PolicyPayload(BaseModel):
    name: str
    description: str = ""
    role: str
    resource: str
    required_mfa: bool = True
    min_device_trust: int = 0
    max_risk: int = 100
    action: str = "ALLOW"
    enabled: bool = True


class DevicePosturePayload(BaseModel):
    managed: bool
    encrypted: bool
    edr_active: bool
    status: str = "trusted"
    trust_score: int = 95


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP_AUTHENTICATION = "STEP_UP_AUTHENTICATION"


def token_for(user: sqlite3.Row, session_id: str) -> str:
    payload = {"sub": str(user["id"]), "email": user["email"], "role": user["role"], "sid": session_id, "exp": datetime.now(timezone.utc).timestamp() + 1800}
    return encode_token(payload)


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> sqlite3.Row:
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = decode_token(credentials.credentials)
        user_id, session_id = int(payload["sub"]), payload["sid"]
    except (KeyError, ValueError, json.JSONDecodeError, IndexError):
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    with db() as connection:
        session = connection.execute("SELECT * FROM sessions WHERE id = ? AND revoked = 0", (session_id,)).fetchone()
        user = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not session or not user:
        raise HTTPException(status_code=401, detail="Session revoked or unknown")
    return user


def risk_assessment(user: sqlite3.Row, device: sqlite3.Row | None, resource: str, ip: str | None) -> dict[str, Any]:
    score, reasons = 0, []
    if not device:
        score += 35; reasons.append("Unknown device")
    else:
        if not device["managed"]: score += 25; reasons.append("Unmanaged device")
        if not device["encrypted"]: score += 15; reasons.append("Storage encryption disabled")
        if not device["edr_active"]: score += 15; reasons.append("EDR inactive")
        if device["trust_score"] < 50: score += 20; reasons.append("Low device trust score")
    if ip and ip.startswith("203.0.113."): score += 45; reasons.append("Suspicious IP reputation")
    if resource in {"financial-reports", "hr-records", "confidential-documents"}: score += 20; reasons.append("Sensitive resource requested")
    if user["failed_logins"] > 0: score += min(15, user["failed_logins"] * 5); reasons.append("Recent failed login activity")
    score = min(100, score)
    level = "LOW" if score <= 30 else "MEDIUM" if score <= 60 else "HIGH" if score <= 80 else "CRITICAL"
    return {"score": score, "level": level, "reasons": reasons or ["No elevated risk indicators"]}


def device_trust(device: sqlite3.Row | None) -> int:
    if not device or device["status"] == "blocked":
        return 0
    posture_score = 10 + (30 if device["managed"] else 0) + (30 if device["encrypted"] else 0) + (25 if device["edr_active"] else 0)
    return max(0, min(100, min(int(device["trust_score"]), posture_score)))


def evaluate(user: sqlite3.Row, request: AccessRequest) -> dict[str, Any]:
    with db() as connection:
        device = connection.execute("SELECT * FROM devices WHERE id = ? AND user_id = ?", (request.device_id, user["id"])).fetchone()
        policies = connection.execute("SELECT * FROM policies WHERE enabled = 1 ORDER BY id").fetchall()
    risk = risk_assessment(user, device, request.resource, request.ip)
    trust = device_trust(device)
    matching = [p for p in policies if p["role"] == user["role"] and (p["resource"] == request.resource or p["resource"] == "*")]
    policy = matching[0] if matching else None
    reasons = list(risk["reasons"])
    decision = Decision.DENY
    if policy and policy["action"] == "ALLOW" and trust >= policy["min_device_trust"] and risk["score"] <= policy["max_risk"]:
        decision = Decision.ALLOW
    elif policy and policy["action"] == "ALLOW" and (trust < policy["min_device_trust"] or risk["score"] > policy["max_risk"]):
        decision = Decision.STEP_UP_AUTHENTICATION if risk["score"] <= 80 else Decision.DENY
        reasons.append("Policy threshold not satisfied")
    else:
        reasons.append("No matching least-privilege policy")
    result = {"decision": decision, "risk": risk, "device_trust": trust, "policy": policy["name"] if policy else "default-deny", "reasons": reasons, "resource": request.resource}
    with db() as connection:
        connection.execute("INSERT INTO audit_logs(timestamp,user_id,email,ip,device_id,resource,action,decision,risk_score,risk_level,reason,policy) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (now(), user["id"], user["email"], request.ip or (device["ip"] if device else "unknown"), request.device_id, request.resource, request.method, decision.value, risk["score"], risk["level"], "; ".join(reasons), result["policy"]))
        connection.execute("INSERT INTO access_requests(timestamp,user_id,resource,decision,risk_score,device_id) VALUES (?,?,?,?,?,?)", (now(), user["id"], request.resource, decision.value, risk["score"], request.device_id))
        if decision != Decision.ALLOW:
            connection.execute("INSERT INTO security_events(timestamp,user_id,event_type,severity,details) VALUES (?,?,?,?,?)", (now(), user["id"], "ACCESS_REVIEW", risk["level"], "; ".join(reasons)))
        connection.commit()
    return result


@app.post("/auth/login")
def login(payload: LoginRequest):
    with db() as connection:
        user = connection.execute("SELECT * FROM users WHERE email = ?", (payload.email.lower(),)).fetchone()
        if user and user["locked_until"] and user["locked_until"] > now():
            raise HTTPException(status_code=429, detail="Account temporarily locked after repeated failures")
        if not user or not password_verify(payload.password, user["password_hash"]):
            if user:
                failed_logins = user["failed_logins"] + 1
                locked_until = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat() if failed_logins >= 5 else None
                connection.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?", (failed_logins, locked_until, user["id"]))
                event = "ACCOUNT_LOCKED" if locked_until else "FAILED_LOGIN"
                connection.execute("INSERT INTO security_events(timestamp,user_id,event_type,severity,details) VALUES (?,?,?,?,?)", (now(), user["id"], event, "HIGH" if locked_until else "MEDIUM", "Invalid credentials"))
                connection.commit()
            raise HTTPException(status_code=429 if user and locked_until else 401, detail="Account temporarily locked after repeated failures" if user and locked_until else "Invalid credentials")
        connection.execute("UPDATE users SET failed_logins = 0 WHERE id = ?", (user["id"],)); connection.commit()
    if user["mfa_enabled"] and payload.otp != "123456":
        with db() as connection:
            connection.execute("INSERT INTO security_events(timestamp,user_id,event_type,severity,details) VALUES (?,?,?,?,?)", (now(), user["id"], "MFA_REQUIRED", "LOW", "Demo OTP verification required")); connection.commit()
        return {"mfa_required": True, "message": "MFA required. Demo OTP is 123456."}
    session_id = secrets.token_urlsafe(18)
    with db() as connection:
        connection.execute("INSERT OR IGNORE INTO sessions VALUES (?, ?, ?, ?, ?, 0, 1)", (session_id, user["id"], payload.device_id, now(), now())); connection.commit()
    return {"access_token": token_for(user, session_id), "token_type": "bearer", "user": {"email": user["email"], "name": user["name"], "role": user["role"]}, "session_id": session_id}


@app.post("/auth/logout")
def logout(user: sqlite3.Row = Depends(current_user), credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(credentials.credentials)
    with db() as connection:
        connection.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (payload["sid"],))
        connection.execute("INSERT INTO security_events(timestamp,user_id,event_type,severity,details) VALUES (?,?,?,?,?)", (now(), user["id"], "SESSION_REVOKED", "LOW", "User logout")); connection.commit()
    return {"message": "Session revoked"}


@app.post("/access/evaluate")
def access_evaluate(payload: AccessRequest, user: sqlite3.Row = Depends(current_user)):
    return evaluate(user, payload)


@app.get("/me")
def me(user: sqlite3.Row = Depends(current_user)):
    return {"email": user["email"], "name": user["name"], "role": user["role"], "department": user["department"], "mfa_enabled": bool(user["mfa_enabled"]), "identity_status": "VERIFIED"}


@app.get("/dashboard/stats")
def dashboard_stats(user: sqlite3.Row = Depends(current_user)):
    if user["role"] not in {"admin", "analyst"}: raise HTTPException(403, "Security role required")
    with db() as connection:
        values = {"total_requests": connection.execute("SELECT COUNT(*) c FROM audit_logs").fetchone()["c"], "allowed": connection.execute("SELECT COUNT(*) c FROM audit_logs WHERE decision='ALLOW'").fetchone()["c"], "denied": connection.execute("SELECT COUNT(*) c FROM audit_logs WHERE decision != 'ALLOW'").fetchone()["c"], "high_risk": connection.execute("SELECT COUNT(*) c FROM audit_logs WHERE risk_level IN ('HIGH','CRITICAL')").fetchone()["c"], "trusted_devices": connection.execute("SELECT COUNT(*) c FROM devices WHERE status='trusted'").fetchone()["c"], "active_sessions": connection.execute("SELECT COUNT(*) c FROM sessions WHERE revoked=0").fetchone()["c"], "active_users": connection.execute("SELECT COUNT(*) c FROM users WHERE locked_until IS NULL OR locked_until < ?", (now(),)).fetchone()["c"]}
        values["logs"] = [dict(row) for row in connection.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 8").fetchall()]
    return values


@app.get("/resources")
def resources(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        rows = connection.execute("SELECT * FROM resources ORDER BY id").fetchall()
        if user["id"] < 10:
            rows = [row for row in rows if row["id"] in {"internal-directory", "financial-reports", "security-reports", "confidential-documents"}]
        return [dict(row) for row in rows]


@app.get("/audit-logs")
def audit_logs(user: sqlite3.Row = Depends(current_user), search: str = Query(default="")):
    if user["role"] not in {"admin", "analyst"}: raise HTTPException(403, "Security role required")
    with db() as connection:
        rows = connection.execute("SELECT * FROM audit_logs WHERE resource LIKE ? OR decision LIKE ? ORDER BY id DESC LIMIT 100", (f"%{search}%", f"%{search}%")).fetchall()
    return [dict(row) for row in rows]


@app.get("/events")
def events(user: sqlite3.Row = Depends(current_user)):
    require_admin_or_security = user["role"] in {"admin", "analyst"}
    if not require_admin_or_security:
        raise HTTPException(403, "Security role required")
    with db() as connection:
        rows = connection.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 100").fetchall()
    return [dict(row) for row in rows]


@app.get("/sessions")
def sessions(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        rows = connection.execute("SELECT sessions.*, devices.os, devices.browser, devices.trust_score, devices.ip FROM sessions LEFT JOIN devices ON devices.id=sessions.device_id WHERE sessions.user_id=? ORDER BY sessions.last_seen DESC", (user["id"],)).fetchall()
    return [dict(row) for row in rows]


@app.post("/sessions/{session_id}/terminate")
def terminate_session(session_id: str, user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        session = connection.execute("SELECT * FROM sessions WHERE id=? AND user_id=?", (session_id, user["id"])).fetchone()
        if not session and user["role"] == "admin":
            session = connection.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not session:
            raise HTTPException(404, "Session not found")
        connection.execute("UPDATE sessions SET revoked=1 WHERE id=?", (session_id,))
        connection.execute("INSERT INTO security_events(timestamp,user_id,event_type,severity,details) VALUES (?,?,?,?,?)", (now(), user["id"], "SESSION_TERMINATED", "MEDIUM", f"Session {session_id} terminated")); connection.commit()
    return {"status": "revoked", "session_id": session_id}


@app.get("/devices")
def devices(user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        rows = connection.execute("SELECT * FROM devices WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()
    return [dict(row) for row in rows]


@app.put("/devices/{device_id}/posture")
def update_device_posture(device_id: str, payload: DevicePosturePayload, user: sqlite3.Row = Depends(current_user)):
    with db() as connection:
        device = connection.execute("SELECT * FROM devices WHERE id=? AND user_id=?", (device_id, user["id"])).fetchone()
        if not device:
            raise HTTPException(404, "Device not found")
        trust_score = max(0, min(100, payload.trust_score))
        connection.execute("UPDATE devices SET managed=?,encrypted=?,edr_active=?,status=?,trust_score=?,last_seen=? WHERE id=?", (payload.managed, payload.encrypted, payload.edr_active, payload.status, trust_score, now(), device_id))
        connection.execute("INSERT INTO security_events(timestamp,user_id,event_type,severity,details) VALUES (?,?,?,?,?)", (now(), user["id"], "DEVICE_RISK_CHANGED", "HIGH" if trust_score < 50 else "LOW", f"Device {device_id} posture updated")); connection.commit()
        updated = connection.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    return dict(updated)


@app.get("/admin/users")
def admin_users(user: sqlite3.Row = Depends(current_user)):
    require_admin(user)
    with db() as connection:
        rows = connection.execute("SELECT id,name,email,role,department,mfa_enabled,failed_logins,locked_until FROM users ORDER BY id").fetchall()
    return [dict(row) for row in rows]


@app.get("/admin/stats")
def admin_stats(user: sqlite3.Row = Depends(current_user)):
    require_admin(user)
    return dashboard_stats(user)


def require_admin(user: sqlite3.Row) -> None:
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator role required")


@app.get("/policies")
def policies(user: sqlite3.Row = Depends(current_user)):
    require_admin(user)
    with db() as connection:
        return [dict(row) for row in connection.execute("SELECT * FROM policies ORDER BY id").fetchall()]


@app.post("/policies")
def create_policy(payload: PolicyPayload, user: sqlite3.Row = Depends(current_user)):
    require_admin(user)
    with db() as connection:
        cursor = connection.execute("INSERT INTO policies(name,description,role,resource,required_mfa,min_device_trust,max_risk,action,enabled) VALUES (?,?,?,?,?,?,?,?,?)", (payload.name, payload.description, payload.role, payload.resource, payload.required_mfa, payload.min_device_trust, payload.max_risk, payload.action, payload.enabled))
        connection.execute("INSERT INTO security_events(timestamp,user_id,event_type,severity,details) VALUES (?,?,?,?,?)", (now(), user["id"], "POLICY_CREATED", "LOW", payload.name))
        connection.commit()
        return dict(connection.execute("SELECT * FROM policies WHERE id = ?", (cursor.lastrowid,)).fetchone())


@app.put("/policies/{policy_id}")
def update_policy(policy_id: int, payload: PolicyPayload, user: sqlite3.Row = Depends(current_user)):
    require_admin(user)
    with db() as connection:
        connection.execute("UPDATE policies SET name=?,description=?,role=?,resource=?,required_mfa=?,min_device_trust=?,max_risk=?,action=?,enabled=? WHERE id=?", (payload.name, payload.description, payload.role, payload.resource, payload.required_mfa, payload.min_device_trust, payload.max_risk, payload.action, payload.enabled, policy_id))
        connection.execute("INSERT INTO security_events(timestamp,user_id,event_type,severity,details) VALUES (?,?,?,?,?)", (now(), user["id"], "POLICY_UPDATED", "LOW", f"Policy {policy_id}: {payload.name}"))
        connection.commit()
        row = connection.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Policy not found")
    return dict(row)


@app.get("/health")
def health():
    return {"status": "ok", "service": "zta-api"}
