import secrets

from fastapi.testclient import TestClient
from main import app, db, init_db, risk_assessment

client = TestClient(app)
init_db()


def auth(email="employee@acme.test", device_id="dev-trusted-01"):
    response = client.post("/auth/login", json={"email": email, "password": "Demo@123", "device_id": device_id, "otp": "123456"})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def token(email="employee@acme.test", device_id="dev-trusted-01"):
    response = client.post("/auth/login", json={"email": email, "password": "Demo@123", "device_id": device_id, "otp": "123456"})
    return response.json()["access_token"]


def test_employee_internal_is_allowed():
    response = client.post("/access/evaluate", headers=auth(), json={"resource": "internal-directory", "device_id": "dev-trusted-01"})
    assert response.json()["decision"] == "ALLOW"


def test_employee_restricted_is_denied():
    response = client.post("/access/evaluate", headers=auth(), json={"resource": "financial-reports", "device_id": "dev-trusted-01"})
    assert response.json()["decision"] == "DENY"


def test_unmanaged_device_requires_step_up_or_denies():
    response = client.post("/access/evaluate", headers=auth(device_id="dev-unmanaged-01"), json={"resource": "internal-directory", "device_id": "dev-unmanaged-01", "ip": "203.0.113.44"})
    assert response.json()["decision"] in {"STEP_UP_AUTHENTICATION", "DENY"}


def test_guest_restricted_access_is_denied():
    response = client.post("/access/evaluate", headers=auth("guest@acme.test"), json={"resource": "confidential-documents", "device_id": "dev-trusted-01"})
    assert response.json()["decision"] == "DENY"


def test_admin_wildcard_access_is_allowed():
    response = client.post("/access/evaluate", headers=auth("admin@acme.test", "dev-admin-01"), json={"resource": "admin-console", "device_id": "dev-admin-01"})
    assert response.json()["decision"] == "ALLOW"


def test_suspicious_ip_raises_risk():
    response = client.post("/access/evaluate", headers=auth(), json={"resource": "internal-directory", "device_id": "dev-trusted-01", "ip": "203.0.113.44"})
    assert response.json()["risk"]["score"] >= 25
    assert "Suspicious IP reputation" in response.json()["risk"]["reasons"]


def test_missing_authentication_is_rejected():
    assert client.get("/me").status_code == 401


def test_tampered_token_is_rejected():
    assert client.get("/me", headers={"Authorization": f"Bearer {token()}.tampered"}).status_code == 401


def test_missing_mfa_returns_mfa_challenge():
    response = client.post("/auth/login", json={"email": "employee@acme.test", "password": "Demo@123"})
    assert response.status_code == 200
    assert response.json()["mfa_required"] is True


def test_invalid_password_is_rejected():
    response = client.post("/auth/login", json={"email": "employee@acme.test", "password": "wrong", "otp": "123456"})
    assert response.status_code == 401


def test_unknown_user_is_rejected():
    response = client.post("/auth/login", json={"email": "nobody@acme.test", "password": "wrong", "otp": "123456"})
    assert response.status_code == 401


def test_repeated_failures_lock_account_temporarily():
    with db() as connection:
        connection.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE email = 'guest@acme.test'")
        connection.commit()
    responses = [client.post("/auth/login", json={"email": "guest@acme.test", "password": "wrong"}) for _ in range(5)]
    with db() as connection:
        connection.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE email = 'guest@acme.test'")
        connection.commit()
    assert responses[-1].status_code == 429


def test_revoked_session_cannot_access_again():
    access_token = token()
    assert client.post("/access/evaluate", headers={"Authorization": f"Bearer {access_token}"}, json={"resource": "internal-directory"}).json()["decision"] == "ALLOW"
    assert client.post("/auth/logout", headers={"Authorization": f"Bearer {access_token}"}).status_code == 200
    assert client.get("/me", headers={"Authorization": f"Bearer {access_token}"}).status_code == 401


def test_employee_cannot_view_dashboard_or_policies():
    headers = auth()
    assert client.get("/dashboard/stats", headers=headers).status_code == 403
    assert client.get("/policies", headers=headers).status_code == 403


def test_analyst_cannot_modify_policies():
    payload = {"name": "Forbidden", "role": "employee", "resource": "internal-directory"}
    assert client.post("/policies", headers=auth("analyst@acme.test"), json=payload).status_code == 403


def test_admin_policy_update_changes_evaluation():
    headers = auth("admin@acme.test", "dev-admin-01")
    payload = {"name": "Test boundary", "description": "test", "role": "employee", "resource": f"research-sandbox-{secrets.token_hex(4)}", "required_mfa": True, "min_device_trust": 50, "max_risk": 60, "action": "ALLOW", "enabled": True}
    created = client.post("/policies", headers=headers, json=payload)
    assert created.status_code == 200
    employee = auth()
    assert client.post("/access/evaluate", headers=employee, json={"resource": payload["resource"]}).json()["decision"] == "ALLOW"
    payload["min_device_trust"] = 99
    updated = client.put(f"/policies/{created.json()['id']}", headers=headers, json=payload)
    assert updated.status_code == 200
    assert client.post("/access/evaluate", headers=employee, json={"resource": payload["resource"]}).json()["decision"] == "STEP_UP_AUTHENTICATION"


def test_disabled_policy_is_ignored():
    headers = auth("admin@acme.test", "dev-admin-01")
    payload = {"name": "Disabled boundary", "description": "test", "role": "employee", "resource": f"disabled-sandbox-{secrets.token_hex(4)}", "required_mfa": True, "min_device_trust": 0, "max_risk": 100, "action": "ALLOW", "enabled": False}
    assert client.post("/policies", headers=headers, json=payload).status_code == 200
    result = client.post("/access/evaluate", headers=auth(), json={"resource": payload["resource"]}).json()
    assert result["decision"] == "DENY"
    assert result["policy"] == "default-deny"


def test_identical_risk_inputs_are_deterministic():
    with db() as connection:
        user = connection.execute("SELECT * FROM users WHERE email='employee@acme.test'").fetchone()
        device = connection.execute("SELECT * FROM devices WHERE id='dev-trusted-01'").fetchone()
    first = risk_assessment(user, device, "financial-reports", "203.0.113.44")
    second = risk_assessment(user, device, "financial-reports", "203.0.113.44")
    assert first == second


def test_resources_are_persisted():
    response = client.get("/resources", headers=auth())
    assert {item["sensitivity"] for item in response.json()} == {"INTERNAL", "RESTRICTED", "CONFIDENTIAL"}


def test_security_headers_are_present():
    response = client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_decisions_are_audited_with_no_secret_fields():
    client.post("/access/evaluate", headers=auth(), json={"resource": "internal-directory"})
    with db() as connection:
        row = connection.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        columns = {item[1] for item in connection.execute("PRAGMA table_info(audit_logs)").fetchall()}
    assert row["decision"] == "ALLOW"
    assert {"timestamp", "email", "resource", "risk_score", "risk_level", "reason"}.issubset(columns)
    assert "password" not in columns and "token" not in columns
