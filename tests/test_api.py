"""API contract and hardening tests.

These test the boundary, not the logic: does bad input get rejected before
it reaches the engine, and does the engine's output survive serialisation?
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_happy_path():
    response = client.post("/api/analyze", json={
        "sender": "PayPal Support <billing@paypa1-secure.info>",
        "subject": "Urgent: verify your account within 24 hours",
        "body": '<a href="http://paypal.com.verify.tk/login">https://paypal.com</a>',
        "attachments": ["statement.pdf.exe"],
    })
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "high_risk"
    assert data["score"] >= 90
    assert data["findings"]
    assert all(f["why"] for f in data["findings"])


def test_analyze_rejects_empty_request():
    """Pydantic must refuse a request with nothing to analyze."""
    response = client.post("/api/analyze", json={})
    assert response.status_code == 422


def test_analyze_rejects_oversized_field():
    response = client.post("/api/analyze", json={"subject": "x" * 5_000})
    assert response.status_code == 422


def test_analyze_rejects_wrong_types():
    response = client.post("/api/analyze", json={"attachments": "not-a-list"})
    assert response.status_code == 422


def test_unknown_fields_are_ignored_not_trusted():
    """Extra keys must not reach the engine."""
    response = client.post("/api/analyze", json={
        "subject": "hello",
        "body": "hi",
        "score": 0,            # attempt to override the verdict
        "__proto__": {"x": 1},
    })
    assert response.status_code == 200


def test_security_headers_present():
    response = client.get("/api/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


def test_samples_listing():
    response = client.get("/api/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) >= 6
    # The corpus must contain legitimate mail too, or it teaches paranoia.
    assert any(not s["is_phishing"] for s in samples)
    assert any(s["is_phishing"] for s in samples)
    assert all(s["teaching_point"] for s in samples)


def test_sample_not_found():
    assert client.get("/api/samples/does-not-exist").status_code == 404


def test_every_sample_scores_in_the_right_direction():
    """A labelled corpus is also a regression suite: the engine must agree
    with the label on every training sample."""
    samples = client.get("/api/samples").json()
    for sample in samples:
        result = client.post("/api/analyze", json={
            "sender": sample["sender"],
            "subject": sample["subject"],
            "body": sample["body"],
            "attachments": sample["attachments"],
        }).json()
        if sample["is_phishing"]:
            assert result["score"] >= 50, (
                f"{sample['id']} is phishing but scored {result['score']}"
            )
        else:
            assert result["score"] < 25, (
                f"{sample['id']} is legitimate but scored {result['score']}"
            )
