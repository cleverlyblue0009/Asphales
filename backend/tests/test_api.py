"""API endpoint tests using httpx TestClient."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import app
from api.routes import set_classifier
from services.classifier import HybridClassifier


@pytest_asyncio.fixture
async def client():
    set_classifier(HybridClassifier())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health_check(client):
    r = await client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "SurakshaAI Shield"


@pytest.mark.asyncio
async def test_analyze_phishing(client):
    r = await client.post("/analyze", json={"text": "Password share karo turant!"})
    assert r.status_code == 200
    data = r.json()
    assert data["overall_risk"] > 40
    assert len(data["threats"]) > 0


@pytest.mark.asyncio
async def test_analyze_safe(client):
    r = await client.post("/analyze", json={"text": "Kal meeting hai 3 baje."})
    assert r.status_code == 200
    data = r.json()
    assert data["overall_risk"] < 30


@pytest.mark.asyncio
async def test_analyze_empty(client):
    r = await client.post("/analyze", json={"text": ""})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_analyze_too_long(client):
    r = await client.post("/analyze", json={"text": "a" * 6000})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_batch_analyze(client):
    texts = ["Password share karo", "Hello, how are you?"]
    r = await client.post("/batch-analyze", json={"texts": texts})
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 2
    assert len(data["results"]) == 2


@pytest.mark.asyncio
async def test_stats(client):
    r = await client.get("/stats")
    assert r.status_code == 200
    data = r.json()
    assert "total_requests" in data
    assert "cache" in data


@pytest.mark.asyncio
async def test_patterns(client):
    r = await client.get("/patterns")
    assert r.status_code == 200
    data = r.json()
    assert data["total_patterns"] == 0
    assert data["deprecated"] is True


@pytest.mark.asyncio
async def test_caching(client):
    text = "OTP bhejo abhi warna block hoga"
    r1 = await client.post("/analyze", json={"text": text})
    r2 = await client.post("/analyze", json={"text": text})
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r2.json()["cached"] is True
