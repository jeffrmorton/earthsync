"""Tests for authentication endpoints."""

import pytest


@pytest.mark.asyncio
async def test_register_success(client):
    resp = await client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "securepass123"},
    )
    assert resp.status_code == 201
    assert resp.json()["username"] == "testuser"


@pytest.mark.asyncio
async def test_register_duplicate(client):
    await client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "securepass123"},
    )
    resp = await client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "securepass123"},
    )
    assert resp.status_code == 409
    assert "already taken" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_invalid_username_too_short(client):
    resp = await client.post(
        "/api/auth/register",
        json={"username": "ab", "password": "securepass123"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_password_too_short(client):
    resp = await client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "short"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_username_pattern(client):
    resp = await client.post(
        "/api/auth/register",
        json={"username": "bad user!", "password": "securepass123"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client):
    await client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "securepass123"},
    )
    resp = await client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "securepass123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["expires_in"] == 3600


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    await client.post(
        "/api/auth/register",
        json={"username": "testuser", "password": "securepass123"},
    )
    resp = await client.post(
        "/api/auth/login",
        json={"username": "testuser", "password": "wrongpassword"},
    )
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_login_missing_user(client):
    resp = await client.post(
        "/api/auth/login",
        json={"username": "nobody", "password": "securepass123"},
    )
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.json()["detail"]
