# tests/auth_test.py

import pytest
from backend import create_app, db
from config import TestingConfig


#------------- conftest.py-------------------

@pytest.fixture
def app():
    app = create_app(config_class=TestingConfig)  # Create app with testing config
    with app.app_context():
        db.create_all()  # Set up in-memory database for testing
        yield app
        db.session.remove()
        db.drop_all()  # Clean up after tests


#------------- auth/register-------------------

@pytest.fixture
def client(app):
    return app.test_client()

def test_register(client):
    response = client.post('/auth/register', json={
        'userName': 'testuser',
        'email': 'test@example.com',
        'password': 'password123',
        'name': 'Test',
        'lastName': 'User',
        'age': 30
    })
    assert response.status_code == 200
    assert b'User registered successfully!' in response.data

#------------- auth/loging-------------------
@pytest.fixture
def test_login_page(client):
    response = client.get('/auth/login')
    assert response.status_code == 200
    assert b'Login' in response.data


def test_login_success(client):
    # Register a user first
    client.post('/auth/register', data={
        'userName': 'testlogin',
        'email': 'testlogin@example.com',
        'password': 'password123',
        'name': 'Test',
        'lastName': 'Login',
        'age': 35
    })
    # Attempt to log in
    response = client.post('/auth/login', json={
        'email': 'testlogin@example.com',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert b'accessToken' in response.data


def test_login_missing_fields(client):
    response = client.post('/auth/login', json={
        'email': '',
        'password': 'password123'
    })
    assert response.status_code == 400
    assert b'Email and password are required' in response.data


def test_login_invalid_credentials(client):
    response = client.post('/auth/login', json={
        'email': 'nonexistent@example.com',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert b'Invalid email or password' in response.data
