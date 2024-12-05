import pytest
import sqlite3
import json
from datetime import datetime, timedelta
from main3 import app, createDb, insertKeyIntoDb, generateRsaKeyPair

@pytest.fixture
def client():
    """Fixture to initialize the Flask test client."""
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def setup_database():
    """Setup the database before each test."""
    createDb()
    # Clear database tables before each test
    with sqlite3.connect('totally_not_my_privateKeys.db') as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM keys')
        cursor.execute('DELETE FROM users')
        cursor.execute('DELETE FROM auth_logs')
        conn.commit()
    yield

def test_register_new_user(client):
    """Test successful user registration."""
    data = {'username': 'testuser', 'email': 'testuser@example.com'}
    response = client.post('/register', json=data)
    assert response.status_code == 201
    response_data = json.loads(response.data)
    assert 'password' in response_data
    assert response_data['password'] != ''

def test_register_existing_user(client):
    """Test registration with existing username or email."""
    data = {'username': 'testuser', 'email': 'testuser@example.com'}
    client.post('/register', json=data)  # Register once
    response = client.post('/register', json=data)  # Attempt to register again
    assert response.status_code == 409
    response_data = json.loads(response.data)
    assert response_data['message'] == 'Username or email already exists'

def test_auth_invalid_credentials(client):
    """Test authentication with invalid credentials."""
    auth_data = {'username': 'nonexistent', 'password': 'wrongpassword'}
    response = client.post('/auth', json=auth_data)
    assert response.status_code == 401
    response_data = json.loads(response.data)
    assert response_data['message'] == 'Invalid credentials'

def test_auth_rate_limit(client):
    """Test rate-limiting during authentication."""
    # Register a new user
    data = {'username': 'testuser', 'email': 'testuser@example.com'}
    response = client.post('/register', json=data)
    password = json.loads(response.data)['password']

    # Attempt to authenticate repeatedly
    auth_data = {'username': 'testuser', 'password': password}
    for _ in range(12):  # Exceed the RATE_LIMIT (10)
        response = client.post('/auth', json=auth_data)

    # Check the rate-limited response
    assert response.status_code == 429
    response_data = json.loads(response.data)
    assert response_data['message'] == "Too many requests, please try again later."

def test_get_valid_keys():
    """Test the retrieval of valid keys from the database."""
    key = generateRsaKeyPair()
    expiry = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    insertKeyIntoDb(key, expiry)

    from main3 import getValidKeysFromDb
    keys = getValidKeysFromDb(expired=False)
    assert len(keys) > 0, "Expected at least one valid key"
