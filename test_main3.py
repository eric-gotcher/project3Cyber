import pytest
import json
import sqlite3
from time import sleep
from datetime import datetime, timedelta
from main3 import app, createDb, insertKeyIntoDb, getValidKeysFromDb, generateRsaKeyPair

@pytest.fixture
def client():
    """Fixture to initialize the Flask test client."""
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def setup_database():
    """Setup the database before each test."""
    createDb()  # Create a fresh database
    # Clear any existing keys from the keys table
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM keys')  # Clear existing keys
    cursor.execute('DELETE FROM users')  # Clear existing users
    cursor.execute('DELETE FROM auth_logs')  # Clear authentication logs
    conn.commit()
    conn.close()
    yield

def test_register_new_user(client):
    """Test user registration."""
    data = {'username': 'testuser', 'email': 'testuser@example.com'}
    response = client.post('/register', json=data)
    assert response.status_code == 201
    response_data = json.loads(response.data)
    assert 'password' in response_data
    assert response_data['password'] != ''

def test_register_existing_user(client):
    """Test user registration when username or email already exists."""
    data = {'username': 'testuser', 'email': 'testuser@example.com'}
    client.post('/register', json=data)  # Register the user first
    response = client.post('/register', json=data)  # Try registering again
    assert response.status_code == 409
    response_data = json.loads(response.data)
    assert 'message' in response_data
    assert response_data['message'] == 'Username or email already exists'

def test_jwks(client):
    """Test the /.well-known/jwks.json endpoint."""
    # Store a valid key
    key = generateRsaKeyPair()
    expiry = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    insertKeyIntoDb(key, expiry)

    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    response_data = json.loads(response.data)
    assert 'keys' in response_data
    assert len(response_data['keys']) > 0

    key = response_data['keys'][0]
    assert 'kid' in key
    assert 'kty' in key
    assert 'alg' in key
    assert 'use' in key
    assert 'n' in key
    assert 'e' in key

def test_get_valid_keys(client):
    """Test retrieval of valid keys from the database."""
    # Store a valid key
    key = generateRsaKeyPair()
    expiry = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    insertKeyIntoDb(key, expiry)

    keys = getValidKeysFromDb(expired=False)
    assert len(keys) > 0  # There should be valid keys
