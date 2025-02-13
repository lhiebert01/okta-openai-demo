import os
from flask import Flask, render_template, redirect, request, session, url_for, jsonify
from flask_session import Session
from functools import wraps
import requests
import secrets
import base64
import hashlib
from urllib.parse import urlencode
from dotenv import load_dotenv
import logging
from openai import OpenAI
import openai
import redis
import time
from datetime import datetime, timedelta
import json

# Load environment variables
load_dotenv(override=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

# Redis Configuration
REDIS_URL = os.getenv("REDIS_URL")  # For Render
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")  # For Render

# Session Configuration
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'flask_session:'

# Try Redis connection
try:
    if REDIS_URL:  # For Render
        logger.info(f"Attempting to connect to Redis using URL: {REDIS_URL}")
        redis_client = redis.from_url(REDIS_URL)
    else:  # For local development
        logger.info(f"Attempting to connect to Redis at {REDIS_HOST}:{REDIS_PORT}")
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            decode_responses=True,
            socket_timeout=5
        )
    
    redis_client.ping()
    logger.info("Redis connection successful")
    app.config['SESSION_REDIS'] = redis_client
    
except redis.ConnectionError as e:
    logger.warning(f"Redis connection failed: {e}. Falling back to filesystem sessions")
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = './flask_sessions'

Session(app)

# Okta Settings
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "dev-14162863.okta.com")
OKTA_CLIENT_ID = os.getenv("OKTA_CLIENT_ID", "0oan1mokxuIokN9Ih5d7")
OKTA_CLIENT_SECRET = os.getenv("OKTA_CLIENT_SECRET")
OKTA_REDIRECT_URI = os.getenv("OKTA_REDIRECT_URI", "http://localhost:5000/callback")
OKTA_ISSUER = os.getenv("OKTA_ISSUER", f"https://{OKTA_DOMAIN}/oauth2/ausn1mvtp8e6ob1VV5d7")

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai.api_key = OPENAI_API_KEY

# Verify required environment variables
if not OKTA_CLIENT_SECRET:
    logger.error("OKTA_CLIENT_SECRET must be set in .env file!")
    raise ValueError("Missing OKTA_CLIENT_SECRET")

if not OPENAI_API_KEY:
    logger.error("OPENAI_API_KEY must be set in .env file!")
    raise ValueError("Missing OPENAI_API_KEY")

def format_time_remaining(seconds):
    """Format remaining time into days, hours, minutes, seconds"""
    if seconds <= 0:
        return "Expired"
    
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{int(days)} days")
    if hours > 0:
        parts.append(f"{int(hours)} hours")
    if minutes > 0:
        parts.append(f"{int(minutes)} minutes")
    if seconds > 0 and not parts:  # Only show seconds if less than a minute
        parts.append(f"{int(seconds)} seconds")
    
    return ", ".join(parts) if parts else "Less than a minute"

def is_token_expired():
    """Check if the current token is expired"""
    current_time = int(time.time())
    return 'token_expiry' not in session or current_time >= session['token_expiry']

@app.before_request
def before_request():
    """Check token expiration before each request"""
    session.permanent = True
    logger.info(f"Request URL: {request.url}")
    
    # Skip token check for certain routes
    if request.endpoint in ['login', 'callback', 'logout', 'static', 'token_expired']:
        return
        
    if 'access_token' in session and is_token_expired():
        logger.info("Access token expired, redirecting to token expired page.")
        return redirect(url_for('token_expired'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session or is_token_expired():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_info(access_token):
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(
            f'{OKTA_ISSUER}/v1/userinfo',
            headers=headers
        )
        response.raise_for_status()
        user_info = response.json()

        # Get additional user profile information from Okta
        api_token = os.getenv('OKTA_API_TOKEN')
        if api_token:
            user_id = user_info["sub"]
            profile_url = f'https://{OKTA_DOMAIN}/api/v1/users/{user_id}'
            profile_response = requests.get(
                profile_url,
                headers={'Authorization': f'SSWS {api_token}'}
            )
            
            if profile_response.ok:
                profile_data = profile_response.json()
                # Add additional profile fields to user_info
                user_info['profile'] = profile_data.get('profile', {})
                logger.info(f"Available profile fields: {user_info['profile'].keys()}")
            else:
                logger.error(f"Profile API error: {profile_response.status_code}")

        # Get user groups
        if api_token:
            groups_url = f'https://{OKTA_DOMAIN}/api/v1/users/{user_info["sub"]}/groups'
            groups_response = requests.get(
                groups_url,
                headers={'Authorization': f'SSWS {api_token}'}
            )
            
            if groups_response.ok:
                groups = groups_response.json()
                user_info['groups'] = [
                    {'name': g['profile']['name'], 'type': g['type']} 
                    for g in groups
                ]
                logger.info(f"Groups found: {user_info['groups']}")
            else:
                logger.error(f"Groups API error: {groups_response.status_code}")

        return user_info
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return None
    
@app.route('/')
@login_required
def index():
    user_info = get_user_info(session.get('access_token'))
    if not user_info:
        session.clear()
        return redirect(url_for('login'))

    # Calculate token expiration information
    token_expiry_time = session.get("token_expiry", 0)
    current_time = int(time.time())
    remaining_seconds = max(token_expiry_time - current_time, 0)
    
    remaining_time = format_time_remaining(remaining_seconds)
    expiry_datetime = datetime.fromtimestamp(token_expiry_time)

    # Parse ID token for additional information
    id_token = session.get('id_token', '')
    try:
        # Get the payload part of the JWT (second part)
        id_token_payload = id_token.split('.')[1]
        # Add padding if needed
        id_token_payload += '=' * ((4 - len(id_token_payload) % 4) % 4)
        # Decode the base64 string
        id_token_data = json.loads(base64.b64decode(id_token_payload))
        
        # Format timestamps
        auth_time = datetime.fromtimestamp(id_token_data.get('auth_time', 0))
        id_token_expiry = datetime.fromtimestamp(id_token_data.get('exp', 0))
        
        # Add authentication details to user_info
        user_info['auth_details'] = {
            'auth_time': auth_time.strftime('%Y-%m-%d %H:%M:%S'),
            'auth_method': id_token_data.get('amr', ['Unknown'])[0],
            'issuer': id_token_data.get('iss', 'Unknown'),
            'id_token_expiry': id_token_expiry.strftime('%Y-%m-%d %H:%M:%S')
        }
        
    except Exception as e:
        logger.error(f"Error parsing ID token: {e}")
        user_info['auth_details'] = {}

    return render_template('index.html',
                         user=user_info,
                         auth_info={
                             'access_token': session.get('access_token'),
                             'id_token': session.get('id_token', 'Not found'),
                             'token_expiry': expiry_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                             'remaining_time': remaining_time,
                             'redirect_uri': OKTA_REDIRECT_URI,
                             'issuer': OKTA_ISSUER,
                             'scope': 'openid profile email'
                         },
                         okta_domain=OKTA_DOMAIN,
                         client_id=OKTA_CLIENT_ID)

@app.route('/token_expired')
def token_expired():
    """Show token expired page"""
    return render_template('token_expired.html')

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    try:
        prompt = request.form['prompt']
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": prompt}
        ]
        
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            temperature=0.7
        )
        
        chat_response = response.choices[0].message.content

        user_info = get_user_info(session.get('access_token'))
        return render_template('index.html',
                             user=user_info,
                             auth_info={
                                 'access_token': session.get('access_token'),
                                 'id_token': session.get('id_token', 'Not found'),
                                 'token_expiry': session.get('token_expiry', 'Not found'),
                                 'remaining_time': format_time_remaining(
                                     max(session.get('token_expiry', 0) - int(time.time()), 0)
                                 ),
                                 'redirect_uri': OKTA_REDIRECT_URI,
                                 'issuer': OKTA_ISSUER,
                                 'scope': 'openid profile email'
                             },
                             okta_domain=OKTA_DOMAIN,
                             client_id=OKTA_CLIENT_ID,
                             chat_response=chat_response,
                             last_prompt=prompt)
    except Exception as e:
        logger.error(f"Chat failed: {str(e)}")
        return f'Chat failed: {str(e)}', 400

@app.route('/login')
def login():
    code_verifier = secrets.token_urlsafe(43)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    state = secrets.token_hex(16)
    
    session['code_verifier'] = code_verifier
    session['oauth_state'] = state

    logger.info(f"Login - State: {state}, Code Verifier: {code_verifier}")

    params = {
        'client_id': OKTA_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid profile email',
        'redirect_uri': OKTA_REDIRECT_URI,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    auth_url = f'{OKTA_ISSUER}/v1/authorize?{urlencode(params)}'
    logger.info(f"Authorization URL: {auth_url}")
    return redirect(auth_url)

@app.route('/callback')
def callback():
    logger.info(f"Callback - Session Data: {dict(session)}")
    logger.info(f"Callback - Query Params: {dict(request.args)}")

    received_state = request.args.get('state')
    stored_state = session.get('oauth_state')

    if not stored_state or received_state != stored_state:
        logger.error(f"State mismatch: Stored={stored_state}, Received={received_state}")
        return redirect(url_for('login'))

    code = request.args.get('code')
    if not code:
        return redirect(url_for('login'))

    token_payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': OKTA_REDIRECT_URI,
        'client_id': OKTA_CLIENT_ID,
        'client_secret': OKTA_CLIENT_SECRET,
        'code_verifier': session.get('code_verifier')
    }

    try:
        token_response = requests.post(f'{OKTA_ISSUER}/v1/token', data=token_payload)
        token_response.raise_for_status()
        tokens = token_response.json()

        session['access_token'] = tokens['access_token']
        session['id_token'] = tokens.get('id_token', 'Not found')
        session['token_expiry'] = int(time.time()) + tokens['expires_in']

        logger.info("Authentication successful!")
        return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"Token exchange failed: {str(e)}")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Get user id_token for Okta logout
    id_token = session.get('id_token')
    # Clear Flask session
    session.clear()
    logger.info("User logged out.")
    
    # Construct Okta logout URL with redirect back to the application login
    params = {
        'id_token_hint': id_token,
        'post_logout_redirect_uri': url_for('login', _external=True),
        'state': secrets.token_hex(16)
    }
    
    # Use the authorization server endpoint for logout
    logout_url = f"https://{OKTA_DOMAIN}/oauth2/v1/logout?{urlencode(params)}"
    logger.info(f"Redirecting to Okta logout URL: {logout_url}")
    
    return redirect(logout_url)

@app.route('/token_status')
def token_status():
    """API endpoint to check token status"""
    current_time = int(time.time())
    expiry_time = session.get("token_expiry", 0)
    remaining_seconds = max(expiry_time - current_time, 0)
    
    return jsonify({
        'valid': not is_token_expired(),
        'remaining_time': remaining_seconds,
        'remaining_formatted': format_time_remaining(remaining_seconds)
    })

if __name__ == '__main__':
    logger.info("Starting Flask Okta Authentication Demo")
    app.run(debug=True, port=5000)
