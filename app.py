import os
from flask import Flask, render_template, redirect, request, session, url_for
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

# Load environment variables
load_dotenv(override=True)

# Configure logging
logging.basicConfig(
   level=logging.INFO,
   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.secret_key = os.getenv("SECRET_KEY", "your-strong-secret-key")
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_FILE_DIR'] = './flask_sessions'
app.config['SESSION_COOKIE_SECURE'] = False  # Set True in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

Session(app)

# Okta Settings
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "dev-14162863.okta.com")
OKTA_CLIENT_ID = os.getenv("OKTA_CLIENT_ID", "0oan1mokxuIokN9Ih5d7")
OKTA_CLIENT_SECRET = os.getenv("OKTA_CLIENT_SECRET")
OKTA_REDIRECT_URI = os.getenv("OKTA_REDIRECT_URI", "http://localhost:5000/callback")
OKTA_ISSUER = os.getenv("OKTA_ISSUER", "https://dev-14162863.okta.com/oauth2/ausn1mvtp8e6ob1VV5d7")

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai.api_key = OPENAI_API_KEY 

if not OKTA_CLIENT_SECRET:
   logger.error("OKTA_CLIENT_SECRET must be set in .env file!")
   raise ValueError("Missing OKTA_CLIENT_SECRET")

if not OPENAI_API_KEY:
   logger.error("OPENAI_API_KEY must be set in .env file!")
   raise ValueError("Missing OPENAI_API_KEY")

@app.before_request
def before_request():
   session.permanent = True
   logger.info(f"Request URL: {request.url}")
   logger.info(f"Session Data: {dict(session)}")

def login_required(f):
   @wraps(f)
   def decorated_function(*args, **kwargs):
       if 'access_token' not in session:
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

       api_token = os.getenv('OKTA_API_TOKEN')
       if not api_token:
           logger.error("OKTA_API_TOKEN not set in .env")
           return user_info

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
   user_info = get_user_info(session['access_token'])
   if not user_info:
       session.clear()
       return redirect(url_for('login'))

   return render_template('index.html',
                        user=user_info,
                        auth_info={'access_token': session.get('access_token'),
                                 'id_token': session.get('id_token', 'Not found')},
                        okta_domain=OKTA_DOMAIN,
                        client_id=OKTA_CLIENT_ID)

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

       user_info = get_user_info(session['access_token'])
       return render_template('index.html',
                            user=user_info,
                            auth_info={'access_token': session['access_token'],
                                     'id_token': session.get('id_token', 'Not found')},
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

   return redirect(f'{OKTA_ISSUER}/v1/authorize?{urlencode(params)}')

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
       'code_verifier': session['code_verifier']
   }

   try:
       token_response = requests.post(f'{OKTA_ISSUER}/v1/token', data=token_payload)
       token_response.raise_for_status()
       tokens = token_response.json()

       session['access_token'] = tokens['access_token']
       session['id_token'] = tokens.get('id_token', 'Not found')

       logger.info("Authentication successful!")
       return redirect(url_for('index'))

   except Exception as e:
       logger.error(f"Token exchange failed: {str(e)}")
       return redirect(url_for('login'))

@app.route('/logout')
def logout():
   session.clear()
   logger.info("User logged out.")
   return redirect(url_for('login'))

if __name__ == '__main__':
   logger.info("Starting Flask Okta Authentication Demo")
   app.run(debug=True, port=5000)