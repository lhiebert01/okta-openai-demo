# 🔐 OKTA + OpenAI: Secure GenAI Web App Demo

A Flask application demonstrating OAuth 2.0 authentication with Okta, featuring PKCE (Proof Key for Code Exchange) for Secure Identity handling and flow, group management, user profile handling, and OpenAI ChatGPT integration for AI interactions.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![Okta](https://img.shields.io/badge/okta-2024+-orange.svg)](https://developer.okta.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI-API-green.svg)](https://openai.com)

## 🔑 Understanding Okta Authentication Flow

### What is Okta?
Okta is an Identity Provider (IdP) that manages user authentication and authorization. It implements OAuth 2.0 and OpenID Connect protocols to provide secure access to applications without handling passwords directly. This demo showcases integrating Okta's authentication services with a Python Flask application and securing AI interactions using OpenAI's ChatGPT.

### PKCE (Proof Key for Code Exchange)
PKCE is an extension to the OAuth 2.0 authorization framework that helps prevent certain types of attacks, such as code injection attacks, in authorization code grant flow. Here is a brief overview of the flow using PKCE:

    - The client application initiates the authentication request, including a code challenge and code challenge method in the request.
    - The authorization server validates the code challenge and code challenge method, and issues an authorization code to the client.
    - The client then exchanges the authorization code for an access token by providing the authorization code along with the original code verifier used to generate the code challenge.
    - The authorization server verifies the code verifier and exchanges it for an access token, allowing the client to access protected resources on behalf of the user.

### Authentication Flow
1. **Initial Request**
   - User attempts to access protected route
   - Application checks for valid session
   - Redirects to Okta login if no valid session exists

2. **PKCE Authentication**
   - Application generates code verifier and challenge
   - Redirects to Okta with challenge
   - Okta authenticates user credentials
   - Returns authorization code

3. **Token Exchange**
   - Application exchanges code for tokens using verifier
   - Receives access token, ID token, and refresh token
   - Establishes session with tokens

4. **Authorization**
   - Application uses access token for API requests
   - Retrieves user profile and group memberships
   - Enforces group-based access control

### OpenAI Integration
1. **ChatGPT Access**
   - Secure API key management
   - GPT-3.5-turbo model integration
   - Real-time response handling

2. **AI Features**
   - Interactive chat interface
   - Natural language processing
   - Context-aware responses
   - Secure access control

## ✨ Features

### Authentication & Security
- **OAuth 2.0 with PKCE Flow**
  - Secure authentication implementation
  - Token management (5-minute expiration)
  - CSRF protection
  
- **User Management**
  - Group membership display
  - Profile information
  - Session handling
  
- **Security Features**
  - HTTPOnly cookies
  - Secure session storage
  - API token protection

### AI Integration
- **OpenAI Features**
  - ChatGPT interaction
  - Real-time responses
  - Natural language interface
  - Secure API access

### Debug & Monitoring
- Token visualization
- Session tracking
- Group management display
- Debug information panel

## 🚀 Quick Start

1. Clone repository:
```bash
git clone [repository-url]
cd okta-flask-demo
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.template .env
```
Edit `.env`:
```
OKTA_DOMAIN=your-domain.okta.com
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
OKTA_REDIRECT_URI=http://localhost:5000/callback
OKTA_ISSUER=https://your-domain.okta.com/oauth2/default
OKTA_API_TOKEN=your-api-token
OPENAI_API_KEY=your-openai-api-key
SECRET_KEY=your-secret-key
```

4. Run application:
```bash
python app.py
```

## ⚙️ Configuration

### Okta Setup
1. Create Application
   - Okta Developer Console → Applications → Create App Integration
   - Select OIDC - OpenID Connect
   - Choose Web Application
   - Configure redirect URIs:
     - Sign-in: http://localhost:5000/callback
     - Sign-out: http://localhost:5000/login
   - Grant type: Authorization Code

2. API Token
   - Security → API → Tokens
   - Create Token
   - Save token securely
   - Add to .env file

3. Configure Groups
   - Directory → Groups
   - Create test groups
   - Assign users to groups

### OpenAI Setup
1. Create API Key
   - OpenAI dashboard → API keys
   - Generate new key
   - Add to .env file

2. Model Configuration
   - Default: gpt-3.5-turbo
   - Temperature: 0.7
   - Max tokens: configurable

## 🔒 Security Implementation

### PKCE Flow
- Code verifier generation
- SHA256 challenge creation
- State parameter validation

### Token Management
- 5-minute access token expiration
- Secure token storage
- Auto re-authentication

### Session Security
- HTTPOnly cookies
- Secure cookie option
- SameSite protection
- Session file storage

## 🚀 Deployment

### Production Settings
1. Enable HTTPS
2. Update .env configuration
3. Set secure cookie options
4. Configure production logging
5. Set API rate limits

### Platform Updates
1. Add production URLs
2. Update API token settings
3. Configure trusted origins
4. Set OpenAI API restrictions

## 🔧 Troubleshooting

### Common Issues
1. Token Expiration
   - Check debug information
   - Verify token validity
   - Clear session if needed

2. Group Access
   - Verify API token permissions
   - Check group assignments
   - Review API response logs

3. Session Issues
   - Clear browser cookies
   - Check session configuration
   - Verify HTTPS settings

4. AI Integration
   - Verify API key validity
   - Check rate limits
   - Monitor response times

## 📚 API Documentation

### Routes
- `/`: Main application page (protected)
- `/login`: Initiates OAuth flow
- `/callback`: OAuth callback handling
- `/logout`: Session termination
- `/chat`: OpenAI interaction endpoint

### Key Functions
- `login_required`: Authentication decorator
- `get_user_info`: Fetches user data and groups
- `before_request`: Request middleware
- `chat`: Handles AI interactions

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

Developed by [Lindsay Hiebert](https://www.linkedin.com/in/lindsayhiebert/)
- GitHub: [lhiebert01](https://github.com/lhiebert01)
- LinkedIn: [lindsayhiebert](https://www.linkedin.com/in/lindsayhiebert/)

## 🙏 Acknowledgments

- Okta for authentication services
- OpenAI for ChatGPT API
- Flask team for the web framework
- Python-jose for JWT handling

---