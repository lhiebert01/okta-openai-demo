# Okta Authentication Analysis & Documentation

## 1. Authentication Components Overview

### Access Token Anatomy
```json
{
  "kid": "3lsb_1rgHEXUKzFFMH_-oOR4dNiR_zgIE2jhKcA6C7U",  // Key ID for validation
  "alg": "RS256",                                         // Signing algorithm
  "ver": 1,                                              // Token version
  "jti": "AT.poP...",                                    // Unique token identifier
  "iss": "https://dev-14162863.okta.com/oauth2/...",    // Token issuer
  "aud": "FlaskOKTA",                                    // Intended audience
  "iat": 1738353944,                                     // Issued at timestamp
  "exp": 1738397144,                                     // Expiration time
  "cid": "0oan1mokxuIokN9Ih5d7",                        // Client ID
  "uid": "00umw40wtgFCXJnQ45d7",                        // User ID
  "scp": ["profile", "email", "openid"],                 // Granted scopes
  "auth_time": 1738353943                                // Authentication time
}
```

### ID Token Structure
```json
{
  "sub": "00umw40wtgFCXJnQ45d7",                        // Subject identifier
  "name": "JohnSmith-SampleUserName",                   // User's full name
  "email": "JohnSmith-SampleUserName@gmail.com",        // Email address
  "ver": 1,                                             // Token version
  "amr": ["mfa", "otp", "pwd"],                        // Authentication methods
  "preferred_username": "JohnSmith-SampleUserName@...",         // Login identifier
  "auth_time": 1738353943                               // Auth timestamp
}
```

### Group Types & Meanings
1. **BUILT_IN Groups**
   - Everyone: Default system group
   - Purpose: Basic access control
   
2. **OKTA_GROUP Types**
   - GenAITutor App Users: Application-specific group
   - NewGENAIGroup: Custom application group
   - Purpose: Application access control

## 2. Original Authentication Output

```plaintext
[Original screen output as shown above]
```

## 3. Detailed Component Analysis

### Authentication Headers
- **Domain (dev-14162863.okta.com)**
  - Organization identifier
  - Used for API endpoints
  - Environment indicator (dev)

- **Client ID (0oan1mokxuIokN9Ih5d7)**
  - Application identifier
  - OAuth 2.0 client credentials
  - Used in token requests

### Token Details

#### Access Token
Purpose: API Authorization
- Lifetime: 5 minutes
- Scope: ["profile", "email", "openid"]
- Usage: Bearer token for API calls
- Format: JWT (3 parts)
  1. Header (algorithm, key ID)
  2. Payload (claims)
  3. Signature (verification)

#### ID Token
Purpose: User Identity
- Contains user profile information
- OpenID Connect standard
- Authentication proof
- Multi-factor authentication details ["mfa", "otp", "pwd"]

### Session Information
```json
{
  "_permanent": true,
  "access_token": "eyJraWQiO...",
  "code_verifier": "eUIrVmyJ...",      // PKCE verifier
  "id_token": "eyJraWQiO...",
  "oauth_state": "7cb745bf..."         // CSRF token
}
```

### User Profile Attributes
1. **Core Attributes**
   - email_verified: Email validation status
   - locale: Language/region (en_US)
   - zoneinfo: Timezone (America/Los_Angeles)
   - updated_at: Profile update timestamp

2. **Group Memberships**
   - System Groups: Everyone (BUILT_IN)
   - Application Groups: 
     - GenAITutor App Users (OKTA_GROUP)
     - NewGENAIGroup (OKTA_GROUP)

## 4. Security Components

### Authentication Methods (AMR)
- **MFA**: Multi-factor authentication enabled
- **OTP**: One-time password used
- **PWD**: Password authentication

### Token Security
1. **PKCE Flow**
   - code_verifier: Challenge verifier
   - oauth_state: CSRF protection

2. **JWT Validation**
   - RS256 signatures
   - Expiration checking
   - Audience validation

### Session Management
- HTTPOnly cookies
- Permanent session flag
- State management
- Token refresh handling

## 5. Integration Points

### API Endpoints
1. **Authorization Server**
   - /oauth2/ausn1mvtp8e6ob1VV5d7

2. **User Management**
   - /api/v1/users
   - /api/v1/groups

### Scopes & Permissions
1. **OpenID Connect**
   - openid
   - profile
   - email

2. **Custom Scopes**
   - Groups access
   - User management

---
