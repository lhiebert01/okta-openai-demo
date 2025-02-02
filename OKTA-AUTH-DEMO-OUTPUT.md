# OKTA + OpenAI Demo Output Example

## Authentication Display

```
🌟 ⚡ 🔐 Welcome to the OKTA + OpenAI: Secure GenAI Web App Demo 🔑 🚀 💫

🔐 Authentication Status
Status: Successfully Authenticated! ✓

Okta Domain: dev-14162863.okta.com
Client ID: 0oan1mokxuIokN9Ih5d7

Token Information:
Access Token: eyJraWQiO...
ID Token: eyJraWQiO...
```

## OpenAI Integration
```
Ask ChatGPT anything...
[Chat Interface]
```

## User Profile Information
```json
{
  "Name": "JohnSmith-SampleUserName",
  "Email": "JohnSmith-SampleUserName@gmail.com",
  "Preferred Username": "lindsay.hiebert@gmail.com",
  
  "Group Memberships": [
    {
      "name": "Everyone",
      "type": "BUILT_IN"
    },
    {
      "name": "GenAITutor App Users",
      "type": "OKTA_GROUP"
    },
    {
      "name": "NewGENAIGroup",
      "type": "OKTA_GROUP"
    }
  ]
}
```

## Complete User Profile
```json
{
  "email": "JohnSmith-SampleUserName@gmail.com",
  "email_verified": true,
  "family_name": "Smith",
  "given_name": "John",
  "groups": [
    {
      "name": "Everyone",
      "type": "BUILT_IN"
    },
    {
      "name": "GenAITutor App Users",
      "type": "OKTA_GROUP"
    },
    {
      "name": "NewGENAIGroup",
      "type": "OKTA_GROUP"
    }
  ],
  "locale": "en_US",
  "name": "John Smith (Sample User)",
  "preferred_username": "JohnSmith-SampleUserName@gmail.com",
  "sub": "00umy9x8di2dde1EY5d7",
  "updated_at": 1738182666,
  "zoneinfo": "America/Los_Angeles"
}
```

## Debug Information
```json
{
  "_permanent": true,
  "access_token": "eyJraWQiO...[truncated]",
  "code_verifier": "jdHSkJErSyjooh6pvGJb1ZDJfCJDNQ3exfoZc0q9NAByuIPmmojnZfWvOg",
  "id_token": "eyJraWQiO...[truncated]",
  "oauth_state": "52740aaecb983e151f7d0a64a0d80ae0"
}

Page loaded at: 2/2/2025, 12:40:36 AM
```