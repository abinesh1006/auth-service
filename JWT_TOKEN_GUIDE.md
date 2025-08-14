# JWT Token Generation - OAuth2 Authorization Code Flow Guide

## 🎯 Complete JWT Token Generation Process

Your Spring Authorization Server automatically generates JWT tokens through the OAuth2 authorization code flow. Here's the complete process:

## 📋 Step-by-Step JWT Token Generation

### Step 1: Authorization Request
Navigate to the authorization endpoint to start the flow:

```
GET http://localhost:8080/oauth2/authorize?response_type=code&client_id=auth-client&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid%20profile%20read%20write
```

**Parameters:**
- `response_type=code` - Request authorization code
- `client_id=auth-client` - Your OAuth2 client ID
- `redirect_uri=http://127.0.0.1:8080/authorized` - Callback URL
- `scope=openid profile read write` - Requested permissions

### Step 2: User Authentication
- User will be redirected to login page
- Login with: `admin` / `admin123` or `testuser` / `test123`
- Grant consent to the application

### Step 3: Authorization Code Received
After successful login and consent, you'll receive an authorization code in the callback URL:
```
http://127.0.0.1:8080/authorized?code=AUTHORIZATION_CODE_HERE&state=STATE_VALUE
```

### Step 4: Exchange Code for JWT Tokens
Make a POST request to the token endpoint:

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'auth-client:secret' | base64)" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTHORIZATION_CODE" \
  -d "redirect_uri=http://127.0.0.1:8080/authorized"
```

## 🔑 JWT Token Response Format

The token endpoint returns JWT tokens in the following format:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1In0...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1In0...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1In0...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid profile read write"
}
```

## 🔍 JWT Token Structure

### Access Token Claims:
```json
{
  "iss": "http://localhost:8080",
  "sub": "admin",
  "aud": ["auth-client"],
  "exp": 1723629025,
  "iat": 1723628725,
  "scope": ["read", "write"],
  "client_id": "auth-client"
}
```

### ID Token Claims (OpenID Connect):
```json
{
  "iss": "http://localhost:8080",
  "sub": "admin",
  "aud": "auth-client",
  "exp": 1723629025,
  "iat": 1723628725,
  "email": "admin@example.com",
  "email_verified": true,
  "preferred_username": "admin"
}
```

## 🧪 Testing Tools & Examples

### 1. Browser-Based Flow Test
Open this URL in your browser:
```
http://localhost:8080/oauth2/authorize?response_type=code&client_id=auth-client&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid%20profile%20read%20write
```

### 2. cURL Command Examples

#### Get Authorization Code (Manual):
1. Open authorization URL in browser
2. Login and consent
3. Copy code from callback URL

#### Exchange Code for JWT Tokens:
```bash
# Replace YOUR_AUTHORIZATION_CODE with actual code
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic YXV0aC1jbGllbnQ6c2VjcmV0" \
  -d "grant_type=authorization_code&code=YOUR_AUTHORIZATION_CODE&redirect_uri=http://127.0.0.1:8080/authorized"
```

### 3. Postman Collection Settings

#### Authorization Request:
- **Method**: GET
- **URL**: `http://localhost:8080/oauth2/authorize`
- **Params**: 
  - `response_type`: code
  - `client_id`: auth-client
  - `redirect_uri`: http://127.0.0.1:8080/authorized
  - `scope`: openid profile read write

#### Token Exchange:
- **Method**: POST
- **URL**: `http://localhost:8080/oauth2/token`
- **Headers**: 
  - `Content-Type`: application/x-www-form-urlencoded
  - `Authorization`: Basic YXV0aC1jbGllbnQ6c2VjcmV0
- **Body**: 
  - `grant_type`: authorization_code
  - `code`: {your_authorization_code}
  - `redirect_uri`: http://127.0.0.1:8080/authorized

## 🔒 JWT Token Validation

### Validate JWT Token:
```bash
# Use the access token to call protected endpoints
curl -H "Authorization: Bearer YOUR_JWT_ACCESS_TOKEN" \
  http://localhost:8080/api/users
```

### Introspect Token:
```bash
curl -X POST http://localhost:8080/oauth2/introspect \
  -H "Authorization: Basic YXV0aC1jbGllbnQ6c2VjcmV0" \
  -d "token=YOUR_JWT_ACCESS_TOKEN"
```

## 🔄 Refresh Token Flow

Use refresh token to get new JWT access token:
```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic YXV0aC1jbGllbnQ6c2VjcmV0" \
  -d "grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN"
```

## 🛠️ JWT Token Configuration

Your authorization server is configured with:
- **Algorithm**: RS256 (RSA with SHA-256)
- **Access Token TTL**: 5 minutes
- **Refresh Token TTL**: 60 minutes
- **Issuer**: http://localhost:8080
- **Key Rotation**: Automatic on restart

## 📊 Token Endpoints Summary

| Endpoint | Purpose | Method |
|----------|---------|---------|
| `/oauth2/authorize` | Get authorization code | GET |
| `/oauth2/token` | Exchange code for JWT tokens | POST |
| `/oauth2/introspect` | Validate token | POST |
| `/oauth2/revoke` | Revoke token | POST |
| `/.well-known/jwks.json` | Get JWT signing keys | GET |

Your Spring Authorization Server is fully configured to generate secure JWT tokens with all the features from your user entity integrated!