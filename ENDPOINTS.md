# Spring Authorization Server - API Endpoints Guide

## 🚀 Server Information
- **Base URL**: `http://localhost:8080`
- **Server Port**: 8080

## 🔐 OAuth2/OpenID Connect Endpoints

### Authorization Endpoint
```
GET /oauth2/authorize
```
**Purpose**: Initiates the OAuth2 authorization code flow
**Example URL**:
```
http://localhost:8080/oauth2/authorize?response_type=code&client_id=auth-client&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid profile read
```

### Token Endpoint
```
POST /oauth2/token
```
**Purpose**: Exchange authorization code for access token
**Content-Type**: `application/x-www-form-urlencoded`
**Body Parameters**:
```
grant_type=authorization_code
&code={authorization_code}
&client_id=auth-client
&client_secret=secret
&redirect_uri=http://127.0.0.1:8080/authorized
```

### OpenID Connect Discovery
```
GET /.well-known/openid-configuration
```
**Purpose**: Returns OpenID Connect configuration metadata

### JWKs Endpoint
```
GET /.well-known/jwks.json
```
**Purpose**: Returns JSON Web Key Set for token verification

### Token Introspection
```
POST /oauth2/introspect
```
**Purpose**: Validate and get information about tokens

### Token Revocation
```
POST /oauth2/revoke
```
**Purpose**: Revoke access or refresh tokens

## 🔑 Authentication Endpoints

### Login Page
```
GET /login
```
**Purpose**: Custom login page
**Test Credentials**:
- Username: `admin` | Password: `admin123`
- Username: `testuser` | Password: `test123`

### Login Form Submission
```
POST /login
```
**Purpose**: Process login credentials
**Form Data**: `username` and `password`

### Logout
```
POST /logout
```
**Purpose**: Log out the current user

## 🏠 Application Endpoints

### Home Page
```
GET /
```
**Purpose**: Application home page with endpoint links

### Profile Page
```
GET /profile
```
**Purpose**: User profile information (requires authentication)

### Authorization Success
```
GET /authorized
```
**Purpose**: OAuth2 callback endpoint after successful authorization

## 👥 User Management API (Secured)

### Get All Users
```
GET /api/users
```
**Authorization**: Admin role required
**Response**: List of all users

### Get User by ID
```
GET /api/users/{id}
```
**Authorization**: Admin or owner
**Response**: User details

### Create New User
```
POST /api/users
Content-Type: application/json

{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "password123"
}
```
**Authorization**: Admin role required

### Update User
```
PUT /api/users/{id}
Content-Type: application/json

{
  "username": "updateduser",
  "email": "updated@example.com",
  "isActive": true,
  "isMfaEnabled": true
}
```
**Authorization**: Admin or owner

### Delete User
```
DELETE /api/users/{id}
```
**Authorization**: Admin role required

### Block User
```
POST /api/users/{id}/block
```
**Authorization**: Admin role required

### Unblock User
```
POST /api/users/{id}/unblock
```
**Authorization**: Admin role required

### Change Password
```
POST /api/users/{id}/change-password
Content-Type: application/json

{
  "newPassword": "newpassword123"
}
```
**Authorization**: Admin or owner

## 🔧 Development & Monitoring Endpoints

### H2 Database Console
```
GET /h2-console
```
**Purpose**: Access H2 database console (development only)
**Credentials**:
- JDBC URL: `jdbc:h2:mem:authdb`
- Username: `sa`
- Password: `password`

### Health Check
```
GET /actuator/health
```
**Purpose**: Application health status

### Application Info
```
GET /actuator/info
```
**Purpose**: Application information

## 📋 OAuth2 Client Configuration

### Pre-configured Client
- **Client ID**: `auth-client`
- **Client Secret**: `secret`
- **Grant Types**: `authorization_code`, `refresh_token`
- **Scopes**: `openid`, `profile`, `read`, `write`
- **Redirect URIs**: 
  - `http://127.0.0.1:8080/authorized`
  - `http://127.0.0.1:8080/login/oauth2/code/auth-client`

## 🧪 Testing the Authorization Flow

### Step 1: Authorization Request
Navigate to:
```
http://localhost:8080/oauth2/authorize?response_type=code&client_id=auth-client&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid profile read
```

### Step 2: Login
- Use credentials: `admin` / `admin123`

### Step 3: Authorization Consent
- Grant permissions to the client

### Step 4: Get Authorization Code
- Code will be in the callback URL

### Step 5: Exchange for Token
```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'auth-client:secret' | base64)" \
  -d "grant_type=authorization_code&code={YOUR_CODE}&redirect_uri=http://127.0.0.1:8080/authorized"
```

## 🔒 Security Features Implemented

- ✅ Account lockout after 5 failed login attempts
- ✅ Password encryption using BCrypt
- ✅ JWT token-based authentication
- ✅ OpenID Connect support
- ✅ Token expiration (5 min access, 60 min refresh)
- ✅ CSRF protection
- ✅ Secure headers
- ✅ Multi-factor authentication ready (field in user entity)