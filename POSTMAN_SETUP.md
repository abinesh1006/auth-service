# Postman Setup for Spring Authorization Server

## 📋 Postman Collection Configuration

### Collection Overview
This Postman collection allows you to test the complete OAuth2 Authorization Code Flow with JWT token generation.

## 🔧 Environment Variables Setup

Create a new environment in Postman with these variables:

```json
{
  "auth_server_url": "http://localhost:8080",
  "client_id": "auth-client",
  "client_secret": "secret",
  "redirect_uri": "http://127.0.0.1:8080/authorized",
  "scope": "openid profile read write",
  "authorization_code": "",
  "access_token": "",
  "refresh_token": "",
  "id_token": ""
}
```

## 📂 Postman Collection Structure

### Folder 1: OAuth2 Authorization Flow

#### 1.1 Get Authorization Code (Manual)
- **Method**: GET
- **URL**: `{{auth_server_url}}/oauth2/authorize`
- **Params**:
  - `response_type`: code
  - `client_id`: {{client_id}}
  - `redirect_uri`: {{redirect_uri}}
  - `scope`: {{scope}}
  - `state`: test-state
- **Note**: Copy this URL and open in browser, then extract code from callback URL

#### 1.2 Exchange Code for JWT Tokens
- **Method**: POST
- **URL**: `{{auth_server_url}}/oauth2/token`
- **Headers**:
  - `Content-Type`: application/x-www-form-urlencoded
  - `Authorization`: Basic {{client_credentials_base64}}
- **Body** (x-www-form-urlencoded):
  - `grant_type`: authorization_code
  - `code`: {{authorization_code}}
  - `redirect_uri`: {{redirect_uri}}
- **Tests Script**:
```javascript
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.environment.set("access_token", response.access_token);
    pm.environment.set("refresh_token", response.refresh_token);
    pm.environment.set("id_token", response.id_token);
    console.log("Tokens saved to environment variables");
}
```

#### 1.3 Refresh Token
- **Method**: POST
- **URL**: `{{auth_server_url}}/oauth2/token`
- **Headers**:
  - `Content-Type`: application/x-www-form-urlencoded
  - `Authorization`: Basic {{client_credentials_base64}}
- **Body** (x-www-form-urlencoded):
  - `grant_type`: refresh_token
  - `refresh_token`: {{refresh_token}}

### Folder 2: Token Management

#### 2.1 Validate JWT Token
- **Method**: GET
- **URL**: `{{auth_server_url}}/api/token/validate`
- **Headers**:
  - `Authorization`: Bearer {{access_token}}

#### 2.2 Get JWT Token Info
- **Method**: GET
- **URL**: `{{auth_server_url}}/api/token/info`
- **Headers**:
  - `Authorization`: Bearer {{access_token}}

#### 2.3 Introspect Token
- **Method**: POST
- **URL**: `{{auth_server_url}}/oauth2/introspect`
- **Headers**:
  - `Content-Type`: application/x-www-form-urlencoded
  - `Authorization`: Basic {{client_credentials_base64}}
- **Body** (x-www-form-urlencoded):
  - `token`: {{access_token}}

#### 2.4 Revoke Token
- **Method**: POST
- **URL**: `{{auth_server_url}}/oauth2/revoke`
- **Headers**:
  - `Content-Type`: application/x-www-form-urlencoded
  - `Authorization`: Basic {{client_credentials_base64}}
- **Body** (x-www-form-urlencoded):
  - `token`: {{access_token}}

### Folder 3: User Management API (Protected)

#### 3.1 Get All Users
- **Method**: GET
- **URL**: `{{auth_server_url}}/api/users`
- **Headers**:
  - `Authorization`: Bearer {{access_token}}

#### 3.2 Create User
- **Method**: POST
- **URL**: `{{auth_server_url}}/api/users`
- **Headers**:
  - `Content-Type`: application/json
  - `Authorization`: Bearer {{access_token}}
- **Body** (JSON):
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "password123"
}
```

#### 3.3 Get User by ID
- **Method**: GET
- **URL**: `{{auth_server_url}}/api/users/{{user_id}}`
- **Headers**:
  - `Authorization`: Bearer {{access_token}}

#### 3.4 Update User
- **Method**: PUT
- **URL**: `{{auth_server_url}}/api/users/{{user_id}}`
- **Headers**:
  - `Content-Type`: application/json
  - `Authorization`: Bearer {{access_token}}
- **Body** (JSON):
```json
{
  "username": "updateduser",
  "email": "updated@example.com",
  "isActive": true,
  "isMfaEnabled": true
}
```

#### 3.5 Change Password
- **Method**: POST
- **URL**: `{{auth_server_url}}/api/users/{{user_id}}/change-password`
- **Headers**:
  - `Content-Type`: application/json
  - `Authorization`: Bearer {{access_token}}
- **Body** (JSON):
```json
{
  "newPassword": "newpassword123"
}
```

#### 3.6 Block User
- **Method**: POST
- **URL**: `{{auth_server_url}}/api/users/{{user_id}}/block`
- **Headers**:
  - `Authorization`: Bearer {{access_token}}

#### 3.7 Unblock User
- **Method**: POST
- **URL**: `{{auth_server_url}}/api/users/{{user_id}}/unblock`
- **Headers**:
  - `Authorization`: Bearer {{access_token}}

### Folder 4: OpenID Connect & Discovery

#### 4.1 OpenID Configuration
- **Method**: GET
- **URL**: `{{auth_server_url}}/.well-known/openid-configuration`

#### 4.2 JWKS (JSON Web Key Set)
- **Method**: GET
- **URL**: `{{auth_server_url}}/.well-known/jwks.json`

### Folder 5: Application Endpoints

#### 5.1 Home Page
- **Method**: GET
- **URL**: `{{auth_server_url}}/`

#### 5.2 User Profile
- **Method**: GET
- **URL**: `{{auth_server_url}}/profile`
- **Headers**:
  - `Authorization`: Bearer {{access_token}}

#### 5.3 Health Check
- **Method**: GET
- **URL**: `{{auth_server_url}}/actuator/health`

## 🔑 Pre-request Scripts

### Collection-level Pre-request Script:
```javascript
// Generate Base64 encoded client credentials
const clientId = pm.environment.get("client_id");
const clientSecret = pm.environment.get("client_secret");
const credentials = btoa(clientId + ":" + clientSecret);
pm.environment.set("client_credentials_base64", credentials);
```

## 🧪 Testing Workflow

### Step 1: Setup Environment
1. Create a new environment in Postman
2. Add all the environment variables listed above
3. Set `auth_server_url` to `http://localhost:8080`

### Step 2: Start Authorization Flow
1. Run "Get Authorization Code (Manual)" request
2. Copy the URL from the request and open it in your browser
3. Login with `admin` / `admin123`
4. Grant consent
5. Copy the authorization code from the callback URL
6. Set the `authorization_code` environment variable

### Step 3: Get JWT Tokens
1. Run "Exchange Code for JWT Tokens" request
2. The response will automatically save tokens to environment variables

### Step 4: Test Protected Endpoints
1. Use any of the User Management API requests
2. The JWT token will be automatically included in the Authorization header

## 🔄 Auto-refresh Setup

Add this to the Tests tab of requests that might fail due to expired tokens:

```javascript
if (pm.response.code === 401) {
    console.log("Token expired, attempting refresh...");
    
    const refreshToken = pm.environment.get("refresh_token");
    if (refreshToken) {
        pm.sendRequest({
            url: pm.environment.get("auth_server_url") + "/oauth2/token",
            method: "POST",
            header: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Basic " + pm.environment.get("client_credentials_base64")
            },
            body: {
                mode: "urlencoded",
                urlencoded: [
                    {key: "grant_type", value: "refresh_token"},
                    {key: "refresh_token", value: refreshToken}
                ]
            }
        }, function(err, response) {
            if (response.code === 200) {
                const tokens = response.json();
                pm.environment.set("access_token", tokens.access_token);
                console.log("Token refreshed successfully");
            }
        });
    }
}
```

## 📁 Import Instructions

1. Copy the collection JSON from the next file
2. Open Postman
3. Click Import > Raw Text
4. Paste the JSON
5. Create environment with the variables above
6. Start testing!

This setup provides complete testing coverage for your Spring Authorization Server with JWT token generation!