# 🔐 COMPLETE PERMISSION SYSTEM ANALYSIS & API DOCUMENTATION

## 📋 TABLE OF CONTENTS
1. [System Overview](#system-overview)
2. [Authentication Flow](#authentication-flow)
3. [Authorization System](#authorization-system)
4. [API Endpoints Documentation](#api-endpoints-documentation)
5. [Request/Response Structures](#request-response-structures)
6. [Permission Flow Analysis](#permission-flow-analysis)
7. [Error Handling](#error-handling)
8. [Best Practices](#best-practices)

---

## 🏗️ SYSTEM OVERVIEW

### Architecture Pattern
- **Pattern**: Domain-Driven Design with Repository Pattern
- **Validation**: Zod schemas with nestjs-zod integration
- **Caching**: Redis for permission caching
- **Database**: PostgreSQL with Prisma ORM
- **Authentication**: JWT with dual-token system (access + refresh)
- **Authorization**: RBAC + Condition-based permissions

### Core Components
```
src/routes/
├── auth/           # Authentication & verification flows
├── permission/     # Permission management CRUD
├── role/          # Role management CRUD  
├── user/          # User management CRUD
├── profile/       # User profile management
└── sessions/      # Session & device management
```

---

## 🔐 AUTHENTICATION FLOW

### 1. Registration Flow
```
POST /auth/initiate-registration → SLT Cookie + OTP
POST /auth/otp/verify → User Created + Tokens
```

**Request Bodies:**
```typescript
// POST /auth/initiate-registration
{
  "email": "user@example.com"
}

// POST /auth/otp/verify
{
  "code": "123456"
}
```

### 2. Login Flow
```
POST /auth/login → SLT Cookie + OTP/2FA (if required)
POST /auth/otp/verify OR POST /auth/2fa/verify → Tokens
```

**Request Bodies:**
```typescript
// POST /auth/login
{
  "emailOrUsername": "user@example.com",
  "password": "password123",
  "rememberMe": false
}

// OTP Verification
{
  "code": "123456"
}

// 2FA Verification
{
  "code": "123456",
  "method": "AUTHENTICATOR_APP" | "RECOVERY_CODE"
}
```

### 3. Token Management
```typescript
// POST /auth/refresh-token
// Uses httpOnly refresh token cookie - no body needed
{}

// POST /auth/logout
// No body needed
{}
```

---

## 🛡️ AUTHORIZATION SYSTEM

### Permission Structure
```typescript
interface Permission {
  id: number
  action: string        // "create", "read", "update", "delete"
  subject: string       // "User", "Role", "Permission", "Profile"
  description?: string  // Human-readable description
  category?: string     // Grouping category
  conditions?: object   // JSON conditions for dynamic permissions
  uiMetadata?: object   // UI-specific metadata
}
```

### Permission Format
```
{subject}:{action}[:{condition}]

Examples:
- "User:create"
- "User:read"
- "User:update:own"
- "User:delete"
- "Permission:read"
- "Role:create"
- "Profile:update:own"
- "2FA:setup:own"
```

### Role-Based Access Control
```typescript
interface Role {
  id: number
  name: string
  description?: string
  isSystemRole: boolean
  isSuperAdmin: boolean
  permissions: Permission[]
}
```

---

## 📡 API ENDPOINTS DOCUMENTATION

### 🔐 Authentication Endpoints

#### Registration
| Method | Endpoint | Request Body | Response | Description |
|--------|----------|--------------|----------|-------------|
| `POST` | `/auth/initiate-registration` | `{email}` | SLT Token + Message | Start registration |
| `POST` | `/auth/complete-registration` | User details | User + Tokens | Complete registration |

#### Login & Verification
| Method | Endpoint | Request Body | Response | Description |
|--------|----------|--------------|----------|-------------|
| `POST` | `/auth/login` | `{emailOrUsername, password, rememberMe?}` | SLT Token / Tokens | Login user |
| `POST` | `/auth/otp/send` | `{email, purpose, deviceId?, metadata?}` | SLT Token | Send OTP |
| `POST` | `/auth/otp/verify` | `{code}` | User + Tokens | Verify OTP |
| `POST` | `/auth/otp/resend` | - | SLT Token | Resend OTP |

#### Two-Factor Authentication
| Method | Endpoint | Request Body | Response | Description |
|--------|----------|--------------|----------|-------------|
| `POST` | `/auth/2fa/setup` | - | `{secret, uri}` | Setup 2FA |
| `POST` | `/auth/2fa/confirm-setup` | `{code, method?}` | `{recoveryCodes}` | Confirm 2FA setup |
| `POST` | `/auth/2fa/verify` | `{code, method?}` | User + Tokens | Verify 2FA |
| `POST` | `/auth/2fa/disable` | `{code, method}` | Message | Disable 2FA |
| `POST` | `/auth/2fa/regenerate-recovery-codes` | `{code, method}` | `{recoveryCodes}` | Regenerate codes |

#### Password Management
| Method | Endpoint | Request Body | Response | Description |
|--------|----------|--------------|----------|-------------|
| `POST` | `/auth/password/change` | `{currentPassword, newPassword, revokeOtherSessions?}` | Message | Change password |
| `POST` | `/auth/password/initiate-reset` | `{email}` | SLT Token | Start password reset |
| `POST` | `/auth/password/set-new` | `{newPassword, confirmPassword, revokeAllSessions?}` | Message | Set new password |

#### Social Authentication
| Method | Endpoint | Request Body | Query Params | Response | Description |
|--------|----------|--------------|--------------|----------|-------------|
| `GET` | `/auth/social/google` | - | `{action, redirectUrl?}` | `{url}` | Get Google auth URL |
| `GET` | `/auth/social/google/callback` | - | `{code, state, error?}` | User + Tokens / Link Required | Google callback |
| `POST` | `/auth/social/complete-link` | `{password?}` | - | User + Tokens | Complete social linking |
| `POST` | `/auth/social/unlink/google` | - | - | SLT Token | Unlink Google account |

#### Token Management
| Method | Endpoint | Request Body | Response | Description |
|--------|----------|--------------|----------|-------------|
| `POST` | `/auth/refresh-token` | - | New Tokens | Refresh access token |
| `POST` | `/auth/logout` | - | Message | Logout user |
| `GET` | `/auth/ui-capabilities` | - | UI Capabilities | Get user capabilities |

---

### 👥 Session Management

| Method | Endpoint | Request Body | Query Params | Response | Description |
|--------|----------|--------------|--------------|----------|-------------|
| `GET` | `/sessions` | - | `{page?, limit?}` | Grouped Sessions | Get user sessions |
| `POST` | `/sessions/revoke` | `{sessionIds?, deviceIds?, excludeCurrentSession?}` | - | Revoke Result | Revoke sessions |
| `POST` | `/sessions/revoke-all` | `{excludeCurrentSession?}` | - | SLT Token | Revoke all sessions |
| `PATCH` | `/sessions/devices/:deviceId/name` | `{name}` | - | Message | Update device name |
| `POST` | `/sessions/devices/trust-current` | - | - | Message | Trust current device |
| `DELETE` | `/sessions/devices/:deviceId/untrust` | - | - | Message | Untrust device |

---

### 🔑 Permission Management

| Method | Endpoint | Request Body | Query Params | Response | Description |
|--------|----------|--------------|--------------|----------|-------------|
| `GET` | `/permissions` | - | `{page?, limit?}` | Grouped Permissions | Get all permissions |
| `POST` | `/permissions` | `{action, subject, description?, category?, conditions?}` | - | Permission | Create permission |
| `GET` | `/permissions/:id` | - | - | Permission | Get permission by ID |
| `PATCH` | `/permissions/:id` | Partial permission data | - | Permission | Update permission |
| `DELETE` | `/permissions/:id` | - | - | - | Delete permission |

**Permission Request Body:**
```typescript
{
  "action": "create",
  "subject": "User", 
  "description": "Create new users",
  "category": "User Management",
  "conditions": {
    "departmentId": "${user.departmentId}"
  }
}
```

---

### 👑 Role Management

| Method | Endpoint | Request Body | Response | Description |
|--------|----------|--------------|----------|-------------|
| `GET` | `/roles` | - | Roles Array | Get all roles |
| `POST` | `/roles` | `{name, description?, permissionIds?}` | Role | Create role |
| `GET` | `/roles/:id` | - | Role | Get role by ID |
| `PATCH` | `/roles/:id` | Partial role data | Role | Update role |
| `DELETE` | `/roles/:id` | - | Message | Delete role |

**Role Request Body:**
```typescript
{
  "name": "Content Manager",
  "description": "Manages content and posts",
  "permissionIds": [1, 2, 3, 4]
}
```

---

### 👤 User Management

| Method | Endpoint | Request Body | Response | Description |
|--------|----------|--------------|----------|-------------|
| `GET` | `/users` | - | Users Array | Get all users |
| `POST` | `/users` | User creation data | SLT Token | Create user (OTP flow) |
| `GET` | `/users/:id` | - | User | Get user by ID |
| `PATCH` | `/users/:id` | Partial user data | User | Update user |
| `DELETE` | `/users/:id` | - | - | Delete user |

**User Creation Request Body:**
```typescript
{
  "email": "newuser@example.com",
  "password": "password123",
  "roleId": 2,
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe",
  "phoneNumber": "+84901234567",
  "bio": "Software developer",
  "countryCode": "VN"
}
```

---

### 👤 Profile Management

| Method | Endpoint | Request Body | Response | Description |
|--------|----------|--------------|----------|-------------|
| `GET` | `/profile` | - | Profile | Get current user profile |
| `PATCH` | `/profile` | `{firstName?, lastName?, username?, phoneNumber?}` | Profile | Update profile |

---

## 📊 REQUEST/RESPONSE STRUCTURES

### Standard Response Format
```typescript
// Success Response
{
  "success": true,
  "statusCode": 200,
  "message": "Operation completed successfully",
  "data": {...} // Optional, varies by endpoint
}

// Paginated Response  
{
  "success": true,
  "statusCode": 200,
  "message": "Data retrieved successfully",
  "data": [...],
  "metadata": {
    "totalItems": 100,
    "page": 1,
    "limit": 10,
    "totalPages": 10
  }
}

// Error Response
{
  "success": false,
  "statusCode": 400,
  "error": "VALIDATION_ERROR",
  "message": "Invalid input data",
  "details": [
    {
      "code": "VALIDATION_ERROR", 
      "path": "email"
    }
  ]
}
```

### Authentication Response Formats

#### Login Success
```typescript
{
  "success": true,
  "statusCode": 200,
  "message": "auth.success.login",
  "data": {
    "user": {
      "id": 1,
      "username": "johndoe",
      "avatar": "https://...",
      "isDeviceTrustedInSession": true
    }
  }
  // Tokens set in httpOnly cookies
}
```

#### Verification Needed
```typescript
{
  "success": true,
  "statusCode": 200,
  "message": "auth.verification.required",
  "verificationType": "OTP" | "2FA"
  // SLT token set in httpOnly cookie
}
```

#### 2FA Setup Response
```typescript
{
  "success": true,
  "statusCode": 200,
  "message": "2FA setup initiated",
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "uri": "otpauth://totp/ShopSifu:user@example.com?secret=..."
  }
}
```

### Session Response Format
```typescript
{
  "success": true,
  "statusCode": 200,
  "message": "Sessions retrieved successfully",
  "data": {
    "devices": [
      {
        "deviceId": 1,
        "deviceName": "MacBook Pro",
        "deviceType": "Desktop",
        "os": "macOS",
        "osVersion": "14.0",
        "browser": "Chrome",
        "browserVersion": "118.0",
        "isDeviceTrusted": true,
        "deviceTrustExpiration": "2024-01-15T00:00:00Z",
        "lastActive": "2024-01-01T12:00:00Z",
        "location": "Hanoi, Vietnam",
        "activeSessionsCount": 2,
        "isCurrentDevice": true,
        "sessions": [
          {
            "id": "session-uuid",
            "createdAt": "2024-01-01T10:00:00Z",
            "lastActive": "2024-01-01T12:00:00Z",
            "ipAddress": "192.168.1.1",
            "location": "Hanoi, Vietnam",
            "browser": "Chrome",
            "browserVersion": "118.0",
            "os": "macOS",
            "osVersion": "14.0",
            "deviceType": "Desktop",
            "app": "ShopSifu Web",
            "isActive": true,
            "inactiveDuration": null,
            "isCurrentSession": true
          }
        ]
      }
    ],
    "meta": {
      "currentPage": 1,
      "itemsPerPage": 5,
      "totalItems": 1,
      "totalPages": 1
    }
  }
}
```

### Permission Response Format
```typescript
{
  "success": true,
  "statusCode": 200,
  "message": "Permissions retrieved successfully",
  "data": {
    "groups": [
      {
        "subject": "User",
        "displayName": "USERS",
        "permissionsCount": 4,
        "permissions": [
          {
            "id": 1,
            "action": "create",
            "httpMethod": "POST",
            "endpoint": "/api/v1/users"
          },
          {
            "id": 2,
            "action": "read",
            "httpMethod": "GET", 
            "endpoint": "/api/v1/users"
          }
        ]
      }
    ],
    "meta": {
      "currentPage": 1,
      "totalPages": 3,
      "totalGroups": 8
    }
  }
}
```

---

## 🔄 PERMISSION FLOW ANALYSIS

### 1. Permission Guard Flow
```
Request → @Auth() → JwtAuthGuard → @UseGuards(PermissionGuard) → @RequirePermissions(['User:create'])

PermissionGuard Process:
1. Extract required permissions from decorator
2. Get user's role from JWT payload
3. Check Redis cache for role permissions
4. If cache miss, query database
5. Evaluate permissions against requirements
6. Check conditions if any (e.g., :own suffix)
7. Allow/Deny request
```

### 2. Permission Conditions
```typescript
// Static permissions
"User:read"           // Can read any user
"User:create"         // Can create users

// Conditional permissions  
"User:update:own"     // Can only update own user
"Profile:read:own"    // Can only read own profile

// Dynamic conditions (stored in conditions field)
{
  "departmentId": "${user.departmentId}",
  "status": "ACTIVE"
}
```

### 3. Auto-Generated API Endpoints
The system automatically generates API endpoints from permissions:

```typescript
// Permission: "User:create" → POST /api/v1/users
// Permission: "User:read" → GET /api/v1/users  
// Permission: "User:update" → PATCH /api/v1/users/:id
// Permission: "User:delete" → DELETE /api/v1/users/:id

// Subject pluralization rules:
User → users
Role → roles  
Permission → permissions
Category → categories
```

### 4. Permission Caching Strategy
```typescript
// Redis Cache Structure
"permissions:role:{roleId}" → Permission[]
"permissions:user:{userId}" → Permission[] // For user-specific overrides

// Cache TTL: 1 hour
// Cache invalidation: On role/permission changes
```

---

## ⚠️ ERROR HANDLING

### Common Error Codes
```typescript
// Authentication Errors
"AUTH_TOKEN_MISSING"           // No token provided
"AUTH_TOKEN_INVALID"           // Invalid token format
"AUTH_TOKEN_EXPIRED"           // Token expired
"AUTH_CREDENTIALS_INVALID"     // Wrong email/password
"AUTH_USER_NOT_FOUND"         // User doesn't exist
"AUTH_EMAIL_NOT_VERIFIED"     // Email not verified
"AUTH_ACCOUNT_SUSPENDED"      // Account suspended

// Authorization Errors  
"PERMISSION_DENIED"           // No permission for action
"ROLE_NOT_FOUND"             // Role doesn't exist
"PERMISSION_NOT_FOUND"       // Permission doesn't exist

// Validation Errors
"VALIDATION_ERROR"           // Input validation failed
"EMAIL_ALREADY_EXISTS"       // Email in use
"USERNAME_TAKEN"             // Username taken

// OTP/2FA Errors
"OTP_INVALID"                // Wrong OTP code
"OTP_EXPIRED"                // OTP expired
"OTP_ATTEMPTS_EXCEEDED"      // Too many attempts
"2FA_NOT_ENABLED"            // 2FA not set up
"2FA_CODE_INVALID"           // Wrong 2FA code

// Session Errors
"SESSION_NOT_FOUND"          // Session doesn't exist
"DEVICE_NOT_FOUND"           // Device doesn't exist
"SLT_COOKIE_MISSING"         // Security token missing
```

### Error Response Examples
```typescript
// Validation Error
{
  "success": false,
  "statusCode": 422,
  "error": "VALIDATION_ERROR",
  "message": "Invalid input data",
  "details": [
    {
      "code": "VALIDATION_ERROR",
      "path": "email",
      "message": "Email không hợp lệ"
    }
  ]
}

// Permission Denied
{
  "success": false,
  "statusCode": 403,
  "error": "PERMISSION_DENIED", 
  "message": "You don't have permission to perform this action"
}

// Rate Limit Exceeded
{
  "success": false,
  "statusCode": 429,
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Too many requests. Please try again later."
}
```

---

## 🔐 SECURITY FEATURES

### 1. Token Security
- **Access Token**: Short-lived (15 min), contains minimal user info
- **Refresh Token**: Long-lived (7 days), httpOnly cookie, secure
- **SLT Token**: One-time verification token for sensitive operations

### 2. Device Trust System
- Device fingerprinting for recognition
- Trust expiration (configurable)
- Automatic untrust on suspicious activity
- Location tracking and alerts

### 3. Rate Limiting
```typescript
// Throttle configurations
@Throttle({ default: { limit: 5, ttl: 60000 } })  // 5 requests per minute
@Throttle({ default: { limit: 3, ttl: 60000 } })  // 3 OTP requests per minute
```

### 4. Security Headers
- CSP (Content Security Policy)
- HSTS (HTTP Strict Transport Security)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer

### 5. Audit Logging
- All authentication attempts
- Permission changes
- Sensitive operations
- Failed access attempts
- IP and location tracking

---

## 📋 BEST PRACTICES

### 1. Frontend Integration
```typescript
// API Client Setup
const apiClient = axios.create({
  baseURL: '/api/v1',
  withCredentials: true, // For httpOnly cookies
});

// Request interceptor for access token
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('accessToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor for token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      try {
        await apiClient.post('/auth/refresh-token');
        return apiClient.request(error.config);
      } catch (refreshError) {
        // Redirect to login
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
```

### 2. Permission Checking
```typescript
// Frontend permission checking
function hasPermission(userPermissions: string[], required: string[]): boolean {
  return required.every(permission => 
    userPermissions.some(userPerm => 
      userPerm === permission || userPerm.endsWith(':*')
    )
  );
}

// Usage in components
if (hasPermission(user.permissions, ['User:create'])) {
  // Show create user button
}
```

### 3. Error Handling
```typescript
// Standardized error handling
interface ApiError {
  success: false;
  statusCode: number;
  error: string;
  message: string;
  details?: any;
}

function handleApiError(error: ApiError) {
  switch (error.error) {
    case 'PERMISSION_DENIED':
      showToast('Access denied', 'error');
      break;
    case 'VALIDATION_ERROR':
      showValidationErrors(error.details);
      break;
    default:
      showToast(error.message, 'error');
  }
}
```

### 4. OTP/2FA Flow Implementation
```typescript
// OTP Flow
async function loginUser(credentials) {
  try {
    const response = await apiClient.post('/auth/login', credentials);
    
    if (response.data.verificationType) {
      // Redirect to verification page
      router.push(`/verify?type=${response.data.verificationType}`);
    } else {
      // Login successful, redirect to dashboard
      router.push('/dashboard');
    }
  } catch (error) {
    handleApiError(error.response.data);
  }
}

// Verification
async function verifyOTP(code: string) {
  try {
    const response = await apiClient.post('/auth/otp/verify', { code });
    // Login completed, redirect to dashboard
    router.push('/dashboard');
  } catch (error) {
    handleApiError(error.response.data);
  }
}
```

---

## 📈 PERFORMANCE CONSIDERATIONS

### 1. Caching Strategy
- **Permission Cache**: Redis, 1-hour TTL
- **Role Cache**: Redis, 1-hour TTL  
- **Session Cache**: Redis, matches token expiry
- **Device Cache**: Redis, 30-day TTL

### 2. Database Optimization
- Indexed fields: email, roleId, subject+action
- Soft deletes with deletedAt indexing
- Pagination on all list endpoints
- Query optimization with Prisma

### 3. API Rate Limiting
- Authentication endpoints: 5/min
- OTP requests: 3/min
- General API: 100/min
- File uploads: 10/min

---

## 🔧 DEBUGGING & MONITORING

### 1. Logging Levels
```typescript
// Permission denied
this.logger.warn(`Permission denied for user ${userId}: required ${requiredPermissions}`);

// Authentication events
this.logger.log(`User ${userId} logged in from ${ipAddress}`);

// Security events
this.logger.error(`Failed login attempt for ${email} from ${ipAddress}`);
```

### 2. Health Checks
- Database connectivity
- Redis connectivity
- JWT secret validation
- External service availability

### 3. Metrics to Monitor
- Authentication success/failure rates
- Permission check latency
- Token refresh frequency
- Active session counts
- Failed verification attempts

---

*📅 Document Version: 1.0*  
*🔄 Last Updated: January 2024*  
*👥 Maintained by: ShopSifu Development Team*
