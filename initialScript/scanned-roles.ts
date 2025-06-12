// Auto-generated roles from scanning database and codebase
// Generated at: 2025-06-12T11:02:05.710Z
// Total roles found: 3

export const SCANNED_ROLES = [
  {
    "name": "Customer",
    "description": "Customer role (auto-detected)",
    "isSystemRole": false,
    "permissionStrategy": "CUSTOM",
    "permissions": [
      {
        "action": "login",
        "subject": "Auth"
      },
      {
        "action": "register",
        "subject": "Auth"
      },
      {
        "action": "refresh",
        "subject": "Auth"
      },
      {
        "action": "logout",
        "subject": "Auth"
      },
      {
        "action": "verify_otp",
        "subject": "Auth"
      },
      {
        "action": "send_otp",
        "subject": "Auth"
      },
      {
        "action": "reset_password",
        "subject": "Auth"
      },
      {
        "action": "link_social",
        "subject": "Auth"
      },
      {
        "action": "read",
        "subject": "UserProfile"
      },
      {
        "action": "update",
        "subject": "UserProfile"
      },
      {
        "action": "read",
        "subject": "Device"
      },
      {
        "action": "update",
        "subject": "Device"
      },
      {
        "action": "delete",
        "subject": "Device"
      },
      {
        "action": "read",
        "subject": "Product"
      },
      {
        "action": "read",
        "subject": "Category"
      },
      {
        "action": "read",
        "subject": "Brand"
      }
    ],
    "foundIn": "code",
    "filePath": "/Users/tedydev/Workspace/Codespaces/GitHub/Shopsifu/server-shopsifu/src/routes/user/user.service.ts"
  },
  {
    "name": "Administrator",
    "description": "Administrator role (auto-detected)",
    "isSystemRole": true,
    "permissionStrategy": "CUSTOM",
    "permissions": [],
    "foundIn": "both",
    "filePath": "/Users/tedydev/Workspace/Codespaces/GitHub/Shopsifu/server-shopsifu/src/routes/user/user.service.ts"
  },
  {
    "name": "roles",
    "description": "roles role (auto-detected)",
    "isSystemRole": false,
    "permissionStrategy": "CUSTOM",
    "permissions": [],
    "foundIn": "both",
    "filePath": "/Users/tedydev/Workspace/Codespaces/GitHub/Shopsifu/server-shopsifu/src/routes/permission/permission.service.ts"
  }
] as const;

// Breakdown by source:
// code: 1 roles
// both: 2 roles


// Role strategies:
// CUSTOM: 3 roles

