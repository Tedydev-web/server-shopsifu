// Auto-generated roles from scanning database and codebase
// Generated at: 2025-06-11T18:11:59.411Z
// Total roles found: 4

export const SCANNED_ROLES = [
  {
    "name": "Admin",
    "description": "Administrator with full system access",
    "isSystemRole": true,
    "permissionStrategy": "ALL",
    "permissions": [
      {
        "action": "manage",
        "subject": "all"
      },
      {
        "action": "create",
        "subject": "User"
      },
      {
        "action": "read",
        "subject": "User"
      },
      {
        "action": "update",
        "subject": "User"
      },
      {
        "action": "delete",
        "subject": "User"
      },
      {
        "action": "create",
        "subject": "Role"
      },
      {
        "action": "read",
        "subject": "Role"
      },
      {
        "action": "update",
        "subject": "Role"
      },
      {
        "action": "delete",
        "subject": "Role"
      },
      {
        "action": "create",
        "subject": "Permission"
      },
      {
        "action": "read",
        "subject": "Permission"
      },
      {
        "action": "update",
        "subject": "Permission"
      },
      {
        "action": "delete",
        "subject": "Permission"
      },
      {
        "action": "action",
        "subject": "subject"
      },
      {
        "action": "action",
        "subject": "subjectType"
      },
      {
        "action": "read",
        "subject": "Device"
      },
      {
        "action": "delete",
        "subject": "Device"
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
        "action": "update",
        "subject": "Device"
      }
    ],
    "foundIn": "database"
  },
  {
    "name": "Customer",
    "description": "Standard customer account",
    "isSystemRole": false,
    "permissionStrategy": "CUSTOM",
    "permissions": [
      {
        "action": "read",
        "subject": "Device"
      },
      {
        "action": "delete",
        "subject": "Device"
      }
    ],
    "foundIn": "code",
    "filePath": "/Users/tedydev/Workspace/Codespaces/GitHub/Shopsifu/server-shopsifu/src/routes/user/user.service.ts"
  },
  {
    "name": "Seller",
    "description": "Vendor/Seller account with permissions to manage their products",
    "isSystemRole": false,
    "permissionStrategy": "CUSTOM",
    "permissions": [
      {
        "action": "read",
        "subject": "Device"
      },
      {
        "action": "delete",
        "subject": "Device"
      }
    ],
    "foundIn": "database"
  },
  {
    "name": "Administrator",
    "description": "Administrator role (auto-detected)",
    "isSystemRole": true,
    "permissionStrategy": "CUSTOM",
    "permissions": [],
    "foundIn": "code",
    "filePath": "/Users/tedydev/Workspace/Codespaces/GitHub/Shopsifu/server-shopsifu/src/routes/user/user.service.ts"
  }
] as const;

// Breakdown by source:
// database: 2 roles
// code: 2 roles


// Role strategies:
// ALL: 1 roles
// CUSTOM: 3 roles

