// Auto-generated roles from scanning database and codebase
// Generated at: 2025-06-12T04:29:31.287Z
// Total roles found: 5

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
    "name": "Seller",
    "description": "Vendor/Seller account with permissions to manage their products",
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
      },
      {
        "action": "create",
        "subject": "Product"
      },
      {
        "action": "update",
        "subject": "Product"
      },
      {
        "action": "read",
        "subject": "Order"
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
    "foundIn": "both",
    "filePath": "/Users/tedydev/Workspace/Codespaces/GitHub/Shopsifu/server-shopsifu/src/routes/user/user.service.ts"
  },
  {
    "name": "roles",
    "description": "roles role (auto-detected)",
    "isSystemRole": false,
    "permissionStrategy": "CUSTOM",
    "permissions": [],
    "foundIn": "code",
    "filePath": "/Users/tedydev/Workspace/Codespaces/GitHub/Shopsifu/server-shopsifu/src/routes/permission/permission.service.ts"
  }
] as const;

// Breakdown by source:
// database: 2 roles
// code: 2 roles
// both: 1 roles


// Role strategies:
// ALL: 1 roles
// CUSTOM: 4 roles

