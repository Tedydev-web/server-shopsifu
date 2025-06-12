import { AppSubject } from '../casl/casl-ability.factory'

export interface PermissionDefinition {
  subject: AppSubject | string // Allow string for model classes
  action: string
  description?: string
  uiPath?: string
  isSystemPermission?: boolean
  conditions?: Record<string, any>
}

/**
 * =============================================================================
 * ALL PERMISSIONS
 * =============================================================================
 * This is the single source of truth for all permissions in the system.
 *
 * It is used to:
 * - Seed the database with permissions.
 * - Provide a list of available permissions for the frontend.
 * - Ensure consistency between the code and the database.
 *
 * @see initialScript/seed.ts to see how this is used.
 *
 * @guidelines
 * - `subject` should be in PascalCase (e.g., 'User', 'Role').
 * - `action` should be in lowercase (e.g., 'create', 'read', 'update', 'delete').
 * - `uiPath` is the frontend path associated with this permission (e.g., '/users', '/roles').
 * - `description` should be a clear and concise explanation of the permission.
 * - `isSystemPermission` should be true for critical permissions that should not be deleted.
 * =============================================================================
 */
export const ALL_PERMISSIONS: PermissionDefinition[] = [
  // --- User Management ---
  {
    subject: AppSubject.User,
    action: 'create',
    uiPath: '/users/create',
    description: 'Allow creating new users'
  },
  {
    subject: AppSubject.User,
    action: 'read',
    uiPath: '/users',
    description: 'Allow viewing user list and details'
  },
  {
    subject: AppSubject.User,
    action: 'update',
    uiPath: '/users/:id/edit',
    description: 'Allow updating user information'
  },
  {
    subject: AppSubject.User,
    action: 'delete',
    uiPath: '/users',
    description: 'Allow deleting users'
  },

  // --- Role Management ---
  {
    subject: AppSubject.Role,
    action: 'create',
    uiPath: '/roles/create',
    description: 'Allow creating new roles'
  },
  {
    subject: AppSubject.Role,
    action: 'read',
    uiPath: '/roles',
    description: 'Allow viewing role list and details'
  },
  {
    subject: AppSubject.Role,
    action: 'update',
    uiPath: '/roles/:id/edit',
    description: 'Allow updating roles and their permissions'
  },
  {
    subject: AppSubject.Role,
    action: 'delete',
    uiPath: '/roles',
    description: 'Allow deleting roles'
  },

  // --- Permission Management ---
  {
    subject: AppSubject.Permission,
    action: 'read',
    uiPath: '/permissions',
    description: 'Allow viewing permission list'
  },

  // --- Profile Management (Personal) ---
  {
    subject: AppSubject.Profile,
    action: 'read:own',
    uiPath: '/profile',
    description: 'Allow viewing own profile'
  },
  {
    subject: AppSubject.Profile,
    action: 'update:own',
    uiPath: '/profile',
    description: 'Allow updating own profile'
  },

  // --- Security (Personal) ---
  {
    subject: AppSubject.TwoFactor,
    action: 'create', // Corresponds to setting up
    description: 'Allow setting up Two-Factor Authentication for own account'
  },
  {
    subject: AppSubject.TwoFactor,
    action: 'update', // Corresponds to verifying
    description: 'Allow verifying with a Two-Factor code for own account'
  },
  {
    subject: AppSubject.TwoFactor,
    action: 'delete', // Corresponds to disabling
    description: 'Allow disabling Two-Factor Authentication for own account'
  },

  // --- Super Admin ---
  {
    subject: AppSubject.All,
    action: 'manage',
    description: 'Allow performing any action on any resource',
    isSystemPermission: true
  }
]

// Optional: For super-admin or system-level checks
export const SYSTEM_PERMISSIONS = {
  MANAGE_ALL: {
    subject: AppSubject.All,
    action: 'manage'
  }
}
