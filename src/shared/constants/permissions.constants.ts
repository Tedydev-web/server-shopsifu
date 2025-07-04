import { AppSubject } from '../providers/casl/casl-ability.factory'

export interface PermissionDefinition {
  subject: AppSubject | string // Allow string for model classes
  action: string
  description?: string
  isSystemPermission?: boolean
  conditions?: Record<string, any>
}

export const ALL_PERMISSIONS: PermissionDefinition[] = [
  // --- User Management ---
  {
    subject: AppSubject.User,
    action: 'create',
    description: 'Allow creating new users'
  },
  {
    subject: AppSubject.User,
    action: 'read',
    description: 'Allow viewing user list and details'
  },
  {
    subject: AppSubject.User,
    action: 'update',
    description: 'Allow updating user information'
  },
  {
    subject: AppSubject.User,
    action: 'delete',
    description: 'Allow deleting users'
  },

  // --- Role Management ---
  {
    subject: AppSubject.Role,
    action: 'create',
    description: 'Allow creating new roles'
  },
  {
    subject: AppSubject.Role,
    action: 'read',
    description: 'Allow viewing role list and details'
  },
  {
    subject: AppSubject.Role,
    action: 'update',
    description: 'Allow updating roles and their permissions'
  },
  {
    subject: AppSubject.Role,
    action: 'delete',
    description: 'Allow deleting roles'
  },

  // --- Permission Management ---
  {
    subject: AppSubject.Permission,
    action: 'read',
    description: 'Allow viewing permission list'
  },

  // --- Profile Management (Personal) ---
  {
    subject: AppSubject.Profile,
    action: 'read:own',
    description: 'Allow viewing own profile',
    conditions: {
      userId: 'user.id'
    }
  },
  {
    subject: AppSubject.Profile,
    action: 'update:own',
    description: 'Allow updating own profile',
    conditions: {
      userId: 'user.id'
    }
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

  // --- Password Management (Personal) ---
  {
    subject: AppSubject.Password,
    action: 'update',
    description: 'Allow changing own password'
  },

  // --- Session Management ---
  {
    subject: AppSubject.Session,
    action: 'read',
    description: 'Allow viewing session list'
  },
  {
    subject: AppSubject.Session,
    action: 'delete',
    description: 'Allow deleting sessions'
  },
  {
    subject: AppSubject.Session,
    action: 'update',
    description: 'Allow updating session information'
  },
  {
    subject: AppSubject.Session,
    action: 'create',
    description: 'Allow creating new sessions'
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
