import { DefaultArgs } from '@prisma/client/runtime/library'
import { Prisma } from '@prisma/client'

// Use a type that can be dynamically used for Zod schemas if needed.
export const AppPermission = {
  // System & Core
  MANAGE_ALL: {
    action: 'manage',
    subject: 'all',
    category: 'System',
    description: 'Full access to all resources. (Super-admin only)'
  },

  // Authentication
  AUTH_LOGIN: { action: 'login', subject: 'Auth', category: 'Auth', description: 'Log in to an account' },
  AUTH_REGISTER: { action: 'register', subject: 'Auth', category: 'Auth', description: 'Register a new account' },
  AUTH_REFRESH_TOKEN: {
    action: 'refresh',
    subject: 'Auth',
    category: 'Auth',
    description: 'Refresh authentication token'
  },
  AUTH_LOGOUT: { action: 'logout', subject: 'Auth', category: 'Auth', description: 'Log out from an account' },
  AUTH_VERIFY_OTP: { action: 'verify_otp', subject: 'Auth', category: 'Auth', description: 'Verify an OTP code' },
  AUTH_SEND_OTP: { action: 'send_otp', subject: 'Auth', category: 'Auth', description: 'Request to send an OTP' },
  AUTH_RESET_PASSWORD: {
    action: 'reset_password',
    subject: 'Auth',
    category: 'Auth',
    description: 'Reset password'
  },
  AUTH_LINK_SOCIAL: {
    action: 'link_social',
    subject: 'Auth',
    category: 'Auth',
    description: 'Link a social media account'
  },

  // User Profile
  PROFILE_READ_OWN: {
    action: 'read',
    subject: 'UserProfile',
    category: 'Profile',
    description: 'Read own user profile'
  },
  PROFILE_UPDATE_OWN: {
    action: 'update',
    subject: 'UserProfile',
    category: 'Profile',
    description: 'Update own user profile'
  },

  // User Management (Admin)
  USER_READ: { action: 'read', subject: 'User', category: 'User Management', description: 'View list of users' },
  USER_CREATE: { action: 'create', subject: 'User', category: 'User Management', description: 'Create a new user' },
  USER_UPDATE: { action: 'update', subject: 'User', category: 'User Management', description: 'Update a user' },
  USER_DELETE: { action: 'delete', subject: 'User', category: 'User Management', description: 'Delete a user' },

  // Role Management (Admin)
  ROLE_READ: { action: 'read', subject: 'Role', category: 'Role Management', description: 'View roles' },
  ROLE_CREATE: { action: 'create', subject: 'Role', category: 'Role Management', description: 'Create a new role' },
  ROLE_UPDATE: { action: 'update', subject: 'Role', category: 'Role Management', description: 'Update a role' },
  ROLE_DELETE: { action: 'delete', subject: 'Role', category: 'Role Management', description: 'Delete a role' },

  // Permission Management (Admin)
  PERMISSION_READ: {
    action: 'read',
    subject: 'Permission',
    category: 'Permission Management',
    description: 'View permissions'
  },

  // Session & Device Management
  DEVICE_READ_OWN: {
    action: 'read',
    subject: 'Device',
    category: 'Device Management',
    description: 'View own devices and sessions'
  },
  DEVICE_UPDATE_OWN: {
    action: 'update',
    subject: 'Device',
    category: 'Device Management',
    description: 'Update own device details (e.g., name)'
  },
  DEVICE_DELETE_OWN: {
    action: 'delete',
    subject: 'Device',
    category: 'Device Management',
    description: 'Revoke own sessions/devices'
  },

  // Public Catalog Access
  CATALOG_READ: {
    action: 'read',
    subject: 'Catalog',
    category: 'Catalog',
    description: 'View public catalog data (products, categories, brands)'
  }
} as const // Use "as const" to make it a strict object with literal types

// Type for a single permission object
export type AppPermissionValue = (typeof AppPermission)[keyof typeof AppPermission]

// Type for Prisma's PermissionCreateInput
type PermissionCreateInput = Prisma.PermissionCreateInput

// All permissions that should exist in the database
export const ALL_PERMISSIONS: PermissionCreateInput[] = Object.values(AppPermission)

// --- Role Definitions ---

export const AppRole = {
  ADMIN: 'Admin',
  CUSTOMER: 'Customer',
  SELLER: 'Seller'
} as const

// --- Role to Permission Assignments ---

type RoleName = (typeof AppRole)[keyof typeof AppRole]
type PermissionAssignments = Record<RoleName, AppPermissionValue[]>

export const ROLE_PERMISSIONS: PermissionAssignments = {
  [AppRole.ADMIN]: [
    // Admin gets all permissions
    AppPermission.MANAGE_ALL
  ],
  [AppRole.CUSTOMER]: [
    // Auth
    AppPermission.AUTH_LOGIN,
    AppPermission.AUTH_REGISTER,
    AppPermission.AUTH_REFRESH_TOKEN,
    AppPermission.AUTH_LOGOUT,
    AppPermission.AUTH_VERIFY_OTP,
    AppPermission.AUTH_SEND_OTP,
    AppPermission.AUTH_RESET_PASSWORD,
    AppPermission.AUTH_LINK_SOCIAL,
    // Profile
    AppPermission.PROFILE_READ_OWN,
    AppPermission.PROFILE_UPDATE_OWN,
    // Devices
    AppPermission.DEVICE_READ_OWN,
    AppPermission.DEVICE_UPDATE_OWN,
    AppPermission.DEVICE_DELETE_OWN,
    // Catalog
    AppPermission.CATALOG_READ
  ],
  [AppRole.SELLER]: [
    // Auth
    AppPermission.AUTH_LOGIN,
    AppPermission.AUTH_REGISTER,
    AppPermission.AUTH_REFRESH_TOKEN,
    AppPermission.AUTH_LOGOUT,
    AppPermission.AUTH_VERIFY_OTP,
    AppPermission.AUTH_SEND_OTP,
    AppPermission.AUTH_RESET_PASSWORD,
    AppPermission.AUTH_LINK_SOCIAL,
    // Profile
    AppPermission.PROFILE_READ_OWN,
    AppPermission.PROFILE_UPDATE_OWN,
    // Devices
    AppPermission.DEVICE_READ_OWN,
    AppPermission.DEVICE_UPDATE_OWN,
    AppPermission.DEVICE_DELETE_OWN,
    // Catalog
    AppPermission.CATALOG_READ
    // TODO: Add seller-specific permissions here later
    // e.g., managing their own products, viewing their orders
  ]
}

// Full role definitions for seeding
export const ROLES_TO_SEED = [
  {
    name: AppRole.ADMIN,
    description: 'Administrator with full system access',
    isSystemRole: true,
    permissions: ROLE_PERMISSIONS[AppRole.ADMIN]
  },
  {
    name: AppRole.CUSTOMER,
    description: 'Standard customer account',
    isSystemRole: false,
    permissions: ROLE_PERMISSIONS[AppRole.CUSTOMER]
  },
  {
    name: AppRole.SELLER,
    description: 'Vendor/Seller account with permissions to manage their products',
    isSystemRole: false,
    permissions: ROLE_PERMISSIONS[AppRole.SELLER]
  }
]
