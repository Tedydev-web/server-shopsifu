#!/usr/bin/env tsx
/**
 * Complete Role & Permission Seeding Script
 * Seeds all 3 roles (Admin, Customer, Seller) with comprehensive permissions,
 * conditions, and ui_metadata following business logic and best practices.
 */

import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

// ================================================================
// PERMISSION DEFINITIONS WITH CONDITIONS & UI_METADATA
// ================================================================

interface PermissionSeedData {
  action: string
  subject: string
  conditions?: object | null
  ui_metadata?: object | null
  description?: string | null
}

// Core system permissions discovered from controllers
const CORE_PERMISSIONS: PermissionSeedData[] = [
  // User Management Permissions
  {
    action: 'create',
    subject: 'User',
    description: 'Create new users in the system',
    ui_metadata: {
      icon: 'UserPlus',
      color: '#10B981',
      category: 'User Management',
      displayName: 'Create Users',
      description: 'Add new users to the system',
      formConfig: {
        fields: ['email', 'password', 'roleId', 'firstName', 'lastName'],
        required: ['email', 'password', 'roleId']
      }
    }
  },
  {
    action: 'read',
    subject: 'User',
    description: 'View user information and lists',
    ui_metadata: {
      icon: 'Users',
      color: '#3B82F6',
      category: 'User Management',
      displayName: 'View Users',
      description: 'Access user profiles and lists',
      tableConfig: {
        columns: ['id', 'email', 'status', 'role', 'createdAt'],
        sortable: ['email', 'createdAt', 'status'],
        filterable: ['role', 'status']
      }
    }
  },
  {
    action: 'update',
    subject: 'User',
    description: 'Modify user information',
    conditions: {
      or: [{ '==': [{ var: 'user.role' }, 'Admin'] }, { and: [{ '==': [{ var: 'user.id' }, { var: 'resource.id' }] }] }]
    },
    ui_metadata: {
      icon: 'UserEdit',
      color: '#F59E0B',
      category: 'User Management',
      displayName: 'Edit Users',
      description: 'Modify user profiles and settings',
      formConfig: {
        fields: ['email', 'status', 'roleId', 'firstName', 'lastName'],
        conditionalFields: {
          admin: ['roleId', 'status'],
          self: ['firstName', 'lastName', 'email']
        }
      }
    }
  },
  {
    action: 'delete',
    subject: 'User',
    description: 'Remove users from the system',
    conditions: {
      and: [{ '==': [{ var: 'user.role' }, 'Admin'] }, { '!=': [{ var: 'user.id' }, { var: 'resource.id' }] }]
    },
    ui_metadata: {
      icon: 'UserMinus',
      color: '#EF4444',
      category: 'User Management',
      displayName: 'Delete Users',
      description: 'Remove users from the system',
      confirmationRequired: true,
      warningMessage: 'This action cannot be undone'
    }
  },

  // Role Management Permissions
  {
    action: 'create',
    subject: 'Role',
    description: 'Create new roles and permission sets',
    ui_metadata: {
      icon: 'Shield',
      color: '#8B5CF6',
      category: 'Role Management',
      displayName: 'Create Roles',
      description: 'Define new roles and their permissions',
      formConfig: {
        fields: ['name', 'description', 'isSystemRole', 'permissions'],
        required: ['name']
      }
    }
  },
  {
    action: 'read',
    subject: 'Role',
    description: 'View roles and their permissions',
    ui_metadata: {
      icon: 'ShieldCheck',
      color: '#3B82F6',
      category: 'Role Management',
      displayName: 'View Roles',
      description: 'Access role definitions and permissions',
      tableConfig: {
        columns: ['id', 'name', 'description', 'isSystemRole'],
        sortable: ['name'],
        filterable: ['isSystemRole']
      }
    }
  },
  {
    action: 'update',
    subject: 'Role',
    description: 'Modify role definitions and permissions',
    conditions: {
      or: [{ '==': [{ var: 'user.role' }, 'Admin'] }, { '!=': [{ var: 'resource.isSystemRole' }, true] }]
    },
    ui_metadata: {
      icon: 'ShieldEdit',
      color: '#F59E0B',
      category: 'Role Management',
      displayName: 'Edit Roles',
      description: 'Modify role permissions and settings',
      formConfig: {
        fields: ['name', 'description', 'permissions'],
        readonly: ['isSystemRole'],
        conditionalFields: {
          admin: ['name', 'description', 'permissions'],
          manager: ['permissions']
        }
      }
    }
  },
  {
    action: 'delete',
    subject: 'Role',
    description: 'Remove roles from the system',
    conditions: {
      and: [{ '==': [{ var: 'user.role' }, 'Admin'] }, { '!=': [{ var: 'resource.isSystemRole' }, true] }]
    },
    ui_metadata: {
      icon: 'ShieldX',
      color: '#EF4444',
      category: 'Role Management',
      displayName: 'Delete Roles',
      description: 'Remove non-system roles',
      confirmationRequired: true,
      warningMessage: 'Users with this role will lose access'
    }
  },

  // Permission Management Permissions
  {
    action: 'create',
    subject: 'Permission',
    description: 'Create new permissions',
    ui_metadata: {
      icon: 'Key',
      color: '#10B981',
      category: 'Permission Management',
      displayName: 'Create Permissions',
      description: 'Define new system permissions',
      formConfig: {
        fields: ['action', 'subject', 'conditions', 'uiMetadata', 'description'],
        required: ['action', 'subject']
      }
    }
  },
  {
    action: 'read',
    subject: 'Permission',
    description: 'View system permissions',
    ui_metadata: {
      icon: 'KeyRound',
      color: '#3B82F6',
      category: 'Permission Management',
      displayName: 'View Permissions',
      description: 'Access permission definitions',
      tableConfig: {
        columns: ['id', 'action', 'subject', 'description'],
        sortable: ['action', 'subject'],
        filterable: ['subject'],
        groupBy: 'subject'
      }
    }
  },
  {
    action: 'update',
    subject: 'Permission',
    description: 'Modify permission definitions',
    ui_metadata: {
      icon: 'KeyEdit',
      color: '#F59E0B',
      category: 'Permission Management',
      displayName: 'Edit Permissions',
      description: 'Modify permission settings and conditions',
      formConfig: {
        fields: ['conditions', 'uiMetadata', 'description'],
        readonly: ['action', 'subject']
      }
    }
  },
  {
    action: 'delete',
    subject: 'Permission',
    description: 'Remove permissions from the system',
    ui_metadata: {
      icon: 'KeyX',
      color: '#EF4444',
      category: 'Permission Management',
      displayName: 'Delete Permissions',
      description: 'Remove unused permissions',
      confirmationRequired: true,
      warningMessage: 'This will affect all roles using this permission'
    }
  },

  // Profile Management Permissions
  {
    action: 'read:own',
    subject: 'Profile',
    description: 'View own profile information',
    conditions: {
      '==': [{ var: 'user.id' }, { var: 'resource.userId' }]
    },
    ui_metadata: {
      icon: 'User',
      color: '#3B82F6',
      category: 'Profile',
      displayName: 'View Profile',
      description: 'Access your profile information',
      scope: 'own'
    }
  },
  {
    action: 'update:own',
    subject: 'Profile',
    description: 'Update own profile information',
    conditions: {
      '==': [{ var: 'user.id' }, { var: 'resource.userId' }]
    },
    ui_metadata: {
      icon: 'UserEdit',
      color: '#F59E0B',
      category: 'Profile',
      displayName: 'Edit Profile',
      description: 'Update your profile information',
      scope: 'own',
      formConfig: {
        fields: ['firstName', 'lastName', 'username', 'bio', 'avatar'],
        required: ['firstName', 'lastName']
      }
    }
  },

  // Two-Factor Authentication Permissions
  {
    action: 'setup:own',
    subject: '2FA',
    description: 'Set up two-factor authentication',
    conditions: {
      '==': [{ var: 'user.id' }, { var: 'resource.userId' }]
    },
    ui_metadata: {
      icon: 'ShieldCheck',
      color: '#10B981',
      category: 'Security',
      displayName: 'Setup 2FA',
      description: 'Enable two-factor authentication',
      scope: 'own'
    }
  },
  {
    action: 'verify:own',
    subject: '2FA',
    description: 'Verify two-factor authentication codes',
    conditions: {
      '==': [{ var: 'user.id' }, { var: 'resource.userId' }]
    },
    ui_metadata: {
      icon: 'CheckCircle',
      color: '#3B82F6',
      category: 'Security',
      displayName: 'Verify 2FA',
      description: 'Verify authentication codes',
      scope: 'own'
    }
  },
  {
    action: 'disable:own',
    subject: '2FA',
    description: 'Disable two-factor authentication',
    conditions: {
      '==': [{ var: 'user.id' }, { var: 'resource.userId' }]
    },
    ui_metadata: {
      icon: 'ShieldX',
      color: '#EF4444',
      category: 'Security',
      displayName: 'Disable 2FA',
      description: 'Turn off two-factor authentication',
      scope: 'own',
      confirmationRequired: true
    }
  },
  {
    action: 'regenerate_codes:own',
    subject: '2FA',
    description: 'Regenerate two-factor recovery codes',
    conditions: {
      '==': [{ var: 'user.id' }, { var: 'resource.userId' }]
    },
    ui_metadata: {
      icon: 'RefreshCw',
      color: '#F59E0B',
      category: 'Security',
      displayName: 'Regenerate Codes',
      description: 'Generate new recovery codes',
      scope: 'own',
      confirmationRequired: true
    }
  },

  // Additional business permissions for customers and sellers
  {
    action: 'read',
    subject: 'Product',
    description: 'View product catalog',
    ui_metadata: {
      icon: 'Package',
      color: '#3B82F6',
      category: 'Catalog',
      displayName: 'View Products',
      description: 'Browse product catalog'
    }
  },
  {
    action: 'create',
    subject: 'Product',
    description: 'Create new products',
    conditions: {
      or: [{ '==': [{ var: 'user.role' }, 'Admin'] }, { '==': [{ var: 'user.role' }, 'Seller'] }]
    },
    ui_metadata: {
      icon: 'PackagePlus',
      color: '#10B981',
      category: 'Catalog',
      displayName: 'Create Products',
      description: 'Add new products to catalog',
      formConfig: {
        fields: ['name', 'description', 'price', 'category', 'images'],
        required: ['name', 'price', 'category']
      }
    }
  },
  {
    action: 'update',
    subject: 'Product',
    description: 'Update product information',
    conditions: {
      or: [
        { '==': [{ var: 'user.role' }, 'Admin'] },
        {
          and: [
            { '==': [{ var: 'user.role' }, 'Seller'] },
            { '==': [{ var: 'user.id' }, { var: 'resource.sellerId' }] }
          ]
        }
      ]
    },
    ui_metadata: {
      icon: 'PackageEdit',
      color: '#F59E0B',
      category: 'Catalog',
      displayName: 'Edit Products',
      description: 'Update product details'
    }
  },
  {
    action: 'read',
    subject: 'Category',
    description: 'View product categories',
    ui_metadata: {
      icon: 'Grid',
      color: '#3B82F6',
      category: 'Catalog',
      displayName: 'View Categories',
      description: 'Browse product categories'
    }
  },
  {
    action: 'read',
    subject: 'Brand',
    description: 'View product brands',
    ui_metadata: {
      icon: 'Tag',
      color: '#3B82F6',
      category: 'Catalog',
      displayName: 'View Brands',
      description: 'Browse product brands'
    }
  },
  {
    action: 'read',
    subject: 'Order',
    description: 'View order information',
    conditions: {
      or: [
        { '==': [{ var: 'user.role' }, 'Admin'] },
        {
          and: [
            { '==': [{ var: 'user.role' }, 'Customer'] },
            { '==': [{ var: 'user.id' }, { var: 'resource.customerId' }] }
          ]
        },
        {
          and: [{ '==': [{ var: 'user.role' }, 'Seller'] }, { in: [{ var: 'user.id' }, { var: 'resource.sellerIds' }] }]
        }
      ]
    },
    ui_metadata: {
      icon: 'ShoppingCart',
      color: '#3B82F6',
      category: 'Orders',
      displayName: 'View Orders',
      description: 'Access order information'
    }
  },
  {
    action: 'read',
    subject: 'Device',
    description: 'View device information',
    conditions: {
      or: [{ '==': [{ var: 'user.role' }, 'Admin'] }, { '==': [{ var: 'user.id' }, { var: 'resource.userId' }] }]
    },
    ui_metadata: {
      icon: 'Smartphone',
      color: '#3B82F6',
      category: 'Security',
      displayName: 'View Devices',
      description: 'View registered devices'
    }
  },
  {
    action: 'update',
    subject: 'Device',
    description: 'Update device settings',
    conditions: {
      or: [{ '==': [{ var: 'user.role' }, 'Admin'] }, { '==': [{ var: 'user.id' }, { var: 'resource.userId' }] }]
    },
    ui_metadata: {
      icon: 'Settings',
      color: '#F59E0B',
      category: 'Security',
      displayName: 'Edit Devices',
      description: 'Update device settings'
    }
  },
  {
    action: 'delete',
    subject: 'Device',
    description: 'Remove registered devices',
    conditions: {
      or: [{ '==': [{ var: 'user.role' }, 'Admin'] }, { '==': [{ var: 'user.id' }, { var: 'resource.userId' }] }]
    },
    ui_metadata: {
      icon: 'Trash',
      color: '#EF4444',
      category: 'Security',
      displayName: 'Delete Devices',
      description: 'Remove registered devices',
      confirmationRequired: true
    }
  }
]

// ================================================================
// ROLE DEFINITIONS WITH PERMISSION ASSIGNMENTS
// ================================================================

interface RoleSeedData {
  name: string
  description: string
  isSystemRole: boolean
  permissions: string[] // Array of permission identifiers (action:subject)
}

const ROLES_DATA: RoleSeedData[] = [
  {
    name: 'Admin',
    description: 'System administrator with full access to all features',
    isSystemRole: true,
    permissions: [] // Admin gets ALL permissions
  },
  {
    name: 'Customer',
    description: 'Standard customer account with basic user privileges',
    isSystemRole: false,
    permissions: [
      // Profile management
      'read:own:Profile',
      'update:own:Profile',

      // Two-factor authentication
      'setup:own:2FA',
      'verify:own:2FA',
      'disable:own:2FA',
      'regenerate_codes:own:2FA',

      // Device management
      'read:Device',
      'update:Device',
      'delete:Device',

      // Catalog browsing
      'read:Product',
      'read:Category',
      'read:Brand',

      // Order management (own orders only)
      'read:Order'
    ]
  },
  {
    name: 'Seller',
    description: 'Vendor account with product management capabilities',
    isSystemRole: false,
    permissions: [
      // All customer permissions
      'read:own:Profile',
      'update:own:Profile',
      'setup:own:2FA',
      'verify:own:2FA',
      'disable:own:2FA',
      'regenerate_codes:own:2FA',
      'read:Device',
      'update:Device',
      'delete:Device',
      'read:Product',
      'read:Category',
      'read:Brand',
      'read:Order',

      // Additional seller permissions
      'create:Product',
      'update:Product'
    ]
  }
]

// ================================================================
// SEEDING FUNCTIONS
// ================================================================

async function clearExistingData() {
  console.log('🧹 Clearing existing role-permission assignments...')

  // Clear role-permission relationships but keep existing roles and permissions
  await prisma.rolePermission.deleteMany({})

  console.log('✅ Cleared existing role-permission assignments')
}

async function seedPermissions() {
  console.log('🔑 Seeding permissions...')

  for (const permData of CORE_PERMISSIONS) {
    const identifier = `${permData.action}:${permData.subject}`

    try {
      await prisma.permission.upsert({
        where: {
          action_subject: {
            action: permData.action,
            subject: permData.subject
          }
        },
        update: {
          conditions: permData.conditions as any,
          uiMetadata: permData.ui_metadata as any,
          description: permData.description
        },
        create: {
          action: permData.action,
          subject: permData.subject,
          conditions: permData.conditions as any,
          uiMetadata: permData.ui_metadata as any,
          description: permData.description
        }
      })

      console.log(`  ✓ ${identifier}`)
    } catch (error: any) {
      console.error(`  ❌ Failed to seed permission ${identifier}:`, error.message)
    }
  }

  console.log(`✅ Seeded ${CORE_PERMISSIONS.length} permissions`)
}

async function seedRoles() {
  console.log('👥 Seeding roles and assigning permissions...')

  for (const roleData of ROLES_DATA) {
    try {
      // Create or update the role
      const role = await prisma.role.upsert({
        where: { name: roleData.name },
        update: {
          description: roleData.description
        },
        create: {
          name: roleData.name,
          description: roleData.description,
          isSystemRole: roleData.isSystemRole
        }
      })

      console.log(`  ✓ Role: ${roleData.name}`)

      // For Admin role, assign ALL permissions
      if (roleData.name === 'Admin') {
        // Clear existing permissions for this role
        await prisma.rolePermission.deleteMany({
          where: { roleId: role.id }
        })

        // Get all permissions and assign them to Admin
        const allPermissions = await prisma.permission.findMany()

        for (const permission of allPermissions) {
          await prisma.rolePermission.create({
            data: {
              roleId: role.id,
              permissionId: permission.id
            }
          })
        }

        console.log(`    ✓ Assigned ALL ${allPermissions.length} permissions to Admin`)
      } else {
        // For other roles, assign specific permissions
        // Clear existing permissions for this role
        await prisma.rolePermission.deleteMany({
          where: { roleId: role.id }
        })

        // Add new permissions
        for (const permIdentifier of roleData.permissions) {
          const [action, subject] = permIdentifier.split(':')

          const permission = await prisma.permission.findFirst({
            where: {
              action,
              subject
            }
          })

          if (permission) {
            await prisma.rolePermission.create({
              data: {
                roleId: role.id,
                permissionId: permission.id
              }
            })
            console.log(`    ✓ Assigned: ${permIdentifier}`)
          } else {
            console.warn(`    ⚠️  Permission not found: ${permIdentifier}`)
          }
        }
      }
    } catch (error: any) {
      console.error(`  ❌ Failed to seed role ${roleData.name}:`, error.message)
    }
  }

  console.log(`✅ Seeded ${ROLES_DATA.length} roles`)
}

async function validateSeeding() {
  console.log('🔍 Validating seeded data...')

  // Check permissions
  const permissionCount = await prisma.permission.count()
  console.log(`  📊 Total permissions in database: ${permissionCount}`)

  // Check roles
  const roles = await prisma.role.findMany({
    include: {
      permissions: {
        include: {
          permission: true
        }
      }
    }
  })

  console.log(`  📊 Total roles in database: ${roles.length}`)

  for (const role of roles) {
    console.log(`    ${role.name}: ${role.permissions.length} permissions assigned`)
  }

  // Check for permissions with conditions and ui_metadata
  const permissionsWithConditions = await prisma.permission.count({
    where: {
      conditions: { not: null }
    }
  })

  const permissionsWithUIMetadata = await prisma.permission.count({
    where: {
      uiMetadata: { not: null }
    }
  })

  console.log(`  📊 Permissions with conditions: ${permissionsWithConditions}`)
  console.log(`  📊 Permissions with UI metadata: ${permissionsWithUIMetadata}`)
}

async function main() {
  console.log('🚀 Starting Complete Role & Permission Seeding')
  console.log('============================================\n')

  try {
    await clearExistingData()
    await seedPermissions()
    await seedRoles()
    await validateSeeding()

    console.log('\n🎉 Seeding completed successfully!')
    console.log('\n📋 Summary:')
    console.log(`   • Permissions: ${CORE_PERMISSIONS.length} total`)
    console.log(`   • Roles: ${ROLES_DATA.length} total`)
    console.log(`   • Admin: ALL permissions strategy`)
    console.log(
      `   • Customer: ${ROLES_DATA.find((r) => r.name === 'Customer')?.permissions.length} specific permissions`
    )
    console.log(`   • Seller: ${ROLES_DATA.find((r) => r.name === 'Seller')?.permissions.length} specific permissions`)
    console.log('\n✅ Ready to test GET endpoints with properly seeded data!')
  } catch (error: any) {
    console.error('❌ Seeding failed:', error.message)
    console.error('Stack:', error.stack)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
  }
}

// Only run if called directly
if (require.main === module) {
  void main()
}

export { main as seedCompleteRolesPermissions }
