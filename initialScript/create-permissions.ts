import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

// IMPORTANT: Define a system user ID that exists in your User table.
// This ID will be used for createdById and updatedById fields for permissions created by this script.
// TODO: Replace with a real system user ID or make configurable

interface DesiredPermission {
  action: string
  subject: string
  category: string
  description?: string | null
}

// Source of truth for all permissions in the system
const desiredPermissions: DesiredPermission[] = [
  // RBAC - PERMISSIONS
  {
    category: 'RBAC_PERMISSIONS',
    subject: 'Permission',
    action: 'READ', // Standardized from 'List Permissions'
    description: 'GET /rbac/permissions (View all permissions)'
  },
  {
    category: 'RBAC_PERMISSIONS',
    subject: 'Permission',
    action: 'READ', // Standardized from 'Read Permission'
    description: 'GET /rbac/permissions/:id (View a specific permission)'
  },
  {
    category: 'RBAC_PERMISSIONS',
    subject: 'Permission',
    action: 'CREATE', // Standardized from 'Create Permission'
    description: 'POST /rbac/permissions (Create a new permission)'
  },
  {
    category: 'RBAC_PERMISSIONS',
    subject: 'Permission',
    action: 'UPDATE', // Standardized from 'Update Permission'
    description: 'PATCH /rbac/permissions/:id (Update a specific permission)'
  },
  {
    category: 'RBAC_PERMISSIONS',
    subject: 'Permission',
    action: 'DELETE', // Standardized from 'Delete Permission'
    description: 'DELETE /rbac/permissions/:id (Delete a specific permission)'
  },

  // RBAC - ROLES (Example, expand as needed)
  {
    category: 'RBAC_ROLES',
    subject: 'Role',
    action: 'READ', // Standardized from 'List Roles'
    description: 'GET /rbac/roles (View all roles)'
  },
  {
    category: 'RBAC_ROLES',
    subject: 'Role',
    action: 'CREATE', // Standardized from 'Create Role'
    description: 'POST /rbac/roles (Create a new role)'
  },
  // Add more permissions for USERS, FILES, etc. as per your UI and requirements

  // PROFILE MANAGEMENT
  {
    category: 'PROFILE_MANAGEMENT',
    subject: 'OwnProfile',
    action: 'READ',
    description: 'Xem thông tin cá nhân của chính mình'
  },
  {
    category: 'PROFILE_MANAGEMENT',
    subject: 'OwnProfile',
    action: 'UPDATE',
    description: 'Cập nhật thông tin cá nhân của chính mình'
  }
]

async function bootstrap() {
  console.log('Starting permission synchronization...')

  let createdCount = 0
  let updatedCount = 0

  for (const dp of desiredPermissions) {
    const permissionData = {
      action: dp.action,
      subject: dp.subject,
      category: dp.category,
      description: dp.description ?? null // Handle undefined description
      // 'conditions' field is omitted as it's not in DesiredPermission interface or array
      // createdById and updatedById are not set here, assuming they are optional or handled by DB/Prisma defaults if needed.
    }

    const existingPermission = await prisma.permission.findUnique({
      where: { UQ_action_subject: { action: dp.action, subject: dp.subject } } // Corrected unique constraint name
    })

    if (existingPermission) {
      // Check if update is needed (category or description changed)
      if (
        existingPermission.category !== permissionData.category ||
        existingPermission.description !== permissionData.description
      ) {
        await prisma.permission.update({
          where: { id: existingPermission.id },
          data: {
            category: permissionData.category,
            description: permissionData.description
            // updatedById: SYSTEM_USER_ID, // Example if you need to set it
          }
        })
        updatedCount++
      }
    } else {
      // Create new permission
      await prisma.permission.create({
        data: {
          ...permissionData
          // createdById: SYSTEM_USER_ID, // Example if you need to set it
        }
      })
      createdCount++
    }
  }

  if (createdCount > 0) {
    console.log(`Created ${createdCount} new permissions.`)
  }
  if (updatedCount > 0) {
    console.log(`Updated ${updatedCount} existing permissions.`)
  }
  if (createdCount === 0 && updatedCount === 0) {
    console.log('All desired permissions are already up to date.')
  }

  // 2. Find or create the ADMIN role
  const adminRoleName = 'Admin'
  let adminRole = await prisma.role.findUnique({
    where: { name: adminRoleName }
  })

  if (!adminRole) {
    adminRole = await prisma.role.create({
      data: {
        name: adminRoleName,
        description: 'Administrator role with all permissions'
        // createdById: SYSTEM_USER_ID, // Example if you need to set it
      }
    })
    console.log(`Created ADMIN role (ID: ${adminRole.id}).`)
  } else {
    console.log(`Found ADMIN role (ID: ${adminRole.id}).`)
  }

  // 3. Fetch ALL permissions from the database
  const allPermissions = await prisma.permission.findMany()
  console.log(`Found ${allPermissions.length} total permissions in the database.`)

  // 4. Assign all permissions to the ADMIN role
  if (adminRole && allPermissions.length > 0) {
    const rolePermissionsData = allPermissions.map((p) => ({
      roleId: adminRole.id,
      permissionId: p.id
      // assignedById: SYSTEM_USER_ID, // Example if you need to set it
    }))

    const assignResult = await prisma.rolePermission.createMany({
      data: rolePermissionsData,
      skipDuplicates: true
    })

    const newLinksCreated = assignResult.count
    // Note: assignResult.count for createMany with skipDuplicates indicates the number of records actually created.
    // It doesn't directly tell us how many were skipped if we don't know how many potential duplicates existed.
    // To accurately log skipped duplicates, we'd need to query existing RolePermissions first or count distinct roleId-permissionId pairs.
    // For simplicity, we'll just log the number of links processed for creation.
    console.log(
      `Processed ${rolePermissionsData.length} permission assignments for ADMIN role. ${newLinksCreated} new links created (duplicates skipped).`
    )
  } else if (allPermissions.length === 0) {
    console.log('No permissions found in the database to assign to ADMIN role.')
  } else if (!adminRole) {
    console.warn('ADMIN role not available, cannot assign permissions.')
  }

  console.log('Permission synchronization and ADMIN role assignment finished successfully.')
}

async function main() {
  try {
    await bootstrap()
  } catch (e) {
    console.error('Error during permission synchronization script:', e)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
    console.log('Script finished. Prisma client disconnected.')
  }
}

void main()
