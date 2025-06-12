import { PrismaClient, Role } from '@prisma/client'
import * as dotenv from 'dotenv'
import * as path from 'path'
import { Logger } from '@nestjs/common'
import { ALL_PERMISSIONS } from '../src/shared/constants/permissions.constants'
import { PermissionDefinition } from 'src/shared/constants/permissions.constants'
import * as bcrypt from 'bcrypt'

// Load environment variables
dotenv.config({ path: path.resolve(process.cwd(), '.env') })

const logger = new Logger('SeedScript')
const prisma = new PrismaClient()

/**
 * The single source of truth for core roles in the system.
 * These roles are essential for the application to function correctly.
 */
const CORE_ROLES = [
  {
    name: 'Super Admin',
    description: 'Has all permissions in the system. Cannot be deleted.',
    isSystemRole: true,
    isSuperAdmin: true
  },
  {
    name: 'Admin',
    description: 'Administrator role with broad, but not all, permissions.',
    isSystemRole: true
  },
  {
    name: 'Customer',
    description: 'Default role for new users who sign up.',
    isSystemRole: true
  }
]

/**
 * Default admin user configuration
 */
const DEFAULT_ADMIN = {
  email: process.env.ADMIN_EMAIL,
  password: process.env.ADMIN_PASSWORD,
  firstName: 'Admin',
  lastName: 'User',
  username: 'admin'
}

async function main() {
  logger.log('🚀 Starting database seeding process...')

  try {
    await seedPermissions()
    const roles = await seedRoles()
    await assignAllPermissionsToSuperAdmin(roles)
    await createAdminUser(roles)

    logger.log('✅ Database seeding completed successfully!')
  } catch (error) {
    logger.error('❌ An error occurred during the seeding process:', error)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
  }
}

/**
 * Seeds all permissions from the single source of truth (`ALL_PERMISSIONS`) into the database.
 * It uses `upsert` to create new permissions or update existing ones.
 */
async function seedPermissions() {
  logger.log('\n[1/3] Synchronizing permissions...')

  // 1. Get permissions from the source of truth (code)
  const codePermissions = ALL_PERMISSIONS
  const codePermissionMap = new Map<string, PermissionDefinition>()
  for (const p of codePermissions) {
    codePermissionMap.set(`${p.subject}:${p.action}`, p)
  }

  // 2. Get permissions from the database
  const dbPermissions = await prisma.permission.findMany()
  const dbPermissionMap = new Map<string, (typeof dbPermissions)[0]>()
  for (const p of dbPermissions) {
    dbPermissionMap.set(`${p.subject}:${p.action}`, p)
  }

  // 3. Determine what to create, update, or delete
  const toCreate: PermissionDefinition[] = []
  const toUpdate: { id: number; data: PermissionDefinition }[] = []
  const toDelete: number[] = []

  // Check for permissions to create or update
  for (const [key, codePerm] of codePermissionMap.entries()) {
    const dbPerm = dbPermissionMap.get(key)
    if (dbPerm) {
      // If it exists, check if it needs an update
      const uiMetadata = (dbPerm.uiMetadata as any) || {}
      if (dbPerm.description !== codePerm.description || uiMetadata.uiPath !== codePerm.uiPath) {
        toUpdate.push({ id: dbPerm.id, data: codePerm })
      }
    } else {
      // If it doesn't exist, create it
      toCreate.push(codePerm)
    }
  }

  // Check for permissions to delete
  for (const [key, dbPerm] of dbPermissionMap.entries()) {
    if (!codePermissionMap.has(key)) {
      // If a DB permission is not in our code definition, delete it
      // Add a safeguard to prevent deleting critical system permissions if needed
      if (!dbPerm.isSystemPermission) {
        toDelete.push(dbPerm.id)
      }
    }
  }

  // 4. Execute database operations
  if (toCreate.length > 0) {
    await prisma.permission.createMany({
      data: toCreate.map((p) => ({
        subject: p.subject,
        action: p.action,
        description: p.description,
        isSystemPermission: p.isSystemPermission ?? false,
        uiMetadata: {
          uiPath: p.uiPath,
          description: p.description
        }
      }))
    })
    logger.log(`   - Created ${toCreate.length} new permissions.`)
  }

  if (toUpdate.length > 0) {
    for (const update of toUpdate) {
      await prisma.permission.update({
        where: { id: update.id },
        data: {
          description: update.data.description,
          isSystemPermission: update.data.isSystemPermission ?? false,
          uiMetadata: {
            uiPath: update.data.uiPath,
            description: update.data.description
          }
        }
      })
    }
    logger.log(`   - Updated ${toUpdate.length} permissions.`)
  }

  if (toDelete.length > 0) {
    await prisma.permission.deleteMany({
      where: {
        id: {
          in: toDelete
        }
      }
    })
    logger.log(`   - Deleted ${toDelete.length} stale permissions.`)
  }

  if (toCreate.length === 0 && toUpdate.length === 0 && toDelete.length === 0) {
    logger.log('   - No changes needed. Permissions are already in sync.')
  } else {
    logger.log('✅ Permissions synchronization complete.')
  }
}

/**
 * Seeds the core roles (`Super Admin`, `Admin`, `Customer`) into the database.
 * Ensures that these essential roles exist.
 */
async function seedRoles(): Promise<Role[]> {
  logger.log('\n[2/3] Seeding core roles...')
  const seededRoles: Role[] = []
  let createdCount = 0
  let existingCount = 0

  for (const roleDef of CORE_ROLES) {
    const role = await prisma.role.upsert({
      where: { name: roleDef.name },
      update: {
        description: roleDef.description,
        isSystemRole: roleDef.isSystemRole,
        isSuperAdmin: roleDef.isSuperAdmin ?? false
      },
      create: {
        name: roleDef.name,
        description: roleDef.description,
        isSystemRole: roleDef.isSystemRole,
        isSuperAdmin: roleDef.isSuperAdmin ?? false
      }
    })

    if (role.createdAt.getTime() === role.updatedAt.getTime()) {
      createdCount++
    } else {
      existingCount++
    }
    seededRoles.push(role)
  }

  logger.log(`✅ Core roles seeded: ${createdCount} created, ${existingCount} already existed.`)
  return seededRoles
}

/**
 * Assigns all existing permissions to the "Super Admin" role.
 * This ensures the Super Admin always has full access.
 * @param roles - The list of roles, used to find the Super Admin role.
 */
async function assignAllPermissionsToSuperAdmin(roles: Role[]) {
  logger.log('\n[3/4] Assigning all permissions to Super Admin...')
  const superAdminRole = roles.find((r) => r.name === 'Super Admin')

  if (!superAdminRole) {
    logger.warn('⚠️ Super Admin role not found. Skipping permission assignment.')
    return
  }

  const allPermissions = await prisma.permission.findMany({
    select: { id: true }
  })

  const existingAssignments = await prisma.rolePermission.findMany({
    where: { roleId: superAdminRole.id },
    select: { permissionId: true }
  })
  const existingPermissionIds = new Set(existingAssignments.map((p) => p.permissionId))

  const newAssignments = allPermissions
    .filter((p) => !existingPermissionIds.has(p.id))
    .map((p) => ({
      roleId: superAdminRole.id,
      permissionId: p.id
    }))

  if (newAssignments.length > 0) {
    await prisma.rolePermission.createMany({
      data: newAssignments
    })
  }

  logger.log(
    `✅ Assigned ${newAssignments.length} new permissions to Super Admin. Total permissions: ${allPermissions.length}.`
  )
}

/**
 * Creates an admin user if one doesn't already exist.
 * @param roles - The list of roles, used to find the Admin role.
 */
async function createAdminUser(roles: Role[]) {
  logger.log('\n[4/4] Creating default admin user...')

  // Find the Admin role
  const adminRole = roles.find((r) => r.name === 'Admin')
  const superAdminRole = roles.find((r) => r.name === 'Super Admin')

  if (!adminRole && !superAdminRole) {
    logger.warn('⚠️ Neither Admin nor Super Admin role found. Skipping admin user creation.')
    return
  }

  // Use Super Admin role if Admin role is not available
  const roleToAssign = superAdminRole || adminRole

  // Check if the admin user already exists
  const existingAdmin = await prisma.user.findUnique({
    where: { email: DEFAULT_ADMIN.email }
  })

  if (existingAdmin) {
    logger.log(`ℹ️ Admin user with email ${DEFAULT_ADMIN.email} already exists. Skipping creation.`)
    return
  }

  // Hash the password
  const saltRounds = 10
  const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN.password, saltRounds)

  // Create the admin user with profile
  const adminUser = await prisma.user.create({
    data: {
      email: DEFAULT_ADMIN.email,
      password: hashedPassword,
      status: 'ACTIVE',
      isEmailVerified: true,
      roleId: roleToAssign.id,
      userProfile: {
        create: {
          firstName: DEFAULT_ADMIN.firstName,
          lastName: DEFAULT_ADMIN.lastName,
          username: DEFAULT_ADMIN.username
        }
      }
    }
  })

  logger.log(`✅ Created admin user with email: ${adminUser.email} and password: ${DEFAULT_ADMIN.password}`)
  logger.log('   ⚠️ Please change the default password after first login!')
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
