import { PrismaClient } from '@prisma/client'
import { HashingService } from '../src/shared/services/hashing.service'
import appConfig from '../src/shared/config'
import { ALL_PERMISSIONS, ROLES_TO_SEED } from './permission-definitions'

const prisma = new PrismaClient()
const hashingService = new HashingService()
const config = appConfig()

// IMPORTANT: Define a system user ID that exists in your User table.
// This ID will be used for createdById and updatedById fields for permissions created by this script.
// TODO: Replace with a real system user ID or make configurable

async function seedPermissions() {
  console.log('--- Starting Permission Synchronization ---')
  let createdCount = 0
  let updatedCount = 0
  let deletedCount = 0

  const desiredPermissions = ALL_PERMISSIONS
  const existingPermissions = await prisma.permission.findMany()
  const existingPermissionMap = new Map(existingPermissions.map((p) => [`${p.action}:${p.subject}`, p]))

  // 1. Create or Update permissions
  for (const p of desiredPermissions) {
    const key = `${p.action}:${p.subject}`
    const existing = existingPermissionMap.get(key)

    const permissionData = {
      action: p.action,
      subject: p.subject,
      category: p.category,
      description: p.description ?? null
    }

    if (existing) {
      if (existing.category !== permissionData.category || existing.description !== permissionData.description) {
        await prisma.permission.update({ where: { id: existing.id }, data: permissionData })
        updatedCount++
      }
    } else {
      await prisma.permission.create({ data: permissionData })
      createdCount++
    }
  }

  // 2. Delete obsolete permissions
  const desiredPermissionKeys = new Set(desiredPermissions.map((p) => `${p.action}:${p.subject}`))
  for (const ep of existingPermissions) {
    const key = `${ep.action}:${ep.subject}`
    if (!desiredPermissionKeys.has(key)) {
      // RolePermission table has onDelete: Cascade, so we only need to delete from Permission
      await prisma.permission.delete({ where: { id: ep.id } })
      deletedCount++
    }
  }

  console.log(`Synchronization complete.`)
  console.log(`Created: ${createdCount}, Updated: ${updatedCount}, Deleted: ${deletedCount}`)
  if (createdCount + updatedCount + deletedCount === 0) {
    console.log('All permissions are already up-to-date.')
  }
}

async function seedRolesAndAssignments() {
  console.log('\n--- Starting Role and Assignment Synchronization ---')

  for (const roleData of ROLES_TO_SEED) {
    const role = await prisma.role.upsert({
      where: { name: roleData.name },
      update: { description: roleData.description, isSystemRole: roleData.isSystemRole },
      create: {
        name: roleData.name,
        description: roleData.description,
        isSystemRole: roleData.isSystemRole
      }
    })
    console.log(`Upserted role: ${role.name.toUpperCase()} (ID: ${role.id})`)

    // Find the IDs of the permissions to be assigned
    const permissionsToAssign = await prisma.permission.findMany({
      where: {
        OR: roleData.permissions.map((p) => ({ action: p.action, subject: p.subject }))
      },
      select: { id: true }
    })

    const permissionIds = permissionsToAssign.map((p) => p.id)

    // Clear existing permissions for this role to ensure a clean slate
    await prisma.rolePermission.deleteMany({ where: { roleId: role.id } })

    // Create new assignments
    if (permissionIds.length > 0) {
      await prisma.rolePermission.createMany({
        data: permissionIds.map((permissionId) => ({
          roleId: role.id,
          permissionId: permissionId
        })),
        skipDuplicates: true // Should not be necessary after deleteMany, but good for safety
      })
      console.log(`-> Assigned ${permissionIds.length} permissions to ${role.name.toUpperCase()}.`)
    } else {
      console.log(`-> No permissions assigned to ${role.name.toUpperCase()}.`)
    }
  }
}

async function seedAdminUser() {
  console.log('\n--- Starting Admin User Synchronization ---')
  if (!config.ADMIN_EMAIL) {
    console.warn('ADMIN_EMAIL not set in .env. Skipping admin user creation.')
    return
  }

  const adminRole = await prisma.role.findUnique({ where: { name: 'Admin' } })
  if (!adminRole) {
    console.error('FATAL: Admin role not found in database. Cannot create admin user. Please run role seeding first.')
    return
  }

  const existingAdmin = await prisma.user.findUnique({ where: { email: config.ADMIN_EMAIL } })

  if (existingAdmin) {
    console.log(`Admin user ${config.ADMIN_EMAIL} already exists. Verifying role...`)
    if (existingAdmin.roleId !== adminRole.id) {
      await prisma.user.update({ where: { id: existingAdmin.id }, data: { roleId: adminRole.id } })
      console.log(`-> Role updated for admin user ${config.ADMIN_EMAIL}.`)
    } else {
      console.log(`-> Admin role is correct.`)
    }
    return
  }

  // Create admin user if they don't exist
  if (!config.ADMIN_PASSWORD || !config.ADMIN_NAME) {
    throw new Error('FATAL: Missing ADMIN_PASSWORD or ADMIN_NAME in .env. Cannot create new admin.')
  }
  const hashedPassword = await hashingService.hash(config.ADMIN_PASSWORD)
  await prisma.user.create({
    data: {
      email: config.ADMIN_EMAIL,
      password: hashedPassword,
      roleId: adminRole.id,
      isEmailVerified: true,
      status: 'ACTIVE',
      userProfile: {
        create: {
          username: config.ADMIN_NAME,
          firstName: 'Admin',
          lastName: 'User'
        }
      }
    }
  })
  console.log(`Created new admin user: ${config.ADMIN_EMAIL}`)
}

async function main() {
  try {
    await seedPermissions()
    await seedRolesAndAssignments()
    await seedAdminUser()
    console.log('\n✅ Seeding script finished successfully.')
  } catch (e) {
    console.error('\n❌ Error during seeding script execution:', e)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
  }
}

main()
