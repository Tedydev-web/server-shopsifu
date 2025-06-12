import { PrismaClient } from '@prisma/client'
import { HashingService } from '../src/shared/services/hashing.service'
import { PermissionScanner } from './permission-scanner'
import { RoleScanner } from './role-scanner'
import * as dotenv from 'dotenv'

// Load environment variables
dotenv.config()

const prisma = new PrismaClient()
const hashingService = new HashingService()

// Get config directly from env
const config = {
  ADMIN_EMAIL: process.env.ADMIN_EMAIL,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
  ADMIN_NAME: process.env.ADMIN_NAME
}

async function scanAndSeedPermissions() {
  console.log('🔍 --- Starting Automatic Permission Scanning and Synchronization ---')

  const scanner = new PermissionScanner()
  const scannedPermissions = await scanner.scanPermissions()
  const permissionsToSeed = scanner.generatePermissionsForSeeding()

  console.log(`\n📊 Permission Summary:`)
  console.log(`  - Total scanned: ${scannedPermissions.length}`)
  console.log(`  - Including manage:all: ${permissionsToSeed.length}`)

  let createdCount = 0
  let updatedCount = 0
  let deletedCount = 0

  const existingPermissions = await prisma.permission.findMany()
  const existingPermissionMap = new Map(existingPermissions.map((p) => [`${p.action}:${p.subject}`, p]))

  for (const p of permissionsToSeed) {
    const key = `${p.action}:${p.subject}`
    const existing = existingPermissionMap.get(key)

    const permissionData = {
      action: p.action,
      subject: p.subject,
      description: p.description
    }

    if (existing) {
      if (existing.description !== permissionData.description) {
        await prisma.permission.update({ where: { id: existing.id }, data: permissionData })
        updatedCount++
        console.log(`  ✓ Updated: ${key}`)
      }
    } else {
      await prisma.permission.create({ data: permissionData })
      createdCount++
      console.log(`  ✓ Created: ${key}`)
    }
  }

  const desiredPermissionKeys = new Set(permissionsToSeed.map((p) => `${p.action}:${p.subject}`))
  for (const ep of existingPermissions) {
    const key = `${ep.action}:${ep.subject}`
    if (!desiredPermissionKeys.has(key)) {
      await prisma.permission.delete({ where: { id: ep.id } })
      deletedCount++
      console.log(`  ✗ Deleted: ${key}`)
    }
  }

  console.log(`\n✅ Permission synchronization complete:`)
  console.log(`  - Created: ${createdCount}`)
  console.log(`  - Updated: ${updatedCount}`)
  console.log(`  - Deleted: ${deletedCount}`)

  if (createdCount + updatedCount + deletedCount === 0) {
    console.log('  - All permissions are already up-to-date.')
  }

  return { createdCount, updatedCount, deletedCount }
}

async function seedRolesAndAssignments() {
  console.log('\n🔐 --- Starting Role and Assignment Synchronization ---')

  // Use role scanner to discover roles automatically
  const roleScanner = new RoleScanner()
  const scannedRoles = await roleScanner.scanRoles()

  if (scannedRoles.length === 0) {
    console.warn('⚠️  No roles discovered. Creating minimal default roles...')
    // Fallback: create essential roles if none found
    scannedRoles.push(
      {
        name: 'Admin',
        description: 'Administrator with full system access',
        isSystemRole: true,
        permissionStrategy: 'ALL',
        permissions: [],
        foundIn: 'code'
      },
      {
        name: 'Customer',
        description: 'Standard customer account',
        isSystemRole: false,
        permissionStrategy: 'CUSTOM',
        permissions: [
          { action: 'login', subject: 'Auth' },
          { action: 'register', subject: 'Auth' },
          { action: 'read', subject: 'UserProfile' },
          { action: 'update', subject: 'UserProfile' }
        ],
        foundIn: 'code'
      }
    )
  }

  const allPermissions = await prisma.permission.findMany()
  const permissionMap = new Map(allPermissions.map((p) => [`${p.action}:${p.subject}`, p]))

  for (const roleConfig of scannedRoles) {
    const role = await prisma.role.upsert({
      where: { name: roleConfig.name },
      update: {
        description: roleConfig.description,
        isSystemRole: roleConfig.isSystemRole
      },
      create: {
        name: roleConfig.name,
        description: roleConfig.description,
        isSystemRole: roleConfig.isSystemRole
      }
    })
    console.log(`✓ Upserted role: ${role.name.toUpperCase()} (ID: ${role.id}) [${roleConfig.foundIn}]`)

    let permissionIds: number[] = []

    if (roleConfig.permissionStrategy === 'ALL') {
      permissionIds = allPermissions.map((p) => p.id)
      console.log(`  -> Admin role: Assigned ALL ${permissionIds.length} permissions`)
    } else {
      const rolePermissions = roleConfig.permissions || []
      permissionIds = rolePermissions
        .map((rp) => {
          const key = `${rp.action}:${rp.subject}`
          const permission = permissionMap.get(key)
          if (!permission) {
            console.warn(`  ⚠️  Permission not found: ${key}`)
            return null
          }
          return permission.id
        })
        .filter((id): id is number => id !== null)

      console.log(`  -> ${roleConfig.name} role: Assigned ${permissionIds.length} custom permissions`)
    }

    await prisma.rolePermission.deleteMany({ where: { roleId: role.id } })

    if (permissionIds.length > 0) {
      await prisma.rolePermission.createMany({
        data: permissionIds.map((permissionId) => ({
          roleId: role.id,
          permissionId: permissionId
        })),
        skipDuplicates: true
      })
    }
  }

  // Export scanned roles for review
  await roleScanner.exportToFile('./initialScript/scanned-roles.ts')

  console.log('✅ Role and assignment synchronization complete')
}

async function seedAdminUser() {
  console.log('\n👤 --- Starting Admin User Synchronization ---')

  if (!config.ADMIN_EMAIL) {
    console.warn('ADMIN_EMAIL not set in .env. Skipping admin user creation.')
    return
  }

  const adminRole = await prisma.role.findUnique({ where: { name: 'Admin' } })
  if (!adminRole) {
    console.error('FATAL: Admin role not found in database. Cannot create admin user.')
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
  console.log(`✓ Created new admin user: ${config.ADMIN_EMAIL}`)
}

async function main() {
  try {
    console.log('🚀 Starting Automatic Permission & Role Seeding Script')
    console.log('===================================================\n')

    console.log('🎯 Features:')
    console.log('  • Auto-discovery of permissions from codebase')
    console.log('  • Auto-discovery of roles from database & code')
    console.log('  • Intelligent permission categorization')
    console.log('  • Admin role gets ALL permissions automatically')
    console.log('  • Smart defaults for common roles\n')

    console.log('⏳ Step 1: Scanning and seeding permissions...')
    await scanAndSeedPermissions()
    console.log('✅ Step 1 completed!\n')

    console.log('⏳ Step 2: Scanning and seeding roles...')
    await seedRolesAndAssignments()
    console.log('✅ Step 2 completed!\n')

    console.log('⏳ Step 3: Creating admin user...')
    await seedAdminUser()
    console.log('✅ Step 3 completed!\n')

    console.log('\n🎉 ================================')
    console.log('✅ Automated seeding completed successfully!')
    console.log('✅ No more hardcoded configurations!')
    console.log('================================')
  } catch (e) {
    console.error('\n💥 ================================')
    console.error('❌ Error during seeding script execution:', e)
    console.error('================================')
    process.exit(1)
  } finally {
    console.log('🔧 Disconnecting from database...')
    await prisma.$disconnect()
    console.log('✅ Database disconnected successfully!')
    console.log('🏁 Script execution finished!')
  }
}

void main()
