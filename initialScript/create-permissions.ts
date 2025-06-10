import { PrismaClient } from '@prisma/client'
import { HashingService } from '../src/shared/services/hashing.service'
import appConfig from '../src/shared/config'
import * as fs from 'fs'
import * as path from 'path'

const prisma = new PrismaClient()
const hashingService = new HashingService()
const config = appConfig()

// IMPORTANT: Define a system user ID that exists in your User table.
// This ID will be used for createdById and updatedById fields for permissions created by this script.
// TODO: Replace with a real system user ID or make configurable

interface DesiredPermission {
  action: string
  subject: string
  category: string
  description?: string | null
}

function discoverPermissionsFromControllers(): DesiredPermission[] {
  const discoveredPermissions = new Map<string, DesiredPermission>()
  const routesDir = path.join(__dirname, '../src/routes')

  const controllerFiles = getAllFiles(routesDir).filter((file) => file.endsWith('.controller.ts'))

  const permissionRegex = /ability\.can\(\s*Action\.(\w+)\s*,\s*'(\w+)'\s*\)/g

  controllerFiles.forEach((file) => {
    const content = fs.readFileSync(file, 'utf8')
    let match
    while ((match = permissionRegex.exec(content)) !== null) {
      const action = match[1].toLowerCase()
      const subject = match[2]
      const key = `${action}:${subject}`

      if (!discoveredPermissions.has(key)) {
        discoveredPermissions.set(key, {
          action: action,
          subject: subject,
          category: subject.replace('UserProfile', 'Profile'), // Simple mapping for category
          description: `Allows to ${action} ${subject}(s)`
        })
      }
    }
  })

  return Array.from(discoveredPermissions.values())
}

function getAllFiles(dirPath: string, arrayOfFiles: string[] = []): string[] {
  const files = fs.readdirSync(dirPath)

  files.forEach(function (file) {
    if (fs.statSync(path.join(dirPath, file)).isDirectory()) {
      arrayOfFiles = getAllFiles(path.join(dirPath, file), arrayOfFiles)
    } else {
      arrayOfFiles.push(path.join(dirPath, file))
    }
  })

  return arrayOfFiles
}

async function seedPermissions() {
  console.log('Starting permission synchronization...')
  let createdCount = 0
  let updatedCount = 0
  let deletedCount = 0

  const desiredPermissions = discoverPermissionsFromControllers()

  // Always add the 'manage all' permission for admins
  desiredPermissions.push({
    action: 'manage',
    subject: 'all',
    category: 'System',
    description: 'Grants full access to all resources.'
  })

  const existingPermissions = await prisma.permission.findMany()

  // Sync: Create or Update
  for (const dp of desiredPermissions) {
    const permissionData = {
      action: dp.action,
      subject: dp.subject,
      category: dp.category,
      description: dp.description ?? null
    }

    const existingPermission = existingPermissions.find((p) => p.action === dp.action && p.subject === dp.subject)

    if (existingPermission) {
      if (
        existingPermission.category !== permissionData.category ||
        existingPermission.description !== permissionData.description
      ) {
        await prisma.permission.update({
          where: { id: existingPermission.id },
          data: {
            category: permissionData.category,
            description: permissionData.description
          }
        })
        updatedCount++
      }
    } else {
      await prisma.permission.create({ data: permissionData })
      createdCount++
    }
  }

  // Sync: Delete
  const desiredPermissionKeys = new Set(desiredPermissions.map((p) => `${p.action}:${p.subject}`))
  for (const ep of existingPermissions) {
    const key = `${ep.action}:${ep.subject}`
    if (!desiredPermissionKeys.has(key)) {
      // Before deleting, ensure it's not linked to any roles
      await prisma.rolePermission.deleteMany({ where: { permissionId: ep.id } })
      await prisma.permission.delete({ where: { id: ep.id } })
      deletedCount++
    }
  }

  console.log(`Discovered ${desiredPermissions.length - 1} permissions from controllers.`)
  console.log(`Created ${createdCount} new permissions.`)
  console.log(`Updated ${updatedCount} existing permissions.`)
  console.log(`Deleted ${deletedCount} obsolete permissions.`)
  if (createdCount === 0 && updatedCount === 0 && deletedCount === 0) {
    console.log('All permissions are already up to date.')
  }
}

async function seedRolesAndAssignments() {
  console.log('Starting role and assignment synchronization...')

  // 1. Create/find Admin role and set as system role
  const adminRoleName = 'Admin'
  const adminRole = await prisma.role.upsert({
    where: { name: adminRoleName },
    update: { isSystemRole: true },
    create: {
      name: adminRoleName,
      description: 'Administrator role with all permissions',
      isSystemRole: true
    }
  })
  console.log(`Upserted ADMIN role (ID: ${adminRole.id}) and ensured it is a system role.`)

  // 2. Assign 'manage all' permission to Admin role
  const manageAllPermission = await prisma.permission.findUnique({
    where: { UQ_action_subject: { action: 'manage', subject: 'all' } }
  })

  if (manageAllPermission) {
    await prisma.rolePermission.createMany({
      data: [{ roleId: adminRole.id, permissionId: manageAllPermission.id }],
      skipDuplicates: true
    })
    console.log(`Ensured 'manage:all' permission is assigned to ADMIN role.`)
  } else {
    console.warn(`Could not find 'manage:all' permission to assign to ADMIN role.`)
  }

  // 3. Create/find Customer role
  const customerRoleName = 'Customer'
  const customerRole = await prisma.role.upsert({
    where: { name: customerRoleName },
    update: {},
    create: {
      name: customerRoleName,
      description: 'Standard customer role with basic permissions'
    }
  })
  console.log(`Upserted CUSTOMER role (ID: ${customerRole.id}).`)

  // 4. Assign specific permissions to Customer role
  const customerPermissions = await prisma.permission.findMany({
    where: {
      OR: [
        { subject: 'Product', action: 'read' },
        { subject: 'Category', action: 'read' },
        { subject: 'Brand', action: 'read' },
        { subject: 'UserProfile', action: 'read' },
        { subject: 'UserProfile', action: 'update' },
        { subject: 'Device', action: 'read' },
        { subject: 'Device', action: 'update' },
        { subject: 'Device', action: 'delete' }
      ]
    }
  })

  if (customerPermissions.length > 0) {
    await prisma.rolePermission.createMany({
      data: customerPermissions.map((p) => ({
        roleId: customerRole.id,
        permissionId: p.id
      })),
      skipDuplicates: true
    })
    console.log(`Assigned ${customerPermissions.length} permissions to CUSTOMER role.`)
  }
}

async function seedAdminUser() {
  console.log('Starting admin user synchronization...')
  if (!config.ADMIN_EMAIL) {
    console.warn('ADMIN_EMAIL not set in environment variables. Skipping admin user creation.')
    return
  }

  const adminRole = await prisma.role.findUnique({ where: { name: 'Admin' } })
  if (!adminRole) {
    console.error('Admin role not found. Cannot create admin user.')
    return
  }

  const existingAdmin = await prisma.user.findUnique({ where: { email: config.ADMIN_EMAIL } })

  if (existingAdmin) {
    console.log(`Admin user ${config.ADMIN_EMAIL} already exists.`)
    // Optionally update roleId if it's incorrect
    if (existingAdmin.roleId !== adminRole.id) {
      await prisma.user.update({ where: { id: existingAdmin.id }, data: { roleId: adminRole.id } })
      console.log(`Updated role for admin user ${config.ADMIN_EMAIL}.`)
    }
    return
  }

  // Create admin user if they don't exist
  if (!config.ADMIN_PASSWORD || !config.ADMIN_NAME) {
    throw new Error('Missing admin environment variables (ADMIN_PASSWORD, ADMIN_NAME) for new admin creation.')
  }
  const hashedPassword = await hashingService.hash(config.ADMIN_PASSWORD)
  await prisma.user.create({
    data: {
      email: config.ADMIN_EMAIL,
      password: hashedPassword,
      roleId: adminRole.id,
      isEmailVerified: true,
      userProfile: {
        create: {
          username: config.ADMIN_NAME,
          firstName: 'Admin',
          lastName: 'User'
        }
      }
    }
  })
  console.log(`Created admin user: ${config.ADMIN_EMAIL}`)
}

async function main() {
  try {
    await seedPermissions()
    await seedRolesAndAssignments()
    await seedAdminUser()
    console.log('Seeding script finished successfully.')
  } catch (e) {
    console.error('Error during seeding script:', e)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
  }
}

main()
