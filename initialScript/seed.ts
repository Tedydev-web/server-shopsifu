import { PrismaClient, Role } from '@prisma/client'
import * as dotenv from 'dotenv'
import * as path from 'path'
import { Logger } from '@nestjs/common'
import { ALL_PERMISSIONS } from '../src/shared/constants/permissions.constants'
import { PermissionDefinition } from 'src/shared/constants/permissions.constants'
import { AppSubject } from '../src/shared/providers/casl/casl-ability.factory'
import * as bcrypt from 'bcrypt'

dotenv.config({ path: path.resolve(process.cwd(), '.env') })

const logger = new Logger('SeedScript')
const prisma = new PrismaClient()

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
    name: 'Seller',
    description: 'Seller role with permissions to manage products and orders.',
    isSystemRole: true
  },
  {
    name: 'Customer',
    description: 'Default role for new users who sign up.',
    isSystemRole: true
  }
]

const PERMISSION_CATEGORIES = {
  AUTH: {
    subjects: ['Auth'],
    actions: ['login', 'register', 'refresh', 'logout', 'verify_otp', 'send_otp', 'reset_password', 'link_social']
  },

  USER_MANAGEMENT: {
    subjects: [AppSubject.User],
    actions: ['create', 'read', 'update', 'delete']
  },

  ROLE_MANAGEMENT: {
    subjects: [AppSubject.Role],
    actions: ['create', 'read', 'update', 'delete']
  },

  PERMISSION_MANAGEMENT: {
    subjects: [AppSubject.Permission],
    actions: ['read']
  },

  PROFILE: {
    subjects: [AppSubject.Profile],
    actions: ['read:own', 'update:own']
  },

  TWO_FACTOR: {
    subjects: [AppSubject.TwoFactor, AppSubject.Password],
    actions: ['create', 'update', 'delete']
  },

  CATALOG: {
    subjects: ['Product', 'Category', 'Brand'],
    actions: ['read']
  },

  PRODUCT_MANAGEMENT: {
    subjects: ['Product', 'SKU'],
    actions: ['create', 'update:own', 'delete:own']
  },

  ORDER_CUSTOMER: {
    subjects: ['Order'],
    actions: ['create', 'read:own']
  },

  ORDER_SELLER: {
    subjects: ['Order'],
    actions: ['read:seller', 'update:seller']
  },

  SYSTEM_ADMIN: {
    subjects: [AppSubject.All],
    actions: ['manage']
  }
}

const ROLE_PERMISSION_MAPPING: Record<string, string[]> = {
  'Super Admin': Object.keys(PERMISSION_CATEGORIES),
  Admin: [
    'AUTH',
    'USER_MANAGEMENT',
    'ROLE_MANAGEMENT',
    'PERMISSION_MANAGEMENT',
    'PROFILE',
    'TWO_FACTOR',
    'CATALOG',
    'PRODUCT_MANAGEMENT',
    'ORDER_CUSTOMER',
    'ORDER_SELLER'
  ],
  Seller: ['AUTH', 'PROFILE', 'TWO_FACTOR', 'CATALOG', 'PRODUCT_MANAGEMENT', 'ORDER_CUSTOMER', 'ORDER_SELLER'],
  Customer: ['AUTH', 'PROFILE', 'TWO_FACTOR', 'CATALOG', 'ORDER_CUSTOMER']
}

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
    await assignPermissionsToRoles(roles)
    await createAdminUser(roles)

    logger.log('✅ Database seeding completed successfully!')
  } catch (error) {
    logger.error('❌ An error occurred during the seeding process:', error)
    process.exit(1)
  } finally {
    await prisma.$disconnect()
  }
}

async function seedPermissions() {
  logger.log('\n[1/3] Synchronizing permissions...')

  const codePermissions = ALL_PERMISSIONS
  const codePermissionMap = new Map<string, PermissionDefinition>()
  for (const p of codePermissions) {
    codePermissionMap.set(`${p.subject}:${p.action}`, p)
  }

  const dbPermissions = await prisma.permission.findMany()
  const dbPermissionMap = new Map<string, (typeof dbPermissions)[0]>()
  for (const p of dbPermissions) {
    dbPermissionMap.set(`${p.subject}:${p.action}`, p)
  }

  const toCreate: PermissionDefinition[] = []
  const toUpdate: { id: number; data: PermissionDefinition }[] = []
  const toDelete: number[] = []

  for (const [key, codePerm] of codePermissionMap.entries()) {
    const dbPerm = dbPermissionMap.get(key)
    if (dbPerm) {
      if (
        dbPerm.description !== codePerm.description ||
        JSON.stringify(dbPerm.conditions) !== JSON.stringify(codePerm.conditions || null)
      ) {
        toUpdate.push({ id: dbPerm.id, data: codePerm })
      }
    } else {
      toCreate.push(codePerm)
    }
  }

  for (const [key, dbPerm] of dbPermissionMap.entries()) {
    if (!codePermissionMap.has(key)) {
      if (!dbPerm.isSystemPermission) {
        toDelete.push(dbPerm.id)
      }
    }
  }

  if (toCreate.length > 0) {
    await prisma.permission.createMany({
      data: toCreate.map((p) => ({
        subject: p.subject,
        action: p.action,
        description: p.description,
        conditions: (p.conditions as any) || undefined,
        isSystemPermission: p.isSystemPermission ?? false
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
          conditions: (update.data.conditions as any) || undefined,
          isSystemPermission: update.data.isSystemPermission ?? false
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

async function getPermissionsByCategory(category: { subjects: string[]; actions: string[] }) {
  return await prisma.permission.findMany({
    where: {
      AND: [
        {
          subject: {
            in: category.subjects
          }
        },
        {
          action: {
            in: category.actions
          }
        }
      ]
    },
    select: { id: true }
  })
}

async function assignPermissionsToRoles(roles: Role[]) {
  logger.log('\n[3/3] Assigning permissions to roles...')

  for (const role of roles) {
    const categoryNames = ROLE_PERMISSION_MAPPING[role.name]
    if (!categoryNames) {
      logger.warn(`⚠️ No permission categories defined for role '${role.name}'. Skipping permission assignment.`)
      continue
    }

    logger.log(`   - Processing permissions for role '${role.name}'...`)

    if (role.isSuperAdmin) {
      await assignAllPermissionsToRole(role.id)
      continue
    }

    let totalAssignedCount = 0

    for (const categoryName of categoryNames) {
      const category = PERMISSION_CATEGORIES[categoryName as keyof typeof PERMISSION_CATEGORIES]
      if (!category) {
        logger.warn(`⚠️ Permission category '${categoryName}' not found. Skipping.`)
        continue
      }

      const permissions = await getPermissionsByCategory(category)
      const newPermissionCount = await assignPermissionsToRole(
        role.id,
        permissions.map((p) => p.id)
      )

      if (newPermissionCount > 0) {
        logger.log(`     - Assigned ${newPermissionCount} permissions from category '${categoryName}'`)
        totalAssignedCount += newPermissionCount
      }
    }

    logger.log(`   ✅ Assigned a total of ${totalAssignedCount} permissions to role '${role.name}'`)
  }

  logger.log('✅ Permission assignment completed.')
}

async function assignPermissionsToRole(roleId: number, permissionIds: number[]): Promise<number> {
  const existingAssignments = await prisma.rolePermission.findMany({
    where: { roleId },
    select: { permissionId: true }
  })
  const existingPermissionIds = new Set(existingAssignments.map((p) => p.permissionId))

  const newPermissions = permissionIds.filter((id) => !existingPermissionIds.has(id))

  if (newPermissions.length > 0) {
    await prisma.rolePermission.createMany({
      data: newPermissions.map((permissionId) => ({
        roleId,
        permissionId
      })),
      skipDuplicates: true
    })
  }

  return newPermissions.length
}

async function assignAllPermissionsToRole(roleId: number) {
  const allPermissions = await prisma.permission.findMany({
    select: { id: true }
  })

  const newPermissionCount = await assignPermissionsToRole(
    roleId,
    allPermissions.map((p) => p.id)
  )

  logger.log(
    `   ✅ Assigned ${newPermissionCount} permissions to Super Admin role. Total permissions: ${allPermissions.length}.`
  )
}

async function createAdminUser(roles: Role[]) {
  logger.log('\n[4/4] Creating default admin user...')

  const adminRole = roles.find((r) => r.name === 'Admin')
  const superAdminRole = roles.find((r) => r.name === 'Super Admin')

  if (!adminRole && !superAdminRole) {
    logger.warn('⚠️ Neither Admin nor Super Admin role found. Skipping admin user creation.')
    return
  }

  const roleToAssign = superAdminRole || adminRole

  const existingAdmin = await prisma.user.findUnique({
    where: { email: DEFAULT_ADMIN.email }
  })

  if (existingAdmin) {
    logger.log(`ℹ️ Admin user with email ${DEFAULT_ADMIN.email} already exists. Skipping creation.`)
    return
  }

  const saltRounds = 10
  const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN.password, saltRounds)

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
