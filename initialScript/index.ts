import { Role } from '@prisma/client'
import envConfig from '../src/shared/config'
import { HashingService } from '../src/shared/services/hashing.service'
import { PrismaService } from '../src/shared/services/prisma.service'

enum RoleName {
  Admin = 'Admin',
  Client = 'Client',
  Seller = 'Seller'
}
const prisma = new PrismaService()
const hashingService = new HashingService()
const main = async () => {
  const roleCount = await prisma.role.count()
  if (roleCount > 0) {
    throw new Error('Roles already exist')
  }
  const roles = await prisma.role.createMany({
    data: [
      {
        name: RoleName.Admin,
        description: 'Admin role'
      },
      {
        name: RoleName.Client,
        description: 'Client role'
      },
      {
        name: RoleName.Seller,
        description: 'Seller role'
      }
    ]
  })

  const adminRole = await prisma.role.findFirstOrThrow({
    where: {
      name: RoleName.Admin
    }
  })
  const config = envConfig()
  if (!config.ADMIN_PASSWORD || !config.ADMIN_EMAIL || !config.ADMIN_NAME || !config.ADMIN_PHONE_NUMBER) {
    throw new Error('Missing admin environment variables')
  }
  const hashedPassword = await hashingService.hash(config.ADMIN_PASSWORD)
  const adminUser = await prisma.user.create({
    data: {
      email: config.ADMIN_EMAIL,
      password: hashedPassword,
      roleId: adminRole.id,
      userProfile: {
        create: {
          username: config.ADMIN_NAME,
          phoneNumber: config.ADMIN_PHONE_NUMBER
        }
      }
    }
  })
  return {
    createdRoleCount: roles.count,
    adminUser
  }
}

main()
  .then(({ adminUser, createdRoleCount }) => {
    console.log(`Created ${createdRoleCount} roles`)
    console.log(`Created admin user: ${adminUser.email}`)
  })
  .catch(console.error)
