import { HashingService } from '../../src/shared/services/hashing.service'
import { PrismaClient } from '@prisma/client'
import { RoleName } from '../../src/shared/constants/role.constant'
import { UserStatus } from '../../src/shared/constants/user.constant'

const prisma = new PrismaClient()
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
  const hashedPassword = await hashingService.hash(process.env.ADMIN_PASSWORD as string)
  const adminUser = await prisma.user.create({
    data: {
      email: process.env.ADMIN_EMAIL as string,
      password: hashedPassword,
      name: process.env.ADMIN_NAME as string,
      phoneNumber: process.env.ADMIN_PHONE_NUMBER as string,
      roleId: adminRole.id,
      status: UserStatus.ACTIVE
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
