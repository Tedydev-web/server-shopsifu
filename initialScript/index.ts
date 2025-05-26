import { PrismaService } from '../src/shared/services/prisma.service'
import { HashingService } from '../src/shared/services/hashing.service'
import { RolesService } from '../src/routes/auth/roles.service'
import envConfig from '../src/shared/config'
import { RoleName } from '../src/routes/auth/constants/role.constant'

const prisma = new PrismaService()
const hashingService = new HashingService()
const rolesService = new RolesService(prisma)

async function main() {
  // Create roles if they don't exist
  const adminRoleNameValue = RoleName.Admin
  const clientRoleNameValue = RoleName.Client

  let adminRole = await prisma.role.findUnique({
    where: { name: adminRoleNameValue }
  })

  if (!adminRole) {
    adminRole = await prisma.role.create({
      data: {
        name: adminRoleNameValue,
        description: 'Administrator role with full access',
        isActive: true
      }
    })
    console.log(`Role '${adminRoleNameValue}' created.`)
  } else {
    console.log(`Role '${adminRoleNameValue}' already exists.`)
  }

  let clientRole = await prisma.role.findUnique({
    where: { name: clientRoleNameValue }
  })

  if (!clientRole) {
    clientRole = await prisma.role.create({
      data: {
        name: clientRoleNameValue,
        description: 'Client role with limited access',
        isActive: true
      }
    })
    console.log(`Role '${clientRoleNameValue}' created.`)
  } else {
    console.log(`Role '${clientRoleNameValue}' already exists.`)
  }

  // Create admin user if it doesn't exist and required ENV vars are set
  const adminEmail = envConfig.ADMIN_EMAIL
  if (adminEmail) {
    const existingAdmin = await prisma.user.findUnique({ where: { email: adminEmail } })
    if (!existingAdmin) {
      if (
        envConfig.ADMIN_EMAIL &&
        envConfig.ADMIN_DEFAULT_PASSWORD &&
        envConfig.ADMIN_NAME &&
        envConfig.ADMIN_DEFAULT_PHONE_NUMBER
      ) {
        const clientRoleId = await rolesService.getClientRoleId()
        if (!clientRoleId) {
          console.error('Client role not found, cannot create admin user.')
        } else {
          const hashedPassword = await hashingService.hash(envConfig.ADMIN_DEFAULT_PASSWORD)
          await prisma.user.create({
            data: {
              email: envConfig.ADMIN_EMAIL,
              name: envConfig.ADMIN_NAME,
              password: hashedPassword,
              phoneNumber: envConfig.ADMIN_DEFAULT_PHONE_NUMBER,
              roleId: clientRoleId,
              status: 'ACTIVE'
            }
          })
          console.log(`Admin user '${envConfig.ADMIN_EMAIL}' created.`)
        }
      } else {
        console.log(
          'Admin user creation skipped because ADMIN_EMAIL, ADMIN_DEFAULT_PASSWORD, ADMIN_NAME, or ADMIN_DEFAULT_PHONE_NUMBER is not set in .env'
        )
      }
    } else {
      console.log(`Admin user '${envConfig.ADMIN_EMAIL}' already exists.`)
    }
  } else {
    console.log('Admin user creation skipped because ADMIN_EMAIL is not set in .env')
  }
}

main()
  .catch((e) => {
    console.error(e)
    // Không cần await ở đây nếu $disconnect không trả về Promise hoặc không critical
    prisma.$disconnect()
    process.exit(1)
  })
  .finally(() => {
    // Đảm bảo finally không trả về Promise nếu không cần thiết
    prisma.$disconnect()
  })
