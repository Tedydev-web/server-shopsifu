import { DatabaseService } from '../src/shared/database/services/database.service'
import { RoleName } from '../src/shared/constants/role.constant'
import * as argon2 from 'argon2'
const prisma = new DatabaseService()
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
	const hashedPassword = await argon2.hash(process.env.ADMIN_PASSWORD)
	const adminUser = await prisma.user.create({
		data: {
			email: process.env.ADMIN_EMAIL,
			password: hashedPassword,
			name: process.env.ADMIN_NAME,
			phoneNumber: process.env.ADMIN_PHONE_NUMBER,
			roleId: adminRole.id
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
