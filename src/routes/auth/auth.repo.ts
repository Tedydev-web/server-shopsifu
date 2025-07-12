import { Injectable } from '@nestjs/common'
import { DeviceType, RefreshTokenType, VerificationCodeType } from 'src/routes/auth/auth.model'
import { TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { DatabaseService } from 'src/shared/database/services/database.service'
import { RoleType } from 'src/shared/models/shared-role.model'
import { UserType } from 'src/shared/models/shared-user.model'
import { WhereUniqueUserType } from 'src/shared/repositories/shared-user.repo'

@Injectable()
export class AuthRepository {
	constructor(private readonly databaseService: DatabaseService) {}

	async createUser(
		user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'roleId'>
	): Promise<Omit<UserType, 'password' | 'totpSecret'>> {
		return this.databaseService.user.create({
			data: user,
			omit: {
				password: true,
				totpSecret: true
			}
		})
	}

	async createUserInclueRole(
		user: Pick<UserType, 'email' | 'name' | 'password' | 'phoneNumber' | 'avatar' | 'roleId'>
	): Promise<UserType & { role: RoleType }> {
		return this.databaseService.user.create({
			data: user,
			include: {
				role: true
			}
		})
	}

	async createVerificationCode(
		payload: Pick<VerificationCodeType, 'email' | 'type' | 'code' | 'expiresAt'>
	): Promise<VerificationCodeType> {
		return this.databaseService.verificationCode.upsert({
			where: {
				email_code_type: {
					email: payload.email,
					code: payload.code,
					type: payload.type
				}
			},
			create: payload,
			update: {
				code: payload.code,
				expiresAt: payload.expiresAt
			}
		})
	}

	async findUniqueVerificationCode(
		uniqueValue:
			| { id: number }
			| {
					email_code_type: {
						email: string
						code: string
						type: TypeOfVerificationCodeType
					}
			  }
	): Promise<VerificationCodeType | null> {
		return this.databaseService.verificationCode.findUnique({
			where: uniqueValue
		})
	}

	createRefreshToken(data: { token: string; userId: number; expiresAt: Date; deviceId: number }) {
		return this.databaseService.refreshToken.create({
			data
		})
	}

	createDevice(
		data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'> & Partial<Pick<DeviceType, 'lastActive' | 'isActive'>>
	) {
		return this.databaseService.device.create({
			data
		})
	}

	async findUniqueUserIncludeRole(where: WhereUniqueUserType): Promise<(UserType & { role: RoleType }) | null> {
		return this.databaseService.user.findFirst({
			where: {
				...where,
				deletedAt: null
			},
			include: {
				role: true
			}
		})
	}

	async findUniqueRefreshTokenIncludeUserRole(where: {
		token: string
	}): Promise<(RefreshTokenType & { user: UserType & { role: RoleType } }) | null> {
		return this.databaseService.refreshToken.findUnique({
			where,
			include: {
				user: {
					include: {
						role: true
					}
				}
			}
		})
	}

	updateDevice(deviceId: number, data: Partial<DeviceType>): Promise<DeviceType> {
		return this.databaseService.device.update({
			where: {
				id: deviceId
			},
			data
		})
	}

	deleteRefreshToken(where: { token: string }): Promise<RefreshTokenType> {
		return this.databaseService.refreshToken.delete({
			where
		})
	}

	deleteVerificationCode(
		uniqueValue:
			| { id: number }
			| {
					email_code_type: {
						email: string
						code: string
						type: TypeOfVerificationCodeType
					}
			  }
	): Promise<VerificationCodeType> {
		return this.databaseService.verificationCode.delete({
			where: uniqueValue
		})
	}
}
