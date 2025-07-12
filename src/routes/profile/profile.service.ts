import { Injectable } from '@nestjs/common'
import { InvalidPasswordException, NotFoundRecordException } from 'src/shared/error'
import { ChangePasswordBodyType, UpdateMeBodyType } from './profile.model'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { HelperEncryptionService } from 'src/shared/helper/services/helper.encryption.service'

@Injectable()
export class ProfileService {
	constructor(
		private readonly sharedUserRepository: SharedUserRepository,
		private readonly helperEncryptionService: HelperEncryptionService
	) {}

	async getProfile(userId: number) {
		const user = await this.sharedUserRepository.findUniqueIncludeRolePermissions({
			id: userId
		})

		if (!user) {
			throw NotFoundRecordException
		}

		return user
	}

	async updateProfile({ userId, body }: { userId: number; body: UpdateMeBodyType }) {
		try {
			return await this.sharedUserRepository.update(
				{ id: userId },
				{
					...body,
					updatedById: userId
				}
			)
		} catch (error) {
			if (isUniqueConstraintPrismaError(error)) {
				throw NotFoundRecordException
			}
			throw error
		}
	}

	async changePassword({
		userId,
		body
	}: {
		userId: number
		body: Omit<ChangePasswordBodyType, 'confirmNewPassword'>
	}) {
		try {
			const { password, newPassword } = body
			const user = await this.sharedUserRepository.findUnique({
				id: userId
			})
			if (!user) {
				throw NotFoundRecordException
			}
			const isPasswordMatch = await this.helperEncryptionService.match(password, user.password)
			if (!isPasswordMatch) {
				throw InvalidPasswordException
			}
			const hashedPassword = await this.helperEncryptionService.createHash(newPassword)

			await this.sharedUserRepository.update(
				{ id: userId },
				{
					password: hashedPassword,
					updatedById: userId
				}
			)
			return {
				message: 'Password changed successfully'
			}
		} catch (error) {
			if (isUniqueConstraintPrismaError(error)) {
				throw NotFoundRecordException
			}
			throw error
		}
	}
}
