import { InjectQueue } from '@nestjs/bullmq'
import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import { Role } from '@prisma/client'
import { Queue } from 'bullmq'

import { APP_BULL_QUEUES } from 'src/shared/enums/app.enum'
import { AWS_SES_EMAIL_TEMPLATES } from 'src/shared/aws/enums/aws.ses.enum'
import { DatabaseService } from 'src/shared/database/services/database.service'
import { ISendEmailBasePayload, IWelcomeEmailDataPaylaod } from 'src/shared/helper/interfaces/email.interface'

import { HelperEncryptionService } from 'src/shared/helper/services/helper.encryption.service'
import { IAuthUser } from 'src/shared/request/interfaces/request.interface'
import { LoginBodyType, RegisterBodyType } from './auth.model'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { SharedRoleRepository } from 'src/shared/repositories/shared-role.repo'

@Injectable()
export class AuthService {
	constructor(
		private readonly databaseService: DatabaseService,
		private readonly helperEncryptionService: HelperEncryptionService,
		private readonly sharedUserRepository: SharedUserRepository,
		private readonly sharedRoleRepository: SharedRoleRepository,
		@InjectQueue(APP_BULL_QUEUES.EMAIL)
		private emailQueue: Queue
	) {}

	public async login(data: LoginBodyType & { userAgent: string; ip: string }) {
		try {
			const { email, password, userAgent, ip } = data

			const user = await this.sharedUserRepository.findUnique({ email })

			if (!user) {
				throw new HttpException('user.error.userNotFound', HttpStatus.NOT_FOUND)
			}

			const passwordMatched = await this.helperEncryptionService.match(user.password, password)

			if (!passwordMatched) {
				throw new HttpException('auth.error.invalidPassword', HttpStatus.BAD_REQUEST)
			}

			const tokens = await this.helperEncryptionService.createJwtTokens({
				roleId: user.roleId,
				userId: user.id.toString()
			})

			return {
				...tokens,
				user
			}
		} catch (error) {
			throw error
		}
	}

	public async signup(data: RegisterBodyType) {
		try {
			const { email, phoneNumber, name, password } = data

			const existingUser = await this.sharedUserRepository.findUnique({
				email
			})

			if (existingUser) {
				throw new HttpException('user.error.userExists', HttpStatus.CONFLICT)
			}

			const hashed = await this.helperEncryptionService.createHash(password)
			const clientRoleId = await this.sharedRoleRepository.getClientRoleId()
			const createdUser = await this.databaseService.user.create({
				data: {
					email,
					password: hashed,
					phoneNumber,
					name,
					roleId: clientRoleId
				}
			})

			const tokens = await this.helperEncryptionService.createJwtTokens({
				roleId: createdUser.roleId,
				userId: createdUser.id.toString()
			})

			this.emailQueue.add(
				AWS_SES_EMAIL_TEMPLATES.WELCOME_EMAIL,
				{
					data: {
						email: createdUser.email
					},
					toEmails: [email]
				} as ISendEmailBasePayload<IWelcomeEmailDataPaylaod>,
				{ delay: 15000 }
			)

			return {
				...tokens,
				user: createdUser
			}
		} catch (error) {
			throw error
		}
	}

	public async refreshTokens(payload: IAuthUser) {
		return this.helperEncryptionService.createJwtTokens({
			userId: payload.userId,
			roleId: payload.roleId
		})
	}
}
