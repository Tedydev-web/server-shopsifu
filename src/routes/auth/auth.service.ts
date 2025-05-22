import { HttpException, Injectable, HttpStatus, Logger } from '@nestjs/common'
import { addMilliseconds } from 'date-fns'
import {
  DisableTwoFactorBodyType,
  LoginBodyType,
  RegisterBodyType,
  ResetPasswordBodyType,
  SendOTPBodyType,
  TwoFactorVerifyBodyType,
  VerifyCodeBodyType
} from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { RolesService } from 'src/routes/auth/roles.service'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { TokenService } from 'src/shared/services/token.service'
import ms from 'ms'
import {
  TokenType,
  TwoFactorMethodType,
  TypeOfVerificationCode,
  CookieNames,
  REQUEST_USER_KEY
} from 'src/shared/constants/auth.constant'
import { EmailService } from 'src/shared/services/email.service'
import { AccessTokenPayload, AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import {
  EmailAlreadyExistsException,
  EmailNotFoundException,
  InvalidOTPTokenException,
  InvalidPasswordException,
  InvalidTOTPException,
  OTPTokenExpiredException,
  TOTPAlreadyEnabledException,
  TOTPNotEnabledException,
  UnauthorizedAccessException,
  DeviceMismatchException,
  InvalidDeviceException,
  DeviceSetupFailedException,
  DeviceAssociationFailedException,
  AbsoluteSessionLifetimeExceededException
} from 'src/routes/auth/auth.error'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { v4 as uuidv4 } from 'uuid'
import envConfig from 'src/shared/config'
import { Response } from 'express'
import { Request } from 'express'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma, VerificationToken as PrismaVerificationToken, Device } from '@prisma/client'
import { TwoFactorMethodTypeType } from 'src/shared/constants/auth.constant'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { OtpService } from 'src/shared/services/otp.service'
import { DeviceService } from 'src/shared/services/device.service'

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepository: AuthRepository,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly twoFactorService: TwoFactorService,
    private readonly auditLogService: AuditLogService,
    private readonly otpService: OtpService,
    private readonly deviceService: DeviceService
  ) {}

  async verifyCode(body: VerifyCodeBodyType & { userAgent: string; ip: string }) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'OTP_VERIFY_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { type: body.type, codeProvided: !!body.code }
    }
    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        await this.otpService.validateVerificationCode({
          email: body.email,
          code: body.code,
          type: body.type,
          tx
        })

        const existingUser = await this.sharedUserRepository.findUnique({ email: body.email })
        if (existingUser) {
          auditLogEntry.userId = existingUser.id
        }

        let userId: number | undefined = undefined
        if (body.type !== TypeOfVerificationCode.REGISTER) {
          const userFromSharedRepo = await this.sharedUserRepository.findUnique({ email: body.email })
          if (userFromSharedRepo) {
            userId = userFromSharedRepo.id
          }
        }

        let deviceId: number | undefined = undefined
        if (userId) {
          try {
            const device = await this.deviceService.findOrCreateDevice(
              {
                userId,
                userAgent: body.userAgent,
                ip: body.ip
              },
              tx as any
            )
            deviceId = device.id
          } catch (error) {
            auditLogEntry.errorMessage = DeviceSetupFailedException.message
            auditLogEntry.notes = 'Device creation/finding failed during OTP verification'
            console.error('Could not create or find device in verifyCode', error)
          }
        }

        const token = await this.otpService.createOtpToken({
          email: body.email,
          type: body.type,
          userId,
          deviceId,
          tx
        })

        await this.otpService.deleteVerificationCode(body.email, body.code, body.type, tx)

        return { otpToken: token }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'OTP_VERIFY_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async sendOTP(body: SendOTPBodyType) {
    const user = await this.sharedUserRepository.findUnique({
      email: body.email
    })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw EmailAlreadyExistsException
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      throw EmailNotFoundException
    }

    return this.otpService.sendOTP(body.email, body.type)
  }

  async register(body: RegisterBodyType & { userAgent?: string; ip?: string }) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'USER_REGISTER_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        otpTokenProvided: !!body.otpToken,
        nameProvided: !!body.name,
        phoneNumberProvided: !!body.phoneNumber
      }
    }

    try {
      const user = await this.prismaService.$transaction(async (tx) => {
        const verificationToken = await this.otpService.validateVerificationToken({
          token: body.otpToken,
          email: body.email,
          type: TypeOfVerificationCode.REGISTER,
          tokenType: TokenType.OTP,
          tx
        })

        if (verificationToken.userId) {
          auditLogEntry.userId = verificationToken.userId
        }
        auditLogEntry.details.verificationTokenDeviceId = verificationToken.deviceId

        if (verificationToken.deviceId && body.userAgent && body.ip) {
          const isValidDevice = await this.deviceService.validateDevice(
            verificationToken.deviceId,
            body.userAgent,
            body.ip,
            tx
          )
          if (!isValidDevice) {
            auditLogEntry.errorMessage = DeviceMismatchException.message
            auditLogEntry.details.reason = 'DEVICE_MISMATCH_ON_REGISTER'
            auditLogEntry.details.validatedDeviceId = verificationToken.deviceId
            throw DeviceMismatchException
          }
          auditLogEntry.details.deviceValidatedOnRegister = true
        }

        const clientRoleId = await this.rolesService.getClientRoleId()
        const hashedPassword = await this.hashingService.hash(body.password)

        const existingUserCheck = await tx.user.findUnique({ where: { email: body.email }, select: { id: true } })
        if (existingUserCheck) {
          auditLogEntry.errorMessage = EmailAlreadyExistsException.message
          auditLogEntry.details.reason = 'EMAIL_ALREADY_EXISTS_PRE_CREATE_CHECK'
        }

        const createdUser = await this.authRepository.createUser(
          {
            email: body.email,
            name: body.name,
            phoneNumber: body.phoneNumber,
            password: hashedPassword,
            roleId: clientRoleId
          },
          tx
        )

        auditLogEntry.userId = createdUser.id
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_REGISTER_SUCCESS'
        auditLogEntry.details.roleIdAssigned = clientRoleId

        await this.otpService.deleteOtpToken(body.otpToken, tx)

        return createdUser
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return user
    } catch (error) {
      if (
        isUniqueConstraintPrismaError(error) ||
        (auditLogEntry.details.reason === 'EMAIL_ALREADY_EXISTS_PRE_CREATE_CHECK' && !auditLogEntry.errorMessage)
      ) {
        auditLogEntry.errorMessage = EmailAlreadyExistsException.message
        auditLogEntry.details.reason = 'EMAIL_ALREADY_EXISTS'
      } else if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during registration'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      if (isUniqueConstraintPrismaError(error)) {
        throw EmailAlreadyExistsException
      }
      throw error
    }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res?: Response) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'USER_LOGIN_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        rememberMeRequested: body.rememberMe
      }
    }
    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        const user = await tx.user.findUnique({
          where: { email: body.email },
          include: { role: true }
        })
        if (!user) {
          auditLogEntry.errorMessage = EmailNotFoundException.message
          auditLogEntry.details.reason = 'USER_NOT_FOUND'
          throw EmailNotFoundException
        }
        auditLogEntry.userId = user.id

        const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
        if (!isPasswordMatch) {
          console.warn('[DEBUG AuthService login] Invalid password for user:', user.email)
          auditLogEntry.errorMessage = InvalidPasswordException.message
          auditLogEntry.details.reason = 'INVALID_PASSWORD'
          throw InvalidPasswordException
        }

        let device: Device
        try {
          device = await this.deviceService.findOrCreateDevice(
            {
              userId: user.id,
              userAgent: body.userAgent,
              ip: body.ip
            },
            tx as any
          )
          auditLogEntry.details.deviceId = device.id
        } catch (error) {
          console.error('[DEBUG AuthService login] Error creating/finding device:', error)
          auditLogEntry.errorMessage = DeviceSetupFailedException.message
          auditLogEntry.details.deviceError = 'DeviceSetupFailed'
          throw DeviceSetupFailedException
        }

        if (!this.deviceService.isSessionValid(device)) {
          this.logger.warn(
            `[SECURITY AuthService login] Absolute session lifetime exceeded for user ${user.id}, device ${device.id}. Forcing re-login.`
          )
          await this.tokenService.deleteAllRefreshTokensForDevice(device.id, tx as any)
          auditLogEntry.errorMessage = AbsoluteSessionLifetimeExceededException.message
          auditLogEntry.details.reason = 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED_LOGIN'
          auditLogEntry.notes = `All refresh tokens for device ${device.id} invalidated due to absolute session lifetime exceeded during login.`
          throw AbsoluteSessionLifetimeExceededException
        }

        if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod) {
          auditLogEntry.details.twoFactorMethod = user.twoFactorMethod
          if (device.isTrusted) {
            this.logger.debug(`Device ${device.id} is trusted for user ${user.id}. Skipping 2FA.`)
            auditLogEntry.notes = '2FA skipped: Trusted device.'
          } else {
            const otpToken = uuidv4()
            await this.authRepository.createVerificationToken(
              {
                token: otpToken,
                email: user.email,
                type: TypeOfVerificationCode.LOGIN_2FA,
                tokenType: TokenType.OTP,
                userId: user.id,
                deviceId: device.id,
                metadata: JSON.stringify({ rememberMe: body.rememberMe }),
                expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
              },
              tx
            )
            auditLogEntry.status = AuditLogStatus.SUCCESS
            auditLogEntry.notes = '2FA required: Device not trusted.'
            return {
              message: 'Auth.Login.2FARequired',
              loginSessionToken: otpToken,
              twoFactorMethod: user.twoFactorMethod,
              askToTrustDevice: true
            }
          }
        }

        const { accessToken, refreshToken, maxAgeForRefreshTokenCookie } = await this.generateTokens(
          {
            userId: user.id,
            deviceId: device.id,
            roleId: user.roleId,
            roleName: user.role.name
          },
          tx,
          body.rememberMe
        )

        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshToken, maxAgeForRefreshTokenCookie)
        } else {
          console.warn(
            '[DEBUG AuthService login - Direct login] Response object (res) is NOT present. Cookies will not be set by login function directly.'
          )
        }

        // Nếu người dùng chọn "Remember Me" và thiết bị chưa được tin cậy, hãy tin cậy nó
        if (body.rememberMe && !device.isTrusted) {
          try {
            await this.deviceService.trustDevice(device.id, user.id, tx as any)
            auditLogEntry.notes = (auditLogEntry.notes ? auditLogEntry.notes + '; ' : '') + 'Device trusted.'
            this.logger.debug(`Device ${device.id} trusted for user ${user.id} due to rememberMe selection.`)
          } catch (trustError) {
            this.logger.error(`Failed to trust device ${device.id} for user ${user.id}`, trustError)
            auditLogEntry.notes = (auditLogEntry.notes ? auditLogEntry.notes + '; ' : '') + 'Failed to trust device.'
          }
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_LOGIN_SUCCESS'
        return {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name
        }
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during login'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async generateTokens(
    { userId, deviceId, roleId, roleName }: AccessTokenPayloadCreate,
    prismaTx?: Prisma.TransactionClient,
    rememberMe?: boolean
  ) {
    return this.tokenService.generateTokens({ userId, deviceId, roleId, roleName }, prismaTx as any, rememberMe)
  }

  async refreshToken({ userAgent, ip }: { userAgent: string; ip: string }, req: Request, res?: Response) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'REFRESH_TOKEN_ATTEMPT',
      ipAddress: ip,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE,
      details: {}
    }

    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        const tokenToUse = req?.cookies?.[CookieNames.REFRESH_TOKEN]
        auditLogEntry.details.tokenProvidedInRequest = !!tokenToUse

        if (!tokenToUse) {
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          console.warn('[DEBUG AuthService refreshToken] No refresh token provided.')
          auditLogEntry.errorMessage = UnauthorizedAccessException.message
          auditLogEntry.details.reason = 'NO_REFRESH_TOKEN_PROVIDED'
          throw UnauthorizedAccessException
        }

        const existingRefreshToken = await this.tokenService.findRefreshTokenWithUserAndDevice(tokenToUse, tx as any)

        if (!existingRefreshToken || !existingRefreshToken.user) {
          const potentiallyReplayedToken = await this.tokenService.findRefreshToken(tokenToUse, tx as any)

          if (potentiallyReplayedToken) {
            auditLogEntry.userId = potentiallyReplayedToken.userId
            auditLogEntry.details.replayedTokenInfo = {
              used: potentiallyReplayedToken.used,
              expired: potentiallyReplayedToken.expiresAt < new Date()
            }
            console.warn(
              `[SECURITY AuthService refreshToken] Potentially replayed/expired token used. UserId: ${potentiallyReplayedToken.userId}. Invalidating all tokens for this user.`
            )

            await this.tokenService.deleteAllRefreshTokens(potentiallyReplayedToken.userId, tx as any)
            auditLogEntry.notes = 'Potential replay attack or used/expired token. All user tokens invalidated.'
          }

          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          console.warn(
            '[DEBUG AuthService refreshToken] Refresh token not found in DB, user data missing, or token invalid/used/expired.'
          )
          auditLogEntry.errorMessage = UnauthorizedAccessException.message
          auditLogEntry.details.reason = 'REFRESH_TOKEN_INVALID_OR_NOT_FOUND'
          throw UnauthorizedAccessException
        }

        auditLogEntry.userId = existingRefreshToken.userId
        auditLogEntry.userEmail = existingRefreshToken.user.email
        auditLogEntry.details.originalTokenInfo = {
          rememberMe: existingRefreshToken.rememberMe,
          originalDeviceId: existingRefreshToken.deviceId,
          originalTokenExpiresAt: existingRefreshToken.expiresAt
        }

        // >>> START ABSOLUTE SESSION LIFETIME CHECK
        if (existingRefreshToken.device && existingRefreshToken.device.sessionCreatedAt) {
          const sessionAgeMs = new Date().getTime() - new Date(existingRefreshToken.device.sessionCreatedAt).getTime()
          if (sessionAgeMs > envConfig.ABSOLUTE_SESSION_LIFETIME_MS) {
            this.logger.warn(
              `[SECURITY AuthService refreshToken] Absolute session lifetime exceeded for user ${existingRefreshToken.userId}, device ${existingRefreshToken.deviceId}. Session created at: ${existingRefreshToken.device.sessionCreatedAt}`
            )
            await this.tokenService.deleteAllRefreshTokensForDevice(existingRefreshToken.deviceId, tx as any)
            if (res) {
              this.tokenService.clearTokenCookies(res)
            }
            auditLogEntry.errorMessage = 'Error.Auth.Session.AbsoluteLifetimeExceeded'
            auditLogEntry.details.reason = 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED'
            auditLogEntry.notes = `All refresh tokens for device ${existingRefreshToken.deviceId} invalidated due to absolute session lifetime exceeded.`
            throw new ApiException(
              HttpStatus.UNAUTHORIZED,
              'Unauthenticated',
              'Error.Auth.Session.AbsoluteLifetimeExceeded'
            )
          }
        } else if (existingRefreshToken.device) {
          // This case should ideally not happen if all new devices get sessionCreatedAt
          this.logger.warn(
            `[SECURITY AuthService refreshToken] Device ${existingRefreshToken.deviceId} for user ${existingRefreshToken.userId} is missing sessionCreatedAt. Forcing re-authentication.`
          )
          await this.tokenService.deleteAllRefreshTokensForDevice(existingRefreshToken.deviceId, tx as any)
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          auditLogEntry.errorMessage = 'Error.Auth.Device.MissingSessionCreationTime'
          auditLogEntry.details.reason = 'DEVICE_MISSING_SESSION_CREATION_TIME'
          auditLogEntry.notes = `All refresh tokens for device ${existingRefreshToken.deviceId} invalidated due to missing session creation time on device.`
          throw new ApiException(
            HttpStatus.UNAUTHORIZED,
            'Unauthenticated',
            'Error.Auth.Device.MissingSessionCreationTime'
          )
        }
        // <<< END ABSOLUTE SESSION LIFETIME CHECK

        try {
          await this.tokenService.markRefreshTokenUsed(tokenToUse, tx as any)
        } catch (error) {
          if (isNotFoundPrismaError(error)) {
            if (res) {
              this.tokenService.clearTokenCookies(res)
            }
            console.warn('[DEBUG AuthService refreshToken] RT disappeared before it could be marked as used.')
            auditLogEntry.errorMessage = UnauthorizedAccessException.message
            auditLogEntry.details.reason = 'REFRESH_TOKEN_DISAPPEARED_BEFORE_MARKING_USED'
            throw UnauthorizedAccessException
          }
          console.error('[DEBUG AuthService refreshToken] Error marking RT as used:', error)
          auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Error marking RT as used'
          throw error
        }

        const deviceFromRefreshToken = existingRefreshToken.device
        let currentDeviceId: number | undefined = undefined

        if (deviceFromRefreshToken) {
          auditLogEntry.details.deviceValidationAttempt = {
            providedUserAgent: userAgent,
            expectedUserAgent: deviceFromRefreshToken.userAgent,
            providedIp: ip,
            expectedIp: deviceFromRefreshToken.ip
          }
          const isValidDevice = await this.deviceService.validateDevice(deviceFromRefreshToken.id, userAgent, ip, tx)
          if (!isValidDevice) {
            console.warn(
              '[DEBUG AuthService refreshToken] Device validation failed. Potential session hijack attempt or user changed device significantly.'
            )
            await this.tokenService.deleteAllRefreshTokens(existingRefreshToken.userId, tx as any)
            if (res) {
              this.tokenService.clearTokenCookies(res)
            }
            auditLogEntry.errorMessage = DeviceMismatchException.message
            auditLogEntry.details.reason = 'DEVICE_MISMATCH_ON_REFRESH'
            auditLogEntry.notes = 'All user tokens invalidated due to device mismatch.'
            throw DeviceMismatchException
          }
          currentDeviceId = deviceFromRefreshToken.id
          auditLogEntry.details.deviceValidated = true
        } else {
          console.warn(
            '[DEBUG AuthService refreshToken] Refresh token does not have an associated device ID. Rejecting refresh.'
          )
          await this.tokenService.deleteAllRefreshTokens(existingRefreshToken.userId, tx as any)
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          auditLogEntry.errorMessage = InvalidDeviceException.message
          auditLogEntry.details.reason = 'NO_DEVICE_ASSOCIATED_WITH_REFRESH_TOKEN'
          auditLogEntry.notes = 'All user tokens invalidated due to missing device on refresh token.'
          throw InvalidDeviceException
        }

        const userFromRefreshToken = existingRefreshToken.user
        const shouldRememberUser = existingRefreshToken.rememberMe

        if (!currentDeviceId) {
          console.error(
            '[CRITICAL AuthService refreshToken] currentDeviceId is undefined before generating new tokens. This should not happen if device validation passed.'
          )
          await this.tokenService.deleteAllRefreshTokens(existingRefreshToken.userId, tx as any)
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          auditLogEntry.errorMessage = InvalidDeviceException.message
          auditLogEntry.details.reason = 'CRITICAL_UNDEFINED_DEVICE_ID_BEFORE_NEW_TOKEN_GENERATION'
          auditLogEntry.notes = 'All user tokens invalidated.'
          throw InvalidDeviceException
        }

        const {
          accessToken: newAccessToken,
          refreshToken: newRefreshTokenString,
          maxAgeForRefreshTokenCookie
        } = await this.tokenService.generateTokens(
          {
            userId: userFromRefreshToken.id,
            deviceId: currentDeviceId,
            roleId: userFromRefreshToken.roleId,
            roleName: userFromRefreshToken.role.name
          },
          tx as any,
          shouldRememberUser
        )

        if (res) {
          this.tokenService.setTokenCookies(res, newAccessToken, newRefreshTokenString, maxAgeForRefreshTokenCookie)
        }

        // Nếu người dùng chọn "Remember Me" (từ loginSessionToken) và thiết bị chưa được tin cậy, hãy tin cậy nó
        if (shouldRememberUser && currentDeviceId && !deviceFromRefreshToken?.isTrusted) {
          try {
            // Cần lấy lại thông tin device đầy đủ nếu deviceFromRefreshToken không có sẵn hoặc không đủ tin cậy
            const currentDevice = await this.deviceService.findDeviceById(currentDeviceId, tx as any)
            if (currentDevice && !currentDevice.isTrusted) {
              await this.deviceService.trustDevice(currentDeviceId, userFromRefreshToken.id, tx as any)
              auditLogEntry.notes =
                (auditLogEntry.notes ? auditLogEntry.notes + '; ' : '') + 'Device trusted after 2FA.'
              this.logger.debug(
                `Device ${currentDeviceId} trusted for user ${userFromRefreshToken.id} after 2FA due to rememberMe selection.`
              )
            } else if (currentDevice && currentDevice.isTrusted) {
              this.logger.debug(`Device ${currentDeviceId} was already trusted for user ${userFromRefreshToken.id}.`)
            }
          } catch (trustError) {
            this.logger.error(
              `Failed to trust device ${currentDeviceId} for user ${userFromRefreshToken.id} after 2FA`,
              trustError
            )
            auditLogEntry.notes =
              (auditLogEntry.notes ? auditLogEntry.notes + '; ' : '') + 'Failed to trust device after 2FA.'
          }
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'REFRESH_TOKEN_SUCCESS'
        auditLogEntry.details.newTokensGeneratedForDeviceId = currentDeviceId
        auditLogEntry.details.newRefreshTokenRememberMe = shouldRememberUser

        return {
          accessToken: newAccessToken
        }
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during token refresh'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async logout(req: Request, res: Response) {
    const auditLogEntry: {
      action: string
      status: AuditLogStatus
      details: Record<string, any>
      userId?: number
      userEmail?: string
      ipAddress?: string
      userAgent?: string
      errorMessage?: string
      notes?: string
    } = {
      action: 'USER_LOGOUT_ATTEMPT',
      status: AuditLogStatus.FAILURE,
      details: {}
    }
    if (req) {
      auditLogEntry.ipAddress = req.ip
      auditLogEntry.userAgent = req.headers['user-agent']
      const activeUser = req[REQUEST_USER_KEY] as AccessTokenPayload | undefined
      if (activeUser) {
        auditLogEntry.userId = activeUser.userId
        const user = await this.sharedUserRepository.findUnique({ id: activeUser.userId })
        if (user) auditLogEntry.userEmail = user.email
      }
    }

    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        const tokenFromCookie = req?.cookies?.[CookieNames.REFRESH_TOKEN]

        auditLogEntry.details = {
          tokenFoundInCookie: !!tokenFromCookie
        }

        if (tokenFromCookie) {
          try {
            await this.tokenService.deleteRefreshToken(tokenFromCookie, tx as any)
            auditLogEntry.details.tokenCookieDeleted = true
          } catch (error) {
            this.logger.warn(`Error deleting refresh token from cookie: ${error.message}`)
            auditLogEntry.details.tokenCookieDeleteError = error.message
          }
        }

        if (res) {
          this.tokenService.clearTokenCookies(res)
          auditLogEntry.details.cookiesCleared = true
        }

        return { message: 'Auth.Logout.Successful' }
      })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_LOGOUT_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }

      if (res) {
        try {
          this.tokenService.clearTokenCookies(res)
          auditLogEntry.details.cookiesClearedOnError = true
        } catch (cookieError) {
          this.logger.error('Error clearing cookies during logout error handling', cookieError)
        }
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async resetPassword(body: ResetPasswordBodyType & { userAgent?: string; ip?: string }) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'PASSWORD_RESET_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { otpTokenProvided: !!body.otpToken }
    }
    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        await this.otpService.validateVerificationToken({
          token: body.otpToken,
          email: body.email,
          type: TypeOfVerificationCode.FORGOT_PASSWORD,
          tokenType: TokenType.OTP,
          tx
        })

        const user = await tx.user.findUnique({ where: { email: body.email } })
        if (!user) {
          auditLogEntry.errorMessage = EmailNotFoundException.message
          throw EmailNotFoundException
        }
        auditLogEntry.userId = user.id

        const hashedPassword = await this.hashingService.hash(body.newPassword)
        await tx.user.update({
          where: { id: user.id },
          data: { password: hashedPassword }
        })

        await this.otpService.deleteOtpToken(body.otpToken, tx)

        await tx.refreshToken.deleteMany({ where: { userId: user.id } })
        auditLogEntry.notes = 'All refresh tokens for the user were invalidated.'

        return { message: 'Auth.Password.ResetSuccessful' }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PASSWORD_RESET_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async setupTwoFactorAuth(userId: number) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: '2FA_SETUP_INITIATED_ATTEMPT',
      userId: userId,
      status: AuditLogStatus.FAILURE,
      details: {}
    }
    try {
      const userForEmail = await this.sharedUserRepository.findUnique({ id: userId })
      if (userForEmail) {
        auditLogEntry.userEmail = userForEmail.email
      }

      const result = await this.prismaService.$transaction(async (tx) => {
        const user = await tx.user.findUnique({ where: { id: userId } })
        if (!user) {
          auditLogEntry.errorMessage = EmailNotFoundException.message
          auditLogEntry.details.reason = 'USER_NOT_FOUND_FOR_2FA_SETUP'
          throw EmailNotFoundException
        }
        auditLogEntry.userEmail = user.email

        if (user.twoFactorEnabled) {
          auditLogEntry.errorMessage = TOTPAlreadyEnabledException.message
          auditLogEntry.details.reason = '2FA_ALREADY_ENABLED'
          throw TOTPAlreadyEnabledException
        }

        const { secret, uri: otpauthUrl } = this.twoFactorService.generateTOTPSecret(user.email)
        const setupToken = uuidv4()

        await this.authRepository.deleteVerificationTokenByEmailAndType(
          user.email,
          TypeOfVerificationCode.SETUP_2FA,
          TokenType.SETUP_2FA_TOKEN,
          tx
        )

        await this.authRepository.createVerificationToken(
          {
            token: setupToken,
            email: user.email,
            userId: user.id,
            type: TypeOfVerificationCode.SETUP_2FA,
            tokenType: TokenType.SETUP_2FA_TOKEN,
            metadata: JSON.stringify({ tempTwoFactorSecret: secret }),
            expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
          },
          tx
        )

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = '2FA_SETUP_INITIATED_SUCCESS'
        auditLogEntry.details.setupTokenGenerated = true
        auditLogEntry.details.otpUriGenerated = !!otpauthUrl

        return {
          secret: secret,
          uri: otpauthUrl,
          setupToken
        }
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage =
          error instanceof Error ? error.message : 'Unknown error during 2FA setup initiation'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async confirmTwoFactorSetup(userId: number, setupToken: string, totpCode: string) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: '2FA_CONFIRM_SETUP_ATTEMPT',
      userId: userId,
      status: AuditLogStatus.FAILURE,
      details: { setupTokenProvided: !!setupToken, totpCodeProvided: !!totpCode }
    }
    try {
      const userForEmail = await this.sharedUserRepository.findUnique({ id: userId })
      if (userForEmail) auditLogEntry.userEmail = userForEmail.email

      const result = await this.prismaService.$transaction(async (tx) => {
        const verificationToken = (await this.authRepository.findUniqueVerificationToken(
          { token: setupToken },
          tx
        )) as PrismaVerificationToken | null

        let tempTwoFactorSecret: string | undefined = undefined
        if (verificationToken?.metadata) {
          try {
            const parsedMetadata = JSON.parse(verificationToken.metadata)
            tempTwoFactorSecret = parsedMetadata.tempTwoFactorSecret
          } catch (e) {
            console.error('Error parsing metadata for tempTwoFactorSecret', e)
            auditLogEntry.errorMessage = 'Error parsing metadata for tempTwoFactorSecret'
            throw InvalidOTPTokenException
          }
        }

        if (
          !verificationToken ||
          verificationToken.userId !== userId ||
          verificationToken.type !== TypeOfVerificationCode.SETUP_2FA ||
          verificationToken.tokenType !== TokenType.SETUP_2FA_TOKEN ||
          !tempTwoFactorSecret
        ) {
          auditLogEntry.errorMessage = InvalidOTPTokenException.message
          throw InvalidOTPTokenException
        }

        if (verificationToken.expiresAt < new Date()) {
          await this.authRepository.deleteVerificationToken({ token: setupToken }, tx)
          auditLogEntry.errorMessage = OTPTokenExpiredException.message
          throw OTPTokenExpiredException
        }

        const isValidTOTP = this.twoFactorService.verifyTOTP({
          email: verificationToken.email,
          token: totpCode,
          secret: tempTwoFactorSecret
        })
        if (!isValidTOTP) {
          auditLogEntry.errorMessage = InvalidTOTPException.message
          throw InvalidTOTPException
        }

        await this.twoFactorService.updateUserTwoFactorStatus(
          userId,
          {
            twoFactorEnabled: true,
            twoFactorSecret: tempTwoFactorSecret,
            twoFactorMethod: TwoFactorMethodType.TOTP as TwoFactorMethodTypeType,
            twoFactorVerifiedAt: new Date()
          },
          tx as any
        )

        const recoveryCodes = this.twoFactorService.generateRecoveryCodes()
        await this.twoFactorService.saveRecoveryCodes(userId, recoveryCodes, tx as any)

        await this.authRepository.deleteVerificationToken({ token: setupToken }, tx)
        auditLogEntry.notes = 'Recovery codes generated and stored.'

        return {
          message: 'Auth.2FA.ConfirmSetupSuccessful',
          recoveryCodes
        }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_CONFIRM_SETUP_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      if (!auditLogEntry.userEmail && userId) {
        const userForEmailOnError = await this.sharedUserRepository.findUnique({ id: userId })
        if (userForEmailOnError) auditLogEntry.userEmail = userForEmailOnError.email
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyType & { userId: number; userAgent?: string; ip?: string }) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: '2FA_DISABLE_ATTEMPT',
      userId: data.userId,
      ipAddress: data.ip,
      userAgent: data.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        verificationTypeAttempted: data.type,
        codeProvided: !!data.code
      }
    }

    try {
      const userForEmail = await this.sharedUserRepository.findUnique({ id: data.userId })
      if (userForEmail) {
        auditLogEntry.userEmail = userForEmail.email
      }

      const result = await this.prismaService.$transaction(async (tx) => {
        const user = await tx.user.findUnique({ where: { id: data.userId } })
        if (!user) {
          auditLogEntry.errorMessage = EmailNotFoundException.message
          auditLogEntry.details.reason = 'USER_NOT_FOUND_FOR_2FA_DISABLE'
          throw EmailNotFoundException
        }
        auditLogEntry.userEmail = user.email

        if (!user.twoFactorEnabled || !user.twoFactorSecret || !user.twoFactorMethod) {
          auditLogEntry.errorMessage = TOTPNotEnabledException.message
          auditLogEntry.details.reason = '2FA_NOT_ENABLED_CANNOT_DISABLE'
          throw TOTPNotEnabledException
        }
        auditLogEntry.details.methodWasEnabled = user.twoFactorMethod

        if (data.type === TwoFactorMethodType.TOTP) {
          const isValidTOTP = this.twoFactorService.verifyTOTP({
            email: user.email,
            token: data.code,
            secret: user.twoFactorSecret
          })
          if (!isValidTOTP) {
            auditLogEntry.errorMessage = InvalidTOTPException.message
            auditLogEntry.details.reason = 'INVALID_TOTP_FOR_2FA_DISABLE'
            throw InvalidTOTPException
          }
          auditLogEntry.details.totpVerifiedForDisable = true
        } else if (data.type === TwoFactorMethodType.OTP) {
          try {
            await this.otpService.validateVerificationCode({
              email: user.email,
              code: data.code,
              type: TypeOfVerificationCode.DISABLE_2FA,
              tx
            })
            auditLogEntry.details.otpVerifiedForDisable = true

            await this.otpService.deleteVerificationCode(user.email, data.code, TypeOfVerificationCode.DISABLE_2FA, tx)
          } catch (error) {
            auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Invalid OTP for 2FA disable'
            if (error instanceof ApiException) {
              auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
            }
            auditLogEntry.details.reason = 'INVALID_OTP_FOR_2FA_DISABLE'
            throw error
          }
        } else {
          auditLogEntry.errorMessage = 'Unsupported 2FA disable type'
          auditLogEntry.details.reason = 'UNSUPPORTED_2FA_DISABLE_TYPE'
          throw new HttpException('Unsupported 2FA disable type', HttpStatus.BAD_REQUEST)
        }

        await this.twoFactorService.updateUserTwoFactorStatus(
          data.userId,
          {
            twoFactorEnabled: false,
            twoFactorSecret: null,
            twoFactorMethod: null,
            twoFactorVerifiedAt: null
          },
          tx as any
        )

        await this.twoFactorService.deleteAllRecoveryCodes(data.userId, tx as any)
        auditLogEntry.details.recoveryCodesDeleted = true

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = '2FA_DISABLE_SUCCESS'
        auditLogEntry.details.methodDisabled = user.twoFactorMethod

        return { message: 'Auth.2FA.DisableSuccessful' }
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during 2FA disable'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async verifyTwoFactor(body: TwoFactorVerifyBodyType & { userAgent: string; ip: string }, res?: Response) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: '2FA_VERIFY_ATTEMPT',
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        loginSessionTokenProvided: !!body.loginSessionToken,
        verificationTypeAttempted: body.type,
        codeProvided: !!body.code
      }
    }

    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        const initialVerificationToken = await this.otpService.findVerificationToken(body.loginSessionToken, tx)

        if (initialVerificationToken) {
          auditLogEntry.userEmail = initialVerificationToken.email
          if (initialVerificationToken.userId) {
            auditLogEntry.userId = initialVerificationToken.userId
          }
        }

        if (!initialVerificationToken || !initialVerificationToken.email) {
          auditLogEntry.errorMessage = InvalidOTPTokenException.message
          auditLogEntry.details.reason = 'INVALID_LOGIN_SESSION_TOKEN'
          throw InvalidOTPTokenException
        }

        let rememberMe = false
        if (initialVerificationToken.metadata) {
          try {
            const parsedMetadata = JSON.parse(initialVerificationToken.metadata)
            if (typeof parsedMetadata.rememberMe === 'boolean') {
              rememberMe = parsedMetadata.rememberMe
            }
            auditLogEntry.details.rememberMeSettingFromToken = rememberMe
          } catch (e) {
            console.warn('[AuthService verifyTwoFactor] Could not parse rememberMe from token metadata', e)
            auditLogEntry.notes = 'Error parsing rememberMe from token metadata.'
          }
        }

        const verificationToken = await this.otpService.validateVerificationToken({
          token: body.loginSessionToken,
          email: initialVerificationToken.email,
          type: TypeOfVerificationCode.LOGIN_2FA,
          tokenType: TokenType.OTP,
          deviceId: initialVerificationToken.deviceId ?? undefined,
          tx
        })
        auditLogEntry.userEmail = verificationToken.email
        if (verificationToken.userId) {
          auditLogEntry.userId = verificationToken.userId
        }

        const user = await tx.user.findUnique({
          where: { email: verificationToken.email },
          include: { role: true }
        })

        if (!user || !user.twoFactorEnabled || !user.twoFactorSecret || !user.twoFactorMethod) {
          await this.otpService.deleteOtpToken(body.loginSessionToken, tx)
          auditLogEntry.errorMessage = TOTPNotEnabledException.message
          auditLogEntry.details.reason = '2FA_NOT_ENABLED_FOR_USER'
          throw TOTPNotEnabledException
        }
        auditLogEntry.details.userTwoFactorMethod = user.twoFactorMethod

        let isValid2FACode = false
        if (body.type === TwoFactorMethodType.TOTP && body.code) {
          if (user.twoFactorMethod === TwoFactorMethodType.TOTP) {
            isValid2FACode = this.twoFactorService.verifyTOTP({
              email: user.email,
              token: body.code,
              secret: user.twoFactorSecret
            })
          } else {
            await this.otpService.deleteOtpToken(body.loginSessionToken, tx)
            auditLogEntry.errorMessage = 'Invalid 2FA method for TOTP code.'
            auditLogEntry.details.reason = 'INVALID_2FA_METHOD_FOR_TOTP_CODE'
            throw new HttpException('Invalid 2FA method for TOTP code.', 400)
          }
        } else if (body.type === TwoFactorMethodType.OTP && body.code) {
          isValid2FACode = true
          auditLogEntry.details.otpVerifiedBypassTwoFactorMethod = true
        } else if (body.type === TwoFactorMethodType.RECOVERY && body.code) {
          await this.twoFactorService.verifyRecoveryCode(user.id, body.code, tx as any)
          isValid2FACode = true
          auditLogEntry.details.recoveryCodeUsed = true
        } else {
          await this.otpService.deleteOtpToken(body.loginSessionToken, tx)
          auditLogEntry.errorMessage =
            'Either a TOTP code or an OTP code or a recovery code (with correct type) must be provided.'
          auditLogEntry.details.reason = 'MISSING_2FA_CODE_OR_INVALID_TYPE'
          throw new HttpException(
            'Either a TOTP code or an OTP code or a recovery code (with correct type) must be provided.',
            400
          )
        }

        if (!isValid2FACode) {
          await this.otpService.deleteOtpToken(body.loginSessionToken, tx)
          auditLogEntry.errorMessage = InvalidTOTPException.message
          auditLogEntry.details.reason =
            body.type === TwoFactorMethodType.RECOVERY ? 'INVALID_RECOVERY_CODE' : 'INVALID_TOTP_CODE'
          throw InvalidTOTPException
        }

        let deviceId = verificationToken.deviceId
        if (!deviceId && body.userAgent && body.ip) {
          try {
            const device = await this.deviceService.findOrCreateDevice(
              {
                userId: user.id,
                userAgent: body.userAgent,
                ip: body.ip
              },
              tx as any
            )
            deviceId = device.id
            auditLogEntry.details.newDeviceCreated = true
          } catch (error) {
            console.error('Error creating device in verifyTwoFactor:', error)
            auditLogEntry.errorMessage = DeviceAssociationFailedException.message
            auditLogEntry.details.deviceError = 'DeviceCreationFailureIn2FAVerify'
            throw DeviceAssociationFailedException
          }
        } else if (deviceId && body.userAgent && body.ip) {
          const isValidDevice = await this.deviceService.validateDevice(deviceId, body.userAgent, body.ip, tx as any)
          if (!isValidDevice) {
            await this.otpService.deleteOtpToken(body.loginSessionToken, tx)
            auditLogEntry.errorMessage = DeviceMismatchException.message
            auditLogEntry.details.deviceError = 'DeviceMismatchIn2FAVerify'
            throw DeviceMismatchException
          }
          auditLogEntry.details.existingDeviceValidated = true
        }

        if (!deviceId) {
          await this.otpService.deleteOtpToken(body.loginSessionToken, tx)
          auditLogEntry.errorMessage = DeviceAssociationFailedException.message
          auditLogEntry.details.deviceError = 'DeviceIDMissingIn2FAVerify'
          throw DeviceAssociationFailedException
        }
        auditLogEntry.details.finalDeviceId = deviceId

        await this.twoFactorService.updateUserTwoFactorStatus(
          user.id,
          {
            twoFactorEnabled: true,
            twoFactorVerifiedAt: new Date(),
            twoFactorMethod: user.twoFactorMethod,
            twoFactorSecret: user.twoFactorSecret
          },
          tx as any
        )

        const { accessToken, refreshToken, maxAgeForRefreshTokenCookie } = await this.generateTokens(
          {
            userId: user.id,
            deviceId: deviceId,
            roleId: user.roleId,
            roleName: user.role.name
          },
          tx,
          rememberMe
        )

        await this.otpService.deleteOtpToken(body.loginSessionToken, tx)

        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshToken, maxAgeForRefreshTokenCookie)
        }

        // Nếu người dùng chọn "Remember Me" (từ loginSessionToken) và thiết bị chưa được tin cậy, hãy tin cậy nó
        if (rememberMe && verificationToken.deviceId) {
          try {
            const deviceForTrustCheck = await this.deviceService.findDeviceById(verificationToken.deviceId, tx as any)
            if (deviceForTrustCheck && !deviceForTrustCheck.isTrusted) {
              await this.deviceService.trustDevice(verificationToken.deviceId, user.id, tx as any)
              auditLogEntry.notes =
                (auditLogEntry.notes ? auditLogEntry.notes + '; ' : '') + 'Device trusted after 2FA.'
              this.logger.debug(
                `Device ${verificationToken.deviceId} trusted for user ${user.id} after 2FA due to rememberMe selection.`
              )
            } else if (deviceForTrustCheck && deviceForTrustCheck.isTrusted) {
              this.logger.debug(`Device ${verificationToken.deviceId} was already trusted for user ${user.id}.`)
            }
          } catch (trustError) {
            this.logger.error(
              `Failed to trust device ${verificationToken.deviceId} for user ${user.id} after 2FA`,
              trustError
            )
            auditLogEntry.notes =
              (auditLogEntry.notes ? auditLogEntry.notes + '; ' : '') + 'Failed to trust device after 2FA.'
          }
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = '2FA_VERIFY_SUCCESS'
        auditLogEntry.details.rememberMeApplied = rememberMe

        return {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name
        }
      })
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      if (!auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = error instanceof Error ? error.message : 'Unknown error during 2FA verification'
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async createLoginSessionToken(
    {
      email,
      userId,
      deviceId,
      rememberMe
    }: {
      email: string
      userId: number
      deviceId: number
      rememberMe?: boolean
    },
    tx?: Prisma.TransactionClient
  ): Promise<string> {
    const otpToken = uuidv4()
    const metadata: Record<string, any> = {}
    if (rememberMe !== undefined) {
      metadata.rememberMe = rememberMe
    }

    await this.authRepository.createVerificationToken(
      {
        token: otpToken,
        email,
        userId,
        deviceId,
        type: TypeOfVerificationCode.LOGIN_2FA,
        tokenType: TokenType.OTP,
        metadata: Object.keys(metadata).length > 0 ? JSON.stringify(metadata) : undefined,
        expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
      },
      tx
    )
    return otpToken
  }
}
