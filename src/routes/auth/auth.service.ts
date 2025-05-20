import { HttpException, Injectable, HttpStatus, Logger } from '@nestjs/common'
import { addMilliseconds } from 'date-fns'
import {
  DisableTwoFactorBodyType,
  LoginBodyType,
  RefreshTokenBodyType,
  RegisterBodyType,
  ResetPasswordBodyType,
  SendOTPBodyType,
  TwoFactorVerifyBodyType,
  VerifyCodeBodyType
} from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { RolesService } from 'src/routes/auth/roles.service'
import { generateOTP, isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { TokenService } from 'src/shared/services/token.service'
import ms from 'ms'
import {
  TokenType,
  TokenTypeType,
  TwoFactorMethodType,
  TypeOfVerificationCode,
  TypeOfVerificationCodeType,
  CookieNames,
  REQUEST_USER_KEY
} from 'src/shared/constants/auth.constant'
import { EmailService } from 'src/shared/services/email.service'
import { AccessTokenPayload, AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import {
  EmailAlreadyExistsException,
  EmailNotFoundException,
  FailedToSendOTPException,
  InvalidLoginSessionException,
  InvalidOTPException,
  InvalidOTPTokenException,
  InvalidPasswordException,
  InvalidTOTPException,
  OTPExpiredException,
  OTPTokenExpiredException,
  TOTPAlreadyEnabledException,
  TOTPNotEnabledException,
  UnauthorizedAccessException,
  DeviceMismatchException,
  InvalidDeviceException,
  InvalidRecoveryCodeException,
  DeviceSetupFailedException,
  DeviceAssociationFailedException
} from 'src/routes/auth/auth.error'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { v4 as uuidv4 } from 'uuid'
import envConfig from 'src/shared/config'
import { Response } from 'express'
import { Request } from 'express'
import { PrismaService } from 'src/shared/services/prisma.service'
import {
  Prisma,
  RecoveryCode as PrismaRecoveryCode,
  VerificationToken as PrismaVerificationToken,
  VerificationCodeType as PrismaVerificationCodeEnum
} from '@prisma/client'
import { TwoFactorMethodTypeType } from 'src/shared/constants/auth.constant'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/shared/services/audit.service'
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
            auditLogEntry.errorMessage = DeviceSetupFailedException().message
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
          auditLogEntry.errorMessage = InvalidLoginSessionException.message
          auditLogEntry.details.reason = 'USER_NOT_FOUND'
          throw InvalidLoginSessionException
        }
        auditLogEntry.userId = user.id

        const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
        if (!isPasswordMatch) {
          console.warn('[DEBUG AuthService login] Invalid password for user:', user.email)
          auditLogEntry.errorMessage = InvalidPasswordException.message
          auditLogEntry.details.reason = 'INVALID_PASSWORD'
          throw InvalidPasswordException
        }

        if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod) {
          const otpToken = uuidv4()
          let deviceId: number | undefined = undefined
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
            auditLogEntry.details.deviceId = deviceId
            auditLogEntry.details.twoFactorMethod = user.twoFactorMethod
          } catch (error) {
            console.error('[DEBUG AuthService login - 2FA flow] Error creating/finding device:', error)
            auditLogEntry.errorMessage = DeviceSetupFailedException().message
            auditLogEntry.details.deviceError = 'DeviceSetupFailed'
            throw DeviceSetupFailedException()
          }

          await this.authRepository.createVerificationToken(
            {
              token: otpToken,
              email: user.email,
              type: TypeOfVerificationCode.LOGIN_2FA,
              tokenType: TokenType.OTP,
              userId: user.id,
              deviceId,
              metadata: JSON.stringify({ rememberMe: body.rememberMe }),
              expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
            },
            tx
          )
          auditLogEntry.status = AuditLogStatus.SUCCESS
          auditLogEntry.notes = '2FA required'
          return {
            message: 'Auth.Login.2FARequired',
            loginSessionToken: otpToken,
            twoFactorMethod: user.twoFactorMethod
          }
        }

        let deviceId: number | undefined
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
          auditLogEntry.details.deviceId = deviceId
          auditLogEntry.details.twoFactorFlow = false
        } catch (error) {
          console.error('[DEBUG AuthService login - Direct login] Error creating/finding device:', error)
          auditLogEntry.errorMessage = DeviceSetupFailedException().message
          auditLogEntry.details.deviceError = 'DeviceSetupFailed'
          throw DeviceSetupFailedException()
        }

        if (!deviceId) {
          console.error('[DEBUG AuthService login - Direct login] Device ID is undefined after creation attempt.')
          auditLogEntry.errorMessage = 'Device ID is undefined after creation attempt (direct login)'
          auditLogEntry.details.deviceError = 'DeviceIDUndefined'
          throw DeviceSetupFailedException()
        }

        const { accessToken, refreshToken, maxAgeForRefreshTokenCookie } = await this.generateTokens(
          {
            userId: user.id,
            deviceId: deviceId,
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

  /**
   * Tạo cặp access token và refresh token mới
   * @param payload Dữ liệu người dùng cần nhúng vào token
   * @param prismaTx Client transaction Prisma (tùy chọn)
   * @param rememberMe Có ghi nhớ đăng nhập không (tùy chọn)
   * @returns Object chứa accessToken, refreshToken và maxAgeForRefreshTokenCookie
   */
  async generateTokens(
    { userId, deviceId, roleId, roleName }: AccessTokenPayloadCreate,
    prismaTx?: Prisma.TransactionClient,
    rememberMe?: boolean
  ) {
    return this.tokenService.generateTokens({ userId, deviceId, roleId, roleName }, prismaTx as any, rememberMe)
  }

  /**
   * Làm mới access token dựa trên refresh token hợp lệ
   * @param data Thông tin refreshToken, userAgent và IP
   * @param req Request object để truy xuất cookie nếu cần
   * @param res Response object để cập nhật cookie
   * @returns Object chứa accessToken mới
   */
  async refreshToken(
    { refreshToken, userAgent, ip }: RefreshTokenBodyType & { userAgent: string; ip: string },
    req?: Request,
    res?: Response
  ) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Record<string, any> } = {
      action: 'REFRESH_TOKEN_ATTEMPT',
      ipAddress: ip,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE,
      details: {}
    }

    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        // Lấy token từ body hoặc cookie
        const tokenToUse = refreshToken || (req && req.cookies && req.cookies[CookieNames.REFRESH_TOKEN])
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

        // Lấy thông tin refresh token kèm theo thông tin user và device
        const existingRefreshToken = await this.tokenService.findRefreshTokenWithUserAndDevice(tokenToUse, tx as any)

        if (!existingRefreshToken || !existingRefreshToken.user) {
          // Kiểm tra xem token có phải đã bị sử dụng hoặc hết hạn
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

            // Xóa tất cả token của người dùng nếu phát hiện tấn công replay
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

        try {
          // Đánh dấu token đã được sử dụng
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

        // Tạo cặp token mới (access token và refresh token)
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
          // Cập nhật cookies với token mới
          this.tokenService.setTokenCookies(res, newAccessToken, newRefreshTokenString, maxAgeForRefreshTokenCookie)
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

  /**
   * Đăng xuất người dùng và xóa refresh token
   * @param refreshTokenInput Token đầu vào từ request body (có thể null hoặc undefined)
   * @param req Request object chứa cookie và thông tin người dùng (tùy chọn)
   * @param res Response object để xóa cookie (tùy chọn)
   * @returns Thông báo đăng xuất thành công
   */
  async logout(refreshTokenInput?: string, req?: Request, res?: Response) {
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
        // Lấy token từ cả body và cookie
        const tokenFromBody = refreshTokenInput
        const tokenFromCookie = req?.cookies?.[CookieNames.REFRESH_TOKEN]

        auditLogEntry.details = {
          tokenProvidedInBody: !!tokenFromBody,
          tokenFoundInCookie: !!tokenFromCookie
        }

        // Ưu tiên sử dụng token từ body, nếu không có thì dùng từ cookie
        if (tokenFromBody) {
          try {
            await this.tokenService.deleteRefreshToken(tokenFromBody, tx as any)
            auditLogEntry.details.tokenBodyDeleted = true
          } catch (error) {
            // Ghi log nhưng không báo lỗi để tiếp tục xử lý
            this.logger.warn(`Error deleting refresh token from body: ${error.message}`)
            auditLogEntry.details.tokenBodyDeleteError = error.message
          }
        }

        // Nếu có token từ cookie và khác token từ body, cũng xóa luôn
        if (tokenFromCookie && tokenFromCookie !== tokenFromBody) {
          try {
            await this.tokenService.deleteRefreshToken(tokenFromCookie, tx as any)
            auditLogEntry.details.tokenCookieDeleted = true
          } catch (error) {
            // Ghi log nhưng không báo lỗi
            this.logger.warn(`Error deleting refresh token from cookie: ${error.message}`)
            auditLogEntry.details.tokenCookieDeleteError = error.message
          }
        }

        // Luôn xóa cookie khi đăng xuất, bất kể token có tồn tại hay không
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

      // Đảm bảo xóa cookie ngay cả khi xử lý xóa token thất bại
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
          // Với OTP, không quan tâm twoFactorMethod của người dùng là gì
          // OTP đã được xác thực khi tạo loginSessionToken, chúng ta chỉ cần kiểm tra token đã hợp lệ
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
            auditLogEntry.errorMessage = DeviceAssociationFailedException().message
            auditLogEntry.details.deviceError = 'DeviceCreationFailureIn2FAVerify'
            throw DeviceAssociationFailedException()
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
          auditLogEntry.errorMessage = DeviceAssociationFailedException().message
          auditLogEntry.details.deviceError = 'DeviceIDMissingIn2FAVerify'
          throw DeviceAssociationFailedException()
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
}
