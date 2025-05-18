import { HttpException, Injectable } from '@nestjs/common'
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
  RefreshTokenAlreadyUsedException,
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
  User as PrismaUser,
  RecoveryCode as PrismaRecoveryCode,
  VerificationToken as PrismaVerificationToken,
  RefreshToken as PrismaRefreshToken,
  VerificationCodeType as PrismaVerificationCodeEnum,
  Role as PrismaRole
} from '@prisma/client'
import { TwoFactorMethodTypeType } from 'src/shared/constants/auth.constant'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/shared/services/audit.service'
import { ApiException } from 'src/shared/exceptions/api.exception'

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepository: AuthRepository,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly twoFactorService: TwoFactorService,
    private readonly auditLogService: AuditLogService
  ) {}

  async validateVerificationCode({
    email,
    code,
    type
  }: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }) {
    const verificationCode = await this.authRepository.findUniqueVerificationCode({
      email_code_type: {
        email,
        code,
        type: type as PrismaVerificationCodeEnum
      }
    })
    if (!verificationCode) {
      throw InvalidOTPException
    }
    if (verificationCode.expiresAt < new Date()) {
      throw OTPExpiredException
    }
    return verificationCode
  }

  async validateVerificationToken({
    token,
    email,
    type,
    tokenType,
    deviceId
  }: {
    token: string
    email: string
    type: TypeOfVerificationCodeType
    tokenType: TokenTypeType
    deviceId?: number
  }) {
    const verificationToken = (await this.authRepository.findUniqueVerificationToken({
      token
    })) as PrismaVerificationToken | null

    if (!verificationToken) {
      throw InvalidOTPTokenException
    }

    if (
      verificationToken.email !== email ||
      (verificationToken.type as string) !== type ||
      verificationToken.tokenType !== tokenType
    ) {
      throw InvalidOTPTokenException
    }

    if (verificationToken.expiresAt < new Date()) {
      throw OTPTokenExpiredException
    }

    if (deviceId !== undefined && verificationToken.deviceId !== undefined && deviceId !== verificationToken.deviceId) {
      throw DeviceMismatchException
    }

    return verificationToken
  }

  async verifyCode(body: VerifyCodeBodyType & { userAgent: string; ip: string }) {
    let auditLogEntry: Partial<AuditLogData> = {
      action: 'OTP_VERIFY_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { type: body.type, codeProvided: !!body.code }
    }
    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        const verificationCode = await this.validateVerificationCode({
          email: body.email,
          code: body.code,
          type: body.type
        })
        // Nếu code hợp lệ, có thể đã có user ID liên quan nếu type không phải REGISTER
        const existingUser = await this.sharedUserRepository.findUnique({ email: body.email })
        if (existingUser) {
          auditLogEntry.userId = existingUser.id
        }

        await this.authRepository.deleteVerificationTokenByEmailAndType(body.email, body.type, TokenType.OTP, tx)

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
            const device = await this.authRepository.findOrCreateDevice(
              {
                userId,
                userAgent: body.userAgent,
                ip: body.ip
              },
              tx
            )
            deviceId = device.id
          } catch (error) {
            auditLogEntry.errorMessage = DeviceSetupFailedException().message
            auditLogEntry.notes = 'Device creation/finding failed during OTP verification'
            // Không throw ở đây để luồng chính vẫn có thể tạo token nếu deviceId là optional
            console.error('Không thể tạo hoặc tìm device trong verifyCode', error)
          }
        }

        const token = uuidv4()
        await this.authRepository.createVerificationToken(
          {
            token,
            email: body.email,
            type: body.type,
            tokenType: TokenType.OTP,
            userId,
            deviceId,
            expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
          },
          tx
        )

        await this.authRepository.deleteVerificationCode(
          {
            email_code_type: {
              email: body.email,
              code: body.code,
              type: body.type as PrismaVerificationCodeEnum
            }
          },
          tx
        )
        return { otpToken: token }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'OTP_VERIFY_SUCCESS'
      this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async register(body: RegisterBodyType & { userAgent?: string; ip?: string }) {
    try {
      return await this.prismaService.$transaction(async (tx) => {
        const verificationToken = await this.validateVerificationToken({
          token: body.otpToken,
          email: body.email,
          type: TypeOfVerificationCode.REGISTER,
          tokenType: TokenType.OTP
        })

        if (verificationToken.deviceId && body.userAgent && body.ip) {
          const isValidDevice = await this.authRepository.validateDevice(
            verificationToken.deviceId,
            body.userAgent,
            body.ip,
            tx
          )
          if (!isValidDevice) {
            throw DeviceMismatchException
          }
        }

        const clientRoleId = await this.rolesService.getClientRoleId()
        const hashedPassword = await this.hashingService.hash(body.password)
        const user = await this.authRepository.createUser(
          {
            email: body.email,
            name: body.name,
            phoneNumber: body.phoneNumber,
            password: hashedPassword,
            roleId: clientRoleId
          },
          tx
        )

        await this.authRepository.deleteVerificationToken({ token: body.otpToken }, tx)
        return user
      })
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw EmailAlreadyExistsException
      }
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

    await this.authRepository.deleteVerificationCodesByEmailAndType({
      email: body.email,
      type: body.type
    })

    const code = generateOTP()
    await this.authRepository.createVerificationCode({
      email: body.email,
      code,
      type: body.type,
      expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN))
    })

    const { error } = await this.emailService.sendOTP({
      email: body.email,
      code
    })
    if (error) {
      throw FailedToSendOTPException
    }
    return { message: 'Auth.Otp.SentSuccessfully' }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res?: Response) {
    console.log('[DEBUG AuthService login] Received login request for email:', body.email)
    return this.prismaService.$transaction(async (tx) => {
      let auditLogEntry: Partial<AuditLogData> = {
        action: 'USER_LOGIN_ATTEMPT',
        userEmail: body.email,
        ipAddress: body.ip,
        userAgent: body.userAgent,
        status: AuditLogStatus.FAILURE // Mặc định là thất bại
      }
      try {
        const user = await tx.user.findUnique({
          where: { email: body.email },
          include: { role: true }
        })
        if (!user) {
          console.warn('[DEBUG AuthService login] User not found:', body.email)
          auditLogEntry.errorMessage = 'User not found or invalid login session'
          throw InvalidLoginSessionException
        }
        console.log('[DEBUG AuthService login] User found:', {
          id: user.id,
          email: user.email,
          twoFactorEnabled: user.twoFactorEnabled
        })
        auditLogEntry.userId = user.id

        const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
        if (!isPasswordMatch) {
          console.warn('[DEBUG AuthService login] Invalid password for user:', user.email)
          auditLogEntry.errorMessage = 'Invalid password'
          throw InvalidPasswordException
        }
        console.log('[DEBUG AuthService login] Password matched for user:', user.email)

        if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod) {
          console.log('[DEBUG AuthService login] 2FA is ENABLED for user. Proceeding with 2FA flow.', user.email)
          const otpToken = uuidv4()
          let deviceId: number | undefined = undefined
          try {
            const device = await this.authRepository.findOrCreateDevice(
              {
                userId: user.id,
                userAgent: body.userAgent,
                ip: body.ip
              },
              tx
            )
            deviceId = device.id
            console.log('[DEBUG AuthService login - 2FA flow] Device created/found with ID:', deviceId)
          } catch (error) {
            console.error('[DEBUG AuthService login - 2FA flow] Error creating/finding device:', error)
            auditLogEntry.errorMessage = error.message
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
          console.log('[DEBUG AuthService login - 2FA flow] LOGIN_2FA token created. Returning 2FA prompt.')
          auditLogEntry.status = AuditLogStatus.SUCCESS // Thành công đến bước yêu cầu 2FA
          auditLogEntry.notes = '2FA required'
          this.auditLogService.record(auditLogEntry as AuditLogData) // Ghi log
          return {
            message: 'Auth.Login.2FARequired',
            loginSessionToken: otpToken,
            twoFactorMethod: user.twoFactorMethod
          }
        }

        console.log(
          '[DEBUG AuthService login] 2FA is NOT ENABLED or not fully configured. Proceeding with direct login.',
          user.email
        )
        let deviceId: number | undefined
        try {
          const device = await this.authRepository.findOrCreateDevice(
            {
              userId: user.id,
              userAgent: body.userAgent,
              ip: body.ip
            },
            tx
          )
          deviceId = device.id
          console.log('[DEBUG AuthService login - Direct login] Device created/found with ID:', deviceId)
        } catch (error) {
          console.error('[DEBUG AuthService login - Direct login] Error creating/finding device:', error)
          auditLogEntry.errorMessage = error.message
          throw DeviceSetupFailedException()
        }

        if (!deviceId) {
          console.error('[DEBUG AuthService login - Direct login] Device ID is undefined after creation attempt.')
          auditLogEntry.errorMessage = 'Device ID is undefined after creation attempt'
          throw DeviceSetupFailedException()
        }

        console.log('[DEBUG AuthService login - Direct login] Generating tokens...')
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
        console.log(
          '[DEBUG AuthService login - Direct login] Tokens generated. AccessToken present:',
          !!accessToken,
          'RefreshToken present:',
          !!refreshToken
        )

        if (res) {
          console.log('[DEBUG AuthService login - Direct login] Response object present, attempting to set cookies.')
          this.tokenService.setTokenCookies(res, accessToken, refreshToken, maxAgeForRefreshTokenCookie)
        } else {
          console.warn(
            '[DEBUG AuthService login - Direct login] Response object (res) is NOT present. Cookies will not be set by login function directly.'
          )
        }

        console.log('[DEBUG AuthService login - Direct login] Returning user profile.')
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_LOGIN_SUCCESS' // Cập nhật action
        this.auditLogService.record(auditLogEntry as AuditLogData) // Ghi log
        return {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: user.role.name
        }
      } catch (error) {
        auditLogEntry.errorMessage = error.message
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        }
        this.auditLogService.record(auditLogEntry as AuditLogData) // Ghi log lỗi
        throw error
      }
    })
  }

  async generateTokens(
    { userId, deviceId, roleId, roleName }: AccessTokenPayloadCreate,
    prismaTx?: Prisma.TransactionClient,
    rememberMe?: boolean
  ) {
    const client = prismaTx || this.prismaService
    console.log(`[DEBUG TokenService generateTokens] rememberMe flag: ${rememberMe}`)

    const accessToken = this.tokenService.signAccessToken({
      userId,
      deviceId,
      roleId,
      roleName
    })
    const refreshToken = uuidv4()

    let refreshTokenExpiresInMs: number
    if (rememberMe) {
      refreshTokenExpiresInMs = envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
      console.log(`[DEBUG TokenService generateTokens] Using REMEMBER_ME lifetime: ${refreshTokenExpiresInMs}ms`)
    } else {
      refreshTokenExpiresInMs = envConfig.DEFAULT_REFRESH_TOKEN_COOKIE_MAX_AGE
      console.log(`[DEBUG TokenService generateTokens] Using DEFAULT lifetime: ${refreshTokenExpiresInMs}ms`)
    }
    const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)

    await this.authRepository.createRefreshToken(
      {
        token: refreshToken,
        userId,
        deviceId,
        expiresAt: refreshTokenExpiresAt,
        rememberMe: !!rememberMe
      },
      client
    )

    return {
      accessToken,
      refreshToken,
      maxAgeForRefreshTokenCookie: refreshTokenExpiresInMs
    }
  }

  async refreshToken(
    { refreshToken, userAgent, ip }: RefreshTokenBodyType & { userAgent: string; ip: string },
    req?: Request,
    res?: Response
  ) {
    console.log('[DEBUG AuthService refreshToken] Received refreshToken request.')
    let auditLogEntry: Partial<AuditLogData> = {
      action: 'REFRESH_TOKEN_ATTEMPT',
      ipAddress: ip,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE
    }
    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        const tokenToUse = refreshToken || (req && req.cookies && req.cookies[CookieNames.REFRESH_TOKEN])
        console.log('[DEBUG AuthService refreshToken] Token to use:', tokenToUse ? 'Present' : 'MISSING')
        auditLogEntry.details = { tokenProvided: !!tokenToUse }

        if (!tokenToUse) {
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          console.warn('[DEBUG AuthService refreshToken] No refresh token provided.')
          auditLogEntry.errorMessage = UnauthorizedAccessException.message
          throw UnauthorizedAccessException
        }

        const existingRefreshToken = await tx.refreshToken.findUnique({
          where: { token: tokenToUse },
          include: { user: { include: { role: true } }, device: true }
        })

        if (!existingRefreshToken || !existingRefreshToken.user) {
          const potentiallyReplayedToken = await tx.refreshToken.findUnique({
            where: { token: tokenToUse },
            select: { userId: true, used: true, expiresAt: true }
          })

          if (potentiallyReplayedToken) {
            auditLogEntry.userId = potentiallyReplayedToken.userId
            console.warn(
              `[SECURITY AuthService refreshToken] Potentially replayed/expired token used. UserId: ${potentiallyReplayedToken.userId}. Invalidating all tokens for this user.`
            )
            await tx.refreshToken.deleteMany({ where: { userId: potentiallyReplayedToken.userId } })
            auditLogEntry.notes = 'Potential replay attack or expired/used token.'
          }

          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          console.warn(
            '[DEBUG AuthService refreshToken] Refresh token not found in DB (or user data missing), or token is invalid/used/expired.'
          )
          auditLogEntry.errorMessage = UnauthorizedAccessException.message
          throw UnauthorizedAccessException
        }

        // Gán userId và userEmail sớm nhất có thể
        auditLogEntry.userId = existingRefreshToken.userId
        auditLogEntry.userEmail = existingRefreshToken.user.email

        try {
          await tx.refreshToken.update({
            where: { token: tokenToUse },
            data: { used: true }
          })
          console.log('[DEBUG AuthService refreshToken] Marked current RT as used.')
        } catch (error) {
          if (isNotFoundPrismaError(error)) {
            if (res) {
              this.tokenService.clearTokenCookies(res)
            }
            console.warn('[DEBUG AuthService refreshToken] RT disappeared before it could be marked as used.')
            auditLogEntry.errorMessage = UnauthorizedAccessException.message
            throw UnauthorizedAccessException
          }
          console.error('[DEBUG AuthService refreshToken] Error marking RT as used:', error)
          auditLogEntry.errorMessage = error.message
          throw error
        }

        const deviceFromRefreshToken = existingRefreshToken.device
        let currentDeviceId: number | undefined = undefined

        if (deviceFromRefreshToken) {
          console.log(
            '[DEBUG AuthService refreshToken] Validating device. Device ID from RT:',
            deviceFromRefreshToken.id
          )
          const isValidDevice = await this.authRepository.validateDevice(deviceFromRefreshToken.id, userAgent, ip, tx)
          if (!isValidDevice) {
            console.warn(
              '[DEBUG AuthService refreshToken] Device validation failed. Potential session hijack attempt or user changed device significantly.'
            )
            await tx.refreshToken.deleteMany({ where: { userId: existingRefreshToken.userId } })
            if (res) {
              this.tokenService.clearTokenCookies(res)
            }
            auditLogEntry.errorMessage = DeviceMismatchException.message
            throw DeviceMismatchException
          }
          currentDeviceId = deviceFromRefreshToken.id
          console.log(
            '[DEBUG AuthService refreshToken] Device validated successfully. Using deviceId:',
            currentDeviceId
          )
        } else {
          console.warn(
            '[DEBUG AuthService refreshToken] Refresh token does not have an associated device ID. Rejecting refresh.'
          )
          await tx.refreshToken.deleteMany({ where: { userId: existingRefreshToken.userId } })
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          auditLogEntry.errorMessage = InvalidDeviceException.message
          throw InvalidDeviceException
        }

        const userFromRefreshToken = existingRefreshToken.user
        const shouldRememberUser = existingRefreshToken.rememberMe
        console.log(
          `[DEBUG AuthService refreshToken] Generating new tokens. rememberMe status for new RT: ${shouldRememberUser}, Device ID: ${currentDeviceId}`
        )

        if (!currentDeviceId) {
          console.error(
            '[CRITICAL AuthService refreshToken] currentDeviceId is undefined before generating new tokens. This should not happen if device validation passed.'
          )
          await tx.refreshToken.deleteMany({ where: { userId: existingRefreshToken.userId } })
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          auditLogEntry.errorMessage = InvalidDeviceException.message
          throw InvalidDeviceException
        }

        const {
          accessToken: newAccessToken,
          refreshToken: newRefreshTokenString,
          maxAgeForRefreshTokenCookie
        } = await this.generateTokens(
          {
            userId: userFromRefreshToken.id,
            deviceId: currentDeviceId,
            roleId: userFromRefreshToken.roleId,
            roleName: userFromRefreshToken.role.name
          },
          tx,
          shouldRememberUser
        )
        console.log('[DEBUG AuthService refreshToken] New tokens generated.')

        if (res) {
          this.tokenService.setTokenCookies(res, newAccessToken, newRefreshTokenString, maxAgeForRefreshTokenCookie)
          console.log('[DEBUG AuthService refreshToken] New AT/RT cookies set.')
        }

        return {
          accessToken: newAccessToken
        }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'REFRESH_TOKEN_SUCCESS'
      this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async logout(refreshTokenInput: string, req?: Request, res?: Response) {
    let auditLogEntry: Partial<AuditLogData> = {
      action: 'USER_LOGOUT_ATTEMPT',
      status: AuditLogStatus.FAILURE
    }
    if (req) {
      auditLogEntry.ipAddress = req.ip
      auditLogEntry.userAgent = req.headers['user-agent']
      // Cố gắng lấy userId từ access token nếu có (dù có thể không cần thiết cho logout)
      const activeUser = req[REQUEST_USER_KEY] as AccessTokenPayload | undefined
      if (activeUser) {
        auditLogEntry.userId = activeUser.userId
        const user = await this.sharedUserRepository.findUnique({ id: activeUser.userId })
        if (user) auditLogEntry.userEmail = user.email
      }
    }

    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        const tokenToUse = refreshTokenInput || (req && req.cookies && req.cookies[CookieNames.REFRESH_TOKEN])
        auditLogEntry.details = {
          tokenProvidedInBody: !!refreshTokenInput,
          tokenFoundInCookie: !!(req && req.cookies && req.cookies[CookieNames.REFRESH_TOKEN])
        }

        if (tokenToUse) {
          await tx.refreshToken.deleteMany({ where: { token: tokenToUse } })
        }
        if (res) {
          res.clearCookie(CookieNames.REFRESH_TOKEN, {
            httpOnly: true,
            secure: envConfig.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/api/v1/auth',
            domain: envConfig.COOKIE_DOMAIN
          })
          this.tokenService.clearTokenCookies(res)
        }
        return { message: 'Auth.Logout.Successful' }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_LOGOUT_SUCCESS'
      this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async resetPassword(body: ResetPasswordBodyType & { userAgent?: string; ip?: string }) {
    let auditLogEntry: Partial<AuditLogData> = {
      action: 'PASSWORD_RESET_ATTEMPT',
      userEmail: body.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: { otpTokenProvided: !!body.otpToken }
    }
    try {
      const result = await this.prismaService.$transaction(async (tx) => {
        await this.validateVerificationToken({
          token: body.otpToken,
          email: body.email,
          type: TypeOfVerificationCode.FORGOT_PASSWORD,
          tokenType: TokenType.OTP
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
        await this.authRepository.deleteVerificationToken({ token: body.otpToken }, tx)

        // Log out all other sessions
        await tx.refreshToken.deleteMany({ where: { userId: user.id } })
        auditLogEntry.notes = 'All refresh tokens for the user were invalidated.'

        return { message: 'Auth.Password.ResetSuccessful' }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'PASSWORD_RESET_SUCCESS'
      this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async setupTwoFactorAuth(userId: number) {
    return this.prismaService.$transaction(async (tx) => {
      const user = await tx.user.findUnique({ where: { id: userId } })
      if (!user) {
        throw EmailNotFoundException
      }
      if (user.twoFactorEnabled) {
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

      return {
        secret: secret,
        uri: otpauthUrl,
        setupToken
      }
    })
  }

  async confirmTwoFactorSetup(userId: number, setupToken: string, totpCode: string) {
    let auditLogEntry: Partial<AuditLogData> = {
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

        await this.authRepository.updateUser(
          { id: userId },
          {
            twoFactorEnabled: true,
            twoFactorSecret: tempTwoFactorSecret,
            twoFactorMethod: TwoFactorMethodType.TOTP as TwoFactorMethodTypeType,
            twoFactorVerifiedAt: new Date(),
            totpSecret: null // Đảm bảo clear totpSecret cũ nếu có
          },
          tx
        )

        const recoveryCodes = this.generateRecoveryCodes()
        const hashedRecoveryCodes = await Promise.all(
          recoveryCodes.map(async (code) => ({
            userId,
            code: await this.hashingService.hash(code)
          }))
        )
        await this.authRepository.createManyRecoveryCodes(hashedRecoveryCodes, tx)

        await this.authRepository.deleteVerificationToken({ token: setupToken }, tx)
        auditLogEntry.notes = 'Recovery codes generated and stored.'

        return {
          message: 'Auth.2FA.ConfirmSetupSuccessful',
          recoveryCodes
        }
      })
      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = '2FA_CONFIRM_SETUP_SUCCESS'
      this.auditLogService.record(auditLogEntry as AuditLogData)
      return result
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      if (error instanceof ApiException) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      if (!auditLogEntry.userEmail && userId) {
        // Cố gắng lấy email nếu chưa có
        const userForEmailOnError = await this.sharedUserRepository.findUnique({ id: userId })
        if (userForEmailOnError) auditLogEntry.userEmail = userForEmailOnError.email
      }
      this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyType & { userId: number }) {
    return this.prismaService.$transaction(async (tx) => {
      const user = await tx.user.findUnique({ where: { id: data.userId } })
      if (!user) {
        throw EmailNotFoundException
      }

      if (!user.twoFactorEnabled || !user.twoFactorSecret) {
        throw TOTPNotEnabledException
      }

      await this.authRepository.updateUser(
        { id: data.userId },
        {
          twoFactorEnabled: false,
          twoFactorSecret: null,
          twoFactorMethod: null as TwoFactorMethodTypeType | null,
          twoFactorVerifiedAt: null,
          totpSecret: null
        },
        tx
      )

      await this.authRepository.deleteRecoveryCodesByUserId(data.userId, tx)

      return { message: 'Auth.2FA.DisableSuccessful' }
    })
  }

  async verifyTwoFactor(body: TwoFactorVerifyBodyType & { userAgent: string; ip: string }, res?: Response) {
    return this.prismaService.$transaction(async (tx) => {
      const initialVerificationToken = (await this.authRepository.findUniqueVerificationToken(
        { token: body.loginSessionToken },
        tx
      )) as PrismaVerificationToken | null

      if (!initialVerificationToken || !initialVerificationToken.email) {
        throw InvalidOTPTokenException
      }

      // Lấy rememberMe từ metadata của initialVerificationToken (LOGIN_2FA token)
      let rememberMe = false // Giá trị mặc định
      if (initialVerificationToken.metadata) {
        try {
          const parsedMetadata = JSON.parse(initialVerificationToken.metadata)
          if (typeof parsedMetadata.rememberMe === 'boolean') {
            rememberMe = parsedMetadata.rememberMe
          }
        } catch (e) {
          console.warn('[AuthService verifyTwoFactor] Could not parse rememberMe from token metadata', e)
        }
      }

      const verificationToken = await this.validateVerificationToken({
        token: body.loginSessionToken,
        email: initialVerificationToken.email,
        type: TypeOfVerificationCode.LOGIN_2FA,
        tokenType: TokenType.OTP,
        deviceId: initialVerificationToken.deviceId ?? undefined
      })

      const user = await tx.user.findUnique({
        where: { email: verificationToken.email },
        include: { role: true }
      })

      if (!user || !user.twoFactorEnabled || !user.twoFactorSecret || !user.twoFactorMethod) {
        await this.authRepository.deleteVerificationToken({ token: body.loginSessionToken }, tx)
        throw TOTPNotEnabledException
      }

      let isValid2FACode = false
      if (body.type === TwoFactorMethodType.TOTP && body.code) {
        if (user.twoFactorMethod === TwoFactorMethodType.TOTP) {
          isValid2FACode = this.twoFactorService.verifyTOTP({
            email: user.email,
            token: body.code,
            secret: user.twoFactorSecret
          })
        } else {
          await this.authRepository.deleteVerificationToken({ token: body.loginSessionToken }, tx)
          throw new HttpException('Invalid 2FA method for TOTP code.', 400)
        }
      } else if (body.type === TwoFactorMethodType.RECOVERY && body.code) {
        await this.verifyRecoveryCode(user.id, body.code, tx)
        isValid2FACode = true
      } else {
        await this.authRepository.deleteVerificationToken({ token: body.loginSessionToken }, tx)
        throw new HttpException('Either a TOTP code or a recovery code (with correct type) must be provided.', 400)
      }

      if (!isValid2FACode) {
        await this.authRepository.deleteVerificationToken({ token: body.loginSessionToken }, tx)
        throw InvalidTOTPException
      }

      let deviceId = verificationToken.deviceId
      if (!deviceId && body.userAgent && body.ip) {
        try {
          const device = await this.authRepository.findOrCreateDevice(
            {
              userId: user.id,
              userAgent: body.userAgent,
              ip: body.ip
            },
            tx
          )
          deviceId = device.id
        } catch (error) {
          console.error('Lỗi khi tạo device trong verifyTwoFactor:', error)
        }
      } else if (deviceId && body.userAgent && body.ip) {
        const isValidDevice = await this.authRepository.validateDevice(deviceId, body.userAgent, body.ip, tx)
        if (!isValidDevice) {
          await this.authRepository.deleteVerificationToken({ token: body.loginSessionToken }, tx)
          throw DeviceMismatchException
        }
      }

      if (!deviceId) {
        await this.authRepository.deleteVerificationToken({ token: body.loginSessionToken }, tx)
        throw DeviceAssociationFailedException()
      }

      await this.authRepository.updateUser({ id: user.id }, { twoFactorVerifiedAt: new Date() }, tx)

      const { accessToken, refreshToken, maxAgeForRefreshTokenCookie } = await this.generateTokens(
        {
          userId: user.id,
          deviceId: deviceId,
          roleId: user.roleId,
          roleName: user.role.name
        },
        tx,
        rememberMe // Sử dụng rememberMe đã lấy từ metadata
      )

      await this.authRepository.deleteVerificationToken({ token: body.loginSessionToken }, tx)

      if (res) {
        this.tokenService.setTokenCookies(res, accessToken, refreshToken, maxAgeForRefreshTokenCookie)
      }

      return {
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role.name
      }
    })
  }

  async verifyRecoveryCode(userId: number, recoveryCodeInput: string, prismaTx?: Prisma.TransactionClient) {
    const client = prismaTx || this.prismaService
    const userWithRecoveryCodes = await this.authRepository.findUserWithRecoveryCodes(userId, client)

    if (
      !userWithRecoveryCodes ||
      !userWithRecoveryCodes.RecoveryCode ||
      userWithRecoveryCodes.RecoveryCode.length === 0
    ) {
      throw InvalidRecoveryCodeException
    }

    let matchedCodeEntry: PrismaRecoveryCode | null = null
    for (const rcEntry of userWithRecoveryCodes.RecoveryCode) {
      if (await this.hashingService.compare(recoveryCodeInput, rcEntry.code)) {
        matchedCodeEntry = rcEntry
        break
      }
    }

    if (!matchedCodeEntry) {
      throw InvalidRecoveryCodeException
    }

    if (matchedCodeEntry.used) {
      throw InvalidRecoveryCodeException
    }
    await this.authRepository.updateRecoveryCode(matchedCodeEntry.id, { used: true }, client)
    return matchedCodeEntry
  }

  private generateRecoveryCodes(): string[] {
    const codes: string[] = []
    for (let i = 0; i < 8; i++) {
      const group1 = Math.random().toString(36).substring(2, 7).toUpperCase()
      const group2 = Math.random().toString(36).substring(2, 7).toUpperCase()
      codes.push(`${group1}-${group2}`)
    }
    return codes
  }
}
