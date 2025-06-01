import { Injectable, HttpStatus, Logger } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { LoginBodyType, RegisterBodyType, TwoFactorVerifyBodyType, RegisterResType } from 'src/routes/auth/auth.model'
import { Response, Request } from 'express'
import {
  DeviceMismatchException,
  DeviceSetupFailedException,
  EmailAlreadyExistsException,
  EmailNotFoundException,
  InvalidPasswordException,
  MissingRefreshTokenException,
  SessionNotFoundException,
  InvalidRefreshTokenException,
  UnauthorizedAccessException,
  SltCookieMissingException,
  MaxVerificationAttemptsExceededException
} from 'src/routes/auth/auth.error'
import { isUniqueConstraintPrismaError } from 'src/shared/utils/type-guards.utils'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { Device, Prisma, User, UserProfile, UserStatus, Role } from '@prisma/client'
import { TypeOfVerificationCode, TwoFactorMethodType } from '../constants/auth.constants'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { v4 as uuidv4 } from 'uuid'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import envConfig from 'src/shared/config'
import { GeolocationData, GeolocationService } from 'src/shared/services/geolocation.service'
import { SessionManagementService } from './session-management.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { RolesService } from '../roles.service'
import { AuthRepository } from '../auth.repo'
import { UserRepository } from '../repositories/shared-user.repo'
import { EmailService } from '../providers/email.service'
import { TokenService } from '../providers/token.service'
import { TwoFactorService } from '../providers/2fa.service'
import { OtpService } from '../providers/otp.service'
import { DeviceService } from '../providers/device.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { JwtService } from '@nestjs/jwt'
import { ReverifyPasswordBodyType } from '../auth.dto'
import { SltContextData } from '../providers/otp.service'
import { InvalidOTPException } from '../auth.error'
import { SessionFinalizationService } from './session-finalization.service'
import { SltHelperService } from './slt-helper.service'
import { MAX_SLT_ATTEMPTS } from '../constants/auth.constants'

@Injectable()
export class AuthenticationService extends BaseAuthService {
  private readonly logger = new Logger(AuthenticationService.name)

  constructor(
    prismaService: PrismaService,
    hashingService: HashingService,
    rolesService: RolesService,
    authRepository: AuthRepository,
    userRepository: UserRepository,
    emailService: EmailService,
    tokenService: TokenService,
    twoFactorService: TwoFactorService,
    otpService: OtpService,
    deviceService: DeviceService,
    i18nService: I18nService,
    redisService: RedisService,
    geolocationService: GeolocationService,
    jwtService: JwtService,
    private readonly sessionManagementService: SessionManagementService,
    private readonly sessionFinalizationService: SessionFinalizationService,
    private readonly sltHelperService: SltHelperService
  ) {
    super(
      prismaService,
      hashingService,
      rolesService,
      authRepository,
      userRepository,
      emailService,
      tokenService,
      twoFactorService,
      otpService,
      deviceService,
      i18nService,
      redisService,
      geolocationService,
      jwtService
    )
  }

  private async generateUniqueUsername(baseUsername: string, tx: PrismaTransactionClient): Promise<string> {
    let username = baseUsername.toLowerCase().replace(/\s+/g, '_').substring(0, 20)
    username = username.replace(/[^a-z0-9_.]/g, '')

    if (username.length < 3) {
      username = `user_${username}`.substring(0, 20)
    }

    let counter = 0
    let finalUsername = username
    const MAX_USERNAME_LENGTH = 30

    while (true) {
      const existingProfile = await tx.userProfile.findUnique({
        where: { username: finalUsername }
      })
      if (!existingProfile) {
        break
      }
      counter++
      const suffix = `_${counter}`
      const availableLength = MAX_USERNAME_LENGTH - suffix.length
      finalUsername = `${username.substring(0, availableLength)}${suffix}`
      if (counter > 1000) {
        finalUsername = `user_${uuidv4().substring(0, 8)}`
        const checkRandom = await tx.userProfile.findUnique({ where: { username: finalUsername } })
        if (checkRandom) {
          throw new ApiException(
            HttpStatus.INTERNAL_SERVER_ERROR,
            'UsernameGenerationFailed',
            'Error.Auth.Register.UsernameGenerationFailed'
          )
        }
        break
      }
    }
    return finalUsername
  }

  async register(body: RegisterBodyType & { userAgent?: string; ip?: string; sltCookieValue?: string }): Promise<void> {
    if (!body.sltCookieValue) {
      throw new ApiException(HttpStatus.BAD_REQUEST, 'SltTokenMissing', 'Error.Auth.Session.InvalidLogin')
    }

    let sltJtiForFinalizeOnError: string | undefined

    try {
      await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
          body.sltCookieValue!,
          body.ip!,
          body.userAgent!,
          TypeOfVerificationCode.REGISTER
        )
        sltJtiForFinalizeOnError = sltContext.sltJti

        // Set email from SLT context
        const email = sltContext.email
        if (!email) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'EmailMissing', 'Error.Auth.Email.Missing')
        }

        if (
          !sltContext.metadata?.otpVerified ||
          sltContext.metadata?.stageVerified !== TypeOfVerificationCode.REGISTER
        ) {
          throw new ApiException(
            HttpStatus.BAD_REQUEST,
            'OtpVerificationRequired',
            'Error.Auth.Otp.VerificationRequired'
          )
        }

        if (sltContext.deviceId && sltContext.deviceId !== 0 && body.userAgent && body.ip) {
          const isValidDevice = await this.deviceService.validateDevice(
            sltContext.deviceId,
            body.userAgent,
            body.ip,
            tx
          )
          if (!isValidDevice) {
            throw new DeviceMismatchException()
          }
        }

        const clientRoleId = await this.rolesService.getClientRoleId()
        const hashedPassword = await this.hashingService.hash(body.password)

        const existingUserCheck = await tx.user.findUnique({
          where: { email: email },
          select: { id: true }
        })
        if (existingUserCheck) {
          throw new EmailAlreadyExistsException()
        }

        // Kiểm tra số điện thoại đã tồn tại chưa
        if (body.phoneNumber) {
          const existingPhoneCheck = await tx.userProfile.findFirst({
            where: { phoneNumber: body.phoneNumber },
            select: { id: true }
          })
          if (existingPhoneCheck) {
            throw new ApiException(HttpStatus.CONFLICT, 'PhoneNumberTaken', 'Error.Auth.Register.PhoneNumberTaken')
          }
        }

        let finalUsername: string
        if (body.username) {
          finalUsername = body.username
          const existingProfileByUsername = await tx.userProfile.findUnique({
            where: { username: finalUsername }
          })
          if (existingProfileByUsername) {
            throw new ApiException(HttpStatus.CONFLICT, 'UsernameTaken', 'Error.Auth.Register.UsernameTaken')
          }
        } else {
          const baseUsername = `${body.lastName}${body.firstName}`
          finalUsername = await this.generateUniqueUsername(baseUsername, tx)
        }

        const userDataToCreate: Omit<Prisma.UserCreateInput, 'role'> & { roleId: number } = {
          email: email,
          password: hashedPassword,
          roleId: clientRoleId,
          status: UserStatus.ACTIVE,
          isEmailVerified: true, // Email already verified via OTP
          userProfile: {
            create: {
              firstName: body.firstName,
              lastName: body.lastName,
              username: finalUsername,
              phoneNumber: body.phoneNumber
            }
          }
        }

        await this.userRepository.createUserInternal(userDataToCreate, tx)
      })

      return
    } catch (error) {
      if (sltJtiForFinalizeOnError) {
        try {
          await this.otpService.incrementSltAttempts(sltJtiForFinalizeOnError)
        } catch (sltError) {
          throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
        }
      }

      if (isUniqueConstraintPrismaError(error)) {
        if (error.meta?.target && Array.isArray(error.meta?.target) && error.meta.target.includes('email')) {
          throw new EmailAlreadyExistsException()
        }
        if (error.meta?.target && Array.isArray(error.meta?.target) && error.meta.target.includes('username')) {
          throw new ApiException(HttpStatus.CONFLICT, 'UsernameTaken', 'Error.Auth.Register.UsernameTaken')
        }
      }

      throw error
    }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res?: Response) {
    try {
      const user = await this.userRepository.findUniqueWithDetails({ email: body.email })
      if (!user) {
        throw new EmailNotFoundException()
      }

      if (user.status !== UserStatus.ACTIVE) {
        throw new ApiException(HttpStatus.FORBIDDEN, 'UserInactive', 'Error.Auth.User.NotActive')
      }

      if (!user.role) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'UserRoleMissing', 'Error.Auth.User.RoleMissing')
      }

      const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
      if (!isPasswordMatch) {
        throw new InvalidPasswordException()
      }

      let device: Device
      try {
        device = await this.deviceService.findOrCreateDevice({
          userId: user.id,
          userAgent: body.userAgent,
          ip: body.ip
        })
      } catch (error) {
        throw new DeviceSetupFailedException()
      }

      const shouldAskToTrustDevice = !device.isTrusted
      const sessionId = uuidv4()
      const now = new Date()

      const geoLocation: GeolocationData | null = this.geolocationService.lookup(body.ip)

      if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod && !device.isTrusted) {
        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: body.ip,
          userAgent: body.userAgent,
          purpose: TypeOfVerificationCode.LOGIN_2FA,
          metadata: { rememberMe: body.rememberMe, initiatedFrom: 'login' }
        })

        if (res) {
          this.sltHelperService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_2FA)
        }

        const message = await this.i18nService.translate('Auth.Login.2FARequired', {
          lang: I18nContext.current()?.lang
        })
        return {
          message,
          twoFactorMethod: user.twoFactorMethod
        }
      } else if (!device.isTrusted) {
        const sltJwt = await this.otpService.initiateOtpWithSltCookie({
          email: user.email,
          userId: user.id,
          deviceId: device.id,
          ipAddress: body.ip,
          userAgent: body.userAgent,
          purpose: TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
          metadata: { rememberMe: body.rememberMe, initiatedFrom: 'login' }
        })

        if (res) {
          this.sltHelperService.setSltCookie(res, sltJwt, TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP)
        }

        const message = await this.i18nService.translate('Auth.Login.DeviceVerificationOtpRequired', {
          lang: I18nContext.current()?.lang
        })
        return {
          message,
          twoFactorMethod: TwoFactorMethodType.OTP
        }
      }

      if (!res) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      const userForFinalization = {
        ...user,
        userProfile: user.userProfile,
        role: {
          id: user.role.id,
          name: user.role.name
        }
      }

      const finalizationResult = await this.sessionFinalizationService.finalizeSuccessfulAuthentication({
        user: userForFinalization,
        device,
        rememberMe: body.rememberMe,
        ipAddress: body.ip,
        userAgent: body.userAgent,
        source: 'direct-login',
        res,
        existingSessionId: sessionId
      })

      return {
        ...finalizationResult,
        askToTrustDevice: shouldAskToTrustDevice
      }
    } catch (error) {
      this.logger.error('[AuthenticationService.login] Caught error:', error, typeof error)
      throw error
    }
  }

  async logout(req: Request, res: Response) {
    const refreshTokenFromCookie = this.tokenService.extractRefreshTokenFromRequest(req)
    let activeUserFromToken: AccessTokenPayload | undefined = undefined

    try {
      const accessToken = this.tokenService.extractTokenFromHeader(req)
      if (accessToken) {
        try {
          activeUserFromToken = await this.tokenService.verifyAccessToken(accessToken)
        } catch (e) {
          throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
        }
      }

      if (!refreshTokenFromCookie) {
        if (activeUserFromToken && activeUserFromToken.sessionId) {
          await this.tokenService.invalidateSession(activeUserFromToken.sessionId, 'USER_LOGOUT_NO_RT_COOKIE_WITH_AT')
        }

        this.tokenService.clearTokenCookies(res)
        const sltCookieConfig = envConfig.cookie.sltToken
        res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })

        const message = await this.i18nService.translate('Auth.Logout.Processed', {
          lang: I18nContext.current()?.lang
        })
        return { message }
      }

      const sessionId = await this.tokenService.findSessionIdByRefreshTokenJti(refreshTokenFromCookie)
      if (sessionId) {
        if (activeUserFromToken && activeUserFromToken.sessionId !== sessionId) {
          throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
        }

        await this.tokenService.invalidateSession(sessionId, 'USER_LOGOUT')
        await this.tokenService.markRefreshTokenJtiAsUsed(refreshTokenFromCookie, sessionId)
      } else {
        await this.tokenService.markRefreshTokenJtiAsUsed(refreshTokenFromCookie, 'UNKNOWN_SESSION_ON_LOGOUT')
      }

      this.tokenService.clearTokenCookies(res)

      const sltCookieConfig = envConfig.cookie.sltToken
      res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })

      const message = await this.i18nService.translate('Auth.Logout.Success', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }

  async setRememberMe(
    activeUser: AccessTokenPayload,
    rememberMe: boolean,
    req: Request,
    res: Response,
    ip: string,
    userAgent: string
  ) {
    const currentRefreshTokenJti = this.tokenService.extractRefreshTokenFromRequest(req)
    if (!currentRefreshTokenJti) {
      throw MissingRefreshTokenException
    }

    const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${activeUser.sessionId}`
    const sessionDetails = await this.redisService.hgetall(sessionDetailsKey)

    if (Object.keys(sessionDetails).length === 0) {
      throw SessionNotFoundException
    }

    if (sessionDetails.currentRefreshTokenJti !== currentRefreshTokenJti) {
      await this.tokenService.invalidateSession(activeUser.sessionId, 'RT_JTI_MISMATCH_ON_REMEMBER_ME')
      this.tokenService.clearTokenCookies(res)
      throw InvalidRefreshTokenException
    }

    const newMaxAgeForRefreshTokenCookie = rememberMe
      ? envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
      : envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE

    this.tokenService.setTokenCookies(res, '', currentRefreshTokenJti, newMaxAgeForRefreshTokenCookie, true)

    await this.redisService.hset(sessionDetailsKey, 'rememberMe', rememberMe.toString())

    const message = await this.i18nService.translate('Auth.RememberMe.Set', {
      lang: I18nContext.current()?.lang
    })
    return { message }
  }

  async completeLoginWithUntrustedDeviceOtp(
    body: TwoFactorVerifyBodyType & { userAgent: string; ip: string },
    sltContext: SltContextData & { sltJti: string },
    res?: Response
  ) {
    try {
      if (!res) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      const user = await this.userRepository.findUniqueWithDetails({ id: sltContext.userId })
      if (!user || !user.role) {
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new ApiException(HttpStatus.NOT_FOUND, 'UserNotFound', 'Error.User.NotFound')
      }

      if (!body.code) {
        const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
        if (newAttempts >= MAX_SLT_ATTEMPTS) {
          await this.otpService.finalizeSlt(sltContext.sltJti)
          if (res) this.tokenService.clearSltCookie(res)
          throw new MaxVerificationAttemptsExceededException()
        }
        throw new ApiException(HttpStatus.BAD_REQUEST, 'OtpCodeMissing', 'Error.Auth.Otp.Required')
      }

      // Xác thực OTP code
      try {
        await this.otpService.verifyOtpOnly(
          sltContext.email || user.email,
          body.code,
          TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
          sltContext.userId,
          body.ip,
          body.userAgent
        )
      } catch (error) {
        const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
        if (newAttempts >= MAX_SLT_ATTEMPTS) {
          await this.otpService.finalizeSlt(sltContext.sltJti)
          if (res) this.tokenService.clearSltCookie(res)
          throw new MaxVerificationAttemptsExceededException()
        }
        throw error
      }

      let deviceToUse = await this.deviceService.findDeviceById(sltContext.deviceId)
      if (!deviceToUse) {
        deviceToUse = await this.deviceService.findOrCreateDevice({
          userId: user.id,
          userAgent: body.userAgent,
          ip: body.ip
        })
      } else if (deviceToUse.userId !== user.id) {
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new DeviceMismatchException()
      }

      const userForFinalization = {
        ...user,
        userProfile: user.userProfile,
        role: {
          id: user.role.id,
          name: user.role.name
        }
      }

      const shouldTrustDevice = body.rememberMe === true
      if (shouldTrustDevice && !deviceToUse.isTrusted) {
        await this.deviceService.trustDevice(deviceToUse.id, user.id)
      }

      const finalizationResult = await this.sessionFinalizationService.finalizeSuccessfulAuthentication({
        user: userForFinalization,
        device: deviceToUse,
        rememberMe: body.rememberMe === undefined ? false : body.rememberMe,
        ipAddress: body.ip,
        userAgent: body.userAgent,
        source: 'untrusted-device-otp-verification',
        res,
        sltToFinalize: { jti: sltContext.sltJti, purpose: sltContext.purpose as TypeOfVerificationCode }
      })

      return {
        ...finalizationResult
      }
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }

  async finalizeOauthLogin(
    user: User & { role: { id: number; name: string }; userProfile: UserProfile | null },
    device: Device,
    rememberMe: boolean,
    ipAddress: string,
    userAgent: string,
    source: string = 'oauth-general',
    res?: Response
  ) {
    try {
      const sessionId = uuidv4()

      if (!res) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      const finalizationResult = await this.sessionFinalizationService.finalizeSuccessfulAuthentication({
        user,
        device,
        rememberMe,
        ipAddress,
        userAgent,
        source,
        res,
        existingSessionId: sessionId
      })

      return {
        userId: finalizationResult.id,
        email: finalizationResult.email,
        role: finalizationResult.role,
        roleId: user.role.id,
        isDeviceTrustedInSession: finalizationResult.isDeviceTrustedInSession,
        currentDeviceId: device.id,
        userProfile: finalizationResult.userProfile
      }
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }

  async reverifyPassword(
    userId: number,
    sessionId: string,
    body: ReverifyPasswordBodyType,
    ipAddress?: string,
    userAgent?: string,
    sltCookieValue?: string,
    res?: Response
  ): Promise<{ message: string }> {
    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
        include: { RecoveryCode: true, userProfile: true }
      })

      if (!user) {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      let verificationSuccess = false
      let sltContextForOtp: (SltContextData & { sltJti: string }) | null = null

      if (body.verificationMethod === 'password') {
        if (!body.password) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Password.Invalid')
        }
        const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
        if (!isPasswordMatch) {
          throw new InvalidPasswordException()
        }
        verificationSuccess = true
      } else if (body.verificationMethod === 'otp') {
        if (!body.otpCode) {
          throw new InvalidOTPException()
        }
        if (!sltCookieValue) {
          throw new SltCookieMissingException()
        }

        try {
          sltContextForOtp = await this.otpService.validateSltFromCookieAndGetContext(
            sltCookieValue,
            ipAddress || 'N/A',
            userAgent || 'N/A',
            TypeOfVerificationCode.REVERIFY_SESSION_OTP
          )

          if (sltContextForOtp.userId !== userId) {
            await this.otpService.finalizeSlt(sltContextForOtp.sltJti)
            if (res) this.tokenService.clearSltCookie(res)
            throw new UnauthorizedAccessException()
          }

          await this.otpService.verifyOtpOnly(
            user.email,
            body.otpCode,
            TypeOfVerificationCode.REVERIFY_SESSION_OTP,
            userId,
            ipAddress,
            userAgent
          )
          verificationSuccess = true

          await this.otpService.finalizeSlt(sltContextForOtp.sltJti)
          if (res) this.tokenService.clearSltCookie(res)
        } catch (otpOrSltError) {
          if (sltContextForOtp) {
            await this.sltHelperService.handleSltAttemptIncrementAndFinalization(
              sltContextForOtp.sltJti,
              MAX_SLT_ATTEMPTS,
              'reverifyPasswordWithOtp',
              res
            )
          }
          throw otpOrSltError
        }
      } else if (body.verificationMethod === 'totp') {
        if (!body.totpCode) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidTOTP')
        }
        if (!user.twoFactorEnabled || !user.twoFactorSecret || user.twoFactorMethod !== TwoFactorMethodType.TOTP) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'OperationNotAllowed', 'Error.Auth.2FA.NotEnabled')
        }
        const isTotpValid = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: user.twoFactorSecret,
          token: body.totpCode
        })
        if (!isTotpValid) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidTOTP')
        }
        verificationSuccess = true
      } else if (body.verificationMethod === 'recovery') {
        if (!body.recoveryCode) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidRecoveryCode')
        }
        if (!user.twoFactorEnabled) {
          throw new ApiException(HttpStatus.BAD_REQUEST, 'OperationNotAllowed', 'Error.Auth.2FA.NotEnabled')
        }
        await this.twoFactorService.verifyRecoveryCode(userId, body.recoveryCode, this.prismaService)
        verificationSuccess = true
      } else {
        const exhaustiveCheck: never = body
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Global.ValidationFailed')
      }

      if (verificationSuccess) {
        const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
        const removedCount = await this.redisService.hdel(sessionDetailsKey, 'requiresPasswordReverification')

        const message = await this.i18nService.translate('Auth.Session.ReverifiedSuccessfully', {
          lang: I18nContext.current()?.lang
        })
        return { message }
      } else {
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
    } catch (error) {
      throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
    }
  }

  async initiateSessionReverificationOtp(
    activeUser: AccessTokenPayload,
    ipAddress: string,
    userAgent: string
  ): Promise<string> {
    const user = await this.userRepository.findUnique({ id: activeUser.userId })
    if (!user || !user.email) {
      throw new ApiException(HttpStatus.NOT_FOUND, 'UserNotFoundForSlt', 'Error.User.NotFound')
    }
    const userEmail = user.email

    const userProfile = await this.prismaService.userProfile.findUnique({ where: { userId: activeUser.userId } })
    const displayName = userProfile?.firstName || userProfile?.lastName || userEmail

    try {
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: userEmail,
        userId: activeUser.userId,
        deviceId: activeUser.deviceId,
        ipAddress: ipAddress,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.REVERIFY_SESSION_OTP
      })

      return sltJwt
    } catch (error) {
      if (error instanceof ApiException) {
        throw error
      }
      throw new ApiException(
        HttpStatus.INTERNAL_SERVER_ERROR,
        'SLT_INITIATION_FAILED',
        'Error.Auth.Slt.InitiationFailed'
      )
    }
  }
}
