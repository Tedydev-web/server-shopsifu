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
import { AuditLogData, AuditLogStatus, AuditLogService } from 'src/routes/audit-log/audit-log.service'
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
    auditLogService: AuditLogService,
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
      auditLogService,
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
        this.logger.error(`Could not generate unique username for base: ${baseUsername} after 1000 attempts.`)

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
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'USER_REGISTER_ATTEMPT',
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        sltCookieProvided: !!body.sltCookieValue,
        providedFirstName: body.firstName,
        providedLastName: body.lastName,
        providedUsername: body.username,
        providedPhoneNumber: body.phoneNumber
      }
    }

    if (!body.sltCookieValue) {
      auditLogEntry.errorMessage = 'SLT cookie is missing for registration.'
      auditLogEntry.details.reason = 'MISSING_SLT_COOKIE_REGISTER'
      await this.auditLogService.record(auditLogEntry as AuditLogData)
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

        if (!auditLogEntry.userEmail && email) {
          auditLogEntry.userEmail = email
        }

        auditLogEntry.details.sltJti = sltContext.sltJti
        auditLogEntry.details.sltPurpose = sltContext.purpose
        auditLogEntry.details.sltDeviceIdFromContext = sltContext.deviceId
        auditLogEntry.details.sltUserIdFromContext = sltContext.userId
        auditLogEntry.details.sltEmailFromContext = email

        if (
          !sltContext.metadata?.otpVerified ||
          sltContext.metadata?.stageVerified !== TypeOfVerificationCode.REGISTER
        ) {
          auditLogEntry.errorMessage = 'OTP not verified for registration via SLT context.'
          auditLogEntry.details.reason = 'SLT_OTP_NOT_VERIFIED_FOR_REGISTER'
          auditLogEntry.details.sltMetadata = sltContext.metadata as Prisma.JsonObject | undefined
          throw new ApiException(
            HttpStatus.BAD_REQUEST,
            'OtpVerificationRequired',
            'Error.Auth.Otp.VerificationRequired'
          )
        }
        auditLogEntry.details.sltOtpStageVerified = true

        if (sltContext.deviceId && sltContext.deviceId !== 0 && body.userAgent && body.ip) {
          const isValidDevice = await this.deviceService.validateDevice(
            sltContext.deviceId,
            body.userAgent,
            body.ip,
            tx
          )
          if (!isValidDevice) {
            auditLogEntry.errorMessage = 'Device mismatch on register SLT'
            auditLogEntry.details.reason = 'DEVICE_MISMATCH_ON_REGISTER_SLT'
            auditLogEntry.details.validatedDeviceId = sltContext.deviceId
            throw new DeviceMismatchException()
          }
          auditLogEntry.details.deviceValidatedOnRegisterSlt = true
        } else if (sltContext.deviceId === 0) {
          auditLogEntry.details.sltDeviceWasPlaceholder = true
        }

        const clientRoleId = await this.rolesService.getClientRoleId()
        const hashedPassword = await this.hashingService.hash(body.password)

        const existingUserCheck = await tx.user.findUnique({
          where: { email: email },
          select: { id: true }
        })
        if (existingUserCheck) {
          auditLogEntry.errorMessage = 'Email already exists (pre-create check)'
          auditLogEntry.details.reason = 'EMAIL_ALREADY_EXISTS_PRE_CREATE_CHECK'
          throw new EmailAlreadyExistsException()
        }

        // Kiểm tra số điện thoại đã tồn tại chưa
        if (body.phoneNumber) {
          const existingPhoneCheck = await tx.userProfile.findFirst({
            where: { phoneNumber: body.phoneNumber },
            select: { id: true }
          })
          if (existingPhoneCheck) {
            auditLogEntry.errorMessage = 'Phone number already exists'
            auditLogEntry.details.reason = 'PHONE_NUMBER_ALREADY_EXISTS'
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
            auditLogEntry.errorMessage = `Username '${finalUsername}' already exists.`
            auditLogEntry.details.reason = 'USERNAME_ALREADY_EXISTS'
            throw new ApiException(HttpStatus.CONFLICT, 'UsernameTaken', 'Error.Auth.Register.UsernameTaken')
          }
        } else {
          const baseUsername = `${body.lastName}${body.firstName}`
          finalUsername = await this.generateUniqueUsername(baseUsername, tx)
        }
        auditLogEntry.details.finalUsername = finalUsername

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

        // Success, update audit log
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_REGISTERED'
      })

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      return
    } catch (error) {
      if (sltJtiForFinalizeOnError) {
        try {
          await this.otpService.incrementSltAttempts(sltJtiForFinalizeOnError)
        } catch (sltError) {
          this.logger.error(`Error incrementing SLT attempts: ${sltError.message}`, sltError.stack)
        }
      }

      auditLogEntry.errorMessage = error?.message || 'Unknown registration error'
      if (isUniqueConstraintPrismaError(error)) {
        if (error.meta?.target && Array.isArray(error.meta?.target) && error.meta.target.includes('email')) {
          auditLogEntry.errorMessage = 'Email already exists (unique constraint error)'
          auditLogEntry.details.reason = 'EMAIL_ALREADY_EXISTS_UNIQUE_CONSTRAINT'
          await this.auditLogService.record(auditLogEntry as AuditLogData)
          throw new EmailAlreadyExistsException()
        }
        if (error.meta?.target && Array.isArray(error.meta?.target) && error.meta.target.includes('username')) {
          auditLogEntry.errorMessage = 'Username already exists (unique constraint error)'
          auditLogEntry.details.reason = 'USERNAME_ALREADY_EXISTS_UNIQUE_CONSTRAINT'
          await this.auditLogService.record(auditLogEntry as AuditLogData)
          throw new ApiException(HttpStatus.CONFLICT, 'UsernameTaken', 'Error.Auth.Register.UsernameTaken')
        }
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }, res?: Response) {
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
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
      const user = await this.userRepository.findUniqueWithDetails({ email: body.email })
      if (!user) {
        auditLogEntry.errorMessage = 'User not found for login.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND'
        throw new EmailNotFoundException()
      }
      auditLogEntry.userId = user.id

      if (user.status !== UserStatus.ACTIVE) {
        this.logger.warn(`[DEBUG AuthenticationService login] User ${user.email} is not active. Status: ${user.status}`)
        auditLogEntry.errorMessage = 'User account is not active.'
        auditLogEntry.details.reason = 'USER_NOT_ACTIVE'
        auditLogEntry.details.userStatus = user.status
        throw new ApiException(HttpStatus.FORBIDDEN, 'UserInactive', 'Error.Auth.User.NotActive')
      }

      if (!user.role) {
        this.logger.error(
          `[AuthenticationService.login] User ${user.id} does not have a role. Cannot finalize session.`
        )
        auditLogEntry.errorMessage = 'User role not found during login finalization.'
        auditLogEntry.details.reason = 'USER_ROLE_MISSING_LOGIN_FINALIZE'
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'UserRoleMissing', 'Error.Auth.User.RoleMissing')
      }

      const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
      if (!isPasswordMatch) {
        this.logger.warn('[DEBUG AuthenticationService login] Invalid password for user:', user.email)
        auditLogEntry.errorMessage = 'Invalid password provided for login.'
        auditLogEntry.details.reason = 'INVALID_PASSWORD'
        throw new InvalidPasswordException()
      }

      let device: Device
      try {
        device = await this.deviceService.findOrCreateDevice({
          userId: user.id,
          userAgent: body.userAgent,
          ip: body.ip
        })
        auditLogEntry.details.deviceId = device.id
      } catch (error) {
        this.logger.error('[DEBUG AuthenticationService login] Error creating/finding device:', error)
        auditLogEntry.errorMessage = 'Failed to setup or find device during login.'
        auditLogEntry.details.deviceError = 'DeviceSetupFailed'
        throw new DeviceSetupFailedException()
      }

      const shouldAskToTrustDevice = !device.isTrusted
      const sessionId = uuidv4()
      const now = new Date()

      const geoLocation: GeolocationData | null = this.geolocationService.lookup(body.ip)
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object' && geoLocation) {
        auditLogEntry.details.location = `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
      }

      if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod && !device.isTrusted) {
        auditLogEntry.details.twoFactorMethod = user.twoFactorMethod
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.notes = '2FA required: Device not trusted.'
        await this.auditLogService.record(auditLogEntry as AuditLogData)

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
        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.notes = 'Device verification OTP required: Device not trusted.'
        await this.auditLogService.record(auditLogEntry as AuditLogData)

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
        this.logger.error('[AuthenticationService.login] Response object (res) is undefined. Cannot finalize session.')
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

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_LOGIN_SUCCESS'

      return {
        ...finalizationResult,
        askToTrustDevice: shouldAskToTrustDevice
      }
    } catch (error) {
      this.logger.error('[AuthenticationService.login] Caught error:', error, typeof error)
      if (!auditLogEntry.errorMessage) {
        if (error instanceof ApiException) {
          auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
        } else if (error instanceof Error) {
          auditLogEntry.errorMessage = error.message
        } else if (typeof error === 'string') {
          auditLogEntry.errorMessage = error
        } else {
          try {
            auditLogEntry.errorMessage = JSON.stringify(error)
          } catch (stringifyError) {
            this.logger.error('[AuthenticationService.login] Failed to stringify caught error:', stringifyError)
            auditLogEntry.errorMessage = 'Unknown error during login (non-serializable error object)'
          }
        }
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async logout(req: Request, res: Response) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'USER_LOGOUT_ATTEMPT',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] as string,
      status: AuditLogStatus.FAILURE
    }

    const refreshTokenFromCookie = this.tokenService.extractRefreshTokenFromRequest(req)
    let activeUserFromToken: AccessTokenPayload | undefined = undefined

    try {
      const accessToken = this.tokenService.extractTokenFromHeader(req)
      if (accessToken) {
        try {
          activeUserFromToken = await this.tokenService.verifyAccessToken(accessToken)
          auditLogEntry.userId = activeUserFromToken.userId
          if (activeUserFromToken.sessionId) {
            auditLogEntry.details = {
              ...(auditLogEntry.details as object),
              sessionId: activeUserFromToken.sessionId
            } as Prisma.JsonObject
          }
        } catch (e) {
          this.logger.debug(
            'Could not decode or verify access token during logout. It might be expired or invalid. Will proceed if refresh token is present.'
          )
        }
      }

      if (!refreshTokenFromCookie) {
        this.logger.log('Logout called without refresh token cookie.')
        if (activeUserFromToken && activeUserFromToken.sessionId) {
          this.logger.log(
            `Invalidating session ${activeUserFromToken.sessionId} based on Access Token as Refresh Token cookie is missing.`
          )
          await this.tokenService.invalidateSession(activeUserFromToken.sessionId, 'USER_LOGOUT_NO_RT_COOKIE_WITH_AT')
          auditLogEntry.notes =
            'Logout processed: No refresh token cookie, session invalidated based on Access Token. Client cookies cleared.'
          auditLogEntry.details = {
            ...(auditLogEntry.details as object),
            sessionInvalidatedByAT: activeUserFromToken.sessionId
          } as Prisma.JsonObject
        } else {
          this.logger.log(
            'No refresh token cookie and no valid Access Token session to invalidate. Clearing only client-side cookies.'
          )
          auditLogEntry.notes = 'Logout processed: No refresh token cookie, no AT session. Client cookies cleared.'
        }

        this.tokenService.clearTokenCookies(res)
        const sltCookieConfig = envConfig.cookie.sltToken
        res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'USER_LOGOUT_SUCCESS'
        await this.auditLogService.record(auditLogEntry as AuditLogData)
        const message = await this.i18nService.translate('Auth.Logout.Processed', {
          lang: I18nContext.current()?.lang
        })
        return { message }
      }

      const sessionId = await this.tokenService.findSessionIdByRefreshTokenJti(refreshTokenFromCookie)
      if (sessionId) {
        auditLogEntry.details = {
          ...(auditLogEntry.details as object),
          sessionIdBeingLoggedOut: sessionId
        } as Prisma.JsonObject
        if (activeUserFromToken && activeUserFromToken.sessionId !== sessionId) {
          this.logger.warn(
            `Logout for session ${sessionId} initiated by user with active session ${activeUserFromToken.sessionId}. This is unusual for standard logout.`
          )
          auditLogEntry.notes = 'Logout for a session different from the active AT session.'
        }
        await this.tokenService.invalidateSession(sessionId, 'USER_LOGOUT')
        await this.tokenService.markRefreshTokenJtiAsUsed(refreshTokenFromCookie, sessionId)
      } else {
        await this.tokenService.markRefreshTokenJtiAsUsed(refreshTokenFromCookie, 'UNKNOWN_SESSION_ON_LOGOUT')
        this.logger.warn(
          `Session ID not found for refresh token JTI during logout. Refresh token JTI: ${refreshTokenFromCookie.substring(0, 10)}...`
        )
        auditLogEntry.notes = 'Session not found for refresh token, but RT JTI marked as used.'
      }

      this.tokenService.clearTokenCookies(res)

      const sltCookieConfig = envConfig.cookie.sltToken
      res.clearCookie(sltCookieConfig.name, { path: sltCookieConfig.path, domain: sltCookieConfig.domain })

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_LOGOUT_SUCCESS'
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      const message = await this.i18nService.translate('Auth.Logout.Success', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      const finalErrorAuditLog: AuditLogData = {
        action: auditLogEntry.action || 'USER_LOGOUT_EXCEPTION',
        status: AuditLogStatus.FAILURE,
        userId: auditLogEntry.userId,
        userEmail: auditLogEntry.userEmail,
        ipAddress: auditLogEntry.ipAddress || req?.ip,
        userAgent: auditLogEntry.userAgent || (req?.headers['user-agent'] as string),
        errorMessage: error instanceof Error ? error.message : String(error),
        details: (auditLogEntry.details || { errorType: error?.constructor?.name }) as Prisma.JsonObject,
        notes: auditLogEntry.notes || 'Exception during logout process',
        entity: auditLogEntry.entity,
        entityId: auditLogEntry.entityId,
        geoLocation: auditLogEntry.geoLocation as Prisma.JsonObject | undefined
      }

      await this.auditLogService.record(finalErrorAuditLog)

      this.logger.error(
        `Logout failed: ${finalErrorAuditLog.errorMessage}`,
        error instanceof Error ? error.stack : undefined,
        `Audit Details: ${JSON.stringify(finalErrorAuditLog.details)}`
      )

      this.tokenService.clearTokenCookies(res)
      const sltCookieConfigOnError = envConfig.cookie.sltToken
      res.clearCookie(sltCookieConfigOnError.name, {
        path: sltCookieConfigOnError.path,
        domain: sltCookieConfigOnError.domain
      })

      throw error
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
      this.logger.warn(
        `[AuthService setRememberMe] No refresh token JTI found in request for user ${activeUser.userId}`
      )

      throw MissingRefreshTokenException
    }

    const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${activeUser.sessionId}`
    const sessionDetails = await this.redisService.hgetall(sessionDetailsKey)

    if (Object.keys(sessionDetails).length === 0) {
      this.logger.warn(
        `[AuthService setRememberMe] Session details not found in Redis for session ${activeUser.sessionId}, user ${activeUser.userId}. Cannot update rememberMe.`
      )
      throw SessionNotFoundException
    }

    if (sessionDetails.currentRefreshTokenJti !== currentRefreshTokenJti) {
      this.logger.error(
        `[AuthService setRememberMe] CRITICAL: Mismatch between request RT JTI and session RT JTI for user ${activeUser.userId}, session ${activeUser.sessionId}. Request JTI: ${currentRefreshTokenJti}, Session JTI: ${sessionDetails.currentRefreshTokenJti}. Aborting rememberMe update and invalidating session.`
      )
      await this.tokenService.invalidateSession(activeUser.sessionId, 'RT_JTI_MISMATCH_ON_REMEMBER_ME')
      this.tokenService.clearTokenCookies(res)
      throw InvalidRefreshTokenException
    }

    const newMaxAgeForRefreshTokenCookie = rememberMe
      ? envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
      : envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE

    this.tokenService.setTokenCookies(res, '', currentRefreshTokenJti, newMaxAgeForRefreshTokenCookie, true)

    await this.redisService.hset(sessionDetailsKey, 'rememberMe', rememberMe.toString())

    this.auditLogService.record({
      userId: activeUser.userId,
      action: 'REMEMBER_ME_UPDATED',
      status: AuditLogStatus.SUCCESS,
      entity: 'Session',
      entityId: activeUser.sessionId,
      ipAddress: ip,
      userAgent: userAgent,
      details: {
        rememberMe,
        oldMaxAge: sessionDetails.rememberMeMaxAge,
        newMaxAge: newMaxAgeForRefreshTokenCookie
      } as Prisma.JsonObject
    })

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
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'COMPLETE_LOGIN_UNTRUSTED_DEVICE_ATTEMPT',
      userId: sltContext.userId,
      userEmail: sltContext.email,
      ipAddress: body.ip,
      userAgent: body.userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        sltJti: sltContext.sltJti,
        sltPurpose: sltContext.purpose,
        sltDeviceId: sltContext.deviceId,
        otpCodeProvided: !!body.code,
        rememberMeProvided: body.rememberMe
      }
    }

    try {
      if (!res) {
        this.logger.error(
          '[completeLoginWithUntrustedDeviceOtp] Response object (res) is required but was not provided. Cannot finalize session.'
        )
        auditLogEntry.errorMessage = 'Response object missing, cannot finalize session.'
        auditLogEntry.details.reason = 'MISSING_RESPONSE_OBJECT_UNTRUSTED_LOGIN'
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }

      const user = await this.userRepository.findUniqueWithDetails({ id: sltContext.userId })
      if (!user || !user.role) {
        auditLogEntry.errorMessage = 'User not found from SLT context for untrusted device login.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND_UNTRUSTED_LOGIN'
        await this.otpService.finalizeSlt(sltContext.sltJti)
        if (res) this.tokenService.clearSltCookie(res)
        throw new ApiException(HttpStatus.NOT_FOUND, 'UserNotFound', 'Error.User.NotFound')
      }
      auditLogEntry.userEmail = user.email

      // Kiểm tra xem người dùng đã cung cấp mã OTP chưa
      if (!body.code) {
        auditLogEntry.errorMessage = 'No OTP code provided for untrusted device login.'
        auditLogEntry.details.reason = 'NO_OTP_CODE_PROVIDED'
        const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
        auditLogEntry.details.sltAttempts = newAttempts
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
        auditLogEntry.errorMessage =
          error instanceof Error ? error.message : 'Invalid OTP code for untrusted device login'
        auditLogEntry.details.reason = 'INVALID_OTP_CODE'
        const newAttempts = await this.otpService.incrementSltAttempts(sltContext.sltJti)
        auditLogEntry.details.sltAttempts = newAttempts
        if (newAttempts >= MAX_SLT_ATTEMPTS) {
          await this.otpService.finalizeSlt(sltContext.sltJti)
          if (res) this.tokenService.clearSltCookie(res)
          throw new MaxVerificationAttemptsExceededException()
        }
        throw error
      }

      let deviceToUse = await this.deviceService.findDeviceById(sltContext.deviceId)
      if (!deviceToUse) {
        this.logger.warn(
          `Device ID ${sltContext.deviceId} from SLT context not found. Attempting to create or find matching device for user ${user.id}`
        )
        deviceToUse = await this.deviceService.findOrCreateDevice({
          userId: user.id,
          userAgent: body.userAgent,
          ip: body.ip
        })
        auditLogEntry.details.deviceRecreatedOrFound = deviceToUse.id
      } else if (deviceToUse.userId !== user.id) {
        this.logger.error(
          `Device ID ${sltContext.deviceId} from SLT context belongs to user ${deviceToUse.userId}, but SLT context is for user ${user.id}. Critical mismatch.`
        )
        auditLogEntry.errorMessage = 'Device in SLT context does not belong to the authenticated user.'
        auditLogEntry.details.reason = 'DEVICE_USER_MISMATCH_SLT_UNTRUSTED'
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
        this.logger.log(`Marking device ${deviceToUse.id} as trusted for user ${user.id} due to rememberMe=true.`)
        await this.deviceService.trustDevice(deviceToUse.id, user.id)
        auditLogEntry.details.deviceTrusted = true
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

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'COMPLETE_LOGIN_UNTRUSTED_DEVICE_SUCCESS'
      auditLogEntry.details.finalDeviceId = deviceToUse.id
      auditLogEntry.details.finalSessionId = finalizationResult.sessionId
      auditLogEntry.details.finalAccessTokenJti = finalizationResult.accessTokenJti
      auditLogEntry.details.isDeviceTrusted = deviceToUse.isTrusted
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return {
        ...finalizationResult
      }
    } catch (error) {
      if (!auditLogEntry.errorMessage && error instanceof Error) {
        auditLogEntry.errorMessage = error.message
      }
      if (!auditLogEntry.details.reason && error instanceof ApiException) {
        auditLogEntry.details.reason = error.errorCode
      } else if (!auditLogEntry.details.reason) {
        auditLogEntry.details.reason = 'UNHANDLED_EXCEPTION_UNTRUSTED_LOGIN'
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
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
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'USER_OAUTH_LOGIN_FINALIZE_ATTEMPT',
      userId: user.id,
      userEmail: user.email,
      ipAddress: ipAddress,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        source,
        finalRememberMe: rememberMe,
        initialDeviceId: device.id
      }
    }

    try {
      const sessionId = uuidv4()

      if (!res) {
        this.logger.error(
          '[AuthenticationService.finalizeOauthLogin] Response object (res) is undefined. Cannot finalize session.'
        )
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

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_OAUTH_LOGIN_FINALIZE_SUCCESS'

      await this.auditLogService.record(auditLogEntry as AuditLogData)

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
      this.logger.error(
        `[AuthenticationService.finalizeOauthLogin] Error finalizing OAuth login for user ${user.email}:`,
        error
      )
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      if (error instanceof ApiException && !auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
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
    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'SESSION_REVERIFY_ATTEMPT',
      userId,
      ipAddress,
      userAgent,
      entity: 'Session',
      entityId: sessionId,
      status: AuditLogStatus.FAILURE,
      details: { verificationMethod: body.verificationMethod }
    }

    try {
      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
        include: { RecoveryCode: true, userProfile: true }
      })

      if (!user) {
        auditLogEntry.errorMessage = 'User not found during session reverification.'
        auditLogEntry.details.reason = 'USER_NOT_FOUND'
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
      auditLogEntry.userEmail = user.email

      let verificationSuccess = false
      let sltContextForOtp: (SltContextData & { sltJti: string }) | null = null

      if (body.verificationMethod === 'password') {
        if (!body.password) {
          auditLogEntry.errorMessage = 'Password is required for password verification method.'
          auditLogEntry.details.reason = 'MISSING_PASSWORD_FIELD'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.Password.Invalid')
        }
        const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
        if (!isPasswordMatch) {
          auditLogEntry.errorMessage = 'Invalid current password for reverification.'
          auditLogEntry.details.reason = 'INVALID_CURRENT_PASSWORD'
          throw new InvalidPasswordException()
        }
        verificationSuccess = true
        auditLogEntry.details.passwordVerified = true
      } else if (body.verificationMethod === 'otp') {
        if (!body.otpCode) {
          auditLogEntry.errorMessage = 'OTP code is required for OTP verification method.'
          auditLogEntry.details.reason = 'MISSING_OTP_CODE_FIELD'
          throw new InvalidOTPException()
        }
        if (!sltCookieValue) {
          auditLogEntry.errorMessage = 'SLT cookie is required for OTP-based session reverification.'
          auditLogEntry.details.reason = 'MISSING_SLT_COOKIE_FOR_OTP_REVERIFY'
          throw new SltCookieMissingException()
        }

        try {
          sltContextForOtp = await this.otpService.validateSltFromCookieAndGetContext(
            sltCookieValue,
            ipAddress || 'N/A',
            userAgent || 'N/A',
            TypeOfVerificationCode.REVERIFY_SESSION_OTP
          )
          auditLogEntry.details.sltJti = sltContextForOtp.sltJti
          auditLogEntry.details.sltPurposeValidated = sltContextForOtp.purpose

          if (sltContextForOtp.userId !== userId) {
            auditLogEntry.errorMessage = 'User ID mismatch between SLT context and active user for OTP reverification.'
            auditLogEntry.details.reason = 'USER_ID_MISMATCH_SLT_OTP_REVERIFY'
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
          auditLogEntry.details.otpVerified = true

          await this.otpService.finalizeSlt(sltContextForOtp.sltJti)
          auditLogEntry.details.sltFinalizedOnOtpSuccess = sltContextForOtp.sltJti
          if (res) this.tokenService.clearSltCookie(res)
        } catch (otpOrSltError) {
          auditLogEntry.errorMessage = `OTP/SLT verification failed for session reverification: ${otpOrSltError.message}`
          auditLogEntry.details.otpOrSltError = otpOrSltError.message
          if (otpOrSltError instanceof ApiException) {
            auditLogEntry.details.otpOrSltErrorCode = otpOrSltError.errorCode
          }

          if (sltContextForOtp) {
            await this.sltHelperService.handleSltAttemptIncrementAndFinalization(
              sltContextForOtp.sltJti,
              MAX_SLT_ATTEMPTS,
              'reverifyPasswordWithOtp',
              auditLogEntry,
              res
            )
          }
          throw otpOrSltError
        }
      } else if (body.verificationMethod === 'totp') {
        if (!body.totpCode) {
          auditLogEntry.errorMessage = 'TOTP code is required for TOTP verification method.'
          auditLogEntry.details.reason = 'MISSING_TOTP_CODE_FIELD'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidTOTP')
        }
        if (!user.twoFactorEnabled || !user.twoFactorSecret || user.twoFactorMethod !== TwoFactorMethodType.TOTP) {
          auditLogEntry.errorMessage = 'TOTP verification not available or not configured for this user.'
          auditLogEntry.details.reason = 'TOTP_NOT_CONFIGURED'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'OperationNotAllowed', 'Error.Auth.2FA.NotEnabled')
        }
        const isTotpValid = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: user.twoFactorSecret,
          token: body.totpCode
        })
        if (!isTotpValid) {
          auditLogEntry.errorMessage = 'Invalid TOTP code for session reverification.'
          auditLogEntry.details.reason = 'INVALID_TOTP_FOR_REVERIFICATION'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidTOTP')
        }
        verificationSuccess = true
        auditLogEntry.details.totpVerified = true
      } else if (body.verificationMethod === 'recovery') {
        if (!body.recoveryCode) {
          auditLogEntry.errorMessage = 'Recovery code is required for recovery code verification method.'
          auditLogEntry.details.reason = 'MISSING_RECOVERY_CODE_FIELD'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Auth.2FA.InvalidRecoveryCode')
        }
        if (!user.twoFactorEnabled) {
          auditLogEntry.errorMessage = 'Recovery code verification not available as 2FA is not enabled.'
          auditLogEntry.details.reason = 'RECOVERY_CODE_2FA_NOT_ENABLED'
          throw new ApiException(HttpStatus.BAD_REQUEST, 'OperationNotAllowed', 'Error.Auth.2FA.NotEnabled')
        }
        await this.twoFactorService.verifyRecoveryCode(userId, body.recoveryCode, this.prismaService)
        verificationSuccess = true
        auditLogEntry.details.recoveryCodeVerified = true
      } else {
        const exhaustiveCheck: never = body
        auditLogEntry.errorMessage = 'Invalid verification method specified.'
        auditLogEntry.details.reason = 'INVALID_VERIFICATION_METHOD_UNREACHABLE'
        throw new ApiException(HttpStatus.BAD_REQUEST, 'ValidationError', 'Error.Global.ValidationFailed')
      }

      if (verificationSuccess) {
        const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${sessionId}`
        const removedCount = await this.redisService.hdel(sessionDetailsKey, 'requiresPasswordReverification')

        if (removedCount > 0) {
          this.logger.log(`Session ${sessionId} reverified via ${body.verificationMethod}, flag removed from Redis.`)
          auditLogEntry.details.reverificationFlagRemoved = true
        } else {
          this.logger.warn(
            `Session ${sessionId} reverified via ${body.verificationMethod}, but reverification flag was not found or not removed from Redis.`
          )
          auditLogEntry.details.reverificationFlagRemoved = false
          auditLogEntry.notes = 'Reverification flag was not present in session details in Redis.'
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'SESSION_REVERIFY_SUCCESS'
        await this.auditLogService.record(auditLogEntry as AuditLogData)

        const message = await this.i18nService.translate('Auth.Session.ReverifiedSuccessfully', {
          lang: I18nContext.current()?.lang
        })
        return { message }
      } else {
        auditLogEntry.errorMessage = 'Verification failed due to an unknown reason after method selection.'
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
    } catch (error) {
      this.logger.error(
        `Session reverification failed for user ${userId}, session ${sessionId} with method ${body.verificationMethod}:`,
        error
      )
      if (!auditLogEntry.errorMessage && error instanceof Error) {
        auditLogEntry.errorMessage = error.message
      }
      if (error instanceof ApiException && !auditLogEntry.errorMessage) {
        auditLogEntry.errorMessage = JSON.stringify(error.getResponse())
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async initiateSessionReverificationOtp(
    activeUser: AccessTokenPayload,
    ipAddress: string,
    userAgent: string
  ): Promise<string> {
    const user = await this.userRepository.findUnique({ id: activeUser.userId })
    if (!user || !user.email) {
      this.logger.error(
        `[AuthenticationService] User not found or email missing for ID: ${activeUser.userId} during SLT initiation for session reverification.`
      )
      throw new ApiException(HttpStatus.NOT_FOUND, 'UserNotFoundForSlt', 'Error.User.NotFound')
    }
    const userEmail = user.email

    const userProfile = await this.prismaService.userProfile.findUnique({ where: { userId: activeUser.userId } })
    const displayName = userProfile?.firstName || userProfile?.lastName || userEmail

    this.logger.log(
      `[AuthenticationService] Initiating session reverification OTP via SLT for user ${activeUser.userId} (Email: ${userEmail}, Device: ${activeUser.deviceId})`
    )

    try {
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: userEmail,
        userId: activeUser.userId,
        deviceId: activeUser.deviceId,
        ipAddress: ipAddress,
        userAgent: userAgent,
        purpose: TypeOfVerificationCode.REVERIFY_SESSION_OTP
      })

      this.logger.log(
        `Successfully initiated SLT for session reverification for user ${userEmail}. SLT JTI (from decoded JWT if possible, or just acknowledge): ${sltJwt ? 'Generated' : 'Not Generated (Error?)'}`
      )

      await this.auditLogService.record({
        action: 'REVERIFICATION_OTP_SLT_INITIATED',
        userId: activeUser.userId,
        userEmail: userEmail,
        ipAddress: ipAddress,
        userAgent: userAgent,
        status: AuditLogStatus.SUCCESS,
        details: {
          context: 'session_reverification_slt',
          displayName,
          deviceId: activeUser.deviceId,
          sltPurpose: TypeOfVerificationCode.REVERIFY_SESSION_OTP
        } as Prisma.JsonObject
      })
      return sltJwt
    } catch (error) {
      this.logger.error(
        `[AuthenticationService] Failed to initiate SLT for session reverification OTP for user ${userEmail}:`,
        error
      )
      await this.auditLogService.record({
        action: 'REVERIFICATION_OTP_SLT_INITIATE_FAILED',
        userId: activeUser.userId,
        userEmail: userEmail,
        ipAddress: ipAddress,
        userAgent: userAgent,
        status: AuditLogStatus.FAILURE,
        errorMessage: error instanceof Error ? error.message : 'Unknown SLT initiation error',
        details: {
          context: 'session_reverification_slt',
          displayName,
          deviceId: activeUser.deviceId
        } as Prisma.JsonObject
      })
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
