import { Injectable, Logger } from '@nestjs/common'
import { Response } from 'express'
import { Device, Prisma, User, UserProfile } from '@prisma/client'
import { TokenService } from '../providers/token.service'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { AuditLogService, AuditLogStatus, AuditLogData } from 'src/routes/audit-log/audit-log.service'
import { SessionManagementService } from './session-management.service'
import { OtpService } from '../providers/otp.service'
import { EmailService } from '../providers/email.service'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { GeolocationService, GeolocationData } from 'src/shared/services/geolocation.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { UserProfileResType } from '../auth.model'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { v4 as uuidv4 } from 'uuid'
import envConfig from 'src/shared/config'
import ms from 'ms'
import { TypeOfVerificationCode } from '../constants/auth.constants'
import { JwtService } from '@nestjs/jwt'

export interface FinalizeAuthParams {
  user: User & { role: { id: number; name: string }; userProfile: UserProfile | null }
  device: Device
  rememberMe: boolean
  ipAddress: string
  userAgent: string
  source: string
  res: Response
  sltToFinalize?: {
    jti: string
    purpose?: TypeOfVerificationCode
  }
  tx?: Prisma.TransactionClient
  existingSessionId?: string
}

export interface SessionFinalizationResult extends UserProfileResType {
  sessionId: string
  accessTokenJti: string
}

@Injectable()
export class SessionFinalizationService {
  private readonly logger = new Logger(SessionFinalizationService.name)

  constructor(
    private readonly tokenService: TokenService,
    private readonly redisService: RedisService,
    private readonly auditLogService: AuditLogService,
    private readonly sessionManagementService: SessionManagementService,
    private readonly otpService: OtpService,
    private readonly emailService: EmailService,
    private readonly i18nService: I18nService,
    private readonly geolocationService: GeolocationService,
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService
  ) {}

  async finalizeSuccessfulAuthentication(params: FinalizeAuthParams): Promise<SessionFinalizationResult> {
    const { user, device, rememberMe, ipAddress, userAgent, source, res, sltToFinalize, tx, existingSessionId } = params

    const prismaClient = tx || this.prismaService
    const currentSessionId = existingSessionId || uuidv4()
    const now = new Date()

    const auditLogEntry: Partial<AuditLogData> & { details: Prisma.JsonObject } = {
      action: 'USER_SESSION_FINALIZE_ATTEMPT',
      userId: user.id,
      userEmail: user.email,
      ipAddress,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        source,
        sessionId: currentSessionId,
        deviceId: device.id,
        rememberMe,
        sltJti: sltToFinalize?.jti,
        sltPurpose: sltToFinalize?.purpose
      }
    }

    try {
      const { accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie, accessTokenPayload } =
        await this.tokenService.generateTokens(
          {
            userId: user.id,
            deviceId: device.id,
            roleId: user.role.id,
            roleName: user.role.name,
            sessionId: currentSessionId,
            isDeviceTrustedInSession: device.isTrusted || rememberMe
          },
          prismaClient,
          rememberMe
        )

      this.tokenService.setTokenCookies(res, accessToken, refreshTokenJti, maxAgeForRefreshTokenCookie)

      const geoLocation: GeolocationData | null = this.geolocationService.lookup(ipAddress)
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object' && geoLocation) {
        auditLogEntry.details.location = `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
      }

      const decodedToken = this.jwtService.decode(accessToken)
      const accessTokenExp = decodedToken?.exp

      let absoluteSessionLifetimeMs = envConfig.ABSOLUTE_SESSION_LIFETIME_MS
      if (isNaN(absoluteSessionLifetimeMs)) {
        this.logger.warn(
          `Invalid ABSOLUTE_SESSION_LIFETIME_MS detected (NaN): ${envConfig.ABSOLUTE_SESSION_LIFETIME}. Falling back to 30 days.`
        )
        absoluteSessionLifetimeMs = ms('30d')
      }
      const absoluteSessionLifetimeSeconds = Math.floor(absoluteSessionLifetimeMs / 1000)
      const refreshTokenTTL = maxAgeForRefreshTokenCookie
        ? Math.floor(maxAgeForRefreshTokenCookie / 1000)
        : absoluteSessionLifetimeSeconds

      const sessionData: Record<string, string | number | boolean | undefined | null> = {
        userId: user.id,
        deviceId: device.id,
        ipAddress,
        userAgent,
        createdAt: now.toISOString(),
        lastActiveAt: now.toISOString(),
        isTrusted: device.isTrusted,
        rememberMe,
        roleId: user.role.id,
        roleName: user.role.name,
        geoCountry: geoLocation?.country,
        geoCity: geoLocation?.city,
        source,
        currentAccessTokenJti: accessTokenPayload.jti,
        currentRefreshTokenJti: refreshTokenJti,
        accessTokenExp: accessTokenExp,
        maxLifetimeExpiresAt: new Date(Date.now() + absoluteSessionLifetimeMs).toISOString()
      }

      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${currentSessionId}`
      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${user.id}`
      const deviceSessionsKey = `${REDIS_KEY_PREFIX.DEVICE_SESSIONS}${device.id}`
      const refreshTokenJtiToSessionKey = `${REDIS_KEY_PREFIX.REFRESH_TOKEN_JTI_TO_SESSION}${refreshTokenJti}`

      await this.redisService.pipeline((pipeline) => {
        pipeline.hmset(sessionKey, sessionData as Record<string, string>)
        pipeline.expire(sessionKey, absoluteSessionLifetimeSeconds)
        pipeline.sadd(userSessionsKey, currentSessionId)
        pipeline.sadd(deviceSessionsKey, currentSessionId)
        pipeline.set(refreshTokenJtiToSessionKey, currentSessionId, 'EX', refreshTokenTTL)
        return pipeline
      })
      this.logger.log(`Session ${currentSessionId} for user ${user.id} finalized and recorded in Redis.`)

      this.sessionManagementService
        .enforceSessionAndDeviceLimits(user.id, currentSessionId, device.id)
        .then((limitsResult) => {
          if (limitsResult.deviceLimitApplied || limitsResult.sessionLimitApplied) {
            this.logger.log(
              `Session/device limits applied for user ${user.id} (session: ${currentSessionId}). Devices removed: ${limitsResult.devicesRemovedCount}, Sessions revoked: ${limitsResult.sessionsRevokedCount}`
            )
          }
        })
        .catch((limitError) => {
          this.logger.error(
            `Error enforcing session/device limits for user ${user.id} (session: ${currentSessionId}): ${limitError.message}`,
            limitError.stack
          )
        })

      if ((device.isTrusted || rememberMe) && geoLocation?.country && geoLocation?.city && user.userProfile) {
        const knownLocationsKey = `${REDIS_KEY_PREFIX.USER_KNOWN_LOCATIONS}${user.id}`
        const locationString = `${geoLocation.city.toLowerCase()}_${geoLocation.country.toLowerCase()}`
        const isNewLocation = await this.redisService.sadd(knownLocationsKey, locationString)
        if (isNewLocation === 1) {
          this.logger.warn(
            `New login location detected for user ${user.id} on trusted/remembered device ${device.id}: ${locationString}. Sending alert.`
          )
          auditLogEntry.notes =
            `${auditLogEntry.notes || ''}; New trusted device login location: ${locationString}. Alert email sent.`.trim()
          const lang = I18nContext.current()?.lang || 'en'
          const displayName = user.userProfile.firstName || user.userProfile.lastName || user.email
          this.emailService
            .sendSecurityAlertEmail({
              to: user.email,
              userName: displayName,
              alertSubject: this.i18nService.translate(
                'email.Email.SecurityAlert.Subject.NewTrustedDeviceLoginLocation',
                { lang }
              ),
              alertTitle: this.i18nService.translate('email.Email.SecurityAlert.Title.NewTrustedDeviceLoginLocation', {
                lang
              }),
              mainMessage: this.i18nService.translate(
                'email.Email.SecurityAlert.MainMessage.NewTrustedDeviceLoginLocation',
                { lang }
              ),
              actionDetails: [
                {
                  label: this.i18nService.translate('email.Email.Field.Time', { lang }),
                  value: new Date().toLocaleString(lang)
                },
                { label: this.i18nService.translate('email.Email.Field.IPAddress', { lang }), value: ipAddress },
                { label: this.i18nService.translate('email.Email.Field.Device', { lang }), value: userAgent },
                {
                  label: this.i18nService.translate('email.Email.Field.Location', { lang }),
                  value: `${geoLocation.city || 'N/A'}, ${geoLocation.country || 'N/A'}`
                }
              ],
              secondaryMessage: this.i18nService.translate('email.Email.SecurityAlert.SecondaryMessage.NotYou', {
                lang
              }),
              actionButtonText: this.i18nService.translate('email.Email.SecurityAlert.Button.SecureAccount', { lang }),
              actionButtonUrl: `${envConfig.FRONTEND_URL}/account/security`
            })
            .catch((emailError) => {
              this.logger.error(
                `Failed to send new trusted device login location alert to ${user.email}: ${emailError.message}`,
                emailError.stack
              )
            })
        }
      }

      if (sltToFinalize?.jti) {
        await this.otpService.finalizeSlt(sltToFinalize.jti)
        this.tokenService.clearSltCookie(res)
        this.logger.log(`SLT JTI ${sltToFinalize.jti} finalized and cookie cleared.`)
        if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
          auditLogEntry.details.sltFinalizedOnSuccess = sltToFinalize.jti
        }
      } else {
        // Always clear SLT cookie if exists to prevent leftover tokens
        this.tokenService.clearSltCookie(res)
      }

      auditLogEntry.status = AuditLogStatus.SUCCESS
      auditLogEntry.action = 'USER_SESSION_FINALIZED'
      this.auditLogService.recordAsync(auditLogEntry as AuditLogData)

      const userProfileData: UserProfileResType = {
        id: user.id,
        email: user.email,
        role: user.role.name,
        isDeviceTrustedInSession: accessTokenPayload.isDeviceTrustedInSession,
        userProfile: user.userProfile
          ? {
              firstName: user.userProfile.firstName,
              lastName: user.userProfile.lastName,
              avatar: user.userProfile.avatar,
              username: user.userProfile.username
            }
          : null
      }

      return {
        ...userProfileData,
        sessionId: currentSessionId,
        accessTokenJti: accessTokenPayload.jti
      }
    } catch (error) {
      this.logger.error(
        `Error in finalizeSuccessfulAuthentication for user ${user.email} (source: ${source}): ${error.message}`,
        error.stack
      )
      auditLogEntry.errorMessage = error instanceof Error ? error.message : String(error)
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        if (error.details && typeof error.details === 'object' && error.details !== null) {
          auditLogEntry.details.originalErrorDetails = error.details as Prisma.JsonObject
        } else if (error.details) {
          auditLogEntry.details.originalErrorDetails = { message: String(error.details) }
        }
      } else if (error.details) {
        auditLogEntry.details = { originalErrorDetails: { message: String(error.details) } }
      }

      if (
        sltToFinalize?.jti &&
        auditLogEntry.details &&
        typeof auditLogEntry.details === 'object' &&
        !auditLogEntry.details.sltFinalizedOnSuccess &&
        !auditLogEntry.details.sltFinalizedOnError
      ) {
        try {
          await this.otpService.finalizeSlt(sltToFinalize.jti)
          this.tokenService.clearSltCookie(res)
          auditLogEntry.details.sltFinalizedOnError = sltToFinalize.jti
          this.logger.warn(`SLT JTI ${sltToFinalize.jti} finalized due to error during session finalization.`)
        } catch (sltFinalizeError) {
          this.logger.error(
            `Failed to finalize SLT JTI ${sltToFinalize.jti} during error handling: ${sltFinalizeError.message}`
          )
          if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
            auditLogEntry.details.sltFinalizationErrorOnError = sltFinalizeError.message
          } else {
            auditLogEntry.details = { sltFinalizationErrorOnError: sltFinalizeError.message }
          }
        }
      }

      this.auditLogService.recordAsync(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
