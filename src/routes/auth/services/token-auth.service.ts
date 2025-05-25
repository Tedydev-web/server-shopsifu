import { Injectable, HttpStatus } from '@nestjs/common'
import { Request, Response } from 'express'
import { Prisma } from '@prisma/client'
import { BaseAuthService } from './base-auth.service'
import { AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { UnauthorizedAccessException } from '../auth.error'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import envConfig from 'src/shared/config'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class TokenAuthService extends BaseAuthService {
  async generateTokens(
    { userId, deviceId, roleId, roleName }: AccessTokenPayloadCreate,
    prismaTx?: PrismaTransactionClient,
    rememberMe?: boolean
  ) {
    return this.tokenService.generateTokens({ userId, deviceId, roleId, roleName }, prismaTx, rememberMe)
  }

  async refreshToken({ userAgent, ip }: { userAgent: string; ip: string }, req: Request, res?: Response) {
    const auditLogEntry: Omit<Partial<AuditLogData>, 'details'> & { details: Prisma.JsonObject } = {
      action: 'REFRESH_TOKEN_ATTEMPT',
      ipAddress: ip,
      userAgent: userAgent,
      status: AuditLogStatus.FAILURE,
      details: {}
    }

    try {
      const result = await this.prismaService.$transaction(async (tx: PrismaTransactionClient) => {
        const tokenToUse = req?.cookies?.[CookieNames.REFRESH_TOKEN]
        auditLogEntry.details.tokenProvidedInRequest = !!tokenToUse

        if (!tokenToUse) {
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          this.logger.warn('[DEBUG TokenAuthService refreshToken] No refresh token provided.')
          auditLogEntry.errorMessage = UnauthorizedAccessException.message
          auditLogEntry.details.reason = 'NO_REFRESH_TOKEN_PROVIDED'
          throw UnauthorizedAccessException
        }

        const existingRefreshToken = await this.tokenService.findRefreshTokenWithUserAndDevice(tokenToUse, tx)

        if (!existingRefreshToken || !existingRefreshToken.user) {
          const potentiallyReplayedToken = await this.tokenService.findRefreshToken(tokenToUse, tx)

          if (potentiallyReplayedToken) {
            auditLogEntry.userId = potentiallyReplayedToken.userId
            auditLogEntry.details.replayedTokenInfo = {
              used: potentiallyReplayedToken.used,
              expired: potentiallyReplayedToken.expiresAt < new Date()
            }
            this.logger.warn(
              `[SECURITY TokenAuthService refreshToken] Potentially replayed/expired token used. UserId: ${potentiallyReplayedToken.userId}. Invalidating all tokens for this user.`
            )

            await this.tokenService.deleteAllRefreshTokens(potentiallyReplayedToken.userId, tx)
            auditLogEntry.notes = 'Potential replay attack or used/expired token. All user tokens invalidated.'
          }

          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          this.logger.warn(
            '[DEBUG TokenAuthService refreshToken] Refresh token not found in DB, user data missing, or token invalid/used/expired.'
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
          originalTokenExpiresAt: existingRefreshToken.expiresAt.toISOString()
        }

        if (existingRefreshToken.device && existingRefreshToken.device.sessionCreatedAt) {
          const sessionAgeMs = new Date().getTime() - new Date(existingRefreshToken.device.sessionCreatedAt).getTime()
          if (sessionAgeMs > envConfig.ABSOLUTE_SESSION_LIFETIME_MS) {
            this.logger.warn(
              `[SECURITY TokenAuthService refreshToken] Absolute session lifetime exceeded for user ${existingRefreshToken.userId}, device ${existingRefreshToken.deviceId}. Session created at: ${existingRefreshToken.device.sessionCreatedAt?.toISOString()}`
            )
            await this.tokenService.deleteAllRefreshTokensForDevice(existingRefreshToken.deviceId, tx)
            if (res) {
              this.tokenService.clearTokenCookies(res)
            }
            auditLogEntry.errorMessage = 'Error.Auth.Session.AbsoluteLifetimeExceeded'
            auditLogEntry.details.reason = 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED'
            auditLogEntry.details.sessionCreatedAt = existingRefreshToken.device.sessionCreatedAt.toISOString()
            auditLogEntry.notes = `All refresh tokens for device ${existingRefreshToken.deviceId} invalidated due to absolute session lifetime exceeded.`
            throw new ApiException(
              HttpStatus.UNAUTHORIZED,
              'Unauthenticated',
              'Error.Auth.Session.AbsoluteLifetimeExceeded'
            )
          }
        }

        if (existingRefreshToken.expiresAt < new Date()) {
          await this.tokenService.deleteAllRefreshTokens(existingRefreshToken.userId, tx)
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          auditLogEntry.errorMessage = UnauthorizedAccessException.message
          auditLogEntry.details.reason = 'REFRESH_TOKEN_EXPIRED'
          throw UnauthorizedAccessException
        }

        if (existingRefreshToken.used) {
          await this.tokenService.deleteAllRefreshTokens(existingRefreshToken.userId, tx)
          if (res) {
            this.tokenService.clearTokenCookies(res)
          }
          auditLogEntry.errorMessage = UnauthorizedAccessException.message
          auditLogEntry.details.reason = 'REFRESH_TOKEN_ALREADY_USED'
          auditLogEntry.notes = 'All refresh tokens invalidated due to token reuse.'
          throw UnauthorizedAccessException
        }

        // Validate device fingerprint
        try {
          if (existingRefreshToken.device && existingRefreshToken.device.userAgent) {
            const currentDeviceFingerprint = this.deviceService.basicDeviceFingerprint(userAgent)
            const storedDeviceFingerprint = this.deviceService.basicDeviceFingerprint(
              existingRefreshToken.device.userAgent
            )

            if (currentDeviceFingerprint !== storedDeviceFingerprint) {
              this.logger.warn(
                `[SECURITY TokenAuthService refreshToken] Device fingerprint mismatch during token refresh. UserId: ${
                  existingRefreshToken.userId
                }, expected: "${storedDeviceFingerprint}", got: "${currentDeviceFingerprint}"`
              )
              auditLogEntry.errorMessage = 'Device fingerprint changed'
              auditLogEntry.details.reason = 'DEVICE_FINGERPRINT_MISMATCH'
              auditLogEntry.details.fingerprintMismatch = {
                expected: storedDeviceFingerprint,
                received: currentDeviceFingerprint
              }

              if (res) {
                this.tokenService.clearTokenCookies(res)
              }

              await this.tokenService.deleteAllRefreshTokens(existingRefreshToken.userId, tx)
              auditLogEntry.notes = 'All refresh tokens invalidated due to device fingerprint change.'
              throw UnauthorizedAccessException
            }
          }
        } catch (error) {
          // Nếu không thể so sánh fingerprint, tiếp tục xử lý
          this.logger.warn('Could not validate device fingerprint, proceeding with token refresh', error)
        }

        await this.tokenService.markRefreshTokenUsed(tokenToUse, tx)
        const { accessToken, refreshToken, maxAgeForRefreshTokenCookie } = await this.generateTokens(
          {
            userId: existingRefreshToken.userId,
            deviceId: existingRefreshToken.deviceId,
            roleId: existingRefreshToken.user.roleId,
            roleName: existingRefreshToken.user.role.name
          },
          tx,
          existingRefreshToken.rememberMe
        )

        if (res) {
          this.tokenService.setTokenCookies(res, accessToken, refreshToken, maxAgeForRefreshTokenCookie)
        }

        auditLogEntry.status = AuditLogStatus.SUCCESS
        auditLogEntry.action = 'REFRESH_TOKEN_SUCCESS'

        const message = await this.i18nService.translate('error.Auth.Token.Refreshed', {
          lang: I18nContext.current()?.lang
        })
        return { message }
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
}
