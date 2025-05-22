import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, HttpStatus } from '@nestjs/common'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { TokenService } from 'src/shared/services/token.service'
import { Request } from 'express'
import { DeviceService } from 'src/shared/services/device.service'
import envConfig from 'src/shared/config'
import {
  AbsoluteSessionLifetimeExceededException,
  DeviceMissingSessionCreationTimeException,
  InvalidDeviceException,
  ReAuthenticationRequiredException
} from 'src/routes/auth/auth.error'
import { AuditLogService } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from '../exceptions/api.exception'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(
    private readonly tokenService: TokenService,
    private readonly deviceService: DeviceService,
    private readonly auditLogService: AuditLogService
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>()

    const token = this.tokenService.extractTokenFromRequest(request)

    if (!token) {
      throw MissingAccessTokenException
    }

    try {
      const decodedAccessToken = await this.tokenService.verifyAccessToken(token)
      request[REQUEST_USER_KEY] = decodedAccessToken

      const { userId, deviceId } = decodedAccessToken

      if (!deviceId) {
        // This case should ideally not happen if tokens always include deviceId
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: 'FAILURE' as any,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'],
          errorMessage: 'Missing deviceId in access token payload.',
          details: { reason: 'MISSING_DEVICE_ID_IN_TOKEN' }
        })
        throw InvalidDeviceException
      }

      const device = await this.deviceService.findDeviceById(deviceId)

      if (!device || !device.isActive) {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: 'FAILURE' as any,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'],
          errorMessage: `Device not found or inactive. Device ID: ${deviceId}`,
          details: { reason: 'DEVICE_NOT_FOUND_OR_INACTIVE', deviceId }
        })
        throw InvalidDeviceException
      }

      // 1. Check Absolute Session Lifetime
      if (device.sessionCreatedAt) {
        const sessionAgeMs = new Date().getTime() - new Date(device.sessionCreatedAt).getTime()
        if (sessionAgeMs > envConfig.ABSOLUTE_SESSION_LIFETIME_MS) {
          this.auditLogService.recordAsync({
            action: 'ACCESS_TOKEN_GUARD_DENY',
            userId,
            status: 'FAILURE' as any,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'],
            errorMessage: `Absolute session lifetime exceeded. Device ID: ${deviceId}. Session created at: ${device.sessionCreatedAt.toISOString()}`,
            details: {
              reason: 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED',
              deviceId,
              sessionCreatedAt: device.sessionCreatedAt.toISOString()
            }
          })
          throw AbsoluteSessionLifetimeExceededException
        }
      } else {
        // This case should ideally not happen
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: 'FAILURE' as any,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'],
          errorMessage: `Device is missing sessionCreatedAt. Device ID: ${deviceId}. Forcing re-authentication.`,
          details: { reason: 'DEVICE_MISSING_SESSION_CREATION_TIME', deviceId }
        })
        throw DeviceMissingSessionCreationTimeException
      }

      // 2. Check Re-authentication After Inactivity
      const timeSinceLastActiveMs = new Date().getTime() - new Date(device.lastActive).getTime()
      if (timeSinceLastActiveMs > envConfig.MAX_SESSION_INACTIVITY_MS) {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: 'FAILURE' as any,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'],
          errorMessage: `Re-authentication required due to inactivity. Device ID: ${deviceId}. Last active: ${device.lastActive.toISOString()}`,
          details: {
            reason: 'RE_AUTHENTICATION_REQUIRED_INACTIVITY',
            deviceId,
            lastActive: device.lastActive.toISOString()
          }
        })
        throw ReAuthenticationRequiredException
      }

      // If we reach here, all checks passed.
      // We are NOT updating device.lastActive here to avoid excessive DB writes on every request.
      // lastActive is updated during login, token refresh, etc.

      return true
    } catch (error) {
      if (
        error instanceof ApiException &&
        (error.message === AbsoluteSessionLifetimeExceededException.message ||
          error.message === DeviceMissingSessionCreationTimeException.message ||
          error.message === ReAuthenticationRequiredException.message ||
          error.message === InvalidDeviceException.message)
      ) {
        throw error
      }
      // For other errors (e.g., token expired, invalid token format from verifyAccessToken)
      this.auditLogService.recordAsync({
        action: 'ACCESS_TOKEN_GUARD_DENY',
        userId: (request[REQUEST_USER_KEY] as any)?.userId,
        status: 'FAILURE' as any,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'],
        errorMessage: error instanceof Error ? error.message : 'Invalid or expired access token.',
        details: { reason: 'INVALID_OR_EXPIRED_ACCESS_TOKEN', originalError: error?.constructor?.name }
      })
      throw new UnauthorizedException('Error.Auth.Token.InvalidOrExpiredAccessToken')
    }
  }
}

// Need to define MissingAccessTokenException if it's not already globally available
// For now, assuming it's a specific UnauthorizedException message
const MissingAccessTokenException = new UnauthorizedException('Error.Auth.Token.MissingAccessToken')
