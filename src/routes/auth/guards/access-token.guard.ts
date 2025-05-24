import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { TokenService } from 'src/routes/auth/providers/token.service'
import { Request } from 'express'
import { DeviceService } from 'src/routes/auth/providers/device.service'
import envConfig from 'src/shared/config'
import {
  AbsoluteSessionLifetimeExceededException,
  DeviceMissingSessionCreationTimeException,
  InvalidDeviceException
} from 'src/routes/auth/auth.error'
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { Prisma } from '@prisma/client'

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
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: 'Missing deviceId in access token payload.',
          details: { reason: 'MISSING_DEVICE_ID_IN_TOKEN' } as Prisma.JsonObject
        })
        throw InvalidDeviceException
      }

      const device = await this.deviceService.findDeviceById(deviceId)

      if (!device || !device.isActive) {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: `Device not found or inactive. Device ID: ${deviceId}`,
          details: { reason: 'DEVICE_NOT_FOUND_OR_INACTIVE', deviceId } as Prisma.JsonObject
        })
        throw InvalidDeviceException
      }

      if (device.sessionCreatedAt) {
        const sessionAgeMs = new Date().getTime() - new Date(device.sessionCreatedAt).getTime()
        if (sessionAgeMs > envConfig.ABSOLUTE_SESSION_LIFETIME_MS) {
          this.auditLogService.recordAsync({
            action: 'ACCESS_TOKEN_GUARD_DENY',
            userId,
            status: AuditLogStatus.FAILURE,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] as string,
            errorMessage: `Absolute session lifetime exceeded. Device ID: ${deviceId}. Session created at: ${device.sessionCreatedAt.toISOString()}`,
            details: {
              reason: 'ABSOLUTE_SESSION_LIFETIME_EXCEEDED',
              deviceId,
              sessionCreatedAt: device.sessionCreatedAt.toISOString()
            } as Prisma.JsonObject
          })
          throw AbsoluteSessionLifetimeExceededException
        }
      } else {
        this.auditLogService.recordAsync({
          action: 'ACCESS_TOKEN_GUARD_DENY',
          userId,
          status: AuditLogStatus.FAILURE,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] as string,
          errorMessage: `Device is missing sessionCreatedAt. Device ID: ${deviceId}. Forcing re-authentication.`,
          details: { reason: 'DEVICE_MISSING_SESSION_CREATION_TIME', deviceId } as Prisma.JsonObject
        })
        throw DeviceMissingSessionCreationTimeException
      }

      return true
    } catch (error) {
      if (
        error instanceof ApiException &&
        (error.message === AbsoluteSessionLifetimeExceededException.message ||
          error.message === DeviceMissingSessionCreationTimeException.message ||
          error.message === InvalidDeviceException.message)
      ) {
        throw error
      }
      this.auditLogService.recordAsync({
        action: 'ACCESS_TOKEN_GUARD_DENY',
        userId: (request[REQUEST_USER_KEY] as any)?.userId,
        status: AuditLogStatus.FAILURE,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] as string,
        errorMessage: error instanceof Error ? error.message : 'Invalid or expired access token.',
        details: {
          reason: 'INVALID_OR_EXPIRED_ACCESS_TOKEN',
          originalError: error?.constructor?.name
        } as Prisma.JsonObject
      })
      throw new UnauthorizedException('Error.Auth.Token.InvalidOrExpiredAccessToken')
    }
  }
}

const MissingAccessTokenException = new UnauthorizedException('Error.Auth.Token.MissingAccessToken')
