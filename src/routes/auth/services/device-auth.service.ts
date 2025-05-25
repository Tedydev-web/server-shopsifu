import { Injectable } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { I18nContext } from 'nestjs-i18n'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'

@Injectable()
export class DeviceAuthService extends BaseAuthService {
  async trustDevice(activeUser: AccessTokenPayload, ip: string, userAgent: string) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'TRUST_DEVICE_ATTEMPT',
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: { deviceId: activeUser.deviceId, sessionId: activeUser.sessionId } as Record<string, any>
    }

    try {
      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${activeUser.sessionId}`
      const sessionDetails = await this.redisService.hgetall(sessionKey)

      if (!sessionDetails || Object.keys(sessionDetails).length === 0) {
        auditLogEntry.errorMessage = `Session ${activeUser.sessionId} not found.`
        throw new Error('Session not found for trusting device.')
      }

      if (parseInt(sessionDetails.userId, 10) !== activeUser.userId) {
        auditLogEntry.errorMessage = 'User ID mismatch between token and session.'
        throw new Error('User ID in token does not match session.')
      }

      // Không cần thiết phải gọi deviceService.isDeviceOwnedByUser nữa vì đã xác thực qua session
      // const isValidDevice = await this.deviceService.isDeviceOwnedByUser(activeUser.deviceId, activeUser.userId)
      // if (!isValidDevice) {
      //   auditLogEntry.errorMessage = 'Device does not belong to user'
      //   throw new Error('Device does not belong to user')
      // }

      // Cập nhật session trên Redis
      await this.redisService.hset(sessionKey, {
        isTrusted: 'true', // Redis lưu trữ dưới dạng string
        lastActiveAt: new Date().toISOString()
      })

      // Cập nhật device trong Prisma
      try {
        await this.deviceService.updateDevice(activeUser.deviceId, { isTrusted: true })
      } catch (dbError) {
        this.logger.warn(
          `Failed to update device isTrusted in DB for device ${activeUser.deviceId}, but session in Redis is updated. Error: ${dbError.message}`
        )
        // Không throw lỗi ở đây để không ảnh hưởng luồng chính nếu Redis đã cập nhật thành công
      }

      auditLogEntry.action = 'TRUST_DEVICE_SUCCESS'
      auditLogEntry.status = AuditLogStatus.SUCCESS
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Record<string, any>).trustedAt = new Date().toISOString()
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      const message = await this.i18nService.translate('Auth.Device.Trusted', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async untrustDevice(activeUser: AccessTokenPayload, ip: string, userAgent: string) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'UNTRUST_DEVICE_ATTEMPT',
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: { deviceId: activeUser.deviceId, sessionId: activeUser.sessionId } as Record<string, any>
    }

    try {
      const sessionKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${activeUser.sessionId}`
      const sessionDetails = await this.redisService.hgetall(sessionKey)

      if (!sessionDetails || Object.keys(sessionDetails).length === 0) {
        auditLogEntry.errorMessage = `Session ${activeUser.sessionId} not found.`
        throw new Error('Session not found for untrusting device.')
      }

      if (parseInt(sessionDetails.userId, 10) !== activeUser.userId) {
        auditLogEntry.errorMessage = 'User ID mismatch between token and session.'
        throw new Error('User ID in token does not match session.')
      }

      // Cập nhật session trên Redis
      await this.redisService.hset(sessionKey, {
        isTrusted: 'false', // Redis lưu trữ dưới dạng string
        lastActiveAt: new Date().toISOString()
      })

      // Cập nhật device trong Prisma
      try {
        await this.deviceService.updateDevice(activeUser.deviceId, { isTrusted: false })
      } catch (dbError) {
        this.logger.warn(
          `Failed to update device isTrusted in DB for device ${activeUser.deviceId}, but session in Redis is updated. Error: ${dbError.message}`
        )
      }

      auditLogEntry.action = 'UNTRUST_DEVICE_SUCCESS'
      auditLogEntry.status = AuditLogStatus.SUCCESS
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Record<string, any>).untrustedAt = new Date().toISOString()
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)
      const message = await this.i18nService.translate('Auth.Device.Untrusted', {
        lang: I18nContext.current()?.lang
      })
      return { message }
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async logoutFromAllDevices(
    activeUser: AccessTokenPayload,
    ip: string,
    userAgent: string,
    currentDeviceId: number = activeUser.deviceId
  ) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'LOGOUT_ALL_DEVICES_ATTEMPT',
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        excludeDeviceId: currentDeviceId
      } as Record<string, any>
    }

    try {
      // Vô hiệu hóa tất cả các thiết bị, ngoại trừ thiết bị hiện tại
      // const result = await this.deviceService.deactivateAllUserDevices(activeUser.userId, currentDeviceId)
      // Không cần deactivate device trong DB nữa, thay vào đó là invalidate sessions trên Redis

      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${activeUser.userId}`
      const allUserSessionIds = await this.redisService.smembers(userSessionsKey)
      let invalidatedCount = 0

      for (const sessionId of allUserSessionIds) {
        if (sessionId !== activeUser.sessionId) {
          // Không invalidate session hiện tại
          await this.tokenService.invalidateSession(sessionId, 'LOGOUT_FROM_OTHER_DEVICE_VIA_LOGOUT_ALL')
          invalidatedCount++
        }
      }

      // Vô hiệu hóa tất cả refresh token, ngoại trừ token hiện tại
      // await this.tokenService.deleteAllRefreshTokens(activeUser.userId)
      // Logic này đã được xử lý bởi invalidateSession (nó sẽ blacklist RT JTI và xóa mapping)

      auditLogEntry.action = 'LOGOUT_ALL_DEVICES_SUCCESS'
      auditLogEntry.status = AuditLogStatus.SUCCESS
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        // (auditLogEntry.details as Record<string, any>).devicesDeactivated = result.count
        ;(auditLogEntry.details as Record<string, any>).sessionsInvalidated = invalidatedCount
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)

      // return { deactivated: result.count }
      return { sessionsInvalidated: invalidatedCount }
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }

  async logoutFromDevice(activeUser: AccessTokenPayload, deviceIdToLogout: number, ip: string, userAgent: string) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'LOGOUT_FROM_DEVICE_ATTEMPT',
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: {
        deviceIdToLogout,
        currentSessionId: activeUser.sessionId,
        currentDeviceId: activeUser.deviceId
      } as Record<string, any>
    }

    if (activeUser.deviceId === deviceIdToLogout) {
      auditLogEntry.errorMessage = 'Cannot logout from the current active device using this method. Use regular logout.'
      // It is implied that if user wants to logout from current device, they should use the main /logout endpoint
      // which will invalidate the current session associated with the activeUser.sessionId
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw new Error(
        'Cannot logout from the current active device using this specific method. Use general logout for current device.'
      )
    }

    try {
      const userSessionsKey = `${REDIS_KEY_PREFIX.USER_SESSIONS}${activeUser.userId}`
      const allUserSessionIds = await this.redisService.smembers(userSessionsKey)
      let invalidatedCount = 0
      let deviceSessionFoundAndInvalidated = false

      for (const sessionId of allUserSessionIds) {
        if (sessionId === activeUser.sessionId) continue // Skip current session

        const sessionDetails = await this.redisService.hgetall(sessionId)
        if (sessionDetails && parseInt(sessionDetails.deviceId, 10) === deviceIdToLogout) {
          await this.tokenService.invalidateSession(sessionId, 'USER_REQUEST_LOGOUT_SPECIFIC_DEVICE')
          invalidatedCount++
          deviceSessionFoundAndInvalidated = true
        }
      }

      if (!deviceSessionFoundAndInvalidated) {
        this.logger.warn(
          `No active session found for device ${deviceIdToLogout} of user ${activeUser.userId} to logout.`
        )
        // Not necessarily an error, could be that device had no active sessions or was already logged out.
        // We can choose to return success or a specific message.
      }

      // Optionally, update the Device model in DB if needed, e.g., set isActive to false.
      // For now, we are only invalidating sessions.
      // await this.deviceService.updateDevice(deviceIdToLogout, { isActive: false });

      auditLogEntry.action = 'LOGOUT_FROM_DEVICE_SUCCESS'
      auditLogEntry.status = AuditLogStatus.SUCCESS
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Record<string, any>).sessionsInvalidated = invalidatedCount
      }
      await this.auditLogService.record(auditLogEntry as AuditLogData)

      const message = await this.i18nService.translate('Auth.Device.LogoutSpecificSuccess', {
        lang: I18nContext.current()?.lang,
        args: { deviceId: deviceIdToLogout, count: invalidatedCount }
      })
      return { message, sessionsInvalidated: invalidatedCount }
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
