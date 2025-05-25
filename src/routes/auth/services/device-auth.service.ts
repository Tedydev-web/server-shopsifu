import { Injectable } from '@nestjs/common'
import { BaseAuthService } from './base-auth.service'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { AuditLogData, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class DeviceAuthService extends BaseAuthService {
  async trustDevice(activeUser: AccessTokenPayload, ip: string, userAgent: string) {
    const auditLogEntry: Partial<AuditLogData> = {
      action: 'TRUST_DEVICE_ATTEMPT',
      userId: activeUser.userId,
      ipAddress: ip,
      userAgent,
      status: AuditLogStatus.FAILURE,
      details: { deviceId: activeUser.deviceId } as Record<string, any>
    }

    try {
      const isValidDevice = await this.deviceService.isDeviceOwnedByUser(activeUser.deviceId, activeUser.userId)
      if (!isValidDevice) {
        auditLogEntry.errorMessage = 'Device does not belong to user'
        throw new Error('Device does not belong to user')
      }

      const device = await this.deviceService.trustDevice(activeUser.deviceId, activeUser.userId)

      auditLogEntry.action = 'TRUST_DEVICE_SUCCESS'
      auditLogEntry.status = AuditLogStatus.SUCCESS
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Record<string, any>).trustedAt = device.lastActive.toISOString()
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
      const result = await this.deviceService.deactivateAllUserDevices(activeUser.userId, currentDeviceId)

      // Vô hiệu hóa tất cả refresh token, ngoại trừ token hiện tại
      await this.tokenService.deleteAllRefreshTokens(activeUser.userId)

      auditLogEntry.action = 'LOGOUT_ALL_DEVICES_SUCCESS'
      auditLogEntry.status = AuditLogStatus.SUCCESS
      if (auditLogEntry.details && typeof auditLogEntry.details === 'object') {
        ;(auditLogEntry.details as Record<string, any>).devicesDeactivated = result.count
      }

      await this.auditLogService.record(auditLogEntry as AuditLogData)

      return { deactivated: result.count }
    } catch (error) {
      auditLogEntry.errorMessage = error.message
      await this.auditLogService.record(auditLogEntry as AuditLogData)
      throw error
    }
  }
}
