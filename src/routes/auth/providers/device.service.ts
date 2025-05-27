import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma, Device } from '@prisma/client'
import { DeviceSetupFailedException } from 'src/routes/auth/auth.error'
import { AuditLog } from 'src/shared/decorators/audit-log.decorator'
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import envConfig from 'src/shared/config'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { UAParser } from 'ua-parser-js'
import { EmailService } from './email.service'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { SharedUserRepository } from '../repositories/shared-user.repo'
import { ApiException } from 'src/shared/exceptions/api.exception'

// Định nghĩa một kiểu con cho thông tin user cần thiết cho notification
interface UserForNotification {
  id: number
  email: string
  name: string | null
}

@Injectable()
export class DeviceService {
  private readonly logger = new Logger(DeviceService.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly auditLogService: AuditLogService,
    private readonly emailService: EmailService,
    private readonly i18nService: I18nService,
    private readonly geolocationService: GeolocationService,
    private readonly sharedUserRepository: SharedUserRepository
  ) {}

  // Added _normalizeDeviceType (can be moved to a shared util)
  private _normalizeDeviceType(
    parsedDeviceType?: string,
    osName?: string,
    browserName?: string
  ): 'console' | 'mobile' | 'tablet' | 'tv' | 'wearable' | 'desktop' | 'unknown' {
    switch (parsedDeviceType) {
      case 'console':
      case 'mobile':
      case 'tablet':
      case 'wearable':
        return parsedDeviceType
      case 'smarttv':
        return 'tv'
      default:
        if (osName && browserName && !parsedDeviceType) {
          return 'desktop'
        }
        return 'unknown'
    }
  }

  /**
   * Tạo fingerprint chi tiết hơn cho thiết bị dựa trên User-Agent.
   * Mục tiêu là tạo ra một chuỗi định danh ổn định hơn cho cùng một thiết bị/môi trường duyệt web.
   */
  basicDeviceFingerprint(userAgent: string | null | undefined): string {
    const uaToProcess = userAgent || ''
    const parser = new UAParser(uaToProcess)
    const device = parser.getDevice()
    const os = parser.getOS()
    const browser = parser.getBrowser()

    const type = device.type || 'unknown_type' // ví dụ: 'mobile', 'tablet', 'desktop' (suy luận từ os/browser nếu không có)
    let osName = os.name ? os.name.toLowerCase().replace(/\s+/g, '_') : 'unknown_os'
    const osVersion = os.version ? os.version.split('.')[0] : 'any_version' // Lấy phiên bản chính
    let browserName = browser.name ? browser.name.toLowerCase().replace(/\s+/g, '_') : 'unknown_browser'
    const browserVersion = browser.version ? browser.version.split('.')[0] : 'any_version' // Lấy phiên bản chính

    // Chuẩn hóa một số trường hợp phổ biến
    if (osName.includes('mac_os') || osName.includes('macos')) osName = 'macos'
    if (osName.includes('windows')) osName = 'windows'
    if (browserName.includes('mobile_safari')) browserName = 'safari_mobile'
    if (browserName.includes('chrome') && type === 'mobile') browserName = 'chrome_mobile'

    // Suy luận 'desktop' nếu device.type không có nhưng có OS và browser
    const inferredType = device.type || (os.name && browser.name ? 'desktop' : 'unknown_type')

    return `${inferredType}-${osName}_${osVersion}-${browserName}_${browserVersion}`.substring(0, 255) // Ensure it fits VarChar(255)
  }

  @AuditLog({
    action: 'DEVICE_RECORD_CREATED_INTERNAL',
    entity: 'Device',
    getUserId: (args) => args[0]?.user?.connect?.id,
    getEntityId: (_, result) => result?.id,
    getDetails: (args) => ({ userAgent: args[0]?.userAgent, ip: args[0]?.ip, fingerprint: args[0]?.fingerprint })
  })
  async createDeviceRecordInternal(data: Prisma.DeviceCreateInput, tx?: PrismaTransactionClient): Promise<Device> {
    this.logger.debug(`Creating new device record for user ${data.user?.connect?.id}, fingerprint: ${data.fingerprint}`)
    const client = tx || this.prismaService
    return client.device.create({
      data
    })
  }

  async updateDevice(deviceId: number, data: Prisma.DeviceUpdateInput, tx?: PrismaTransactionClient): Promise<Device> {
    this.logger.debug(`Updating device record ${deviceId}`)
    const client = tx || this.prismaService
    return client.device.update({
      where: { id: deviceId },
      data
    })
  }

  async findDeviceById(deviceId: number, tx?: PrismaTransactionClient): Promise<Device | null> {
    this.logger.debug(`Finding device record with ID ${deviceId}`)
    const client = tx || this.prismaService
    return client.device.findUnique({
      where: { id: deviceId }
    })
  }

  private async _sendNewDeviceLoginNotification(
    user: UserForNotification | null,
    newDeviceUserAgent: string,
    ipAddress: string,
    fingerprintDetails: { type: string; osName: string; osVersion: string; browserName: string; browserVersion: string }
  ): Promise<void> {
    if (!user || !user.email) {
      this.logger.warn(
        `Cannot send new device notification for user ID ${user?.id || 'unknown'}: user data or email is missing.`
      )
      return
    }

    const lang = I18nContext.current()?.lang || 'en'
    const locationData = this.geolocationService.lookup(ipAddress)
    const locationString = locationData
      ? `${locationData.city || ''}${locationData.city && locationData.country ? ', ' : ''}${locationData.country || ''}`
      : await this.i18nService.translate('Email.Field.LocationUnknown', { lang })

    const subject = await this.i18nService.translate('Email.SecurityAlert.Subject.NewDeviceFingerprintLogin', { lang })
    const title = await this.i18nService.translate('Email.SecurityAlert.Title.NewDeviceFingerprintLogin', { lang })
    const mainMessage = await this.i18nService.translate('Email.SecurityAlert.MainMessage.NewDeviceFingerprintLogin', {
      lang,
      args: { userName: user.name || user.email } // Use name or email as fallback
    })
    const secondaryMessage = await this.i18nService.translate('Email.SecurityAlert.SecondaryMessage.NotYou', { lang })

    const actionDetails = [
      {
        label: await this.i18nService.translate('Email.Field.Time', { lang }),
        value: new Date().toLocaleString(lang)
      },
      {
        label: await this.i18nService.translate('Email.Field.IPAddress', { lang }),
        value: ipAddress
      },
      {
        label: await this.i18nService.translate('Email.Field.Location', { lang }),
        value: locationString || 'N/A'
      },
      {
        label: await this.i18nService.translate('Email.Field.FingerprintDevice', { lang }),
        value: `${fingerprintDetails.type || 'N/A'}`
      },
      {
        label: await this.i18nService.translate('Email.Field.FingerprintOS', { lang }),
        value: `${fingerprintDetails.osName || 'N/A'} ${fingerprintDetails.osVersion || ''}`.trim()
      },
      {
        label: await this.i18nService.translate('Email.Field.FingerprintBrowser', { lang }),
        value: `${fingerprintDetails.browserName || 'N/A'} ${fingerprintDetails.browserVersion || ''}`.trim()
      }
      // User agent đầy đủ có thể quá dài, cân nhắc bỏ hoặc rút gọn nếu cần
      // {
      //   label: await this.i18nService.translate('Email.Field.Device', { lang }),
      //   value: newDeviceUserAgent,
      // },
    ]

    // Consider adding a button to review security activity if such a page exists
    // const actionButtonText = await this.i18nService.translate('Email.SecurityAlert.Button.ReviewActivity', { lang })
    // const actionButtonUrl = `${envConfig.FRONTEND_HOST_URL}/account/security`

    this.emailService
      .sendSecurityAlertEmail({
        to: user.email,
        userName: user.name || user.email,
        alertSubject: subject,
        alertTitle: title,
        mainMessage,
        actionDetails,
        secondaryMessage
        // actionButtonText,
        // actionButtonUrl,
      })
      .then(() => {
        this.logger.log(`New device login notification sent to ${user.email} for user ID ${user.id}`)
      })
      .catch((error) => {
        this.logger.error(
          `Failed to send new device login notification to ${user.email} for user ID ${user.id}: ${error.message}`,
          error.stack
        )
      })
  }

  @AuditLog({
    action: 'DEVICE_FINGERPRINT_CHECK_ATTEMPT',
    entity: 'Device',
    getUserId: (args) => args[0]?.userId,
    getDetails: (args) => ({
      userAgentProvided: args[0]?.userAgent,
      ipProvided: args[0]?.ip
    }),
    getErrorDetails: (args) => ({
      userAgentProvided: args[0]?.userAgent,
      ipProvided: args[0]?.ip
    })
  })
  async findOrCreateDevice(
    data: { userId: number; userAgent: string; ip: string },
    tx?: PrismaTransactionClient
  ): Promise<Device> {
    const client = tx || this.prismaService
    const fingerprint = this.basicDeviceFingerprint(data.userAgent)

    this.logger.debug(
      `[DeviceService] findOrCreateDevice for user ${data.userId}, IP: ${data.ip}, UserAgent: ${data.userAgent}, Fingerprint: ${fingerprint}`
    )

    let device = await client.device.findFirst({
      where: {
        userId: data.userId,
        fingerprint
      }
    })

    const deviceLogDetails: Record<string, any> = {
      userId: data.userId,
      fingerprint,
      requestedIp: data.ip,
      requestedUserAgent: data.userAgent
    }

    if (device) {
      this.logger.debug(
        `[DeviceService] Found existing device ${device.id} for user ${data.userId} with fingerprint ${fingerprint}`
      )
      deviceLogDetails.foundDeviceId = device.id

      // Device found, update lastActive, IP, and potentially userAgent
      const updates: Prisma.DeviceUpdateInput = {
        lastActive: new Date(),
        ip: data.ip
      }

      let userAgentChanged = false
      if (device.userAgent !== data.userAgent) {
        updates.userAgent = data.userAgent
        userAgentChanged = true
        this.logger.warn(
          `[DeviceService] User agent changed for device ${device.id} (user ${data.userId}). Old: ${device.userAgent}, New: ${data.userAgent}. Fingerprint remains the same.`
        )
        deviceLogDetails.userAgentChanged = true
        deviceLogDetails.oldUserAgent = device.userAgent
      }

      device = await this.updateDevice(device.id, updates, client)

      this.auditLogService.recordAsync({
        action: userAgentChanged ? 'DEVICE_DETAILS_UPDATED_ON_LOGIN' : 'DEVICE_ACTIVITY_LOGIN',
        userId: data.userId,
        entity: 'Device',
        entityId: device.id,
        status: AuditLogStatus.SUCCESS,
        details: deviceLogDetails as Prisma.JsonObject,
        ipAddress: data.ip,
        userAgent: data.userAgent,
        notes: userAgentChanged
          ? 'Device last active, IP, and user agent updated due to login with matching fingerprint but different UA.'
          : 'Device last active and IP updated due to login with matching fingerprint.'
      })
    } else {
      this.logger.warn(
        `[DeviceService] No device found for user ${data.userId} with fingerprint ${fingerprint}. Creating a new device.`
      )

      const newDeviceData: Prisma.DeviceCreateInput = {
        user: { connect: { id: data.userId } },
        userAgent: data.userAgent,
        ip: data.ip,
        fingerprint,
        name: null, // Initially no name
        isTrusted: false,
        isActive: true // New devices are active by default
      }

      device = await this.createDeviceRecordInternal(newDeviceData, client)
      deviceLogDetails.createdDeviceId = device.id

      this.auditLogService.recordAsync({
        action: 'NEW_DEVICE_CREATED_ON_LOGIN',
        userId: data.userId,
        entity: 'Device',
        entityId: device.id,
        status: AuditLogStatus.SUCCESS,
        details: deviceLogDetails as Prisma.JsonObject,
        ipAddress: data.ip,
        userAgent: data.userAgent,
        notes: 'New device record created due to login with an unrecognized fingerprint.'
      })

      // Send notification for new device
      const userForNotification = await this.sharedUserRepository.findUnique({ id: data.userId }, client)
      const uaParsed = new UAParser(data.userAgent)
      const fingerprintDetails = {
        type: this._normalizeDeviceType(uaParsed.getDevice().type, uaParsed.getOS().name, uaParsed.getBrowser().name),
        osName: uaParsed.getOS().name || 'Unknown OS',
        osVersion: uaParsed.getOS().version || 'N/A',
        browserName: uaParsed.getBrowser().name || 'Unknown Browser',
        browserVersion: uaParsed.getBrowser().version || 'N/A'
      }

      if (userForNotification) {
        this._sendNewDeviceLoginNotification(userForNotification, data.userAgent, data.ip, fingerprintDetails).catch(
          (error) => {
            this.logger.error(
              `[DeviceService] Failed to send new device login notification for user ${data.userId}, device ${device?.id}: ${error.message}`,
              error.stack
            )
          }
        )
      }
    }
    return device
  }

  @AuditLog({
    action: 'DEVICE_VALIDATE',
    entity: 'Device',
    getEntityId: (args) => args[0],
    getDetails: (args, result) => ({
      userAgent: args[1],
      ip: args[2],
      validated: result
    })
  })
  async validateDevice(
    deviceId: number,
    userAgent: string,
    ip: string,
    tx?: PrismaTransactionClient
  ): Promise<boolean> {
    this.logger.debug(`Validating device ${deviceId} with provided User-Agent and IP`)
    const client = tx || this.prismaService
    const device = await this.findDeviceById(deviceId, client)

    if (!device || !device.isActive) {
      this.logger.warn(`Device ${deviceId} not found or inactive. Validation failed.`)
      return false
    }

    const currentRequestFingerprint = this.basicDeviceFingerprint(userAgent)
    const updates: Prisma.DeviceUpdateInput = {
      lastActive: new Date(),
      ip: ip
    }
    let isValid = false

    if (device.fingerprint) {
      if (device.fingerprint === currentRequestFingerprint) {
        this.logger.debug(
          `Device ${deviceId} validated successfully with matching fingerprint: ${currentRequestFingerprint}.`
        )
        isValid = true
        if (device.userAgent !== userAgent) {
          this.logger.warn(
            `Device ${deviceId} (fingerprint match): UserAgent updated from "${device.userAgent}" to "${userAgent}".`
          )
          updates.userAgent = userAgent
        }
      } else {
        this.logger.warn(
          `Device ${deviceId} FINGERPRINT MISMATCH: DB fingerprint "${device.fingerprint}", current request fingerprint "${currentRequestFingerprint}". UA received: "${userAgent}". Validation failed.`
        )
        isValid = false
      }
    } else {
      // Fallback for devices without a fingerprint (older records)
      // Consider these less secure; exact User-Agent match might be required, or always fail to force re-authentication and fingerprint generation.
      // For now, let's be strict: if no fingerprint, it must be an exact UA match.
      if (device.userAgent === userAgent) {
        this.logger.debug(
          `Device ${deviceId} (no fingerprint): Validated successfully with exact User-Agent match. Consider re-authentication to generate fingerprint.`
        )
        isValid = true
      } else {
        this.logger.warn(
          `Device ${deviceId} (no fingerprint): User-Agent mismatch. DB UA: "${device.userAgent}", Request UA: "${userAgent}". Validation failed.`
        )
        isValid = false
      }
    }

    // Always update lastActive and IP if device was found and active, regardless of validation outcome for this specific check,
    // as this indicates an attempt to use the device session.
    await this.updateDevice(deviceId, updates, client)

    return isValid
  }

  @AuditLog({
    action: 'DEVICE_DEACTIVATE',
    entity: 'Device',
    getEntityId: (args) => args[0]
  })
  async deactivateDevice(deviceId: number, tx?: PrismaTransactionClient): Promise<Device> {
    this.logger.debug(`Deactivating device ${deviceId}`)
    const client = tx || this.prismaService
    return this.updateDevice(deviceId, { isActive: false }, client)
  }

  @AuditLog({
    action: 'DEVICE_DEACTIVATE_ALL',
    getUserId: (args) => args[0],
    getDetails: (args, result) => ({
      excludedDeviceId: args[1],
      deactivatedCount: result.count
    })
  })
  async deactivateAllUserDevices(
    userId: number,
    excludeDeviceId?: number,
    tx?: PrismaTransactionClient
  ): Promise<Prisma.BatchPayload> {
    this.logger.debug(
      `Deactivating all devices for user ${userId}${excludeDeviceId ? ` except device ${excludeDeviceId}` : ''}`
    )
    const client = tx || this.prismaService
    const whereClause: Prisma.DeviceWhereInput = {
      userId,
      isActive: true
    }
    if (excludeDeviceId) {
      whereClause.id = { not: excludeDeviceId }
    }
    return client.device.updateMany({
      where: whereClause,
      data: {
        isActive: false
      }
    })
  }

  @AuditLog({
    action: 'DEVICE_LIST',
    getUserId: (args) => args[0],
    getDetails: (_, result) => ({
      deviceCount: result.length
    })
  })
  async getUserActiveDevices(userId: number, tx?: PrismaTransactionClient): Promise<Device[]> {
    this.logger.debug(`Getting active devices for user ${userId}`)
    const client = tx || this.prismaService
    return client.device.findMany({
      where: {
        userId,
        isActive: true
      },
      orderBy: {
        lastActive: 'desc'
      }
    })
  }

  async isDeviceOwnedByUser(deviceId: number, userId: number, tx?: PrismaTransactionClient): Promise<boolean> {
    this.logger.debug(`Checking if device ${deviceId} is owned by user ${userId}`)
    const client = tx || this.prismaService
    const device = await client.device.findUnique({
      where: {
        id: deviceId
      },
      select: {
        userId: true
      }
    })
    return device?.userId === userId
  }

  @AuditLog({
    action: 'DEVICE_TRUST',
    entity: 'Device',
    getUserId: (args) => args[1],
    getEntityId: (args) => args[0],
    getDetails: (args) => ({ deviceId: args[0], userId: args[1] })
  })
  async trustDevice(deviceId: number, userId: number, tx?: PrismaTransactionClient): Promise<Device> {
    const client = tx || this.prismaService
    const device = await client.device.findUnique({ where: { id: deviceId } })

    if (!device || device.userId !== userId) {
      this.logger.warn(
        `[DeviceService] Attempt to trust device ${deviceId} failed: Not found or not owned by user ${userId}.`
      )
      throw new ApiException(HttpStatus.NOT_FOUND, 'DEVICE_NOT_FOUND', 'Error.Auth.Device.NotFoundForUser')
    }

    if (device.isTrusted) {
      this.logger.debug(`[DeviceService] Device ${deviceId} is already trusted for user ${userId}. No action needed.`)
      return device
    }

    const updatedDevice = await client.device.update({
      where: { id: deviceId },
      data: { isTrusted: true, lastActive: new Date() } // Update lastActive as well
    })

    this.auditLogService.recordAsync({
      action: 'DEVICE_TRUSTED',
      userId,
      entity: 'Device',
      entityId: deviceId,
      status: AuditLogStatus.SUCCESS,
      details: {
        deviceUserAgent: device.userAgent,
        trustedBy: 'USER_ACTION' // Or system action if applicable
      } as Prisma.JsonObject,
      notes: `Device ${deviceId} explicitly trusted by user ${userId}.`
    })
    this.logger.log(`[DeviceService] Device ${deviceId} trusted successfully for user ${userId}.`)
    return updatedDevice
  }
}
