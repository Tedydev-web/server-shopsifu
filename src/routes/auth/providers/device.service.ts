import { Injectable, Logger, HttpStatus } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma, Device, UserProfile } from '@prisma/client'
import { AuditLog } from 'src/shared/decorators/audit-log.decorator'
import { AuditLogService, AuditLogStatus } from 'src/routes/audit-log/audit-log.service'
import { PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { UAParser } from 'ua-parser-js'
import { EmailService } from './email.service'
import { I18nService, I18nContext } from 'nestjs-i18n'
import { GeolocationService } from 'src/shared/services/geolocation.service'
import { UserRepository } from '../repositories/shared-user.repo'
import { ApiException } from 'src/shared/exceptions/api.exception'

interface UserForNotification {
  id: number
  email: string
  userProfile: Pick<UserProfile, 'firstName' | 'lastName'> | null
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
    private readonly userRepository: UserRepository
  ) {}

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

    const type = device.type || 'unknown_type'
    let osName = os.name ? os.name.toLowerCase().replace(/\s+/g, '_') : 'unknown_os'
    const osVersion = os.version ? os.version.split('.')[0] : 'any_version'
    let browserName = browser.name ? browser.name.toLowerCase().replace(/\s+/g, '_') : 'unknown_browser'
    const browserVersion = browser.version ? browser.version.split('.')[0] : 'any_version'

    if (osName.includes('mac_os') || osName.includes('macos')) osName = 'macos'
    if (osName.includes('windows')) osName = 'windows'
    if (browserName.includes('mobile_safari')) browserName = 'safari_mobile'
    if (browserName.includes('chrome') && type === 'mobile') browserName = 'chrome_mobile'

    const inferredType = device.type || (os.name && browser.name ? 'desktop' : 'unknown_type')

    return `${inferredType}-${osName}_${osVersion}-${browserName}_${browserVersion}`.substring(0, 255)
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

    const displayName = user.userProfile?.firstName || user.userProfile?.lastName || user.email

    const lang = I18nContext.current()?.lang || 'en'
    const locationData = this.geolocationService.lookup(ipAddress)
    const locationString = locationData
      ? `${locationData.city || ''}${locationData.city && locationData.country ? ', ' : ''}${locationData.country || ''}`
      : await this.i18nService.translate('Email.Field.LocationUnknown', { lang })

    const subject = await this.i18nService.translate('Email.SecurityAlert.Subject.NewDeviceFingerprintLogin', { lang })
    const title = await this.i18nService.translate('Email.SecurityAlert.Title.NewDeviceFingerprintLogin', { lang })
    const mainMessage = await this.i18nService.translate('Email.SecurityAlert.MainMessage.NewDeviceFingerprintLogin', {
      lang,
      args: { userName: displayName }
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
    ]

    this.emailService
      .sendSecurityAlertEmail({
        to: user.email,
        userName: displayName,
        alertSubject: subject,
        alertTitle: title,
        mainMessage,
        actionDetails,
        secondaryMessage
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

    const currentGeoLocationData = this.geolocationService.lookup(data.ip)
    const currentCity = currentGeoLocationData?.city || null
    const currentCountry = currentGeoLocationData?.country || null

    if (device) {
      this.logger.debug(
        `[DeviceService] Found existing device ${device.id} for user ${data.userId} with fingerprint ${fingerprint}`
      )
      deviceLogDetails.foundDeviceId = device.id

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

      const significantLocationChange =
        (currentCity && device.lastKnownCity !== currentCity) ||
        (currentCountry && device.lastKnownCountry !== currentCountry) ||
        (data.ip !== device.lastKnownIp &&
          ((!device.lastKnownCity && currentCity) || (!device.lastKnownCountry && currentCountry)))

      if (data.ip !== device.lastKnownIp) {
        updates.lastKnownIp = data.ip
        updates.lastKnownCity = currentCity
        updates.lastKnownCountry = currentCountry
        deviceLogDetails.ipChanged = true
        deviceLogDetails.oldIp = device.lastKnownIp
        deviceLogDetails.newIp = data.ip
        deviceLogDetails.newCity = currentCity
        deviceLogDetails.newCountry = currentCountry
      }

      if (significantLocationChange) {
        deviceLogDetails.significantLocationChange = true
        deviceLogDetails.oldCity = device.lastKnownCity
        deviceLogDetails.oldCountry = device.lastKnownCountry

        const now = new Date()
        const notificationCooldownMs = 24 * 60 * 60 * 1000
        const canSendNotification =
          !device.lastNotificationSentAt ||
          now.getTime() - device.lastNotificationSentAt.getTime() > notificationCooldownMs

        if (canSendNotification) {
          const userWithProfile = await this.userRepository.findUniqueWithDetails({ id: data.userId }, client)
          if (userWithProfile) {
            const userForNotification: UserForNotification = {
              id: userWithProfile.id,
              email: userWithProfile.email,
              userProfile: userWithProfile.userProfile
                ? {
                    firstName: userWithProfile.userProfile.firstName,
                    lastName: userWithProfile.userProfile.lastName
                  }
                : null
            }
            this._sendKnownDeviceNewLocationNotification(
              userForNotification,
              device,
              data.ip,
              currentCity,
              currentCountry,
              data.userAgent
            ).catch((error) => {
              this.logger.error(
                `[DeviceService] Failed to send known device new location notification for user ${data.userId}, device ${device?.id}: ${error.message}`,
                error.stack
              )
            })
            updates.lastNotificationSentAt = now
            deviceLogDetails.notificationSent = 'KNOWN_DEVICE_NEW_LOCATION'
          } else {
            deviceLogDetails.notificationSkippedReason = 'USER_NOT_FOUND_FOR_NOTIFICATION'
          }
        } else {
          deviceLogDetails.notificationSkippedReason = 'COOLDOWN_PERIOD_ACTIVE'
          this.logger.debug(
            `[DeviceService] Notification for location change on device ${device.id} (user ${data.userId}) skipped due to cooldown.`
          )
        }
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
          : significantLocationChange
            ? 'Device last active, IP updated. Significant location change detected.'
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
        name: null,
        isTrusted: false,
        isActive: true,
        lastKnownIp: data.ip,
        lastKnownCity: currentCity,
        lastKnownCountry: currentCountry,
        lastNotificationSentAt: new Date()
      }

      device = await this.createDeviceRecordInternal(newDeviceData, client)
      deviceLogDetails.createdDeviceId = device.id
      deviceLogDetails.initialIp = data.ip
      deviceLogDetails.initialCity = currentCity
      deviceLogDetails.initialCountry = currentCountry

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

      const userWithProfile = await this.userRepository.findUniqueWithDetails({ id: data.userId }, client)
      const uaParsed = new UAParser(data.userAgent)
      const fingerprintDetails = {
        type: this._normalizeDeviceType(uaParsed.getDevice().type, uaParsed.getOS().name, uaParsed.getBrowser().name),
        osName: uaParsed.getOS().name || 'Unknown OS',
        osVersion: uaParsed.getOS().version || 'N/A',
        browserName: uaParsed.getBrowser().name || 'Unknown Browser',
        browserVersion: uaParsed.getBrowser().version || 'N/A'
      }

      if (userWithProfile) {
        const userForNotification: UserForNotification = {
          id: userWithProfile.id,
          email: userWithProfile.email,
          userProfile: userWithProfile.userProfile
            ? {
                firstName: userWithProfile.userProfile.firstName,
                lastName: userWithProfile.userProfile.lastName
              }
            : null
        }
        this._sendNewDeviceLoginNotification(userForNotification, data.userAgent, data.ip, fingerprintDetails).catch(
          (error) => {
            this.logger.error(
              `[DeviceService] Failed to send new device login notification for user ${data.userId}, device ${device?.id}: ${error.message}`,
              error.stack
            )
          }
        )
      } else {
        deviceLogDetails.notificationSkippedReason = 'USER_NOT_FOUND_FOR_NEW_DEVICE_NOTIFICATION'
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
      data: { isTrusted: true, lastActive: new Date() }
    })

    this.auditLogService.recordAsync({
      action: 'DEVICE_TRUSTED',
      userId,
      entity: 'Device',
      entityId: deviceId,
      status: AuditLogStatus.SUCCESS,
      details: {
        deviceUserAgent: device.userAgent,
        trustedBy: 'USER_ACTION'
      } as Prisma.JsonObject,
      notes: `Device ${deviceId} explicitly trusted by user ${userId}.`
    })
    this.logger.log(`[DeviceService] Device ${deviceId} trusted successfully for user ${userId}.`)
    return updatedDevice
  }

  private async _sendKnownDeviceNewLocationNotification(
    user: UserForNotification,
    device: Device,
    newIpAddress: string,
    newCity: string | null,
    newCountry: string | null,
    currentUserAgent: string
  ): Promise<void> {
    if (!user || !user.email) {
      this.logger.warn(
        `Cannot send known device new location notification for user ID ${user.id}: user data or email is missing.`
      )
      return
    }

    const displayName = user.userProfile?.firstName || user.userProfile?.lastName || user.email

    const lang = I18nContext.current()?.lang || 'en'

    const subject = await this.i18nService.translate('Email.SecurityAlert.Subject.NewTrustedDeviceLoginLocation', {
      lang
    })
    const title = await this.i18nService.translate('Email.SecurityAlert.Title.NewTrustedDeviceLoginLocation', { lang })
    const mainMessage = await this.i18nService.translate(
      'Email.SecurityAlert.MainMessage.NewTrustedDeviceLoginLocation',
      {
        lang,
        args: { userName: displayName }
      }
    )
    const secondaryMessage = await this.i18nService.translate('Email.SecurityAlert.SecondaryMessage.NotYou', { lang })

    const newLocationString =
      newCity && newCountry
        ? `${newCity}, ${newCountry}`
        : newCity || newCountry || (await this.i18nService.translate('Email.Field.LocationUnknown', { lang })) || 'N/A'
    const oldLocationString =
      device.lastKnownCity && device.lastKnownCountry
        ? `${device.lastKnownCity}, ${device.lastKnownCountry}`
        : device.lastKnownCity ||
          device.lastKnownCountry ||
          (await this.i18nService.translate('Email.Field.LocationUnknown', { lang })) ||
          'N/A'

    const uaParsed = new UAParser(currentUserAgent)
    const fingerprintDetails = {
      type: this._normalizeDeviceType(uaParsed.getDevice().type, uaParsed.getOS().name, uaParsed.getBrowser().name),
      osName: uaParsed.getOS().name || 'Unknown OS',
      osVersion: uaParsed.getOS().version || 'N/A',
      browserName: uaParsed.getBrowser().name || 'Unknown Browser',
      browserVersion: uaParsed.getBrowser().version || 'N/A'
    }

    const actionDetails = [
      {
        label: await this.i18nService.translate('Email.Field.Time', { lang }),
        value: new Date().toLocaleString(lang)
      },
      {
        label: await this.i18nService.translate('Email.Field.DeviceName', { lang, defaultValue: 'Device Name' }),
        value:
          device.name ||
          (await this.i18nService.translate('Email.Field.DeviceIdentifier', {
            lang,
            defaultValue: `Device ID: ${device.id}`
          })) ||
          `Device ID: ${device.id}`
      },
      {
        label: await this.i18nService.translate('Email.Field.NewIPAddress', { lang, defaultValue: 'New IP Address' }),
        value: newIpAddress
      },
      {
        label: await this.i18nService.translate('Email.Field.NewApprox.Location', {
          lang,
          defaultValue: 'New Approx. Location'
        }),
        value: newLocationString
      },
      {
        label: await this.i18nService.translate('Email.Field.OldIPAddress', {
          lang,
          defaultValue: 'Previous IP Address'
        }),
        value: device.lastKnownIp || 'N/A'
      },
      {
        label: await this.i18nService.translate('Email.Field.OldLocation', {
          lang,
          defaultValue: 'Previous Approx. Location'
        }),
        value: oldLocationString
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
    ]

    this.emailService
      .sendSecurityAlertEmail({
        to: user.email,
        userName: displayName,
        alertSubject: subject,
        alertTitle: title,
        mainMessage,
        actionDetails,
        secondaryMessage
      })
      .then(() => {
        this.logger.log(
          `Known device new location notification sent to ${user.email} for user ID ${user.id}, device ID ${device.id}`
        )
      })
      .catch((error) => {
        this.logger.error(
          `Failed to send known device new location notification to ${user.email} for user ID ${user.id}, device ID ${device.id}: ${error.message}`,
          error.stack
        )
      })
  }
}
