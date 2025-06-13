import { Injectable, Logger } from '@nestjs/common'
import { Device, Prisma } from '@prisma/client'
import { PrismaService } from 'src/shared/providers/prisma/prisma.service'
import { ConfigService } from '@nestjs/config'
import { UserAgentService } from 'src/shared/services/user-agent.service'

export type DeviceCreateData = {
  userId: number
  userAgent: string
  ipAddress: string
  name?: string
  isTrusted?: boolean
}

@Injectable()
export class DeviceRepository {
  private readonly logger = new Logger(DeviceRepository.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
    private readonly userAgentService: UserAgentService
  ) {}

  /**
   * Tìm thiết bị theo ID
   */
  async findById(deviceId: number): Promise<Device | null> {
    this.logger.debug(`[findById] Finding device with id: ${deviceId}`)
    return this.prismaService.device.findUnique({
      where: { id: deviceId }
    })
  }

  /**
   * Tìm thiết bị của user
   */
  async findDevicesByUserId(userId: number): Promise<Device[]> {
    this.logger.debug(`[findDevicesByUserId] Finding devices for user ${userId}`)
    return this.prismaService.device.findMany({
      where: { userId },
      orderBy: {
        lastActive: 'desc'
      }
    })
  }

  /**
   * Tìm hoặc tạo thiết bị
   */
  async upsertDevice(userId: number, userAgent: string, ipAddress: string, name?: string): Promise<Device> {
    this.logger.debug(`[upsertDevice] Upserting device for user ${userId} with user agent ${userAgent}`)
    const existingDevice = await this.findByUserIdAndUserAgent(userId, userAgent)

    if (existingDevice) {
      this.logger.debug(`[upsertDevice] Found existing device with id: ${existingDevice.id}`)
      return this.prismaService.device.update({
        where: { id: existingDevice.id },
        data: { ip: ipAddress, lastActive: new Date() }
      })
    }

    this.logger.debug(`[upsertDevice] No existing device found, creating a new one.`)
    const uaInfo = this.userAgentService.parse(userAgent)
    const defaultDeviceName = name ?? uaInfo.deviceName

    const deviceData: Prisma.DeviceCreateInput = {
      user: { connect: { id: userId } },
      name: defaultDeviceName,
      userAgent,
      ip: ipAddress,
      isTrusted: false,
      trustExpiration: null,
      lastActive: new Date()
    }

    return this.prismaService.device.create({
      data: deviceData
    })
  }

  /**
   * Cập nhật trạng thái tin cậy của thiết bị
   */
  async updateDeviceTrustStatus(deviceId: number, isTrusted: boolean, trustExpirationDate?: Date): Promise<Device> {
    this.logger.debug(
      `[updateDeviceTrustStatus] Updating trust status for device ${deviceId} to ${isTrusted ? 'trusted' : 'untrusted'}`
    )
    const trustExpiration =
      isTrusted === false ? null : (trustExpirationDate ?? this.getTrustExpirationDate(isTrusted ? undefined : 0))

    const updatedDevice = await this.prismaService.device.update({
      where: { id: deviceId },
      data: { isTrusted, trustExpiration }
    })

    if (!updatedDevice) {
      this.logger.warn(`[updateDeviceTrustStatus] Device with ID ${deviceId} not found.`)
    }

    return updatedDevice
  }

  /**
   * Kiểm tra xem thiết bị có còn trong thời gian tin cậy hay không
   */
  async isDeviceTrustValid(deviceId: number): Promise<boolean> {
    this.logger.debug(`[isDeviceTrustValid] Checking trust validity for device ${deviceId}`)
    const device = await this.findById(deviceId)
    if (!device || !device.isTrusted) {
      return false
    }

    if (device.trustExpiration && device.trustExpiration.getTime() < Date.now()) {
      this.logger.log(`[isDeviceTrustValid] Device ${deviceId} trust has expired. Untrusting...`)
      // Asynchronously untrust the device
      this.updateDeviceTrustStatus(deviceId, false).catch((err) => {
        this.logger.error(`Failed to untrust expired device ${deviceId}`, err)
      })
      return false
    }

    return true
  }

  /**
   * Cập nhật fingerprint của thiết bị
   */
  async updateDeviceFingerprint(deviceId: number, fingerprint: string): Promise<Device> {
    this.logger.debug(`[updateDeviceFingerprint] Updating fingerprint for device ${deviceId}`)
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { fingerprint }
    })
  }

  /**
   * Cập nhật tên thiết bị
   */
  async updateDeviceName(deviceId: number, name: string): Promise<Device> {
    this.logger.debug(`[updateDeviceName] Updating name for device ${deviceId} to "${name}"`)
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { name }
    })
  }

  /**
   * Cập nhật thời gian thông báo cuối
   */
  async updateLastNotificationSent(deviceId: number): Promise<Device> {
    this.logger.debug(`[updateLastNotificationSent] Updating last notification sent time for device ${deviceId}`)
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { lastNotificationSentAt: new Date() }
    })
  }

  /**
   * Đánh dấu thiết bị là không còn hoạt động
   */
  async markDeviceAsInactive(deviceId: number): Promise<Device> {
    this.logger.debug(`[markDeviceAsInactive] Marking device ${deviceId} as inactive`)
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { isActive: false }
    })
  }

  /**
   * Tìm thiết bị dựa trên userId và userAgent
   * Phương thức này được sử dụng để xác định xem người dùng đang sử dụng thiết bị cũ hay mới
   */
  async findByUserIdAndUserAgent(userId: number, userAgent: string): Promise<Device | null> {
    const devices = await this.prismaService.device.findMany({
      where: { userId }
    })
    const currentUserAgentInfo = this.userAgentService.parse(userAgent)

    for (const device of devices) {
      const storedUserAgentInfo = this.userAgentService.parse(device.userAgent)

      const isSameBrowser = storedUserAgentInfo.browser === currentUserAgentInfo.browser
      const isSameOS = storedUserAgentInfo.os === currentUserAgentInfo.os

      if (isSameBrowser && isSameOS) {
        this.logger.debug(`[findByUserIdAndUserAgent] Found matching device ${device.id}`)
        return device
      }
    }

    this.logger.debug(`[findByUserIdAndUserAgent] No matching device found for user ${userId}`)
    return null
  }

  /**
   * Tạo thiết bị mới
   */
  async createDevice(data: DeviceCreateData): Promise<Device> {
    const { userId, userAgent, ipAddress, name, isTrusted = false } = data
    const uaInfo = this.userAgentService.parse(userAgent)

    const trustExpiration = isTrusted ? this.getTrustExpirationDate() : null
    const defaultDeviceName = name ?? uaInfo.deviceName

    return this.prismaService.device.create({
      data: {
        user: { connect: { id: userId } },
        name: defaultDeviceName,
        userAgent,
        ip: ipAddress,
        isTrusted,
        trustExpiration,
        lastActive: new Date()
      }
    })
  }

  /**
   * Tính ngày hết hạn tin cậy
   */
  private getTrustExpirationDate(customExpiryDays?: number): Date {
    const expiryDays = customExpiryDays ?? this.configService.get<number>('auth.deviceTrust.expiresInDays', 90)
    const date = new Date()
    date.setDate(date.getDate() + expiryDays)
    return date
  }

  /**
   * Cập nhật thông tin vị trí của thiết bị
   */
  async updateDeviceLocation(
    deviceId: number,
    locationData: {
      ip?: string
      lastKnownCountry?: string
      lastKnownCity?: string
    }
  ): Promise<Device> {
    this.logger.debug(`[updateDeviceLocation] Updating location for device ${deviceId}`)
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: locationData
    })
  }
}
