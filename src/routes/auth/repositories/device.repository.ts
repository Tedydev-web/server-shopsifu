import { Injectable, Logger } from '@nestjs/common'
import { Device, Prisma } from '@prisma/client'
import { PrismaService } from 'src/shared/services/prisma.service'
import { ConfigService } from '@nestjs/config'

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
  private readonly deviceTrustDuration: number

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService
  ) {
    // Lấy thời gian tin cậy thiết bị từ config
    this.deviceTrustDuration = configService.get<number>('DEVICE_TRUST_DURATION_MS', 90 * 24 * 60 * 60 * 1000) // Mặc định 90 ngày
  }

  /**
   * Tìm thiết bị theo ID
   */
  async findById(deviceId: number): Promise<Device | null> {
    return this.prismaService.device.findUnique({
      where: { id: deviceId }
    })
  }

  /**
   * Tìm thiết bị của user
   */
  async findDevicesByUserId(userId: number): Promise<Device[]> {
    return this.prismaService.device.findMany({
      where: { userId }
    })
  }

  /**
   * Tìm hoặc tạo thiết bị
   */
  async upsertDevice(userId: number, userAgent: string, ipAddress: string, name?: string): Promise<Device> {
    try {
      // Tìm thiết bị dựa trên userId và userAgent
      const existingDevice = await this.prismaService.device.findFirst({
        where: {
          userId,
          userAgent
        }
      })

      // Nếu đã tồn tại, cập nhật thông tin
      if (existingDevice) {
        this.logger.debug(`Updating existing device ID ${existingDevice.id} for user ${userId}`)
        let updateData: Prisma.DeviceUpdateInput = {
          lastActive: new Date(),
          ip: ipAddress
        }

        // Kiểm tra thời hạn tin cậy
        if (existingDevice.isTrusted && existingDevice.trustExpiration) {
          if (new Date() > existingDevice.trustExpiration) {
            this.logger.debug(`Trust expired for device ${existingDevice.id} of user ${userId}`)
            updateData.isTrusted = false
            updateData.trustExpiration = null
          }
        }

        return this.prismaService.device.update({
          where: {
            id: existingDevice.id
          },
          data: updateData
        })
      }

      // Nếu chưa tồn tại, tạo mới
      this.logger.debug(`Creating new device for user ${userId}`)
      return this.prismaService.device.create({
        data: {
          userId,
          userAgent,
          ip: ipAddress,
          name: name || `Device ${new Date().toISOString().substring(0, 10)}`,
          isActive: true,
          isTrusted: false, // Thiết bị mới mặc định không được tin tưởng
          trustExpiration: null
        }
      })
    } catch (error) {
      this.logger.error(`Error upserting device: ${error.message}`)
      throw error
    }
  }

  /**
   * Cập nhật trạng thái tin cậy của thiết bị
   */
  async updateDeviceTrustStatus(deviceId: number, isTrusted: boolean): Promise<Device> {
    const updateData: Prisma.DeviceUpdateInput = {
      isTrusted,
      trustExpiration: isTrusted ? new Date(Date.now() + this.deviceTrustDuration) : null
    }

    return this.prismaService.device.update({
      where: { id: deviceId },
      data: updateData
    })
  }

  /**
   * Kiểm tra xem thiết bị có thực sự được tin cậy không (dựa vào thời hạn)
   */
  async isDeviceTrusted(deviceId: number): Promise<boolean> {
    const device = await this.prismaService.device.findUnique({
      where: { id: deviceId }
    })

    if (!device || !device.isTrusted) {
      return false
    }

    // Nếu không có thời hạn tin cậy (thiết lập trước khi thêm tính năng), coi như đã hết hạn
    if (!device.trustExpiration) {
      await this.updateDeviceTrustStatus(deviceId, false)
      return false
    }

    // So sánh với thời gian hiện tại
    const now = new Date()
    if (now > device.trustExpiration) {
      // Đã hết hạn, cập nhật lại trạng thái
      await this.updateDeviceTrustStatus(deviceId, false)
      return false
    }

    return true
  }

  /**
   * Cập nhật tên thiết bị
   */
  async updateDeviceName(deviceId: number, name: string): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { name }
    })
  }

  /**
   * Cập nhật thời gian thông báo cuối
   */
  async updateLastNotificationSent(deviceId: number): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { lastNotificationSentAt: new Date() }
    })
  }

  /**
   * Đánh dấu thiết bị là không còn hoạt động
   */
  async markDeviceAsInactive(deviceId: number): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { isActive: false }
    })
  }

  async findByUserIdAndUserAgent(userId: number, userAgent: string): Promise<Device | null> {
    return this.prismaService.device.findFirst({
      where: {
        userId,
        userAgent
      }
    })
  }

  async createDevice(data: DeviceCreateData): Promise<Device> {
    const { userId, userAgent, ipAddress, name, isTrusted } = data

    return this.prismaService.device.create({
      data: {
        userId,
        userAgent: userAgent || 'unknown',
        ip: ipAddress || 'unknown',
        name: name || `Device ${new Date().toISOString()}`,
        isTrusted: isTrusted || false,
        lastActive: new Date()
      }
    })
  }

  private determineDeviceType(userAgent: string): string {
    userAgent = userAgent.toLowerCase()

    if (userAgent.includes('mobile') || userAgent.includes('android') || userAgent.includes('iphone')) {
      return 'mobile'
    } else if (userAgent.includes('tablet') || userAgent.includes('ipad')) {
      return 'tablet'
    } else if (userAgent.includes('bot') || userAgent.includes('crawl') || userAgent.includes('spider')) {
      return 'bot'
    } else {
      return 'desktop'
    }
  }
}
