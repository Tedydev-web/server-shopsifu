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

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService
  ) {}

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
        return this.prismaService.device.update({
          where: {
            id: existingDevice.id
          },
          data: {
            lastActive: new Date(),
            ip: ipAddress
            // Không cập nhật trạng thái tin tưởng của thiết bị nếu đã tồn tại
          }
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
          isTrusted: false // Thiết bị mới mặc định không được tin tưởng
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
    const data: any = { isTrusted }

    // Nếu thiết bị được đánh dấu tin cậy, thiết lập thời gian hết hạn
    if (isTrusted) {
      // Tính thời gian hết hạn từ cấu hình
      const expiryDays = this.configService.get<number>('DEVICE_TRUST_EXPIRATION_DAYS', 30)
      const expiryDate = new Date()
      expiryDate.setDate(expiryDate.getDate() + expiryDays)
      data.trustExpiration = expiryDate
    } else {
      // Nếu bỏ tin cậy, xóa thời gian hết hạn
      data.trustExpiration = null
    }

    return this.prismaService.device.update({
      where: { id: deviceId },
      data
    })
  }

  /**
   * Kiểm tra xem thiết bị có còn trong thời gian tin cậy hay không
   */
  async isDeviceTrustValid(deviceId: number): Promise<boolean> {
    const device = await this.prismaService.device.findUnique({
      where: { id: deviceId }
    })

    if (!device) {
      return false
    }

    // Nếu thiết bị không được đánh dấu tin cậy, trả về false
    if (!device.isTrusted) {
      return false
    }

    // Nếu không có thời gian hết hạn hoặc thời gian hết hạn còn hiệu lực
    if (!device.trustExpiration || new Date() <= device.trustExpiration) {
      return true
    }

    // Nếu đã hết hạn, cập nhật lại trạng thái tin cậy
    await this.prismaService.device.update({
      where: { id: deviceId },
      data: {
        isTrusted: false,
        trustExpiration: null
      }
    })

    return false
  }

  /**
   * Cập nhật fingerprint của thiết bị
   */
  async updateDeviceFingerprint(deviceId: number, fingerprint: string): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { fingerprint }
    })
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
