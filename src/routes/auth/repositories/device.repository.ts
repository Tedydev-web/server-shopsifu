import { Injectable, Logger } from '@nestjs/common'
import { Device, Prisma } from '@prisma/client'
import { PrismaService } from 'src/shared/services/prisma.service'

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

  constructor(private readonly prismaService: PrismaService) {}

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
        return this.prismaService.device.update({
          where: {
            id: existingDevice.id
          },
          data: {
            lastActive: new Date(),
            ip: ipAddress
          }
        })
      }

      // Nếu chưa tồn tại, tạo mới
      return this.prismaService.device.create({
        data: {
          userId,
          userAgent,
          ip: ipAddress,
          name: name || `Device ${new Date().toISOString().substring(0, 10)}`,
          isActive: true,
          isTrusted: false
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
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { isTrusted }
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
