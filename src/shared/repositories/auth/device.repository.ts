import { Injectable, Logger } from '@nestjs/common'
import { Device, Prisma } from '@prisma/client'
import { PrismaService } from 'src/shared/services/prisma.service'
import { ConfigService } from '@nestjs/config'
import { UAParser } from 'ua-parser-js'

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
  async updateDeviceTrustStatus(deviceId: number, isTrusted: boolean, trustExpirationDate?: Date): Promise<Device> {
    const data: Prisma.DeviceUpdateInput = { isTrusted }

    // Nếu thiết bị được đánh dấu tin cậy
    if (isTrusted) {
      if (trustExpirationDate) {
        data.trustExpiration = trustExpirationDate
      } else {
        // Tính thời gian hết hạn từ cấu hình nếu không được cung cấp
        const expiryDays = this.configService.get<number>('security.deviceTrustDurationDays', 30)
        const expiryDate = new Date()
        expiryDate.setDate(expiryDate.getDate() + expiryDays)
        data.trustExpiration = expiryDate
      }
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

  /**
   * Tìm thiết bị dựa trên userId và userAgent
   * Phương thức này được sử dụng để xác định xem người dùng đang sử dụng thiết bị cũ hay mới
   */
  async findByUserIdAndUserAgent(userId: number, userAgent: string): Promise<Device | null> {
    this.logger.debug(`[findByUserIdAndUserAgent] Tìm thiết bị cho userId: ${userId} với userAgent: ${userAgent}`)

    // Trích xuất thông tin cơ bản từ userAgent
    const deviceType = this.determineDeviceType(userAgent)
    const browserInfo = this.extractBrowserInfo(userAgent)
    const osInfo = this.extractOSInfo(userAgent)

    // Tìm tất cả thiết bị của người dùng
    const userDevices = await this.prismaService.device.findMany({
      where: { userId }
    })

    if (!userDevices.length) {
      this.logger.debug(`[findByUserIdAndUserAgent] Không tìm thấy thiết bị cho userId: ${userId}`)
      return null
    }

    // Tạo "fingerprint" đơn giản từ thông tin trình duyệt và thiết bị
    const deviceFingerprint = `${deviceType}-${browserInfo.browser}-${osInfo.os}`
    this.logger.debug(`[findByUserIdAndUserAgent] Device fingerprint: ${deviceFingerprint}`)

    // Tìm thiết bị phù hợp
    // Ưu tiên 1: Thiết bị có cùng userAgent chính xác
    // Ưu tiên 2: Thiết bị có cùng loại, trình duyệt và OS
    for (const device of userDevices) {
      // Ưu tiên 1: Kiểm tra userAgent chính xác
      if (device.userAgent === userAgent) {
        this.logger.debug(`[findByUserIdAndUserAgent] Tìm thấy thiết bị chính xác: ${device.id}`)
        return device
      }

      // Ưu tiên 2: Kiểm tra thông tin trích xuất
      const savedDeviceType = this.determineDeviceType(device.userAgent)
      const savedBrowserInfo = this.extractBrowserInfo(device.userAgent)
      const savedOSInfo = this.extractOSInfo(device.userAgent)
      const savedFingerprint = `${savedDeviceType}-${savedBrowserInfo.browser}-${savedOSInfo.os}`

      if (savedFingerprint === deviceFingerprint) {
        this.logger.debug(`[findByUserIdAndUserAgent] Tìm thấy thiết bị tương tự: ${device.id}`)
        return device
      }
    }

    // Không tìm thấy thiết bị phù hợp
    this.logger.debug(`[findByUserIdAndUserAgent] Không tìm thấy thiết bị phù hợp cho userId: ${userId}`)
    return null
  }

  /**
   * Trích xuất thông tin trình duyệt từ user agent
   */
  private extractBrowserInfo(userAgent: string): { browser: string; version: string } {
    try {
      if (!userAgent) {
        return { browser: 'Unknown', version: '' }
      }
      const parser = new UAParser(userAgent)
      const browserInfo = parser.getBrowser()
      return {
        browser: browserInfo.name || 'Unknown',
        version: browserInfo.version || ''
      }
    } catch (error) {
      this.logger.error(`Error extracting browser info using ua-parser-js: ${error.message}`)
      return { browser: 'Unknown', version: '' } // Fallback
    }
  }

  /**
   * Trích xuất thông tin hệ điều hành từ user agent
   */
  private extractOSInfo(userAgent: string): { os: string; version: string } {
    try {
      if (!userAgent) {
        return { os: 'Unknown', version: '' }
      }
      const parserInstance = new UAParser(userAgent)
      const osInfo = parserInstance.getOS()
      return {
        os: osInfo.name || 'Unknown',
        version: osInfo.version || ''
      }
    } catch (error) {
      this.logger.error(`Error extracting OS info using ua-parser-js: ${error.message}`)
      return { os: 'Unknown', version: '' } // Fallback
    }
  }

  /**
   * Tạo thiết bị mới
   */
  async createDevice(data: DeviceCreateData): Promise<Device> {
    return this.prismaService.device.create({
      data: {
        userId: data.userId,
        userAgent: data.userAgent,
        ip: data.ipAddress,
        name: data.name || `Device ${new Date().toISOString().substring(0, 10)}`,
        isActive: true,
        isTrusted: data.isTrusted ?? false,
        trustExpiration: data.isTrusted
          ? this.getTrustExpirationDate(this.configService.get<number>('security.deviceTrustDurationDays', 30))
          : null
      }
    })
  }

  /**
   * Tính ngày hết hạn tin cậy
   */
  private getTrustExpirationDate(customExpiryDays?: number): Date {
    const expiryDays = customExpiryDays ?? this.configService.get<number>('security.deviceTrustDurationDays', 30)
    const expiryDate = new Date()
    expiryDate.setDate(expiryDate.getDate() + expiryDays)
    return expiryDate
  }

  /**
   * Xác định loại thiết bị từ user agent
   */
  private determineDeviceType(userAgent: string): string {
    if (!userAgent) {
      return 'Unknown'
    }

    const lowerUA = userAgent.toLowerCase()

    if (lowerUA.includes('iphone')) {
      return 'iPhone'
    } else if (lowerUA.includes('ipad')) {
      return 'iPad'
    } else if (lowerUA.includes('android') && lowerUA.includes('mobile')) {
      return 'Android Phone'
    } else if (lowerUA.includes('android')) {
      return 'Android Tablet'
    } else if (lowerUA.includes('windows phone')) {
      return 'Windows Phone'
    } else if (lowerUA.includes('windows') && lowerUA.includes('touch')) {
      return 'Windows Tablet'
    } else if (lowerUA.includes('windows')) {
      return 'Windows Desktop'
    } else if (lowerUA.includes('macintosh') || lowerUA.includes('mac os')) {
      return 'Mac'
    } else if (lowerUA.includes('linux') && !lowerUA.includes('android')) {
      return 'Linux'
    }

    return 'Unknown'
  }

  /**
   * Cập nhật thông tin vị trí của thiết bị
   */
  async updateDeviceLocation(
    deviceId: number,
    locationData: {
      lastKnownIp?: string
      lastKnownCountry?: string
      lastKnownCity?: string
    }
  ): Promise<Device> {
    const now = new Date()

    return this.prismaService.device.update({
      where: { id: deviceId },
      data: {
        ...locationData,
        lastActive: now
      }
    })
  }
}
