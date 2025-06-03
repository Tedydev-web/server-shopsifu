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

    if (userDevices.length === 0) {
      this.logger.debug(`[findByUserIdAndUserAgent] Không tìm thấy thiết bị nào cho userId: ${userId}`)
      return null
    }

    // Tìm thiết bị phù hợp nhất dựa trên:
    // 1. Chính xác userAgent (trường hợp đăng nhập nhiều lần từ cùng một trình duyệt)
    const exactMatch = userDevices.find((device) => device.userAgent === userAgent)
    if (exactMatch) {
      this.logger.debug(`[findByUserIdAndUserAgent] Tìm thấy thiết bị chính xác với ID: ${exactMatch.id}`)
      return exactMatch
    }

    // 2. Phù hợp về OS, deviceType và browser
    for (const device of userDevices) {
      const deviceOsInfo = this.extractOSInfo(device.userAgent)
      const deviceBrowserInfo = this.extractBrowserInfo(device.userAgent)
      const deviceTypeMatch = this.determineDeviceType(device.userAgent)

      const isSameOS = deviceOsInfo.os === osInfo.os
      const isSameBrowser = deviceBrowserInfo.browser === browserInfo.browser
      const isSameDeviceType = deviceTypeMatch === deviceType

      // Nếu cùng loại thiết bị, OS và trình duyệt, coi là cùng thiết bị
      if (isSameOS && isSameBrowser && isSameDeviceType) {
        this.logger.debug(
          `[findByUserIdAndUserAgent] Tìm thấy thiết bị tương tự với ID: ${device.id}, ` +
            `OS: ${isSameOS}, Browser: ${isSameBrowser}, DeviceType: ${isSameDeviceType}`
        )
        return device
      }
    }

    this.logger.debug(`[findByUserIdAndUserAgent] Không tìm thấy thiết bị phù hợp cho userId: ${userId}`)
    return null
  }

  /**
   * Trích xuất thông tin trình duyệt từ user agent
   */
  private extractBrowserInfo(userAgent: string): { browser: string; version: string } {
    let browser = 'Unknown'
    let version = 'Unknown'

    // Chrome
    const chromeMatch = userAgent.match(/Chrome\/([0-9.]+)/)
    if (chromeMatch) {
      browser = 'Chrome'
      version = chromeMatch[1]
    }

    // Firefox
    const firefoxMatch = userAgent.match(/Firefox\/([0-9.]+)/)
    if (firefoxMatch) {
      browser = 'Firefox'
      version = firefoxMatch[1]
    }

    // Safari (phải kiểm tra sau Chrome vì Chrome trên iOS cũng có chứa Safari)
    const safariMatch = userAgent.match(/Safari\/([0-9.]+)/)
    if (safariMatch && !chromeMatch) {
      browser = 'Safari'
      version = safariMatch[1]

      // Lấy phiên bản Safari chính xác hơn từ Version tag
      const versionMatch = userAgent.match(/Version\/([0-9.]+)/)
      if (versionMatch) {
        version = versionMatch[1]
      }
    }

    // Edge
    const edgeMatch = userAgent.match(/Edg(e)?\/([0-9.]+)/)
    if (edgeMatch) {
      browser = 'Edge'
      version = edgeMatch[2]
    }

    // Opera
    const operaMatch = userAgent.match(/OPR\/([0-9.]+)/)
    if (operaMatch) {
      browser = 'Opera'
      version = operaMatch[1]
    }

    return { browser, version }
  }

  /**
   * Trích xuất thông tin hệ điều hành từ user agent
   */
  private extractOSInfo(userAgent: string): { os: string; version: string } {
    let os = 'Unknown'
    let version = 'Unknown'

    // Windows
    const windowsMatch = userAgent.match(/Windows NT ([0-9.]+)/)
    if (windowsMatch) {
      os = 'Windows'

      // Chuyển đổi version number sang tên phiên bản
      const versionMap: { [key: string]: string } = {
        '10.0': '10',
        '6.3': '8.1',
        '6.2': '8',
        '6.1': '7',
        '6.0': 'Vista',
        '5.2': 'XP',
        '5.1': 'XP'
      }

      version = versionMap[windowsMatch[1]] || windowsMatch[1]
    }

    // MacOS
    const macOSMatch = userAgent.match(/Mac OS X ([0-9_\.]+)/)
    if (macOSMatch) {
      os = 'macOS'
      version = macOSMatch[1].replace(/_/g, '.')

      // Xử lý Mac OS X 11_15_7 cho đúng
      const parts = version.split('.')
      if (parts.length >= 2) {
        const majorVersion = parseInt(parts[0], 10)
        if (majorVersion >= 11) {
          // Với macOS 11+, sử dụng tên phiên bản như Big Sur, Monterey, etc.
          const versionNames: { [key: string]: string } = {
            '11': 'Big Sur',
            '12': 'Monterey',
            '13': 'Ventura',
            '14': 'Sonoma'
          }
          version = versionNames[parts[0]] || version
        } else if (majorVersion === 10) {
          // Với macOS 10.x, sử dụng tên phiên bản như Catalina, Mojave, etc.
          const minorVersion = parseInt(parts[1], 10)
          const versionNames: { [key: number]: string } = {
            15: 'Catalina',
            14: 'Mojave',
            13: 'High Sierra',
            12: 'Sierra',
            11: 'El Capitan',
            10: 'Yosemite',
            9: 'Mavericks'
          }
          version = versionNames[minorVersion] ? `${version} (${versionNames[minorVersion]})` : version
        }
      }
    }

    // Linux
    const linuxMatch = userAgent.match(/Linux/)
    if (linuxMatch) {
      os = 'Linux'

      // Detect Ubuntu
      if (userAgent.includes('Ubuntu')) {
        os = 'Ubuntu'
        const ubuntuMatch = userAgent.match(/Ubuntu[/\s]([0-9.]+)/)
        if (ubuntuMatch) {
          version = ubuntuMatch[1]
        }
      }
    }

    // iOS
    const iOSMatch = userAgent.match(/iPhone OS ([0-9_]+)/) || userAgent.match(/iPad.*OS ([0-9_]+)/)
    if (iOSMatch) {
      os = 'iOS'
      version = iOSMatch[1].replace(/_/g, '.')
    }

    // Android
    const androidMatch = userAgent.match(/Android ([0-9.]+)/)
    if (androidMatch) {
      os = 'Android'
      version = androidMatch[1]
    }

    return { os, version }
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

  /**
   * Xác định loại thiết bị từ userAgent
   * @param userAgent Chuỗi user agent
   * @returns Loại thiết bị: Desktop, Mobile, Tablet, TV, hoặc Unknown
   */
  private determineDeviceType(userAgent: string): string {
    // Kiểm tra Tablet
    if (/(tablet|ipad|playbook|silk)|(android(?!.*mobile))/i.test(userAgent) || /iPad/.test(userAgent)) {
      return 'Tablet'
    }

    // Kiểm tra Mobile
    if (
      /Mobile|Android|iP(hone|od)|IEMobile|BlackBerry|Kindle|Silk-Accelerated|(hpw|web)OS|Opera M(obi|ini)/.test(
        userAgent
      ) ||
      // Nhận dạng iPhone/iPod
      /iPhone|iPod/.test(userAgent)
    ) {
      return 'Mobile'
    }

    // Kiểm tra Smart TV
    if (/smart-tv|SmartTV|SMART-TV|Opera TV|AppleTV|GoogleTV|BRAVIA|Roku|WebOS|Android TV/i.test(userAgent)) {
      return 'TV'
    }

    // Kiểm tra Wearable (smartwatch, etc.)
    if (/Watch|SM-R|Fitbit|Galaxy Watch|Apple Watch/i.test(userAgent)) {
      return 'Wearable'
    }

    // Kiểm tra Game Console
    if (/Xbox|PlayStation|Nintendo/i.test(userAgent)) {
      return 'Game Console'
    }

    // Mặc định là Desktop nếu không phải Mobile hoặc Tablet
    return 'Desktop'
  }
}
