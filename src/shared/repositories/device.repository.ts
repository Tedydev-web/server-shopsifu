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
  fingerprint?: string
}

@Injectable()
export class DeviceRepository {
  private readonly logger = new Logger(DeviceRepository.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly configService: ConfigService,
    private readonly userAgentService: UserAgentService
  ) {}

  async findById(deviceId: number): Promise<Device | null> {
    return this.prismaService.device.findUnique({
      where: { id: deviceId }
    })
  }

  async findDevicesByUserId(userId: number): Promise<Device[]> {
    return this.prismaService.device.findMany({
      where: { userId },
      orderBy: {
        lastActive: 'desc'
      }
    })
  }

  async upsertDevice(
    userId: number,
    userAgent: string,
    ipAddress: string,
    fingerprint?: string,
    name?: string
  ): Promise<Device> {
    // 1. Cố gắng tìm bằng fingerprint (chính xác nhất)
    if (fingerprint) {
      const existingDevice = await this.findDeviceByFingerprint(fingerprint)
      if (existingDevice) {
        return this.prismaService.device.update({
          where: { id: existingDevice.id },
          data: { ip: ipAddress, lastActive: new Date() }
        })
      }
    }

    // 2. Nếu không có fingerprint hoặc không tìm thấy, thử tìm bằng User Agent (dự phòng)
    const existingDeviceByUA = await this.findByUserIdAndUserAgent(userId, userAgent)
    if (existingDeviceByUA) {
      // Cập nhật fingerprint nếu có và thiết bị chưa có
      const dataToUpdate: Prisma.DeviceUpdateInput = { ip: ipAddress, lastActive: new Date() }
      if (fingerprint && !existingDeviceByUA.fingerprint) {
        dataToUpdate.fingerprint = fingerprint
      }
      return this.prismaService.device.update({
        where: { id: existingDeviceByUA.id },
        data: dataToUpdate
      })
    }

    // 3. Nếu không tìm thấy, tạo mới
    return this.createDevice({ userId, userAgent, ipAddress, name, fingerprint })
  }

  async updateDeviceTrustStatus(deviceId: number, isTrusted: boolean, trustExpirationDate?: Date): Promise<Device> {
    const trustExpiration =
      isTrusted === false ? null : (trustExpirationDate ?? this.getTrustExpirationDate(isTrusted ? undefined : 0))

    const updatedDevice = await this.prismaService.device.update({
      where: { id: deviceId },
      data: { isTrusted, trustExpiration }
    })

    return updatedDevice
  }

  async isDeviceTrustValid(deviceId: number): Promise<boolean> {
    const device = await this.findById(deviceId)
    if (!device || !device.isTrusted) {
      return false
    }

    if (device.trustExpiration && device.trustExpiration.getTime() < Date.now()) {
      // Asynchronously untrust the device
      this.updateDeviceTrustStatus(deviceId, false).catch(() => {})
      return false
    }

    return true
  }

  async updateDeviceFingerprint(deviceId: number, fingerprint: string): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { fingerprint }
    })
  }

  async updateDeviceName(deviceId: number, name: string): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { name }
    })
  }

  async updateLastNotificationSent(deviceId: number): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { lastNotificationSentAt: new Date() }
    })
  }

  async markDeviceAsInactive(deviceId: number): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: { isActive: false }
    })
  }

  async findByUserIdAndUserAgent(userId: number, userAgent: string): Promise<Device | null> {
    const uaInfo = this.userAgentService.parse(userAgent)

    // Find a device that matches the key characteristics
    const device = await this.prismaService.device.findFirst({
      where: {
        userId,
        // We consider it the "same" device if browser and OS match.
        // This avoids creating new devices for minor browser patch versions.
        browser: uaInfo.browser,
        os: uaInfo.os,
        deviceType: uaInfo.deviceType
      }
    })

    if (device) {
      return device
    }

    return null
  }

  async createDevice(data: DeviceCreateData): Promise<Device> {
    const { userId, userAgent, ipAddress, name, isTrusted = false, fingerprint } = data
    const uaInfo = this.userAgentService.parse(userAgent)

    const trustExpiration = isTrusted ? this.getTrustExpirationDate() : null
    const defaultDeviceName = name ?? uaInfo.deviceName

    return this.prismaService.device.create({
      data: {
        user: { connect: { id: userId } },
        name: defaultDeviceName,
        fingerprint,
        userAgent,
        ip: ipAddress,
        isTrusted,
        trustExpiration,
        lastActive: new Date(),
        // Store parsed information
        browser: uaInfo.browser,
        browserVersion: uaInfo.browserVersion,
        os: uaInfo.os,
        osVersion: uaInfo.osVersion,
        deviceType: uaInfo.deviceType,
        deviceVendor: uaInfo.deviceVendor,
        deviceModel: uaInfo.deviceModel
      }
    })
  }

  private getTrustExpirationDate(customExpiryDays?: number): Date {
    const expiryDays = customExpiryDays ?? this.configService.get<number>('auth.deviceTrust.expiresInDays', 90)
    const date = new Date()
    date.setDate(date.getDate() + expiryDays)
    return date
  }

  async updateDeviceLocation(
    deviceId: number,
    locationData: {
      ip?: string
      lastKnownCountry?: string
      lastKnownCity?: string
    }
  ): Promise<Device> {
    return this.prismaService.device.update({
      where: { id: deviceId },
      data: locationData
    })
  }

  async findDeviceByFingerprint(fingerprint: string): Promise<Device | null> {
    if (!fingerprint) return null
    return this.prismaService.device.findUnique({
      where: { fingerprint }
    })
  }
}
