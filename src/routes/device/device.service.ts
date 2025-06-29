import { Inject, Injectable, Logger, Req } from '@nestjs/common'
import { Device } from '@prisma/client'
import { Request } from 'express'
import * as tokens from 'src/shared/constants/injection.tokens'
import { DeviceFingerprintService } from 'src/shared/services/device-fingerprint.service'
import { DeviceRepository } from './device.repository'
import { DeviceError } from './device.error'

@Injectable()
export class DeviceService {
  private readonly logger = new Logger(DeviceService.name)

  constructor(
    @Inject(tokens.DEVICE_FINGERPRINT_SERVICE)
    private readonly deviceFingerprintService: DeviceFingerprintService,
    private readonly deviceRepository: DeviceRepository,
  ) {}

  async findOrCreateDevice(userId: number, req: Request): Promise<Device> {
    const deviceInfo = await this.deviceFingerprintService.extractInfo(req)

    // Try to find an existing device by fingerprint first
    if (deviceInfo.fingerprint) {
      const existingDevice = await this.deviceRepository.findByFingerprint(deviceInfo.fingerprint)
      if (existingDevice && existingDevice.userId === userId) {
        // Update IP and last active time for the existing device
        return this.deviceRepository.update(existingDevice.id, {
          ip: deviceInfo.ip,
          lastActive: new Date(),
        })
      }
    }

    // If no matching fingerprint, create a new device
    const newDevice = await this.deviceRepository.create({
      userId,
      ip: deviceInfo.ip,
      userAgent: deviceInfo.userAgent.raw,
      name: deviceInfo.userAgent.deviceName,
      fingerprint: deviceInfo.fingerprint,
      browser: deviceInfo.userAgent.browser,
      browserVersion: deviceInfo.userAgent.browserVersion,
      os: deviceInfo.userAgent.os,
      osVersion: deviceInfo.userAgent.osVersion,
      deviceType: deviceInfo.userAgent.deviceType,
      deviceVendor: deviceInfo.userAgent.deviceVendor,
      deviceModel: deviceInfo.userAgent.deviceModel,
    })

    return newDevice
  }

  async listDevicesForUser(userId: number) {
    const devices = await this.deviceRepository.findMany({ where: { userId, isActive: true } })

    // Map to only include fields needed for response
    // Handle nullable fields properly: convert placeholder values to null
    const result = devices.map((device) => ({
      id: device.id,
      name: device.name,
      ip: device.ip,
      lastActive: device.lastActive,
      createdAt: device.createdAt,
      browser: this.normalizeNullableField(device.browser),
      os: this.normalizeNullableField(device.os),
      deviceType: this.normalizeNullableField(device.deviceType),
    }))

    console.log('Device list response:', JSON.stringify(result, null, 2))
    return result
  }

  async renameDevice(userId: number, deviceId: number, name: string): Promise<Device> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device) {
      throw DeviceError.DeviceNotFound
    }
    if (device.userId !== userId) {
      throw DeviceError.DeviceNotBelongToUser
    }
    return this.deviceRepository.update(deviceId, { name })
  }

  async revokeDevice(userId: number, deviceId: number): Promise<void> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device) {
      throw DeviceError.DeviceNotFound
    }
    if (device.userId !== userId) {
      throw DeviceError.DeviceNotBelongToUser
    }

    // Đánh dấu thiết bị là không hoạt động
    await this.deviceRepository.update(deviceId, { isActive: false })
  }

  /**
   * Normalize nullable fields by converting placeholder values to null
   * This ensures Zod schema validation passes
   */
  private normalizeNullableField(value: string | null | undefined): string | null {
    if (!value || value === 'Unknown' || value === 'unknown' || value.trim() === '') {
      return null
    }
    return value
  }
}
