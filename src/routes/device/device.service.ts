import { ForbiddenException, Injectable, Logger } from '@nestjs/common'
import { Device } from '@prisma/client'
import { Request } from 'express'
import { DeviceFingerprintService } from 'src/shared/services/auth/device-fingerprint.service'
import { DeviceRepository } from './device.repository'
import { I18nService } from 'nestjs-i18n'
import { isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { NotFoundRecordException } from 'src/shared/error'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

@Injectable()
export class DeviceService {
  private readonly logger = new Logger(DeviceService.name)

  constructor(
    private readonly deviceFingerprintService: DeviceFingerprintService,
    private readonly deviceRepository: DeviceRepository,
    private readonly i18n: I18nService<I18nTranslations>
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
          lastActive: new Date()
        })
      }
    }

    try {
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
        deviceModel: deviceInfo.userAgent.deviceModel
      })

      return newDevice
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        this.logger.warn(`Race condition handled: Device with fingerprint already exists, re-fetching.`)
        // The device was created by a concurrent request, so we fetch it.
        const device = await this.deviceRepository.findByFingerprint(deviceInfo.fingerprint)
        if (device) return device
      }
      // Re-throw if it's a different error or re-fetching fails
      throw error
    }
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
      deviceType: this.normalizeNullableField(device.deviceType)
    }))

    console.log('Device list response:', JSON.stringify(result, null, 2))
    return result
  }

  async renameDevice(userId: number, deviceId: number, name: string): Promise<Device> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device) {
      throw NotFoundRecordException
    }
    if (device.userId !== userId) {
      throw ForbiddenException
    }
    return this.deviceRepository.update(deviceId, { name })
  }

  async revokeDevice(userId: number, deviceId: number): Promise<{ message: string }> {
    const device = await this.deviceRepository.findById(deviceId)
    if (!device) {
      throw NotFoundRecordException
    }
    if (device.userId !== userId) {
      throw ForbiddenException
    }

    // Đánh dấu thiết bị là không hoạt động
    await this.deviceRepository.update(deviceId, { isActive: false })

    return {
      message: this.i18n.t('device.success.DEVICE_REVOKED')
    }
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
