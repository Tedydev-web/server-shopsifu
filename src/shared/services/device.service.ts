import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { Prisma, PrismaClient, Device } from '@prisma/client'
import { DeviceSetupFailedException } from 'src/routes/auth/auth.error'
import { AuditLog } from '../decorators/audit-log.decorator'
import { AuditLogService } from 'src/routes/audit-log/audit-log.service'
import { isUniqueConstraintPrismaError, isNotFoundPrismaError } from '../utils/type-guards.utils'
import envConfig from 'src/shared/config'

type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

@Injectable()
export class DeviceService {
  private readonly logger = new Logger(DeviceService.name)

  constructor(
    private readonly prismaService: PrismaService,
    private readonly auditLogService: AuditLogService
  ) {}

  @AuditLog({
    action: 'DEVICE_CREATE',
    entity: 'Device',
    getUserId: (args) => args[0]?.user?.connect?.id,
    getEntityId: (_, result) => result?.id,
    getDetails: (args) => ({ userAgent: args[0]?.userAgent, ip: args[0]?.ip })
  })
  async createDevice(data: Prisma.DeviceCreateInput, tx?: PrismaTransactionClient): Promise<Device> {
    this.logger.debug(`Creating new device for user ${data.user?.connect?.id}`)
    const client = tx || this.prismaService

    return client.device.create({
      data
    })
  }

  async updateDevice(deviceId: number, data: Prisma.DeviceUpdateInput, tx?: PrismaTransactionClient): Promise<Device> {
    this.logger.debug(`Updating device ${deviceId}`)
    const client = tx || this.prismaService

    return client.device.update({
      where: {
        id: deviceId
      },
      data
    })
  }

  async findDeviceById(deviceId: number, tx?: PrismaTransactionClient): Promise<Device | null> {
    this.logger.debug(`Finding device with ID ${deviceId}`)
    const client = tx || this.prismaService

    return client.device.findUnique({
      where: {
        id: deviceId
      }
    })
  }

  async findActiveDeviceByUserAgent(
    userId: number,
    userAgent: string,
    tx?: PrismaTransactionClient
  ): Promise<Device | null> {
    this.logger.debug(`Finding active device for user ${userId} with matching User-Agent`)
    const client = tx || this.prismaService

    return client.device.findFirst({
      where: {
        userId: userId,
        userAgent: userAgent,
        isActive: true
      }
    })
  }

  @AuditLog({
    action: 'DEVICE_FIND_OR_CREATE',
    entity: 'Device',
    getUserId: (args) => args[0]?.userId,
    getEntityId: (_, result) => result?.id,
    getDetails: (args, result) => ({
      userAgent: args[0]?.userAgent,
      ip: args[0]?.ip,
      isNewDevice: result?.createdAt.getTime() === result?.lastActive.getTime()
    }),
    getErrorDetails: (args) => ({
      userAgent: args[0]?.userAgent,
      ip: args[0]?.ip
    })
  })
  async findOrCreateDevice(
    data: { userId: number; userAgent: string; ip: string },
    tx?: PrismaTransactionClient
  ): Promise<Device> {
    try {
      this.logger.debug(`Finding or creating device for user ${data.userId}`)
      const client = tx || this.prismaService

      const existingDevice = await this.findActiveDeviceByUserAgent(data.userId, data.userAgent, client)

      if (existingDevice) {
        this.logger.debug(
          `Found existing device ${existingDevice.id} for user ${data.userId}, updating last active timestamp`
        )
        const updateData: Prisma.DeviceUpdateInput = {
          ip: data.ip,
          lastActive: new Date()
        }

        // Check if absolute session lifetime has been exceeded
        if (existingDevice.sessionCreatedAt && envConfig.ABSOLUTE_SESSION_LIFETIME_MS > 0) {
          const sessionAgeMs = new Date().getTime() - new Date(existingDevice.sessionCreatedAt).getTime()
          if (sessionAgeMs > envConfig.ABSOLUTE_SESSION_LIFETIME_MS) {
            this.logger.warn(
              `Device ${existingDevice.id} for user ${data.userId} exceeded absolute session lifetime. Resetting sessionCreatedAt.`
            )
            updateData.sessionCreatedAt = new Date() // Reset session lifetime
          }
        }

        const updatedDevice = await this.updateDevice(existingDevice.id, updateData, client)

        this.auditLogService.recordAsync({
          action: 'DEVICE_UPDATE',
          entity: 'Device',
          entityId: existingDevice.id,
          userId: data.userId,
          status: 'SUCCESS' as any,
          ipAddress: data.ip,
          userAgent: data.userAgent,
          details: {
            deviceId: existingDevice.id,
            lastActiveTimestamp: new Date().toISOString()
          }
        })

        return updatedDevice
      }

      this.logger.debug(`No matching device found for user ${data.userId}, creating new device`)
      const newDevice = await this.createDevice(
        {
          user: { connect: { id: data.userId } },
          userAgent: data.userAgent,
          ip: data.ip,
          sessionCreatedAt: new Date() // Ensure new devices also get sessionCreatedAt
        },
        client
      )

      this.auditLogService.recordAsync({
        action: 'DEVICE_CREATE',
        entity: 'Device',
        entityId: newDevice.id,
        userId: data.userId,
        status: 'SUCCESS' as any,
        ipAddress: data.ip,
        userAgent: data.userAgent,
        details: {
          deviceId: newDevice.id,
          createdAtTimestamp: newDevice.createdAt.toISOString()
        }
      })

      return newDevice
    } catch (error) {
      this.auditLogService.recordAsync({
        action: 'DEVICE_SETUP_FAILED',
        entity: 'Device',
        userId: data.userId,
        status: 'FAILURE' as any,
        ipAddress: data.ip,
        userAgent: data.userAgent,
        errorMessage: error.message,
        details: {
          errorStack: error.stack?.substring(0, 200),
          errorCode: isUniqueConstraintPrismaError(error)
            ? 'UNIQUE_CONSTRAINT'
            : isNotFoundPrismaError(error)
              ? 'NOT_FOUND'
              : 'UNKNOWN'
        }
      })

      this.logger.error(`Error in findOrCreateDevice for user ${data.userId}: ${error.message}`, error.stack)
      throw DeviceSetupFailedException
    }
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
      this.logger.warn(`Device ${deviceId} not found or inactive`)
      return false
    }

    const isUserAgentMatched = device.userAgent === userAgent

    if (!isUserAgentMatched) {
      this.logger.warn(`Device ${deviceId} User-Agent mismatch: expected "${device.userAgent}", got "${userAgent}"`)
    }

    await this.updateDevice(
      deviceId,
      {
        lastActive: new Date(),
        ip
      },
      client
    )

    return isUserAgentMatched
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
    getUserId: (args) => args[1], // userId is the second argument
    getEntityId: (args) => args[0], // deviceId is the first argument
    getDetails: (args) => ({ deviceId: args[0], userId: args[1] })
  })
  async trustDevice(deviceId: number, userId: number, tx?: PrismaTransactionClient): Promise<Device> {
    this.logger.debug(`Trusting device ${deviceId} for user ${userId}`)
    const client = tx || this.prismaService

    const device = await this.findDeviceById(deviceId, client)
    if (!device) {
      this.logger.warn(`Device ${deviceId} not found when trying to trust.`)
      throw new Error(`Device with ID ${deviceId} not found.`)
    }

    if (device.userId !== userId) {
      this.logger.warn(
        `User ${userId} attempted to trust device ${deviceId} not belonging to them (belongs to user ${device.userId}).`
      )
      throw new Error(`Device does not belong to user.`)
    }

    return this.updateDevice(deviceId, { isTrusted: true }, client)
  }

  isSessionValid(device: Device): boolean {
    if (!device.sessionCreatedAt || envConfig.ABSOLUTE_SESSION_LIFETIME_MS <= 0) {
      // If no session creation time or no absolute lifetime configured, session is considered valid (or handled by other means)
      return true
    }
    const sessionAgeMs = new Date().getTime() - new Date(device.sessionCreatedAt).getTime()
    const isValid = sessionAgeMs <= envConfig.ABSOLUTE_SESSION_LIFETIME_MS
    if (!isValid) {
      this.logger.warn(
        `Device ${device.id} for user ${device.userId} session created at ${device.sessionCreatedAt?.toISOString()} has exceeded absolute lifetime of ${envConfig.ABSOLUTE_SESSION_LIFETIME_MS}ms.`
      )
    }
    return isValid
  }
}
