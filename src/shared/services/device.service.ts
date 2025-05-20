import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { Prisma, PrismaClient, Device } from '@prisma/client'
import { DeviceType } from 'src/routes/auth/auth.model'
import { DeviceSetupFailedException } from 'src/routes/auth/auth.error'
import { AuditLog } from '../decorators/audit-log.decorator'
import { AuditLogService } from './audit.service'
import { isUniqueConstraintPrismaError, isNotFoundPrismaError } from '../utils/type-guards.utils'

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

  /**
   * Tạo thiết bị mới
   * @param data Thông tin thiết bị cần tạo
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Thiết bị đã được tạo
   */
  @AuditLog({
    action: 'DEVICE_CREATE',
    entity: 'Device',
    getUserId: (args) => args[0]?.userId,
    getEntityId: (_, result) => result?.id,
    getDetails: (args) => ({ userAgent: args[0]?.userAgent, ip: args[0]?.ip })
  })
  async createDevice(
    data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'> & Partial<Pick<DeviceType, 'lastActive' | 'isActive'>>,
    tx?: PrismaTransactionClient
  ): Promise<Device> {
    this.logger.debug(`Creating new device for user ${data.userId}`)
    const client = tx || this.prismaService

    return client.device.create({
      data
    })
  }

  /**
   * Cập nhật thông tin thiết bị
   * @param deviceId ID thiết bị
   * @param data Thông tin cần cập nhật
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Thiết bị sau khi cập nhật
   */
  async updateDevice(deviceId: number, data: Partial<DeviceType>, tx?: PrismaTransactionClient): Promise<Device> {
    this.logger.debug(`Updating device ${deviceId}`)
    const client = tx || this.prismaService

    return client.device.update({
      where: {
        id: deviceId
      },
      data
    })
  }

  /**
   * Tìm thiết bị dựa trên ID
   * @param deviceId ID thiết bị
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Thiết bị nếu tìm thấy, null nếu không
   */
  async findDeviceById(deviceId: number, tx?: PrismaTransactionClient): Promise<Device | null> {
    this.logger.debug(`Finding device with ID ${deviceId}`)
    const client = tx || this.prismaService

    return client.device.findUnique({
      where: {
        id: deviceId
      }
    })
  }

  /**
   * Tìm thiết bị hoạt động cho người dùng với userAgent cụ thể
   * @param userId ID người dùng
   * @param userAgent User-Agent của thiết bị
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Thiết bị nếu tìm thấy, null nếu không
   */
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

  /**
   * Tìm hoặc tạo thiết bị mới
   * @param data Thông tin thiết bị
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Thiết bị (đã tìm thấy hoặc mới tạo)
   * @throws DeviceSetupFailedException nếu có lỗi trong quá trình thiết lập
   */
  @AuditLog({
    action: 'DEVICE_FIND_OR_CREATE',
    entity: 'Device',
    getUserId: (args) => args[0]?.userId,
    getEntityId: (_, result) => result?.id,
    getDetails: (args, result) => ({
      userAgent: args[0]?.userAgent,
      ip: args[0]?.ip,
      isNewDevice: result?.createdAt === result?.lastActive
    }),
    getErrorDetails: (args) => ({
      userAgent: args[0]?.userAgent,
      ip: args[0]?.ip
    })
  })
  async findOrCreateDevice(
    data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'>,
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
        const updatedDevice = await this.updateDevice(
          existingDevice.id,
          {
            ip: data.ip,
            lastActive: new Date()
          },
          client
        )

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
      const newDevice = await this.createDevice(data, client)

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

  /**
   * Xác thực thiết bị dựa trên User-Agent và IP
   * @param deviceId ID thiết bị
   * @param userAgent User-Agent hiện tại
   * @param ip Địa chỉ IP hiện tại
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns true nếu thiết bị hợp lệ, false nếu không
   */
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

  /**
   * Vô hiệu hóa thiết bị
   * @param deviceId ID thiết bị
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Thiết bị đã bị vô hiệu hóa
   */
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

  /**
   * Vô hiệu hóa tất cả thiết bị của người dùng
   * @param userId ID người dùng
   * @param excludeDeviceId ID thiết bị muốn loại trừ (tùy chọn)
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Số lượng thiết bị đã vô hiệu hóa
   */
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

  /**
   * Lấy danh sách thiết bị hoạt động của người dùng
   * @param userId ID người dùng
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns Danh sách thiết bị hoạt động
   */
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

  /**
   * Kiểm tra xem thiết bị có thuộc về người dùng không
   * @param deviceId ID thiết bị
   * @param userId ID người dùng
   * @param tx Client transaction Prisma (tùy chọn)
   * @returns true nếu thiết bị thuộc về người dùng, false nếu không
   */
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
}
