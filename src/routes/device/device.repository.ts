import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repo'
import { Device } from '@prisma/client'

// Dữ liệu cần thiết để tạo một thiết bị mới, bao gồm tất cả các trường
// được phân tích từ fingerprint service.
export type CreateDeviceData = Pick<
  Device,
  | 'userId'
  | 'ip'
  | 'userAgent'
  | 'name'
  | 'fingerprint'
  | 'browser'
  | 'browserVersion'
  | 'os'
  | 'osVersion'
  | 'deviceType'
  | 'deviceVendor'
  | 'deviceModel'
>

@Injectable()
export class DeviceRepository extends BaseRepository<Device> {
  constructor(prismaService: PrismaService) {
    super(prismaService, 'device')
  }

  protected getSearchableFields(): string[] {
    return ['name', 'os', 'browser', 'ip', 'fingerprint']
  }

  protected getSortableFields(): string[] {
    return ['createdAt', 'lastActive', 'name']
  }

  async findByFingerprint(fingerprint: string, prismaClient?: PrismaTransactionClient): Promise<Device | null> {
    if (!fingerprint) return null
    const client = this.getClient(prismaClient)
    return client.device.findUnique({
      where: { fingerprint }
    })
  }

  async createDevice(data: CreateDeviceData, prismaClient?: PrismaTransactionClient): Promise<Device> {
    const client = this.getClient(prismaClient)
    return client.device.create({
      data
    })
  }

  async updateDeviceActivity(id: number, ip: string, prismaClient?: PrismaTransactionClient): Promise<Device> {
    const client = this.getClient(prismaClient)
    return client.device.update({
      where: { id },
      data: { ip, lastActive: new Date() }
    })
  }
}
