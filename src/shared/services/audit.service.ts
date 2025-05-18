import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { Prisma } from '@prisma/client'

export enum AuditLogStatus {
  SUCCESS = 'SUCCESS',
  FAILURE = 'FAILURE'
}

export interface AuditLogData {
  userId?: number
  userEmail?: string
  action: string // Ví dụ: USER_LOGIN, PRODUCT_CREATED
  entity?: string // Ví dụ: User, Product
  entityId?: string | number
  details?: Prisma.JsonValue // Prisma.JsonValue cho phép object, array, string, number, boolean, null
  ipAddress?: string
  userAgent?: string
  status: AuditLogStatus
  errorMessage?: string
  notes?: string
}

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name)

  constructor(private readonly prisma: PrismaService) {}

  async record(data: AuditLogData): Promise<void> {
    try {
      const { userId, entityId, details, ...otherAuditData } = data

      const createInputData: Prisma.AuditLogCreateInput = {
        ...otherAuditData,
        entityId: entityId?.toString(),
        details: details === null ? Prisma.DbNull : details
      }

      if (userId) {
        createInputData.user = { connect: { id: userId } }
      }

      await this.prisma.auditLog.create({ data: createInputData })
    } catch (error) {
      this.logger.error('Failed to record audit log:', error)
      // Trong môi trường production, bạn có thể muốn không ném lỗi này ra ngoài
      // để không ảnh hưởng đến luồng chính của người dùng.
      // throw error; // Bỏ comment nếu muốn ném lỗi
    }
  }
}
