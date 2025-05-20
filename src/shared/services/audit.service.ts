import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from './prisma.service'
import { Prisma } from '@prisma/client'
import { normalizeAuditLogDetails, maskSensitiveFields, DEFAULT_SENSITIVE_FIELDS } from '../utils/audit-log.utils'
import { isNullOrUndefined, isObject } from '../utils/type-guards.utils'

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

export interface AuditLogOptions {
  maskSensitiveData?: boolean
  sensitiveFields?: string[]
  skipErrors?: boolean
}

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name)
  private readonly logQueue: AuditLogData[] = []
  private isProcessingQueue = false
  private readonly batchSize = 20 // Số lượng log tối đa được xử lý trong một lần
  private readonly defaultOptions: AuditLogOptions = {
    maskSensitiveData: true,
    sensitiveFields: DEFAULT_SENSITIVE_FIELDS,
    skipErrors: true
  }

  constructor(private readonly prisma: PrismaService) {
    // Khởi tạo quy trình xử lý hàng đợi định kỳ
    setInterval(() => {
      void this.processQueue()
    }, 5000)
  }

  /**
   * Ghi log audit (đồng bộ)
   * @param data Dữ liệu log
   * @param options Tùy chọn ghi log
   * @returns Promise<void>
   */
  async record(data: AuditLogData, options: AuditLogOptions = this.defaultOptions): Promise<void> {
    try {
      const { userId, entityId, details, ...otherAuditData } = this.prepareLogData(data, options)

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
      this.logger.error(`Failed to record audit log: ${error.message}`, error.stack)
      if (!options.skipErrors) {
        throw error
      }
    }
  }

  /**
   * Ghi log audit không chặn luồng chính
   * @param data Dữ liệu log
   * @param options Tùy chọn ghi log
   */
  recordAsync(data: AuditLogData, options: AuditLogOptions = this.defaultOptions): void {
    try {
      this.queueLog(data, options)
    } catch (error) {
      this.logger.error(`Failed to queue audit log: ${error.message}`, error.stack)
    }
  }

  /**
   * Ghi nhiều log audit trong một lần
   * @param dataArray Mảng dữ liệu log
   * @param options Tùy chọn ghi log
   * @returns Promise<void>
   */
  async recordBatch(dataArray: AuditLogData[], options: AuditLogOptions = this.defaultOptions): Promise<void> {
    if (!Array.isArray(dataArray) || dataArray.length === 0) {
      return
    }

    try {
      await this.prisma.$transaction(async (tx) => {
        for (const data of dataArray) {
          const { userId, entityId, details, ...otherAuditData } = this.prepareLogData(data, options)

          const createInputData: Prisma.AuditLogCreateInput = {
            ...otherAuditData,
            entityId: entityId?.toString(),
            details: details === null ? Prisma.DbNull : details
          }

          if (userId) {
            createInputData.user = { connect: { id: userId } }
          }

          await tx.auditLog.create({ data: createInputData })
        }
      })
    } catch (error) {
      this.logger.error(`Failed to record batch audit logs: ${error.message}`, error.stack)
      if (!options.skipErrors) {
        throw error
      }
    }
  }

  /**
   * Ghi log thành công
   * @param action Hành động
   * @param data Dữ liệu bổ sung
   * @param options Tùy chọn ghi log
   */
  success(
    action: string,
    data: Omit<AuditLogData, 'action' | 'status'>,
    options: AuditLogOptions = this.defaultOptions
  ): void {
    this.recordAsync(
      {
        ...data,
        action,
        status: AuditLogStatus.SUCCESS
      },
      options
    )
  }

  /**
   * Ghi log thất bại
   * @param action Hành động
   * @param data Dữ liệu bổ sung
   * @param options Tùy chọn ghi log
   */
  failure(
    action: string,
    data: Omit<AuditLogData, 'action' | 'status'>,
    options: AuditLogOptions = this.defaultOptions
  ): void {
    this.recordAsync(
      {
        ...data,
        action,
        status: AuditLogStatus.FAILURE
      },
      options
    )
  }

  /**
   * Ghi log thành công đồng bộ
   * @param action Hành động
   * @param data Dữ liệu bổ sung
   * @param options Tùy chọn ghi log
   * @returns Promise<void>
   */
  async successSync(
    action: string,
    data: Omit<AuditLogData, 'action' | 'status'>,
    options: AuditLogOptions = this.defaultOptions
  ): Promise<void> {
    await this.record(
      {
        ...data,
        action,
        status: AuditLogStatus.SUCCESS
      },
      options
    )
  }

  /**
   * Ghi log thất bại đồng bộ
   * @param action Hành động
   * @param data Dữ liệu bổ sung
   * @param options Tùy chọn ghi log
   * @returns Promise<void>
   */
  async failureSync(
    action: string,
    data: Omit<AuditLogData, 'action' | 'status'>,
    options: AuditLogOptions = this.defaultOptions
  ): Promise<void> {
    await this.record(
      {
        ...data,
        action,
        status: AuditLogStatus.FAILURE
      },
      options
    )
  }

  /**
   * Thêm log vào hàng đợi
   * @private
   * @param data Dữ liệu log
   * @param options Tùy chọn ghi log
   */
  private queueLog(data: AuditLogData, options: AuditLogOptions): void {
    // Chuẩn bị dữ liệu log
    const preparedData = this.prepareLogData(data, options)

    // Thêm vào hàng đợi
    this.logQueue.push(preparedData)

    // Xử lý hàng đợi nếu đủ lớn
    if (this.logQueue.length >= this.batchSize) {
      void this.processQueue()
    }
  }

  /**
   * Xử lý hàng đợi log
   * @private
   */
  private async processQueue(): Promise<void> {
    if (this.isProcessingQueue || this.logQueue.length === 0) {
      return
    }

    try {
      this.isProcessingQueue = true

      // Lấy một batch từ hàng đợi
      const batchToProcess = this.logQueue.splice(0, this.batchSize)

      if (batchToProcess.length > 0) {
        await this.recordBatch(batchToProcess)
      }
    } catch (error) {
      this.logger.error(`Failed to process audit log queue: ${error.message}`, error.stack)
    } finally {
      this.isProcessingQueue = false

      // Nếu vẫn còn log trong hàng đợi, tiếp tục xử lý
      if (this.logQueue.length > 0) {
        setImmediate(() => {
          void this.processQueue()
        })
      }
    }
  }

  /**
   * Chuẩn bị dữ liệu log trước khi ghi
   * @private
   * @param data Dữ liệu log
   * @param options Tùy chọn ghi log
   * @returns Dữ liệu log đã chuẩn bị
   */
  private prepareLogData(data: AuditLogData, options: AuditLogOptions): AuditLogData {
    const preparedData = { ...data }

    // Xử lý details - che giấu thông tin nhạy cảm nếu cần
    if (isObject(preparedData.details)) {
      if (options.maskSensitiveData) {
        preparedData.details = maskSensitiveFields(preparedData.details, options.sensitiveFields)
      }

      // Chuẩn hóa chi tiết để đảm bảo an toàn khi lưu trữ
      preparedData.details = normalizeAuditLogDetails(preparedData.details as Record<string, any>)
    }

    return preparedData
  }
}
