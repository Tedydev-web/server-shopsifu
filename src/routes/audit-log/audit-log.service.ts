import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { AuditLogRepository } from './audit-log.repo'
import { AuditLogQueryType, AuditLogType } from './audit-log.model'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'
import { Prisma } from '@prisma/client'
import {
  normalizeAuditLogDetails,
  maskSensitiveFields,
  DEFAULT_SENSITIVE_FIELDS
} from 'src/shared/utils/audit-log.utils'
import { isObject } from 'src/shared/utils/type-guards.utils'
import { GeolocationService } from 'src/shared/services/geolocation.service'

export enum AuditLogStatus {
  SUCCESS = 'SUCCESS',
  FAILURE = 'FAILURE'
}

export interface AuditLogData {
  userId?: number
  userEmail?: string
  action: string
  entity?: string
  entityId?: string | number
  details?: Prisma.JsonValue
  ipAddress?: string
  userAgent?: string
  status: AuditLogStatus
  errorMessage?: string
  notes?: string
  geoLocation?: Prisma.JsonValue
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
  private readonly batchSize = 20
  private readonly defaultOptions: AuditLogOptions = {
    maskSensitiveData: true,
    sensitiveFields: DEFAULT_SENSITIVE_FIELDS,
    skipErrors: true
  }

  constructor(
    private readonly auditLogRepository: AuditLogRepository,
    private readonly prismaService: PrismaService,
    private readonly geolocationService: GeolocationService
  ) {
    setInterval(() => {
      void this.processQueue()
    }, 5000)
  }

  async findAll(query: AuditLogQueryType): Promise<PaginatedResponseType<AuditLogType>> {
    // Recording will be handled by @AuditLog decorator in controller
    return this.auditLogRepository.findAll(query)
  }

  async findById(id: number): Promise<AuditLogType | null> {
    const log = await this.auditLogRepository.findById(id)
    // Recording will be handled by @AuditLog decorator in controller
    return log
  }

  async getDistinctActions(): Promise<string[]> {
    return this.auditLogRepository.getDistinctActions()
  }

  async getDistinctEntities(): Promise<string[]> {
    return this.auditLogRepository.getDistinctEntities()
  }

  async getStats() {
    const [totalLogs, totalSuccessLogs, totalFailureLogs, totalEntities] = await Promise.all([
      this.prismaService.auditLog.count(),
      this.prismaService.auditLog.count({ where: { status: AuditLogStatus.SUCCESS } }),
      this.prismaService.auditLog.count({ where: { status: AuditLogStatus.FAILURE } }),
      this.prismaService.auditLog
        .groupBy({
          by: ['entity'],
          _count: true
        })
        .then((results) => results.length)
    ])

    return {
      totalLogs,
      totalSuccessLogs,
      totalFailureLogs,
      totalEntities
    }
  }

  async record(data: AuditLogData, options: AuditLogOptions = this.defaultOptions): Promise<void> {
    try {
      const { userId, entityId, details, geoLocation, ...otherAuditData } = this.prepareLogData(data, options)

      const createInputData: Prisma.AuditLogCreateInput = {
        ...otherAuditData,
        entityId: entityId?.toString(),
        details: details === null ? Prisma.DbNull : details,
        geoLocation: geoLocation === null ? Prisma.DbNull : geoLocation === undefined ? undefined : geoLocation
      }

      if (userId) {
        createInputData.user = { connect: { id: userId } }
      }

      await this.prismaService.auditLog.create({ data: createInputData })
      // Invalidate caches after successful recording
      await this.auditLogRepository.invalidateAllAuditLogListsCache()
      await this.auditLogRepository.invalidateAuditLogDistinctCache()
    } catch (error) {
      this.logger.error(`Failed to record audit log: ${error.message}`, error.stack)
      if (!options.skipErrors) {
        throw error
      }
    }
  }

  recordAsync(data: AuditLogData, options: AuditLogOptions = this.defaultOptions): void {
    try {
      this.queueLog(data, options)
    } catch (error) {
      this.logger.error(`Failed to queue audit log: ${error.message}`, error.stack)
    }
  }

  async recordBatch(dataArray: AuditLogData[], options: AuditLogOptions = this.defaultOptions): Promise<void> {
    if (!Array.isArray(dataArray) || dataArray.length === 0) {
      return
    }

    try {
      await this.prismaService.$transaction(async (tx) => {
        for (const data of dataArray) {
          const { userId, entityId, details, geoLocation, ...otherAuditData } = this.prepareLogData(data, options)

          const createInputData: Prisma.AuditLogCreateInput = {
            ...otherAuditData,
            entityId: entityId?.toString(),
            details: details === null ? Prisma.DbNull : details,
            geoLocation: geoLocation === null ? Prisma.DbNull : geoLocation === undefined ? undefined : geoLocation
          }

          if (userId) {
            createInputData.user = { connect: { id: userId } }
          }

          await tx.auditLog.create({ data: createInputData })
        }
      })
      // Invalidate caches after batch success
      await this.auditLogRepository.invalidateAllAuditLogListsCache()
      await this.auditLogRepository.invalidateAuditLogDistinctCache()
    } catch (error) {
      this.logger.error(`Failed to record batch audit logs: ${error.message}`, error.stack)
      if (!options.skipErrors) {
        throw error
      }
    }
  }

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

  private queueLog(data: AuditLogData, options: AuditLogOptions): void {
    const preparedData = this.prepareLogData(data, options)

    this.logQueue.push(preparedData)

    if (this.logQueue.length >= this.batchSize) {
      void this.processQueue()
    }
  }

  private async processQueue(): Promise<void> {
    if (this.isProcessingQueue || this.logQueue.length === 0) {
      return
    }

    try {
      this.isProcessingQueue = true

      const batchToProcess = this.logQueue.splice(0, this.batchSize)

      if (batchToProcess.length > 0) {
        await this.recordBatch(batchToProcess)
        // Invalidate caches after batch success
        await this.auditLogRepository.invalidateAllAuditLogListsCache()
        await this.auditLogRepository.invalidateAuditLogDistinctCache()
        this.logger.debug(`Processed and invalidated cache for ${batchToProcess.length} audit logs.`)
      }
    } catch (error) {
      this.logger.error(`Failed to process audit log queue: ${error.message}`, error.stack)
    } finally {
      this.isProcessingQueue = false

      if (this.logQueue.length > 0) {
        setImmediate(() => {
          void this.processQueue()
        })
      }
    }
  }

  private prepareLogData(data: AuditLogData, options: AuditLogOptions): AuditLogData {
    const preparedData = { ...data }

    if (isObject(preparedData.details)) {
      if (options.maskSensitiveData) {
        preparedData.details = maskSensitiveFields(preparedData.details, options.sensitiveFields)
      }

      preparedData.details = normalizeAuditLogDetails(preparedData.details as Record<string, any>)
    }

    if (preparedData.ipAddress) {
      try {
        const geoLocationResult = this.geolocationService.lookup(preparedData.ipAddress)
        if (geoLocationResult) {
          // Assign directly, Prisma will handle the JsonValue type.
          preparedData.geoLocation = geoLocationResult as unknown as Prisma.JsonValue
        } else {
          // If lookup returns null (e.g., IP not found, no error), set geoLocation to null in preparedData.
          // This will be converted to Prisma.DbNull later if needed.
          preparedData.geoLocation = null
        }
      } catch (geoError) {
        this.logger.warn(`Failed to lookup geolocation for IP ${preparedData.ipAddress}: ${geoError.message}`)
        preparedData.geoLocation = { error: 'Geolocation lookup failed' } as unknown as Prisma.JsonValue
      }
    } else {
      preparedData.geoLocation = undefined // No IP, so no geo data.
    }

    return preparedData
  }
}
