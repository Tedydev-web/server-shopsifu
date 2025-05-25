import { Injectable, Inject } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { AuditLogQueryType, AuditLogType } from './audit-log.model'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'
import { AuditLogStatus } from './audit-log.service'
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager'

@Injectable()
export class AuditLogRepository extends BaseRepository<AuditLogType> {
  constructor(
    protected readonly prismaService: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache
  ) {
    super(prismaService, AuditLogRepository.name)
  }

  async findAll(
    query: AuditLogQueryType,
    prismaClient?: PrismaTransactionClient
  ): Promise<PaginatedResponseType<AuditLogType>> {
    const {
      page = 1,
      limit = 10,
      sortBy = 'timestamp',
      sortOrder = 'desc',
      search = '',
      userId,
      action,
      entity,
      startDate,
      endDate,
      status,
      all = false
    } = query || {}

    const where: any = {}

    if (search) {
      where.OR = this.getSearchableFields().map((field) => ({
        [field]: { contains: search, mode: 'insensitive' }
      }))
    }

    if (userId) where.userId = userId
    if (action) where.action = action
    if (entity) where.entity = entity
    if (status) where.status = status

    if (startDate || endDate) {
      where.timestamp = {}
      if (startDate) where.timestamp.gte = new Date(startDate)
      if (endDate) where.timestamp.lte = new Date(endDate)
    }

    const shouldCache = !all && limit <= 100
    const cacheKey = shouldCache
      ? `audit-logs:${page}:${limit}:${sortBy}:${sortOrder}:${search}:${userId || ''}:${action || ''}:${entity || ''}:${startDate || ''}:${endDate || ''}:${status || ''}`
      : null

    const effectiveLimit = all ? 1000 : limit

    if (shouldCache && cacheKey) {
      const cachedData = await this.cacheManager.get<PaginatedResponseType<AuditLogType>>(cacheKey)
      if (cachedData) return cachedData

      const result = await this.paginateQuery<AuditLogType>(
        'auditLog',
        {
          page,
          limit: effectiveLimit,
          sortBy,
          sortOrder,
          search
        },
        where,
        { user: true },
        prismaClient
      )
      await this.cacheManager.set(cacheKey, result, 10000)
      return result
    }

    return this.paginateQuery<AuditLogType>(
      'auditLog',
      {
        page,
        limit: effectiveLimit,
        sortBy,
        sortOrder,
        search
      },
      where,
      { user: true },
      prismaClient
    )
  }

  async findById(id: number, prismaClient?: PrismaTransactionClient): Promise<AuditLogType | null> {
    const client = this.getClient(prismaClient)

    const cacheKey = `audit-log:${id}`

    const cachedLog = await this.cacheManager.get<AuditLogType>(cacheKey)
    if (cachedLog) return cachedLog

    const result = await client.auditLog.findUnique({
      where: { id },
      include: { user: true }
    })

    if (!result) return null

    const auditLog: AuditLogType = {
      id: result.id,
      timestamp: result.timestamp,
      userId: result.userId,
      userEmail: result.userEmail || result.user?.email || null,
      action: result.action,
      entity: result.entity,
      entityId: result.entityId,
      ipAddress: result.ipAddress,
      userAgent: result.userAgent,
      status: result.status as AuditLogStatus,
      errorMessage: result.errorMessage,
      details: result.details,
      notes: result.notes
    }
    await this.cacheManager.set(cacheKey, auditLog, 30000)
    return auditLog
  }

  async getDistinctActions(prismaClient?: PrismaTransactionClient): Promise<string[]> {
    const client = this.getClient(prismaClient)
    const cacheKey = 'audit-logs:actions:distinct'

    const cachedActions = await this.cacheManager.get<string[]>(cacheKey)
    if (cachedActions) return cachedActions

    const result = await client.auditLog.groupBy({
      by: ['action'],
      orderBy: {
        action: 'asc'
      }
    })
    const actions = result.map((item) => item.action)
    await this.cacheManager.set(cacheKey, actions, 300000)
    return actions
  }

  async getDistinctEntities(prismaClient?: PrismaTransactionClient): Promise<string[]> {
    const client = this.getClient(prismaClient)
    const cacheKey = 'audit-logs:entities:distinct'

    const cachedEntities = await this.cacheManager.get<string[]>(cacheKey)
    if (cachedEntities) return cachedEntities

    const result = await client.auditLog.groupBy({
      by: ['entity'],
      where: {
        entity: {
          not: null
        }
      },
      orderBy: {
        entity: 'asc'
      }
    })
    const entities = result.map((item) => item.entity as string).filter(Boolean)
    await this.cacheManager.set(cacheKey, entities, 300000)
    return entities
  }

  protected getSearchableFields(): string[] {
    return ['action', 'entity', 'userEmail', 'notes', 'errorMessage']
  }
}
