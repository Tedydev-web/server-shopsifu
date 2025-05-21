import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { CacheService } from 'src/shared/services/cache.service'
import { AuditLogQueryType, AuditLogType } from './audit-log.model'
import { PaginatedResponseType } from 'src/shared/models/pagination.model'
import { AuditLogStatus } from './audit-log.service'

@Injectable()
export class AuditLogRepository extends BaseRepository<AuditLogType> {
  constructor(
    protected readonly prismaService: PrismaService,
    private readonly cacheService: CacheService
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
      return this.cacheService.getOrSet(
        cacheKey,
        () =>
          this.paginateQuery(
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
          ),
        10000
      )
    }

    return this.paginateQuery(
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

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
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

        return auditLog
      },
      30000
    )
  }

  async getDistinctActions(prismaClient?: PrismaTransactionClient): Promise<string[]> {
    const client = this.getClient(prismaClient)

    const cacheKey = 'audit-logs:actions:distinct'

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        const result = await client.auditLog.groupBy({
          by: ['action'],
          orderBy: {
            action: 'asc'
          }
        })
        return result.map((item) => item.action)
      },
      300000
    )
  }

  async getDistinctEntities(prismaClient?: PrismaTransactionClient): Promise<string[]> {
    const client = this.getClient(prismaClient)

    const cacheKey = 'audit-logs:entities:distinct'

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
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
        return result.map((item) => item.entity as string).filter(Boolean)
      },
      300000
    )
  }

  protected getSearchableFields(): string[] {
    return ['action', 'entity', 'userEmail', 'notes', 'errorMessage']
  }
}
