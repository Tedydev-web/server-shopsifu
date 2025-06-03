import { Logger } from '@nestjs/common'
import { PrismaService } from '../services/prisma.service'
import { PaginationOptions, PaginatedResponseType, createPaginatedResponse } from '../models/pagination.model'
import { Prisma } from '@prisma/client'

export type PrismaTransactionClient = Omit<
  Prisma.TransactionClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

export abstract class BaseRepository<T> {
  protected readonly logger: Logger

  constructor(protected readonly prismaService: PrismaService) {}

  protected getClient(prismaClient?: PrismaTransactionClient): PrismaTransactionClient | PrismaService {
    return prismaClient || this.prismaService
  }

  protected async paginateQuery<Entity>(
    model: string,
    query: PaginationOptions,
    where: any = {},
    include: any = {},
    prismaClient?: PrismaTransactionClient
  ): Promise<PaginatedResponseType<Entity>> {
    const client = this.getClient(prismaClient)
    const { page = 1, limit = 10, sortBy, sortOrder = 'asc', search, includeDeleted = false } = query

    const whereClause = { ...where }

    if (!includeDeleted && 'deletedAt' in (client[model] as any)) {
      whereClause.deletedAt = null
    }

    if (search && this.getSearchableFields().length > 0) {
      whereClause.OR = this.getSearchableFields().map((field) => ({
        [field]: { contains: search, mode: 'insensitive' }
      }))
    }

    const totalItems = await client[model].count({ where: whereClause })

    const data = await client[model].findMany({
      where: whereClause,
      ...(include && Object.keys(include).length > 0 && { include }),
      ...(sortBy && { orderBy: { [sortBy]: sortOrder } }),
      skip: (page - 1) * limit,
      take: limit
    })

    return createPaginatedResponse<Entity>(data as Entity[], totalItems, {
      page,
      limit,
      sortBy,
      sortOrder,
      search,
      includeDeleted
    })
  }

  protected getSearchableFields(): string[] {
    return []
  }

  protected async paginateWithCursor<Entity>(
    model: string,
    cursorField: string = 'id',
    cursorValue?: string | number,
    limit: number = 10,
    where: any = {},
    include: any = {},
    sortOrder: 'asc' | 'desc' = 'asc',
    prismaClient?: PrismaTransactionClient
  ): Promise<{
    data: Entity[]
    nextCursor: string | number | null
    hasMore: boolean
  }> {
    const client = this.getClient(prismaClient)

    const cursor = cursorValue ? { [cursorField]: cursorValue } : undefined

    const data = await client[model].findMany({
      where,
      ...(include && Object.keys(include).length > 0 && { include }),
      orderBy: { [cursorField]: sortOrder },
      ...(cursor && { cursor: { [cursorField]: cursor[cursorField] }, skip: 1 }),
      take: limit + 1
    })

    const hasMore = data.length > limit
    const items = hasMore ? data.slice(0, limit) : data

    const nextCursor = hasMore && items.length > 0 ? items[items.length - 1][cursorField] : null

    return {
      data: items as Entity[],
      nextCursor,
      hasMore
    }
  }
}
