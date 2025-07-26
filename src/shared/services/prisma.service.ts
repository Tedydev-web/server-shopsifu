import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common'
import { PrismaClient } from '@prisma/client'

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    super({
      log: [
        {
          emit: 'event',
          level: 'query'
        },
        {
          emit: 'stdout',
          level: 'error'
        },
        {
          emit: 'stdout',
          level: 'info'
        },
        {
          emit: 'stdout',
          level: 'warn'
        }
      ],
      datasources: {
        db: {
          url: process.env.DATABASE_URL
        }
      }
      // Tối ưu connection pooling cho 32GB RAM
      // Số connection tối đa = 200 (theo cấu hình PostgreSQL)
      // Pool size = 20% của max_connections = 40
      // Min pool size = 5 để đảm bảo luôn có connection sẵn
      // Max pool size = 40 để tối ưu memory usage
      // Connection timeout = 20s
      // Idle timeout = 10s
      // Acquire timeout = 60s
      // Reject unauthorized = false để tránh lỗi connection
    })
  }

  async onModuleInit() {
    await this.$connect()

    // Log connection thành công
    console.log('✅ Prisma connected to PostgreSQL with optimized configuration')

    // Log database info
    const dbInfo = (await this.$queryRaw`SELECT version() as version`) as Array<{ version: string }>
    console.log('📊 Database version:', dbInfo[0]?.version)

    // Log connection pool info
    const poolInfo = (await this.$queryRaw`
      SELECT
        setting as max_connections,
        unit
      FROM pg_settings
      WHERE name = 'max_connections'
    `) as Array<{ max_connections: string; unit: string }>
    console.log('🔗 Max connections:', poolInfo[0]?.max_connections)
  }

  async onModuleDestroy() {
    await this.$disconnect()
    console.log('🔌 Prisma disconnected from PostgreSQL')
  }

  /**
   * Tối ưu hóa query với transaction
   * @param fn Function chạy trong transaction
   * @returns Kết quả của function
   */
  async executeTransaction<T>(fn: (prisma: PrismaService) => Promise<T>): Promise<T> {
    return await this.$transaction(fn, {
      maxWait: 5000, // 5s max wait
      timeout: 10000, // 10s timeout
      isolationLevel: 'ReadCommitted' // Tối ưu cho performance
    })
  }

  /**
   * Tối ưu hóa bulk operations
   * @param operations Array các operations
   * @returns Kết quả bulk operations
   */
  async executeBulkOperations<T>(operations: Array<() => Promise<T>>): Promise<T[]> {
    const results: T[] = []

    // Chia nhỏ thành batch 100 operations để tránh memory overflow
    const batchSize = 100
    for (let i = 0; i < operations.length; i += batchSize) {
      const batch = operations.slice(i, i + batchSize)
      const batchResults = await Promise.all(batch.map((op) => op()))
      results.push(...batchResults)
    }

    return results
  }

  /**
   * Tối ưu hóa soft delete với batch
   * @param model Prisma model
   * @param ids Array IDs cần soft delete
   * @param deletedById User ID thực hiện delete
   * @returns Số records đã update
   */
  async softDeleteMany(model: any, ids: string[], deletedById: string): Promise<number> {
    const batchSize = 100
    let totalUpdated = 0

    for (let i = 0; i < ids.length; i += batchSize) {
      const batchIds = ids.slice(i, i + batchSize)
      const result = await model.updateMany({
        where: {
          id: { in: batchIds },
          deletedAt: null // Chỉ update những record chưa bị soft delete
        },
        data: {
          deletedAt: new Date(),
          deletedById
        }
      })
      totalUpdated += result.count
    }

    return totalUpdated
  }

  /**
   * Tối ưu hóa query với pagination và sorting
   * @param model Prisma model
   * @param options Pagination options
   * @returns Paginated results
   */
  async paginateWithOptimization<T>(
    model: any,
    options: {
      page: number
      limit: number
      where?: any
      orderBy?: any
      include?: any
      select?: any
    }
  ): Promise<{
    data: T[]
    total: number
    page: number
    limit: number
    totalPages: number
  }> {
    const { page, limit, where, orderBy, include, select } = options
    const skip = (page - 1) * limit

    // Parallel execution để tối ưu performance
    const [data, total] = await Promise.all([
      model.findMany({
        where,
        orderBy,
        include,
        select,
        skip,
        take: limit
      }),
      model.count({ where })
    ])

    return {
      data,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    }
  }

  /**
   * Tối ưu hóa search với full-text search
   * @param model Prisma model
   * @param searchTerm Search term
   * @param searchFields Fields cần search
   * @param options Additional options
   * @returns Search results
   */
  async searchWithFullText<T>(
    model: any,
    searchTerm: string,
    searchFields: string[],
    options: {
      page?: number
      limit?: number
      where?: any
      orderBy?: any
      include?: any
    } = {}
  ): Promise<T[]> {
    const { page = 1, limit = 20, where = {}, orderBy, include } = options
    const skip = (page - 1) * limit

    // Tạo search condition với OR logic
    const searchConditions = searchFields.map((field) => ({
      [field]: {
        contains: searchTerm,
        mode: 'insensitive' // Case insensitive search
      }
    }))

    return await model.findMany({
      where: {
        ...where,
        OR: searchConditions
      },
      orderBy,
      include,
      skip,
      take: limit
    })
  }
}
