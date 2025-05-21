import { Injectable } from '@nestjs/common'
import {
  CreateLanguageBodyType,
  LanguageType,
  UpdateLanguageBodyType,
  GetLanguagesQueryType
} from 'src/routes/language/language.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { CacheService } from 'src/shared/services/cache.service'

@Injectable()
export class LanguageRepo extends BaseRepository<LanguageType> {
  constructor(
    protected readonly prismaService: PrismaService,
    private readonly cacheService: CacheService
  ) {
    super(prismaService, LanguageRepo.name)
  }

  async findAll(
    query?: GetLanguagesQueryType,
    prismaClient?: PrismaTransactionClient
  ): Promise<{ languages: LanguageType[]; totalItems: number }> {
    const {
      page = 1,
      limit = 10,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      search = '',
      includeDeleted = false,
      startDate,
      endDate,
      all = false
    } = query || {}

    const where: any = {}

    if (search) {
      where.OR = this.getSearchableFields().map((field) => ({
        [field]: { contains: search, mode: 'insensitive' }
      }))
    }

    if (!includeDeleted) {
      where.deletedAt = null
    }

    if (startDate || endDate) {
      where.createdAt = {}
      if (startDate) where.createdAt.gte = new Date(startDate)
      if (endDate) where.createdAt.lte = new Date(endDate)
    }

    const shouldCache = !all && limit <= 100
    const cacheKey = shouldCache
      ? `languages:list:${page}:${limit}:${sortBy}:${sortOrder}:${search}:${includeDeleted}:${startDate || ''}:${endDate || ''}:${all}`
      : null

    const effectiveLimit = all ? 1000 : limit

    if (shouldCache && cacheKey) {
      return this.cacheService.getOrSet(
        cacheKey,
        async () => {
          const result = await this.paginateQuery<LanguageType>(
            'language',
            {
              page,
              limit: effectiveLimit,
              sortBy,
              sortOrder,
              search
            },
            where,
            {},
            prismaClient
          )

          return {
            languages: result.data,
            totalItems: result.totalItems
          }
        },
        30000
      )
    }

    const result = await this.paginateQuery<LanguageType>(
      'language',
      {
        page,
        limit: effectiveLimit,
        sortBy,
        sortOrder,
        search
      },
      where,
      {},
      prismaClient
    )

    return {
      languages: result.data,
      totalItems: result.totalItems
    }
  }

  async findById(
    id: string,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<LanguageType | null> {
    const client = this.getClient(prismaClient)

    const cacheKey = `language:${id}:${includeDeleted}`

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        const where: Prisma.LanguageWhereUniqueInput = { id }
        if (!includeDeleted) {
          where.deletedAt = null
        }
        return client.language.findUnique({ where })
      },
      30000
    )
  }

  async create(
    { createdById, data }: { createdById: number; data: CreateLanguageBodyType },
    prismaClient?: PrismaTransactionClient
  ): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Creating language: ${JSON.stringify(data)}`)

    const result = await client.language.create({
      data: {
        ...data,
        createdById
      }
    })

    this.cacheService.invalidate('languages:list')

    return result
  }

  async update(
    {
      id,
      updatedById,
      data
    }: {
      id: string
      updatedById: number
      data: UpdateLanguageBodyType
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Updating language ${id}: ${JSON.stringify(data)}`)

    const result = await client.language.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        ...data,
        updatedById
      }
    })

    this.cacheService.invalidate(`language:${id}`)
    this.cacheService.invalidate('languages:list')

    return result
  }

  async softDelete(id: string, deletedById: number, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Soft deleting language: ${id}`)

    const result = await client.language.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        deletedAt: new Date(),
        updatedById: deletedById
      }
    })

    this.cacheService.invalidate(`language:${id}`)
    this.cacheService.invalidate('languages:list')

    return result
  }

  async hardDelete(id: string, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Hard deleting language: ${id}`)

    const result = await client.language.delete({
      where: { id }
    })

    this.cacheService.invalidate(`language:${id}`)
    this.cacheService.invalidate('languages:list')

    return result
  }

  async restore(id: string, updatedById: number, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Restoring language: ${id}`)

    const result = await client.language.update({
      where: {
        id,
        NOT: {
          deletedAt: null
        }
      },
      data: {
        deletedAt: null,
        updatedById
      }
    })

    this.cacheService.invalidate(`language:${id}`)
    this.cacheService.invalidate('languages:list')

    return result
  }

  async countReferences(id: string, prismaClient?: PrismaTransactionClient): Promise<number> {
    const client = this.getClient(prismaClient)

    const cacheKey = `language:${id}:references`

    return this.cacheService.getOrSet(
      cacheKey,
      async () => {
        const [productCount, categoryCount, brandCount] = await Promise.all([
          client.productTranslation.count({ where: { languageId: id } }),
          client.categoryTranslation.count({ where: { languageId: id } }),
          client.brandTranslation.count({ where: { languageId: id } })
        ])
        return productCount + categoryCount + brandCount
      },
      60000
    )
  }

  protected getSearchableFields(): string[] {
    return ['id', 'name']
  }
}
