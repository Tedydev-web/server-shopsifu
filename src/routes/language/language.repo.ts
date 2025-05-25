import { Injectable, Inject } from '@nestjs/common'
import {
  CreateLanguageBodyType,
  LanguageType,
  UpdateLanguageBodyType,
  GetLanguagesQueryType
} from 'src/routes/language/language.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { CACHE_MANAGER, Cache } from '@nestjs/cache-manager'

@Injectable()
export class LanguageRepo extends BaseRepository<LanguageType> {
  constructor(
    protected readonly prismaService: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache
  ) {
    super(prismaService, LanguageRepo.name)
  }

  private async invalidateLanguageItemCache(id: string) {
    await this.cacheManager.del(`language:${id}`)
    await this.cacheManager.del(`language:${id}:includeDeleted`)
    // Note: Invalidating list caches (e.g., languages:list:*) is more complex
    // as cacheManager.del does not support patterns directly.
    // For now, list caches will expire based on their TTL.
    // A more advanced strategy would involve SCAN + DEL if using Redis directly,
    // or versioning cache keys for lists.
  }

  private async invalidateAllLanguageListsCache() {
    // This is a placeholder. In a real scenario with Redis,
    // you might use SCAN and DEL to remove keys matching a pattern like 'languages:list:*'.
    // For now, we accept that list caches will expire based on TTL or be stale until then.
    this.logger.warn('invalidateAllLanguageListsCache called - specific list invalidation is preferred.')
    // Example: If we knew all possible pagination/filter keys, we could delete them.
    // Or, use a versioned key for lists that changes on any CUD operation.
  }

  async findAll(
    query?: GetLanguagesQueryType,
    prismaClient?: PrismaTransactionClient
  ): Promise<{ languages: LanguageType[]; totalItems: number }> {
    const { page = 1, limit = 10, sortBy = 'id', sortOrder = 'asc', search = '', includeDeleted = false } = query || {}

    const where: Prisma.LanguageWhereInput = {}
    if (search) {
      where.OR = [
        { id: { contains: search, mode: 'insensitive' } },
        { name: { contains: search, mode: 'insensitive' } }
      ]
    }
    if (!includeDeleted) {
      where.deletedAt = null
    }

    const cacheKey = `languages:list:${page}:${limit}:${sortBy}:${sortOrder}:${search}:${includeDeleted}`
    const cachedLanguages = await this.cacheManager.get<{ languages: LanguageType[]; totalItems: number }>(cacheKey)
    if (cachedLanguages) return cachedLanguages

    const client = this.getClient(prismaClient)

    const languagesPromise = client.language.findMany({
      where,
      skip: (page - 1) * limit,
      take: limit,
      orderBy: { [sortBy]: sortOrder }
    })
    const totalItemsPromise = client.language.count({ where })

    const [languages, totalItems] = await Promise.all([languagesPromise, totalItemsPromise])

    await this.cacheManager.set(cacheKey, { languages, totalItems }, 60000)
    return { languages, totalItems }
  }

  async findById(
    id: string,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<LanguageType | null> {
    const client = this.getClient(prismaClient)
    const cacheKey = `language:${id}${includeDeleted ? ':includeDeleted' : ''}`
    const cachedLanguage = await this.cacheManager.get<LanguageType | null>(cacheKey)
    if (cachedLanguage !== undefined) return cachedLanguage

    const language = await client.language.findUnique({
      where: { id, ...(includeDeleted ? {} : { deletedAt: null }) }
    })
    await this.cacheManager.set(cacheKey, language, 300000)
    return language
  }

  async create(
    { createdById, data }: { createdById: number; data: CreateLanguageBodyType },
    prismaClient?: PrismaTransactionClient
  ): Promise<LanguageType> {
    const client = this.getClient(prismaClient)
    const result = await client.language.create({
      data: {
        ...data,
        createdById
      }
    })
    await this.invalidateAllLanguageListsCache()
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
    const result = await client.language.update({
      where: { id },
      data: {
        ...data,
        updatedById,
        updatedAt: new Date()
      }
    })
    await this.invalidateLanguageItemCache(id)
    await this.invalidateAllLanguageListsCache()
    return result
  }

  async softDelete(id: string, deletedById: number, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)
    const result = await client.language.update({
      where: { id },
      data: {
        deletedAt: new Date(),
        deletedById
      }
    })
    await this.invalidateLanguageItemCache(id)
    await this.invalidateAllLanguageListsCache()
    return result
  }

  async hardDelete(id: string, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)
    const result = await client.language.delete({ where: { id } })
    await this.invalidateLanguageItemCache(id)
    await this.invalidateAllLanguageListsCache()
    return result
  }

  async restore(id: string, updatedById: number, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)
    const result = await client.language.update({
      where: { id },
      data: {
        deletedAt: null,
        deletedById: null,
        updatedById,
        updatedAt: new Date()
      }
    })
    await this.invalidateLanguageItemCache(id)
    await this.invalidateAllLanguageListsCache()
    return result
  }

  async countReferences(id: string, prismaClient?: PrismaTransactionClient): Promise<number> {
    const client = this.getClient(prismaClient)
    const cacheKey = `language:${id}:references`

    const cachedValue = await this.cacheManager.get<number>(cacheKey)
    if (cachedValue !== undefined && cachedValue !== null) {
      return cachedValue
    }

    const freshValue = await (async () => {
      const [productCount, categoryCount, brandCount] = await Promise.all([
        client.productTranslation.count({ where: { languageId: id } }),
        client.categoryTranslation.count({ where: { languageId: id } }),
        client.brandTranslation.count({ where: { languageId: id } })
      ])
      return productCount + categoryCount + brandCount
    })()

    await this.cacheManager.set(cacheKey, freshValue, 60000) // TTL from original getOrSet
    return freshValue
  }

  protected getSearchableFields(): string[] {
    return ['id', 'name']
  }
}
