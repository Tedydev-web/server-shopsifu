import { Injectable } from '@nestjs/common'
import { BrandRepo } from 'src/routes/brand/brand.repo'
import { CreateBrandBodyType, UpdateBrandBodyType } from 'src/routes/brand/brand.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { PaginationQueryType } from 'src/shared/models/request.model'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { Cacheable, CacheEvict } from 'src/shared/decorators/cacheable.decorator'
import { RedisService } from 'src/shared/services/redis.service'

@Injectable()
export class BrandService {
  constructor(
    private brandRepo: BrandRepo,
    private i18n: I18nService<I18nTranslations>,
    private readonly redisService: RedisService
  ) {}

  /**
   * 🎯 Cache brand list với dynamic key theo pagination và language
   */
  @Cacheable({
    key: 'brand:list',
    ttl: 1800, // 30 minutes
    scope: 'module',
    moduleName: 'BrandModule',
    keyGenerator: (pagination: PaginationQueryType) => {
      const lang = I18nContext.current()?.lang || 'vi'
      return `${lang}:page:${pagination.page}:limit:${pagination.limit}`
    }
  })
  async list(pagination: PaginationQueryType) {
    const data = await this.brandRepo.list(pagination, I18nContext.current()?.lang as string)
    return {
      message: this.i18n.t('brand.brand.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  /**
   * 🎯 Cache brand detail theo ID và language
   */
  @Cacheable({
    key: 'brand:detail',
    ttl: 3600, // 1 hour
    scope: 'module',
    moduleName: 'BrandModule',
    keyGenerator: (id: string) => {
      const lang = I18nContext.current()?.lang || 'vi'
      return `${id}:${lang}`
    }
  })
  async findById(id: string) {
    const brand = await this.brandRepo.findById(id, I18nContext.current()?.lang as string)
    if (!brand) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('brand.brand.success.GET_DETAIL_SUCCESS'),
      data: brand
    }
  }

  /**
   * ♻️ Invalidate brand cache khi tạo brand mới
   */
  @CacheEvict(['BrandModule:brand:list:*', 'BrandModule:brand:detail:*'])
  async create({ data, user }: { data: CreateBrandBodyType; user: AccessTokenPayload }) {
    const brand = await this.brandRepo.create({
      createdById: user.userId,
      data
    })
    return {
      message: this.i18n.t('brand.brand.success.CREATE_SUCCESS'),
      data: brand
    }
  }

  /**
   * ♻️ Invalidate brand cache khi update brand
   */
  @CacheEvict(['BrandModule:brand:list:*', 'BrandModule:brand:detail:*'])
  async update({ id, data, user }: { id: string; data: UpdateBrandBodyType; user: AccessTokenPayload }) {
    try {
      const brand = await this.brandRepo.update({
        id,
        updatedById: user.userId,
        data
      })
      return {
        message: this.i18n.t('brand.brand.success.UPDATE_SUCCESS'),
        data: brand
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  /**
   * ♻️ Invalidate brand cache khi delete brand
   */
  @CacheEvict(['BrandModule:brand:list:*', 'BrandModule:brand:detail:*'])
  async delete({ id, user }: { id: string; user: AccessTokenPayload }) {
    try {
      await this.brandRepo.delete({
        id,
        deletedById: user.userId
      })
      return {
        message: this.i18n.t('brand.brand.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
