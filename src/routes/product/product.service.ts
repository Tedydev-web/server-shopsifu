import { Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import { GetProductsQueryType } from 'src/routes/product/product.model'
import { NotFoundRecordException } from 'src/shared/error'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { RedisService } from 'src/shared/services/redis.service'
import { Cacheable } from 'src/shared/decorators/cacheable.decorator'

@Injectable()
export class ProductService {
  constructor(
    private productRepo: ProductRepo,
    private i18n: I18nService<I18nTranslations>,
    private readonly redisService: RedisService
  ) {}

  @Cacheable({
    key: 'products',
    ttl: 1800,
    ttlJitter: 300,
    staleTtl: 900,
    scope: 'global',
    keyGenerator: (props: { query: GetProductsQueryType }) => {
      const lang = (I18nContext.current()?.lang as string) || 'vi'

      const limit = props.query.limit || 10
      const isHomepage =
        (props.query.page ?? 1) === 1 &&
        (limit === 48 || limit === 10) &&
        !props.query.name &&
        (!props.query.brandIds || props.query.brandIds.length === 0) &&
        (!props.query.categories || props.query.categories.length === 0) &&
        props.query.minPrice === undefined &&
        props.query.maxPrice === undefined &&
        !props.query.createdById

      if (isHomepage) {
        return `homepage:${lang}:${limit}`
      }

      const filters = {
        p: props.query.page || 1,
        l: props.query.limit || 10,
        n: props.query.name || '',
        b: props.query.brandIds?.sort().join(',') || '',
        c: props.query.categories?.sort().join(',') || '',
        min: props.query.minPrice || 0,
        max: props.query.maxPrice || 0,
        by: props.query.orderBy || '',
        sort: props.query.sortBy || '',
        user: props.query.createdById || ''
      }

      return `search:${lang}:${Buffer.from(JSON.stringify(filters)).toString('base64')}`
    }
  })
  async list(props: { query: GetProductsQueryType }) {
    const lang = (I18nContext.current()?.lang as string) || 'vi'

    const data = await this.productRepo.list({
      page: props.query.page,
      limit: props.query.limit,
      languageId: lang,
      isPublic: true,
      brandIds: props.query.brandIds,
      minPrice: props.query.minPrice,
      maxPrice: props.query.maxPrice,
      categories: props.query.categories,
      name: props.query.name,
      createdById: props.query.createdById,
      orderBy: props.query.orderBy,
      sortBy: props.query.sortBy
    })

    return {
      message: this.i18n.t('product.product.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  @Cacheable({
    key: 'product:detail',
    ttl: 3600,
    ttlJitter: 600,
    staleTtl: 1800,
    scope: 'module',
    moduleName: 'ProductModule',
    keyGenerator: (props: { productId: string }) => {
      const lang = 'vi'
      return `${props.productId}:${lang}:public`
    }
  })
  async getDetail(props: { productId: string }) {
    const product = await this.productRepo.getDetail({
      productId: props.productId,
      languageId: I18nContext.current()?.lang as string,
      isPublic: true
    })
    if (!product) {
      throw NotFoundRecordException
    }
    return {
      message: this.i18n.t('product.product.success.GET_DETAIL_SUCCESS'),
      data: product.data
    }
  }
}
