import { Inject, Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import { GetProductsQueryType } from 'src/routes/product/product.model'
import { NotFoundRecordException } from 'src/shared/error'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { CACHE_MANAGER } from '@nestjs/cache-manager'
import { Cache } from 'cache-manager'
import {
  PRODUCT_LIST_CACHE_PREFIX,
  PRODUCT_LIST_TTL_MS,
  PRODUCT_LIST_VERSION_KEY
} from '../../shared/constants/product.constant'

@Injectable()
export class ProductService {
  constructor(
    private productRepo: ProductRepo,
    private i18n: I18nService<I18nTranslations>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache
  ) {}

  async list(props: { query: GetProductsQueryType }) {
    const lang = (I18nContext.current()?.lang as string) || 'vi'
    const isDefaultHome =
      (props.query.page ?? 1) === 1 &&
      (props.query.limit ?? 10) === 10 &&
      !props.query.name &&
      (!props.query.brandIds || props.query.brandIds.length === 0) &&
      (!props.query.categories || props.query.categories.length === 0) &&
      props.query.minPrice === undefined &&
      props.query.maxPrice === undefined &&
      !props.query.createdById

    // Cache theo version key để dễ invalidation hàng loạt
    const version = (await this.cacheManager.get<number>(PRODUCT_LIST_VERSION_KEY)) || 1
    const rawKey = isDefaultHome
      ? `${PRODUCT_LIST_CACHE_PREFIX}:home:v${version}:lang:${lang}`
      : `${PRODUCT_LIST_CACHE_PREFIX}:q:${JSON.stringify(props.query)}:v${version}:lang:${lang}`

    const cached = await this.cacheManager.get<any>(rawKey)
    if (cached) {
      // Revive Date cho dữ liệu lấy từ Redis (tránh ZodSerializationException)
      if (cached?.data && Array.isArray(cached.data)) {
        cached.data = cached.data.map((p: any) => ({
          ...p,
          createdAt: p.createdAt ? new Date(p.createdAt) : p.createdAt,
          updatedAt: p.updatedAt ? new Date(p.updatedAt) : p.updatedAt,
          productTranslations: Array.isArray(p.productTranslations)
            ? p.productTranslations.map((t: any) => ({
                ...t,
                createdAt: t.createdAt ? new Date(t.createdAt) : t.createdAt,
                updatedAt: t.updatedAt ? new Date(t.updatedAt) : t.updatedAt
              }))
            : p.productTranslations
        }))
      }
      return cached
    }

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
    const response = {
      message: this.i18n.t('product.product.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
    await this.cacheManager.set(rawKey, response, PRODUCT_LIST_TTL_MS)
    return response
  }

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
