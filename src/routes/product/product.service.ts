import { Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import { GetProductsQueryType } from 'src/routes/product/product.model'
import { NotFoundRecordException } from 'src/shared/error'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class ProductService {
  constructor(
    private productRepo: ProductRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async list(props: { query: GetProductsQueryType }) {
    const data = await this.productRepo.list({
      page: props.query.page,
      limit: props.query.limit,
      languageId: I18nContext.current()?.lang as string,
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
      data: data.data
    }
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
      data: product
    }
  }
}
