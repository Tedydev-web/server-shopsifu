import { Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import { GetProductsQueryType } from 'src/routes/product/product.model'
import { NotFoundRecordException } from 'src/shared/error'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'

@Injectable()
export class ProductService {
  constructor(
    private productRepo: ProductRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async list(props: { query: GetProductsQueryType }) {
    const data = await this.productRepo.list({
      ...props.query,
      languageId: I18nContext.current()?.lang as string,
      isPublic: true
    })
    return {
      ...data,
      message: this.i18n.t('product.product.success.GET_PRODUCTS')
    }
  }

  async getDetail(props: { productId: number }) {
    const product = await this.productRepo.getDetail({
      productId: props.productId,
      languageId: I18nContext.current()?.lang as string,
      isPublic: true
    })
    if (!product) {
      throw NotFoundRecordException
    }
    return {
      data: product,
      message: this.i18n.t('product.product.success.GET_PRODUCT_DETAIL')
    }
  }
}
