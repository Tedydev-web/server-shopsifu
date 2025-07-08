import { Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import { GetProductsQueryType } from 'src/routes/product/product.model'
import { NotFoundRecordException } from 'src/shared/error'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class ProductService {
  constructor(private productRepo: ProductRepo) {}

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
      sortBy: props.query.sortBy,
    })
    return data
  }

  async getDetail(props: { productId: number }) {
    const product = await this.productRepo.getDetail({
      productId: props.productId,
      languageId: I18nContext.current()?.lang as string,
      isPublic: true,
    })
    if (!product) {
      throw NotFoundRecordException
    }
    return product
  }
}
