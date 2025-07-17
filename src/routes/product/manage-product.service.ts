import { ForbiddenException, Injectable } from '@nestjs/common'
import { ProductRepo } from 'src/routes/product/product.repo'
import {
  CreateProductBodyType,
  GetManageProductsQueryType,
  UpdateProductBodyType
} from 'src/routes/product/product.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { RoleName } from 'src/shared/constants/role.constant'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'

@Injectable()
export class ManageProductService {
  constructor(
    private productRepo: ProductRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  /**
   * Kiểm tra nếu người dùng không phải là người tạo sản phẩm hoặc admin thì không cho tiếp tục
   */
  validatePrivilege({
    userIdRequest,
    roleNameRequest,
    createdById
  }: {
    userIdRequest: string
    roleNameRequest: string
    createdById: string | undefined | null
  }) {
    if (userIdRequest !== createdById && roleNameRequest !== RoleName.Admin) {
      throw new ForbiddenException()
    }
    return true
  }

  /**
   * @description: Xem danh sách sản phẩm của một shop, bắt buộc phải truyền query param là `createdById`
   */
  async list(props: { query: GetManageProductsQueryType; userIdRequest: string; roleNameRequest: string }) {
    this.validatePrivilege({
      userIdRequest: props.userIdRequest,
      roleNameRequest: props.roleNameRequest,
      createdById: props.query.createdById
    })
    const data = await this.productRepo.list({
      page: props.query.page,
      limit: props.query.limit,
      languageId: I18nContext.current()?.lang as string,
      createdById: props.query.createdById,
      isPublic: props.query.isPublic,
      brandIds: props.query.brandIds,
      minPrice: props.query.minPrice,
      maxPrice: props.query.maxPrice,
      categories: props.query.categories,
      name: props.query.name,
      orderBy: props.query.orderBy,
      sortBy: props.query.sortBy
    })
    return {
      message: this.i18n.t('product.product.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async getDetail(props: { productId: string; userIdRequest: string; roleNameRequest: string }) {
    const product = await this.productRepo.getDetail({
      productId: props.productId,
      languageId: I18nContext.current()?.lang as string
    })

    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: props.userIdRequest,
      roleNameRequest: props.roleNameRequest,
      createdById: product.data.createdById
    })
    return {
      message: this.i18n.t('product.product.success.GET_DETAIL_SUCCESS'),
      data: product.data
    }
  }

  async create({ data, createdById }: { data: CreateProductBodyType; createdById: string }) {
    const product = await this.productRepo.create({
      createdById,
      data
    })
    return {
      message: this.i18n.t('product.product.success.CREATE_SUCCESS'),
      data: product
    }
  }

  async update({
    productId,
    data,
    updatedById,
    roleNameRequest
  }: {
    productId: string
    data: UpdateProductBodyType
    updatedById: string
    roleNameRequest: string
  }) {
    const product = await this.productRepo.findById(productId)
    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: updatedById,
      roleNameRequest,
      createdById: product.createdById
    })
    try {
      const updatedProduct = await this.productRepo.update({
        id: productId,
        updatedById,
        data
      })
      return {
        message: this.i18n.t('product.product.success.UPDATE_SUCCESS'),
        data: updatedProduct
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({
    productId,
    deletedById,
    roleNameRequest
  }: {
    productId: string
    deletedById: string
    roleNameRequest: string
  }) {
    const product = await this.productRepo.findById(productId)
    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: deletedById,
      roleNameRequest,
      createdById: product.createdById
    })
    try {
      await this.productRepo.delete({
        id: productId,
        deletedById
      })
      return {
        message: this.i18n.t('product.product.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
