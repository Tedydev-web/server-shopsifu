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
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { RedisService } from 'src/shared/services/redis.service'
import { CacheEvict } from 'src/shared/decorators/cacheable.decorator'

@Injectable()
export class ManageProductService {
  constructor(
    private productRepo: ProductRepo,
    private i18n: I18nService<I18nTranslations>,
    private readonly redisService: RedisService
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
  async list(props: { query: GetManageProductsQueryType; user: AccessTokenPayload }) {
    this.validatePrivilege({
      userIdRequest: props.user.userId,
      roleNameRequest: props.user.roleName,
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

  async getDetail(props: { productId: string; user: AccessTokenPayload }) {
    const product = await this.productRepo.getDetail({
      productId: props.productId,
      languageId: I18nContext.current()?.lang as string
    })

    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: props.user.userId,
      roleNameRequest: props.user.roleName,
      createdById: product.data.createdById
    })
    return {
      message: this.i18n.t('product.product.success.GET_DETAIL_SUCCESS'),
      data: product.data
    }
  }

  /**
   * ⚡ Invalidate product & search cache khi tạo product mới
   */
  @CacheEvict(['products:*', 'ProductModule:product:*', 'SearchModule:search:*'])
  async create({ data, user }: { data: CreateProductBodyType; user: AccessTokenPayload }) {
    const product = await this.productRepo.create({
      createdById: user.userId,
      data
    })

    return {
      message: this.i18n.t('product.product.success.CREATE_SUCCESS'),
      data: product.data
    }
  }

  /**
   * ⚡ Invalidate product & search cache khi update product
   */
  @CacheEvict(['products:*', 'ProductModule:product:*', 'SearchModule:search:*'])
  async update({
    productId,
    data,
    user
  }: {
    productId: string
    data: UpdateProductBodyType
    user: AccessTokenPayload
  }) {
    const product = await this.productRepo.findById(productId)
    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: user.userId,
      roleNameRequest: user.roleName,
      createdById: product.createdById
    })
    try {
      const updatedProduct = await this.productRepo.update({
        id: productId,
        updatedById: user.userId,
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

  /**
   * ⚡ Invalidate product & search cache khi delete product
   */
  @CacheEvict(['products:*', 'ProductModule:product:*', 'SearchModule:search:*'])
  async delete({ productId, user }: { productId: string; user: AccessTokenPayload }) {
    const product = await this.productRepo.findById(productId)
    if (!product) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: user.userId,
      roleNameRequest: user.roleName,
      createdById: product.createdById
    })
    try {
      await this.productRepo.delete({
        id: productId,
        deletedById: user.userId
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
