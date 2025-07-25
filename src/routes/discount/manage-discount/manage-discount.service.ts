import { Injectable } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DiscountRepo } from 'src/routes/discount/discount.repo'
import {
  CreateDiscountBodyType,
  GetManageDiscountsQueryType,
  UpdateDiscountBodyType
} from 'src/routes/discount/discount.model'
import {
  DiscountCodeAlreadyExistsException,
  DiscountNotFoundException,
  DiscountForbiddenException,
  DiscountProductOwnershipException,
  InvalidDiscountDateRangeException,
  ShopVoucherWithProductsException,
  ProductVoucherWithoutProductsException,
  InvalidMaxDiscountValueException,
  InvalidDiscountCodeFormatException
} from 'src/routes/discount/discount.error'
import { RoleName } from 'src/shared/constants/role.constant'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { VoucherType, DisplayType, DiscountType } from 'src/shared/constants/discount.constant'

@Injectable()
export class ManageDiscountService {
  constructor(
    private readonly discountRepo: DiscountRepo,
    private readonly i18n: I18nService<I18nTranslations>,
    private readonly prismaService: PrismaService
  ) {}

  /**
   * JSDoc for validatePrivilege
   */
  private validatePrivilege({
    userIdRequest,
    roleNameRequest,
    shopId
  }: {
    userIdRequest: string
    roleNameRequest: string
    shopId: string | null | undefined
  }) {
    if (userIdRequest !== shopId && roleNameRequest !== RoleName.Admin) {
      throw DiscountForbiddenException
    }
  }

  /**
   * JSDoc for validateProductOwnership
   */
  private async validateProductOwnership(productIds: string[] | undefined, sellerId: string) {
    if (!productIds || productIds.length === 0) return
    const products = await this.prismaService.product.findMany({
      where: { id: { in: productIds } },
      select: { id: true, createdById: true }
    })
    if (products.length !== productIds.length || products.some((p) => p.createdById !== sellerId)) {
      throw DiscountProductOwnershipException
    }
  }

  /**
   * JSDoc for validateDiscountExistence
   */
  private async validateDiscountExistence(code: string, excludeId?: string) {
    const existing = await this.prismaService.discount.findUnique({
      where: { code }
    })
    if (existing && (!excludeId || existing.id !== excludeId)) {
      throw DiscountCodeAlreadyExistsException
    }
  }

  /**
   * JSDoc for validateDiscountLogic
   */
  private validateDiscountLogic(data: CreateDiscountBodyType | UpdateDiscountBodyType) {
    const { startDate, endDate, voucherType, productIds, discountType, maxDiscountValue, code } = data

    if (endDate <= startDate) {
      throw InvalidDiscountDateRangeException
    }

    if (voucherType === VoucherType.SHOP && productIds && productIds.length > 0) {
      throw ShopVoucherWithProductsException
    }

    if (voucherType === VoucherType.PRODUCT && (!productIds || productIds.length === 0)) {
      throw ProductVoucherWithoutProductsException
    }

    if (discountType === DiscountType.FIX_AMOUNT && maxDiscountValue) {
      throw InvalidMaxDiscountValueException
    }

    if (!/^[A-Z0-9]{4,9}$/.test(code)) {
      throw InvalidDiscountCodeFormatException
    }
  }

  /**
   * JSDoc for list
   */
  async list({ query, user }: { query: GetManageDiscountsQueryType; user: AccessTokenPayload }) {
    if (user.roleName === RoleName.Seller) {
      query.shopId = user.userId
    }
    const result = await this.discountRepo.list(query)
    return {
      message: this.i18n.t('discount.discount.success.GET_SUCCESS'),
      data: result.data,
      metadata: result.metadata
    }
  }

  /**
   * JSDoc for findById
   */
  async findById(id: string, user: AccessTokenPayload) {
    const discount = await this.discountRepo.getDetail(id)
    if (!discount) throw DiscountNotFoundException
    this.validatePrivilege({
      userIdRequest: user.userId,
      roleNameRequest: user.roleName,
      shopId: discount.data.shopId
    })
    return discount
  }

  /**
   * JSDoc for create
   */
  async create({ data, user }: { data: CreateDiscountBodyType; user: AccessTokenPayload }) {
    await this.validateDiscountExistence(data.code)
    this.validateDiscountLogic(data)

    const dataToCreate: CreateDiscountBodyType = { ...data }

    if (user.roleName === RoleName.Seller) {
      const shop = await this.prismaService.user.findUnique({ where: { id: user.userId } })
      const prefix = shop?.name?.substring(0, 4).toUpperCase() || 'SHOP'
      if (!data.code.startsWith(prefix)) {
        throw InvalidDiscountCodeFormatException
      }
      await this.validateProductOwnership(data.productIds, user.userId)
      return this.discountRepo.create({
        createdById: user.userId,
        data: { ...dataToCreate, isPlatform: false }
      })
    }

    if (user.roleName !== RoleName.Admin && data.isPlatform) {
      throw DiscountForbiddenException
    }

    const discount = await this.discountRepo.create({
      createdById: user.userId,
      data: dataToCreate
    })

    return {
      message: this.i18n.t('discount.discount.success.CREATE_SUCCESS'),
      data: discount.data
    }
  }

  /**
   * JSDoc for update
   */
  async update({ id, data, user }: { id: string; data: UpdateDiscountBodyType; user: AccessTokenPayload }) {
    const discount = await this.discountRepo.findById(id)
    if (!discount) throw DiscountNotFoundException

    this.validatePrivilege({ userIdRequest: user.userId, roleNameRequest: user.roleName, shopId: discount.shopId })

    if (data.code) {
      await this.validateDiscountExistence(data.code, id)
    }

    this.validateDiscountLogic(data)

    const dataToUpdate: UpdateDiscountBodyType = { ...data }

    if (user.roleName === RoleName.Seller) {
      await this.validateProductOwnership(data.productIds, user.userId)
    }

    const updatedDiscount = await this.discountRepo.update({
      id,
      updatedById: user.userId,
      data: dataToUpdate
    })

    return {
      message: this.i18n.t('discount.discount.success.UPDATE_SUCCESS'),
      data: updatedDiscount
    }
  }

  /**
   * JSDoc for delete
   */
  async delete(id: string, user: AccessTokenPayload) {
    const discount = await this.discountRepo.findById(id)
    if (!discount) throw DiscountNotFoundException
    this.validatePrivilege({ userIdRequest: user.userId, roleNameRequest: user.roleName, shopId: discount.shopId })
    await this.discountRepo.delete({ id, deletedById: user.userId })
    return { message: this.i18n.t('discount.discount.success.DELETE_SUCCESS') }
  }
}
