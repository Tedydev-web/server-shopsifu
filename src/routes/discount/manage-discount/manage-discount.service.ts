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
  DiscountProductOwnershipException
} from 'src/routes/discount/discount.error'
import { RoleName } from 'src/shared/constants/role.constant'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { VoucherType, DisplayType } from 'src/shared/constants/discount.constant'

@Injectable()
export class ManageDiscountService {
  constructor(
    private readonly discountRepo: DiscountRepo,
    private readonly i18n: I18nService<I18nTranslations>,
    private readonly prismaService: PrismaService
  ) {}

  /**
   * Kiểm tra quyền thao tác trên discount (chủ sở hữu hoặc admin)
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
   * Kiểm tra seller chỉ được áp dụng discount cho sản phẩm của mình
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
   * Kiểm tra mã discount đã tồn tại chưa
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
   * Danh sách discount quản lý
   */
  async list({ query, user }: { query: GetManageDiscountsQueryType; user: AccessTokenPayload }) {
    if (user.roleName === RoleName.Seller) {
      query.shopId = user.userId
    }
    const result = await this.discountRepo.list(query)
    return {
      message: this.i18n.t('discount.discount.success.GET_SUCCESS' as any),
      data: result.data,
      metadata: result.metadata
    }
  }

  /**
   * Lấy chi tiết discount
   */
  async findById(id: string, user: AccessTokenPayload) {
    const discount = await this.discountRepo.findById(id)
    if (!discount) throw DiscountNotFoundException
    this.validatePrivilege({ userIdRequest: user.userId, roleNameRequest: user.roleName, shopId: discount.shopId })
    return { data: discount }
  }

  /**
   * Tạo mới discount
   */
  async create({ data, user }: { data: CreateDiscountBodyType; user: AccessTokenPayload }) {
    await this.validateDiscountExistence(data.code)
    let dataToCreate: any = { ...data }
    if (user.roleName === RoleName.Seller) {
      // Tự động sinh prefix code
      const shop = await this.prismaService.user.findUnique({ where: { id: user.userId } })
      const prefix = shop?.name?.substring(0, 4).toUpperCase() || 'SHOP'
      if (!data.code.startsWith(prefix)) {
        throw DiscountCodeAlreadyExistsException // hoặc custom exception cho prefix sai
      }
      dataToCreate = {
        ...dataToCreate,
        code: data.code,
        shopId: user.userId,
        categoryIds: undefined,
        brandIds: undefined,
        voucherType: VoucherType.SHOP,
        displayType: DisplayType.PUBLIC,
        isPlatform: false
      }
      await this.validateProductOwnership(data.productIds, user.userId)
    }
    // Validate code: regex, độ dài, prefix (Admin cũng nên kiểm tra nếu tạo cho shop)
    if (!/^[A-Z0-9]{4,9}$/.test(dataToCreate.code)) {
      throw DiscountCodeAlreadyExistsException // hoặc custom exception cho code không hợp lệ
    }
    // Nếu là Admin, validate isPlatform: chỉ Admin được phép tạo isPlatform=true
    if (user.roleName !== RoleName.Admin && dataToCreate.isPlatform) {
      throw DiscountForbiddenException
    }
    const discount = await this.discountRepo.create({
      createdById: user.userId,
      data: dataToCreate
    })
    return {
      message: this.i18n.t('discount.discount.success.CREATE_SUCCESS' as any),
      data: discount
    }
  }

  /**
   * Cập nhật discount
   */
  async update({ id, data, user }: { id: string; data: UpdateDiscountBodyType; user: AccessTokenPayload }) {
    const discount = await this.discountRepo.findById(id)
    if (!discount) throw DiscountNotFoundException
    this.validatePrivilege({ userIdRequest: user.userId, roleNameRequest: user.roleName, shopId: discount.shopId })
    if (data.code) await this.validateDiscountExistence(data.code, id)
    let dataToUpdate: any = { ...data }
    if (user.roleName === RoleName.Seller) {
      dataToUpdate = {
        ...dataToUpdate,
        categoryIds: undefined,
        brandIds: undefined,
        shopId: undefined
      }
      await this.validateProductOwnership(data.productIds, user.userId)
    }
    const updatedDiscount = await this.discountRepo.update({
      id,
      updatedById: user.userId,
      data: dataToUpdate
    })
    return {
      message: this.i18n.t('discount.discount.success.UPDATE_SUCCESS' as any),
      data: updatedDiscount
    }
  }

  /**
   * Xóa discount
   */
  async delete(id: string, user: AccessTokenPayload) {
    const discount = await this.discountRepo.findById(id)
    if (!discount) throw DiscountNotFoundException
    this.validatePrivilege({ userIdRequest: user.userId, roleNameRequest: user.roleName, shopId: discount.shopId })
    await this.discountRepo.delete({ id, deletedById: user.userId })
    return { message: this.i18n.t('discount.discount.success.DELETE_SUCCESS' as any) }
  }
}
