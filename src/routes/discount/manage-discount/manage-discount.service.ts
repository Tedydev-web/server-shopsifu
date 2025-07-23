import { ForbiddenException, Injectable } from '@nestjs/common'
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
  DiscountForbiddenException
} from 'src/routes/discount/discount.error'
import { RoleName } from 'src/shared/constants/role.constant'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { Prisma } from '@prisma/client'
import { NotFoundRecordException } from 'src/shared/error'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

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
  validatePrivilege({
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
    return true
  }

  /**
   * Kiểm tra seller chỉ được áp dụng discount cho sản phẩm của mình
   */
  private async validateProductOwnership(productIds: string[], sellerId: string) {
    if (!productIds || productIds.length === 0) return
    const products = await this.prismaService.product.findMany({
      where: { id: { in: productIds } },
      select: { id: true, createdById: true }
    })
    if (products.length !== productIds.length || products.some((p) => p.createdById !== sellerId)) {
      throw DiscountForbiddenException
    }
  }

  /**
   * Kiểm tra mã discount đã tồn tại chưa
   */
  private async validateDiscountExistence(code: string) {
    const existing = await this.prismaService.discount.findUnique({
      where: { code }
    })
    if (existing) {
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
    // Admin có thể xem tất cả
    const result = await this.discountRepo.list(query)
    return {
      message: this.i18n.t('discount.discount.success.GET_SUCCESS' as any),
      data: result.data.map((d) => this.mapToResponse(d).data),
      metadata: result.metadata
    }
  }

  /**
   * Lấy chi tiết discount
   */
  async findById(id: string, user: AccessTokenPayload) {
    const discount = await this.sharedDiscountRepo.findById(id)
    if (!discount) {
      throw DiscountNotFoundException
    }
    this.validatePrivilege({ userIdRequest: user.userId, roleNameRequest: user.roleName, shopId: discount.shopId })
    return this.mapToResponse(discount)
  }

  /**
   * Tạo mới discount
   */
  async create({ data, user }: { data: CreateDiscountBodyType; user: AccessTokenPayload }) {
    await this.validateDiscountExistence(data.code)
    const dataTemp: any = { ...data }
    if (user.roleName === RoleName.Seller) {
      dataTemp.shopId = user.userId
      await this.validateProductOwnership(data.products ?? [], user.userId)
    }
    try {
      const discount = await this.discountRepo.create({
        createdById: user.userId,
        data: dataTemp
      })
      return this.mapToResponse(discount, this.i18n.t('discount.discount.success.CREATE_SUCCESS' as any))
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        throw DiscountCodeAlreadyExistsException
      }
      throw err
    }
  }

  /**
   * Cập nhật discount
   */
  async update({ id, data, user }: { id: string; data: UpdateDiscountBodyType; user: AccessTokenPayload }) {
    const discount = await this.sharedDiscountRepo.findById(id)
    if (!discount) {
      throw DiscountNotFoundException
    }
    this.validatePrivilege({ userIdRequest: user.userId, roleNameRequest: user.roleName, shopId: discount.shopId })
    if (data.code) {
      const existing = await this.sharedDiscountRepo.findByCode(data.code)
      if (existing && existing.id !== id) {
        throw DiscountCodeAlreadyExistsException
      }
    }
    if (user.roleName === RoleName.Seller && data.products) {
      await this.validateProductOwnership(data.products, user.userId)
    }
    try {
      const updatedDiscount = await this.discountRepo.update({
        id,
        updatedById: user.userId,
        data
      })
      return this.mapToResponse(updatedDiscount, this.i18n.t('discount.discount.success.UPDATE_SUCCESS' as any))
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        throw DiscountCodeAlreadyExistsException
      }
      throw err
    }
  }

  /**
   * Xóa discount
   */
  async delete(id: string, user: AccessTokenPayload) {
    const discount = await this.sharedDiscountRepo.findById(id)
    if (!discount) {
      throw DiscountNotFoundException
    }
    this.validatePrivilege({ userIdRequest: user.userId, roleNameRequest: user.roleName, shopId: discount.shopId })
    await this.discountRepo.delete({ id, deletedById: user.userId })
    return { message: this.i18n.t('discount.discount.success.DELETE_SUCCESS' as any) }
  }

  /**
   * Chuẩn hóa response trả về (chỉ trả về id cho các quan hệ)
   */
  private mapToResponse(discount: any, message?: string) {
    const { products, categories, brands, ...rest } = discount
    return {
      ...(message ? { message } : {}),
      data: {
        ...rest,
        products: products.map((p: any) => p.id),
        categories: categories.map((c: any) => c.id),
        brands: brands.map((b: any) => b.id)
      }
    }
  }
}
