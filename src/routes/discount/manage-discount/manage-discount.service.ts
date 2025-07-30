import { Injectable, ForbiddenException } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { DiscountRepo } from '../discount.repo'
import {
  GetManageDiscountsQueryType,
  GetDiscountDetailResType,
  CreateDiscountBodyType,
  UpdateDiscountBodyType
} from '../discount.model'
import { RoleName } from 'src/shared/constants/role.constant'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'

@Injectable()
export class ManageDiscountService {
  constructor(
    private discountRepo: DiscountRepo,
    private i18n: I18nService<I18nTranslations>
  ) {}

  /**
   * Kiểm tra nếu người dùng không phải là người tạo discount hoặc admin thì không cho tiếp tục
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
   * @description: Xem danh sách discount của một shop, bắt buộc phải truyền query param là `createdById`
   */
  async list(props: { query: GetManageDiscountsQueryType; user: AccessTokenPayload }) {
    this.validatePrivilege({
      userIdRequest: props.user.userId,
      roleNameRequest: props.user.roleName,
      createdById: props.query.createdById
    })
    const data = await this.discountRepo.list({
      page: props.query.page,
      limit: props.query.limit,
      name: props.query.name,
      code: props.query.code,
      discountStatus: props.query.discountStatus,
      discountType: props.query.discountType,
      discountApplyType: props.query.discountApplyType,
      voucherType: props.query.voucherType,
      displayType: props.query.displayType,
      isPlatform: props.query.isPlatform,
      startDate: props.query.startDate,
      endDate: props.query.endDate,
      minValue: props.query.minValue,
      maxValue: props.query.maxValue,
      shopId: props.query.shopId,
      createdById: props.query.createdById,
      orderBy: props.query.orderBy,
      sortBy: props.query.sortBy
    })
    return {
      message: this.i18n.t('discount.discount.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async getDetail(props: { discountId: string; user: AccessTokenPayload }) {
    const discount = await this.discountRepo.getDetail({
      discountId: props.discountId,
      createdById: props.user.userId
    })

    if (!discount) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: props.user.userId,
      roleNameRequest: props.user.roleName,
      createdById: discount.data.createdById
    })
    return {
      message: this.i18n.t('discount.discount.success.GET_SUCCESS'),
      data: discount.data
    }
  }

  async create({ data, user }: { data: CreateDiscountBodyType; user: AccessTokenPayload }) {
    const discount = await this.discountRepo.create({
      createdById: user.userId,
      data
    })
    return {
      message: this.i18n.t('discount.discount.success.CREATE_SUCCESS'),
      data: discount.data
    }
  }

  async update({
    discountId,
    data,
    user
  }: {
    discountId: string
    data: UpdateDiscountBodyType
    user: AccessTokenPayload
  }) {
    const discount = await this.discountRepo.findById(discountId)
    if (!discount) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: user.userId,
      roleNameRequest: user.roleName,
      createdById: discount.createdById
    })
    try {
      const updatedDiscount = await this.discountRepo.update({
        id: discountId,
        updatedById: user.userId,
        data
      })
      return {
        message: this.i18n.t('discount.discount.success.UPDATE_SUCCESS'),
        data: updatedDiscount
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ discountId, user }: { discountId: string; user: AccessTokenPayload }) {
    const discount = await this.discountRepo.findById(discountId)
    if (!discount) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: user.userId,
      roleNameRequest: user.roleName,
      createdById: discount.createdById
    })
    try {
      await this.discountRepo.delete({
        id: discountId,
        deletedById: user.userId
      })
      return {
        message: this.i18n.t('discount.discount.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
