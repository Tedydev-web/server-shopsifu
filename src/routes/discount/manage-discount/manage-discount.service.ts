import { ForbiddenException, Injectable } from '@nestjs/common'
import {
  CreateDiscountBodyType,
  GetManageDiscountsQueryType,
  UpdateDiscountBodyType
} from 'src/routes/discount/discount.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { I18nService } from 'nestjs-i18n'
import { RoleName } from 'src/shared/constants/role.constant'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { DiscountRepo } from '../discount.repo'

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
    shopId
  }: {
    userIdRequest: string
    roleNameRequest: string
    shopId: string | undefined | null
  }) {
    if (roleNameRequest !== RoleName.Admin && userIdRequest !== shopId) {
      throw new ForbiddenException()
    }
    return true
  }

  async list(props: { query: GetManageDiscountsQueryType; userIdRequest: string; roleNameRequest: string }) {
    if (props.roleNameRequest === RoleName.Seller) {
      props.query.shopId = props.userIdRequest
    }
    const data = await this.discountRepo.list(props.query)
    return {
      message: this.i18n.t('global.global.success.GET_SUCCESS'),
      data: data.data.map((d) => ({ ...d, products: d.products?.map((p) => p.id) ?? [] })),
      metadata: data.metadata
    }
  }

  async getDetail(props: { discountId: string; userIdRequest: string; roleNameRequest: string }) {
    const discount = await this.discountRepo.findById(props.discountId)

    if (!discount) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: props.userIdRequest,
      roleNameRequest: props.roleNameRequest,
      shopId: discount.shopId
    })
    return {
      message: this.i18n.t('global.global.success.GET_DETAIL_SUCCESS'),
      data: { ...discount, products: discount.products?.map((p) => p.id) ?? [] }
    }
  }

  async create({
    data,
    createdById,
    roleName
  }: {
    data: CreateDiscountBodyType
    createdById: string
    roleName: string
  }) {
    const dataTemp: CreateDiscountBodyType = { ...data }
    if (roleName === RoleName.Seller) {
      dataTemp.shopId = createdById
    }

    const discount = await this.discountRepo.create({
      createdById,
      data: dataTemp
    })
    return {
      message: this.i18n.t('global.global.success.CREATE_SUCCESS'),
      data: { ...discount, products: discount.products?.map((p) => p.id) ?? [] }
    }
  }

  async update({
    discountId,
    data,
    updatedById,
    roleNameRequest
  }: {
    discountId: string
    data: UpdateDiscountBodyType
    updatedById: string
    roleNameRequest: string
  }) {
    const discount = await this.discountRepo.findById(discountId)
    if (!discount) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: updatedById,
      roleNameRequest,
      shopId: discount.shopId
    })
    try {
      const updatedDiscount = await this.discountRepo.update({
        id: discountId,
        updatedById,
        data: {
          ...data,
          products: data.products ?? []
        }
      })
      return {
        message: this.i18n.t('global.global.success.UPDATE_SUCCESS'),
        data: { ...updatedDiscount, products: updatedDiscount.products?.map((p) => p.id) ?? [] }
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({
    discountId,
    deletedById,
    roleNameRequest
  }: {
    discountId: string
    deletedById: string
    roleNameRequest: string
  }) {
    const discount = await this.discountRepo.findById(discountId)
    if (!discount) {
      throw NotFoundRecordException
    }
    this.validatePrivilege({
      userIdRequest: deletedById,
      roleNameRequest,
      shopId: discount.shopId
    })
    try {
      await this.discountRepo.delete({
        id: discountId,
        deletedById
      })
      return {
        message: this.i18n.t('global.global.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
