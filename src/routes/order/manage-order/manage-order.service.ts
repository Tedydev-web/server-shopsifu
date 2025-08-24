import { Injectable, ForbiddenException } from '@nestjs/common'
import { OrderRepo } from '../order.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { GetManageOrderListQueryType, GetManageOrderDetailResType } from '../order.model'

@Injectable()
export class ManageOrderService {
  constructor(
    private readonly orderRepo: OrderRepo,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  /**
   * Kiểm tra nếu người dùng không phải là Seller hoặc Admin thì không cho tiếp tục
   */
  validateSellerPrivilege(user: AccessTokenPayload): boolean {
    if (user.roleName !== 'SELLER' && user.roleName !== 'ADMIN') {
      throw new ForbiddenException('Chỉ Seller mới được truy cập tính năng này')
    }
    return true
  }

  /**
   * Lấy danh sách đơn hàng của shop
   */
  async list({ query, user }: { query: GetManageOrderListQueryType; user: AccessTokenPayload }) {
    this.validateSellerPrivilege(user)

    let data
    if (user.roleName === 'ADMIN') {
      // Admin có thể xem tất cả orders
      data = await this.orderRepo.listForAdmin(query)
    } else {
      // Seller chỉ xem orders của shop mình
      data = await this.orderRepo.listByShop(user.userId, query)
    }

    return {
      message: this.i18n.t('order.order.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  /**
   * Lấy chi tiết đơn hàng của shop
   */
  async getDetail({
    orderId,
    user
  }: {
    orderId: string
    user: AccessTokenPayload
  }): Promise<GetManageOrderDetailResType> {
    this.validateSellerPrivilege(user)

    let order
    if (user.roleName === 'ADMIN') {
      // Admin có thể xem tất cả orders - tìm order trực tiếp từ database
      order = await this.orderRepo.detailForAdmin(orderId)
    } else {
      // Seller chỉ xem orders của shop mình
      order = await this.orderRepo.detailByShop(user.userId, orderId)
    }

    if (!order) {
      throw new Error('Order not found')
    }

    return {
      message: this.i18n.t('order.order.success.GET_DETAIL_SUCCESS'),
      data: order.data
    }
  }
}
