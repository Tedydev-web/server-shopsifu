import { Injectable, ForbiddenException } from '@nestjs/common'
import { OrderRepo } from '../order.repo'
import { SharedShippingRepository } from 'src/shared/repositories/shared-shipping.repo'
import { RoleName } from 'src/shared/constants/role.constant'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { GetManageOrderListQueryType, GetManageOrderDetailResType, UpdateOrderStatusType } from './manage-order.model'

@Injectable()
export class ManageOrderService {
  constructor(
    private readonly orderRepo: OrderRepo,
    private readonly sharedShippingRepo: SharedShippingRepository,
    private readonly i18n: I18nService<I18nTranslations>
  ) {}

  /**
   * Kiểm tra nếu người dùng không phải là Seller hoặc Admin thì không cho tiếp tục
   */
  validateSellerPrivilege(user: AccessTokenPayload): boolean {
    if (user.roleName !== RoleName.Seller && user.roleName !== RoleName.Admin) {
      throw new ForbiddenException('Chỉ Seller mới được truy cập tính năng này')
    }
    return true
  }

  /**
   * Lấy danh sách đơn hàng của shop
   */
  async list({ query, user }: { query: GetManageOrderListQueryType; user: AccessTokenPayload }) {
    this.validateSellerPrivilege(user)

    const data = await this.orderRepo.listByShop(user.userId, query)
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

    const order = await this.orderRepo.detailByShop(user.userId, orderId)
    if (!order) {
      throw new Error('Order not found')
    }

    return {
      message: this.i18n.t('order.order.success.GET_DETAIL_SUCCESS'),
      data: order
    }
  }

  /**
   * Cập nhật chỉ trạng thái đơn hàng (PATCH)
   */
  async updateStatus({
    orderId,
    data,
    user
  }: {
    orderId: string
    data: UpdateOrderStatusType
    user: AccessTokenPayload
  }) {
    this.validateSellerPrivilege(user)

    // Validate status transition
    this.validateStatusTransition(data.status)

    const updatedOrder = await this.orderRepo.updateOrderStatus(user.userId, orderId, data.status, user.userId)

    return {
      message: this.i18n.t('order.order.success.UPDATE_SUCCESS'),
      data: updatedOrder
    }
  }

  /**
   * Validate việc chuyển đổi trạng thái đơn hàng
   */
  private validateStatusTransition(newStatus: string): boolean {
    // TODO: Implement status transition validation logic
    // Ví dụ: PENDING_PAYMENT -> PENDING_PICKUP -> PENDING_DELIVERY -> DELIVERED
    // Không cho phép: DELIVERED -> PENDING_PICKUP
    return true
  }
}
