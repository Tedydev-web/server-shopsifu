import { Body, Controller, Get, Param, Patch, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { ManageOrderService } from './manage-order.service'
import {
  GetManageOrderDetailResDTO,
  GetManageOrderListQueryDTO,
  GetManageOrderListResDTO,
  UpdateOrderStatusDTO
} from './manage-order.dto'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('manage-order/orders')
export class ManageOrderController {
  constructor(private readonly manageOrderService: ManageOrderService) {}

  @Get()
  @ZodSerializerDto(GetManageOrderListResDTO)
  list(@Query() query: GetManageOrderListQueryDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageOrderService.list({ query, user })
  }

  @Get(':orderId')
  @ZodSerializerDto(GetManageOrderDetailResDTO)
  getDetail(@Param('orderId') orderId: string, @ActiveUser() user: AccessTokenPayload) {
    return this.manageOrderService.getDetail({ orderId, user })
  }

  @Patch(':orderId/status')
  @ZodSerializerDto(GetManageOrderDetailResDTO)
  updateStatus(
    @Param('orderId') orderId: string,
    @Body() body: UpdateOrderStatusDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.manageOrderService.updateStatus({ orderId, data: body, user })
  }
}
