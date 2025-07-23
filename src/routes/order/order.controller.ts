import { Body, Controller, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CancelOrderBodyDTO,
  CancelOrderResDTO,
  CreateOrderBodyDTO,
  CreateOrderResDTO,
  GetOrderDetailResDTO,
  GetOrderListQueryDTO,
  GetOrderListResDTO,
  GetOrderParamsDTO,
  CalculateOrderBodyDTO,
  CalculateOrderResDTO
} from 'src/routes/order/order.dto'
import { OrderService } from 'src/routes/order/order.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('orders')
export class OrderController {
  constructor(private readonly orderService: OrderService) {}

  @Get()
  @ZodSerializerDto(GetOrderListResDTO)
  getCart(@ActiveUser() user: AccessTokenPayload, @Query() query: GetOrderListQueryDTO) {
    return this.orderService.list(user, query)
  }

  @Post()
  @ZodSerializerDto(CreateOrderResDTO)
  create(@ActiveUser() user: AccessTokenPayload, @Body() body: CreateOrderBodyDTO) {
    return this.orderService.create(user, body)
  }

  @Get(':orderId')
  @ZodSerializerDto(GetOrderDetailResDTO)
  detail(@ActiveUser() user: AccessTokenPayload, @Param() param: GetOrderParamsDTO) {
    return this.orderService.detail(user, param.orderId)
  }

  @Put(':orderId')
  @ZodSerializerDto(CancelOrderResDTO)
  cancel(@ActiveUser() user: AccessTokenPayload, @Param() param: GetOrderParamsDTO, @Body() _: CancelOrderBodyDTO) {
    return this.orderService.cancel(user, param.orderId)
  }

  @Post('calculate')
  @ZodSerializerDto(CalculateOrderResDTO)
  calculate(@ActiveUser() user: AccessTokenPayload, @Body() body: CalculateOrderBodyDTO) {
    return this.orderService.calculate(user, body)
  }
}
