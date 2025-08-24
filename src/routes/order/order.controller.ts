import { Body, Controller, Get, Param, Post, Put, Query, Logger } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
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
  private readonly logger = new Logger(OrderController.name)

  constructor(private readonly orderService: OrderService) {}

  @Get()
  @ZodSerializerDto(GetOrderListResDTO)
  getCart(@ActiveUser() user: AccessTokenPayload, @Query() query: GetOrderListQueryDTO) {
    return this.orderService.list(user, query as any)
  }

  @Post()
  @ZodSerializerDto(CreateOrderResDTO)
  async create(@ActiveUser() user: AccessTokenPayload, @Body() body: CreateOrderBodyDTO) {
    this.logger.log(`[ORDER_CONTROLLER] POST /orders - User: ${user.userId}`)
    this.logger.log(`[ORDER_CONTROLLER] Request body: ${JSON.stringify(body, null, 2)}`)

    try {
      const result = await this.orderService.create(user, body as any)
      this.logger.log(`[ORDER_CONTROLLER] Order created successfully: ${JSON.stringify(result, null, 2)}`)
      return result
    } catch (error) {
      this.logger.error(`[ORDER_CONTROLLER] Lỗi khi tạo order: ${error.message}`, error.stack)
      throw error
    }
  }

  @Get(':orderId')
  @ZodSerializerDto(GetOrderDetailResDTO)
  detail(@ActiveUser() user: AccessTokenPayload, @Param() param: GetOrderParamsDTO) {
    return this.orderService.detail(user, param.orderId)
  }

  @Put(':orderId')
  @ZodSerializerDto(CancelOrderResDTO)
  async cancel(@ActiveUser() user: AccessTokenPayload, @Param() param: GetOrderParamsDTO) {
    this.logger.log(`[ORDER_CONTROLLER] PUT /orders/${param.orderId} - User: ${user.userId}`)

    try {
      const result = await this.orderService.cancel(user, param.orderId)
      this.logger.log(`[ORDER_CONTROLLER] Order cancelled successfully: ${JSON.stringify(result, null, 2)}`)
      return result
    } catch (error) {
      this.logger.error(`[ORDER_CONTROLLER] Lỗi khi hủy order: ${error.message}`, error.stack)
      throw error
    }
  }

  @Post('calculate')
  @ZodSerializerDto(CalculateOrderResDTO)
  calculate(@ActiveUser() user: AccessTokenPayload, @Body() body: CalculateOrderBodyDTO) {
    return this.orderService.calculate(user, body as any)
  }
}
