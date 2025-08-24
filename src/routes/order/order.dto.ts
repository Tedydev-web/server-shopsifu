import { createZodDto } from 'nestjs-zod'
import {
  CancelOrderResSchema,
  CreateOrderBodySchema,
  CreateOrderResSchema,
  GetOrderDetailResSchema,
  GetOrderListQuerySchema,
  GetOrderListResSchema,
  GetOrderParamsSchema,
  CalculateOrderPerShopSchema,
  CalculateOrderResSchema,
  GetManageOrderListQuerySchema,
  GetManageOrderListResSchema,
  GetManageOrderDetailResSchema
} from 'src/routes/order/order.model'

export class GetOrderListResDTO extends createZodDto(GetOrderListResSchema) {}

export class GetOrderListQueryDTO extends createZodDto(GetOrderListQuerySchema) {}

export class GetOrderDetailResDTO extends createZodDto(GetOrderDetailResSchema) {}

export class CreateOrderBodyDTO extends createZodDto(CreateOrderBodySchema) {}

export class CreateOrderResDTO extends createZodDto(CreateOrderResSchema) {}

export class CancelOrderResDTO extends createZodDto(CancelOrderResSchema) {}

export class GetOrderParamsDTO extends createZodDto(GetOrderParamsSchema) {}

export class CalculateOrderBodyDTO extends createZodDto(CalculateOrderPerShopSchema) {}

export class CalculateOrderResDTO extends createZodDto(CalculateOrderResSchema) {}

// Manage Order DTOs
export class GetManageOrderListQueryDTO extends createZodDto(GetManageOrderListQuerySchema) {}

export class GetManageOrderListResDTO extends createZodDto(GetManageOrderListResSchema) {}

export class GetManageOrderDetailResDTO extends createZodDto(GetManageOrderDetailResSchema) {}
