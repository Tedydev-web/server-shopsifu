import { createZodDto } from 'nestjs-zod'
import {
  GetManageOrderListQuerySchema,
  GetManageOrderListResSchema,
  GetManageOrderDetailResSchema,
  UpdateOrderStatusSchema
} from './manage-order.model'

export class GetManageOrderListQueryDTO extends createZodDto(GetManageOrderListQuerySchema) {}

export class GetManageOrderListResDTO extends createZodDto(GetManageOrderListResSchema) {}

export class GetManageOrderDetailResDTO extends createZodDto(GetManageOrderDetailResSchema) {}

export class UpdateOrderStatusDTO extends createZodDto(UpdateOrderStatusSchema) {}
