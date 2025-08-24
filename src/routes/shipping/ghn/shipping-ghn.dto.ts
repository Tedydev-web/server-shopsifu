import { createZodDto } from 'nestjs-zod'
import {
  GetProvincesResSchema,
  GetDistrictsResSchema,
  GetWardsResSchema,
  GetDistrictsQuerySchema,
  GetWardsQuerySchema,
  GetServiceListResSchema,
  CalculateShippingFeeResSchema,
  GetServiceListQuerySchema,
  CalculateShippingFeeSchema,
  CalculateExpectedDeliveryTimeSchema,
  CalculateExpectedDeliveryTimeResSchema,
  CreateOrderSchema,
  CreateOrderResSchema,
  GHNWebhookPayloadSchema,
  GHNWebhookResponseSchema,
  GetOrderInfoQuerySchema,
  GetOrderInfoResSchema,
  GetTrackingUrlQuerySchema,
  GetTrackingUrlResSchema,
  PrintOrderResSchema
} from './shipping-ghn.model'

export class GetProvincesResDTO extends createZodDto(GetProvincesResSchema) {}
export class GetDistrictsResDTO extends createZodDto(GetDistrictsResSchema) {}
export class GetWardsResDTO extends createZodDto(GetWardsResSchema) {}
export class GetDistrictsQueryDTO extends createZodDto(GetDistrictsQuerySchema) {}
export class GetWardsQueryDTO extends createZodDto(GetWardsQuerySchema) {}

export class GetServiceListResDTO extends createZodDto(GetServiceListResSchema) {}
export class CalculateShippingFeeResDTO extends createZodDto(CalculateShippingFeeResSchema) {}
export class GetServiceListQueryDTO extends createZodDto(GetServiceListQuerySchema) {}
export class CalculateShippingFeeDTO extends createZodDto(CalculateShippingFeeSchema) {}

export class CalculateExpectedDeliveryTimeDTO extends createZodDto(CalculateExpectedDeliveryTimeSchema) {}
export class CalculateExpectedDeliveryTimeResDTO extends createZodDto(CalculateExpectedDeliveryTimeResSchema) {}
export class CreateOrderDTO extends createZodDto(CreateOrderSchema) {}
export class CreateOrderResDTO extends createZodDto(CreateOrderResSchema) {}

export class GHNWebhookPayloadDTO extends createZodDto(GHNWebhookPayloadSchema) {}
export class GHNWebhookResponseDTO extends createZodDto(GHNWebhookResponseSchema) {}

export class GetOrderInfoQueryDTO extends createZodDto(GetOrderInfoQuerySchema) {}
export class GetOrderInfoResDTO extends createZodDto(GetOrderInfoResSchema) {}

export class GetTrackingUrlQueryDTO extends createZodDto(GetTrackingUrlQuerySchema) {}
export class GetTrackingUrlResDTO extends createZodDto(GetTrackingUrlResSchema) {}

export class PrintOrderResDTO extends createZodDto(PrintOrderResSchema) {}
