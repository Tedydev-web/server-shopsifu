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
  CalculateShippingFeeSchema
} from './shipping.model'

export class GetProvincesResDTO extends createZodDto(GetProvincesResSchema) {}
export class GetDistrictsResDTO extends createZodDto(GetDistrictsResSchema) {}
export class GetWardsResDTO extends createZodDto(GetWardsResSchema) {}
export class GetDistrictsQueryDTO extends createZodDto(GetDistrictsQuerySchema) {}
export class GetWardsQueryDTO extends createZodDto(GetWardsQuerySchema) {}

export class GetServiceListResDTO extends createZodDto(GetServiceListResSchema) {}
export class CalculateShippingFeeResDTO extends createZodDto(CalculateShippingFeeResSchema) {}
export class GetServiceListQueryDTO extends createZodDto(GetServiceListQuerySchema) {}
export class CalculateShippingFeeDTO extends createZodDto(CalculateShippingFeeSchema) {}
