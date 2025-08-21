import { createZodDto } from 'nestjs-zod'
import {
  GetProvincesResSchema,
  GetDistrictsResSchema,
  GetWardsResSchema,
  GetDistrictsQuerySchema,
  GetWardsQuerySchema
} from './shipping.model'

// Response DTOs
export class GetProvincesResDTO extends createZodDto(GetProvincesResSchema) {}

export class GetDistrictsResDTO extends createZodDto(GetDistrictsResSchema) {}

export class GetWardsResDTO extends createZodDto(GetWardsResSchema) {}

// Query DTOs
export class GetDistrictsQueryDTO extends createZodDto(GetDistrictsQuerySchema) {}

export class GetWardsQueryDTO extends createZodDto(GetWardsQuerySchema) {}
