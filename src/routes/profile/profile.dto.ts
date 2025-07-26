import { createZodDto } from 'nestjs-zod'
import { UpdateMeBodySchema, ChangePasswordBodySchema } from './profile.model'
import {
  CreateAddressBodySchema,
  UpdateAddressBodySchema,
  GetAddressParamsSchema,
  GetUserAddressesResSchema,
  GetUserAddressDetailResSchema,
  CreateAddressResSchema,
  UpdateAddressResSchema,
  GetUserStatisticsResSchema
} from './profile.model'

export class UpdateMeBodyDTO extends createZodDto(UpdateMeBodySchema) {}

export class ChangePasswordBodyDTO extends createZodDto(ChangePasswordBodySchema) {}

// Address DTOs
export class CreateAddressBodyDTO extends createZodDto(CreateAddressBodySchema) {}

export class UpdateAddressBodyDTO extends createZodDto(UpdateAddressBodySchema) {}

export class GetAddressParamsDTO extends createZodDto(GetAddressParamsSchema) {}

export class GetUserAddressesResDTO extends createZodDto(GetUserAddressesResSchema) {}

export class GetUserAddressDetailResDTO extends createZodDto(GetUserAddressDetailResSchema) {}

export class CreateAddressResDTO extends createZodDto(CreateAddressResSchema) {}

export class UpdateAddressResDTO extends createZodDto(UpdateAddressResSchema) {}

export class GetUserStatisticsResDTO extends createZodDto(GetUserStatisticsResSchema) {}
