import { createZodDto } from 'nestjs-zod'
import {
  UserProfileResponseSchema,
  UpdateProfileBodySchema,
  RequestEmailChangeBodySchema,
  VerifyNewEmailBodySchema
} from './profile.model'

export class UserProfileResponseDTO extends createZodDto(UserProfileResponseSchema) {}

export class UpdateProfileBodyDTO extends createZodDto(UpdateProfileBodySchema) {}

export class RequestEmailChangeBodyDTO extends createZodDto(RequestEmailChangeBodySchema) {}

export class VerifyNewEmailBodyDTO extends createZodDto(VerifyNewEmailBodySchema) {}
