import { createZodDto } from 'nestjs-zod'
import { GetUserProfileResSchema, UpdateProfileResSchema } from '../models/shared-user.model'

/**
 * Áp dụng cho Response của api GET('profile') và GET('users/:userId')
 */
export class GetUserProfileResDTO extends createZodDto(GetUserProfileResSchema) {}

/**
 * Áp dụng cho Response của api PUT('profile') và PUT('users/:userId')
 */
export class UpdateProfileResDTO extends createZodDto(UpdateProfileResSchema) {}
