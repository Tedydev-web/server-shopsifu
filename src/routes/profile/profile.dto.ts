import { createZodDto } from 'nestjs-zod'
import { ChangePasswordSchema, ProfileResponseSchema, UpdateProfileSchema } from './profile.schema'

// ===================================================================================
// DTOs
// ===================================================================================

export class ProfileResponseDto extends createZodDto(ProfileResponseSchema) {}
export class ChangePasswordDto extends createZodDto(ChangePasswordSchema) {}
export class UpdateProfileDto extends createZodDto(UpdateProfileSchema) {}
