import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'

export const UserProfileSchema = z.object({
  id: z.number().int().positive(),
  userId: z.number().int().positive(),
  firstName: z.string().max(255).nullable().optional(),
  lastName: z.string().max(255).nullable().optional(),
  username: z.string().max(100).nullable().optional(),
  avatar: z.string().max(1000).url().nullable().optional(),
  bio: z.string().nullable().optional(),
  phoneNumber: z.string().max(50).nullable().optional(),
  isPhoneNumberVerified: z.boolean().default(false),
  phoneNumberVerifiedAt: z.date().nullable().optional(),
  countryCode: z.string().max(10).nullable().optional(),
  secondaryEmail: z.string().email().max(255).nullable().optional(),
  isSecondaryEmailVerified: z.boolean().default(false),
  secondaryEmailVerifiedAt: z.date().nullable().optional(),
  createdAt: z.date(),
  updatedAt: z.date()
})

export type UserProfileType = z.infer<typeof UserProfileSchema>

export class UserProfileDto extends createZodDto(UserProfileSchema) {}

/**
 * Schema for user profile data included in various responses.
 * Picks only the essential, publicly safe fields.
 */
export const PickedUserProfileResponseSchema = UserProfileSchema.pick({
  firstName: true,
  lastName: true,
  username: true,
  avatar: true
})

export type PickedUserProfileResponseType = z.infer<typeof PickedUserProfileResponseSchema>

export class PickedUserProfileResponseDto extends createZodDto(PickedUserProfileResponseSchema) {}
