import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { UserProfileSchema as SharedUserProfileSchema } from '../models/user-profile.model'

/**
 * Schema for user profile data included in various responses.
 * Picks only the essential, publicly safe fields.
 */
export const PickedUserProfileResponseSchema = SharedUserProfileSchema.pick({
  firstName: true,
  lastName: true,
  username: true,
  avatar: true
})

export type PickedUserProfileResponseType = z.infer<typeof PickedUserProfileResponseSchema>

export class PickedUserProfileResponseDto extends createZodDto(PickedUserProfileResponseSchema) {}
