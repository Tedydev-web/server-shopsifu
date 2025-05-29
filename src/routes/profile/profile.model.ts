import { z } from 'zod'
import { UserProfileSchema as SharedUserProfileSchema } from 'src/shared/models/user-profile.model'
import { UserSchema as SharedUserSchema } from 'src/shared/models/shared-user.model'

// Base UserProfile fields that can be directly updated by the user
export const BaseUserProfileUpdatableSchema = SharedUserProfileSchema.pick({
  firstName: true,
  lastName: true,
  username: true,
  avatar: true,
  bio: true,
  phoneNumber: true,
  countryCode: true
}).partial() // All fields are optional for updates

export type BaseUserProfileUpdatableType = z.infer<typeof BaseUserProfileUpdatableSchema>

// Schema for the response when fetching user profile
// It combines selected fields from User and UserProfile
export const UserProfileResponseSchema = z.object({
  id: SharedUserSchema.shape.id,
  email: SharedUserSchema.shape.email, // This will be the primary email later
  isEmailVerified: SharedUserSchema.shape.isEmailVerified,
  status: SharedUserSchema.shape.status,
  role: z.string(), // Will be populated from user.role.name
  twoFactorEnabled: SharedUserSchema.shape.twoFactorEnabled.nullable(),
  userProfile: SharedUserProfileSchema.pick({
    firstName: true,
    lastName: true,
    username: true,
    avatar: true,
    bio: true,
    phoneNumber: true,
    countryCode: true
  }).nullable()
})

export type UserProfileResponseType = z.infer<typeof UserProfileResponseSchema>

// Schema for updating the user profile (request body)
export const UpdateProfileBodySchema = BaseUserProfileUpdatableSchema

export type UpdateProfileBodyType = z.infer<typeof UpdateProfileBodySchema>

// Schema for requesting an email change
export const RequestEmailChangeBodySchema = z.object({
  email: z.string().email({ message: 'Invalid email format' })
})

export type RequestEmailChangeBodyType = z.infer<typeof RequestEmailChangeBodySchema>

// Schema for verifying a new email address
export const VerifyNewEmailBodySchema = z.object({
  token: z.string().min(1, { message: 'Verification token is required' }),
  otp: z.string().min(1, { message: 'OTP is required' })
})

export type VerifyNewEmailBodyType = z.infer<typeof VerifyNewEmailBodySchema>
