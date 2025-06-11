import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { UserStatus } from '@prisma/client'

const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters long')
  .max(100, 'Password must be at most 100 characters long')

// ================================================================
// Enhanced Create User Schema - More comprehensive than registration
// ================================================================
export const CreateUserSchema = z.object({
  // Basic User Information
  email: z.string().email('Email không hợp lệ'),
  password: passwordSchema,
  roleId: z.number().int().positive('Role ID phải là số nguyên dương'),
  status: z.nativeEnum(UserStatus).optional().default('PENDING_VERIFICATION'),

  // User Profile Information
  firstName: z.string().min(1, 'Tên không được để trống').max(100).optional(),
  lastName: z.string().min(1, 'Họ không được để trống').max(100).optional(),
  username: z.string().min(3, 'Username phải có ít nhất 3 ký tự').max(50).optional(),
  phoneNumber: z
    .string()
    .regex(/^(\+84|84|0)[1-9]\d{8,9}$/, 'Số điện thoại không hợp lệ')
    .optional(),

  // Additional Profile Fields
  bio: z.string().max(500, 'Bio không được vượt quá 500 ký tự').optional(),
  avatar: z.string().url('Avatar phải là URL hợp lệ').optional(),
  countryCode: z.string().max(10).optional().default('VN'),

  // Verification and Security
  isEmailVerified: z.boolean().optional().default(false),
  requireEmailVerification: z.boolean().optional().default(true)
})

// ================================================================
// Initiate User Creation Schema - For OTP flow
// ================================================================
export const InitiateUserCreationSchema = CreateUserSchema.omit({
  requireEmailVerification: true
})
  .extend({
    confirmPassword: z.string().min(8, 'Xác nhận mật khẩu phải có ít nhất 8 ký tự')
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Mật khẩu xác nhận không khớp',
    path: ['confirmPassword']
  })

// ================================================================
// Complete User Creation Schema - After OTP verification
// ================================================================
export const CompleteUserCreationSchema = z.object({
  otpCode: z.string().length(6, 'Mã OTP phải có 6 chữ số')
})

export const UpdateUserSchema = CreateUserSchema.partial()
  .extend({
    // Email cập nhật qua flow riêng để tránh xung đột
    email: z.string().email().optional().describe('Email update requires separate verification flow'),
    password: passwordSchema.optional(),
    confirmPassword: z.string().optional()
  })
  .refine(
    (data) => {
      if (data.password && data.confirmPassword) {
        return data.password === data.confirmPassword
      }
      return true
    },
    {
      message: 'Mật khẩu xác nhận không khớp',
      path: ['confirmPassword']
    }
  )

// ================================================================
// Response Schema - Enhanced with profile
// ================================================================
export const UserResponseSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  status: z.nativeEnum(UserStatus),
  roleId: z.number().nullable(),
  isEmailVerified: z.boolean(),
  createdAt: z.date(),
  updatedAt: z.date(),
  userProfile: z
    .object({
      firstName: z.string().nullable(),
      lastName: z.string().nullable(),
      username: z.string().nullable(),
      phoneNumber: z.string().nullable(),
      bio: z.string().nullable(),
      avatar: z.string().nullable(),
      countryCode: z.string().nullable(),
      isPhoneNumberVerified: z.boolean()
    })
    .nullable()
})

// ================================================================
// DTO Classes
// ================================================================
export class CreateUserDto extends createZodDto(CreateUserSchema) {}

export class InitiateUserCreationDto extends createZodDto(InitiateUserCreationSchema) {}

export class CompleteUserCreationDto extends createZodDto(CompleteUserCreationSchema) {}

export class UpdateUserDto extends createZodDto(UpdateUserSchema) {}

export class UserDto extends createZodDto(UserResponseSchema) {
  constructor(partial: Partial<UserDto>) {
    super()
    Object.assign(this, partial)
  }

  static fromEntity(entity: any): UserDto {
    return new UserDto({
      id: entity.id,
      email: entity.email,
      status: entity.status,
      roleId: entity.roleId,
      isEmailVerified: entity.isEmailVerified || false,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
      userProfile: entity.userProfile
        ? {
            firstName: entity.userProfile.firstName,
            lastName: entity.userProfile.lastName,
            username: entity.userProfile.username,
            phoneNumber: entity.userProfile.phoneNumber,
            bio: entity.userProfile.bio,
            avatar: entity.userProfile.avatar,
            countryCode: entity.userProfile.countryCode,
            isPhoneNumberVerified: entity.userProfile.isPhoneNumberVerified || false
          }
        : null
    })
  }
}
