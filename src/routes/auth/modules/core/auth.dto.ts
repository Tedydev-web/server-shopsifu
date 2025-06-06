import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { UserAuthResponseSchema } from 'src/routes/auth/auth.model'
import { CompleteRegistrationSchema } from 'src/routes/auth/auth.model'
import { MessageResSchema } from 'src/shared/models/response.model'

// Register DTOs
export const InitiateRegistrationSchema = z.object({
  email: z.string().email()
})

export const RegistrationResponseSchema = MessageResSchema

// Login DTOs
export const LoginSchema = z.object({
  emailOrUsername: z.string().min(1, 'Email or username is required'),
  password: z.string().min(1, 'Password is required'),
  rememberMe: z.boolean().optional().default(false)
})

export const LoginResponseSchema = z.object({
  requiresTwoFactorAuth: z.boolean(),
  twoFactorMethod: z.string().nullable().optional(),
  requiresDeviceVerification: z.boolean(),
  message: z.string()
})

export const LoginResponseWithTokenSchema = LoginResponseSchema.extend({
  user: UserAuthResponseSchema,
  accessToken: z.string()
})

export const LoginWithOtpResponseSchema = z.object({
  requiresOtp: z.boolean(),
  message: z.string(),
  otpSentToEmail: z.string().optional()
})

// Refresh Token DTOs
export const RefreshTokenSchema = z.object({
  refreshToken: z.string().optional()
})

export const RefreshTokenResponseSchema = z.object({
  accessToken: z.string()
})

// Logout DTOs
export const LogoutSchema = z.object({
  refreshToken: z.string().optional()
})

export const LogoutResponseSchema = MessageResSchema

// Create DTO classes
export class InitiateRegistrationDto extends createZodDto(InitiateRegistrationSchema) {}
export class CompleteRegistrationDto extends createZodDto(CompleteRegistrationSchema) {}
export class LoginDto extends createZodDto(LoginSchema) {}
export class LoginResponseDto extends createZodDto(LoginResponseSchema) {}
export class LoginResponseWithTokenDto extends createZodDto(LoginResponseWithTokenSchema) {}
export class LoginWithOtpResponseDto extends createZodDto(LoginWithOtpResponseSchema) {}
export class RefreshTokenDto extends createZodDto(RefreshTokenSchema) {}
export class RefreshTokenResponseDto extends createZodDto(RefreshTokenResponseSchema) {}
export class LogoutDto extends createZodDto(LogoutSchema) {}
