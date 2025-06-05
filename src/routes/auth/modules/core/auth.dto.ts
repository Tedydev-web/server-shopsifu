import { createZodDto } from 'nestjs-zod'
import { z } from 'zod'
import { LoginBodySchema, UserAuthResponseSchema, CompleteRegistrationSchema } from 'src/routes/auth/auth.model'
import { MessageResSchema } from 'src/shared/models/response.model'

// Register DTOs
export const InitiateRegistrationSchema = z.object({
  email: z.string().email()
})

export const RegistrationResponseSchema = MessageResSchema

// Login DTOs
export const LoginSchema = LoginBodySchema

export const LoginResponseSchema = UserAuthResponseSchema

export const LoginResponseWithTokenSchema = LoginResponseSchema.extend({
  accessToken: z.string(),
  refreshToken: z.string()
})

export const LoginWithOtpResponseSchema = z.object({
  message: z.string(),
  requiresOtp: z.literal(true),
  requiresTwoFactor: z.boolean().optional(),
  email: z.string().email()
})

// Refresh Token DTOs
export const RefreshTokenSchema = z.object({
  refreshToken: z.string().optional()
})

export const RefreshTokenResponseSchema = z.object({
  message: z.string(),
  accessToken: z.string().optional()
})

// Logout DTOs
export const LogoutSchema = z.object({})

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
