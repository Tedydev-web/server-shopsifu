import { createZodDto } from 'nestjs-zod'
import {
  DisableTwoFactorBodySchema,
  GetAuthorizationUrlResSchema,
  LoginBodySchema,
  LoginSessionResSchema,
  LogoutBodySchema,
  RefreshTokenBodySchema,
  RegisterBodySchema,
  RegisterResSchema,
  ResetPasswordBodySchema,
  SendOTPBodySchema,
  TwoFactorConfirmSetupBodySchema,
  TwoFactorConfirmSetupResSchema,
  TwoFactorSetupResSchema,
  TwoFactorVerifyBodySchema,
  UserProfileResSchema,
  VerifyCodeBodySchema,
  VerifyCodeResSchema,
  AccessTokenResSchema,
  RememberMeBodySchema,
  RefreshTokenSuccessResSchema,
  ChangePasswordBodySchema
} from 'src/routes/auth/auth.model'
import { MessageResSchema } from 'src/shared/models/response.model'
import { z } from 'zod'

export class RegisterBodyDTO extends createZodDto(RegisterBodySchema) {}

export class RegisterResDTO extends createZodDto(RegisterResSchema) {}

export class SendOTPBodyDTO extends createZodDto(SendOTPBodySchema) {}

export class LoginBodyDTO extends createZodDto(LoginBodySchema) {}

export class LoginResDTO extends createZodDto(UserProfileResSchema) {}

export class LoginSessionResDTO extends createZodDto(LoginSessionResSchema) {}

export class RefreshTokenBodyDTO extends createZodDto(RefreshTokenBodySchema) {}

export class RefreshTokenResDTO extends createZodDto(AccessTokenResSchema) {}

export class LogoutBodyDTO extends createZodDto(LogoutBodySchema) {}

export class GetAuthorizationUrlResDTO extends createZodDto(GetAuthorizationUrlResSchema) {}

export class ResetPasswordBodyDTO extends createZodDto(ResetPasswordBodySchema) {}

export class TwoFactorSetupResDTO extends createZodDto(TwoFactorSetupResSchema) {}

export class TwoFactorConfirmSetupBodyDTO extends createZodDto(TwoFactorConfirmSetupBodySchema) {}

export class TwoFactorConfirmSetupResDTO extends createZodDto(TwoFactorConfirmSetupResSchema) {}

export class DisableTwoFactorBodyDTO extends createZodDto(DisableTwoFactorBodySchema) {}

export class VerifyCodeBodyDTO extends createZodDto(VerifyCodeBodySchema) {}

export class VerifyCodeResDTO extends createZodDto(VerifyCodeResSchema) {}

export class TwoFactorVerifyBodyDTO extends createZodDto(TwoFactorVerifyBodySchema) {}

export class UserProfileResDTO extends createZodDto(UserProfileResSchema) {}

export class RememberMeBodyDTO extends createZodDto(RememberMeBodySchema) {}

export class RefreshTokenSuccessResDTO extends createZodDto(RefreshTokenSuccessResSchema) {}

export class ChangePasswordBodyDTO extends createZodDto(ChangePasswordBodySchema) {}

export class MessageResDTO extends createZodDto(MessageResSchema) {}

export const ReverifyPasswordBodySchema = z.discriminatedUnion('verificationMethod', [
  z.object({
    verificationMethod: z.literal('password'),
    password: z.string().min(1, 'Password is required')
  }),
  z.object({
    verificationMethod: z.literal('otp'),
    otpCode: z.string().min(6, 'OTP code must be at least 6 characters').max(8, 'OTP code must be at most 8 characters')
  }),
  z.object({
    verificationMethod: z.literal('totp'),
    totpCode: z.string().length(6, 'TOTP code must be 6 characters')
  }),
  z.object({
    verificationMethod: z.literal('recovery'),
    recoveryCode: z.string().min(1, 'Recovery code is required')
  })
])

export type ReverifyPasswordBodyType = z.infer<typeof ReverifyPasswordBodySchema>

export type ChangePasswordBodyType = z.infer<typeof ChangePasswordBodySchema>
