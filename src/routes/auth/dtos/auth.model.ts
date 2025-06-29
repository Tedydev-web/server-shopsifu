import { z } from 'zod'
import {
  RegisterBodySchema,
  VerificationCodeSchema,
  SendOTPBodySchema,
  LoginBodySchema,
  RefreshTokenSchema,
  RefreshTokenBodySchema,
  RoleSchema,
  LogoutBodySchema,
  GoogleAuthStateSchema,
  GetAuthorizationUrlResSchema,
  ForgotPasswordBodySchema,
  DisableTwoFactorBodySchema,
  TwoFactorSetupResSchema,
} from './auth.schema'

export type RegisterBodyType = z.infer<typeof RegisterBodySchema>
export type VerificationCodeType = z.infer<typeof VerificationCodeSchema>
export type SendOTPBodyType = z.infer<typeof SendOTPBodySchema>
export type LoginBodyType = z.infer<typeof LoginBodySchema>
export type RefreshTokenType = z.infer<typeof RefreshTokenSchema>
export type RefreshTokenBodyType = z.infer<typeof RefreshTokenBodySchema>
export type RoleType = z.infer<typeof RoleSchema>
export type LogoutBodyType = z.infer<typeof LogoutBodySchema>
export type GoogleAuthStateType = z.infer<typeof GoogleAuthStateSchema>
export type GetAuthorizationUrlResType = z.infer<typeof GetAuthorizationUrlResSchema>
export type ForgotPasswordBodyType = z.infer<typeof ForgotPasswordBodySchema>
export type DisableTwoFactorBodyType = z.infer<typeof DisableTwoFactorBodySchema>
export type TwoFactorSetupResType = z.infer<typeof TwoFactorSetupResSchema>
