import { createZodDto } from 'nestjs-zod'
import {
  DisableTwoFactorBodySchema,
  GetAuthorizationUrlResSchema,
  LoginBodySchema,
  LoginResSchema,
  LoginSessionResSchema,
  LogoutBodySchema,
  RefreshTokenBodySchema,
  RefreshTokenResSchema,
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
  VerifyCodeResSchema
} from 'src/routes/auth/auth.model'

export class RegisterBodyDTO extends createZodDto(RegisterBodySchema) {}

export class RegisterResDTO extends createZodDto(RegisterResSchema) {}

export class SendOTPBodyDTO extends createZodDto(SendOTPBodySchema) {}

export class LoginBodyDTO extends createZodDto(LoginBodySchema) {}

export class LoginResDTO extends createZodDto(LoginResSchema) {}

export class LoginSessionResDTO extends createZodDto(LoginSessionResSchema) {}

export class RefreshTokenBodyDTO extends createZodDto(RefreshTokenBodySchema) {}

export class RefreshTokenResDTO extends createZodDto(RefreshTokenResSchema) {}

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
