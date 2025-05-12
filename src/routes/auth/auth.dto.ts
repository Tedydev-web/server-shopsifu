import { createZodDto } from 'nestjs-zod'
import {
  DisableTwoFactorBodySchema,
  ResetPasswordBodySchema,
  GetAuthorizationUrlResSchema,
  LoginBodySchema,
  LoginResSchema,
  LogoutBodySchema,
  RefreshTokenBodySchema,
  RefreshTokenResSchema,
  RegisterBodySchema,
  RegisterResSchema,
  SendOTPBodySchema,
  TwoFactorSetupResSchema,
  VerifyOTPBodySchema,
  VerifyOTPResSchema
} from 'src/routes/auth/auth.model'

export class RegisterBodyDTO extends createZodDto(RegisterBodySchema) {}

export class RegisterResDTO extends createZodDto(RegisterResSchema) {}

export class SendOTPBodyDTO extends createZodDto(SendOTPBodySchema) {}

export class LoginBodyDTO extends createZodDto(LoginBodySchema) {}

export class LoginResDTO extends createZodDto(LoginResSchema) {}

export class RefreshTokenBodyDTO extends createZodDto(RefreshTokenBodySchema) {}

export class RefreshTokenResDTO extends createZodDto(RefreshTokenResSchema) {}

export class LogoutBodyDTO extends createZodDto(LogoutBodySchema) {}

export class GetAuthorizationUrlResDTO extends createZodDto(GetAuthorizationUrlResSchema) {}

export class ResetPasswordBodyDTO extends createZodDto(ResetPasswordBodySchema) {}

export class TwoFactorSetupResDTO extends createZodDto(TwoFactorSetupResSchema) {}

export class DisableTwoFactorBodyDTO extends createZodDto(DisableTwoFactorBodySchema) {}

export class VerifyOTPBodyDTO extends createZodDto(VerifyOTPBodySchema) {}

export class VerifyOTPResDTO extends createZodDto(VerifyOTPResSchema) {}
