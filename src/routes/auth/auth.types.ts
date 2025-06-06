import { z } from 'zod'
import { TypeOfVerificationCodeType, TwoFactorMethodTypeType } from 'src/shared/constants/auth.constants'
import { AccessTokenPayload } from './shared/jwt.type'
import { User, Device, Role, UserProfile } from '@prisma/client'
import { PrismaTransactionClient } from 'src/shared/types/prisma.type'
import {
  RegisterBodyType,
  LoginBodyType,
  DisableTwoFactorBodyType,
  TwoFactorVerifyBodyType,
  ResetPasswordBodyType
} from './auth.model'

// OTP related
export interface OtpData {
  code: string
  attempts: number
  createdAt: number
  userId?: number
  deviceId?: number
  metadata?: Record<string, any>
}

// SLT Token related
export interface SltJwtPayload {
  jti: string
  sub: number
  pur: TypeOfVerificationCodeType
  exp?: number
}

export interface SltContextData {
  userId: number
  deviceId: number
  ipAddress: string
  userAgent: string
  purpose: TypeOfVerificationCodeType
  sltJwtExp?: number
  sltJwtCreatedAt?: number
  finalized?: '0' | '1'
  attempts: number
  metadata?: Record<string, any> & { twoFactorMethod?: TwoFactorMethodTypeType }
  email?: string
  createdAt?: Date
}

// Google Auth related
export interface GoogleCallbackSuccessResult {
  user: User & { role: Role; userProfile: UserProfile | null }
  device: Device
  requiresTwoFactorAuth: boolean
  requiresUntrustedDeviceVerification: boolean
  twoFactorMethod?: TwoFactorMethodTypeType | null
  isLoginViaGoogle: true
  message: string
}

export interface GoogleCallbackErrorResult {
  errorCode: string
  errorMessage: string
  redirectToError: true
}

export interface GoogleCallbackAccountExistsWithoutLinkResult {
  needsLinking: true
  existingUserId: number
  existingUserEmail: string
  googleId: string
  googleEmail: string
  googleName?: string | null
  googleAvatar?: string | null
  message: string
}

export type GoogleCallbackReturnType =
  | GoogleCallbackSuccessResult
  | GoogleCallbackErrorResult
  | GoogleCallbackAccountExistsWithoutLinkResult

// Authentication related
export interface AuthResult {
  accessToken: string
  refreshToken: string
  user: {
    id: number
    email: string
    role: string
    isDeviceTrustedInSession: boolean
    userProfile: UserProfile | null
  }
}

// Cookie related
export interface CookieConfig {
  name: string
  path: string
  domain?: string
  maxAge: number
  httpOnly: boolean
  secure: boolean
  sameSite: 'lax' | 'strict' | 'none' | boolean
}

// Session finalization
export interface FinalizeAuthParams {
  user: User & { role: { id: number; name: string }; userProfile: UserProfile | null }
  device: Device
  rememberMe: boolean
  ipAddress: string
  userAgent: string
  source: string
  res: Response
  sltToFinalize?: {
    jti: string
    purpose?: TypeOfVerificationCodeType
  }
  tx?: PrismaTransactionClient
  existingSessionId?: string
}

// Export các types từ model
export { RegisterBodyType, LoginBodyType, DisableTwoFactorBodyType, TwoFactorVerifyBodyType, ResetPasswordBodyType }
