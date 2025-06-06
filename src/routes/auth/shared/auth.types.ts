import { Device, Role, User, UserProfile } from '@prisma/client'
import { Response, Request } from 'express'
import { TypeOfVerificationCodeType, TwoFactorMethodTypeType } from 'src/routes/auth/shared/constants/auth.constants'
import { PrismaTransactionClient } from 'src/shared/types/prisma.type'

/**
 * Auth Provider Interface - Định nghĩa các methods cho authentication provider
 */
export interface IAuthProvider {
  verifyToken(token: string): Promise<any>
  createToken(payload: any): string
  extractTokenFromRequest(req: any): string | null
}

/**
 * User Auth Service Interface - Định nghĩa các methods chính cho user authentication
 */
export interface IUserAuthService {
  validateUser(username: string, password: string): Promise<any>
  login(params: any, res: Response): Promise<any>
  refreshToken(refreshToken: string, deviceInfo: any, res: Response): Promise<any>
  logout(userId: number, sessionId: string, req?: Request, res?: Response): Promise<void>
}

/**
 * OTP Service Interface - Định nghĩa các methods cho OTP service
 */
export interface IOTPService {
  generateOTP(length?: number): string
  sendOTP(
    targetEmail: string,
    type: TypeOfVerificationCodeType,
    userIdForCooldownAndOtpData?: number,
    metadata?: Record<string, any>
  ): Promise<{ message: string; otpCode: string }>
  verifyOTP(
    emailToVerifyAgainst: string,
    code: string,
    type: TypeOfVerificationCodeType,
    userIdForAudit?: number,
    ip?: string,
    userAgent?: string
  ): Promise<boolean>
}

/**
 * Short-Lived Token (SLT) Service Interface
 */
export interface ISLTService {
  createAndStoreSltToken(payload: {
    userId: number
    deviceId: number
    ipAddress: string
    userAgent: string
    purpose: TypeOfVerificationCodeType
    email?: string
    metadata?: Record<string, any>
  }): Promise<string>

  validateSltFromCookieAndGetContext(
    sltCookieValue: string,
    currentIpAddress: string,
    currentUserAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType
  ): Promise<SltContextData & { sltJti: string }>

  updateSltContext(jti: string, updateData: Partial<SltContextData>): Promise<void>

  finalizeSlt(jti: string): Promise<void>

  incrementSltAttempts(sltJti: string): Promise<number>
}

/**
 * Interface cho Session Service
 */
export interface ISessionService {
  getSessions(
    userId: number,
    currentPage?: number,
    itemsPerPage?: number,
    currentSessionIdFromToken?: string
  ): Promise<any>

  revokeItems(
    userId: number,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    currentSessionDetails?: { sessionId?: string; deviceId?: number },
    verificationToken?: string,
    otpCode?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<any>

  invalidateSession(sessionId: string, reason?: string): Promise<void>

  isSessionInvalidated(sessionId: string): Promise<boolean>

  invalidateAllUserSessions(userId: number, reason?: string, sessionIdToExclude?: string): Promise<{ count: number }>
}

/**
 * Interface cho Device Service
 */
export interface IDeviceService {
  findById(deviceId: number): Promise<any>

  updateDeviceTrustStatus(deviceId: number, isTrusted: boolean): Promise<any>

  isDeviceTrustValid(deviceId: number): Promise<boolean>

  markDeviceForReverification(userId: number, deviceId: number, reasonInput: string): Promise<void>

  checkDeviceNeedsReverification(userId: number, deviceId: number): Promise<boolean>

  clearDeviceReverification(userId: number, deviceId: number): Promise<void>
}

/**
 * Cookie Service Interface
 */
export interface ICookieService {
  setAccessTokenCookie(res: Response, accessToken: string): void
  setRefreshTokenCookie(res: Response, refreshToken: string, rememberMe?: boolean): void
  clearAccessTokenCookie(res: Response): void
  clearRefreshTokenCookie(res: Response): void
  setCsrfCookie(res: Response, csrfToken: string): void
  setSltCookie(res: Response, sltToken: string, purpose: TypeOfVerificationCodeType): void
  clearSltCookie(res: Response): void

  // Các phương thức cần bổ sung
  setTokenCookies(res: Response, accessToken: string, refreshToken: string, maxAgeForRefreshTokenCookie?: number): void
  clearTokenCookies(res: Response): void
  setOAuthNonceCookie(res: Response, nonce: string): void
  clearOAuthNonceCookie(res: Response): void
  setOAuthPendingLinkTokenCookie(res: Response, token: string): void
  clearOAuthPendingLinkTokenCookie(res: Response): void
}

/**
 * Token Service Interface
 */
export interface ITokenService {
  generateAccessToken(userId: number, expiresIn?: string): Promise<string>
  generateRefreshToken(userId: number, rememberMe?: boolean): Promise<string>
  validateAccessToken(token: string): Promise<any>
  validateRefreshToken(refreshToken: string): Promise<any>
  signAccessToken(payload: any): string
  signRefreshToken(payload: any): string
  signPendingLinkToken(payload: any): string
  signShortLivedToken(payload: any): string
  verifyAccessToken(token: string): Promise<any>
  verifyRefreshToken(token: string): Promise<any>
  verifyPendingLinkToken(token: string): Promise<any>
  extractTokenFromRequest(req: Request): string | null
  extractRefreshTokenFromRequest(req: Request): string | null
  invalidateAccessTokenJti(accessTokenJti: string, accessTokenExp: number): Promise<void>
  invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string): Promise<void>
  isAccessTokenJtiBlacklisted(accessTokenJti: string): Promise<boolean>
  isRefreshTokenJtiBlacklisted(refreshTokenJti: string): Promise<boolean>
  markRefreshTokenJtiAsUsed(refreshTokenJti: string, sessionId: string, ttlSeconds?: number): Promise<boolean>
}

/**
 * Interface cho các service xác thực
 */
export interface IVerificationService {
  // Giai đoạn thiết lập và cấu hình
  generateSetupDetails?(userId: number, options?: any): Promise<any>

  // Xác minh mã đã nhập
  verifyCode(code: string, context: any): Promise<boolean>

  // Tạo mã xác thực mới (nếu áp dụng)
  generateVerificationCode(options?: any): Promise<string>

  // Vô hiệu hóa phương thức xác thực
  disableVerification(userId: number): Promise<void>
}

/**
 * Interface cho service xác thực hai yếu tố
 */
export interface IMultiFactorService extends IVerificationService {
  // Tạo lại các mã khôi phục
  regenerateRecoveryCodes(userId: number, verificationCode: string): Promise<string[]>

  // Xác minh mã thông qua phương thức cụ thể
  verifyByMethod(method: string, code: string, userId: number): Promise<{ success: boolean; method: string }>
}

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
  isNewUser: boolean
  purpose: TypeOfVerificationCodeType
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

export interface CookieConfig {
  name: string
  path: string
  domain?: string
  maxAge: number
  httpOnly: boolean
  secure: boolean
  sameSite: 'lax' | 'strict' | 'none' | boolean
}

// --- From jwt.type.ts ---

/**
 * Định nghĩa payload của Access Token khi tạo mới
 */
export interface AccessTokenPayloadCreate {
  userId: number
  deviceId?: number
  roleId?: number
  roleName?: string
  sessionId?: string
  jti: string
  isDeviceTrustedInSession?: boolean
  email?: string
  type?: 'ACCESS' | 'REFRESH'
  rememberMe?: boolean
  exp?: number
  iat?: number
}

/**
 * Định nghĩa payload của Access Token khi đã được verify
 */
export interface AccessTokenPayload extends Omit<AccessTokenPayloadCreate, 'exp' | 'iat'> {
  deviceId: number
  roleId: number
  roleName: string
  sessionId: string
  isDeviceTrustedInSession: boolean
  exp: number
  iat: number
}

/**
 * Định nghĩa cho Pending Link Token
 */
export interface PendingLinkTokenPayloadCreate {
  existingUserId: number
  googleId: string
  googleEmail: string
  googleName?: string | null
  googleAvatar?: string | null
}

export interface PendingLinkTokenPayload extends PendingLinkTokenPayloadCreate {
  jti: string
  exp: number
  iat: number
}
