import { Device } from '@prisma/client'
import { Response, Request } from 'express'
import { AccessTokenPayload } from './jwt.type'

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
  sendOTP(email: string, type: string, userId?: number): Promise<any>
  verifyOTP(
    email: string,
    code: string,
    type: string,
    userId?: number,
    ip?: string,
    userAgent?: string
  ): Promise<boolean>
}

/**
 * Session Service Interface
 */
export interface ISessionService {
  getSessions(userId: number, page?: number, limit?: number, currentSessionIdFromToken?: string): Promise<any>
  revokeSession(userId: number, sessionId: string, currentSessionId?: string): Promise<any>
  revokeItems(userId: number, options: any, activeUser: AccessTokenPayload): Promise<any>
}

/**
 * Device Service Interface
 */
export interface IDeviceService {
  findById(deviceId: number): Promise<Device | null>
  upsertDevice(userId: number, userAgent: string, ipAddress: string, name?: string): Promise<Device>
  updateDeviceTrustStatus(deviceId: number, isTrusted: boolean): Promise<Device>
  updateDeviceName(deviceId: number, name: string): Promise<Device>
}

/**
 * Cookie Service Interface
 */
export interface ICookieService {
  setTokenCookies(res: Response, accessToken: string, refreshToken: string, maxAge?: number): void
  clearTokenCookies(res: Response): void
  setSltCookie(res: Response, token: string, purpose: string): void
  clearSltCookie(res: Response): void
  setOAuthNonceCookie(res: Response, nonce: string): void
  clearOAuthNonceCookie(res: Response): void
  setOAuthPendingLinkTokenCookie(res: Response, token: string): void
  clearOAuthPendingLinkTokenCookie(res: Response): void
}

/**
 * Token Service Interface
 */
export interface ITokenService {
  signAccessToken(payload: any): string
  signRefreshToken(payload: any): string
  verifyAccessToken(token: string): Promise<any>
  verifyRefreshToken(token: string): Promise<any>
  invalidateSession(sessionId: string, reason?: string): Promise<void>
  extractTokenFromRequest(req: Request): string | null
  extractRefreshTokenFromRequest(req: Request): string | null
  invalidateAccessTokenJti(accessTokenJti: string, accessTokenExp: number): Promise<void>
  invalidateRefreshTokenJti(refreshTokenJti: string, sessionId: string): Promise<void>
  isAccessTokenJtiBlacklisted(accessTokenJti: string): Promise<boolean>
  isRefreshTokenJtiBlacklisted(refreshTokenJti: string): Promise<boolean>
  markRefreshTokenJtiAsUsed(refreshTokenJti: string, sessionId: string, ttlSeconds?: number): Promise<boolean>
  isSessionInvalidated(sessionId: string): Promise<boolean>
}
