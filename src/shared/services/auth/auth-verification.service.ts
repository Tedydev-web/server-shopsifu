import { Injectable, Logger, Inject } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { REDIS_SERVICE, TOKEN_SERVICE, COOKIE_SERVICE } from 'src/shared/constants/injection.tokens'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import {
  TypeOfVerificationCodeType,
  TypeOfVerificationCode,
  TwoFactorMethodType
} from 'src/shared/constants/auth.constants'
import { UserAuthRepository } from 'src/shared/repositories/auth/user-auth.repository'
import { Request, Response } from 'express'
import { AuthError } from 'src/routes/auth/auth.error'
import { SltContextData } from 'src/routes/auth/auth.types'
import { I18nService } from 'nestjs-i18n'
import { SLTService } from './slt.service'

// Định nghĩa lại VerificationContext để tránh xung đột
export interface VerificationContextData {
  userId: number
  deviceId: number
  email: string
  ipAddress: string
  userAgent: string
  purpose: TypeOfVerificationCodeType
  metadata?: Record<string, any>
  rememberMe?: boolean
}

/**
 * Service xử lý các quá trình xác minh chung trong hệ thống xác thực
 * Không chứa trực tiếp các dependencies đến các service khác để tránh circular dependency
 */
@Injectable()
export class AuthVerificationService {
  private readonly logger = new Logger(AuthVerificationService.name)

  constructor(
    private readonly configService: ConfigService,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly i18nService: I18nService,
    private readonly sltService: SLTService,
    @Inject('IAuthVerificationService') private readonly verificationService: IAuthVerificationService
  ) {}

  /**
   * Xác thực context từ SLT cookie
   */
  async validateSltContext(
    sltCookieValue: string,
    ipAddress: string,
    userAgent: string,
    expectedPurpose?: TypeOfVerificationCodeType
  ): Promise<SltContextData & { sltJti: string }> {
    return this.sltService.validateSltFromCookieAndGetContext(sltCookieValue, ipAddress, userAgent, expectedPurpose)
  }

  /**
   * Tạo và lưu SLT token
   */
  async createVerificationToken(context: VerificationContextData): Promise<string> {
    return this.sltService.createAndStoreSltToken({
      userId: context.userId,
      deviceId: context.deviceId,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      purpose: context.purpose,
      metadata: context.metadata,
      email: context.email
    })
  }

  /**
   * Hoàn thành quá trình xác minh SLT
   */
  async finalizeSltVerification(sltJti: string): Promise<void> {
    return this.sltService.finalizeSlt(sltJti)
  }

  /**
   * Kiểm tra và lấy thông tin người dùng
   */
  async getUserInfo(userId: number): Promise<any> {
    const user = await this.userAuthRepository.findById(userId, {
      email: true,
      twoFactorEnabled: true,
      twoFactorSecret: true,
      twoFactorMethod: true,
      role: true
    })

    if (!user) {
      throw AuthError.EmailNotFound()
    }

    return user
  }

  /**
   * Thiết lập SLT cookie
   */
  setSltCookie(res: Response, sltToken: string, purpose: TypeOfVerificationCodeType): void {
    this.cookieService.setSltCookie(res, sltToken, purpose)
  }

  /**
   * Xóa SLT cookie
   */
  clearSltCookie(res: Response): void {
    this.cookieService.clearSltCookie(res)
  }

  /**
   * Thiết lập token cookies
   */
  setTokenCookies(res: Response, accessToken: string, refreshToken: string, maxAge?: number): void {
    this.cookieService.setTokenCookies(res, accessToken, refreshToken, maxAge)
  }

  /**
   * Xóa token cookies
   */
  clearTokenCookies(res: Response): void {
    this.cookieService.clearTokenCookies(res)
  }

  /**
   * Khởi tạo quá trình xác thực thích hợp dựa vào loại xác thực và trạng thái 2FA
   * Ủy quyền cho IAuthVerificationService
   */
  async initiateVerification(context: VerificationContextData, res: Response): Promise<VerificationResult> {
    return this.verificationService.initiateVerification(context, res)
  }

  /**
   * Xác minh mã OTP hoặc 2FA
   * Ủy quyền cho IAuthVerificationService
   */
  async verifyCode(
    sltCookieValue: string,
    code: string,
    ipAddress: string,
    userAgent: string,
    req: Request,
    res: Response
  ): Promise<VerificationResult> {
    return this.verificationService.verifyCode(sltCookieValue, code, ipAddress, userAgent, req, res)
  }
}
