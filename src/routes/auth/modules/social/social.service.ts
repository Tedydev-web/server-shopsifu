import { Injectable, Logger } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { CookieService } from 'src/routes/auth/shared/cookie/cookie.service'
import { I18nService } from 'nestjs-i18n'
import { HashingService } from 'src/shared/services/hashing.service'
import { Response, Request } from 'express'
import * as crypto from 'crypto'
import { OAuth2Client, TokenPayload } from 'google-auth-library'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'
import { AuthError } from 'src/routes/auth/auth.error'
import { CookieNames } from 'src/shared/constants/auth.constant'
import { UserAuthRepository } from '../../repositories/user-auth.repository'
import { DeviceRepository } from '../../repositories/device.repository'

export interface GoogleCallbackSuccessResult {
  user: any
  device: any
  requiresTwoFactorAuth: boolean
  requiresUntrustedDeviceVerification: boolean
  twoFactorMethod?: string | null
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

interface GoogleAuthStateType {
  nonce: string
  flow?: string
  userId?: number
}

@Injectable()
export class SocialService {
  private readonly logger = new Logger(SocialService.name)
  private oauth2Client: OAuth2Client

  constructor(
    private readonly configService: ConfigService,
    private readonly tokenService: TokenService,
    private readonly cookieService: CookieService,
    private readonly i18nService: I18nService,
    private readonly hashingService: HashingService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly deviceRepository: DeviceRepository
  ) {
    // Khởi tạo OAuth2Client
    this.oauth2Client = new OAuth2Client(
      this.configService.get<string>('oauth.google.clientId'),
      this.configService.get<string>('oauth.google.clientSecret'),
      this.configService.get<string>('oauth.google.redirectUri')
    )
  }

  /**
   * Lấy URL xác thực Google
   */
  getGoogleAuthUrl(stateParams: GoogleAuthStateType): { url: string; nonce: string } {
    const nonce = stateParams.nonce || crypto.randomBytes(16).toString('hex')

    const state = Buffer.from(
      JSON.stringify({
        nonce,
        flow: stateParams.flow || 'login',
        userId: stateParams.userId
      })
    ).toString('base64')

    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
      state,
      prompt: 'consent'
    })

    return { url, nonce }
  }

  /**
   * Lấy tokens Google
   */
  async getGoogleTokens(code: string) {
    try {
      const { tokens } = await this.oauth2Client.getToken(code)
      return tokens
    } catch (error) {
      this.logger.error(`Lỗi lấy Google tokens: ${error.message}`)
      throw error
    }
  }

  /**
   * Xác minh Google ID token
   */
  async verifyGoogleIdToken(idToken: string): Promise<TokenPayload | undefined> {
    try {
      const ticket = await this.oauth2Client.verifyIdToken({
        idToken,
        audience: this.configService.get<string>('oauth.google.clientId')
      })
      return ticket.getPayload()
    } catch (error) {
      this.logger.error(`Lỗi xác minh Google ID token: ${error.message}`)
      return undefined
    }
  }

  /**
   * Xử lý callback từ Google
   */
  async googleCallback({
    code,
    state,
    userAgent = 'Unknown',
    ip = 'Unknown'
  }: {
    code: string
    state: string
    userAgent?: string
    ip?: string
  }): Promise<GoogleCallbackReturnType> {
    try {
      // Giải mã state
      const decodedState = JSON.parse(Buffer.from(state, 'base64').toString()) as GoogleAuthStateType
      const { flow, nonce, userId } = decodedState

      // Lấy tokens
      const tokens = await this.getGoogleTokens(code)
      const idToken = tokens.id_token

      if (!idToken) {
        return {
          errorCode: 'MISSING_ID_TOKEN',
          errorMessage: await this.i18nService.translate('Auth.Error.InvalidToken'),
          redirectToError: true
        }
      }

      // Xác minh ID token
      const payload = await this.verifyGoogleIdToken(idToken)

      if (!payload) {
        return {
          errorCode: 'INVALID_ID_TOKEN',
          errorMessage: await this.i18nService.translate('Auth.Error.InvalidToken'),
          redirectToError: true
        }
      }

      const { sub: googleId, email: googleEmail, name: googleName, picture: googleAvatar } = payload

      // Kiểm tra email đã được xác minh chưa
      if (!payload.email_verified) {
        return {
          errorCode: 'EMAIL_NOT_VERIFIED',
          errorMessage: await this.i18nService.translate('Auth.Error.EmailNotVerified'),
          redirectToError: true
        }
      }

      // Tìm user bằng googleId
      let user = await this.userAuthRepository.findByGoogleId(googleId || '')

      // Tìm user bằng email
      if (!user && googleEmail) {
        const existingUserByEmail = await this.userAuthRepository.findByEmail(googleEmail)

        // Nếu có user với email này nhưng chưa liên kết với Google
        if (existingUserByEmail) {
          return {
            needsLinking: true,
            existingUserId: existingUserByEmail.id,
            existingUserEmail: existingUserByEmail.email,
            googleId: googleId || '',
            googleEmail: googleEmail,
            googleName: googleName || null,
            googleAvatar: googleAvatar || null,
            message: await this.i18nService.translate('Auth.Google.AccountNeedsLinking')
          }
        }

        // Nếu đang đăng nhập hoặc liên kết tài khoản, không tạo tài khoản mới
        if (flow === 'login' || flow === 'link') {
          return {
            errorCode: 'ACCOUNT_NOT_FOUND',
            errorMessage: await this.i18nService.translate('Auth.Error.AccountNotFound'),
            redirectToError: true
          }
        }

        // Tạo user mới nếu có email
        user = await this.createUserFromGoogle(googleId || '', googleEmail, googleName, googleAvatar)
      }

      if (!user) {
        return {
          errorCode: 'ACCOUNT_NOT_FOUND',
          errorMessage: await this.i18nService.translate('Auth.Error.AccountNotFound'),
          redirectToError: true
        }
      }

      // Tạo hoặc tìm device
      const device = await this.deviceRepository.upsertDevice(user.id, userAgent || 'unknown', ip || 'unknown')

      // Kiểm tra 2FA
      const requiresTwoFactorAuth = !!user.twoFactorEnabled && !!user.twoFactorSecret

      // Kiểm tra thiết bị đã được tin tưởng chưa
      const requiresUntrustedDeviceVerification = !device.isTrusted

      return {
        user,
        device,
        requiresTwoFactorAuth,
        requiresUntrustedDeviceVerification,
        twoFactorMethod: user.twoFactorMethod,
        isLoginViaGoogle: true,
        message: await this.i18nService.translate('Auth.Google.LoginSuccess')
      }
    } catch (error) {
      this.logger.error(`Lỗi trong Google callback: ${error.message}`)
      return {
        errorCode: 'INTERNAL_ERROR',
        errorMessage: await this.i18nService.translate('Auth.Error.InternalServerError'),
        redirectToError: true
      }
    }
  }

  /**
   * Tạo user từ thông tin Google
   */
  private async createUserFromGoogle(googleId: string, email: string, name?: string, avatar?: string) {
    const nameParts = name ? name.split(' ') : ['', '']
    const lastName = nameParts.length > 1 ? nameParts.pop() || '' : ''
    const firstName = nameParts.join(' ')

    // Tạo user mới
    return this.userAuthRepository.createUser({
      email,
      password: '', // Không có mật khẩu khi đăng ký bằng Google
      firstName,
      lastName,
      googleId,
      googleAvatar: avatar
    })
  }

  /**
   * Hoàn tất đăng nhập thành công và trả về thông tin người dùng
   */
  finalizeSuccessfulAuth(user: any, device: any, rememberMe: boolean, res: Response) {
    // Tạo session ID
    const sessionId = uuidv4()

    // Tạo payload cho access token
    const payload = {
      userId: user.id,
      email: user.email,
      roleId: user.roleId,
      roleName: user.role?.name || 'USER',
      deviceId: device.id,
      sessionId: device.sessionId || sessionId,
      jti: `access_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`,
      isDeviceTrustedInSession: !!device.isTrusted
    }

    // Tạo tokens
    const accessToken = this.tokenService.signAccessToken(payload)
    const refreshToken = this.tokenService.signRefreshToken({
      ...payload,
      jti: `refresh_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`
    })

    // Set cookie
    this.cookieService.setTokenCookies(
      res,
      accessToken,
      refreshToken,
      rememberMe ? 30 * 24 * 60 * 60 * 1000 : undefined
    )

    // Trả về thông tin user
    return {
      id: user.id,
      email: user.email,
      role: user.role?.name || 'USER',
      isDeviceTrustedInSession: !!device.isTrusted,
      userProfile: user.userProfile || {
        firstName: null,
        lastName: null,
        username: null,
        avatar: null
      }
    }
  }

  /**
   * Liên kết tài khoản Google
   */
  async linkGoogleAccount(userId: number, googleIdToken: string): Promise<{ message: string }> {
    // Xác minh ID token
    const payload = await this.verifyGoogleIdToken(googleIdToken)

    if (!payload) {
      throw AuthError.InvalidSocialToken()
    }

    const { sub: googleId, email: googleEmail } = payload

    // Kiểm tra email đã được xác minh chưa
    if (!payload.email_verified) {
      throw AuthError.InvalidSocialToken()
    }

    // Kiểm tra tài khoản Google đã được liên kết với user khác chưa
    const existingUserWithGoogleId = await this.userAuthRepository.findByGoogleId(googleId || '')

    if (existingUserWithGoogleId && existingUserWithGoogleId.id !== userId) {
      throw AuthError.GoogleAccountAlreadyLinked()
    }

    // Cập nhật user
    await this.userAuthRepository.updateGoogleId(userId, googleId || '')

    return {
      message: await this.i18nService.translate('Auth.Google.LinkSuccess')
    }
  }

  /**
   * Lấy thông tin liên kết đang chờ
   */
  async getPendingLinkDetails(req: Request): Promise<any> {
    const pendingLinkToken = req.cookies?.[CookieNames.OAUTH_PENDING_LINK]

    if (!pendingLinkToken) {
      throw AuthError.MissingAccessToken()
    }

    try {
      const payload = await this.tokenService.verifyPendingLinkToken(pendingLinkToken)

      return {
        existingUserId: payload.existingUserId,
        existingUserEmail: payload.googleEmail, // Sử dụng googleEmail thay vì existingUserEmail
        googleId: payload.googleId,
        googleEmail: payload.googleEmail,
        googleName: payload.googleName,
        googleAvatar: payload.googleAvatar
      }
    } catch (error) {
      throw AuthError.InvalidAccessToken()
    }
  }

  /**
   * Hoàn tất liên kết và đăng nhập
   */
  async completeLinkAndLogin(
    req: Request,
    res: Response,
    userAgent: string,
    ip: string,
    password: string
  ): Promise<any> {
    const pendingLinkToken = req.cookies?.[CookieNames.OAUTH_PENDING_LINK]

    if (!pendingLinkToken) {
      throw AuthError.MissingAccessToken()
    }

    // Xác minh token
    const payload = await this.tokenService.verifyPendingLinkToken(pendingLinkToken)

    // Lấy user
    const user = await this.userAuthRepository.findById(payload.existingUserId)

    if (!user) {
      throw AuthError.EmailNotFound()
    }

    // Kiểm tra mật khẩu
    const isPasswordValid = await this.hashingService.compare(password, user.password)

    if (!isPasswordValid) {
      throw AuthError.InvalidPassword()
    }

    // Cập nhật user với thông tin Google
    await this.userAuthRepository.updateGoogleId(user.id, payload.googleId)

    // Tạo hoặc tìm device
    const device = await this.deviceRepository.upsertDevice(user.id, userAgent || 'unknown', ip || 'unknown')

    // Xóa cookie liên kết
    this.cookieService.clearOAuthPendingLinkTokenCookie(res)

    // Hoàn tất đăng nhập
    return this.finalizeSuccessfulAuth(user, device, true, res)
  }

  /**
   * Hủy liên kết đang chờ
   */
  async cancelPendingLink(req: Request, res: Response): Promise<{ message: string }> {
    // Xóa cookie liên kết
    this.cookieService.clearOAuthPendingLinkTokenCookie(res)

    return {
      message: await this.i18nService.translate('Auth.Google.LinkCancelled')
    }
  }
}
