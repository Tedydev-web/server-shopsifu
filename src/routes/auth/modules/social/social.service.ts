import { Injectable, Logger, Inject, HttpException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'
import { HashingService } from 'src/shared/services/hashing.service'
import { Response, Request } from 'express'
import * as crypto from 'crypto'
import { OAuth2Client, TokenPayload } from 'google-auth-library'
import { v4 as uuidv4 } from 'uuid'
import { AuthError } from 'src/routes/auth/auth.error'
import { CookieNames } from 'src/shared/constants/auth.constants'
import { UserAuthRepository } from 'src/shared/repositories/auth/user-auth.repository'
import { DeviceRepository } from 'src/shared/repositories/auth/device.repository'
import { SessionRepository } from 'src/shared/repositories/auth/session.repository'
import { SecurityAlertType } from 'src/shared/services/email.service'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.constants'
import { OtpService } from '../../modules/otp/otp.service'
import { EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import {
  GoogleCallbackReturnType,
  GoogleCallbackSuccessResult,
  GoogleCallbackErrorResult,
  GoogleCallbackAccountExistsWithoutLinkResult
} from '../../auth.types'
import { ICookieService, ITokenService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { ApiException } from 'src/shared/exceptions/api.exception'

/**
 * Interface để lưu thông tin state khi tạo URL xác thực Google
 */
interface GoogleAuthStateType {
  nonce: string
  flow?: string
  userId?: number
  redirectUrl?: string
  action?: string
}

@Injectable()
export class SocialService {
  private readonly logger = new Logger(SocialService.name)
  private oauth2Client: OAuth2Client

  constructor(
    private readonly configService: ConfigService,
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly i18nService: I18nService,
    private readonly hashingService: HashingService,
    private readonly userAuthRepository: UserAuthRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly sessionRepository: SessionRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: any,
    private readonly otpService: OtpService
  ) {
    this.initOAuth2Client()
  }

  /**
   * Khởi tạo OAuth2Client
   */
  private initOAuth2Client(): void {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID')
    const clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET')
    const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI')

    if (!clientId || !clientSecret || !redirectUri) {
      const errorMessage = `Thiếu cấu hình OAuth2: clientId=${!!clientId}, clientSecret=${!!clientSecret}, redirectUri=${!!redirectUri}`
      this.logger.error(`[initOAuth2Client] ${errorMessage}`)
      // Không throw error ngay lập tức để tránh lỗi khi khởi tạo service
      // Thay vào đó, sẽ throw khi gọi các phương thức liên quan đến OAuth
      return
    }

    try {
      this.oauth2Client = new OAuth2Client(clientId, clientSecret, redirectUri)
      this.logger.debug(`[initOAuth2Client] Khởi tạo OAuth2Client thành công với redirectUri: ${redirectUri}`)
    } catch (error) {
      this.logger.error(`[initOAuth2Client] Lỗi khởi tạo OAuth2Client: ${error.message}`, error.stack)
      // Không throw error để tránh lỗi khi khởi tạo service
    }
  }

  /**
   * Lấy URL xác thực Google
   * @param stateParams Thông tin cần lưu trong state
   * @returns URL xác thực và nonce
   */
  getGoogleAuthUrl(stateParams: GoogleAuthStateType): { url: string; nonce: string } {
    const nonce = stateParams.nonce || crypto.randomBytes(16).toString('hex')
    this.logger.debug(`[getGoogleAuthUrl] Tạo URL xác thực Google với nonce: ${nonce}`)

    // Kiểm tra OAuth2Client đã được khởi tạo đúng cách chưa
    if (!this.oauth2Client) {
      this.logger.error('[getGoogleAuthUrl] OAuth2Client chưa được khởi tạo')
      this.initOAuth2Client()

      if (!this.oauth2Client) {
        throw new Error('Không thể khởi tạo OAuth2Client. Vui lòng kiểm tra cấu hình.')
      }
    }

    // Kiểm tra cấu hình
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID')
    const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI')

    if (!clientId || !redirectUri) {
      this.logger.error(`[getGoogleAuthUrl] Thiếu cấu hình OAuth: clientId=${!!clientId}, redirectUri=${!!redirectUri}`)
      throw new Error('Thiếu cấu hình Google OAuth')
    }

    // Tạo state để lưu thông tin với format chuẩn và mã hóa an toàn hơn
    const stateData = {
      nonce,
      action: stateParams.action || stateParams.flow || 'login',
      userId: stateParams.userId,
      redirectUrl: stateParams.redirectUrl,
      timestamp: Date.now() // Thêm timestamp để tránh reuse state
    }

    const state = Buffer.from(JSON.stringify(stateData)).toString('base64')

    try {
      // Tạo URL xác thực với các tham số bảo mật tốt hơn
      const url = this.oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
        state,
        prompt: 'consent', // Luôn yêu cầu người dùng xác nhận
        include_granted_scopes: true // Bao gồm các quyền đã cấp trước đó
      })

      if (!url) {
        throw new Error('Không thể tạo URL xác thực Google')
      }

      this.logger.debug(`[getGoogleAuthUrl] URL xác thực Google đã được tạo thành công`)
      return { url, nonce }
    } catch (error) {
      this.logger.error(`[getGoogleAuthUrl] Lỗi khi tạo URL xác thực Google: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Lấy tokens từ Google sau khi xác thực
   * @param code Authorization code từ Google
   */
  async getGoogleTokens(code: string) {
    try {
      const { tokens } = await this.oauth2Client.getToken(code)
      return tokens
    } catch (error) {
      this.logger.error(`[getGoogleTokens] Lỗi lấy Google tokens: ${error.message}`)
      throw error
    }
  }

  /**
   * Xác minh Google ID token
   * @param idToken ID token cần xác minh
   */
  async verifyGoogleIdToken(idToken: string): Promise<TokenPayload | undefined> {
    try {
      const ticket = await this.oauth2Client.verifyIdToken({
        idToken,
        audience: this.configService.get<string>('GOOGLE_CLIENT_ID')
      })
      return ticket.getPayload()
    } catch (error) {
      this.logger.error(`[verifyGoogleIdToken] Lỗi xác minh Google ID token: ${error.message}`)
      return undefined
    }
  }

  /**
   * Xác thực và giải mã state từ Google callback
   */
  private verifyAndDecodeState(
    state: string,
    originalNonceFromCookie?: string
  ): GoogleAuthStateType | GoogleCallbackErrorResult {
    try {
      if (!state) {
        this.logger.warn('[verifyAndDecodeState] State không được cung cấp')
        return {
          errorCode: 'MISSING_STATE',
          errorMessage: 'State không được cung cấp',
          redirectToError: true
        }
      }

      // Giải mã state
      const decodedState = JSON.parse(Buffer.from(state, 'base64').toString()) as GoogleAuthStateType & {
        timestamp?: number
      }
      const { nonce: nonceFromState, timestamp } = decodedState

      // Kiểm tra nonce
      if (!originalNonceFromCookie) {
        this.logger.warn('[verifyAndDecodeState] Không tìm thấy nonce trong cookie')
        return {
          errorCode: 'MISSING_NONCE_COOKIE',
          errorMessage: 'Không tìm thấy nonce trong cookie',
          redirectToError: true
        }
      }

      if (nonceFromState !== originalNonceFromCookie) {
        this.logger.warn(
          `[verifyAndDecodeState] Nonce không khớp: fromState=${nonceFromState}, fromCookie=${originalNonceFromCookie}`
        )
        return {
          errorCode: 'NONCE_MISMATCH',
          errorMessage: 'Xác thực không hợp lệ',
          redirectToError: true
        }
      }

      // Kiểm tra timestamp nếu có
      if (timestamp) {
        const now = Date.now()
        const stateAge = now - timestamp
        const maxStateAge = 1000 * 60 * 15 // 15 phút

        if (stateAge > maxStateAge) {
          this.logger.warn(`[verifyAndDecodeState] State đã hết hạn: ${stateAge}ms (max: ${maxStateAge}ms)`)
          return {
            errorCode: 'STATE_EXPIRED',
            errorMessage: 'Phiên xác thực đã hết hạn, vui lòng thử lại',
            redirectToError: true
          }
        }
      }

      // Đảm bảo có action (cả flow cũ và action mới)
      if (!decodedState.action && decodedState.flow) {
        decodedState.action = decodedState.flow
      } else if (!decodedState.action) {
        decodedState.action = 'login' // Mặc định là login
      }

      return decodedState
    } catch (error) {
      this.logger.error(`[verifyAndDecodeState] Lỗi giải mã state: ${error.message}`, error.stack)
      return {
        errorCode: 'INVALID_STATE',
        errorMessage: 'Dữ liệu xác thực không hợp lệ',
        redirectToError: true
      }
    }
  }

  /**
   * Lấy và xác thực thông tin người dùng từ Google
   */
  private async getAndVerifyGoogleUserInfo(code: string): Promise<
    | {
        googleId: string
        googleEmail: string
        googleName: string | null
        googleAvatar: string | null
        emailVerified: boolean
      }
    | GoogleCallbackErrorResult
  > {
    try {
      if (!code) {
        this.logger.error('[getAndVerifyGoogleUserInfo] Code không được cung cấp')
        throw AuthError.GoogleMissingCode()
      }

      this.logger.debug('[getAndVerifyGoogleUserInfo] Bắt đầu lấy tokens từ Google')
      const tokens = await this.getGoogleTokens(code)

      if (!tokens) {
        this.logger.error('[getAndVerifyGoogleUserInfo] Không thể lấy tokens từ Google')
        throw AuthError.GoogleUserInfoFailed()
      }

      const idToken = tokens.id_token

      if (!idToken) {
        this.logger.error('[getAndVerifyGoogleUserInfo] ID Token không có trong response')
        throw AuthError.InvalidSocialToken()
      }

      this.logger.debug('[getAndVerifyGoogleUserInfo] Bắt đầu xác minh ID token')
      const payload = await this.verifyGoogleIdToken(idToken)

      if (!payload) {
        this.logger.error('[getAndVerifyGoogleUserInfo] Không thể xác minh ID token')
        throw AuthError.InvalidSocialToken()
      }

      // Xác thực thêm các trường cần thiết
      if (!payload.sub) {
        this.logger.error('[getAndVerifyGoogleUserInfo] ID token thiếu thông tin subject (sub)')
        throw AuthError.GoogleInvalidPayload()
      }

      if (!payload.email) {
        this.logger.error('[getAndVerifyGoogleUserInfo] ID token thiếu thông tin email')
        throw AuthError.GoogleInvalidPayload()
      }

      this.logger.debug(`[getAndVerifyGoogleUserInfo] Xác minh ID token thành công cho user: ${payload.email}`)

      return {
        googleId: payload.sub,
        googleEmail: payload.email,
        googleName: payload.name || null,
        googleAvatar: payload.picture || null,
        emailVerified: !!payload.email_verified
      }
    } catch (error) {
      this.logger.error(`[getAndVerifyGoogleUserInfo] Lỗi lấy thông tin: ${error.message}`, error.stack)

      if (error instanceof HttpException) {
        const status = error.getStatus()
        const response = error.getResponse()

        return {
          errorCode:
            typeof response === 'object' ? (response as any).errorCode || 'GOOGLE_API_ERROR' : 'GOOGLE_API_ERROR',
          errorMessage:
            typeof response === 'string'
              ? response
              : typeof response === 'object'
                ? (response as any).message || error.message
                : error.message,
          redirectToError: true
        }
      }

      if (error.message.includes('invalid_grant')) {
        return {
          errorCode: 'INVALID_GRANT',
          errorMessage: 'Mã xác thực đã hết hạn hoặc đã được sử dụng. Vui lòng thử lại.',
          redirectToError: true
        }
      }

      return {
        errorCode: 'GOOGLE_API_ERROR',
        errorMessage: 'Không thể lấy thông tin từ Google. Vui lòng thử lại sau.',
        redirectToError: true
      }
    }
  }

  /**
   * Tạo đối tượng thông báo lỗi chuẩn
   */
  private async createErrorResponse(errorCode: string, messageKey: string): Promise<GoogleCallbackErrorResult> {
    const errorMessage = await this.i18nService.translate(messageKey)
    return {
      errorCode,
      errorMessage: String(errorMessage),
      redirectToError: true
    }
  }

  /**
   * Tạo đối tượng yêu cầu liên kết tài khoản
   */
  private async createAccountLinkingResponse(
    existingUserId: number,
    existingUserEmail: string,
    googleId: string,
    googleEmail: string,
    googleName: string | null,
    googleAvatar: string | null
  ): Promise<GoogleCallbackAccountExistsWithoutLinkResult> {
    return {
      needsLinking: true,
      existingUserId,
      existingUserEmail,
      googleId,
      googleEmail,
      googleName: googleName || null,
      googleAvatar: googleAvatar || null,
      message: await this.i18nService.translate('Auth.Google.AccountNeedsLinking')
    }
  }

  /**
   * Xử lý bảo mật sau khi xác thực thành công
   */
  private async handleAuthSuccessWithSecurity(
    user: any,
    userAgent: string,
    ip: string
  ): Promise<GoogleCallbackSuccessResult> {
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
      message: await this.i18nService.translate('Auth.Google.SuccessProceedToSecurityChecks')
    }
  }

  /**
   * Tạo user từ thông tin Google
   */
  private async createUserFromGoogle(googleId: string, email: string, name?: string | null, avatar?: string | null) {
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
      googleAvatar: avatar || undefined
    })
  }

  /**
   * Hoàn tất đăng nhập thành công và trả về thông tin người dùng
   */
  async finalizeSuccessfulAuth(
    user: any,
    device: any,
    rememberMe: boolean,
    res: Response,
    ipAddress?: string,
    userAgent?: string
  ) {
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

    // Tạo session trong Redis
    await this.createSession(user.id, device.id, sessionId, ipAddress, userAgent, rememberMe)

    // Trả về thông tin user
    return {
      id: user.id,
      email: user.email,
      roleName: user.role?.name || 'USER',
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
   * Tạo session mới trong Redis
   */
  private async createSession(
    userId: number,
    deviceId: number,
    sessionId: string,
    ipAddress?: string,
    userAgent?: string,
    rememberMe?: boolean
  ): Promise<void> {
    const sessionExpiresInMs = rememberMe
      ? this.configService.get<number>('SESSION_REMEMBER_ME_DURATION_MS')
      : this.configService.get<number>('SESSION_DEFAULT_DURATION_MS')

    const expiresAt = new Date(Date.now() + (sessionExpiresInMs || 0))

    try {
      await this.sessionRepository.createSession({
        id: sessionId,
        userId,
        deviceId,
        ipAddress: ipAddress || 'Unknown',
        userAgent: userAgent || 'Unknown',
        expiresAt
      })
      this.logger.debug(`[createSession] Session ${sessionId} created for user ${userId}`)
    } catch (error) {
      this.logger.error(
        `[createSession] Failed to create session ${sessionId} for user ${userId}: ${error.message}`,
        error.stack
      )
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

    // Lấy thông tin user hiện tại
    const currentUser = await this.userAuthRepository.findById(userId)
    if (!currentUser) {
      throw AuthError.EmailNotFound()
    }

    // Cập nhật user
    await this.userAuthRepository.updateGoogleId(userId, googleId || '')

    // Gửi email thông báo
    await this.sendSecurityAlert(SecurityAlertType.ACCOUNT_LINKED, currentUser.email, {
      googleEmail,
      linkedAt: new Date().toISOString()
    })

    return {
      message: await this.i18nService.translate('Auth.Google.LinkSuccess')
    }
  }

  /**
   * Gửi email thông báo liên quan đến bảo mật
   */
  private async sendSecurityAlert(
    alertType: SecurityAlertType,
    email: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    try {
      await this.emailService.sendSecurityAlertEmail(alertType, email, metadata)
    } catch (error) {
      this.logger.error(`[sendSecurityAlert] Failed to send email alert: ${error.message}`)
      // Không ảnh hưởng đến kết quả chính
    }
  }

  /**
   * Khởi tạo quá trình hủy liên kết tài khoản Google
   * @description Tạo SLT và gửi OTP để xác minh trước khi hủy liên kết
   */
  async initiateUnlinkGoogleAccount(
    userId: number,
    ipAddress: string,
    userAgent: string,
    res: Response
  ): Promise<{ message: string }> {
    // Lấy thông tin user
    const user = await this.userAuthRepository.findById(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    // Kiểm tra user có liên kết với Google không
    if (!user.googleId) {
      throw new Error('Tài khoản này chưa được liên kết với Google')
    }

    // Kiểm tra nếu user đăng nhập chỉ bằng Google (không có mật khẩu)
    const hasPassword = !!user.password && user.password.length > 0

    // Tạo SLT và gửi OTP nếu không có mật khẩu
    if (!hasPassword) {
      const sltJwt = await this.otpService.initiateOtpWithSltCookie({
        email: user.email,
        userId: user.id,
        deviceId: 0, // Không liên quan đến thiết bị cụ thể
        ipAddress,
        userAgent,
        purpose: TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT
      })

      // Set SLT cookie
      this.cookieService.setSltCookie(res, sltJwt, TypeOfVerificationCode.UNLINK_GOOGLE_ACCOUNT)

      return {
        message: 'Vui lòng xác minh qua OTP để hủy liên kết tài khoản Google'
      }
    }

    // Nếu có mật khẩu, không cần OTP
    return {
      message: 'Vui lòng nhập mật khẩu để xác nhận hủy liên kết tài khoản Google'
    }
  }

  /**
   * Xác minh và hoàn tất hủy liên kết tài khoản Google
   */
  async verifyAndUnlinkGoogleAccount(
    userId: number,
    sltToken: string | undefined,
    verificationCode?: string,
    password?: string,
    res?: Response
  ): Promise<{ message: string; success: boolean }> {
    // Lấy thông tin user
    const user = await this.userAuthRepository.findById(userId)
    if (!user) {
      throw AuthError.EmailNotFound()
    }

    // Kiểm tra user có liên kết với Google không
    if (!user.googleId) {
      throw new Error('Tài khoản này chưa được liên kết với Google')
    }

    // Kiểm tra phương thức xác thực và thực hiện xác minh
    const isVerified = await this.verifyUnlinkAuthentication(user, sltToken, verificationCode, password, res)

    // Nếu đã xác minh thành công, tiến hành hủy liên kết
    if (isVerified) {
      const googleIdBeforeUnlink = user.googleId // Lưu lại để gửi email thông báo

      // Cập nhật user, xóa googleId
      await this.userAuthRepository.updateGoogleId(userId, null) // Thay đổi '' thành null

      // Gửi email thông báo
      await this.sendSecurityAlert(SecurityAlertType.ACCOUNT_UNLINKED, user.email, {
        googleId: googleIdBeforeUnlink, // Sử dụng giá trị đã lưu
        unlinkedAt: new Date().toISOString()
      })

      return {
        message: await this.i18nService.translate('Auth.Google.UnlinkSuccess'),
        success: true
      }
    }

    return {
      message: 'Xác minh không thành công',
      success: false
    }
  }

  /**
   * Xác minh thông tin xác thực cho việc hủy liên kết
   */
  private async verifyUnlinkAuthentication(
    user: any,
    sltToken?: string,
    verificationCode?: string,
    password?: string,
    res?: Response
  ): Promise<boolean> {
    const hasPassword = !!user.password && user.password.length > 0

    // Xử lý theo từng phương thức xác thực
    if (!hasPassword) {
      // Xác thực bằng OTP
      if (!sltToken || !verificationCode) {
        throw AuthError.InvalidOTP()
      }

      try {
        const sltContext = await this.otpService.verifySltOtpStage(sltToken, verificationCode, 'Unknown', 'Unknown')

        if (sltContext.userId !== user.id) {
          throw AuthError.InvalidOTP()
        }

        // Xóa SLT cookie nếu có res
        if (res) {
          this.cookieService.clearSltCookie(res)
        }

        return true
      } catch (error) {
        if (error instanceof ApiException) throw error
        throw AuthError.InvalidOTP()
      }
    } else {
      // Xác thực bằng mật khẩu
      if (!password) {
        throw AuthError.InvalidPassword()
      }

      const isPasswordValid = await this.hashingService.compare(password, user.password)
      if (!isPasswordValid) {
        throw AuthError.InvalidPassword()
      }

      return true
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
        existingUserEmail: payload.googleEmail,
        googleId: payload.googleId,
        googleEmail: payload.googleEmail,
        googleName: payload.googleName,
        googleAvatar: payload.googleAvatar
      }
    } catch (err) {
      this.logger.error(`[getPendingLinkDetails] Lỗi: ${err instanceof Error ? err.message : 'Unknown error'}`)
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

    try {
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

      // Gửi email thông báo
      await this.sendSecurityAlert(SecurityAlertType.ACCOUNT_LINKED, user.email, {
        googleEmail: payload.googleEmail,
        linkedAt: new Date().toISOString()
      })

      // Tạo hoặc tìm device
      const device = await this.deviceRepository.upsertDevice(user.id, userAgent || 'unknown', ip || 'unknown')

      // Xóa cookie liên kết
      this.cookieService.clearOAuthPendingLinkTokenCookie(res)

      // Hoàn tất đăng nhập
      return this.finalizeSuccessfulAuth(user, device, true, res, ip, userAgent)
    } catch (err) {
      this.logger.error(`[completeLinkAndLogin] Lỗi: ${err instanceof Error ? err.message : 'Unknown error'}`)
      throw err
    }
  }

  /**
   * Hủy liên kết đang chờ
   */
  async cancelPendingLink(req: Request, res: Response): Promise<{ message: string }> {
    try {
      // Xóa cookie liên kết
      this.cookieService.clearOAuthPendingLinkTokenCookie(res)

      return {
        message: await this.i18nService.translate('Auth.Google.Link.CancelledSuccessfully')
      }
    } catch (err) {
      this.logger.error(`[cancelPendingLink] Lỗi: ${err instanceof Error ? err.message : 'Unknown error'}`)
      throw err
    }
  }

  /**
   * Xử lý callback từ Google OAuth
   */
  async googleCallback({
    code,
    state,
    originalNonceFromCookie,
    userAgent = 'Unknown',
    ip = 'Unknown'
  }: {
    code: string
    state: string
    originalNonceFromCookie?: string
    userAgent?: string
    ip?: string
  }): Promise<GoogleCallbackReturnType> {
    this.logger.debug(
      `[googleCallback] Bắt đầu xử lý callback với code ${code ? 'có giá trị' : 'trống'} và state ${state ? 'có giá trị' : 'trống'}`
    )

    try {
      // 1. Xác thực state và nonce
      if (!state) {
        return await this.createErrorResponse('MISSING_STATE', 'Auth.Error.Google.StateMissing')
      }

      if (!code) {
        return await this.createErrorResponse('MISSING_CODE', 'Auth.Error.Google.MissingCode')
      }

      const decodedState = this.verifyAndDecodeState(state, originalNonceFromCookie)
      if ('errorCode' in decodedState) {
        this.logger.warn(`[googleCallback] Lỗi xác minh state: ${decodedState.errorCode}`)
        return decodedState
      }

      const { action } = decodedState

      // 2. Lấy và xác thực token
      this.logger.debug(`[googleCallback] Lấy thông tin người dùng từ Google với action: ${action}`)
      const googleUserInfo = await this.getAndVerifyGoogleUserInfo(code)

      if ('errorCode' in googleUserInfo) {
        this.logger.warn(`[googleCallback] Lỗi xác minh Google user info: ${googleUserInfo.errorCode}`)
        return googleUserInfo
      }

      const { googleId, googleEmail, googleName, googleAvatar, emailVerified } = googleUserInfo

      // 3. Kiểm tra email đã được xác minh chưa
      if (!emailVerified) {
        this.logger.warn(`[googleCallback] Email chưa được xác minh: ${googleEmail}`)
        return await this.createErrorResponse('EMAIL_NOT_VERIFIED', 'Auth.Error.EmailNotVerified')
      }

      // 4. Tìm tài khoản người dùng
      this.logger.debug(`[googleCallback] Tìm kiếm người dùng với googleId: ${googleId}`)
      let user = await this.userAuthRepository.findByGoogleId(googleId)

      // 5. Xử lý khi không tìm thấy user theo googleId
      if (!user && googleEmail) {
        this.logger.debug(`[googleCallback] Không tìm thấy user với googleId, tìm kiếm theo email: ${googleEmail}`)

        // Tìm theo email
        const existingUserByEmail = await this.userAuthRepository.findByEmail(googleEmail)

        // 5.1. Nếu có user với email này nhưng chưa liên kết với Google
        if (existingUserByEmail) {
          this.logger.debug(`[googleCallback] Tìm thấy user với email ${googleEmail}, cần liên kết tài khoản`)
          return await this.createAccountLinkingResponse(
            existingUserByEmail.id,
            existingUserByEmail.email,
            googleId,
            googleEmail,
            googleName,
            googleAvatar
          )
        }

        // 5.2. Nếu đang đăng nhập hoặc liên kết, không tạo tài khoản mới
        if (action === 'login' || action === 'link') {
          this.logger.warn(`[googleCallback] Không tìm thấy tài khoản cho action ${action}`)
          return await this.createErrorResponse('ACCOUNT_NOT_FOUND', 'Auth.Error.AccountNotFound')
        }

        // 5.3. Tạo user mới cho action đăng ký
        this.logger.debug(`[googleCallback] Tạo tài khoản mới cho email: ${googleEmail}`)
        try {
          user = await this.createUserFromGoogle(googleId, googleEmail, googleName, googleAvatar)
          this.logger.log(`[googleCallback] Đã tạo tài khoản mới thành công cho email: ${googleEmail}`)
        } catch (error) {
          this.logger.error(`[googleCallback] Lỗi tạo tài khoản mới: ${error.message}`, error.stack)
          return await this.createErrorResponse('USER_CREATION_FAILED', 'Auth.Error.UserCreationFailed')
        }
      }

      if (!user) {
        this.logger.warn(`[googleCallback] Không tìm thấy và không thể tạo tài khoản mới`)
        return await this.createErrorResponse('ACCOUNT_NOT_FOUND', 'Auth.Error.AccountNotFound')
      }

      // 6. Xử lý thiết bị và bảo mật
      this.logger.debug(`[googleCallback] Xử lý thiết bị và bảo mật cho user: ${user.id}`)
      return await this.handleAuthSuccessWithSecurity(user, userAgent, ip)
    } catch (error) {
      this.logger.error(`[googleCallback] Lỗi không mong đợi trong Google callback: ${error.message}`, error.stack)
      return await this.createErrorResponse('INTERNAL_ERROR', 'Auth.Error.InternalServerError')
    }
  }

  /**
   * Xác thực 2FA
   * @description Xử lý xác minh mã 2FA trong cookie SLT
   */
  async verifyTwoFactorAuth(
    sltToken: string,
    code: string,
    rememberMe: boolean,
    userAgent: string,
    ip: string,
    res: Response
  ): Promise<any> {
    this.logger.debug(`[verifyTwoFactorAuth] Xác thực 2FA với mã OTP/TOTP`)

    try {
      // Xác minh SLT token và lấy context
      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        sltToken,
        ip,
        userAgent,
        TypeOfVerificationCode.LOGIN_2FA
      )

      // Xác minh mã 2FA thông qua OTP service
      const isValid = await this.otpService.verifyOTP(
        sltContext.email || '',
        code,
        TypeOfVerificationCode.LOGIN_2FA,
        sltContext.userId,
        ip,
        userAgent
      )

      if (!isValid) {
        throw new Error('Mã xác thực không hợp lệ')
      }

      // Lấy thông tin user
      const user = await this.userAuthRepository.findById(sltContext.userId)
      if (!user) {
        throw new Error('Không tìm thấy thông tin người dùng')
      }

      // Lấy thông tin thiết bị
      const device = await this.deviceRepository.findById(sltContext.deviceId)
      if (!device) {
        throw new Error('Không tìm thấy thông tin thiết bị')
      }

      // Hoàn tất quá trình đăng nhập
      const userData = await this.finalizeSuccessfulAuth(user, device, rememberMe, res, ip, userAgent)

      // Đánh dấu SLT đã hoàn tất
      await this.otpService.finalizeSlt(sltContext.sltJti)

      // Xóa SLT cookie
      this.cookieService.clearSltCookie(res)

      return {
        status: 'success',
        user: userData,
        message: await this.i18nService.translate('Auth.2FA.Verify.Success')
      }
    } catch (error) {
      this.logger.error(`[verifyTwoFactorAuth] Lỗi xác thực 2FA: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Xác thực thiết bị không tin cậy
   * @description Xử lý xác minh OTP cho thiết bị không tin cậy
   */
  async verifyUntrustedDevice(
    sltToken: string,
    code: string,
    userAgent: string,
    ip: string,
    res: Response
  ): Promise<any> {
    this.logger.debug(`[verifyUntrustedDevice] Xác thực thiết bị không tin cậy với mã OTP`)

    try {
      // Xác minh SLT token và lấy context
      const sltContext = await this.otpService.validateSltFromCookieAndGetContext(
        sltToken,
        ip,
        userAgent,
        TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP
      )

      // Xác minh mã OTP
      const isValid = await this.otpService.verifyOTP(
        sltContext.email || '',
        code,
        TypeOfVerificationCode.LOGIN_UNTRUSTED_DEVICE_OTP,
        sltContext.userId,
        ip,
        userAgent
      )

      if (!isValid) {
        throw new Error('Mã OTP không hợp lệ')
      }

      // Lấy thông tin user
      const user = await this.userAuthRepository.findById(sltContext.userId)
      if (!user) {
        throw new Error('Không tìm thấy thông tin người dùng')
      }

      // Lấy thông tin thiết bị
      const device = await this.deviceRepository.findById(sltContext.deviceId)
      if (!device) {
        throw new Error('Không tìm thấy thông tin thiết bị')
      }

      // Hoàn tất quá trình đăng nhập
      const userData = await this.finalizeSuccessfulAuth(user, device, true, res, ip, userAgent)

      // Đánh dấu SLT đã hoàn tất
      await this.otpService.finalizeSlt(sltContext.sltJti)

      // Xóa SLT cookie
      this.cookieService.clearSltCookie(res)

      return {
        status: 'success',
        user: userData,
        message: await this.i18nService.translate('Auth.Otp.Verified')
      }
    } catch (error) {
      this.logger.error(`[verifyUntrustedDevice] Lỗi xác thực thiết bị: ${error.message}`, error.stack)
      throw error
    }
  }
}
