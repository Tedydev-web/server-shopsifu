// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Logger, Inject, HttpException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { I18nService } from 'nestjs-i18n'

// ================================================================
// External Libraries
// ================================================================
import { Response, Request } from 'express'
import * as crypto from 'crypto'
import { OAuth2Client, TokenPayload } from 'google-auth-library'

// ================================================================
// Internal Services & Types
// ================================================================
import { HashingService } from 'src/shared/services/hashing.service'
import { SLTService } from 'src/shared/services/slt.service'
import { EmailService } from 'src/shared/services/email.service'
import { OtpService } from './otp.service'

// ================================================================
// Repositories
// ================================================================
import { SessionRepository } from 'src/routes/auth/repositories'
import { DeviceRepository } from 'src/shared/repositories/device.repository'
import { UserRepository } from 'src/routes/user/user.repository'
import { RoleRepository } from 'src/routes/role/role.repository'

// ================================================================
// Constants & Injection Tokens
// ================================================================
import { EMAIL_SERVICE, HASHING_SERVICE, OTP_SERVICE, SLT_SERVICE } from 'src/shared/constants/injection.tokens'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'
import { CookieNames, TypeOfVerificationCode } from 'src/routes/auth/auth.constants'

// ================================================================
// Types & Interfaces
// ================================================================
import { AuthError } from 'src/routes/auth/auth.error'
import { GlobalError } from 'src/shared/global.error'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { ICookieService, ITokenService } from 'src/routes/auth/auth.types'
import {
  GoogleCallbackReturnType,
  GoogleCallbackErrorResult,
  GoogleCallbackAccountExistsWithoutLinkResult
} from '../auth.types'

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
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    private readonly userRepository: UserRepository,
    private readonly roleRepository: RoleRepository,
    private readonly deviceRepository: DeviceRepository,
    private readonly sessionRepository: SessionRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(SLT_SERVICE) private readonly sltService: SLTService,
    @Inject(OTP_SERVICE) private readonly otpService: OtpService
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
        throw AuthError.GoogleUserInfoFailed()
      }
    }

    // Kiểm tra cấu hình
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID')
    const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI')

    if (!clientId || !redirectUri) {
      this.logger.error(`[getGoogleAuthUrl] Thiếu cấu hình OAuth: clientId=${!!clientId}, redirectUri=${!!redirectUri}`)
      throw AuthError.GoogleUserInfoFailed()
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
        throw AuthError.GoogleUserInfoFailed()
      }

      this.logger.debug(`[getGoogleAuthUrl] URL xác thực Google đã được tạo thành công`)
      return { url, nonce }
    } catch (error) {
      this.logger.error(`[getGoogleAuthUrl] Lỗi khi tạo URL xác thực Google: ${error.message}`, error.stack)
      throw AuthError.GoogleUserInfoFailed()
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
      throw AuthError.GoogleUserInfoFailed()
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
          errorMessage: 'auth.error.social.googleCallbackError',
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
          errorMessage: 'auth.error.social.googleCallbackError',
          redirectToError: true
        }
      }

      if (nonceFromState !== originalNonceFromCookie) {
        this.logger.warn(
          `[verifyAndDecodeState] Nonce không khớp: fromState=${nonceFromState}, fromCookie=${originalNonceFromCookie}`
        )
        return {
          errorCode: 'NONCE_MISMATCH',
          errorMessage: 'auth.error.social.googleCallbackError',
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
            errorMessage: 'auth.error.social.googleCallbackError',
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
        errorMessage: 'auth.error.social.googleCallbackError',
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
          errorMessage: 'auth.error.social.googleCallbackError',
          redirectToError: true
        }
      }

      return {
        errorCode: 'GOOGLE_API_ERROR',
        errorMessage: 'auth.error.social.googleUserInfoFailed',
        redirectToError: true
      }
    }
  }

  /**
   * Tạo đối tượng thông báo lỗi chuẩn
   */
  private createErrorResponse(errorCode: string): GoogleCallbackErrorResult {
    const errorKeyMap: Record<string, string> = {
      MISSING_STATE: 'auth.error.social.googleCallbackError',
      MISSING_CODE: 'auth.error.social.googleMissingCode',
      EMAIL_NOT_VERIFIED: 'auth.error.social.googleInvalidPayload',
      ACCOUNT_NOT_FOUND: 'global.error.notFound.user',
      USER_CREATION_FAILED: 'auth.error.social.googleLinkFailed',
      INTERNAL_ERROR: 'global.error.general.internalServerError'
    }
    const messageKey = errorKeyMap[errorCode] || 'auth.error.social.googleCallbackError'

    return {
      errorCode,
      errorMessage: messageKey,
      redirectToError: true
    }
  }

  /**
   * Tạo đối tượng yêu cầu liên kết tài khoản
   */
  private createAccountLinkingResponse(
    existingUserId: number,
    existingUserEmail: string,
    googleId: string,
    googleEmail: string,
    googleName: string | null,
    googleAvatar: string | null
  ): GoogleCallbackAccountExistsWithoutLinkResult {
    return {
      needsLinking: true,
      existingUserId,
      existingUserEmail,
      googleId,
      googleEmail,
      googleName: googleName || null,
      googleAvatar: googleAvatar || null,
      message: 'auth.success.social.accountNeedsLinking'
    }
  }

  /**
   * Tạo user từ thông tin Google
   */
  private async createUserFromGoogle(googleId: string, email: string, name?: string | null, avatar?: string | null) {
    const nameParts = name ? name.split(' ') : ['', '']
    const lastName = nameParts.length > 1 ? nameParts.pop() || '' : ''
    const firstName = nameParts.join(' ')

    const customerRole = await this.roleRepository.findByName('Customer')
    if (!customerRole) {
      this.logger.error(`[createUserFromGoogle] Role 'Customer' not found. Cannot create user.`)
      throw GlobalError.InternalServerError('Role configuration error.')
    }

    // Tạo user mới
    return this.userRepository.createWithProfile({
      email,
      password: '', // Không có mật khẩu khi đăng ký bằng Google
      roleId: customerRole.id,
      username: email, // Tạm thời dùng email, có thể cho user đổi sau
      firstName,
      lastName,
      googleId,
      googleAvatar: avatar || undefined
    })
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
      `[googleCallback] Bắt đầu xử lý callback với code ${code ? 'có giá trị' : 'trống'} và state ${
        state ? 'có giá trị' : 'trống'
      }`
    )

    try {
      // 1. Xác thực state và nonce
      if (!state) {
        return this.createErrorResponse('MISSING_STATE')
      }

      if (!code) {
        return this.createErrorResponse('MISSING_CODE')
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
        return this.createErrorResponse('EMAIL_NOT_VERIFIED')
      }

      // 4. Tìm tài khoản người dùng
      this.logger.debug(`[googleCallback] Tìm kiếm người dùng với googleId: ${googleId}`)
      let user = await this.userRepository.findByGoogleId(googleId)
      let isNewUser = false

      // 5. Xử lý khi không tìm thấy user theo googleId
      if (!user && googleEmail) {
        this.logger.debug(`[googleCallback] Không tìm thấy user với googleId, tìm kiếm theo email: ${googleEmail}`)

        // Tìm theo email
        const existingUserByEmail = await this.userRepository.findByEmailWithDetails(googleEmail)

        // 5.1. Nếu có user với email này nhưng chưa liên kết với Google
        if (existingUserByEmail) {
          this.logger.debug(`[googleCallback] Tìm thấy user với email ${googleEmail}, cần liên kết tài khoản`)
          return this.createAccountLinkingResponse(
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
          return this.createErrorResponse('ACCOUNT_NOT_FOUND')
        }

        // 5.3. Tạo user mới cho action đăng ký
        this.logger.debug(`[googleCallback] Tạo tài khoản mới cho email: ${googleEmail}`)
        try {
          user = await this.createUserFromGoogle(googleId, googleEmail, googleName, googleAvatar)
          isNewUser = true
          this.logger.log(`[googleCallback] Đã tạo tài khoản mới thành công cho email: ${googleEmail}`)
        } catch (error) {
          this.logger.error(`[googleCallback] Lỗi tạo tài khoản mới: ${error.message}`, error.stack)
          return this.createErrorResponse('USER_CREATION_FAILED')
        }
      }

      if (!user) {
        this.logger.warn(`[googleCallback] Không tìm thấy và không thể tạo tài khoản mới`)
        return this.createErrorResponse('ACCOUNT_NOT_FOUND')
      }

      // 6. Xử lý thiết bị và bảo mật - Logic được chuyển vào từ handleAuthSuccessWithSecurity
      this.logger.debug(`[googleCallback] Xử lý thiết bị và bảo mật cho user: ${user.id}`)
      const device = await this.deviceRepository.upsertDevice(user.id, userAgent || 'unknown', ip || 'unknown')
      const requiresTwoFactorAuth = !!user.twoFactorEnabled
      const isDeviceTrusted = await this.deviceRepository.isDeviceTrustValid(device.id)
      const requiresUntrustedDeviceVerification = !isDeviceTrusted

      return {
        user,
        device,
        requiresTwoFactorAuth,
        requiresUntrustedDeviceVerification,
        twoFactorMethod: user.twoFactorMethod as any,
        isLoginViaGoogle: true,
        isNewUser,
        purpose: isNewUser ? TypeOfVerificationCode.REGISTER : TypeOfVerificationCode.LOGIN,
        message: 'auth.success.social.successProceedToSecurityChecks'
      }
    } catch (error) {
      this.logger.error(`[googleCallback] Lỗi không mong đợi trong Google callback: ${error.message}`, error.stack)
      return this.createErrorResponse('INTERNAL_ERROR')
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
    const existingUserWithGoogleId = await this.userRepository.findByGoogleId(googleId || '')

    if (existingUserWithGoogleId && existingUserWithGoogleId.id !== userId) {
      throw AuthError.GoogleAccountAlreadyLinked()
    }

    // Lấy thông tin user hiện tại
    const currentUser = await this.userRepository.findByIdWithDetails(userId)
    if (!currentUser) {
      throw GlobalError.NotFound('user')
    }

    // Cập nhật user
    await this.userRepository.updateGoogleId(userId, googleId || '')

    // Gửi email thông báo
    await this.emailService.sendAccountLinkStatusChangeEmail(currentUser.email, {
      userName: currentUser.userProfile?.username ?? currentUser.email,
      action: 'linked',
      provider: 'Google'
    })

    return {
      message: 'auth.success.social.linkSuccess'
    }
  }

  /**
   * Hoàn tất hủy liên kết tài khoản Google sau khi đã xác thực.
   * Hàm này không tự xác thực mà giả định việc xác thực đã được thực hiện bởi một service khác (VD: AuthVerificationService).
   */
  async unlinkGoogleAccount(userId: number): Promise<{ message: string; data: { success: boolean } }> {
    // Lấy thông tin user
    const user = await this.userRepository.findByIdWithDetails(userId)
    if (!user) {
      throw GlobalError.NotFound('user')
    }

    // Kiểm tra user có liên kết với Google không
    if (!user.googleId) {
      // Có thể không cần throw lỗi ở đây, mà trả về thông báo nhẹ nhàng hơn
      this.logger.warn(`[unlinkGoogleAccount] User ${userId} requested unlink but has no Google ID.`)
      return {
        message: 'auth.error.social.notLinked',
        data: { success: false }
      }
    }

    const googleIdBeforeUnlink = user.googleId

    // Cập nhật user, xóa googleId
    await this.userRepository.updateGoogleId(userId, null)
    this.logger.log(`[unlinkGoogleAccount] Successfully unlinked Google account for user ${userId}.`)

    // Gửi email thông báo
    await this.emailService.sendAccountLinkStatusChangeEmail(user.email, {
      userName: user.userProfile?.username ?? user.email,
      action: 'unlinked',
      provider: 'Google'
    })

    return {
      message: 'auth.success.social.unlinkSuccess',
      data: { success: true }
    }
  }

  /**
   * Lấy thông tin liên kết đang chờ
   */
  async getPendingLinkDetails(req: Request): Promise<any> {
    const pendingLinkToken = req.cookies?.[CookieNames.OAUTH_PENDING_LINK]

    if (!pendingLinkToken) {
      throw AuthError.PendingSocialLinkTokenMissing()
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
      throw AuthError.InvalidSocialToken()
    }
  }

  /**
   * Hoàn tất liên kết và đăng nhập
   */
  async completeLinkAndLogin(
    pendingLinkToken: string,
    password: string,
    userAgent: string,
    ip: string
  ): Promise<{ message: string; data: { user: any; device: any } }> {
    if (!pendingLinkToken) {
      throw AuthError.PendingSocialLinkTokenMissing()
    }

    try {
      // Xác minh token
      const payload = await this.tokenService.verifyPendingLinkToken(pendingLinkToken)

      // Lấy user
      const user = await this.userRepository.findByIdWithDetails(payload.existingUserId)

      if (!user) {
        throw GlobalError.NotFound('user')
      }

      // Kiểm tra mật khẩu nếu user đã có mật khẩu
      if (user.password) {
        const isPasswordValid = await this.hashingService.compare(password, user.password)
        if (!isPasswordValid) {
          throw AuthError.InvalidPassword()
        }
      }

      // Cập nhật user với thông tin Google
      await this.userRepository.updateGoogleId(user.id, payload.googleId)

      // Gửi email thông báo
      await this.emailService.sendAccountLinkStatusChangeEmail(user.email, {
        userName: user.userProfile?.username ?? user.email,
        action: 'linked',
        provider: 'Google'
      })

      // Tạo hoặc tìm device
      const device = await this.deviceRepository.upsertDevice(user.id, userAgent || 'unknown', ip || 'unknown')

      return {
        message: 'auth.success.social.linkSuccess',
        data: { user, device }
      }
    } catch (err) {
      this.logger.error(`[completeLinkAndLogin] Lỗi: ${err instanceof Error ? err.message : 'Unknown error'}`)
      if (err instanceof HttpException) throw err
      throw AuthError.GoogleLinkFailed()
    }
  }

  /**
   * Hủy liên kết đang chờ
   */
  cancelPendingLink(req: Request, res: Response): { message: string } {
    try {
      // Xóa cookie liên kết
      this.cookieService.clearOAuthPendingLinkTokenCookie(res)

      return {
        message: 'auth.success.social.linkCancelled'
      }
    } catch (err) {
      this.logger.error(`[cancelPendingLink] Lỗi: ${err instanceof Error ? err.message : 'Unknown error'}`)
      throw GlobalError.InternalServerError(err.message)
    }
  }
}
