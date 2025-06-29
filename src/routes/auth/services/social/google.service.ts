import { Injectable, Logger, ForbiddenException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { Response, Request } from 'express'
import { OAuth2Client } from 'google-auth-library'
import { google } from 'googleapis'
import { AuthError } from '../../auth.error'
import { CoreAuthService } from '../core.service'
import { RolesService } from '../roles.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { HashingService } from 'src/shared/services/hashing.service'
import { v4 as uuidv4 } from 'uuid'
import { addMilliseconds } from 'date-fns'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { DeviceService } from 'src/routes/device/device.service'
import { EnvConfigType } from 'src/shared/config'
import { randomBytes } from 'crypto'
import ms from 'ms'
import { SessionService } from 'src/shared/services/session.service'
import { SessionRepository } from '../../repositories/session.repository'
import { AuthRepository } from '../../repositories/auth.repo'

const GOOGLE_OAUTH_NONCE_COOKIE = 'google_oauth_nonce'

@Injectable()
export class GoogleService {
  private oauth2Client: OAuth2Client
  private readonly logger = new Logger(GoogleService.name)
  private readonly clientUrl: string

  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authService: CoreAuthService,
    private readonly configService: ConfigService<EnvConfigType>,
    private readonly cookieService: CookieService,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly deviceService: DeviceService,
    private readonly sessionService: SessionService,
    private readonly sessionRepository: SessionRepository,
    private readonly authRepository: AuthRepository,
  ) {
    const googleConfig = this.configService.get('google')
    const appConfig = this.configService.get('app')

    this.oauth2Client = new google.auth.OAuth2(
      googleConfig.clientId,
      googleConfig.clientSecret,
      googleConfig.redirectUri,
    )
    this.clientUrl = appConfig.clientUrl
  }

  getAuthorizationUrl(res: Response) {
    const scope = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']

    // 1. Tạo nonce để chống tấn công CSRF
    const nonce = randomBytes(16).toString('hex')

    // 2. Lưu nonce vào một httpOnly cookie, an toàn
    res.cookie(GOOGLE_OAUTH_NONCE_COOKIE, nonce, {
      httpOnly: true,
      secure: !this.configService.get('isProd'),
      sameSite: 'lax',
      maxAge: ms('15m'), // Nonce chỉ hợp lệ trong 15 phút
    })

    // 3. Truyền nonce vào state
    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope,
      include_granted_scopes: true,
      state: nonce,
    })
    return { url }
  }

  async googleCallback({ code, state }: { code: string; state: string }, req: Request, res: Response): Promise<void> {
    try {
      // 1. Xác thực CSRF token (nonce)
      const nonce = req.cookies[GOOGLE_OAUTH_NONCE_COOKIE]
      if (!nonce || nonce !== state) {
        throw new ForbiddenException('Invalid state parameter. Possible CSRF attack.')
      }
      // Xóa cookie nonce ngay sau khi xác thực
      res.clearCookie(GOOGLE_OAUTH_NONCE_COOKIE)

      // 2. Dùng code để lấy token
      const { tokens } = await this.oauth2Client.getToken(code)
      this.oauth2Client.setCredentials(tokens)

      // 3. Lấy thông tin google user
      const oauth2 = google.oauth2({
        auth: this.oauth2Client,
        version: 'v2',
      })
      const { data: googleUser } = await oauth2.userinfo.get()
      if (!googleUser.email) {
        throw AuthError.GoogleUserInfoError
      }

      // 4. Tìm hoặc tạo user
      let user = await this.sharedUserRepository.findUnique({ email: googleUser.email })

      if (!user) {
        const clientRoleId = await this.rolesService.getClientRoleId()
        const randomPassword = uuidv4()
        const hashedPassword = await this.hashingService.hash(randomPassword)
        user = await this.authRepository.createUserInclueRole({
          email: googleUser.email,
          name: googleUser.name ?? '',
          password: hashedPassword,
          roleId: clientRoleId,
          phoneNumber: '',
          avatar: googleUser.picture ?? null,
        })
      }

      if (!user) {
        throw AuthError.UserNotFound
      }

      // 5. Sử dụng fingerprint để tìm hoặc tạo thiết bị mới
      const device = await this.deviceService.findOrCreateDevice(user.id, req)

      // 6. Tính toán thời gian hết hạn cho Refresh Token
      const refreshTokenExpiresInMs = this.configService.get('timeInMs').refreshToken
      const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)

      // 7. Tạo một phiên đăng nhập (session) mới trong DB
      const session = await this.sessionRepository.createSession({
        userId: user.id,
        deviceId: device.id,
        ipAddress: device.ip, // Sử dụng IP đã chuẩn hóa
        userAgent: device.userAgent, // Sử dụng User Agent đã chuẩn hóa
        expiresAt: refreshTokenExpiresAt,
      })

      // 7.1 Cache session vào Redis
      await this.sessionService.createSession(session)

      // 8. Tạo mới accessToken và refreshToken với sessionId
      const userRole = await this.rolesService.getRoleById(user.roleId)
      const { accessToken, refreshToken } = await this.authService.generateTokens({
        userId: user.id,
        sessionId: session.id,
        roleId: user.roleId,
        roleName: userRole?.name || 'Client',
      })

      // 9. Set cookies. Google login is like "remember me" by default.
      this.cookieService.setTokenCookies(res, accessToken, refreshToken, true)

      res.redirect(this.clientUrl)
    } catch (error) {
      this.logger.error('Error in googleCallback', error)
      // Redirect to a failure page on the client for better UX
      const failureRedirectUrl = new URL('/auth/login-failure', this.clientUrl)
      if (error instanceof ForbiddenException) {
        failureRedirectUrl.searchParams.set('error', 'csrf_error')
      } else {
        failureRedirectUrl.searchParams.set('error', 'google_oauth_failed')
      }
      res.redirect(failureRedirectUrl.toString())
    }
  }
}
