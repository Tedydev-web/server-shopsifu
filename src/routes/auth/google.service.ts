import { Injectable } from '@nestjs/common'
import { OAuth2Client } from 'google-auth-library'
import { google } from 'googleapis'
import { GoogleAuthStateType } from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { AuthService } from 'src/routes/auth/auth.service'
import { GoogleUserInfoException } from 'src/routes/auth/auth.error'
import { RolesService } from 'src/routes/auth/roles.service'
import envConfig from 'src/shared/config'
import { HashingService } from 'src/shared/services/hashing.service'
import { v4 as uuidv4 } from 'uuid'
import { DeviceService } from 'src/shared/services/device.service'

@Injectable()
export class GoogleService {
  private oauth2Client: OAuth2Client
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authService: AuthService,
    private readonly deviceService: DeviceService
  ) {
    this.oauth2Client = new google.auth.OAuth2(
      envConfig.GOOGLE_CLIENT_ID,
      envConfig.GOOGLE_CLIENT_SECRET,
      envConfig.GOOGLE_REDIRECT_URI
    )
  }
  getAuthorizationUrl({ userAgent, ip, rememberMe }: GoogleAuthStateType & { rememberMe?: boolean }) {
    const scope = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
    const stateObject: GoogleAuthStateType & { rememberMe?: boolean } = {
      userAgent,
      ip
    }
    if (rememberMe !== undefined) {
      stateObject.rememberMe = rememberMe
    }
    const stateString = Buffer.from(JSON.stringify(stateObject)).toString('base64')
    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope,
      include_granted_scopes: true,
      state: stateString,
      prompt: 'select_account'
    })
    return { url }
  }
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
  }) {
    let rememberMe: boolean | undefined = undefined
    try {
      try {
        if (state) {
          const clientInfo = JSON.parse(Buffer.from(state, 'base64').toString()) as GoogleAuthStateType & {
            rememberMe?: boolean
          }
          userAgent = clientInfo.userAgent || userAgent
          ip = clientInfo.ip || ip
          rememberMe = clientInfo.rememberMe
        }
      } catch (error) {
        console.error('Error parsing state', error)
      }
      const { tokens } = await this.oauth2Client.getToken(code)
      this.oauth2Client.setCredentials(tokens)

      const oauth2 = google.oauth2({
        auth: this.oauth2Client,
        version: 'v2'
      })
      const { data } = await oauth2.userinfo.get()
      if (!data.email) {
        throw GoogleUserInfoException
      }

      let user = await this.authRepository.findUniqueUserIncludeRole({
        email: data.email
      })
      if (!user) {
        const clientRoleId = await this.rolesService.getClientRoleId()
        const randomPassword = uuidv4()
        const hashedPassword = await this.hashingService.hash(randomPassword)
        user = await this.authRepository.createUserIncludeRole({
          email: data.email,
          name: data.name ?? '',
          password: hashedPassword,
          roleId: clientRoleId,
          phoneNumber: '',
          avatar: data.picture ?? null
        })
      }

      if (!user) {
        throw new Error('Không thể tạo hoặc tìm thấy người dùng')
      }

      const device = await this.deviceService.findOrCreateDevice({
        userId: user.id,
        userAgent,
        ip
      })

      // Kiểm tra session hợp lệ
      if (!this.deviceService.isSessionValid(device)) {
        // Nếu session không hợp lệ, không cần 2FA, client nên xử lý như một lỗi đăng nhập
        // hoặc yêu cầu đăng nhập lại. Chúng ta sẽ không cấp token.
        // Có thể throw một lỗi cụ thể ở đây nếu cần.
        console.warn(
          `[GoogleService googleCallback] Absolute session lifetime exceeded for user ${String(user.id)}, device ${String(device.id)}.`
        )
        // Để đơn giản, ở đây sẽ throw lỗi chung, client sẽ redirect về trang lỗi/login
        throw new Error('Error.Auth.Session.AbsoluteLifetimeExceeded')
      }

      // Kiểm tra 2FA
      if (user.twoFactorEnabled && user.twoFactorSecret && user.twoFactorMethod) {
        if (device.isTrusted) {
          // Thiết bị tin cậy và session hợp lệ, bỏ qua 2FA
          console.debug(
            `[GoogleService googleCallback] Device ${String(device.id)} is trusted for user ${String(user.id)}. Skipping 2FA.`
          )
        } else {
          // Thiết bị không tin cậy, yêu cầu 2FA
          const loginSessionToken = await this.authService.createLoginSessionToken({
            email: user.email,
            userId: user.id,
            deviceId: device.id,
            rememberMe: rememberMe
          })
          return {
            message: 'Auth.Login.2FARequired',
            loginSessionToken: loginSessionToken,
            twoFactorMethod: user.twoFactorMethod,
            isGoogleAuth: true,
            askToTrustDevice: true // Gợi ý cho client
          }
        }
      }

      const authTokens = await this.authService.generateTokens(
        {
          userId: user.id,
          deviceId: device.id,
          roleId: user.roleId,
          roleName: user.role.name
        },
        undefined, // Không có transaction client ở đây
        rememberMe
      )

      // Nếu người dùng chọn "Remember Me" và thiết bị chưa được tin cậy
      if (rememberMe && !device.isTrusted) {
        try {
          await this.deviceService.trustDevice(device.id, user.id)
          console.debug(
            `[GoogleService googleCallback] Device ${String(device.id)} trusted for user ${String(user.id)} due to rememberMe selection.`
          )
        } catch (trustError) {
          console.error(
            `[GoogleService googleCallback] Failed to trust device ${String(device.id)} for user ${String(user.id)}`,
            trustError
          )
        }
      }

      return {
        userId: user.id,
        email: user.email,
        name: user.name,
        role: user.role.name,
        ...authTokens
      }
    } catch (error) {
      console.error('Error in googleCallback', error)
      throw error
    }
  }
}
