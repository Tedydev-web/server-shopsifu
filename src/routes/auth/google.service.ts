import { Injectable } from '@nestjs/common'
import { google } from 'googleapis'
import { OAuth2Client } from 'google-auth-library'
import { v4 as uuidv4 } from 'uuid'
import { ConfigService } from '@nestjs/config'
import { AuthRepository } from './auth.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { SharedRoleRepository } from 'src/shared/repositories/shared-role.repo'
import { AuthService } from './auth.service'
import { GoogleAuthStateType } from './auth.model'
import { GoogleUserDataSchema } from 'src/shared/models/shared-user.model'
import { GoogleUserInfoError } from './auth.error'

@Injectable()
export class GoogleService {
  private oauth2Client: OAuth2Client
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly hashingService: HashingService,
    private readonly sharedRoleRepository: SharedRoleRepository,
    private readonly authService: AuthService,
    private readonly configService: ConfigService
  ) {
    this.oauth2Client = new google.auth.OAuth2(
      this.configService.get('auth.google.client.id'),
      this.configService.get('auth.google.client.secret'),
      this.configService.get('auth.google.client.redirectUriGoogleCallback')
    )
  }

  getAuthorizationUrl({ userAgent, ip }: GoogleAuthStateType) {
    const scope = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']
    // Chuyển Object sang string base64 an toàn bởi lên url
    const stateString = Buffer.from(
      JSON.stringify({
        userAgent,
        ip
      })
    ).toString('base64')
    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope,
      include_granted_scopes: true,
      state: stateString,
      redirect_uri: this.configService.get('auth.google.client.redirectUriGoogleCallback')
    })
    return { url }
  }

  async googleCallback({ code, state }: { code: string; state: string }) {
    try {
      let userAgent = 'Unknown'
      let ip = 'Unknown'
      // 1. Lấy state từ url
      try {
        if (state) {
          const clientInfo = JSON.parse(Buffer.from(state, 'base64').toString()) as GoogleAuthStateType
          userAgent = clientInfo.userAgent
          ip = clientInfo.ip
        }
      } catch (error) {
        console.error('Error parsing state', error)
      }

      // 2. Dùng code để lấy token
      const { tokens } = await this.oauth2Client.getToken({
        code,
        redirect_uri: this.configService.get('auth.google.client.redirectUriGoogleCallback')
      })
      this.oauth2Client.setCredentials(tokens)

      // 3. Lấy thông tin google user
      const oauth2 = google.oauth2({
        auth: this.oauth2Client,
        version: 'v2'
      })
      const { data } = await oauth2.userinfo.get()
      if (!data.email) {
        throw GoogleUserInfoError
      }

      // 4. Validate và sanitize dữ liệu từ Google
      const validatedGoogleData = GoogleUserDataSchema.parse({
        email: data.email,
        name: data.name,
        picture: data.picture
      })

      let user = await this.authRepository.findUniqueUserIncludeRole({
        email: validatedGoogleData.email
      })

      // Nếu không có user tức là người mới, vậy nên sẽ tiến hành đăng ký
      if (!user) {
        const clientRoleId = await this.sharedRoleRepository.getClientRoleId()
        const randomPassword = uuidv4()
        const hashedPassword = await this.hashingService.hash(randomPassword)

        // Đảm bảo dữ liệu phù hợp với database schema
        const userData = {
          email: validatedGoogleData.email,
          name: validatedGoogleData.name || 'Unknown User',
          password: hashedPassword,
          roleId: clientRoleId,
          phoneNumber: '', // Để trống vì Google không cung cấp số điện thoại
          avatar: validatedGoogleData.picture
        }

        user = await this.authRepository.createUserInclueRole(userData)
      }

      const device = await this.authRepository.createDevice({
        userId: user.id,
        userAgent,
        ip
      })

      const authTokens = await this.authService.generateTokens({
        userId: user.id,
        deviceId: device.id,
        roleId: user.roleId,
        roleName: user.role.name
      })

      return authTokens
    } catch (error) {
      console.error('Error in googleCallback', error)
      throw error
    }
  }
}
