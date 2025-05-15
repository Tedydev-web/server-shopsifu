import { HttpException, Injectable, UnauthorizedException } from '@nestjs/common'
import { addMilliseconds } from 'date-fns'
import {
  DisableTwoFactorBodyType,
  LoginBodyType,
  RefreshTokenBodyType,
  RegisterBodyType,
  ResetPasswordBodyType,
  SendOTPBodyType,
  TwoFactorVerifyBodyType,
  VerifyCodeBodyType
} from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { RolesService } from 'src/routes/auth/roles.service'
import { generateOTP, isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { TokenService } from 'src/shared/services/token.service'
import ms from 'ms'
import envConfig from 'src/shared/config'
import { TypeOfVerificationCode, TypeOfVerificationCodeType } from 'src/shared/constants/auth.constant'
import { EmailService } from 'src/shared/services/email.service'
import { AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import {
  EmailAlreadyExistsException,
  EmailNotFoundException,
  FailedToSendOTPException,
  InvalidLoginSessionException,
  InvalidOTPException,
  InvalidOTPTokenException,
  InvalidPasswordException,
  InvalidTOTPAndCodeException,
  InvalidTOTPException,
  OTPExpiredException,
  OTPTokenExpiredException,
  RefreshTokenAlreadyUsedException,
  TOTPAlreadyEnabledException,
  TOTPNotEnabledException,
  UnauthorizedAccessException
} from 'src/routes/auth/error.model'
import { TwoFactorService } from 'src/shared/services/2fa.service'
import { v4 as uuidv4 } from 'uuid'

@Injectable()
export class AuthService {
  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepository: AuthRepository,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly twoFactorService: TwoFactorService
  ) {}

  async validateVerificationCode({
    email,
    code,
    type
  }: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }) {
    const vevificationCode = await this.authRepository.findUniqueVerificationCode({
      email_code_type: {
        email,
        code,
        type
      }
    })
    if (!vevificationCode) {
      throw InvalidOTPException
    }
    if (vevificationCode.expiresAt < new Date()) {
      throw OTPExpiredException
    }
    return vevificationCode
  }

  async validateOtpToken({ token, email, type }: { token: string; email: string; type: TypeOfVerificationCodeType }) {
    const otpToken = await this.authRepository.findUniqueOtpToken({ token })

    if (!otpToken) {
      throw InvalidOTPTokenException
    }

    if (otpToken.email !== email || otpToken.type !== type) {
      throw InvalidOTPTokenException
    }

    if (otpToken.expiresAt < new Date()) {
      throw OTPTokenExpiredException
    }

    return otpToken
  }

  async verifyCode(body: VerifyCodeBodyType & { userAgent: string; ip: string }) {
    // 1. Xác minh OTP
    await this.validateVerificationCode({
      email: body.email,
      code: body.code,
      type: body.type
    })

    // 2. Xóa các OtpToken cũ nếu có
    await this.authRepository.deleteOtpTokenByEmailAndType(body.email, body.type)

    // 3. Lấy userId nếu email tồn tại trong User (cho FORGOT_PASSWORD, LOGIN, DISABLE_2FA)
    let userId: number | undefined = undefined
    if (body.type !== TypeOfVerificationCode.REGISTER) {
      const user = await this.sharedUserRepository.findUnique({ email: body.email })
      if (user) {
        userId = user.id
      }
    }

    // 4. Lấy hoặc tạo device
    let deviceId: number | undefined = undefined
    if (userId) {
      // Nếu có userId, tạo hoặc tìm thiết bị hiện có
      try {
        const device = await this.authRepository.createDevice({
          userId,
          userAgent: body.userAgent,
          ip: body.ip
        })
        deviceId = device.id
      } catch (error) {
        // Bỏ qua lỗi nếu không thể tạo device
        console.error('Không thể tạo device', error)
      }
    }

    // 5. Tạo OtpToken mới
    const token = uuidv4()
    const otpToken = await this.authRepository.createOtpToken({
      token,
      email: body.email,
      type: body.type,
      userId,
      deviceId,
      expiresAt: addMilliseconds(new Date(), ms('15m'))
    })

    // 6. Xóa mã OTP đã sử dụng
    await this.authRepository.deleteVerificationCode({
      email_code_type: {
        email: body.email,
        code: body.code,
        type: body.type
      }
    })

    return { otpToken: token }
  }

  async register(body: RegisterBodyType) {
    try {
      // 1. Kiểm tra otpToken
      await this.validateOtpToken({
        token: body.otpToken,
        email: body.email,
        type: TypeOfVerificationCode.REGISTER
      })

      // 2. Đăng ký tài khoản mới
      const clientRoleId = await this.rolesService.getClientRoleId()
      const hashedPassword = await this.hashingService.hash(body.password)
      const user = await this.authRepository.createUser({
        email: body.email,
        name: body.name,
        phoneNumber: body.phoneNumber,
        password: hashedPassword,
        roleId: clientRoleId
      })

      // 3. Xóa otpToken đã sử dụng
      await this.authRepository.deleteOtpToken({ token: body.otpToken })

      return user
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw EmailAlreadyExistsException
      }
      throw error
    }
  }

  async sendOTP(body: SendOTPBodyType) {
    const user = await this.sharedUserRepository.findUnique({
      email: body.email
    })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw EmailAlreadyExistsException
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      throw EmailNotFoundException
    }

    // 1. Xóa các mã OTP cũ của người dùng cùng loại (nếu có)
    await this.authRepository.deleteVerificationCodesByEmailAndType({
      email: body.email,
      type: body.type
    })

    // 2. Tạo mã OTP mới với thời hạn 15 phút
    const code = generateOTP()
    await this.authRepository.createVerificationCode({
      email: body.email,
      code,
      type: body.type,
      expiresAt: addMilliseconds(new Date(), ms('15m'))
    })

    // 3. Gửi mã OTP
    const { error } = await this.emailService.sendOTP({
      email: body.email,
      code
    })
    if (error) {
      throw FailedToSendOTPException
    }
    return { message: 'Gửi mã OTP thành công' }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }) {
    // 1. Lấy thông tin user, kiểm tra user có tồn tại hay không, mật khẩu có đúng không
    const user = await this.authRepository.findUniqueUserIncludeRole({
      email: body.email
    })

    if (!user) {
      throw EmailNotFoundException
    }

    const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
    if (!isPasswordMatch) {
      throw InvalidPasswordException
    }

    // 2. Nếu user đã bật 2FA và không có thông tin xác thực 2FA
    if (user.totpSecret && !body.totpCode && !body.code && !body.otpToken) {
      // Tạo loginSessionToken cho phiên xác thực 2FA
      const loginSessionToken = uuidv4()
      // Lưu token vào bảng OtpToken với loại LOGIN
      await this.authRepository.createOtpToken({
        token: loginSessionToken,
        email: user.email,
        type: TypeOfVerificationCode.LOGIN,
        userId: user.id,
        expiresAt: addMilliseconds(new Date(), ms('5m')) // Thời hạn 5 phút
      })

      // Trả về loginSessionToken và thông báo cần 2FA
      return {
        loginSessionToken,
        message: '2FA required',
        twoFactorEnabled: true
      }
    }

    // 3. Nếu user đã bật 2FA và có thông tin xác thực
    if (user.totpSecret) {
      // Xử lý otpToken
      if (body.otpToken) {
        await this.validateOtpToken({
          token: body.otpToken,
          email: user.email,
          type: TypeOfVerificationCode.LOGIN
        })

        // Xóa otpToken đã sử dụng
        await this.authRepository.deleteOtpToken({ token: body.otpToken })
      }
      // Xử lý totpCode hoặc code
      else if (!body.totpCode && !body.code) {
        throw InvalidTOTPAndCodeException
      } else if (body.totpCode) {
        const isValid = this.twoFactorService.verifyTOTP({
          email: user.email,
          secret: user.totpSecret,
          token: body.totpCode
        })
        if (!isValid) {
          throw InvalidTOTPException
        }
      } else if (body.code) {
        // Kiểm tra mã OTP
        await this.validateVerificationCode({
          email: user.email,
          code: body.code,
          type: TypeOfVerificationCode.LOGIN
        })

        // Xóa verification code đã sử dụng
        await this.authRepository.deleteVerificationCode({
          email_code_type: {
            email: user.email,
            code: body.code,
            type: TypeOfVerificationCode.LOGIN
          }
        })
      }
    }

    // 4. Tạo mới device
    const device = await this.authRepository.createDevice({
      userId: user.id,
      userAgent: body.userAgent,
      ip: body.ip
    })

    // 5. Tạo mới accessToken và refreshToken
    const tokens = await this.generateTokens({
      userId: user.id,
      deviceId: device.id,
      roleId: user.roleId,
      roleName: user.role.name
    })
    return tokens
  }

  async generateTokens({ userId, deviceId, roleId, roleName }: AccessTokenPayloadCreate) {
    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccessToken({
        userId,
        deviceId,
        roleId,
        roleName
      }),
      this.tokenService.signRefreshToken({
        userId
      })
    ])
    const decodedRefreshToken = await this.tokenService.verifyRefreshToken(refreshToken)
    await this.authRepository.createRefreshToken({
      token: refreshToken,
      userId,
      expiresAt: new Date(decodedRefreshToken.exp * 1000), // 7 ngày
      deviceId
    })
    return { accessToken, refreshToken }
  }

  async refreshToken({ refreshToken, userAgent, ip }: RefreshTokenBodyType & { userAgent: string; ip: string }) {
    try {
      // 1. Kiểm tra refreshToken có hợp lệ không
      const { userId } = await this.tokenService.verifyRefreshToken(refreshToken)
      // 2. Kiểm tra refreshToken có tồn tại trong database không
      const refreshTokenInDb = await this.authRepository.findUniqueRefreshTokenIncludeUserRole({
        token: refreshToken
      })
      if (!refreshTokenInDb) {
        // Trường hợp đã refresh token rồi, hãy thông báo cho user biết
        // refresh token của họ đã bị đánh cắp
        throw RefreshTokenAlreadyUsedException
      }
      const {
        deviceId,
        user: {
          roleId,
          role: { name: roleName }
        }
      } = refreshTokenInDb
      // 3. Cập nhật device
      const $updateDevice = this.authRepository.updateDevice(deviceId, {
        ip,
        userAgent
      })
      // 4. Xóa refreshToken cũ
      const $deleteRefreshToken = this.authRepository.deleteRefreshToken({
        token: refreshToken
      })
      // 5. Tạo mới accessToken và refreshToken
      const $tokens = this.generateTokens({ userId, roleId, roleName, deviceId })
      const [, , tokens] = await Promise.all([$updateDevice, $deleteRefreshToken, $tokens])
      return tokens
    } catch (error) {
      if (error instanceof HttpException) {
        throw error
      }
      throw UnauthorizedAccessException
    }
  }

  async logout(refreshToken: string) {
    try {
      // 1. Kiểm tra refreshToken có hợp lệ không
      await this.tokenService.verifyRefreshToken(refreshToken)
      // 2. Xóa refreshToken trong database
      const deletedRefreshToken = await this.authRepository.deleteRefreshToken({
        token: refreshToken
      })
      // 3. Cập nhật device là đã logout
      await this.authRepository.updateDevice(deletedRefreshToken.deviceId, {
        isActive: false
      })
      return { message: 'Đăng xuất thành công' }
    } catch (error) {
      // Trường hợp đã refresh token rồi, hãy thông báo cho user biết
      // refresh token của họ đã bị đánh cắp
      if (isNotFoundPrismaError(error)) {
        throw RefreshTokenAlreadyUsedException
      }
      throw UnauthorizedAccessException
    }
  }

  async resetPassword(body: ResetPasswordBodyType) {
    const { email, otpToken, newPassword } = body
    // 1. Kiểm tra email đã tồn tại trong database chưa
    const user = await this.sharedUserRepository.findUnique({
      email
    })
    if (!user) {
      throw EmailNotFoundException
    }

    // 2. Kiểm tra otpToken
    await this.validateOtpToken({
      token: otpToken,
      email,
      type: TypeOfVerificationCode.FORGOT_PASSWORD
    })

    // 3. Cập nhật lại mật khẩu mới và xóa đi token
    const hashedPassword = await this.hashingService.hash(newPassword)
    await Promise.all([
      this.authRepository.updateUser(
        { id: user.id },
        {
          password: hashedPassword
        }
      ),
      this.authRepository.deleteOtpToken({ token: otpToken })
    ])

    return {
      message: 'Đổi mật khẩu thành công'
    }
  }

  async setupTwoFactorAuth(userId: number) {
    // 1. Lấy thông tin user, kiểm tra xem user có tồn tại hay không, và xem họ đã bật 2FA chưa
    const user = await this.sharedUserRepository.findUnique({
      id: userId
    })
    if (!user) {
      throw EmailNotFoundException
    }
    if (user.totpSecret) {
      throw TOTPAlreadyEnabledException
    }
    // 2. Tạo ra secret và uri
    const { secret, uri } = this.twoFactorService.generateTOTPSecret(user.email)
    // 3. Cập nhật secret vào user trong database
    await this.authRepository.updateUser({ id: userId }, { totpSecret: secret })
    // 4. Trả về secret và uri
    return {
      secret,
      uri
    }
  }

  async disableTwoFactorAuth(data: DisableTwoFactorBodyType & { userId: number }) {
    const { userId, totpCode, code } = data
    // 1. Lấy thông tin user, kiểm tra xem user có tồn tại hay không, và xem họ đã bật 2FA chưa
    const user = await this.sharedUserRepository.findUnique({ id: userId })
    if (!user) {
      throw EmailNotFoundException
    }
    if (!user.totpSecret) {
      throw TOTPNotEnabledException
    }

    // 2. Kiểm tra mã TOTP có hợp lệ hay không
    if (totpCode) {
      const isValid = this.twoFactorService.verifyTOTP({
        email: user.email,
        secret: user.totpSecret,
        token: totpCode
      })
      if (!isValid) {
        throw InvalidTOTPException
      }
    } else if (code) {
      // 3. Kiểm tra mã OTP email có hợp lệ hay không
      await this.validateVerificationCode({
        email: user.email,
        code,
        type: TypeOfVerificationCode.DISABLE_2FA
      })
    }

    // 4. Cập nhật secret thành null
    await this.authRepository.updateUser({ id: userId }, { totpSecret: null })

    // 5. Trả về thông báo
    return {
      message: 'Tắt 2FA thành công'
    }
  }

  async verifyTwoFactor(body: TwoFactorVerifyBodyType & { userAgent: string; ip: string }) {
    // 1. Tìm loginSessionToken trong bảng OtpToken
    const otpToken = await this.authRepository.findUniqueOtpToken({ token: body.loginSessionToken })

    if (!otpToken) {
      throw InvalidOTPTokenException
    }

    if (otpToken.expiresAt < new Date()) {
      throw OTPTokenExpiredException
    }

    // 2. Lấy thông tin user
    if (!otpToken.userId) {
      throw InvalidLoginSessionException
    }

    const user = await this.authRepository.findUniqueUserIncludeRole({
      id: otpToken.userId
    })

    if (!user) {
      throw EmailNotFoundException
    }

    // 3. Xác thực 2FA
    if (body.method === 'TOTP') {
      // Xác thực TOTP
      if (!user.totpSecret) {
        throw TOTPNotEnabledException
      }

      const isValid = this.twoFactorService.verifyTOTP({
        email: user.email,
        secret: user.totpSecret,
        token: body.code
      })

      if (!isValid) {
        throw InvalidTOTPException
      }
    } else {
      // Xác thực OTP
      await this.validateVerificationCode({
        email: user.email,
        code: body.code,
        type: TypeOfVerificationCode.LOGIN
      })

      // Xóa verification code đã sử dụng
      await this.authRepository.deleteVerificationCode({
        email_code_type: {
          email: user.email,
          code: body.code,
          type: TypeOfVerificationCode.LOGIN
        }
      })
    }

    // 4. Xóa loginSessionToken đã sử dụng
    await this.authRepository.deleteOtpToken({ token: body.loginSessionToken })

    // 5. Tạo mới device
    const device = await this.authRepository.createDevice({
      userId: user.id,
      userAgent: body.userAgent,
      ip: body.ip
    })

    // 6. Tạo mới accessToken và refreshToken
    const tokens = await this.generateTokens({
      userId: user.id,
      deviceId: device.id,
      roleId: user.roleId,
      roleName: user.role.name
    })

    return tokens
  }
}
