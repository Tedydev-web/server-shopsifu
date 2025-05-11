import { HttpException, Injectable } from '@nestjs/common'
import { addMilliseconds } from 'date-fns'
import {
  LoginBodyType,
  RefreshTokenBodyType,
  RegisterBodyType,
  ResetPasswordBodyType,
  SendOTPBodyType,
  VerifyCodeBodyType,
  VerifyCodeResponseType
} from 'src/routes/auth/auth.model'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { RolesService } from 'src/routes/auth/roles.service'
import { isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helpers'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { TokenService } from 'src/shared/services/token.service'
import ms from 'ms'
import envConfig from 'src/shared/config'
import { TypeOfVerificationCode, TypeOfVerificationCodeType, TypeOfOtpToken } from 'src/shared/constants/auth.constant'
import { EmailService } from 'src/shared/services/email.service'
import { AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import {
  EmailAlreadyExistsException,
  EmailNotFoundException,
  FailedToSendOTPException,
  InvalidOTPException,
  InvalidOtpTokenException,
  InvalidOtpTokenTypeException,
  InvalidPasswordException,
  OTPExpiredException,
  OtpTokenExpiredException,
  RefreshTokenAlreadyUsedException,
  SuccessMessages,
  TooManyAttemptsException,
  UnauthorizedAccessException
} from 'src/routes/auth/error.model'
import { randomUUID } from 'crypto'
import { OtpService } from 'src/shared/services/otp.service'

@Injectable()
export class AuthService {
  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepository: AuthRepository,
    private readonly sharedUserRepository: SharedUserRepository,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService
  ) {}

  /**
   * Chuyển đổi email về dạng chữ thường để đồng nhất
   */
  private normalizeEmail(email: string): string {
    return email.toLowerCase()
  }

  async validateVerificationCode({
    email,
    code,
    type
  }: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }) {
    // Chuẩn hóa email
    email = this.normalizeEmail(email)

    // Tìm verification codes cho email và type này
    const verificationCodes = await this.authRepository.findVerificationCodesByEmailAndType(email, type)

    if (!verificationCodes || verificationCodes.length === 0) {
      throw InvalidOTPException
    }

    // Kiểm tra từng mã OTP tìm thấy
    let validVerificationCode: (typeof verificationCodes)[0] | null = null

    for (const verificationCode of verificationCodes) {
      // Kiểm tra OTP có đang active không (nếu có trường isActive)
      if (verificationCode.isActive === false) {
        continue
      }

      // Kiểm tra xem OTP đã hết hạn chưa
      if (verificationCode.expiresAt < new Date()) {
        throw OTPExpiredException
      }

      // Kiểm tra số lần thử
      if (verificationCode.attempts >= 5) {
        throw TooManyAttemptsException
      }

      // Xác thực mã OTP
      if (await this.otpService.verifyOTP(code, verificationCode.code, verificationCode.salt)) {
        validVerificationCode = verificationCode
        break
      }
    }

    // Không tìm thấy mã OTP hợp lệ
    if (!validVerificationCode) {
      // Tăng số lần thử
      await Promise.all(
        verificationCodes.map((vc) =>
          this.authRepository.updateVerificationCodeAttempts(
            {
              email_code_type: {
                email,
                code: vc.code,
                type
              }
            },
            vc.attempts + 1
          )
        )
      )
      throw InvalidOTPException
    }

    // Vô hiệu hóa tất cả mã OTP của email và type này
    await this.authRepository.invalidateOldVerificationCodes(email, type)

    return validVerificationCode
  }

  async register(body: RegisterBodyType) {
    try {
      // Xác thực token thay vì code OTP
      const otpToken = await this.authRepository.findUniqueOtpTokenWithDevice({
        token: body.token
      })

      if (!otpToken) {
        throw InvalidOtpTokenException
      }

      // Kiểm tra token đã hết hạn chưa
      if (otpToken.expiresAt < new Date()) {
        throw OtpTokenExpiredException
      }

      // Kiểm tra loại token
      if (otpToken.type !== TypeOfOtpToken.EMAIL_VERIFICATION) {
        throw InvalidOtpTokenTypeException
      }

      const clientRoleId = await this.rolesService.getClientRoleId()
      const hashedPassword = await this.hashingService.hash(body.password)

      // Tạo user và đồng thời thực hiện các thao tác khác
      const [user] = await Promise.all([
        this.authRepository.createUser({
          email: body.email,
          name: body.name,
          phoneNumber: body.phoneNumber,
          password: hashedPassword,
          roleId: clientRoleId
        }),
        // Xóa token đã sử dụng
        this.authRepository.deleteOtpToken({
          token: body.token
        }),
        // Cập nhật device với user mới tạo và đánh dấu là active
        this.authRepository.updateDevice(otpToken.deviceId, {
          isActive: true,
          lastActive: new Date() // Cập nhật thời gian hoạt động mới nhất
        })
      ])

      return user
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw EmailAlreadyExistsException
      }
      throw error
    }
  }

  async sendOTP(body: SendOTPBodyType) {
    // Chuẩn hóa email
    const email = this.normalizeEmail(body.email)

    const user = await this.authRepository.findUniqueUserIncludeRole({
      email
    })

    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw EmailAlreadyExistsException
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      throw EmailNotFoundException
    }

    // 0. Xóa các mã OTP cũ
    await this.authRepository.invalidateOldVerificationCodes(email, body.type)

    // 1. Tạo mã OTP
    const plainOtp = this.otpService.generateOTP()

    // 2. Tạo salt ngẫu nhiên
    const salt = randomUUID()

    // 3. Mã hóa OTP trước khi lưu vào database
    const hashedOtp = await this.otpService.hashOTP(plainOtp, salt)

    // 4. Lưu OTP đã mã hóa vào database
    await this.authRepository.createVerificationCode({
      email,
      code: hashedOtp,
      salt,
      type: body.type,
      expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_EXPIRES_IN))
    })

    // 5. Gửi mã OTP gốc cho người dùng
    const { error } = await this.emailService.sendOTP({
      email,
      code: plainOtp
    })

    if (error) {
      throw FailedToSendOTPException
    }

    return { message: SuccessMessages.OTP_SENT }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }) {
    // Chuẩn hóa email
    const email = this.normalizeEmail(body.email)

    const user = await this.authRepository.findUniqueUserIncludeRole({
      email
    })

    if (!user) {
      throw EmailNotFoundException
    }

    const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
    if (!isPasswordMatch) {
      throw InvalidPasswordException
    }

    // Kiểm tra xem người dùng đã xác thực OTP chưa (nếu sử dụng OTP cho đăng nhập)
    // Tìm token OTP đã xác thực thành công trong trường hợp LOGIN
    if (body.token) {
      const otpToken = await this.authRepository.findUniqueOtpTokenWithDevice({
        token: body.token
      })

      if (!otpToken) {
        throw InvalidOtpTokenException
      }

      // Kiểm tra token đã hết hạn chưa
      if (otpToken.expiresAt < new Date()) {
        throw OtpTokenExpiredException
      }

      // Kiểm tra loại token
      if (otpToken.type !== TypeOfOtpToken.EMAIL_VERIFICATION) {
        throw InvalidOtpTokenTypeException
      }

      // Xóa token sau khi đã sử dụng
      await this.authRepository.deleteOtpToken({
        token: body.token
      })

      // Cập nhật device từ token
      await this.authRepository.updateDevice(otpToken.deviceId, {
        ip: body.ip,
        userAgent: body.userAgent,
        isActive: true,
        lastActive: new Date()
      })

      // Tạo tokens từ thiết bị đã được xác thực
      const tokens = await this.generateTokens({
        userId: user.id,
        deviceId: otpToken.deviceId,
        roleId: user.roleId,
        roleName: user.role.name
      })

      return tokens
    }

    // Trường hợp không có token - luồng đăng nhập thông thường
    const device = await this.authRepository.createDevice({
      userId: user.id,
      userAgent: body.userAgent,
      ip: body.ip
    })
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
      expiresAt: new Date(decodedRefreshToken.exp * 1000),
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
      return { message: SuccessMessages.LOGOUT }
    } catch (error) {
      // Trường hợp đã refresh token rồi, hãy thông báo cho user biết
      // refresh token của họ đã bị đánh cắp
      if (isNotFoundPrismaError(error)) {
        throw RefreshTokenAlreadyUsedException
      }
      throw UnauthorizedAccessException
    }
  }

  async verifyCode(body: VerifyCodeBodyType & { userAgent: string; ip: string }): Promise<VerifyCodeResponseType> {
    // Chuẩn hóa email
    const email = this.normalizeEmail(body.email)
    const { code, type, userAgent, ip } = body

    // 1. Tìm user bằng email (không yêu cầu với REGISTER)
    const user = await this.sharedUserRepository.findUnique({
      email
    })

    // Nếu không phải REGISTER mà không tìm thấy user
    if (type !== TypeOfVerificationCode.REGISTER && !user) {
      throw EmailNotFoundException
    }

    // 2. Xác thực mã OTP
    const verificationCode = await this.validateVerificationCode({
      email,
      code,
      type
    })

    // 3. Tạo OTP token với thời hạn giới hạn
    const token = randomUUID()
    const expiresAt = addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN || '15m'))

    // 4. Xác định loại token dựa vào loại verification code
    let otpTokenType: (typeof TypeOfOtpToken)[keyof typeof TypeOfOtpToken]
    switch (type) {
      case TypeOfVerificationCode.FORGOT_PASSWORD:
        otpTokenType = TypeOfOtpToken.FORGOT_PASSWORD
        break
      case TypeOfVerificationCode.REGISTER:
      case TypeOfVerificationCode.LOGIN:
      case TypeOfVerificationCode.DISABLE_2FA:
      default:
        otpTokenType = TypeOfOtpToken.EMAIL_VERIFICATION
    }

    // 5. Đối với REGISTER type và chưa có user, chỉ trả về token và expiresAt
    // Token này sẽ được lưu tạm thời ở client và dùng để đăng ký
    if (type === TypeOfVerificationCode.REGISTER && !user) {
      // Xóa mã OTP đã sử dụng bằng ID
      await this.authRepository.deleteVerificationCode({
        id: verificationCode.id
      })

      // Trả về response với email kèm theo
      return {
        token,
        expiresAt,
        email
      }
    }

    // 6. Với các trường hợp khác (user đã tồn tại), tiếp tục xử lý như bình thường
    // Đã kiểm tra ở trên nên user không thể null ở đây
    if (!user) {
      throw EmailNotFoundException // Đảm bảo an toàn
    }

    // Tạo hoặc cập nhật device
    const device = await this.authRepository.createDevice({
      userId: user.id,
      userAgent,
      ip,
      isActive: true
    })

    // Lưu token vào database với thông tin device
    await this.authRepository.createOtpToken({
      token,
      userId: user.id,
      type: otpTokenType,
      expiresAt,
      deviceId: device.id
    })

    // Xóa mã OTP đã sử dụng bằng ID
    await this.authRepository.deleteVerificationCode({
      id: verificationCode.id
    })

    return {
      token,
      expiresAt
    }
  }

  async resetPassword(body: ResetPasswordBodyType) {
    const { token, newPassword } = body

    // 1. Tìm token trong database kèm thông tin thiết bị
    const otpToken = await this.authRepository.findUniqueOtpTokenWithDevice({ token })

    if (!otpToken) {
      throw InvalidOtpTokenException
    }

    // 2. Kiểm tra token có hết hạn chưa
    if (otpToken.expiresAt < new Date()) {
      throw OtpTokenExpiredException
    }

    // 3. Kiểm tra loại token
    if (otpToken.type !== TypeOfOtpToken.FORGOT_PASSWORD) {
      throw InvalidOtpTokenTypeException
    }

    // 4. Hash mật khẩu mới
    const hashedPassword = await this.hashingService.hash(newPassword)

    // 5. Cập nhật mật khẩu mới, xóa token, và đánh dấu thiết bị
    await Promise.all([
      this.authRepository.updateUser({ id: otpToken.userId }, { password: hashedPassword }),
      this.authRepository.deleteOtpToken({ token }),
      this.authRepository.updateDevice(otpToken.deviceId, {
        isActive: true,
        lastActive: new Date() // Cập nhật thời gian hoạt động mới nhất
      })
    ])

    return {
      message: SuccessMessages.PASSWORD_RESET
    }
  }
}
