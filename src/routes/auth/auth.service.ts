import { HttpException, Injectable } from '@nestjs/common'
import { addMilliseconds } from 'date-fns'
import {
  LoginBodyType,
  RefreshTokenBodyType,
  RegisterBodyType,
  ResetPasswordBodyType,
  SendOTPBodyType,
  VerifyCodeBodyType,
  VerifyCodeResponseType,
  VerificationCodeType
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

  async validateVerificationCode({
    email,
    code,
    type
  }: {
    email: string
    code: string
    type: TypeOfVerificationCodeType
  }) {
    // Tìm tất cả các verification code cho email và type
    const verificationCodes = await this.authRepository.findVerificationCodesByEmailAndType(email, type)

    if (!verificationCodes || verificationCodes.length === 0) {
      throw InvalidOTPException
    }

    let validCode: VerificationCodeType | null = null

    // Kiểm tra từng mã
    for (const verificationCode of verificationCodes) {
      // Kiểm tra xem đã quá số lần thử chưa
      if (verificationCode.attempts >= 5) {
        continue // Bỏ qua mã này nếu đã quá số lần thử
      }

      // Kiểm tra xem OTP đã hết hạn chưa
      if (verificationCode.expiresAt < new Date()) {
        continue // Bỏ qua mã này nếu đã hết hạn
      }

      // Xác thực mã OTP với mã đã được mã hóa
      const isValidOtp = await this.otpService.verifyOTP(code, verificationCode.code, verificationCode.salt)

      if (isValidOtp) {
        validCode = verificationCode
        break // Tìm thấy mã hợp lệ, thoát vòng lặp
      } else {
        // Tăng số lần thử cho mã này
        await this.authRepository.updateVerificationCodeAttempts(
          {
            email_code_type: {
              email,
              code: verificationCode.code,
              type
            }
          },
          verificationCode.attempts + 1
        )
      }
    }

    if (!validCode) {
      throw InvalidOTPException
    }

    return validCode
  }

  async register(body: RegisterBodyType) {
    try {
      // Xác thực mã OTP và lấy bản ghi hợp lệ
      const validCode = await this.validateVerificationCode({
        email: body.email,
        code: body.code,
        type: TypeOfVerificationCode.REGISTER
      })

      const clientRoleId = await this.rolesService.getClientRoleId()
      const hashedPassword = await this.hashingService.hash(body.password)

      const [user] = await Promise.all([
        this.authRepository.createUser({
          email: body.email,
          name: body.name,
          phoneNumber: body.phoneNumber,
          password: hashedPassword,
          roleId: clientRoleId
        }),
        this.authRepository.deleteVerificationCode({
          email_code_type: {
            email: body.email,
            code: validCode.code, // Sử dụng mã đã hash từ validCode
            type: TypeOfVerificationCode.REGISTER
          }
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
    const user = await this.sharedUserRepository.findUnique({
      email: body.email
    })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw EmailAlreadyExistsException
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      throw EmailNotFoundException
    }

    // 1. Tạo mã OTP
    const plainOtp = this.otpService.generateOTP()

    // 2. Tạo salt ngẫu nhiên
    const salt = randomUUID()

    // 3. Mã hóa OTP trước khi lưu vào database
    const hashedOtp = await this.otpService.hashOTP(plainOtp, salt)

    // 4. Lưu OTP đã mã hóa vào database
    await this.authRepository.createVerificationCode({
      email: body.email,
      code: hashedOtp,
      salt,
      type: body.type,
      expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_EXPIRES_IN))
    })

    // 5. Gửi mã OTP gốc cho người dùng
    const { error } = await this.emailService.sendOTP({
      email: body.email,
      code: plainOtp
    })

    if (error) {
      throw FailedToSendOTPException
    }

    return { message: 'Gửi mã OTP thành công' }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }) {
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

  async verifyCode(body: VerifyCodeBodyType & { userAgent: string; ip: string }): Promise<VerifyCodeResponseType> {
    const { email, code, type, userAgent, ip } = body

    // 1. Tìm user bằng email
    const user = await this.sharedUserRepository.findUnique({
      email
    })

    if (!user) {
      throw EmailNotFoundException
    }

    // 2. Xác thực mã OTP và lấy bản ghi hợp lệ
    const validCode = await this.validateVerificationCode({
      email,
      code,
      type
    })

    // 3. Tạo hoặc cập nhật device
    const device = await this.authRepository.createDevice({
      userId: user.id,
      userAgent,
      ip,
      isActive: true
    })

    // 4. Tạo OTP token với thời hạn giới hạn
    const token = randomUUID()
    const expiresAt = addMilliseconds(new Date(), ms(envConfig.OTP_TOKEN_EXPIRES_IN || '15m'))

    // 5. Lưu token vào database với thông tin device
    await this.authRepository.createOtpToken({
      token,
      userId: user.id,
      type:
        type === TypeOfVerificationCode.FORGOT_PASSWORD
          ? TypeOfOtpToken.FORGOT_PASSWORD
          : TypeOfOtpToken.EMAIL_VERIFICATION,
      expiresAt,
      deviceId: device.id
    })

    // 6. Xóa mã OTP đã sử dụng
    await this.authRepository.deleteVerificationCode({
      email_code_type: {
        email,
        code: validCode.code, // Sử dụng mã đã hash
        type
      }
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
      message: 'Đổi mật khẩu thành công'
    }
  }
}
