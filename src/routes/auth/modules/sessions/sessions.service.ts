import { Injectable, Logger, Inject } from '@nestjs/common'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from 'src/routes/auth/auth.error'
import { ConfigService } from '@nestjs/config'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { SessionRepository, SessionPaginationOptions } from '../../repositories/session.repository'
import { DeviceRepository } from '../../repositories/device.repository'
import { ISessionService } from 'src/shared/types/auth.types'
import * as crypto from 'crypto'
import { EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService, SecurityAlertType } from 'src/shared/services/email.service'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class SessionsService implements ISessionService {
  private readonly logger = new Logger(SessionsService.name)

  constructor(
    private readonly tokenService: TokenService,
    private readonly i18nService: I18nService,
    private readonly configService: ConfigService,
    private readonly sessionRepository: SessionRepository,
    private readonly deviceRepository: DeviceRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    private readonly prismaService: PrismaService
  ) {}

  /**
   * Lấy danh sách sessions của user
   */
  async getSessions(userId: number, page: number = 1, limit: number = 10) {
    const options: SessionPaginationOptions = { page, limit }
    return this.sessionRepository.findSessionsByUserId(userId, options)
  }

  /**
   * Thu hồi một session
   */
  async revokeSession(userId: number, sessionId: string, currentSessionId?: string): Promise<{ message: string }> {
    // Kiểm tra session có tồn tại và thuộc về user không
    const session = await this.sessionRepository.findById(sessionId)

    if (!session || session.userId !== userId) {
      throw AuthError.SessionNotFound()
    }

    // Thu hồi session
    await this.tokenService.invalidateSession(sessionId, 'USER_REVOKED')

    return {
      message: await this.i18nService.translate('Auth.Session.Revoked')
    }
  }

  /**
   * Thu hồi nhiều session
   */
  async revokeSessions(
    userId: number,
    options: {
      sessionIds?: string[]
      revokeAll?: boolean
      excludeCurrentSession?: boolean
    },
    currentSessionId?: string
  ): Promise<{ message: string; revokedCount: number }> {
    const { sessionIds, revokeAll, excludeCurrentSession } = options
    let revokedCount = 0

    if (revokeAll) {
      // Thu hồi tất cả session
      if (excludeCurrentSession && currentSessionId) {
        // Lấy tất cả session trừ current session
        const sessions = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })

        // Lọc ra session cần thu hồi
        const sessionsToRevoke = sessions.data.filter((session) => session.id !== currentSessionId)

        // Thu hồi từng session
        for (const session of sessionsToRevoke) {
          await this.tokenService.invalidateSession(session.id, 'USER_REVOKED_BULK')
          revokedCount++
        }
      } else {
        // Thu hồi tất cả session
        const result = await this.sessionRepository.deleteAllUserSessions(
          userId,
          excludeCurrentSession ? currentSessionId : undefined
        )
        revokedCount = result.count
      }
    } else if (sessionIds && sessionIds.length > 0) {
      // Thu hồi các session cụ thể
      for (const sessionId of sessionIds) {
        // Bỏ qua session hiện tại nếu được yêu cầu
        if (excludeCurrentSession && sessionId === currentSessionId) {
          continue
        }

        try {
          const session = await this.sessionRepository.findById(sessionId)

          // Chỉ thu hồi session thuộc về user
          if (session && session.userId === userId) {
            await this.tokenService.invalidateSession(sessionId, 'USER_REVOKED_SELECTED')
            revokedCount++
          }
        } catch (error) {
          this.logger.error(`Lỗi thu hồi session ${sessionId}: ${error.message}`)
        }
      }
    }

    return {
      message: await this.i18nService.translate('Auth.Session.AllRevoked'),
      revokedCount
    }
  }

  /**
   * Cập nhật tên thiết bị
   */
  async updateDeviceName(userId: number, deviceId: string, name: string): Promise<{ message: string }> {
    // Kiểm tra device có tồn tại và thuộc về user không
    const device = await this.deviceRepository.findById(parseInt(deviceId))

    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotFound()
    }

    // Cập nhật tên thiết bị
    await this.deviceRepository.updateDeviceName(parseInt(deviceId), name)

    return {
      message: await this.i18nService.translate('Auth.Device.NameUpdated')
    }
  }

  /**
   * Tạo device fingerprint từ các thông số thiết bị
   */
  private generateFingerprint(userAgent: string, ip: string): string {
    // Sử dụng crypto để tạo ra hash từ thông tin thiết bị
    const data = `${userAgent}|${ip}`
    return crypto.createHash('md5').update(data).digest('hex')
  }

  /**
   * Đánh dấu thiết bị là đáng tin cậy
   */
  async trustDevice(userId: number, deviceId: string, ip?: string, userAgent?: string): Promise<{ message: string }> {
    // Kiểm tra device có tồn tại và thuộc về user không
    const device = await this.deviceRepository.findById(parseInt(deviceId))

    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotOwnedByUser()
    }

    // Kiểm tra thiết bị đã được tin cậy chưa
    if (device.isTrusted && device.trustExpiration && new Date() <= device.trustExpiration) {
      return {
        message: await this.i18nService.translate('Auth.Device.AlreadyTrusted')
      }
    }

    // Cập nhật fingerprint nếu có thông tin userAgent và IP
    if (userAgent && ip) {
      const fingerprint = this.generateFingerprint(userAgent, ip)
      await this.deviceRepository.updateDeviceFingerprint(parseInt(deviceId), fingerprint)
    }

    // Đánh dấu thiết bị là đáng tin cậy với thời hạn 30 ngày
    await this.deviceRepository.updateDeviceTrustStatus(parseInt(deviceId), true)

    // Tìm thông tin user để gửi email
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: { email: true, userProfile: true }
    })

    if (user) {
      // Gửi email thông báo về việc thiết bị được tin cậy
      try {
        await this.emailService.sendSecurityAlertEmail(SecurityAlertType.LOGIN_FROM_NEW_DEVICE, user.email, {
          userName: user.userProfile?.firstName || user.email,
          ipAddress: ip || device.ip,
          device: userAgent || device.userAgent,
          location: device.lastKnownCity ? `${device.lastKnownCity}, ${device.lastKnownCountry}` : 'Unknown',
          isTrusted: true,
          deviceName: device.name || 'Unknown device'
        })
      } catch (error) {
        this.logger.error(`Failed to send device trust notification email: ${error.message}`, error.stack)
        // Không break luồng nếu gửi email thất bại
      }
    }

    return {
      message: await this.i18nService.translate('Auth.Device.Trusted')
    }
  }

  /**
   * Bỏ đánh dấu thiết bị là đáng tin cậy
   */
  async untrustDevice(userId: number, deviceId: string, activeUser?: AccessTokenPayload): Promise<{ message: string }> {
    // Kiểm tra device có tồn tại và thuộc về user không
    const device = await this.deviceRepository.findById(parseInt(deviceId))

    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotOwnedByUser()
    }

    // Bỏ đánh dấu thiết bị là đáng tin cậy
    await this.deviceRepository.updateDeviceTrustStatus(parseInt(deviceId), false)

    // Nếu thiết bị hiện tại đang được bỏ tin cậy, thu hồi tất cả các session của thiết bị
    if (activeUser && activeUser.deviceId === parseInt(deviceId)) {
      // Thu hồi tất cả session thuộc về thiết bị này
      const sessions = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })

      // Lọc ra session thuộc về thiết bị này
      const deviceSessions = sessions.data.filter((session) => session.deviceId === parseInt(deviceId))

      // Thu hồi từng session
      for (const session of deviceSessions) {
        await this.tokenService.invalidateSession(session.id, 'DEVICE_UNTRUSTED')
      }
    }

    return {
      message: await this.i18nService.translate('Auth.Device.Untrusted')
    }
  }

  /**
   * Đánh dấu thiết bị hiện tại là đáng tin cậy
   */
  async trustCurrentDevice(
    userId: number,
    deviceId: number,
    ip?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    // Lấy thông tin thiết bị
    const device = await this.deviceRepository.findById(deviceId)

    if (!device || device.userId !== userId) {
      throw AuthError.DeviceNotOwnedByUser()
    }

    // Kiểm tra thiết bị đã được tin cậy chưa
    if (device.isTrusted && device.trustExpiration && new Date() <= device.trustExpiration) {
      return {
        message: await this.i18nService.translate('Auth.Device.AlreadyTrusted')
      }
    }

    // Cập nhật fingerprint nếu có thông tin
    if (userAgent && ip) {
      const fingerprint = this.generateFingerprint(userAgent, ip)
      await this.deviceRepository.updateDeviceFingerprint(deviceId, fingerprint)
    }

    // Đánh dấu thiết bị là đáng tin cậy với thời hạn 30 ngày
    await this.deviceRepository.updateDeviceTrustStatus(deviceId, true)

    // Tìm thông tin user để gửi email
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: { email: true, userProfile: true }
    })

    if (user) {
      // Gửi email thông báo về việc thiết bị được tin cậy
      try {
        await this.emailService.sendSecurityAlertEmail(SecurityAlertType.LOGIN_FROM_NEW_DEVICE, user.email, {
          userName: user.userProfile?.firstName || user.email,
          ipAddress: ip || device.ip,
          device: userAgent || device.userAgent,
          location: device.lastKnownCity ? `${device.lastKnownCity}, ${device.lastKnownCountry}` : 'Unknown',
          isTrusted: true,
          deviceName: device.name || 'Unknown device'
        })
      } catch (error) {
        this.logger.error(`Failed to send device trust notification email: ${error.message}`, error.stack)
        // Không break luồng nếu gửi email thất bại
      }
    }

    return {
      message: await this.i18nService.translate('Auth.Device.Trusted')
    }
  }
}
