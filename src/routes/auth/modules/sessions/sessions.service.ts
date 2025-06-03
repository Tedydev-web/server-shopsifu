import { Injectable, Logger, Inject } from '@nestjs/common'
import { TokenService } from 'src/routes/auth/shared/token/token.service'
import { I18nService } from 'nestjs-i18n'
import { AuthError } from 'src/routes/auth/auth.error'
import { ConfigService } from '@nestjs/config'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { SessionRepository, Session } from '../../repositories/session.repository'
import { DeviceRepository } from '../../repositories/device.repository'
import { ISessionService } from 'src/shared/types/auth.types'
import * as crypto from 'crypto'
import { EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'
import { EmailService, SecurityAlertType } from 'src/shared/services/email.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { DeviceSessionGroupDto, SessionItemDto, GetGroupedSessionsResponseDto } from './dto/session.dto'
import { GeolocationService } from 'src/shared/services/geolocation.service'

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
    private readonly prismaService: PrismaService,
    private readonly geolocationService: GeolocationService
  ) {}

  /**
   * Lấy danh sách sessions của user, nhóm theo device
   */
  async getSessions(
    userId: number,
    currentPage: number = 1,
    itemsPerPage: number = 5,
    currentSessionIdFromToken: string
  ): Promise<GetGroupedSessionsResponseDto> {
    this.logger.debug(
      `[getSessions] Attempting to get grouped sessions for userId: ${userId}, page: ${currentPage}, limit: ${itemsPerPage}, currentSessionId: ${currentSessionIdFromToken}`
    )

    // Lấy tất cả session của user
    const sessionResult = await this.sessionRepository.findSessionsByUserId(userId, {
      page: 1,
      limit: 1000 // Lấy tất cả session để có thể xử lý theo thiết bị
    })

    // Lấy tất cả device của user
    const devices = await this.deviceRepository.findDevicesByUserId(userId)

    const deviceGroups: DeviceSessionGroupDto[] = []

    for (const device of devices) {
      // Lọc ra các session thuộc về device hiện tại
      const deviceSessions = sessionResult.data.filter((session) => session.deviceId === device.id)

      if (deviceSessions.length === 0) {
        // Skip nếu device không có session
        continue
      }

      // Parse user agent của thiết bị
      const deviceInfo = this.parseUserAgent(deviceSessions[0]?.userAgent || 'Unknown')

      // Sắp xếp session theo lastActive mới nhất trước
      deviceSessions.sort((a, b) => b.lastActive.getTime() - a.lastActive.getTime())

      // Lấy session mới nhất
      const latestSession = deviceSessions[0]

      // Đếm số session đang hoạt động
      const activeSessionsCount = deviceSessions.filter((s) => s.isActive).length

      // Lấy thời gian hoạt động cuối cùng và vị trí từ session mới nhất
      const lastActive = latestSession?.lastActive || device.lastActive
      const location = await this.getLocationFromIP(latestSession?.ipAddress || device.ip)

      const sessionItems = await Promise.all(
        deviceSessions.map(async (session) => {
          const sessionInfo = this.parseUserAgent(session.userAgent)
          const inactiveDuration = session.isActive ? null : this.calculateInactiveDuration(session.lastActive)
          const sessionLocation = await this.getLocationFromIP(session.ipAddress)

          return {
            id: session.id,
            createdAt: session.createdAt,
            lastActive: session.lastActive,
            ipAddress: session.ipAddress,
            location: sessionLocation,
            browser: sessionInfo.browser,
            browserVersion: sessionInfo.browserVersion,
            app: this.determineApp(session.userAgent),
            isActive: session.isActive !== undefined ? session.isActive : true,
            inactiveDuration,
            isCurrentSession: session.id === currentSessionIdFromToken
          }
        })
      )

      deviceGroups.push({
        deviceId: device.id,
        deviceName: device.name,
        deviceType: deviceInfo.deviceType,
        os: deviceInfo.os,
        osVersion: deviceInfo.osVersion,
        browser: deviceInfo.browser,
        browserVersion: deviceInfo.browserVersion,
        isDeviceTrusted: device.isTrusted,
        deviceTrustExpiration: device.trustExpiration,
        lastActive,
        location,
        activeSessionsCount,
        sessions: sessionItems
      })
    }

    // Sắp xếp các device group: device có session mới nhất lên đầu
    deviceGroups.sort((a, b) => {
      const lastActiveA = a.lastActive?.getTime() || 0
      const lastActiveB = b.lastActive?.getTime() || 0
      return lastActiveB - lastActiveA
    })

    this.logger.debug(`[getSessions] Created ${deviceGroups.length} device groups.`)

    // Phân trang các device groups
    const totalItems = deviceGroups.length
    const totalPages = Math.ceil(totalItems / itemsPerPage)
    const startIndex = (currentPage - 1) * itemsPerPage
    const paginatedDeviceGroups = deviceGroups.slice(startIndex, startIndex + itemsPerPage)

    this.logger.debug(
      `[getSessions] Pagination: totalItems=${totalItems}, totalPages=${totalPages}, returning ${paginatedDeviceGroups.length} device groups for page ${currentPage}`
    )

    return {
      devices: paginatedDeviceGroups,
      meta: {
        currentPage,
        itemsPerPage,
        totalItems,
        totalPages
      }
    }
  }

  /**
   * Phân tích chuỗi User-Agent để lấy thông tin thiết bị, trình duyệt và hệ điều hành
   */
  private parseUserAgent(userAgent: string): {
    deviceType: string
    os: string
    osVersion: string
    browser: string
    browserVersion: string
  } {
    try {
      const userAgentLower = userAgent.toLowerCase()

      // Xác định loại thiết bị
      let deviceType = 'Desktop'
      if (
        userAgentLower.includes('mobile') ||
        userAgentLower.includes('android') ||
        userAgentLower.includes('iphone')
      ) {
        deviceType = 'Mobile'
      } else if (userAgentLower.includes('tablet') || userAgentLower.includes('ipad')) {
        deviceType = 'Tablet'
      }

      // Xác định hệ điều hành và phiên bản
      let os = 'Unknown'
      let osVersion = ''

      if (userAgentLower.includes('windows')) {
        os = 'Windows'
        const windowsMatch = userAgentLower.match(/windows nt (\d+\.\d+)/)
        if (windowsMatch) {
          const ntVersion = parseFloat(windowsMatch[1])
          if (ntVersion === 10.0) osVersion = '10'
          else if (ntVersion === 6.3) osVersion = '8.1'
          else if (ntVersion === 6.2) osVersion = '8'
          else if (ntVersion === 6.1) osVersion = '7'
          else osVersion = ntVersion.toString()
        }
      } else if (userAgentLower.includes('macintosh') || userAgentLower.includes('mac os')) {
        os = 'macOS'
        const macMatch = userAgentLower.match(/mac os x (\d+[._]\d+[._]?\d*)/)
        if (macMatch) {
          osVersion = macMatch[1].replace(/_/g, '.')
        }
      } else if (userAgentLower.includes('linux')) {
        os = 'Linux'
      } else if (userAgentLower.includes('android')) {
        os = 'Android'
        const androidMatch = userAgentLower.match(/android (\d+(\.\d+)*)/)
        if (androidMatch) {
          osVersion = androidMatch[1]
        }
      } else if (
        userAgentLower.includes('iphone') ||
        userAgentLower.includes('ipad') ||
        userAgentLower.includes('ipod')
      ) {
        os = 'iOS'
        const iosMatch = userAgentLower.match(/os (\d+[._]\d+[._]?\d*)/)
        if (iosMatch) {
          osVersion = iosMatch[1].replace(/_/g, '.')
        }
      }

      // Xác định trình duyệt và phiên bản
      let browser = 'Unknown'
      let browserVersion = ''

      if (userAgentLower.includes('edge') || userAgentLower.includes('edg/')) {
        browser = 'Edge'
        const edgeMatch = userAgentLower.match(/edge?\/(\d+(\.\d+)*)/)
        if (edgeMatch) {
          browserVersion = edgeMatch[1]
        }
      } else if (userAgentLower.includes('chrome')) {
        browser = 'Chrome'
        const chromeMatch = userAgentLower.match(/chrome\/(\d+(\.\d+)*)/)
        if (chromeMatch) {
          browserVersion = chromeMatch[1]
        }
      } else if (userAgentLower.includes('firefox')) {
        browser = 'Firefox'
        const firefoxMatch = userAgentLower.match(/firefox\/(\d+(\.\d+)*)/)
        if (firefoxMatch) {
          browserVersion = firefoxMatch[1]
        }
      } else if (userAgentLower.includes('safari') && !userAgentLower.includes('chrome')) {
        browser = 'Safari'
        const safariMatch = userAgentLower.match(/version\/(\d+(\.\d+)*)/)
        if (safariMatch) {
          browserVersion = safariMatch[1]
        }
      } else if (userAgentLower.includes('opera') || userAgentLower.includes('opr/')) {
        browser = 'Opera'
        const operaMatch = userAgentLower.match(/(?:opera|opr)\/(\d+(\.\d+)*)/)
        if (operaMatch) {
          browserVersion = operaMatch[1]
        }
      }

      return {
        deviceType,
        os,
        osVersion,
        browser,
        browserVersion
      }
    } catch (error) {
      this.logger.error(`[parseUserAgent] Error parsing user agent: ${error.message}`)
      return {
        deviceType: 'Unknown',
        os: 'Unknown',
        osVersion: '',
        browser: 'Unknown',
        browserVersion: ''
      }
    }
  }

  /**
   * Xác định ứng dụng từ user agent
   */
  private determineApp(userAgent: string): string {
    try {
      const userAgentLower = userAgent.toLowerCase()

      if (userAgentLower.includes('instagram')) {
        return 'Instagram'
      } else if (userAgentLower.includes('youtube')) {
        return 'YouTube'
      } else if (userAgentLower.includes('facebook')) {
        return 'Facebook'
      } else if (userAgentLower.includes('twitter')) {
        return 'Twitter'
      } else if (userAgentLower.includes('linkedin')) {
        return 'LinkedIn'
      } else if (userAgentLower.includes('safari')) {
        return 'Safari'
      } else if (userAgentLower.includes('firefox')) {
        return 'Firefox'
      } else if (userAgentLower.includes('chrome')) {
        return 'Google Chrome'
      } else if (userAgentLower.includes('edge')) {
        return 'Microsoft Edge'
      } else if (userAgentLower.includes('opera')) {
        return 'Opera'
      }

      return 'Unknown App'
    } catch (error) {
      return 'Unknown App'
    }
  }

  /**
   * Lấy thông tin vị trí từ địa chỉ IP
   */
  private async getLocationFromIP(ip: string): Promise<string> {
    try {
      // Sử dụng GeolocationService đã được cải tiến để lấy thông tin vị trí
      return await this.geolocationService.getLocationFromIP(ip)
    } catch (error) {
      this.logger.error(`Lỗi khi lấy thông tin vị trí từ IP ${ip}: ${error.message}`)
      return 'Việt Nam' // Fallback cuối cùng
    }
  }

  /**
   * Tính toán thời gian không hoạt động dựa trên lastActive
   * @param lastActiveDate Thời điểm hoạt động cuối cùng
   * @returns Chuỗi mô tả thời gian không hoạt động (vd: "5 phút", "2 giờ", "3 ngày")
   */
  private calculateInactiveDuration(lastActiveDate: Date): string {
    const now = new Date()
    const lastActive = new Date(lastActiveDate)

    // Đảm bảo lastActive không trong tương lai
    if (lastActive > now) {
      return 'Vừa xong'
    }

    const diffMs = now.getTime() - lastActive.getTime()
    const diffSeconds = Math.floor(diffMs / 1000)

    // Nếu ít hơn 60 giây
    if (diffSeconds < 60) {
      return 'Vừa xong'
    }

    // Nếu ít hơn 60 phút
    const diffMinutes = Math.floor(diffSeconds / 60)
    if (diffMinutes < 60) {
      return `${diffMinutes} phút`
    }

    // Nếu ít hơn 24 giờ
    const diffHours = Math.floor(diffMinutes / 60)
    if (diffHours < 24) {
      return `${diffHours} giờ`
    }

    // Nếu ít hơn 7 ngày
    const diffDays = Math.floor(diffHours / 24)
    if (diffDays < 7) {
      return `${diffDays} ngày`
    }

    // Nếu ít hơn 30 ngày
    const diffWeeks = Math.floor(diffDays / 7)
    if (diffWeeks < 4) {
      return `${diffWeeks} tuần`
    }

    // Nếu ít hơn 12 tháng
    const diffMonths = Math.floor(diffDays / 30)
    if (diffMonths < 12) {
      return `${diffMonths} tháng`
    }

    // Nếu hơn 12 tháng
    const diffYears = Math.floor(diffDays / 365)
    return `${diffYears} năm`
  }

  /**
   * Thu hồi một session cụ thể
   * @param userId ID của người dùng
   * @param sessionId ID của session cần thu hồi
   * @param currentSessionId ID của session hiện tại đang sử dụng
   * @returns Thông báo kết quả
   */
  async revokeSession(userId: number, sessionId: string, currentSessionId?: string): Promise<{ message: string }> {
    this.logger.debug(`[revokeSession] Đang thu hồi session ${sessionId} cho userId: ${userId}`)

    // Kiểm tra xem session có tồn tại không
    const session = await this.sessionRepository.findById(sessionId)

    if (!session) {
      this.logger.warn(`[revokeSession] Session ${sessionId} không tồn tại`)
      throw AuthError.SessionNotFound()
    }

    // Kiểm tra xem session có thuộc về user không
    if (session.userId !== userId) {
      this.logger.warn(
        `[revokeSession] Session ${sessionId} không thuộc về userId: ${userId}, mà thuộc về userId: ${session.userId}`
      )
      throw AuthError.InsufficientPermissions()
    }

    // Kiểm tra xem đang cố revoke session hiện tại không
    if (sessionId === currentSessionId) {
      this.logger.warn(`[revokeSession] Đang cố thu hồi session hiện tại: ${sessionId}`)
      throw AuthError.CannotRevokeCurrent()
    }

    try {
      // 1. Đánh dấu session không hoạt động và xóa khỏi Redis
      await this.sessionRepository.deleteSession(sessionId)
      this.logger.debug(`[revokeSession] Đã xóa session ${sessionId} khỏi Redis`)

      // 2. Vô hiệu hóa các token liên quan đến session
      await this.tokenService.invalidateSession(sessionId, 'REVOKED_BY_USER')
      this.logger.debug(`[revokeSession] Đã vô hiệu hóa session ${sessionId} trong TokenService`)

      // 3. Kiểm tra và cập nhật device nếu cần thiết
      if (session.deviceId) {
        // Kiểm tra xem còn session nào khác cho device này không
        const activeSessions = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
        const hasOtherActiveSessions = activeSessions.data.some(
          (s) => s.id !== sessionId && s.deviceId === session.deviceId && s.isActive
        )

        // Nếu không còn session nào khác, đánh dấu device là không hoạt động
        if (!hasOtherActiveSessions) {
          this.logger.debug(
            `[revokeSession] Không còn session nào cho device ${session.deviceId}, đánh dấu device không hoạt động`
          )
          await this.deviceRepository.markDeviceAsInactive(session.deviceId)
        }
      }

      // 4. Audit log
      // TODO: Thêm audit log nếu cần

      const message = this.i18nService.t('auth.Auth.Session.Revoked')
      return { message }
    } catch (error) {
      this.logger.error(`[revokeSession] Lỗi khi thu hồi session ${sessionId}: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Thu hồi nhiều sessions hoặc devices
   * @param userId ID của người dùng
   * @param options Tùy chọn thu hồi (sessionIds, deviceIds, revokeAllUserSessions, excludeCurrentSession)
   * @param activeUser Thông tin người dùng hiện tại
   * @param verificationToken Token xác thực nếu cần
   * @param otpCode Mã OTP nếu cần xác thực 2FA
   * @param ipAddress Địa chỉ IP của người dùng
   * @param userAgent Thông tin User-Agent của trình duyệt
   * @returns Thông tin về số lượng items đã thu hồi
   */
  async revokeItems(
    userId: number,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    activeUser: AccessTokenPayload,
    verificationToken?: string,
    otpCode?: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{
    message: string
    revokedSessionsCount: number
    revokedDevicesCount: number
    untrustedDevicesCount: number
    revokedSessionIds?: string[]
    revokedDeviceIds?: number[]
    requiresAdditionalVerification?: boolean
    verificationRedirectUrl?: string
  }> {
    this.logger.debug(`[revokeItems] Đang thu hồi items cho userId: ${userId}, options: ${JSON.stringify(options)}`)

    // Kiểm tra xem hành động này có yêu cầu xác thực 2FA không (nếu gỡ tất cả thiết bị hoặc hơn 3 thiết bị)
    const requiresTwoFactorAuth = options.revokeAllUserSessions || (options.deviceIds && options.deviceIds.length > 3)

    // Kiểm tra xem người dùng đã bật 2FA chưa
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: { twoFactorEnabled: true, email: true }
    })

    // Nếu cần xác thực 2FA nhưng chưa cung cấp xác thực
    if (requiresTwoFactorAuth && user?.twoFactorEnabled && !otpCode && !verificationToken) {
      // Tạo SLT token và gửi mã OTP
      // Đây là trường hợp bảo mật cao, cần xác thực OTP trước khi thực hiện hành động
      this.logger.debug(`[revokeItems] Yêu cầu xác thực 2FA trước khi thu hồi nhiều thiết bị`)

      // Trả về thông báo yêu cầu xác thực bổ sung
      return {
        message: this.i18nService.t('auth.Auth.Session.RequiresAdditionalVerification'),
        revokedSessionsCount: 0,
        revokedDevicesCount: 0,
        untrustedDevicesCount: 0,
        requiresAdditionalVerification: true,
        verificationRedirectUrl: '/auth/verify-action?action=revoke-sessions'
      }
    }

    // Đếm số lượng items bị thu hồi
    let revokedSessionsCount = 0
    let revokedDevicesCount = 0
    let untrustedDevicesCount = 0

    // Danh sách các IDs đã xử lý
    const revokedSessionIds: string[] = []
    const revokedDeviceIds: number[] = []

    // Session hiện tại của user
    const currentSessionId = activeUser.sessionId

    try {
      // 1. Thu hồi theo session IDs
      if (options.sessionIds && options.sessionIds.length > 0) {
        this.logger.debug(`[revokeItems] Thu hồi ${options.sessionIds.length} sessions cụ thể`)

        for (const sessionId of options.sessionIds) {
          // Bỏ qua session hiện tại nếu được yêu cầu
          if (options.excludeCurrentSession && sessionId === currentSessionId) {
            this.logger.debug(`[revokeItems] Bỏ qua session hiện tại: ${sessionId}`)
            continue
          }

          try {
            // Lấy thông tin session trước khi xóa
            const session = await this.sessionRepository.findById(sessionId)

            // Chỉ xử lý session thuộc về user
            if (session && session.userId === userId) {
              await this.sessionRepository.deleteSession(sessionId)
              await this.tokenService.invalidateSession(sessionId, 'BULK_REVOKE_BY_USER')
              revokedSessionsCount++
              revokedSessionIds.push(sessionId)

              this.logger.debug(`[revokeItems] Đã thu hồi session: ${sessionId}`)
            } else {
              this.logger.warn(
                `[revokeItems] Bỏ qua session ${sessionId} vì không tìm thấy hoặc không thuộc về userId: ${userId}`
              )
            }
          } catch (error) {
            this.logger.error(`[revokeItems] Lỗi khi thu hồi session ${sessionId}: ${error.message}`)
            // Tiếp tục xử lý các session khác
          }
        }
      }

      // 2. Thu hồi theo device IDs
      if (options.deviceIds && options.deviceIds.length > 0) {
        this.logger.debug(`[revokeItems] Thu hồi sessions của ${options.deviceIds.length} thiết bị`)

        for (const deviceId of options.deviceIds) {
          try {
            // Kiểm tra device có thuộc về user không
            const device = await this.deviceRepository.findById(deviceId)
            if (!device || device.userId !== userId) {
              this.logger.warn(
                `[revokeItems] Bỏ qua device ${deviceId} vì không tìm thấy hoặc không thuộc về userId: ${userId}`
              )
              continue
            }

            // Lấy tất cả sessions của device
            const sessions = await this.getDeviceSessions(userId, deviceId)

            // Thu hồi từng session của device
            for (const session of sessions) {
              // Bỏ qua session hiện tại nếu được yêu cầu
              if (options.excludeCurrentSession && session.id === currentSessionId) {
                this.logger.debug(`[revokeItems] Bỏ qua session hiện tại: ${session.id}`)
                continue
              }

              await this.sessionRepository.deleteSession(session.id)
              await this.tokenService.invalidateSession(session.id, 'DEVICE_REVOKE_BY_USER')
              revokedSessionsCount++
              revokedSessionIds.push(session.id)
            }

            // Đánh dấu device không hoạt động
            await this.deviceRepository.markDeviceAsInactive(deviceId)
            revokedDevicesCount++
            revokedDeviceIds.push(deviceId)

            // Bỏ tin tưởng device nếu đang được tin tưởng
            if (device.isTrusted) {
              await this.deviceRepository.updateDeviceTrustStatus(deviceId, false)
              untrustedDevicesCount++
            }

            this.logger.debug(`[revokeItems] Đã thu hồi device ${deviceId} và ${sessions.length} sessions liên quan`)
          } catch (error) {
            this.logger.error(`[revokeItems] Lỗi khi thu hồi device ${deviceId}: ${error.message}`)
            // Tiếp tục xử lý các device khác
          }
        }
      }

      // 3. Thu hồi tất cả sessions của user
      if (options.revokeAllUserSessions) {
        this.logger.debug(`[revokeItems] Thu hồi tất cả sessions của userId: ${userId}`)

        // Xác định session ID cần loại trừ (nếu có)
        const excludeSessionId = options.excludeCurrentSession ? currentSessionId : undefined

        // Thu hồi tất cả sessions
        const result = await this.sessionRepository.deleteAllUserSessions(userId, excludeSessionId)
        revokedSessionsCount += result.count

        // Đánh dấu tất cả devices không hoạt động (trừ device hiện tại nếu được yêu cầu)
        if (options.excludeCurrentSession && activeUser.deviceId) {
          // Tìm tất cả devices trừ device hiện tại
          const devices = await this.deviceRepository.findDevicesByUserId(userId)
          for (const device of devices) {
            if (device.id !== activeUser.deviceId) {
              await this.deviceRepository.markDeviceAsInactive(device.id)
              revokedDevicesCount++
              revokedDeviceIds.push(device.id)

              // Bỏ tin tưởng nếu đang được tin tưởng
              if (device.isTrusted) {
                await this.deviceRepository.updateDeviceTrustStatus(device.id, false)
                untrustedDevicesCount++
              }
            }
          }
        } else {
          // Đánh dấu tất cả devices không hoạt động
          const devices = await this.deviceRepository.findDevicesByUserId(userId)
          for (const device of devices) {
            await this.deviceRepository.markDeviceAsInactive(device.id)
            revokedDevicesCount++
            revokedDeviceIds.push(device.id)

            // Bỏ tin tưởng nếu đang được tin tưởng
            if (device.isTrusted) {
              await this.deviceRepository.updateDeviceTrustStatus(device.id, false)
              untrustedDevicesCount++
            }
          }
        }

        this.logger.debug(`[revokeItems] Đã thu hồi tất cả sessions của userId: ${userId}, số lượng: ${result.count}`)
      }

      // Gửi email thông báo nếu hành động có rủi ro cao
      if (revokedDevicesCount > 0 || revokedSessionsCount >= 3) {
        try {
          const userEmail = user?.email
          if (userEmail) {
            await this.emailService.sendSecurityAlertEmail(SecurityAlertType.SESSIONS_REVOKED, userEmail, {
              userName: user?.email || 'Người dùng',
              sessionCount: revokedSessionsCount,
              deviceCount: revokedDevicesCount,
              ipAddress: ipAddress || 'Không xác định',
              userAgent: userAgent || 'Không xác định',
              location: await this.geolocationService.getLocationFromIP(ipAddress || '')
            })
          }
        } catch (error) {
          this.logger.error(`[revokeItems] Lỗi khi gửi email thông báo: ${error.message}`)
        }
      }

      // Trả về thông báo phù hợp
      let message: string
      if (revokedSessionsCount === 0) {
        message = this.i18nService.t('auth.Auth.Session.NoSessionsToRevoke')
      } else {
        message = this.i18nService.t('auth.Auth.Session.RevokedSuccessfullyCount', {
          args: { count: revokedSessionsCount }
        })
      }

      return {
        message,
        revokedSessionsCount,
        revokedDevicesCount,
        untrustedDevicesCount,
        revokedSessionIds,
        revokedDeviceIds
      }
    } catch (error) {
      this.logger.error(`[revokeItems] Lỗi khi thu hồi items: ${error.message}`, error.stack)
      throw error
    }
  }

  /**
   * Lấy tất cả sessions của một device
   * @param userId ID của người dùng
   * @param deviceId ID của thiết bị
   * @returns Danh sách sessions
   */
  private async getDeviceSessions(userId: number, deviceId: number): Promise<Session[]> {
    const allSessions = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
    return allSessions.data.filter((session) => session.deviceId === deviceId)
  }

  /**
   * Cập nhật tên thiết bị
   */
  async updateDeviceName(userId: number, deviceId: number, name: string): Promise<{ message: string }> {
    this.logger.debug(
      `[updateDeviceName] User ${userId} attempting to update name for device ${deviceId} to "${name}".`
    )
    const device = await this.deviceRepository.findById(deviceId)

    if (!device || device.userId !== userId) {
      this.logger.warn(`[updateDeviceName] Device ${deviceId} not found or does not belong to user ${userId}.`)
      throw AuthError.DeviceNotOwnedByUser()
    }

    await this.deviceRepository.updateDeviceName(deviceId, name)
    this.logger.log(`[updateDeviceName] Device ${deviceId} name updated to "${name}" by user ${userId}.`)
    return {
      message: await this.i18nService.translate('Auth.Device.NameUpdatedSuccessfully')
    }
  }

  /**
   * Tạo device fingerprint từ các thông số thiết bị
   */
  private generateFingerprint(userAgent: string, ip: string): string {
    const data = `${userAgent}|${ip}`
    return crypto.createHash('md5').update(data).digest('hex')
  }

  /**
   * Đánh dấu thiết bị là đáng tin cậy
   */
  async trustDevice(userId: number, deviceId: number, ip?: string, userAgent?: string): Promise<{ message: string }> {
    this.logger.debug(
      `[trustDevice] User ${userId} attempting to trust device ${deviceId}. IP: ${ip}, UA: ${userAgent}`
    )
    const device = await this.deviceRepository.findById(deviceId)

    if (!device || device.userId !== userId) {
      this.logger.warn(`[trustDevice] Device ${deviceId} not found or does not belong to user ${userId}.`)
      throw AuthError.DeviceNotOwnedByUser()
    }

    if (device.isTrusted && device.trustExpiration && new Date() < device.trustExpiration) {
      this.logger.log(`[trustDevice] Device ${deviceId} is already trusted and trust is valid.`)
      return {
        message: await this.i18nService.translate('Auth.Device.AlreadyTrusted')
      }
    }

    if (userAgent && ip) {
      const fingerprint = this.generateFingerprint(userAgent, ip)
      await this.deviceRepository.updateDeviceFingerprint(deviceId, fingerprint)
      this.logger.debug(`[trustDevice] Updated fingerprint for device ${deviceId}.`)
    }

    await this.deviceRepository.updateDeviceTrustStatus(deviceId, true) // true for trusted, also sets new expiration
    this.logger.log(`[trustDevice] Device ${deviceId} marked as trusted by user ${userId}.`)

    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: { email: true, userProfile: true }
    })

    if (user) {
      try {
        await this.emailService.sendSecurityAlertEmail(SecurityAlertType.DEVICE_TRUSTED, user.email, {
          userName: user.userProfile?.firstName || user.email,
          ipAddress: ip || device.ip,
          device: userAgent || device.userAgent,
          location: device.lastKnownCity ? `${device.lastKnownCity}, ${device.lastKnownCountry}` : 'Unknown',
          deviceName: device.name || 'Unknown device'
        })
        this.logger.debug(`[trustDevice] Sent device trusted notification email to ${user.email}.`)
      } catch (error) {
        this.logger.error(`[trustDevice] Failed to send device trust notification email: ${error.message}`, error.stack)
      }
    }

    return {
      message: await this.i18nService.translate('Auth.Device.Trusted')
    }
  }

  /**
   * Bỏ đánh dấu thiết bị là đáng tin cậy
   * This method is primarily called internally by revokeItems or when a device is explicitly untrusted.
   */
  async untrustDevice(userId: number, deviceId: number): Promise<{ message: string }> {
    this.logger.debug(`[untrustDevice] User ${userId} attempting to untrust device ${deviceId}.`)
    const device = await this.deviceRepository.findById(deviceId)

    if (!device || device.userId !== userId) {
      this.logger.warn(`[untrustDevice] Device ${deviceId} not found or does not belong to user ${userId}.`)
      throw AuthError.DeviceNotOwnedByUser()
    }

    if (!device.isTrusted) {
      this.logger.log(`[untrustDevice] Device ${deviceId} is already untrusted.`)
      return { message: await this.i18nService.translate('Auth.Device.AlreadyUntrusted') }
    }

    await this.deviceRepository.updateDeviceTrustStatus(deviceId, false) // false for untrusted
    this.logger.log(`[untrustDevice] Device ${deviceId} marked as untrusted by user ${userId}.`)

    // Gửi email thông báo (tùy chọn)
    const user = await this.prismaService.user.findUnique({
      where: { id: userId },
      select: { email: true, userProfile: true }
    })
    if (user) {
      try {
        await this.emailService.sendSecurityAlertEmail(SecurityAlertType.DEVICE_UNTRUSTED, user.email, {
          userName: user.userProfile?.firstName || user.email,
          deviceName: device.name || 'Unknown device'
        })
        this.logger.debug(`[untrustDevice] Sent device untrusted notification email to ${user.email}.`)
      } catch (error) {
        this.logger.error(
          `[untrustDevice] Failed to send device untrust notification email: ${error.message}`,
          error.stack
        )
      }
    }

    return {
      message: await this.i18nService.translate('Auth.Device.Untrusted')
    }
  }

  /**
   * Đánh dấu thiết bị hiện tại là đáng tin cậy (Wrapper around trustDevice)
   */
  async trustCurrentDevice(
    userId: number,
    currentDeviceId: number,
    ip?: string,
    userAgent?: string
  ): Promise<{ message: string }> {
    this.logger.debug(`[trustCurrentDevice] User ${userId} attempting to trust current device ${currentDeviceId}.`)
    return this.trustDevice(userId, currentDeviceId, ip, userAgent)
  }
}
