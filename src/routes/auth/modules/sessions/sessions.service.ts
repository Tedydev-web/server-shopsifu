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

    // Lấy TẤT CẢ session của user từ repository, không phân trang ở đây
    // Repository sẽ trả về mảng Session[]
    const allUserSessionsResult = await this.sessionRepository.findSessionsByUserId(userId, {
      page: 1,
      limit: 1000 // Lấy một số lượng lớn để đảm bảo lấy hết, hoặc sửa findSessionsByUserId để không phân trang
    })
    const allSessions: Session[] = allUserSessionsResult.data
    this.logger.debug(`[getSessions] Fetched ${allSessions.length} total sessions for userId: ${userId}`)

    if (allSessions.length === 0) {
      return {
        devices: [],
        meta: { currentPage, itemsPerPage, totalItems: 0, totalPages: 0 }
      }
    }

    // Nhóm session theo deviceId
    const sessionsByDevice = new Map<number, Session[]>()
    for (const session of allSessions) {
      if (!sessionsByDevice.has(session.deviceId)) {
        sessionsByDevice.set(session.deviceId, [])
      }
      sessionsByDevice.get(session.deviceId)?.push(session)
    }
    this.logger.debug(`[getSessions] Grouped sessions into ${sessionsByDevice.size} devices.`)

    const deviceGroups: DeviceSessionGroupDto[] = []
    const deviceIds = Array.from(sessionsByDevice.keys())

    for (const deviceId of deviceIds) {
      const device = await this.deviceRepository.findById(deviceId)
      if (!device) {
        this.logger.warn(`[getSessions] Device with ID ${deviceId} not found, skipping its sessions.`)
        continue
      }

      const deviceSessions = sessionsByDevice.get(deviceId) || []
      // Sắp xếp session trong mỗi device theo lastActive giảm dần
      deviceSessions.sort((a, b) => b.lastActive.getTime() - a.lastActive.getTime())

      const sessionItems: SessionItemDto[] = deviceSessions.map((session) => ({
        id: session.id,
        createdAt: session.createdAt,
        lastActive: session.lastActive,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        isCurrentSession: session.id === currentSessionIdFromToken
      }))

      deviceGroups.push({
        deviceId: device.id,
        deviceName: device.name,
        isDeviceTrusted: device.isTrusted,
        deviceTrustExpiration: device.trustExpiration,
        sessions: sessionItems
      })
    }

    // Sắp xếp các device group: device có session mới nhất lên đầu
    deviceGroups.sort((a, b) => {
      const lastActiveA = a.sessions[0]?.lastActive.getTime() || 0
      const lastActiveB = b.sessions[0]?.lastActive.getTime() || 0
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
   * Thu hồi một session
   */
  async revokeSession(userId: number, sessionId: string, currentSessionId?: string): Promise<{ message: string }> {
    this.logger.debug(
      `[revokeSession] User ${userId} attempting to revoke session ${sessionId}. Current session: ${currentSessionId}`
    )
    // Kiểm tra session có tồn tại và thuộc về user không
    const session = await this.sessionRepository.findById(sessionId)

    if (!session || session.userId !== userId) {
      this.logger.warn(`[revokeSession] Session ${sessionId} not found or does not belong to user ${userId}.`)
      throw AuthError.SessionNotFound()
    }

    // Kiểm tra nếu user cố gắng thu hồi session hiện tại qua endpoint này
    // (Logic phức tạp hơn về việc thu hồi session hiện tại sẽ nằm trong revokeItems)
    // if (sessionId === currentSessionId) {
    //   this.logger.warn(`[revokeSession] User ${userId} attempted to revoke their current session ${sessionId} via single revoke endpoint.`);
    //   throw new AuthError.InvalidRevokeOperation('Cannot revoke current session via this endpoint. Use logout or specific device/session management features.');
    // }

    // Thu hồi session
    await this.tokenService.invalidateSession(sessionId, 'USER_REVOKED_SINGLE')
    this.logger.log(`[revokeSession] Session ${sessionId} revoked by user ${userId}.`)

    return {
      message: await this.i18nService.translate('Auth.Session.Revoked')
    }
  }

  /**
   * Thu hồi nhiều session và/hoặc devices
   */
  async revokeItems(
    userId: number,
    options: {
      sessionIds?: string[]
      deviceIds?: number[]
      revokeAllUserSessions?: boolean
      excludeCurrentSession?: boolean
    },
    activeUser: AccessTokenPayload
  ): Promise<{
    message: string
    revokedSessionsCount: number
    revokedDevicesCount: number // Số device bị revoke (tức là tất cả session của nó bị xóa)
    untrustedDevicesCount: number // Số device bị untrusted
  }> {
    const { sessionIds, deviceIds, revokeAllUserSessions, excludeCurrentSession } = options
    const currentSessionId = activeUser.sessionId
    const currentDeviceId = activeUser.deviceId

    let revokedSessionsCount = 0
    let revokedDevicesCount = 0
    let untrustedDevicesCount = 0

    const sessionsToInvalidate = new Set<string>()
    const devicesToUntrust = new Set<number>()
    const devicesFullyRevoked = new Set<number>() // Devices mà tất cả sessions của nó đã bị revoke

    this.logger.debug(
      `[revokeItems] User ${userId} initiated revoke with options: ${JSON.stringify(options)}. Current session: ${currentSessionId}, current device: ${currentDeviceId}`
    )

    // 0. Lấy tất cả session của user để xử lý logic
    const allUserSessionsResult = await this.sessionRepository.findSessionsByUserId(userId, { page: 1, limit: 1000 })
    const allUserSessions = allUserSessionsResult.data
    const sessionsByDeviceIdMap = new Map<number, Session[]>()
    allUserSessions.forEach((s) => {
      if (!sessionsByDeviceIdMap.has(s.deviceId)) sessionsByDeviceIdMap.set(s.deviceId, [])
      sessionsByDeviceIdMap.get(s.deviceId)!.push(s)
    })

    // 1. Xử lý revokeAllUserSessions
    if (revokeAllUserSessions) {
      this.logger.log(
        `[revokeItems] User ${userId} requested to revoke all their sessions. Exclude current: ${excludeCurrentSession}`
      )
      for (const session of allUserSessions) {
        if (excludeCurrentSession && session.id === currentSessionId) {
          continue
        }
        sessionsToInvalidate.add(session.id)
        // Nếu revoke all, tất cả device liên quan cũng nên được xem xét để untrust
        devicesToUntrust.add(session.deviceId)
        devicesFullyRevoked.add(session.deviceId) // Đánh dấu là device này đã bị revoke hết session
        }
      } else {
      // 2. Xử lý revoke specific devices (deviceIds)
      if (deviceIds && deviceIds.length > 0) {
        this.logger.debug(`[revokeItems] Processing deviceIds for revocation: ${JSON.stringify(deviceIds)}`)
        for (const deviceId of deviceIds) {
          const device = await this.deviceRepository.findById(deviceId)
          if (device && device.userId === userId) {
            devicesToUntrust.add(deviceId)
            devicesFullyRevoked.add(deviceId)
            const sessionsOfDevice = sessionsByDeviceIdMap.get(deviceId) || []
            sessionsOfDevice.forEach((s) => sessionsToInvalidate.add(s.id))
            this.logger.log(
              `[revokeItems] Device ${deviceId} marked for full revocation and untrust by user ${userId}.`
            )
          } else {
            this.logger.warn(`[revokeItems] Device ${deviceId} not found or not owned by user ${userId}.`)
          }
        }
      }

      // 3. Xử lý revoke specific sessions (sessionIds)
      if (sessionIds && sessionIds.length > 0) {
        this.logger.debug(`[revokeItems] Processing sessionIds for revocation: ${JSON.stringify(sessionIds)}`)
        for (const sessionId of sessionIds) {
          const session = allUserSessions.find((s) => s.id === sessionId)
          if (session && session.userId === userId) {
            sessionsToInvalidate.add(sessionId)
            this.logger.log(`[revokeItems] Session ${sessionId} marked for revocation by user ${userId}.`)

            // Kiểm tra nếu đây là session cuối cùng của device
            const deviceSessions = sessionsByDeviceIdMap.get(session.deviceId) || []
            const activeSessionsOnDevice = deviceSessions.filter((s) => !sessionsToInvalidate.has(s.id))
            if (activeSessionsOnDevice.length === 0) {
              this.logger.log(
                `[revokeItems] Session ${sessionId} was the last active session for device ${session.deviceId}. Marking device for untrust.`
              )
              devicesToUntrust.add(session.deviceId)
              devicesFullyRevoked.add(session.deviceId)
            }
          } else {
            this.logger.warn(`[revokeItems] Session ${sessionId} not found or not owned by user ${userId}.`)
          }
        }
      }
    }

    // Thực hiện untrust devices
    for (const deviceIdToUntrust of devicesToUntrust) {
      try {
        await this.deviceRepository.updateDeviceTrustStatus(deviceIdToUntrust, false)
        untrustedDevicesCount++
        this.logger.log(`[revokeItems] Device ${deviceIdToUntrust} untrusted successfully for user ${userId}.`)
      } catch (error) {
        this.logger.error(
          `[revokeItems] Failed to untrust device ${deviceIdToUntrust} for user ${userId}: ${error.message}`,
          error.stack
        )
      }
    }
    revokedDevicesCount = devicesFullyRevoked.size

    // Thực hiện invalidate sessions
    for (const sessionIdToInvalidate of sessionsToInvalidate) {
      try {
        await this.tokenService.invalidateSession(sessionIdToInvalidate, 'USER_REVOKED_ITEMS')
        revokedSessionsCount++
        } catch (error) {
        this.logger.error(
          `[revokeItems] Failed to invalidate session ${sessionIdToInvalidate}: ${error.message}`,
          error.stack
        )
        }
      }

    this.logger.log(
      `[revokeItems] Completed for user ${userId}. Revoked sessions: ${revokedSessionsCount}, Untrusted devices: ${untrustedDevicesCount}, Fully revoked devices: ${revokedDevicesCount}.`
    )

    return {
      message: await this.i18nService.translate('Auth.Session.RevokedSuccessfullyCount', {
        args: { count: revokedSessionsCount }
      }),
      revokedSessionsCount,
      revokedDevicesCount,
      untrustedDevicesCount
    }
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
