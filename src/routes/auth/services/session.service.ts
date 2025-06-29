import { Injectable, Logger } from '@nestjs/common'
import { Response } from 'express'
import { CoreAuthService } from './core.service'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { TokenService } from 'src/shared/services/token.service'
import { CookieService } from 'src/shared/services/cookie.service'
import { AuthError } from '../auth.error'
import { SessionRepository } from '../repositories/session.repository'
import { GlobalError } from 'src/shared/global.error'
import { SessionService as SharedSessionService } from 'src/shared/services/session.service'
import { RolesService } from './roles.service'

interface RefreshTokenInput {
  refreshToken: string | undefined
  res: Response
}

interface LogoutInput {
  accessToken: string | undefined
  refreshToken: string | undefined
  res: Response
}

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name)

  constructor(
    private readonly coreAuthService: CoreAuthService,
    private readonly userRepository: SharedUserRepository,
    private readonly tokenService: TokenService,
    private readonly cookieService: CookieService,
    private readonly sessionRepository: SessionRepository,
    private readonly sharedSessionService: SharedSessionService,
    private readonly rolesService: RolesService,
  ) {}

  async refreshToken({ refreshToken, res }: RefreshTokenInput) {
    if (!refreshToken) {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.InvalidRefreshToken
    }

    const { jti, sessionId, userId } = await this.tokenService.verifyRefreshToken(refreshToken).catch(() => {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.InvalidRefreshToken
    })

    const [isUsed, isBlacklisted] = await Promise.all([
      this.sharedSessionService.isRefreshTokenUsed(jti),
      this.sharedSessionService.isBlacklisted(jti),
    ])

    if (isUsed || isBlacklisted) {
      await this.sharedSessionService.revokeAllUserSessions(userId)
      throw AuthError.RefreshTokenReused
    }

    await this.sharedSessionService.markRefreshTokenAsUsed(jti)
    const session = await this.sharedSessionService.getSession(sessionId)

    if (!session || session.userId !== userId) {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.InvalidRefreshToken
    }
    const user = await this.userRepository.findUnique({ id: session.userId })
    if (!user) {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.UserNotFound
    }

    if (user.status !== 'ACTIVE') {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.UserNotActive
    }

    const userRole = await this.rolesService.getRoleById(user.roleId)
    if (!userRole) {
      this.cookieService.clearTokenCookies(res)
      throw AuthError.RoleNotFound
    }

    await this.sessionRepository.updateSessionLastActive(sessionId)
    const tokens = await this.coreAuthService.generateTokens({
      userId: user.id,
      sessionId: session.id,
      roleId: user.roleId,
      roleName: userRole.name,
    })

    const { exp: newRefreshTokenExp } = await this.tokenService.verifyRefreshToken(tokens.refreshToken)
    await this.sessionRepository.updateSessionOnRotation(sessionId, new Date(newRefreshTokenExp * 1000))

    this.cookieService.setTokenCookies(res, tokens.accessToken, tokens.refreshToken, true)

    return { message: 'auth.success.REFRESH_TOKEN_SUCCESS' }
  }

  async logout({ accessToken, refreshToken, res }: LogoutInput) {
    const promises: Promise<any>[] = []

    if (accessToken) {
      promises.push(this.tokenService.invalidateToken(accessToken))
    }

    if (refreshToken) {
      const revokeAndBlacklistPromise = this.tokenService
        .verifyRefreshToken(refreshToken)
        .then(({ sessionId, userId }) => {
          return this.sharedSessionService.revokeSession(userId, sessionId).then(() => {
            return this.tokenService.invalidateToken(refreshToken)
          })
        })
        .catch(() => {
          if (refreshToken) {
            return this.tokenService.invalidateToken(refreshToken)
          }
          return Promise.resolve()
        })
      promises.push(revokeAndBlacklistPromise)
    }

    this.cookieService.clearTokenCookies(res)
    await Promise.allSettled(promises)
    return { message: 'auth.success.LOGOUT_SUCCESS' }
  }
}
