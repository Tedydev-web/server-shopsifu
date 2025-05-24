import { Injectable, Logger } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import envConfig from 'src/shared/config'
import { AccessTokenPayload, AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import { v4 as uuidv4 } from 'uuid'
import { Request, Response } from 'express'
import { PrismaService } from './prisma.service'
import { addMilliseconds } from 'date-fns'
import { AuthRepository } from 'src/routes/auth/auth.repo'
import { PrismaClient } from '@prisma/client'
import { isNotFoundPrismaError } from 'src/shared/utils/type-guards.utils'
import { UnauthorizedAccessException } from 'src/routes/auth/auth.error'
import { Prisma } from '@prisma/client'
import { DeviceService } from './device.service'

type PrismaTransactionClient = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

@Injectable()
export class TokenService {
  private readonly logger = new Logger(TokenService.name)

  constructor(
    private readonly jwtService: JwtService,
    private readonly prismaService: PrismaService,
    private readonly authRepository: AuthRepository,
    private readonly deviceService: DeviceService
  ) {}

  signAccessToken(payload: AccessTokenPayloadCreate) {
    this.logger.debug(`Signing access token for user ${payload.userId}`)
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: envConfig.ACCESS_TOKEN_SECRET,
        expiresIn: envConfig.ACCESS_TOKEN_EXPIRES_IN,
        algorithm: 'HS256'
      }
    )
  }

  signShortLivedToken(payload: AccessTokenPayloadCreate) {
    this.logger.debug(`Signing short-lived access token for testing purposes: userId=${payload.userId}`)
    return this.jwtService.sign(
      { ...payload, uuid: uuidv4() },
      {
        secret: envConfig.ACCESS_TOKEN_SECRET,
        expiresIn: '10s',
        algorithm: 'HS256'
      }
    )
  }

  verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    return this.jwtService.verifyAsync(token, {
      secret: envConfig.ACCESS_TOKEN_SECRET
    })
  }

  extractTokenFromRequest(req: Request): string | null {
    return req.cookies?.[envConfig.cookie.accessToken.name] || this.extractTokenFromHeader(req)
  }

  extractRefreshTokenFromRequest(req: Request): string | null {
    return req.cookies?.[envConfig.cookie.refreshToken.name] || req.body?.refreshToken
  }

  setTokenCookies(res: Response, accessToken: string, refreshToken: string, maxAgeForRefreshTokenCookie?: number) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken

    const actualRefreshTokenMaxAge = maxAgeForRefreshTokenCookie ?? refreshTokenConfig.maxAge

    if (accessToken && accessTokenConfig.maxAge > 0) {
      res.cookie(accessTokenConfig.name, accessToken, {
        path: accessTokenConfig.path,
        domain: accessTokenConfig.domain,
        maxAge: accessTokenConfig.maxAge,
        httpOnly: accessTokenConfig.httpOnly,
        secure: accessTokenConfig.secure,
        sameSite: accessTokenConfig.sameSite
      })
      this.logger.debug('Access token cookie set successfully')
    } else {
      this.logger.warn(
        'res.cookie SKIPPED for access_token. Reason:',
        !accessToken ? 'AccessToken missing' : 'MaxAge not positive'
      )
    }

    if (refreshToken && actualRefreshTokenMaxAge > 0) {
      res.cookie(refreshTokenConfig.name, refreshToken, {
        path: refreshTokenConfig.path,
        domain: refreshTokenConfig.domain,
        maxAge: actualRefreshTokenMaxAge,
        httpOnly: refreshTokenConfig.httpOnly,
        secure: refreshTokenConfig.secure,
        sameSite: refreshTokenConfig.sameSite
      })
      this.logger.debug('Refresh token cookie set successfully with maxAge:', actualRefreshTokenMaxAge)
    } else {
      this.logger.warn(
        'res.cookie SKIPPED for refresh_token. Reason:',
        !refreshToken ? 'RefreshToken missing' : 'MaxAge not positive'
      )
    }
  }

  clearTokenCookies(res: Response) {
    const accessTokenConfig = envConfig.cookie.accessToken
    const refreshTokenConfig = envConfig.cookie.refreshToken
    const csrfTokenConfig = envConfig.cookie.csrfToken

    res.clearCookie(accessTokenConfig.name, {
      domain: accessTokenConfig.domain,
      path: accessTokenConfig.path,
      httpOnly: accessTokenConfig.httpOnly,
      secure: accessTokenConfig.secure,
      sameSite: accessTokenConfig.sameSite
    })

    res.clearCookie(refreshTokenConfig.name, {
      domain: refreshTokenConfig.domain,
      path: refreshTokenConfig.path,
      httpOnly: refreshTokenConfig.httpOnly,
      secure: refreshTokenConfig.secure,
      sameSite: refreshTokenConfig.sameSite
    })

    res.clearCookie(csrfTokenConfig.name, {
      domain: csrfTokenConfig.domain,
      path: csrfTokenConfig.path,
      httpOnly: csrfTokenConfig.httpOnly,
      secure: csrfTokenConfig.secure,
      sameSite: csrfTokenConfig.sameSite
    })

    this.logger.debug('All token cookies cleared successfully')
  }

  private extractTokenFromHeader(req: Request): string | null {
    const [type, token] = req.headers.authorization?.split(' ') || []
    return type === 'Bearer' ? token : null
  }

  async generateTokens(
    { userId, deviceId, roleId, roleName }: AccessTokenPayloadCreate,
    prismaTx?: PrismaTransactionClient,
    rememberMe?: boolean
  ) {
    this.logger.debug(`Generating tokens for user ${userId}, deviceId ${deviceId}, rememberMe: ${!!rememberMe}`)
    const client = prismaTx || this.prismaService

    const accessToken = this.signAccessToken({
      userId,
      deviceId,
      roleId,
      roleName
    })
    const refreshToken = uuidv4()

    let refreshTokenExpiresInMs: number
    if (rememberMe) {
      refreshTokenExpiresInMs = envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
    } else {
      refreshTokenExpiresInMs = envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE
    }
    const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)

    await this.createRefreshToken(
      {
        token: refreshToken,
        userId,
        deviceId,
        expiresAt: refreshTokenExpiresAt,
        rememberMe: !!rememberMe
      },
      client as any
    )

    return {
      accessToken,
      refreshToken,
      maxAgeForRefreshTokenCookie: refreshTokenExpiresInMs
    }
  }

  async createRefreshToken(
    data: { token: string; userId: number; expiresAt: Date; deviceId: number; rememberMe: boolean },
    tx?: PrismaTransactionClient
  ) {
    this.logger.debug(`Creating refresh token for user ${data.userId}, deviceId ${data.deviceId}`)
    const client = tx || this.prismaService
    return this.authRepository.createRefreshToken(data, client as any)
  }

  async markRefreshTokenUsed(token: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Marking refresh token as used: ${token.substring(0, 8)}...`)
    const client = tx || this.prismaService
    try {
      await client.refreshToken.update({
        where: { token },
        data: { used: true }
      })
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        this.logger.warn(`Refresh token ${token.substring(0, 8)}... not found when trying to mark as used`)
        throw UnauthorizedAccessException
      }
      this.logger.error(`Error marking refresh token as used: ${error.message}`, error.stack)
      throw error
    }
  }

  async deleteRefreshToken(token: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Deleting refresh token: ${token ? token.substring(0, 8) : 'undefined'}...`)

    if (!token) {
      this.logger.warn('Attempted to delete undefined or empty refresh token')
      return
    }

    const client = tx || this.prismaService
    try {
      await this.authRepository.deleteRefreshToken({ token }, client as any)
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        this.logger.warn(`Refresh token ${token.substring(0, 8)}... not found when trying to delete`)
        return
      }
      this.logger.error(`Error deleting refresh token: ${error.message}`, error.stack)
      throw error
    }
  }

  async deleteAllRefreshTokens(userId: number, tx?: PrismaTransactionClient, excludeTokenString?: string) {
    this.logger.debug(
      `Deleting all refresh tokens for user ${userId}` +
        (excludeTokenString ? ` excluding token ${excludeTokenString.substring(0, 8)}...` : '')
    )
    const client = tx || this.prismaService
    const whereClause: Prisma.RefreshTokenWhereInput = { userId }
    if (excludeTokenString) {
      whereClause.NOT = {
        token: excludeTokenString
      }
    }
    await client.refreshToken.deleteMany({
      where: whereClause
    })
  }

  async deleteAllRefreshTokensForDevice(deviceId: number, tx?: PrismaTransactionClient) {
    this.logger.debug(`Deleting all refresh tokens for device ${deviceId}`)
    const client = tx || this.prismaService
    await client.refreshToken.deleteMany({
      where: { deviceId }
    })
  }

  async findRefreshTokenWithUserAndDevice(token: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Finding refresh token with user and device: ${token.substring(0, 8)}...`)
    const client = tx || this.prismaService
    return client.refreshToken.findUnique({
      where: {
        token,
        used: false,
        expiresAt: {
          gt: new Date()
        }
      },
      include: {
        user: {
          include: {
            role: true
          }
        },
        device: true
      }
    })
  }

  async findRefreshToken(token: string, tx?: PrismaTransactionClient) {
    this.logger.debug(`Finding refresh token: ${token.substring(0, 8)}...`)
    const client = tx || this.prismaService
    return client.refreshToken.findUnique({
      where: { token },
      select: { userId: true, used: true, expiresAt: true, deviceId: true, rememberMe: true }
    })
  }

  async refreshTokenSilently(
    refreshToken: string,
    userAgent: string,
    ip: string
  ): Promise<{
    accessToken: string
    refreshToken?: string
    maxAgeForRefreshTokenCookie?: number
  } | null> {
    try {
      this.logger.debug('Attempting to silently refresh token')

      const existingRefreshToken = await this.findRefreshTokenWithUserAndDevice(refreshToken)

      if (!existingRefreshToken || existingRefreshToken.used || existingRefreshToken.expiresAt <= new Date()) {
        this.logger.debug('Refresh token invalid or expired during silent refresh')
        return null
      }

      await this.markRefreshTokenUsed(refreshToken)

      if (existingRefreshToken.device) {
        const userAgentMatch =
          this.deviceService.basicDeviceFingerprint(existingRefreshToken.device.userAgent) ===
          this.deviceService.basicDeviceFingerprint(userAgent)

        if (!userAgentMatch) {
          this.logger.debug('Device fingerprint mismatch during silent refresh')
          return null
        }
      } else {
        this.logger.debug('No device associated with refresh token during silent refresh')
        return null
      }

      const accessToken = this.signAccessToken({
        userId: existingRefreshToken.user.id,
        deviceId: existingRefreshToken.deviceId,
        roleId: existingRefreshToken.user.roleId,
        roleName: existingRefreshToken.user.role.name
      })

      const shouldCreateNewRefreshToken = false
      let newRefreshToken: string | undefined
      let maxAge: number | undefined

      if (shouldCreateNewRefreshToken) {
        const refreshTokenExpiresInMs = existingRefreshToken.rememberMe
          ? envConfig.REMEMBER_ME_REFRESH_TOKEN_COOKIE_MAX_AGE
          : envConfig.REFRESH_TOKEN_COOKIE_MAX_AGE

        const refreshTokenExpiresAt = addMilliseconds(new Date(), refreshTokenExpiresInMs)
        newRefreshToken = uuidv4()

        await this.createRefreshToken({
          token: newRefreshToken,
          userId: existingRefreshToken.user.id,
          deviceId: existingRefreshToken.deviceId,
          expiresAt: refreshTokenExpiresAt,
          rememberMe: existingRefreshToken.rememberMe
        })

        maxAge = refreshTokenExpiresInMs
      }

      return {
        accessToken,
        refreshToken: newRefreshToken,
        maxAgeForRefreshTokenCookie: maxAge
      }
    } catch (error) {
      this.logger.error('Error during silent token refresh', error)
      return null
    }
  }
}
