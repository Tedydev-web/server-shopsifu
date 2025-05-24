import { Injectable, NestInterceptor, ExecutionContext, CallHandler, UnauthorizedException } from '@nestjs/common'
import { Observable, throwError } from 'rxjs'
import { catchError, switchMap } from 'rxjs/operators'
import { TokenService } from '../providers/token.service'
import { Request, Response } from 'express'
import { REQUEST_USER_KEY } from '../../../shared/constants/auth.constant'
import { Logger } from '@nestjs/common'

@Injectable()
export class TokenRefreshInterceptor implements NestInterceptor {
  private readonly logger = new Logger(TokenRefreshInterceptor.name)

  constructor(private readonly tokenService: TokenService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((error) => {
        if (!(error instanceof UnauthorizedException)) {
          return throwError(() => error)
        }

        this.logger.debug('Caught UnauthorizedException - attempting token refresh')

        const request = context.switchToHttp().getRequest<Request>()
        const response = context.switchToHttp().getResponse<Response>()

        const refreshToken = this.tokenService.extractRefreshTokenFromRequest(request)

        if (!refreshToken) {
          this.logger.debug('No refresh token available for auto-refresh')
          return throwError(() => error)
        }

        return this.tryRefreshToken(refreshToken, request).pipe(
          switchMap((result) => {
            if (!result.success) {
              return throwError(() => error)
            }

            if (result.tokens) {
              this.tokenService.setTokenCookies(
                response,
                result.tokens.accessToken,
                result.tokens.refreshToken || '',
                result.tokens.maxAgeForRefreshTokenCookie
              )
            }

            request[REQUEST_USER_KEY] = {
              userId: result.payload.userId,
              deviceId: result.payload.deviceId,
              roleId: result.payload.roleId,
              roleName: result.payload.roleName,
              exp: result.payload.exp,
              iat: result.payload.iat
            }

            return next.handle()
          })
        )
      })
    )
  }

  private tryRefreshToken(
    refreshToken: string,
    request: Request
  ): Observable<{
    success: boolean
    tokens?: {
      accessToken: string
      refreshToken?: string
      maxAgeForRefreshTokenCookie?: number
    }
    payload?: any
  }> {
    return new Observable((subscriber) => {
      this.tokenService
        .refreshTokenSilently(refreshToken, request.headers['user-agent']?.toString() || '', request.ip || '')
        .then((result) => {
          if (!result || !result.accessToken) {
            this.logger.debug('Failed to silently refresh token')
            subscriber.next({ success: false })
            subscriber.complete()
            return
          }

          this.logger.debug('Token refreshed successfully')

          this.tokenService
            .verifyAccessToken(result.accessToken)
            .then((payload) => {
              subscriber.next({
                success: true,
                tokens: {
                  accessToken: result.accessToken,
                  refreshToken: result.refreshToken,
                  maxAgeForRefreshTokenCookie: result.maxAgeForRefreshTokenCookie
                },
                payload
              })
              subscriber.complete()
            })
            .catch((decodeError) => {
              this.logger.error('Error decoding new access token', decodeError)
              subscriber.next({ success: false })
              subscriber.complete()
            })
        })
        .catch((refreshError) => {
          this.logger.debug('Error during silent token refresh', refreshError)
          subscriber.next({ success: false })
          subscriber.complete()
        })
    })
  }
}
