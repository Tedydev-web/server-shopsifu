import { Injectable, NestInterceptor, ExecutionContext, CallHandler, UnauthorizedException } from '@nestjs/common'
import { Observable, throwError } from 'rxjs'
import { catchError, switchMap } from 'rxjs/operators'
import { TokenService } from '../services/token.service'
import { Request, Response } from 'express'
import { REQUEST_USER_KEY } from 'src/shared/constants/auth.constant'
import { Logger } from '@nestjs/common'

/**
 * Interceptor để tự động làm mới token khi access token hết hạn
 * Giúp người dùng không bị đăng xuất nếu refresh token vẫn còn hiệu lực
 */
@Injectable()
export class TokenRefreshInterceptor implements NestInterceptor {
  private readonly logger = new Logger(TokenRefreshInterceptor.name)

  constructor(private readonly tokenService: TokenService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((error) => {
        // Chỉ xử lý lỗi UnauthorizedException
        if (!(error instanceof UnauthorizedException)) {
          return throwError(() => error)
        }

        this.logger.debug('Caught UnauthorizedException - attempting token refresh')

        const request = context.switchToHttp().getRequest<Request>()
        const response = context.switchToHttp().getResponse<Response>()

        // Lấy refresh token từ cookie hoặc request body
        const refreshToken = this.tokenService.extractRefreshTokenFromRequest(request)

        // Nếu không có refresh token, không thể tự động làm mới
        if (!refreshToken) {
          this.logger.debug('No refresh token available for auto-refresh')
          return throwError(() => error)
        }

        // Thử làm mới token
        return this.tryRefreshToken(refreshToken, request).pipe(
          switchMap((result) => {
            if (!result.success) {
              return throwError(() => error)
            }

            // Thiết lập token mới vào cookies
            if (result.tokens) {
              this.tokenService.setTokenCookies(
                response,
                result.tokens.accessToken,
                result.tokens.refreshToken || '',
                result.tokens.maxAgeForRefreshTokenCookie
              )
            }

            // Cập nhật payload trong request với thông tin mới
            request[REQUEST_USER_KEY] = {
              userId: result.payload.userId,
              deviceId: result.payload.deviceId,
              roleId: result.payload.roleId,
              roleName: result.payload.roleName,
              exp: result.payload.exp,
              iat: result.payload.iat
            }

            // Thực hiện lại request ban đầu với token mới
            return next.handle()
          })
        )
      })
    )
  }

  /**
   * Thử làm mới token sử dụng refresh token
   * @param refreshToken Refresh token để làm mới
   * @param request Request object
   * @param response Response object
   * @param originalError Lỗi ban đầu
   * @returns Observable với kết quả làm mới token
   */
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
      // Thực hiện refresh token
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

          // Giải mã token mới để cập nhật thông tin xác thực trong request
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
