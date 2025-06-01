import { Injectable, NestInterceptor, ExecutionContext, CallHandler, UnauthorizedException } from '@nestjs/common'
import { Observable, throwError } from 'rxjs'
import { catchError, switchMap } from 'rxjs/operators'
import { TokenService } from '../providers/token.service'
import { Request, Response } from 'express'
import { REQUEST_USER_KEY } from '../../../shared/constants/auth.constant'
import { Logger } from '@nestjs/common'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

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


        const request = context.switchToHttp().getRequest<Request>()
        const response = context.switchToHttp().getResponse<Response>()

        const refreshToken = this.tokenService.extractRefreshTokenFromRequest(request)

        if (!refreshToken) {
          return throwError(() => error)
        }

        return this.tryRefreshToken(refreshToken, request).pipe(
          switchMap((result) => {
            if (!result.success || !result.payload) {
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

            request[REQUEST_USER_KEY] = result.payload

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
    payload?: AccessTokenPayload
  }> {
    return new Observable((subscriber) => {
      this.tokenService
        .refreshTokenSilently(refreshToken, request.headers['user-agent']?.toString() || '', request.ip || '')
        .then((result) => {
          if (!result || !result.accessToken || !result.accessTokenPayload) {
            subscriber.next({ success: false })
            subscriber.complete()
            return
          }


          subscriber.next({
            success: true,
            tokens: {
              accessToken: result.accessToken,
              refreshToken: result.refreshToken,
              maxAgeForRefreshTokenCookie: result.maxAgeForRefreshTokenCookie
            },
            payload: result.accessTokenPayload
          })
          subscriber.complete()
        })
        .catch((refreshError) => {
          subscriber.next({ success: false })
          subscriber.complete()
        })
    })
  }
}
