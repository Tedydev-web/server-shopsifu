import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger, Inject } from '@nestjs/common'
import { Observable, throwError } from 'rxjs'
import { catchError } from 'rxjs/operators'
import { Request, Response } from 'express'
import { ConfigService } from '@nestjs/config'
import { ITokenService, ICookieService } from 'src/shared/types/auth.types'
import { COOKIE_SERVICE, TOKEN_SERVICE } from 'src/shared/constants/injection.tokens'

@Injectable()
export class TokenRefreshInterceptor implements NestInterceptor {
  private readonly logger = new Logger(TokenRefreshInterceptor.name)

  constructor(
    @Inject(TOKEN_SERVICE) private readonly tokenService: ITokenService,
    @Inject(COOKIE_SERVICE) private readonly cookieService: ICookieService,
    private readonly configService: ConfigService
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((err) => {
        // Chỉ xử lý lỗi token hết hạn
        if (err instanceof Error && err.message.includes('expired')) {
          const req = context.switchToHttp().getRequest<Request>()
          const res = context.switchToHttp().getResponse<Response>()

          // Thử làm mới token với refresh token
          try {
            const refreshToken = this.tokenService.extractRefreshTokenFromRequest(req)
            if (refreshToken) {
              // Xử lý tự động làm mới token
              this.logger.log('Trying to refresh expired token')

              // Trong môi trường production, sẽ triển khai logic thực tế
              // Hiện tại, chỉ log và để token cũ hết hạn
              return throwError(() => err)
            }
          } catch (refreshError) {
            this.logger.error(`Error refreshing token: ${refreshError.message}`)
          }
        }
        return throwError(() => err)
      })
    )
  }
}
