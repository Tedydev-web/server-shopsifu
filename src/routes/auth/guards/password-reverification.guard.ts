import { CanActivate, ExecutionContext, Injectable, Logger, SetMetadata } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { Observable } from 'rxjs'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { GqlExecutionContext } from '@nestjs/graphql' // Nếu dùng GraphQL
import { I18nContext, I18nService } from 'nestjs-i18n'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { HttpStatus } from '@nestjs/common'

export const SKIP_PASSWORD_REVERIFICATION_CHECK = 'skipPasswordReverificationCheck'
export const AllowWithoutPasswordReverification = () => SetMetadata(SKIP_PASSWORD_REVERIFICATION_CHECK, true)

@Injectable()
export class PasswordReverificationGuard implements CanActivate {
  private readonly logger = new Logger(PasswordReverificationGuard.name)

  constructor(
    private readonly reflector: Reflector,
    private readonly redisService: RedisService,
    private readonly i18nService: I18nService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const skipReverificationCheck = this.reflector.getAllAndOverride<boolean>(SKIP_PASSWORD_REVERIFICATION_CHECK, [
      context.getHandler(),
      context.getClass()
    ])

    if (skipReverificationCheck) {
      return true
    }

    let request
    if (context.getType() === 'http') {
      request = context.switchToHttp().getRequest()
    } else if (context.getType() === 'rpc') {
      // Xử lý cho RPC context nếu cần
      this.logger.warn('PasswordReverificationGuard not implemented for RPC context type.')
      return true // Hoặc false tùy theo yêu cầu bảo mật
    } else if (context.getType<any>() === 'graphql') {
      // Cần ép kiểu nếu dùng GqlExecutionContext
      const gqlCtx = GqlExecutionContext.create(context)
      request = gqlCtx.getContext().req
      if (!request) {
        this.logger.error('Request object is undefined in GraphQL context for PasswordReverificationGuard.')
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
    } else {
      this.logger.warn(`PasswordReverificationGuard encountered an unknown context type: ${context.getType()}`)
      return false // Chặn nếu không biết context
    }

    const activeUser = request.user as AccessTokenPayload | undefined

    if (!activeUser || !activeUser.sessionId) {
      this.logger.warn(
        'PasswordReverificationGuard: No active user or session ID found in request. Access will be denied unless skipped.'
      )
      // Điều này không nên xảy ra nếu AccessTokenGuard chạy trước nó
      // Ném lỗi rõ ràng hơn, yêu cầu đăng nhập lại
      throw new ApiException(HttpStatus.UNAUTHORIZED, 'Unauthorized', 'Error.Auth.Access.Unauthorized')
    }

    const sessionDetailsKey = `${REDIS_KEY_PREFIX.SESSION_DETAILS}${activeUser.sessionId}`
    const requiresReverification = await this.redisService.hget(sessionDetailsKey, 'requiresPasswordReverification')

    if (requiresReverification === 'true') {
      this.logger.log(
        `Session ${activeUser.sessionId} for user ${activeUser.userId} requires password reverification. Access denied.`
      )
      const currentLang = I18nContext.current()?.lang
      const message = await this.i18nService.translate('error.Error.Auth.Password.ReverificationRequired', {
        lang: currentLang,
        defaultValue: 'Your session requires password reverification to continue. Please re-enter your password.'
      })
      // Dùng một mã lỗi cụ thể để client có thể xử lý (ví dụ: redirect đến trang reverify)
      throw new ApiException(HttpStatus.FORBIDDEN, 'PasswordReverificationRequired', message, [
        {
          code: 'PASSWORD_REVERIFICATION_REQUIRED',
          path: 'session'
        }
      ])
    }
    return true
  }
}
