import { CanActivate, ExecutionContext, Injectable, Logger, SetMetadata } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'
import { REDIS_KEY_PREFIX } from 'src/shared/constants/redis.constants'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { GqlExecutionContext } from '@nestjs/graphql'
import { I18nContext, I18nService } from 'nestjs-i18n'
import { ApiException } from 'src/shared/exceptions/api.exception'
import { HttpStatus } from '@nestjs/common'
import { AUTH_TYPE_KEY } from 'src/routes/auth/decorators/auth.decorator'
import { AuthType } from 'src/shared/constants/auth.constant'
import { AuthTypeDecoratorPayload } from 'src/routes/auth/decorators/auth.decorator'

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

    const authTypePayload = this.reflector.getAllAndOverride<AuthTypeDecoratorPayload | undefined>(AUTH_TYPE_KEY, [
      context.getHandler(),
      context.getClass()
    ])

    if (authTypePayload && authTypePayload.authTypes.includes(AuthType.None)) {
      this.logger.verbose('PasswordReverificationGuard: Skipping check for @IsPublic() endpoint.')
      return true
    }

    let request
    if (context.getType() === 'http') {
      request = context.switchToHttp().getRequest()
    } else if (context.getType() === 'rpc') {
      this.logger.warn('PasswordReverificationGuard not implemented for RPC context type.')
      return true
    } else if (context.getType<any>() === 'graphql') {
      const gqlCtx = GqlExecutionContext.create(context)
      request = gqlCtx.getContext().req
      if (!request) {
        this.logger.error('Request object is undefined in GraphQL context for PasswordReverificationGuard.')
        throw new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, 'ServerError', 'Error.Global.InternalServerError')
      }
    } else {
      this.logger.warn(`PasswordReverificationGuard encountered an unknown context type: ${context.getType()}`)
      return false
    }

    const activeUser = request.user as AccessTokenPayload | undefined

    if (!activeUser || !activeUser.sessionId) {
      this.logger.warn(
        'PasswordReverificationGuard: No active user or session ID found in request. Access will be denied unless skipped.'
      )

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
