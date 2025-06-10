import { CanActivate, ExecutionContext, ForbiddenException, Injectable, Logger, Type } from '@nestjs/common'
import { Reflector, ModuleRef } from '@nestjs/core'
import { REQUEST_USER_KEY } from 'src/routes/auth/auth.constants'
import { AppAbility, CaslAbilityFactory } from '../casl/casl-ability.factory'
import { IPolicyHandler, PolicyHandlerCallback } from '../casl/casl.types'
import { CHECK_POLICIES_KEY } from '../decorators/check-policies.decorator'

@Injectable()
export class PoliciesGuard implements CanActivate {
  private readonly logger = new Logger(PoliciesGuard.name)

  constructor(
    private readonly reflector: Reflector,
    private readonly caslAbilityFactory: CaslAbilityFactory,
    private readonly moduleRef: ModuleRef
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const policyHandlers =
      this.reflector.get<Array<Type<IPolicyHandler> | PolicyHandlerCallback>>(
        CHECK_POLICIES_KEY,
        context.getHandler()
      ) || []

    if (policyHandlers.length === 0) {
      return true
    }

    const request = context.switchToHttp().getRequest()
    const user = request[REQUEST_USER_KEY]

    if (!user) {
      this.logger.warn('PoliciesGuard requires a user object on the request. Did you forget to use an auth guard?')
      throw new ForbiddenException('Access Denied. User not found for permission check.')
    }

    const ability = this.caslAbilityFactory.createForUser(user)

    for (const handler of policyHandlers) {
      const isAllowed = await this.execPolicyHandler(handler, ability, request)
      if (!isAllowed) {
        this.logger.debug(
          `User ${user.id} failed a policy check for handler ${handler.constructor?.name || 'function'}`
        )
        throw new ForbiddenException('You do not have sufficient permissions to perform this action.')
      }
    }

    return true
  }

  private async execPolicyHandler(
    handler: Type<IPolicyHandler> | PolicyHandlerCallback,
    ability: AppAbility,
    request: any
  ): Promise<boolean> {
    if (typeof handler === 'function' && handler.prototype?.handle) {
      const policyInstance = await this.moduleRef.resolve(handler as Type<IPolicyHandler>)
      return policyInstance.handle(ability, request)
    } else {
      return (handler as PolicyHandlerCallback)(ability, request)
    }
  }
}
