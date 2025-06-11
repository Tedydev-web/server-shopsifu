import { CanActivate, ExecutionContext, ForbiddenException, Injectable, Logger, Type } from '@nestjs/common'
import { ModuleRef, Reflector } from '@nestjs/core'
import { ClsService } from 'nestjs-cls'
import { REQUEST_USER_KEY } from 'src/routes/auth/auth.constants'
import { AppAbility, CaslAbilityFactory, UserWithRolesAndPermissions } from '../casl/casl-ability.factory'
import { IPolicyHandler, PolicyHandlerCallback } from '../casl/casl.types'
import { CHECK_POLICIES_KEY } from '../decorators/check-policies.decorator'

@Injectable()
export class PoliciesGuard implements CanActivate {
  private readonly logger = new Logger(PoliciesGuard.name)

  constructor(
    private readonly reflector: Reflector,
    private readonly caslAbilityFactory: CaslAbilityFactory,
    private readonly moduleRef: ModuleRef,
    private readonly cls: ClsService
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
    const user = this.cls.get<UserWithRolesAndPermissions>(REQUEST_USER_KEY)

    if (!user) {
      this.logger.warn('PoliciesGuard could not find user in CLS context. Auth guard may have failed.')
      throw new ForbiddenException('Access Denied. User context not found for permission check.')
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
    user: UserWithRolesAndPermissions
  ): Promise<boolean> {
    if (typeof handler === 'function' && handler.prototype?.handle) {
      const policyInstance = await this.moduleRef.resolve(handler as Type<IPolicyHandler>)
      return policyInstance.handle(ability, user)
    } else {
      return (handler as PolicyHandlerCallback)(ability, user)
    }
  }
}
