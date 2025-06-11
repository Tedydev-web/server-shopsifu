import { CanActivate, ExecutionContext, Injectable, Logger, Type } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { CaslAbilityFactory, AppAbility } from '../providers/casl/casl-ability.factory'
import { CHECK_POLICIES_KEY } from '../decorators/check-policies.decorator'
import { IPolicyHandler, PolicyHandlerCallback } from '../providers/casl/casl.types'
import { ClsService } from 'nestjs-cls'
import { ModuleRef } from '@nestjs/core'
import { Request } from 'express'

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

    const request: Request = context.switchToHttp().getRequest()
    const user = this.cls.get('user')

    if (!user) {
      this.logger.warn('No user found in CLS context for policy check.')
      // Depending on your app's logic, you might want to throw an UnauthorizedException here.
      return false
    }

    const ability = this.caslAbilityFactory.createForUser(user)

    // Attach ability to request for potential use in services/controllers
    // Note: Be careful with this pattern as it can tightly couple your logic to Express.
    ;(request as any).ability = ability

    const results = await Promise.all(
      policyHandlers.map((handler) => this.execPolicyHandler(handler, ability, request))
    )

    return results.every(Boolean)
  }

  private async execPolicyHandler(
    handler: Type<IPolicyHandler> | PolicyHandlerCallback,
    ability: AppAbility,
    request: Request
  ): Promise<boolean> {
    // Check if handler is a function (callback)
    if (typeof handler === 'function' && !handler.prototype) {
      // It's a callback function
      return await (handler as PolicyHandlerCallback)(ability, request)
    }

    // It's a class-based handler
    const handlerClass = handler as Type<IPolicyHandler>
    const instance = this.moduleRef.get(handlerClass, { strict: false })
    if (!instance) {
      // This can happen if the handler is not provided in any module.
      // A solution is to have a specific module for policies or ensure they are provided where needed.
      // For now, we will try to instantiate it manually if not found.
      try {
        const handlerInstance = await this.moduleRef.create(handlerClass)
        return handlerInstance.handle(ability, request)
      } catch (e) {
        this.logger.error(`Could not instantiate policy handler: ${handlerClass.name}`, e.stack)
        throw new Error(`Could not instantiate policy handler: ${handlerClass.name}`)
      }
    }
    return instance.handle(ability, request)
  }
}
