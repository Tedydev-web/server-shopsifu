import { CanActivate, ExecutionContext, Inject, Injectable, Logger, OnModuleInit, forwardRef } from '@nestjs/common'
import { Reflector, ModuleRef } from '@nestjs/core'
import { UserService } from 'src/routes/user/user.service'
import {
  PERMISSIONS_KEY,
  PERMISSIONS_OPTIONS_KEY,
  PermissionCondition,
  PermissionOptions
} from 'src/shared/decorators/permissions.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { GlobalError } from 'src/shared/global.error'
import { Permission } from '@prisma/client'
import * as jsonLogic from 'json-logic-js'

type UserPermission = Pick<Permission, 'action' | 'subject' | 'conditions'>

@Injectable()
export class PermissionGuard implements CanActivate, OnModuleInit {
  private readonly logger = new Logger(PermissionGuard.name)
  private serviceMap: Map<string, any> = new Map()

  constructor(
    private readonly reflector: Reflector,
    @Inject(forwardRef(() => UserService)) private readonly userService: UserService,
    private readonly moduleRef: ModuleRef
  ) {}

  onModuleInit() {
    // We can pre-populate the service map for known subjects if needed,
    // but dynamic resolution below is more flexible.
    this.serviceMap.set('User', this.userService)
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<string[]>(PERMISSIONS_KEY, context.getHandler())
    const options = this.reflector.get<PermissionOptions>(PERMISSIONS_OPTIONS_KEY, context.getHandler()) || {}

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true
    }

    const request = context.switchToHttp().getRequest()
    const user: ActiveUserData | undefined = request.user

    if (!user) {
      this.logger.warn('[canActivate] User object not found on request. Denying access.')
      return false
    }

    const userPermissions = await this.userService.getUserPermissions(user.id)

    const hasPermission = await this.checkPermissions(requiredPermissions, userPermissions, options, context)

    if (!hasPermission) {
      this.logger.warn(`[canActivate] User ${user.id} lacks required permissions. Access denied.`)
      throw GlobalError.Forbidden()
    }

    return true
  }

  private async checkPermissions(
    requiredPermissions: string[],
    userPermissions: UserPermission[],
    options: PermissionOptions,
    context: ExecutionContext
  ): Promise<boolean> {
    const checkPromises = requiredPermissions.map((required) =>
      this.hasRequiredPermission(required, userPermissions, context)
    )

    const results = await Promise.all(checkPromises)

    if (options.condition === PermissionCondition.AND) {
      return results.every((res) => res)
    }
    return results.some((res) => res)
  }

  private async hasRequiredPermission(
    requiredPermission: string,
    userPermissions: UserPermission[],
    context: ExecutionContext
  ): Promise<boolean> {
    for (const p of userPermissions) {
      const userPermString = `${p.subject}:${p.action}`
      if (this.isPermissionMatch(requiredPermission, userPermString)) {
        if (p.conditions) {
          this.logger.debug(`Found matching permission '${userPermString}' with conditions. Evaluating...`)
          return await this.checkConditions(p.conditions, context)
        }
        this.logger.debug(`Found matching static permission '${userPermString}'. Access granted for this path.`)
        return true // Permission matches and has no conditions
      }
    }
    return false
  }

  private isPermissionMatch(required: string, userPermission: string): boolean {
    if (required === userPermission) return true

    const [reqSubject, reqAction] = required.split(':')
    const [userSubject, userAction] = userPermission.split(':')

    if (reqSubject !== userSubject) return false

    // Handle 'manage' wildcard for actions
    if (userAction === 'manage') return true
    // Handle ':own' suffix as a specific action
    if (reqAction === userAction) return true

    return false
  }

  private async checkConditions(conditions: any, context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()
    const user: ActiveUserData = request.user
    const resourceId = request.params.id

    // Lazy load resource only if conditions require it
    let resource: any = null
    const conditionsString = JSON.stringify(conditions)
    if (conditionsString.includes('resource.')) {
      if (!resourceId) {
        this.logger.warn('[checkConditions] Conditions require a resource, but no ID found in params.')
        return false
      }
      const subject = this.getSubjectFromContext(context)
      if (!subject) {
        this.logger.warn('[checkConditions] Could not determine subject from context.')
        return false
      }
      resource = await this.getResource(subject, resourceId)
      if (!resource) {
        this.logger.warn(`[checkConditions] Resource '${subject}' with ID '${resourceId}' not found.`)
        return false
      }
    }

    const data = {
      user: user,
      resource: resource
    }

    this.logger.debug(`[checkConditions] Evaluating logic with data: ${JSON.stringify(data)}`)
    return jsonLogic.apply(conditions, data)
  }

  private getSubjectFromContext(context: ExecutionContext): string | null {
    const controllerClass = context.getClass()
    const controllerName = controllerClass.name.replace('Controller', '')
    // This is a simple convention. More robust mapping might be needed.
    return controllerName
  }

  private async getResource(subject: string, id: number | string): Promise<any> {
    try {
      let service = this.serviceMap.get(subject)
      if (!service) {
        // Dynamically resolve service from module reference
        const serviceToken = `${subject}Service` // Convention: 'User' -> 'UserService'
        service = this.moduleRef.get(serviceToken, { strict: false })
        this.serviceMap.set(subject, service)
      }

      if (service && typeof service.findOne === 'function') {
        const resource = await service.findOne(Number(id))
        // The service might return a { data, message } object
        return resource?.data ? resource.data : resource
      }
      this.logger.warn(`[getResource] Could not find a 'findOne' method on the service for subject: ${subject}`)
      return null
    } catch (e) {
      this.logger.error(`[getResource] Error resolving service or fetching resource for subject: ${subject}`, e)
      return null
    }
  }
}
