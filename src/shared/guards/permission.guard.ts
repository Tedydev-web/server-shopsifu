import { CanActivate, ExecutionContext, Inject, Injectable, Logger, Type, forwardRef } from '@nestjs/common'
import { ModuleRef, Reflector } from '@nestjs/core'
import { UserService } from 'src/routes/user/user.service'
import { RequiredPermission, PERMISSIONS_KEY } from 'src/shared/decorators/permissions.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { GlobalError } from 'src/shared/global.error'
import { AppAbility, CaslAbilityFactory } from '../providers/casl/casl-ability.factory'
import { User } from 'src/routes/user/user.model'
import { Role } from 'src/routes/role/role.model'
import { Permission } from 'src/routes/permission/permission.model'

@Injectable()
export class PermissionGuard implements CanActivate {
  private readonly logger = new Logger(PermissionGuard.name)

  constructor(
    private readonly reflector: Reflector,
    private readonly moduleRef: ModuleRef,
    @Inject(forwardRef(() => UserService)) private readonly userService: UserService,
    private readonly caslAbilityFactory: CaslAbilityFactory
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions = this.reflector.get<RequiredPermission[]>(PERMISSIONS_KEY, context.getHandler())

    if (!requiredPermissions || requiredPermissions.length === 0) {
      return true
    }

    const request = context.switchToHttp().getRequest()
    const user: ActiveUserData | undefined = request.user

    if (!user) {
      throw GlobalError.Unauthorized()
    }

    const userPermissions = await this.userService.getUserPermissions(user.id)
    const ability = await this.caslAbilityFactory.createForUser(user, userPermissions)

    const checkPromises = requiredPermissions.map((permission) => this.checkPermission(permission, ability, context))

    const results = await Promise.all(checkPromises)
    const hasPermission = results.every(Boolean)

    if (!hasPermission) {
      throw GlobalError.Forbidden()
    }

    return true
  }

  private async checkPermission(
    permission: RequiredPermission,
    ability: AppAbility,
    context: ExecutionContext
  ): Promise<boolean> {
    const { action, subject } = permission

    if (typeof subject === 'string') {
      return ability.can(action, subject)
    }

    // If subject is a class, load the resource and check ability
    const resource = await this.getResource(subject, context)
    if (!resource) {
      return false
    }
    return ability.can(action, resource)
  }

  private async getResource(subject: Type, context: ExecutionContext): Promise<any> {
    const request = context.switchToHttp().getRequest()
    const resourceId = request.params.id

    if (!resourceId) {
      return null
    }

    // This service locator pattern is a point for future improvement.
    // A dedicated factory or map would be more robust.
    const serviceName = `${subject.name}Service`
    this.logger.debug(`Attempting to resolve service: ${serviceName}`)

    try {
      const service = await this.moduleRef.get(serviceName, { strict: false })
      if (!service) {
        this.logger.warn(`Service ${serviceName} not found in module context`)
        return null
      }
      
      if (typeof service.findOne === 'function') {
        const result = await service.findOne(Number(resourceId))
        // Handle services that return a { data, message } wrapper
        return this.instantiateResource(subject, result?.data || result)
      } else {
        this.logger.warn(`Service ${serviceName} does not have findOne method`)
        return null
      }
    } catch (error) {
      this.logger.error(`Error resolving service ${serviceName}:`, error.message)
      return null
    }

    return null
  }

  private instantiateResource(subject: Type, data: any): any {
    if (!data) return null
    // A simple mapping to instantiate correct class
    const subjectMap = {
      User,
      Role,
      Permission
      // Add other resource models here
    }
    const SubjectClass = subjectMap[subject.name as keyof typeof subjectMap]
    if (SubjectClass) {
      return Object.assign(new SubjectClass(), data)
    }
    return data // fallback for subjects not in the map
  }
}
