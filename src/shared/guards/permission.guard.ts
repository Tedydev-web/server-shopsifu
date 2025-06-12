import { Injectable, CanActivate, ExecutionContext, Logger, Inject, forwardRef } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { UserService } from 'src/routes/user/user.service'
import {
  PERMISSIONS_KEY,
  PERMISSIONS_OPTIONS_KEY,
  PermissionCondition,
  PermissionOptions
} from 'src/shared/decorators/permissions.decorator'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { GlobalError } from 'src/shared/global.error'

@Injectable()
export class PermissionGuard implements CanActivate {
  private readonly logger = new Logger(PermissionGuard.name)

  constructor(
    private readonly reflector: Reflector,
    @Inject(forwardRef(() => UserService)) private readonly userService: UserService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredPermissions =
      this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [context.getHandler(), context.getClass()]) || []

    const options = this.reflector.getAllAndOverride<PermissionOptions>(PERMISSIONS_OPTIONS_KEY, [
      context.getHandler(),
      context.getClass()
    ]) || { condition: PermissionCondition.OR }

    // Nếu endpoint không yêu cầu permission, cho phép truy cập
    if (requiredPermissions.length === 0) {
      return true
    }

    const request = context.switchToHttp().getRequest()
    const user: ActiveUserData | undefined = request.user

    if (!user) {
      this.logger.warn('[canActivate] User object not found on request. Denying access.')
      return false // or throw UnauthorizedException
    }

    this.logger.debug(
      `[canActivate] User ${user.id} attempting to access resource requiring permissions with condition: ${options.condition}`
    )
    this.logger.debug(`[canActivate] Required permissions: ${requiredPermissions.join(', ')}`)

    // Lấy permissions real-time (hoặc từ cache) của user
    const userPermissions = await this.userService.getUserPermissions(user.id)
    const userPermissionSet = new Set(userPermissions.map((p) => `${p.subject}:${p.action}`))

    this.logger.debug(`[canActivate] User has permissions: ${[...userPermissionSet].join(', ')}`)

    // Kiểm tra quyền hạn dựa trên điều kiện AND hoặc OR
    let hasPermission: boolean
    if (options.condition === PermissionCondition.AND) {
      // Yêu cầu có TẤT CẢ các quyền
      hasPermission = requiredPermissions.every((p) => this.checkSinglePermission(p, userPermissionSet, context))
    } else {
      // Yêu cầu có ÍT NHẤT MỘT trong các quyền (mặc định)
      hasPermission = requiredPermissions.some((p) => this.checkSinglePermission(p, userPermissionSet, context))
    }

    if (!hasPermission) {
      this.logger.warn(`[canActivate] User ${user.id} lacks required permissions. Access denied.`)
    } else {
      this.logger.log(`[canActivate] User ${user.id} has required permissions. Access granted.`)
    }

    return hasPermission
  }

  /**
   * Kiểm tra một quyền đơn lẻ, có hỗ trợ wildcard 'manage' và kiểm tra sở hữu (ownership).
   * @param requiredPermission - Quyền yêu cầu (vd: 'User:update' hoặc 'User:update:own')
   * @param userPermissionSet - Set các quyền của user
   * @param context - ExecutionContext để truy cập request
   * @returns `true` nếu user có quyền
   */
  private checkSinglePermission(
    requiredPermission: string,
    userPermissionSet: Set<string>,
    context: ExecutionContext
  ): boolean {
    // 1. Kiểm tra quyền sở hữu (ownership)
    const ownPermissionMatch = requiredPermission.match(/^([^:]+):([^:]+):own$/)
    if (ownPermissionMatch) {
      const [, subject, action] = ownPermissionMatch
      const ownPermissionString = `${subject}:${action}:own`

      if (userPermissionSet.has(ownPermissionString)) {
        const request = context.switchToHttp().getRequest()
        const user = request.user as ActiveUserData
        const resourceId = request.params.id

        if (!resourceId) {
          this.logger.warn(`[checkSinglePermission] Ownership check failed: No 'id' found in request params.`)
          return false
        }

        // So sánh ID của user trong token với ID tài nguyên từ params
        // Dùng `==` để so sánh an toàn giữa string và number
        if (user && user.id == resourceId) {
          this.logger.debug(
            `[checkSinglePermission] Ownership granted for '${ownPermissionString}' on resource ${resourceId}`
          )
          return true
        }
      }
    }

    // 2. Kiểm tra quyền thông thường (static permission) và wildcards
    const [subject] = requiredPermission.split(':')
    const hasStaticPermission =
      userPermissionSet.has(requiredPermission) ||
      userPermissionSet.has(`${subject}:manage`) ||
      userPermissionSet.has('all:manage')

    if (hasStaticPermission) {
      this.logger.debug(`[checkSinglePermission] Static permission granted for '${requiredPermission}'`)
    }

    return hasStaticPermission
  }
}
