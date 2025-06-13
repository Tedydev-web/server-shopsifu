import { Injectable, Logger, Inject } from '@nestjs/common'
import { AbilityBuilder, AbilityClass, ExtractSubjectType, InferSubjects, PureAbility } from '@casl/ability'
import sift from 'sift'
import { User } from 'src/routes/user/user.model'
import { Role } from 'src/routes/role/role.model'
import { Permission } from 'src/routes/permission/permission.model'
import { ActiveUserData } from 'src/shared/types/active-user.type'
import { RedisService } from '../redis/redis.service'
import { REDIS_SERVICE } from 'src/shared/constants/injection.tokens'

/**
 * @description
 * Defines all possible actions a user can perform on a subject.
 * 'manage' is a special keyword in CASL that represents "any action".
 */
export enum Action {
  Manage = 'manage', // wildcard for any action
  Create = 'create',
  Read = 'read',
  Update = 'update',
  Delete = 'delete',

  // Special actions for granular control if needed
  ReadOwn = 'read:own',
  UpdateOwn = 'update:own',
  DeleteOwn = 'delete:own',
  CreateOwn = 'create:own'
}

/**
 * @description
 * Defines all subjects (entities) that can be permissioned.
 * This enum is the single source of truth for subject names.
 */
export enum AppSubject {
  User = 'User',
  Role = 'Role',
  Permission = 'Permission',
  Profile = 'Profile',
  Session = 'Session',
  Device = 'Device',
  Password = 'Password',
  TwoFactor = 'TwoFactor',
  SocialAccount = 'SocialAccount',
  All = 'all' // Represents "any subject"
}

/**
 * @description
 * Defines all subjects (entities) that can have permissions.
 * 'all' is a special keyword in CASL that represents "any subject".
 */
export type Subjects = InferSubjects<typeof User | typeof Role | typeof Permission, true> | AppSubject

/**
 * @description
 * Defines the application's ability type using CASL's PureAbility.
 * This provides strong typing for actions and subjects.
 */
export type AppAbility = PureAbility<[Action, Subjects]>

/**
 * Utility function to safely access nested properties of an object.
 * @param obj The object to access.
 * @param path The path to the property (e.g., 'a.b.c').
 * @returns The value at the specified path, or undefined if not found.
 */
function getNestedValue(obj: any, path: string): any {
  return path.split('.').reduce((acc, part) => acc && acc[part], obj)
}

/**
 * Logging context for structured logging
 */
interface LogContext {
  userId?: number
  action?: string
  subject?: string
  permissionId?: number
  [key: string]: any
}

@Injectable()
export class CaslAbilityFactory {
  private readonly logger = new Logger(CaslAbilityFactory.name)
  private readonly CACHE_TTL_SECONDS = 5 * 60 // 5 minutes in seconds
  private readonly CACHE_KEY_PREFIX = 'casl:ability'

  constructor(@Inject(REDIS_SERVICE) private readonly redisService: RedisService) {}

  async createForUser(user: ActiveUserData, permissions: Permission[]): Promise<AppAbility> {
    const startTime = Date.now()

    // Generate cache key
    const permissionsHash = this.generatePermissionsHash(permissions)
    const cacheKey = `${this.CACHE_KEY_PREFIX}:${user.id}:${permissionsHash}`

    // Check Redis cache first
    const cachedAbility = await this.getCachedAbility(cacheKey)
    if (cachedAbility) {
      this.logInfo('ABILITY_CACHE_HIT', 'Retrieved ability from Redis cache', {
        userId: user.id,
        cacheKey,
        processingTimeMs: Date.now() - startTime
      })
      return cachedAbility
    }

    // Build ability if not cached or expired
    const ability = this.buildAbility(user, permissions)

    // Cache the result in Redis
    await this.cacheAbility(cacheKey, ability, user.id)

    const processingTimeMs = Date.now() - startTime
    this.logInfo('ABILITY_CREATED', 'New ability created and cached in Redis', {
      userId: user.id,
      permissionsCount: permissions.length,
      cacheKey,
      processingTimeMs
    })

    return ability
  }

  private buildAbility(user: ActiveUserData, permissions: Permission[]): AppAbility {
    const { can, build } = new AbilityBuilder<AppAbility>(PureAbility as AbilityClass<AppAbility>)

    // Validate input
    if (!user || !Array.isArray(permissions)) {
      this.logError('INVALID_INPUT', 'Invalid user or permissions provided to buildAbility', {
        hasUser: !!user,
        permissionsType: typeof permissions,
        isArray: Array.isArray(permissions)
      })
      return build({
        detectSubjectType: (item) => item.constructor as ExtractSubjectType<Subjects>,
        conditionsMatcher: (conditions) => sift(conditions)
      })
    }

    // Grant manage all permission if user has the specific permission
    if (permissions.some((p) => (p.action as any) === Action.Manage && (p.subject as any) === AppSubject.All)) {
      can(Action.Manage, AppSubject.All)
      this.logInfo('SUPER_ADMIN_PERMISSION', 'Granted manage all permission', { userId: user.id })
    }

    // Iterate over user permissions and build abilities
    let successCount = 0
    let failureCount = 0

    permissions.forEach((permission) => {
      try {
        // Map string actions from DB to Action enum
        const action = this.mapAction(permission.action)

        // Validate subject
        const subject = this.validateSubject(permission.subject)

        if (permission.conditions) {
          const interpolatedConditions = this.interpolateConditions(permission.conditions, user)
          can(action, subject as any, interpolatedConditions)
        } else {
          can(action, subject as any)
        }

        successCount++
      } catch (error) {
        failureCount++
        this.logError('PERMISSION_PROCESSING_ERROR', 'Failed to process permission', {
          userId: user.id,
          permissionId: permission.id,
          action: permission.action,
          subject: permission.subject,
          error: error instanceof Error ? error.message : String(error)
        })
      }
    })

    this.logInfo('PERMISSION_PROCESSING_COMPLETED', 'Finished processing permissions', {
      userId: user.id,
      totalPermissions: permissions.length,
      successCount,
      failureCount
    })

    return build({
      detectSubjectType: (item) => item.constructor as ExtractSubjectType<Subjects>,
      conditionsMatcher: (conditions) => sift(conditions)
    })
  }

  /**
   * Interpolates template variables in permission conditions with user data.
   * @param conditions The conditions object from the permission.
   * @param user The active user data.
   * @returns A new conditions object with variables replaced by actual values.
   */
  private interpolateConditions(conditions: any, user: ActiveUserData): any {
    if (!conditions || typeof conditions !== 'object') {
      return conditions
    }

    const interpolated = { ...conditions }

    for (const key in interpolated) {
      const value = interpolated[key]

      if (typeof value === 'string' && value.startsWith('user.')) {
        const userPath = value.substring(5) // Remove 'user.' prefix
        const interpolatedValue = getNestedValue(user, userPath)

        if (interpolatedValue === undefined) {
          this.logWarn('INTERPOLATION_FAILED', 'Unable to interpolate template variable', {
            templateVariable: value,
            userPath,
            availableUserKeys: Object.keys(user),
            conditionKey: key
          })
        }

        interpolated[key] = interpolatedValue
      } else if (typeof value === 'object' && value !== null) {
        // Recursively interpolate nested objects
        interpolated[key] = this.interpolateConditions(value, user)
      }
    }

    return interpolated
  }

  private mapAction(action: string): Action {
    // Direct mapping for standard actions
    switch (action) {
      case 'read':
        return Action.Read
      case 'update':
        return Action.Update
      case 'delete':
        return Action.Delete
      case 'create':
        return Action.Create
      case 'manage':
        return Action.Manage
      // Own-scoped actions (preferred)
      case 'read:own':
        return Action.ReadOwn
      case 'update:own':
        return Action.UpdateOwn
      case 'delete:own':
        return Action.DeleteOwn
      case 'create:own':
        return Action.CreateOwn
      case 'manage:own':
        return Action.Manage
      // Legacy :all actions (DEPRECATED - will be removed in future versions)
      case 'read:all':
        this.logDeprecatedAction(action, 'read')
        return Action.Read
      case 'update:all':
        this.logDeprecatedAction(action, 'update')
        return Action.Update
      case 'delete:all':
        this.logDeprecatedAction(action, 'delete')
        return Action.Delete
      case 'create:all':
        this.logDeprecatedAction(action, 'create')
        return Action.Create
      case 'manage:all':
        this.logDeprecatedAction(action, 'manage')
        return Action.Manage
      default: {
        // Check if it's already a valid Action enum value
        if (Object.values(Action).includes(action as Action)) {
          return action as Action
        }
        // Fallback: try to capitalize first letter
        const capitalizedAction = action.charAt(0).toUpperCase() + action.slice(1)
        if (capitalizedAction in Action) {
          return Action[capitalizedAction as keyof typeof Action]
        }
        // Last resort: log error and return as-is
        this.logError('UNKNOWN_ACTION', `Unknown action: ${action}`, { action })
        return action as Action
      }
    }
  }

  /**
   * Validates that a subject string is valid
   * @param subject The subject string from the database
   * @returns The validated subject string
   */
  private validateSubject(subject: string): string {
    // Check if it's a valid AppSubject enum value
    if (Object.values(AppSubject).includes(subject as AppSubject)) {
      return subject
    }

    // For model classes (User, Role, Permission, etc.)
    const validModelSubjects = ['User', 'Role', 'Permission', 'Product', 'Category', 'Brand', 'Order', 'SKU']
    if (validModelSubjects.includes(subject)) {
      return subject
    }

    // Allow custom subjects but warn about them
    this.logWarn('UNKNOWN_SUBJECT', 'Unknown subject detected', {
      subject,
      validAppSubjects: Object.values(AppSubject),
      validModelSubjects,
      recommendation: 'Make sure this subject is defined in your system or add it to AppSubject enum'
    })
    return subject
  }

  /**
   * =============================================================================
   * REDIS CACHING METHODS
   * =============================================================================
   */

  private async getCachedAbility(cacheKey: string): Promise<AppAbility | null> {
    try {
      const cachedData = await this.redisService.getJson<{
        abilityRules: any[]
        userId: number
        createdAt: number
      }>(cacheKey)

      if (!cachedData) {
        return null
      }

      // Check if cache is still valid
      const now = Date.now()
      const cacheAge = now - cachedData.createdAt
      if (cacheAge > this.CACHE_TTL_SECONDS * 1000) {
        // Cache expired, delete it
        await this.redisService.del(cacheKey)
        return null
      }

      // Rebuild ability from cached rules
      const { can, build } = new AbilityBuilder<AppAbility>(PureAbility as AbilityClass<AppAbility>)

      // Restore rules from cache
      for (const rule of cachedData.abilityRules) {
        if (rule.inverted) {
          // Handle cannot rules if needed
          continue
        }

        if (rule.conditions) {
          can(rule.action, rule.subject, rule.conditions)
        } else {
          can(rule.action, rule.subject)
        }
      }

      return build({
        detectSubjectType: (item) => item.constructor as ExtractSubjectType<Subjects>,
        conditionsMatcher: (conditions) => sift(conditions)
      })
    } catch (error) {
      this.logError('CACHE_RETRIEVAL_ERROR', 'Failed to retrieve ability from Redis cache', {
        cacheKey,
        error: error instanceof Error ? error.message : String(error)
      })
      return null
    }
  }

  private async cacheAbility(cacheKey: string, ability: AppAbility, userId: number): Promise<void> {
    try {
      // Extract rules from ability for caching
      const abilityRules = ability.rules.map((rule) => ({
        action: rule.action,
        subject: rule.subject,
        conditions: rule.conditions,
        inverted: rule.inverted,
        reason: rule.reason
      }))

      const cacheData = {
        abilityRules,
        userId,
        createdAt: Date.now()
      }

      await this.redisService.setJson(cacheKey, cacheData, this.CACHE_TTL_SECONDS)

      this.logInfo('ABILITY_CACHED', 'Ability cached in Redis', {
        userId,
        cacheKey,
        rulesCount: abilityRules.length,
        ttlSeconds: this.CACHE_TTL_SECONDS
      })
    } catch (error) {
      this.logError('CACHE_STORAGE_ERROR', 'Failed to cache ability in Redis', {
        cacheKey,
        userId,
        error: error instanceof Error ? error.message : String(error)
      })
    }
  }

  /**
   * Clear ability cache for a specific user or all users
   */
  public async clearCache(userId?: number): Promise<void> {
    try {
      if (userId) {
        // Clear cache entries for specific user
        const pattern = `${this.CACHE_KEY_PREFIX}:${userId}:*`
        const deletedCount = await this.redisService.deleteKeysByPattern(pattern)

        this.logInfo('CACHE_CLEARED_USER', 'Cleared Redis cache for specific user', {
          userId,
          pattern,
          deletedCount
        })
      } else {
        // Clear all ability cache
        const pattern = `${this.CACHE_KEY_PREFIX}:*`
        const deletedCount = await this.redisService.deleteKeysByPattern(pattern)

        this.logInfo('CACHE_CLEARED_ALL', 'Cleared all Redis ability cache', {
          pattern,
          deletedCount
        })
      }
    } catch (error) {
      this.logError('CACHE_CLEAR_ERROR', 'Failed to clear Redis cache', {
        userId,
        error: error instanceof Error ? error.message : String(error)
      })
    }
  }

  /**
   * Get cache statistics
   */
  public async getCacheStats(): Promise<{
    totalKeys: number
    keysByUser: Record<string, number>
    oldestCacheTime?: number
    newestCacheTime?: number
  }> {
    try {
      const pattern = `${this.CACHE_KEY_PREFIX}:*`
      const keys = await this.redisService.findKeys(pattern)

      const stats = {
        totalKeys: keys.length,
        keysByUser: {} as Record<string, number>,
        oldestCacheTime: undefined as number | undefined,
        newestCacheTime: undefined as number | undefined
      }

      // Analyze keys to extract user stats
      for (const key of keys) {
        const parts = key.split(':')
        if (parts.length >= 3) {
          const userId = parts[2]
          stats.keysByUser[userId] = (stats.keysByUser[userId] || 0) + 1
        }
      }

      // Get timestamp info from a sample of cache entries
      if (keys.length > 0) {
        const sampleKeys = keys.slice(0, Math.min(10, keys.length))
        const timestamps: number[] = []

        for (const key of sampleKeys) {
          const data = await this.redisService.getJson<{ createdAt: number }>(key)
          if (data?.createdAt) {
            timestamps.push(data.createdAt)
          }
        }

        if (timestamps.length > 0) {
          stats.oldestCacheTime = Math.min(...timestamps)
          stats.newestCacheTime = Math.max(...timestamps)
        }
      }

      return stats
    } catch (error) {
      this.logError('CACHE_STATS_ERROR', 'Failed to get cache statistics', {
        error: error instanceof Error ? error.message : String(error)
      })
      return {
        totalKeys: 0,
        keysByUser: {}
      }
    }
  }

  /**
   * =============================================================================
   * LOGGING METHODS
   * =============================================================================
   */

  private logInfo(event: string, message: string, context: LogContext = {}): void {
    this.logger.log({
      event,
      message,
      timestamp: new Date().toISOString(),
      ...context
    })
  }

  private logError(event: string, message: string, context: LogContext = {}): void {
    this.logger.error({
      event,
      message,
      timestamp: new Date().toISOString(),
      ...context
    })
  }

  private logWarn(event: string, message: string, context: LogContext = {}): void {
    this.logger.warn({
      event,
      message,
      timestamp: new Date().toISOString(),
      ...context
    })
  }

  private logDeprecatedAction(deprecatedAction: string, recommendedAction: string): void {
    this.logWarn(
      'DEPRECATED_ACTION',
      `Action '${deprecatedAction}' is deprecated. Use '${recommendedAction}' instead.`,
      {
        deprecatedAction,
        recommendedAction,
        migrationNote: 'Please update your permissions to use the new action format'
      }
    )
  }

  private generatePermissionsHash(permissions: Permission[]): string {
    try {
      // Create a deterministic hash based on permission IDs and update timestamps
      const sortedPermissions = permissions
        .map((p) => {
          // Ensure updatedAt is properly converted to Date if it's a string
          let updatedAtTime = 0
          if (p.updatedAt) {
            try {
              updatedAtTime = p.updatedAt instanceof Date ? p.updatedAt.getTime() : new Date(p.updatedAt).getTime()
            } catch {
              this.logger.warn(`Invalid date format for permission ${p.id}: ${String(p.updatedAt)}`)
              updatedAtTime = 0
            }
          }
          return `${p.id}:${updatedAtTime}`
        })
        .sort()
        .join('|')

      // Simple hash function (you might want to use a proper hash library in production)
      let hash = 0
      for (let i = 0; i < sortedPermissions.length; i++) {
        const char = sortedPermissions.charCodeAt(i)
        hash = (hash << 5) - hash + char
        hash = hash & hash // Convert to 32bit integer
      }
      return Math.abs(hash).toString(36)
    } catch (error) {
      this.logger.error(`Error generating permissions hash: ${error.message}`)
      // Fallback to a simple hash based on permission IDs only
      return permissions
        .map((p) => p.id)
        .sort()
        .join('|')
    }
  }
}
