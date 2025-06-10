import { Injectable, Logger } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Permission } from './permission.model' // Import từ model mới tạo
import { CreatePermissionDto, UpdatePermissionDto } from './permission.dto'
import { RedisService } from 'src/shared/services/redis.service'
import { RedisKeyManager } from 'src/shared/utils/redis-keys.utils'
import { ALL_PERMISSIONS_CACHE_TTL, PERMISSION_CACHE_TTL } from 'src/shared/constants/redis.constants'

@Injectable()
export class PermissionRepository {
  private readonly logger = new Logger(PermissionRepository.name)
  constructor(
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService
  ) {}

  private async invalidatePermissionCache(permission?: Permission | null): Promise<void> {
    const keysToDel: string[] = [RedisKeyManager.getAllPermissionsCacheKey()]
    if (permission) {
      keysToDel.push(RedisKeyManager.getPermissionCacheKey(permission.id))
      keysToDel.push(RedisKeyManager.getPermissionByActionAndSubjectCacheKey(permission.action, permission.subject))
    }
    await this.redisService.del(keysToDel)
    this.logger.debug(`Invalidated permission cache for keys: ${keysToDel.join(', ')}`)
  }

  async create(createPermissionDto: CreatePermissionDto): Promise<Permission> {
    const { action, subject, description, category } = createPermissionDto
    const newPermission = await this.prisma.permission.create({
      data: {
        action,
        subject,
        description,
        category
      }
    })
    if (newPermission) {
      await this.invalidatePermissionCache()
    }
    return newPermission
  }

  async findAll(): Promise<Permission[]> {
    const cacheKey = RedisKeyManager.getAllPermissionsCacheKey()
    const cachedPermissions = await this.redisService.getJson<Permission[]>(cacheKey)
    if (cachedPermissions) {
      this.logger.debug('findAll permissions from cache')
      return cachedPermissions
    }

    const permissions = await this.prisma.permission.findMany()
    await this.redisService.setJson(cacheKey, permissions, ALL_PERMISSIONS_CACHE_TTL)
    return permissions
  }

  async findById(id: number): Promise<Permission | null> {
    const cacheKey = RedisKeyManager.getPermissionCacheKey(id)
    const cachedPermission = await this.redisService.getJson<Permission>(cacheKey)
    if (cachedPermission) {
      this.logger.debug(`findById permission ${id} from cache`)
      return cachedPermission
    }
    const permission = await this.prisma.permission.findUnique({
      where: { id }
    })
    if (permission) {
      await this.redisService.setJson(cacheKey, permission, PERMISSION_CACHE_TTL)
    }
    return permission
  }

  async findByActionAndSubject(action: string, subject: string): Promise<Permission | null> {
    const cacheKey = RedisKeyManager.getPermissionByActionAndSubjectCacheKey(action, subject)
    const cachedPermission = await this.redisService.getJson<Permission>(cacheKey)
    if (cachedPermission) {
      this.logger.debug(`findByActionAndSubject permission ${action}/${subject} from cache`)
      return cachedPermission
    }
    const permission = await this.prisma.permission.findUnique({
      where: { UQ_action_subject: { action, subject } }
    })
    if (permission) {
      await this.redisService.setJson(cacheKey, permission, PERMISSION_CACHE_TTL)
    }
    return permission
  }

  async update(id: number, updatePermissionDto: UpdatePermissionDto): Promise<Permission> {
    // Dữ liệu để cập nhật, chỉ lấy các trường được cung cấp
    const dataToUpdate: Partial<UpdatePermissionDto> = {}
    if (updatePermissionDto.action) dataToUpdate.action = updatePermissionDto.action
    if (updatePermissionDto.subject) dataToUpdate.subject = updatePermissionDto.subject
    if (updatePermissionDto.description) dataToUpdate.description = updatePermissionDto.description
    if (updatePermissionDto.category) dataToUpdate.category = updatePermissionDto.category

    const updatedPermission = await this.prisma.permission.update({
      where: { id },
      data: dataToUpdate
    })
    if (updatedPermission) {
      await this.invalidatePermissionCache(updatedPermission)
    }
    return updatedPermission
  }

  async remove(id: number): Promise<Permission> {
    const permissionToDelete = await this.findById(id)
    const deletedPermission = await this.prisma.permission.delete({
      where: { id }
    })
    if (deletedPermission) {
      await this.invalidatePermissionCache(permissionToDelete)
    }
    return deletedPermission
  }

  // Thêm các phương thức truy cập dữ liệu khác nếu cần
}
