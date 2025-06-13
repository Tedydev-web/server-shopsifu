// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Inject, forwardRef, Logger } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import { Response } from 'express'
import { OnEvent } from '@nestjs/event-emitter'

// ================================================================
// External Libraries
// ================================================================
import { User } from '@prisma/client'

// ================================================================
// Internal Services & Types
// ================================================================
import { UserRepository } from './user.repository'
import { CreateUserDto, UpdateUserDto } from './user.dto'
import { UserError } from './user.error'
import { HashingService } from 'src/shared/services/hashing.service'
import { I18nTranslations } from 'src/generated/i18n.generated'
import { EmailService } from 'src/shared/services/email.service'
import { AuthVerificationService } from 'src/routes/auth/services/auth-verification.service'
import { TypeOfVerificationCode } from 'src/routes/auth/auth.constants'
import { RoleRepository } from 'src/routes/role/role.repository'
import { RedisService } from 'src/shared/providers/redis/redis.service'
import { RedisKeyManager } from 'src/shared/providers/redis/redis-keys.utils'
import { Permission } from 'src/routes/permission/permission.model'

// ================================================================
// Constants & Injection Tokens
// ================================================================
import { HASHING_SERVICE, REDIS_SERVICE } from 'src/shared/constants/injection.tokens'
import { EMAIL_SERVICE } from 'src/shared/constants/injection.tokens'

// ================================================================
// Types & Interfaces
// ================================================================
export interface UserServiceResponse<T = any> {
  message: string
  data: T
}

export interface InitiateUserCreationResponse {
  message: string
  verificationType: 'OTP'
  requiresVerification: boolean
}

/**
 * Service xử lý các thao tác CRUD và business logic cho User
 * Hỗ trợ hash password, validation, OTP verification và trả về custom i18n messages
 * Tích hợp email notifications cho tất cả các operations
 */
@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name)

  constructor(
    private readonly userRepository: UserRepository,
    private readonly roleRepository: RoleRepository,
    @Inject(REDIS_SERVICE) private readonly redisService: RedisService,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    private readonly i18nService: I18nService<I18nTranslations>,
    @Inject(EMAIL_SERVICE) private readonly emailService: EmailService,
    @Inject(forwardRef(() => AuthVerificationService))
    private readonly authVerificationService: AuthVerificationService
  ) {}

  // ================================================================
  // Public Methods - Permissions
  // ================================================================

  /**
   * Lấy danh sách permissions của user, có sử dụng cache
   * @param userId - ID của user
   * @returns Danh sách các permissions
   */
  async getUserPermissions(userId: number): Promise<Permission[]> {
    const cacheKey = RedisKeyManager.getUserPermissionsCacheKey(userId)

    try {
      const cachedPermissions = await this.redisService.getJson<Permission[]>(cacheKey)
      if (cachedPermissions) {
        this.logger.debug(`[getUserPermissions] Cache hit for user ${userId}`)
        return cachedPermissions
      }
    } catch (error) {
      this.logger.error(`[getUserPermissions] Failed to get from Redis cache for user ${userId}:`, error)
    }

    this.logger.debug(`[getUserPermissions] Cache miss for user ${userId}, fetching from DB.`)
    const user = await this.roleRepository.getUserWithRoleAndPermissions(userId)

    const permissions = user?.role?.permissions || []

    // Cache permissions trong 5 phút
    try {
      await this.redisService.setJson(cacheKey, permissions, 300)
    } catch (error) {
      this.logger.error(`[getUserPermissions] Failed to set Redis cache for user ${userId}:`, error)
    }

    return permissions
  }

  /**
   * Xóa cache permissions của user.
   * Gọi hàm này khi vai trò hoặc quyền của người dùng thay đổi.
   * @param userId - ID của user
   */
  async invalidateUserPermissionsCache(userId: number): Promise<void> {
    const cacheKey = RedisKeyManager.getUserPermissionsCacheKey(userId)
    try {
      await this.redisService.del(cacheKey)
      this.logger.log(`[invalidateUserPermissionsCache] Invalidated permissions cache for user ${userId}`)
    } catch (error) {
      this.logger.error(`[invalidateUserPermissionsCache] Failed to invalidate cache for user ${userId}:`, error)
    }
  }

  // ================================================================
  // Public Methods - Main API endpoints
  // ================================================================

  /**
   * Bước 1: Khởi tạo tạo user với OTP verification
   * Gửi OTP đến email để verify trước khi tạo user thực sự
   * @param createUserDto - Thông tin user cần tạo
   * @param ip - Địa chỉ IP của request
   * @param userAgent - User agent của request
   * @param res - Response object để set SLT cookie
   * @returns InitiateUserCreationResponse với thông tin OTP verification
   */
  async initiateUserCreation(
    createUserDto: CreateUserDto,
    ip: string,
    userAgent: string,
    res: Response
  ): Promise<InitiateUserCreationResponse> {
    // Kiểm tra email đã tồn tại chưa
    const existingUser = await this.userRepository.findByEmail(createUserDto.email)
    if (existingUser) {
      throw UserError.AlreadyExists(createUserDto.email)
    }

    // Khởi tạo verification với AuthVerificationService
    const verificationResult = await this.authVerificationService.initiateVerification(
      {
        userId: 0, // Temporary user ID
        deviceId: 0, // Temporary device ID
        email: createUserDto.email,
        ipAddress: ip,
        userAgent,
        purpose: TypeOfVerificationCode.CREATE_USER,
        metadata: createUserDto
      },
      res
    )

    return {
      message: verificationResult.message,
      verificationType: 'OTP',
      requiresVerification: true
    }
  }

  /**
   * Tạo user trực tiếp (admin only) - skip OTP verification
   * @param createUserDto - Thông tin user cần tạo
   * @returns UserServiceResponse với user object đã được tạo
   * @throws UserError.AlreadyExists nếu email đã tồn tại
   */
  async create(createUserDto: CreateUserDto): Promise<UserServiceResponse<User>> {
    // Kiểm tra email đã tồn tại chưa
    const existingUser = await this.userRepository.findByEmail(createUserDto.email)
    if (existingUser) {
      throw UserError.AlreadyExists(createUserDto.email)
    }

    // Hash password trước khi lưu
    const hashedPassword = await this.hashingService.hash(createUserDto.password)

    // Sử dụng createWithProfile để tạo user với thông tin profile
    const user = await this.userRepository.createWithProfile({
      email: createUserDto.email,
      password: hashedPassword,
      roleId: createUserDto.roleId,
      username: createUserDto.username || createUserDto.email.split('@')[0],
      firstName: createUserDto.firstName || null,
      lastName: createUserDto.lastName || null,
      phoneNumber: createUserDto.phoneNumber || null,
      bio: createUserDto.bio || null,
      avatar: createUserDto.avatar || null,
      countryCode: createUserDto.countryCode || 'VN'
    })

    // Gửi email thông báo user mới được tạo bởi admin
    await this.sendUserCreatedByAdminEmail(user)

    return {
      message: 'user.success.create',
      data: user
    }
  }

  /**
   * Tạo user qua OTP verification flow
   * @param createUserDto - Thông tin user cần tạo (đã verify qua OTP)
   * @returns UserServiceResponse với user object đã được tạo
   * @throws UserError.AlreadyExists nếu email đã tồn tại
   */
  async createFromOtpVerification(createUserDto: CreateUserDto): Promise<UserServiceResponse<User>> {
    // Kiểm tra email đã tồn tại chưa
    const existingUser = await this.userRepository.findByEmail(createUserDto.email)
    if (existingUser) {
      throw UserError.AlreadyExists(createUserDto.email)
    }

    // Hash password trước khi lưu
    const hashedPassword = await this.hashingService.hash(createUserDto.password)

    // Sử dụng createWithProfile để tạo user với thông tin profile
    const user = await this.userRepository.createWithProfile({
      email: createUserDto.email,
      password: hashedPassword,
      roleId: createUserDto.roleId,
      username: createUserDto.username || createUserDto.email.split('@')[0],
      firstName: createUserDto.firstName || null,
      lastName: createUserDto.lastName || null,
      phoneNumber: createUserDto.phoneNumber || null,
      bio: createUserDto.bio || null,
      avatar: createUserDto.avatar || null,
      countryCode: createUserDto.countryCode || 'VN'
    })

    // Gửi email chào mừng cho user mới
    await this.sendWelcomeEmail(user)

    // Gửi email thông báo admin về user mới được tạo qua OTP flow
    await this.sendUserCreatedNotificationToAdmin(user)

    return {
      message: 'user.success.create',
      data: user
    }
  }

  /**
   * Lấy danh sách tất cả users
   * @returns UserServiceResponse với mảng tất cả users
   */
  async findAll(): Promise<UserServiceResponse<User[]>> {
    const users = await this.userRepository.findAll()

    return {
      message: 'user.success.list',
      data: users
    }
  }

  /**
   * Tìm user theo ID
   * @param id - ID của user
   * @returns UserServiceResponse với user object
   * @throws UserError.NotFound nếu không tìm thấy user
   */
  async findOne(id: number): Promise<UserServiceResponse<User>> {
    const user = await this.userRepository.findById(id)
    if (!user) {
      throw UserError.NotFound()
    }

    return {
      message: 'user.success.get',
      data: user
    }
  }

  /**
   * Cập nhật thông tin user
   * @param id - ID của user cần cập nhật
   * @param updateUserDto - Dữ liệu cập nhật
   * @returns UserServiceResponse với user object đã được cập nhật
   * @throws UserError.NotFound nếu user không tồn tại
   */
  async update(id: number, updateUserDto: UpdateUserDto): Promise<UserServiceResponse<User>> {
    // Kiểm tra user tồn tại
    const existingUserResponse = await this.findOne(id)
    const existingUser = existingUserResponse.data

    const dataToUpdate: any = { ...updateUserDto }

    // Hash password mới nếu có
    if (updateUserDto.password) {
      dataToUpdate.password = await this.hashingService.hash(updateUserDto.password)
    }

    // Kiểm tra email trùng lặp nếu có thay đổi email
    if (updateUserDto.email && updateUserDto.email !== existingUser.email) {
      const userWithEmail = await this.userRepository.findByEmail(updateUserDto.email)
      if (userWithEmail && userWithEmail.id !== id) {
        throw UserError.AlreadyExists(updateUserDto.email)
      }
    }

    // Nếu roleId thay đổi, xóa cache permission của user
    if (updateUserDto.roleId && updateUserDto.roleId !== existingUser.roleId) {
      this.logger.log(`Role changed for user ${id}, invalidating permissions cache.`)
      await this.invalidateUserPermissionsCache(id)
    }

    const updatedUser = await this.userRepository.update(id, dataToUpdate)

    // Gửi email thông báo cập nhật user
    await this.sendUserUpdatedEmail(updatedUser, existingUser)

    return {
      message: 'user.success.update',
      data: updatedUser
    }
  }

  /**
   * Xóa user theo ID
   * @param id - ID của user cần xóa
   * @returns UserServiceResponse với user object đã bị xóa
   * @throws UserError.NotFound nếu user không tồn tại
   */
  async remove(id: number): Promise<UserServiceResponse<User>> {
    // Kiểm tra user tồn tại trước khi xóa
    const existingUserResponse = await this.findOne(id)
    const existingUser = existingUserResponse.data

    const deletedUser = await this.userRepository.remove(id)

    // Gửi email thông báo xóa user
    await this.sendUserDeletedEmail(existingUser)

    return {
      message: 'user.success.delete',
      data: deletedUser
    }
  }

  // ================================================================
  // Private Methods - Email Notification Helper Functions
  // ================================================================

  /**
   * Gửi email chào mừng cho user mới
   * @param user - User object
   */
  private async sendWelcomeEmail(user: any): Promise<void> {
    try {
      await this.emailService.sendWelcomeEmail(user.email, {
        userName: user.userProfile?.firstName || user.userProfile?.username || user.email,
        lang: 'vi'
      })
    } catch (error) {
      // Log error nhưng không throw để không affect user creation
      console.error('Failed to send welcome email:', error)
    }
  }

  /**
   * Gửi email thông báo admin về user mới được tạo qua OTP flow
   * @param user - User object với thông tin profile
   */
  private async sendUserCreatedNotificationToAdmin(user: any): Promise<void> {
    try {
      // Lấy email admin từ environment hoặc config
      const adminEmails = process.env.USER_MANAGEMENT_ADMIN_EMAIL?.split(',') || ['admin@shopsifu.com']

      for (const adminEmail of adminEmails) {
        await this.emailService.sendUserCreatedAlert(adminEmail.trim(), {
          userName: 'Administrator',
          newUserInfo: {
            email: user.email,
            firstName: user.userProfile?.firstName,
            lastName: user.userProfile?.lastName,
            phoneNumber: user.userProfile?.phoneNumber,
            role: 'Customer' // Default role cho user tự đăng ký
          },
          adminInfo: {
            adminName: 'System (Self Registration)',
            adminEmail: 'system@shopsifu.com',
            createdAt: new Date().toLocaleString('vi-VN'),
            ipAddress: 'System Generated',
            userAgent: 'OTP Verification Flow'
          },
          lang: 'vi'
        })
      }
    } catch (error) {
      console.error('Failed to send admin notification:', error)
      // Không throw error để không ảnh hưởng đến flow chính
    }
  }

  /**
   * Gửi email thông báo user được tạo bởi admin
   * @param user - User object với thông tin profile
   */
  private async sendUserCreatedByAdminEmail(user: any): Promise<void> {
    try {
      // Lấy email security team và admin từ environment
      const securityEmails = process.env.USER_MANAGEMENT_SECURITY_EMAIL?.split(',') || ['security@shopsifu.com']
      const adminEmails = process.env.USER_MANAGEMENT_ADMIN_EMAIL?.split(',') || ['admin@shopsifu.com']

      const allRecipients = [...securityEmails, ...adminEmails]

      for (const recipientEmail of allRecipients) {
        await this.emailService.sendUserCreatedAlert(recipientEmail.trim(), {
          userName: 'Security Team',
          newUserInfo: {
            email: user.email,
            firstName: user.userProfile?.firstName,
            lastName: user.userProfile?.lastName,
            phoneNumber: user.userProfile?.phoneNumber,
            role: user.role?.name || 'Unknown'
          },
          adminInfo: {
            adminName: 'System Administrator',
            adminEmail: 'admin@shopsifu.com',
            createdAt: new Date().toLocaleString('vi-VN'),
            ipAddress: 'Admin Panel',
            userAgent: 'Administrative Action'
          },
          lang: 'vi'
        })
      }
    } catch (error) {
      console.error('Failed to send user created by admin email:', error)
      // Không throw error để không ảnh hưởng đến flow chính
    }
  }

  /**
   * Gửi email thông báo user được cập nhật
   * @param updatedUser - User object sau khi cập nhật
   * @param previousUser - User object trước khi cập nhật
   */
  private async sendUserUpdatedEmail(updatedUser: any, previousUser: any): Promise<void> {
    try {
      // Xây dựng danh sách các thay đổi
      const changedFields = this.buildChangedFields(previousUser, updatedUser)

      if (changedFields.length === 0) {
        return // Không có thay đổi nào, không cần gửi email
      }

      // Lấy email security team từ environment
      const securityEmails = process.env.USER_MANAGEMENT_SECURITY_EMAIL?.split(',') || ['security@shopsifu.com']

      for (const securityEmail of securityEmails) {
        await this.emailService.sendUserUpdatedAlert(securityEmail.trim(), {
          userName: 'Security Team',
          userInfo: {
            email: updatedUser.email,
            firstName: updatedUser.userProfile?.firstName,
            lastName: updatedUser.userProfile?.lastName,
            phoneNumber: updatedUser.userProfile?.phoneNumber,
            role: updatedUser.role?.name || 'Unknown'
          },
          changedFields,
          adminInfo: {
            adminName: 'System Administrator',
            adminEmail: 'admin@shopsifu.com',
            updatedAt: new Date().toLocaleString('vi-VN'),
            ipAddress: 'Admin Panel',
            userAgent: 'Administrative Update'
          },
          lang: 'vi'
        })
      }
    } catch (error) {
      console.error('Failed to send user updated email:', error)
      // Không throw error để không ảnh hưởng đến flow chính
    }
  }

  /**
   * Gửi email thông báo user bị xóa
   * @param deletedUser - User object đã bị xóa
   */
  private async sendUserDeletedEmail(deletedUser: any): Promise<void> {
    try {
      // Lấy email audit team và security team từ environment
      const auditEmails = process.env.USER_MANAGEMENT_AUDIT_EMAIL?.split(',') || ['audit@shopsifu.com']
      const securityEmails = process.env.USER_MANAGEMENT_SECURITY_EMAIL?.split(',') || ['security@shopsifu.com']

      const allRecipients = [...auditEmails, ...securityEmails]

      for (const recipientEmail of allRecipients) {
        await this.emailService.sendUserDeletedAlert(recipientEmail.trim(), {
          userName: 'Audit Team',
          deletedUserInfo: {
            userId: deletedUser.id.toString(),
            email: deletedUser.email,
            firstName: deletedUser.userProfile?.firstName,
            lastName: deletedUser.userProfile?.lastName,
            phoneNumber: deletedUser.userProfile?.phoneNumber,
            role: deletedUser.role?.name || 'Unknown',
            accountCreatedAt: deletedUser.createdAt?.toLocaleString('vi-VN') || 'Unknown'
          },
          adminInfo: {
            adminName: 'System Administrator',
            adminEmail: 'admin@shopsifu.com',
            deletedAt: new Date().toLocaleString('vi-VN'),
            ipAddress: 'Admin Panel',
            userAgent: 'Administrative Deletion'
          },
          isDangerous: true,
          lang: 'vi'
        })
      }
    } catch (error) {
      console.error('Failed to send user deleted email:', error)
      // Không throw error để không ảnh hưởng đến flow chính
    }
  }

  // ================================================================
  // Private Methods - Utility & Helper Functions
  // ================================================================

  /**
   * Xây dựng danh sách các field đã thay đổi giữa user cũ và mới
   * @param oldUser - User object trước khi cập nhật
   * @param newUser - User object sau khi cập nhật
   * @returns Array các thay đổi với format { field, oldValue, newValue }
   */
  private buildChangedFields(oldUser: any, newUser: any): Array<{ field: string; oldValue: string; newValue: string }> {
    const changes: Array<{ field: string; oldValue: string; newValue: string }> = []

    // Kiểm tra các field chính của user
    const fieldsToCheck = [
      { key: 'email', label: 'Email' },
      { key: 'status', label: 'Status' },
      { key: 'isEmailVerified', label: 'Email Verified' },
      { key: 'roleId', label: 'Role ID' }
    ]

    fieldsToCheck.forEach(({ key, label }) => {
      if (oldUser[key] !== newUser[key]) {
        changes.push({
          field: label,
          oldValue: oldUser[key]?.toString() || 'null',
          newValue: newUser[key]?.toString() || 'null'
        })
      }
    })

    // Kiểm tra các field trong userProfile nếu có
    if (oldUser.userProfile && newUser.userProfile) {
      const profileFields = [
        { key: 'firstName', label: 'First Name' },
        { key: 'lastName', label: 'Last Name' },
        { key: 'username', label: 'Username' },
        { key: 'phoneNumber', label: 'Phone Number' },
        { key: 'bio', label: 'Bio' },
        { key: 'avatar', label: 'Avatar' },
        { key: 'countryCode', label: 'Country Code' }
      ]

      profileFields.forEach(({ key, label }) => {
        if (oldUser.userProfile[key] !== newUser.userProfile[key]) {
          changes.push({
            field: label,
            oldValue: oldUser.userProfile[key]?.toString() || 'empty',
            newValue: newUser.userProfile[key]?.toString() || 'empty'
          })
        }
      })
    }

    return changes
  }

  /**
   * Tìm user theo ID mà không trả về response wrapper (để sử dụng internal)
   * @param id - ID của user
   * @returns User object hoặc null nếu không tìm thấy
   */
  private async findUserById(id: number): Promise<User | null> {
    return this.userRepository.findById(id)
  }

  /**
   * Handles the 'role.updated' event to invalidate user permissions cache.
   * @param payload - The event payload containing the roleId.
   */
  @OnEvent('role.updated')
  async handleRoleUpdated(payload: { roleId: number }) {
    this.logger.debug(`Role with ID ${payload.roleId} updated, invalidating user permissions cache.`)
    const userIds = await this.userRepository.findUserIdsByRoleId(payload.roleId)
    if (userIds.length > 0) {
      const promises = userIds.map((id) => this.invalidateUserPermissionsCache(id))
      await Promise.all(promises)
      this.logger.log(`Invalidated permissions cache for ${userIds.length} users.`)
    }
  }
}
