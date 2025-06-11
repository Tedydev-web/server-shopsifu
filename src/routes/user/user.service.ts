// ================================================================
// NestJS Dependencies
// ================================================================
import { Injectable, Inject } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'

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

// ================================================================
// Constants & Injection Tokens
// ================================================================
import { HASHING_SERVICE } from 'src/shared/constants/injection.tokens'

// ================================================================
// Types & Interfaces
// ================================================================
export interface UserServiceResponse<T = any> {
  message: string
  data: T
}

/**
 * Service xử lý các thao tác CRUD và business logic cho User
 * Hỗ trợ hash password, validation và trả về custom i18n messages
 */
@Injectable()
export class UserService {
  constructor(
    private readonly userRepository: UserRepository,
    @Inject(HASHING_SERVICE) private readonly hashingService: HashingService,
    private readonly i18nService: I18nService<I18nTranslations>
  ) {}

  // ================================================================
  // Public Methods - Main API endpoints
  // ================================================================

  /**
   * Tạo user mới với password đã được hash
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
    const { password, ...rest } = createUserDto
    const hashedPassword = await this.hashingService.hash(password)

    const userData: any = {
      ...rest,
      password: hashedPassword
    }

    const user = await this.userRepository.create(userData)

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

    const updatedUser = await this.userRepository.update(id, dataToUpdate)

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
    await this.findOne(id)
    
    const deletedUser = await this.userRepository.remove(id)

    return {
      message: 'user.success.delete',
      data: deletedUser
    }
  }

  // ================================================================
  // Private Methods - Utility & Helper Functions
  // ================================================================

  /**
   * Tìm user theo ID mà không trả về response wrapper (để sử dụng internal)
   * @param id - ID của user
   * @returns User object hoặc null nếu không tìm thấy
   */
  private async findUserById(id: number): Promise<User | null> {
    return this.userRepository.findById(id)
  }
}
