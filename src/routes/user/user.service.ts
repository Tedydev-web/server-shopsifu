import { ForbiddenException, Injectable } from '@nestjs/common'
import { UserRepo } from 'src/routes/user/user.repo'
import { CreateUserBodyType, GetUsersQueryType, UpdateUserBodyType } from 'src/routes/user/user.model'
import { NotFoundRecordException } from 'src/shared/error'
import {
  isForeignKeyConstraintPrismaError,
  isNotFoundPrismaError,
  isUniqueConstraintPrismaError
} from 'src/shared/helpers'
import {
  CannotUpdateOrDeleteYourselfException,
  RoleNotFoundException,
  UserAlreadyExistsException
} from 'src/routes/user/user.error'
import { RoleName } from 'src/shared/constants/role.constant'
import { SharedUserRepository } from 'src/shared/repositories/shared-user.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { SharedRoleRepository } from 'src/shared/repositories/shared-role.repo'
import { I18nService } from 'nestjs-i18n'
import { I18nTranslations } from 'src/shared/languages/generated/i18n.generated'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Injectable()
export class UserService {
  constructor(
    private userRepo: UserRepo,
    private hashingService: HashingService,
    private sharedUserRepository: SharedUserRepository,
    private sharedRoleRepository: SharedRoleRepository,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async list(pagination: GetUsersQueryType) {
    const data = await this.userRepo.list(pagination)
    return {
      message: this.i18n.t('user.user.success.GET_SUCCESS'),
      data: data.data,
      metadata: data.metadata
    }
  }

  async findById(id: string) {
    const user = await this.sharedUserRepository.findUniqueIncludeRolePermissions({ id })
    if (!user) {
      throw NotFoundRecordException
    }

    // Lấy addresses và statistics để đáp ứng schema yêu cầu
    const [addresses, orders] = await Promise.all([
      this.sharedUserRepository.listAddressesByUserId(id),
      this.sharedUserRepository.getUserOrders(id)
    ])

    // Tính statistics từ orders
    const totalOrders = orders?.length ?? 0
    const totalSpent = orders?.reduce((sum, order) => {
      const orderTotal = order.items?.reduce((itemSum, item) => itemSum + Number(item.skuPrice) * item.quantity, 0) ?? 0
      return sum + orderTotal
    }, 0) ?? 0
    const memberSince = user.createdAt

    return {
      message: this.i18n.t('user.user.success.GET_DETAIL_SUCCESS'),
      data: {
        ...user,
        addresses,
        statistics: {
          totalOrders,
          totalSpent,
          memberSince
        }
      }
    }
  }

  async create({ data, user, roleName }: { data: CreateUserBodyType; user: AccessTokenPayload; roleName: string }) {
    try {
      // Chỉ có admin agent mới có quyền tạo user với role là admin
      await this.verifyRole({
        roleNameAgent: roleName,
        roleIdTarget: data.roleId
      })
      // Hash the password
      const hashedPassword = await this.hashingService.hash(data.password || '')
      const userCreated = await this.userRepo.create({
        createdById: user.userId,
        data: {
          ...data,
          password: hashedPassword
        }
      })
      return {
        message: this.i18n.t('user.user.success.CREATE_SUCCESS'),
        data: userCreated
      }
    } catch (error) {
      if (isForeignKeyConstraintPrismaError(error)) {
        throw RoleNotFoundException
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw UserAlreadyExistsException
      }
      throw error
    }
  }

  /**
   * Function này kiểm tra xem người thực hiện có quyền tác động đến người khác không.
   * Vì chỉ có người thực hiện là admin role mới có quyền sau: Tạo admin user, update roleId thành admin, xóa admin user.
   * Còn nếu không phải admin thì không được phép tác động đến admin
   */
  private async verifyRole({ roleNameAgent, roleIdTarget }) {
    // Agent là admin thì cho phép
    if (roleNameAgent === RoleName.Admin) {
      return true
    } else {
      // Agent không phải admin thì roleIdTarget phải khác admin
      const adminRoleId = await this.sharedRoleRepository.getAdminRoleId()
      if (roleIdTarget === adminRoleId) {
        throw new ForbiddenException()
      }
      return true
    }
  }

  async update({
    id,
    data,
    user,
    roleName
  }: {
    id: string
    data: UpdateUserBodyType
    user: AccessTokenPayload
    roleName: string
  }) {
    try {
      // Không thể cập nhật chính mình
      this.verifyYourself({
        userAgentId: user.userId,
        userTargetId: id
      })
      // Lấy roleId ban đầu của người được update để kiểm tra xem liệu người update có quyền update không
      // Không dùng data.roleId vì dữ liệu này có thể bị cố tình truyền sai
      const roleIdTarget = await this.getRoleIdByUserId(id)
      await this.verifyRole({
        roleNameAgent: roleName,
        roleIdTarget
      })
      const updatedUser = await this.sharedUserRepository.update(
        { id },
        {
          ...data,
          updatedById: user.userId
        }
      )
      return {
        message: this.i18n.t('user.user.success.UPDATE_SUCCESS'),
        data: updatedUser
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      if (isUniqueConstraintPrismaError(error)) {
        throw UserAlreadyExistsException
      }
      if (isForeignKeyConstraintPrismaError(error)) {
        throw RoleNotFoundException
      }
      throw error
    }
  }

  private async getRoleIdByUserId(userId: string) {
    const currentUser = await this.sharedUserRepository.findUnique({
      id: userId
    })
    if (!currentUser) {
      throw NotFoundRecordException
    }
    return currentUser.roleId
  }

  private verifyYourself({ userAgentId, userTargetId }: { userAgentId: string; userTargetId: string }) {
    if (userAgentId === userTargetId) {
      throw CannotUpdateOrDeleteYourselfException
    }
  }

  async delete({ id, user, roleName }: { id: string; user: AccessTokenPayload; roleName: string }) {
    try {
      // Không thể xóa chính mình
      this.verifyYourself({
        userAgentId: user.userId,
        userTargetId: id
      })
      const roleIdTarget = await this.getRoleIdByUserId(id)
      await this.verifyRole({
        roleNameAgent: roleName,
        roleIdTarget
      })
      await this.userRepo.delete({
        id,
        deletedById: user.userId
      })
      return {
        message: this.i18n.t('user.user.success.DELETE_SUCCESS')
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
