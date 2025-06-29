import { Injectable } from '@nestjs/common'
import { UserStatus } from 'src/shared/constants/auth.constant'
import { UserType } from 'src/shared/models/shared-user.model'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { PrismaService } from 'src/shared/services/prisma.service'
import { RoleType } from 'src/shared/models/shared-role.model'
import { PermissionType } from 'src/shared/models/shared-permission.model'

type UserIncludeRolePermissionsType = UserType & { role: RoleType & { permissions: PermissionType[] } }

type WhereUniqueUserType = { id: number; [key: string]: any } | { email: string; [key: string]: any }

@Injectable()
export class SharedUserRepository extends BaseRepository<UserType> {
  constructor(prismaService: PrismaService) {
    super(prismaService, 'user')
  }

  protected getSearchableFields(): string[] {
    return ['name', 'email', 'phoneNumber']
  }

  protected getSortableFields(): string[] {
    return ['id', 'name', 'email', 'phoneNumber', 'createdAt', 'updatedAt']
  }

  async findUnique(email: string, prismaClient?: PrismaTransactionClient): Promise<UserType | null> {
    const client = this.getClient(prismaClient)
    return client.user.findUnique({
      where: { email },
    })
  }

  async findActiveUserByEmail(email: string, prismaClient?: PrismaTransactionClient): Promise<UserType | null> {
    const client = this.getClient(prismaClient)
    return client.user.findFirst({
      where: {
        email,
        status: UserStatus.ACTIVE,
      },
    })
  }

  async findUniqueIncludeRolePermissions(where: WhereUniqueUserType): Promise<UserIncludeRolePermissionsType | null> {
    const user = await this.prismaService.user.findUnique({
      where,
      include: {
        role: {
          include: {
            permissions: {
              where: {
                deletedAt: null,
              },
            },
          },
        },
      },
    })

    // Nếu role bị xóa mềm hoặc không tồn tại, trả về role rỗng với permissions rỗng
    if (!user?.role || user.role.deletedAt !== null) {
      ;(user as any).role = {
        id: 0,
        name: '',
        permissions: [],
      }
    } else if (!user.role.permissions) {
      user.role.permissions = []
    }
    return user
  }

  // Override method update để tương thích với BaseRepository
  async update(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<UserType> {
    const client = this.getClient(prismaClient)
    return client.user.update({
      where: { id: Number(id) },
      data,
    })
  }

  // Thêm method riêng cho update với where condition
  async updateByCondition(
    where: WhereUniqueUserType,
    data: any,
    prismaClient?: PrismaTransactionClient,
  ): Promise<UserType> {
    const client = this.getClient(prismaClient)
    return client.user.update({
      where,
      data,
    })
  }
}
