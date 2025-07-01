import { Injectable } from '@nestjs/common'
import { CreateUserBodyType, GetUsersQueryType, GetUsersResType, UpdateUserBodyType } from 'src/routes/user/user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { UserType } from 'src/shared/models/shared-user.model'
import { PaginationService, PaginatedResult } from 'src/shared/services/pagination.service'

@Injectable()
export class UserRepo {
  constructor(
    private prismaService: PrismaService,
    private paginationService: PaginationService,
  ) {}

  async list(pagination: GetUsersQueryType): Promise<PaginatedResult<UserType>> {
    // Build filter động từ query
    const { email, status, roleId, createdFrom, createdTo, ...baseQuery } = pagination as any
    const where: any = { deletedAt: null }
    if (email) where.email = { contains: email, mode: 'insensitive' }
    if (status) where.status = status
    if (roleId) where.roleId = roleId
    if (createdFrom || createdTo) where.createdAt = {}
    if (createdFrom) where.createdAt.gte = new Date(createdFrom)
    if (createdTo) where.createdAt.lte = new Date(createdTo)
    return this.paginationService.paginate<UserType>('user', baseQuery, where, {
      include: { role: true },
      searchableFields: ['id', 'email', 'name', 'phoneNumber'],
      cursorField: 'id',
    })
  }

  create({ createdById, data }: { createdById: number | null; data: CreateUserBodyType }): Promise<UserType> {
    return this.prismaService.user.create({
      data: {
        ...data,
        createdById,
      },
    })
  }

  delete(
    {
      id,
      deletedById,
    }: {
      id: number
      deletedById: number
    },
    isHard?: boolean,
  ): Promise<UserType> {
    return isHard
      ? this.prismaService.user.delete({
          where: {
            id,
          },
        })
      : this.prismaService.user.update({
          where: {
            id,
            deletedAt: null,
          },
          data: {
            deletedAt: new Date(),
            deletedById,
          },
        })
  }
}
