import { Injectable } from '@nestjs/common'
import { CreateUserBodyType, GetUsersResType, UpdateUserBodyType } from 'src/routes/user/user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { UserType } from 'src/shared/models/shared-user.model'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { I18nService } from 'nestjs-i18n'

@Injectable()
export class UserRepo {
  constructor(
    private prismaService: PrismaService,
    private i18n: I18nService
  ) {}

  async list(pagination: PaginationQueryType): Promise<GetUsersResType> {
    const skip = (pagination.page - 1) * pagination.limit
    const take = pagination.limit
    const [totalItems, data] = await Promise.all([
      this.prismaService.user.count({
        where: {
          deletedAt: null
        }
      }),
      this.prismaService.user.findMany({
        where: {
          deletedAt: null
        },
        skip,
        take,
        include: {
          role: true
        }
      })
    ])
    return {
      message: this.i18n.t('user.user.success.GET_LIST_SUCCESS'),
      data,
      metadata: {
        totalItems,
        page: pagination.page,
        limit: pagination.limit,
        totalPages: Math.ceil(totalItems / pagination.limit),
        hasNext: pagination.page < Math.ceil(totalItems / pagination.limit),
        hasPrevious: pagination.page > 1
      }
    }
  }

  create({ createdById, data }: { createdById: number | null; data: CreateUserBodyType }): Promise<UserType> {
    return this.prismaService.user.create({
      data: {
        ...data,
        createdById
      }
    })
  }

  delete(
    {
      id,
      deletedById
    }: {
      id: number
      deletedById: number
    },
    isHard?: boolean
  ): Promise<UserType> {
    return isHard
      ? this.prismaService.user.delete({
          where: {
            id
          }
        })
      : this.prismaService.user.update({
          where: {
            id,
            deletedAt: null
          },
          data: {
            deletedAt: new Date(),
            deletedById
          }
        })
  }
}
