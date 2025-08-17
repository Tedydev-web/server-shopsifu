import { Injectable } from '@nestjs/common'
import { CreateUserBodyType, GetUsersQueryType, GetUsersResType } from 'src/routes/user/user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { UserType } from 'src/shared/models/shared-user.model'

@Injectable()
export class UserRepo {
  constructor(private prismaService: PrismaService) {}

  async list(pagination: GetUsersQueryType): Promise<GetUsersResType> {
    const skip = ((pagination.page || 1) - 1) * (pagination.limit || 10)
    const take = pagination.limit || 10
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
      data,
      metadata: {
        totalItems,
        page: pagination.page || 1,
        limit: pagination.limit || 10,
        totalPages: Math.ceil(totalItems / (pagination.limit || 10)),
        hasNext: (pagination.page || 1) < Math.ceil(totalItems / (pagination.limit || 10)),
        hasPrev: (pagination.page || 1) > 1
      }
    }
  }

  create({ createdById, data }: { createdById: string | null; data: CreateUserBodyType }): Promise<UserType> {
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
      id: string
      deletedById: string
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
