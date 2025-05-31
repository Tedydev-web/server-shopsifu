import { Injectable } from '@nestjs/common'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { User, Role, UserProfile, Prisma } from '@prisma/client'
import { RoleType } from 'src/routes/auth/auth.model'

@Injectable()
export class UserRepository extends BaseRepository<UserType> {
  constructor(protected readonly prismaService: PrismaService) {
    super(prismaService, UserRepository.name)
  }

  findUnique(
    uniqueObject: { email: string } | { id: number },
    prismaClient?: PrismaTransactionClient
  ): Promise<(User & { userProfile: UserProfile | null }) | null> {
    const client = this.getClient(prismaClient)
    return client.user.findUnique({
      where: uniqueObject,
      include: { userProfile: true }
    })
  }

  async findUniqueWithDetails(
    uniqueObject: { email: string } | { id: number },
    prismaClient?: PrismaTransactionClient
  ): Promise<(User & { role: RoleType | null; userProfile: UserProfile | null }) | null> {
    const client = this.getClient(prismaClient)
    return client.user.findUnique({
      where: uniqueObject,
      include: {
        role: true,
        userProfile: true
      }
    }) as Promise<(User & { role: RoleType | null; userProfile: UserProfile | null }) | null>
  }

  async updateUser(
    where: Prisma.UserWhereUniqueInput,
    data: Prisma.UserUpdateInput,
    prismaClient?: PrismaTransactionClient
  ): Promise<User> {
    const client = this.getClient(prismaClient)
    return client.user.update({
      where,
      data,
      include: {
        userProfile: true,
        role: true
      }
    })
  }

  async createUserInternal(
    data: Omit<Prisma.UserCreateInput, 'role'> & { roleId: number },
    prismaClient?: PrismaTransactionClient
  ): Promise<User & { userProfile: UserProfile | null; role: Role | null }> {
    const client = this.getClient(prismaClient)
    const { roleId, ...userData } = data

    const createInput: Prisma.UserCreateInput = {
      ...userData,
      role: {
        connect: { id: roleId }
      }
    }

    return client.user.create({
      data: createInput,
      include: {
        userProfile: true,
        role: true
      }
    }) as Promise<User & { userProfile: UserProfile | null; role: Role | null }>
  }

  protected getSearchableFields(): string[] {
    return ['email']
  }
}
