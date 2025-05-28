import { Injectable } from '@nestjs/common'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { User, Role, UserProfile } from '@prisma/client'

@Injectable()
export class SharedUserRepository extends BaseRepository<UserType> {
  constructor(protected readonly prismaService: PrismaService) {
    super(prismaService, SharedUserRepository.name)
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

  findUniqueWithRole(
    uniqueObject: { email: string } | { id: number },
    prismaClient?: PrismaTransactionClient
  ): Promise<(User & { role: Pick<Role, 'id' | 'name'>; userProfile: UserProfile | null }) | null> {
    const client = this.getClient(prismaClient)
    return client.user.findUnique({
      where: uniqueObject,
      include: {
        role: {
          select: {
            id: true,
            name: true
          }
        },
        userProfile: true
      }
    }) as Promise<(User & { role: Pick<Role, 'id' | 'name'>; userProfile: UserProfile | null }) | null>
  }

  protected getSearchableFields(): string[] {
    return ['email']
  }
}
