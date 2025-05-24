import { Injectable } from '@nestjs/common'
import { UserType } from 'src/shared/models/shared-user.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'

@Injectable()
export class SharedUserRepository extends BaseRepository<UserType> {
  constructor(protected readonly prismaService: PrismaService) {
    super(prismaService, SharedUserRepository.name)
  }

  findUnique(
    uniqueObject: { email: string } | { id: number },
    prismaClient?: PrismaTransactionClient
  ): Promise<UserType | null> {
    const client = this.getClient(prismaClient)
    return client.user.findUnique({
      where: uniqueObject
    })
  }

  findUniqueWithRole(
    uniqueObject: { email: string } | { id: number },
    prismaClient?: PrismaTransactionClient
  ): Promise<(UserType & { role: { id: number; name: string } }) | null> {
    const client = this.getClient(prismaClient)
    return client.user.findUnique({
      where: uniqueObject,
      include: {
        role: {
          select: {
            id: true,
            name: true
          }
        }
      }
    })
  }

  protected getSearchableFields(): string[] {
    return ['email', 'name', 'phoneNumber']
  }
}
