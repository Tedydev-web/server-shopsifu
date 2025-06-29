import { Injectable } from '@nestjs/common'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'
import { PrismaService } from 'src/shared/services/prisma.service'
import { SessionType } from '../model/session.model'
import { UserType } from 'src/shared/models/shared-user.model'
import { RoleType } from 'src/shared/models/shared-role.model'
import { PermissionType } from 'src/shared/models/shared-permission.model'

export type CreateSessionData = Pick<SessionType, 'userId' | 'deviceId' | 'ipAddress' | 'userAgent' | 'expiresAt'>
export type ValidSessionWithUser = SessionType & {
  user: UserType & { role: RoleType & { permissions: PermissionType[] } }
}

@Injectable()
export class SessionRepository extends BaseRepository<SessionType> {
  constructor(private readonly prisma: PrismaService) {
    super(prisma, 'session')
  }

  protected getSearchableFields(): string[] {
    return ['ipAddress', 'userAgent']
  }

  protected getSortableFields(): string[] {
    return ['createdAt', 'lastActiveAt', 'expiresAt']
  }

  async createSession(data: CreateSessionData, prismaClient?: PrismaTransactionClient): Promise<SessionType> {
    const client = this.getClient(prismaClient)
    return await client.session.create({ data })
  }

  async findValidSessionById(id: string): Promise<ValidSessionWithUser | null> {
    const session = await this.prisma.session.findFirst({
      where: {
        id,
        revokedAt: null,
        expiresAt: {
          gt: new Date(),
        },
      },
      include: {
        user: {
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
        },
      },
    })

    if (!session) {
      return null
    }

    if (session.user.revokedAllSessionsBefore && session.createdAt < session.user.revokedAllSessionsBefore) {
      return null
    }

    return session
  }

  async updateSessionLastActive(id: string): Promise<SessionType> {
    const client = this.getClient()
    return await client.session.update({
      where: { id },
      data: {
        lastActiveAt: new Date(),
      },
    })
  }

  async revokeSession(id: string, prismaClient?: PrismaTransactionClient): Promise<SessionType> {
    const client = this.getClient(prismaClient)
    return client.session.update({
      where: { id },
      data: {
        revokedAt: new Date(),
      },
    })
  }

  async updateSessionOnRotation(id: string, newExpiresAt: Date): Promise<SessionType> {
    return this.prisma.session.update({
      where: { id },
      data: {
        expiresAt: newExpiresAt,
        lastActiveAt: new Date(),
      },
    })
  }

  async findSessionsByDeviceId(deviceId: number, prismaClient?: PrismaTransactionClient): Promise<SessionType[]> {
    const client = this.getClient(prismaClient)
    return client.session.findMany({
      where: { deviceId, revokedAt: null },
    })
  }

  async revokeSessionsByDeviceId(deviceId: number, prismaClient?: PrismaTransactionClient): Promise<void> {
    const client = this.getClient(prismaClient)
    await client.session.updateMany({
      where: {
        deviceId: deviceId,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    })
  }
}
