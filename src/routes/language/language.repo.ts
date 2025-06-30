import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BasePaginationQueryType, PaginatedResponseType } from 'src/shared/models/core.model'
import { CreateLanguageBodyType, LanguageType } from './language.model'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'

@Injectable()
export class LanguageRepo extends BaseRepository<LanguageType> {
  constructor(prismaService: PrismaService) {
    super(prismaService, 'language')
  }

  // === STANDARD REPOSITORY METHODS ===

  protected getSearchableFields(): string[] {
    return ['id', 'name']
  }

  protected getSortableFields(): string[] {
    return ['id', 'name', 'createdAt', 'updatedAt']
  }

  async findAllWithPagination(query: BasePaginationQueryType): Promise<PaginatedResponseType<LanguageType>> {
    return this.paginate(query, { deletedAt: null })
  }

  async findAll(prismaClient?: PrismaTransactionClient): Promise<LanguageType[]> {
    const client = this.getClient(prismaClient)
    return client.language.findMany({
      where: { deletedAt: null },
    })
  }

  async findById(id: string, prismaClient?: PrismaTransactionClient): Promise<LanguageType | null> {
    const client = this.getClient(prismaClient)
    return client.language.findUnique({
      where: {
        id,
        deletedAt: null,
      },
    })
  }

  async create(
    { createdById, data }: { createdById: number; data: CreateLanguageBodyType },
    prismaClient?: PrismaTransactionClient,
  ): Promise<LanguageType> {
    const client = this.getClient(prismaClient)
    return client.language.create({
      data: {
        ...data,
        createdById,
        updatedById: createdById,
      },
    })
  }

  async update(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)
    return client.language.update({
      where: {
        id: String(id),
        deletedAt: null,
      },
      data: {
        ...data,
        updatedById: data.updatedById,
      },
    })
  }

  async delete(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)
    return client.language.update({
      where: {
        id: String(id),
        deletedAt: null,
      },
      data: {
        deletedAt: new Date(),
        deletedById: data.deletedById,
      },
    })
  }

  async findByIdOrName(id: string, name: string, prismaClient?: PrismaTransactionClient): Promise<LanguageType | null> {
    const client = this.getClient(prismaClient)
    return client.language.findFirst({
      where: {
        OR: [
          { id: id },
          {
            name: {
              equals: name,
              mode: 'insensitive',
            },
          },
        ],
        deletedAt: null,
      },
    })
  }

  async findByIdOrNameExcludingCurrent(
    id: string,
    name: string,
    currentId: string,
    prismaClient?: PrismaTransactionClient,
  ): Promise<LanguageType | null> {
    const client = this.getClient(prismaClient)
    return client.language.findFirst({
      where: {
        OR: [
          { id: id },
          {
            name: {
              equals: name,
              mode: 'insensitive',
            },
          },
        ],
        id: {
          not: currentId,
        },
        deletedAt: null,
      },
    })
  }

  async findNameExcludingCurrent(
    name: string,
    currentId: string,
    prismaClient?: PrismaTransactionClient,
  ): Promise<LanguageType | null> {
    const client = this.getClient(prismaClient)
    return client.language.findFirst({
      where: {
        name: {
          equals: name,
          mode: 'insensitive',
        },
        id: {
          not: currentId,
        },
        deletedAt: null,
      },
    })
  }
}
