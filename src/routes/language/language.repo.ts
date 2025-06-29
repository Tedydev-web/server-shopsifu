/* eslint-disable @typescript-eslint/require-await */
import { Injectable } from '@nestjs/common'
import { z } from 'zod'
import { PrismaService } from 'src/shared/services/prisma.service'
import { BasePaginationQueryType, PaginatedResponseType } from 'src/shared/models/pagination.model'
import { CreateLanguageBodyType, LanguageType } from './language.model'
import { BaseRepository, PrismaTransactionClient } from 'src/shared/repositories/base.repository'

// Validation schema cho import data
const LanguageImportSchema = z.object({
  id: z.string().min(1).max(10),
  name: z.string().min(1).max(500),
})

type LanguageImportType = z.infer<typeof LanguageImportSchema> & { __rowNumber?: number }

interface ImportErrorType {
  row: number
  message: string
  value: unknown
}

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
}
