import { Injectable, Logger } from '@nestjs/common'
import {
  CreateLanguageBodyType,
  LanguageType,
  UpdateLanguageBodyType,
  GetLanguagesQueryType
} from 'src/routes/language/language.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Prisma } from '@prisma/client'

// Định nghĩa kiểu cho transaction client
type PrismaTransactionClient = Omit<
  Prisma.TransactionClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

@Injectable()
export class LanguageRepo {
  private readonly logger = new Logger(LanguageRepo.name)

  constructor(private readonly prismaService: PrismaService) {}

  // Helper để lấy client phù hợp (transaction hoặc main)
  private getClient(prismaClient?: PrismaTransactionClient): PrismaTransactionClient | PrismaService {
    return prismaClient || this.prismaService
  }

  async findAll(
    query?: GetLanguagesQueryType,
    prismaClient?: PrismaTransactionClient
  ): Promise<{ languages: LanguageType[]; totalItems: number }> {
    const client = this.getClient(prismaClient)

    const { page = 1, limit = 10, sortBy = 'id', sortOrder = 'asc', search = '', includeDeleted = false } = query || {}

    // Tạo where clause theo điều kiện tìm kiếm
    const where: Prisma.LanguageWhereInput = {}

    // Chỉ xem các record chưa xóa trừ khi yêu cầu xem cả đã xóa
    if (!includeDeleted) {
      where.deletedAt = null
    }

    // Tìm kiếm text
    if (search) {
      where.OR = [
        { id: { contains: search, mode: 'insensitive' } },
        { name: { contains: search, mode: 'insensitive' } }
      ]
    }

    // Đếm tổng số bản ghi phù hợp
    const totalItems = await client.language.count({ where })

    // Lấy dữ liệu với phân trang và sorting
    const languages = await client.language.findMany({
      where,
      orderBy: { [sortBy]: sortOrder },
      skip: (page - 1) * limit,
      take: limit
    })

    return {
      languages,
      totalItems
    }
  }

  async findById(
    id: string,
    includeDeleted: boolean = false,
    prismaClient?: PrismaTransactionClient
  ): Promise<LanguageType | null> {
    const client = this.getClient(prismaClient)

    const where: Prisma.LanguageWhereUniqueInput = { id }

    // Nếu không bao gồm các bản ghi đã xóa, thêm điều kiện deletedAt = null
    if (!includeDeleted) {
      where.deletedAt = null
    }

    return client.language.findUnique({
      where
    })
  }

  async create(
    { createdById, data }: { createdById: number; data: CreateLanguageBodyType },
    prismaClient?: PrismaTransactionClient
  ): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Creating language: ${JSON.stringify(data)}`)

    return client.language.create({
      data: {
        ...data,
        createdById
      }
    })
  }

  async update(
    {
      id,
      updatedById,
      data
    }: {
      id: string
      updatedById: number
      data: UpdateLanguageBodyType
    },
    prismaClient?: PrismaTransactionClient
  ): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Updating language ${id}: ${JSON.stringify(data)}`)

    return client.language.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        ...data,
        updatedById
      }
    })
  }

  async softDelete(id: string, deletedById: number, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Soft deleting language: ${id}`)

    return client.language.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        deletedAt: new Date(),
        updatedById: deletedById
      }
    })
  }

  async hardDelete(id: string, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Hard deleting language: ${id}`)

    return client.language.delete({
      where: { id }
    })
  }

  async restore(id: string, updatedById: number, prismaClient?: PrismaTransactionClient): Promise<LanguageType> {
    const client = this.getClient(prismaClient)

    this.logger.debug(`Restoring language: ${id}`)

    return client.language.update({
      where: {
        id,
        NOT: {
          deletedAt: null
        }
      },
      data: {
        deletedAt: null,
        updatedById
      }
    })
  }

  async countReferences(id: string, prismaClient?: PrismaTransactionClient): Promise<number> {
    const client = this.getClient(prismaClient)

    // Đếm các bản ghi tham chiếu đến ngôn ngữ này
    // Ví dụ: đếm các bản ghi trong ProductTranslation, CategoryTranslation, BrandTranslation...
    const [productCount, categoryCount, brandCount] = await Promise.all([
      client.productTranslation.count({ where: { languageId: id } }),
      client.categoryTranslation.count({ where: { languageId: id } }),
      client.brandTranslation.count({ where: { languageId: id } })
    ])

    return productCount + categoryCount + brandCount
  }
}
