import { Logger } from '@nestjs/common'
import { Prisma } from '@prisma/client'
import { PrismaService } from '../services/prisma.service'

export type PrismaTransactionClient = Omit<
  Prisma.TransactionClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>

export abstract class BaseRepository<T> {
  protected readonly modelName: string
  protected readonly logger = new Logger(BaseRepository.name)

  constructor(
    protected readonly prismaService: PrismaService,
    modelName: string
  ) {
    this.modelName = modelName
  }

  protected getClient(prismaClient?: PrismaTransactionClient): PrismaTransactionClient | PrismaService {
    return prismaClient || this.prismaService
  }

  async findById(id: string | number, prismaClient?: PrismaTransactionClient): Promise<T | null> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].findUnique({ where: { id } })
  }

  async create(data: any, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].create({ data })
  }

  async update(id: string | number, data: any, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].update({ where: { id }, data })
  }

  async delete(id: string | number, prismaClient?: PrismaTransactionClient): Promise<T> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].delete({ where: { id } })
  }

  async findMany(options: { where?: any; include?: any } = {}, prismaClient?: PrismaTransactionClient): Promise<T[]> {
    const client = this.getClient(prismaClient)
    return await client[this.modelName].findMany(options)
  }

  /**
   * Các repository con phải implement phương thức này để xác định các trường có thể tìm kiếm.
   */
  protected abstract getSearchableFields(): string[]

  /**
   * Các repository con phải implement phương thức này để xác định các trường có thể sort.
   */
  protected abstract getSortableFields(): string[]
}
