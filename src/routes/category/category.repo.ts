import { Injectable } from '@nestjs/common'
import {
  CreateCategoryBodyType,
  GetAllCategoriesResType,
  UpdateCategoryBodyType,
  CategoryType,
  CategoryIncludeTranslationType,
  GetAllCategoriesQueryType,
} from 'src/routes/category/category.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaginationService, PaginatedResult } from 'src/shared/services/pagination.service'

@Injectable()
export class CategoryRepo {
  constructor(
    private prismaService: PrismaService,
    private paginationService: PaginationService,
  ) {}

  async findAll(query: GetAllCategoriesQueryType & { languageId: string }): Promise<PaginatedResult<CategoryType>> {
    const { parentCategoryId, languageId, search, ...pagination } = query
    const where: any = {
      deletedAt: null,
      parentCategoryId: parentCategoryId ?? null,
    }

    if (search) {
      where.OR = [
        { name: { contains: search, mode: 'insensitive' } },
        { categoryTranslations: { some: { name: { contains: search, mode: 'insensitive' } } } },
      ]
    }

    const include = {
      categoryTranslations: {
        where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId },
      },
    }
    return this.paginationService.paginate('category', pagination, where, {
      include,
      searchableFields: ['name'],
      cursorFields: ['id'],
    })
  }

  findById({ id, languageId }: { id: number; languageId: string }): Promise<CategoryIncludeTranslationType | null> {
    return this.prismaService.category.findUnique({
      where: {
        id,
        deletedAt: null,
      },
      include: {
        categoryTranslations: {
          where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId },
        },
      },
    })
  }

  create({
    createdById,
    data,
  }: {
    createdById: number | null
    data: CreateCategoryBodyType
  }): Promise<CategoryIncludeTranslationType> {
    return this.prismaService.category.create({
      data: {
        ...data,
        createdById,
      },
      include: {
        categoryTranslations: {
          where: { deletedAt: null },
        },
      },
    })
  }

  async update({
    id,
    updatedById,
    data,
  }: {
    id: number
    updatedById: number
    data: UpdateCategoryBodyType
  }): Promise<CategoryIncludeTranslationType> {
    return this.prismaService.category.update({
      where: {
        id,
        deletedAt: null,
      },
      data: {
        ...data,
        updatedById,
      },
      include: {
        categoryTranslations: {
          where: { deletedAt: null },
        },
      },
    })
  }

  delete(
    {
      id,
      deletedById,
    }: {
      id: number
      deletedById: number
    },
    isHard?: boolean,
  ): Promise<CategoryType> {
    return isHard
      ? this.prismaService.category.delete({
          where: {
            id,
          },
        })
      : this.prismaService.category.update({
          where: {
            id,
            deletedAt: null,
          },
          data: {
            deletedAt: new Date(),
            deletedById,
          },
        })
  }
}
