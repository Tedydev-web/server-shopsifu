import { Injectable } from '@nestjs/common'
import {
  CreateCategoryBodyType,
  GetAllCategoriesResType,
  UpdateCategoryBodyType,
  CategoryType,
} from 'src/routes/category/category.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class CategoryRepo {
  constructor(private readonly prismaService: PrismaService) {}

  async findAll({
    parentCategoryId,
    languageId,
  }: {
    parentCategoryId?: number | null
    languageId: string
  }): Promise<GetAllCategoriesResType> {
    const categories = await this.prismaService.category.findMany({
      where: {
        deletedAt: null,
        parentCategoryId: parentCategoryId ?? null,
      },
      include: {
        categoryTranslations: {
          where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    })

    return {
      data: categories.map((category) => {
        const translation = category.categoryTranslations?.[0]
        return {
          id: category.id,
          parentCategoryId: category.parentCategoryId,
          name: translation?.name || category.name,
          description: translation?.description || null,
          logo: category.logo,
          createdById: category.createdById,
          updatedById: category.updatedById,
          deletedById: category.deletedById,
          deletedAt: category.deletedAt,
          createdAt: category.createdAt,
          updatedAt: category.updatedAt,
        }
      }),
    }
  }

  findById({ id, languageId }: { id: number; languageId: string }): Promise<CategoryType | null> {
    return this.prismaService.category
      .findUnique({
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
      .then((category) => {
        if (!category) return null

        const translation = category.categoryTranslations?.[0]
        return {
          ...category,
          name: translation?.name || category.name,
          description: translation?.description || null,
        }
      })
  }

  create({ createdById, data }: { createdById: number | null; data: CreateCategoryBodyType }): Promise<CategoryType> {
    return this.prismaService.category
      .create({
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
      .then((category) => {
        const translation = category.categoryTranslations?.[0]
        return {
          ...category,
          name: translation?.name || category.name,
          description: translation?.description || null,
        }
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
  }): Promise<CategoryType> {
    return this.prismaService.category
      .update({
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
      .then((category) => {
        const translation = category.categoryTranslations?.[0]
        return {
          ...category,
          name: translation?.name || category.name,
          description: translation?.description || null,
        }
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
      ? this.prismaService.category
          .delete({
            where: {
              id,
            },
          })
          .then((category) => ({
            ...category,
            description: null,
          }))
      : this.prismaService.category
          .update({
            where: {
              id,
              deletedAt: null,
            },
            data: {
              deletedAt: new Date(),
              deletedById,
            },
          })
          .then((category) => ({
            ...category,
            description: null,
          }))
  }
}
