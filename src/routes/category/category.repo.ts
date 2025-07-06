import { Injectable } from '@nestjs/common'
import { I18nService } from 'nestjs-i18n'
import {
  CreateCategoryBodyType,
  GetAllCategoriesResType,
  UpdateCategoryBodyType,
  CategoryType,
  CategoryIncludeTranslationType
} from 'src/routes/category/category.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { I18nTranslations } from 'src/shared/i18n/generated/i18n.generated'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class CategoryRepo {
  constructor(
    private prismaService: PrismaService,
    private i18n: I18nService<I18nTranslations>
  ) {}

  async findAll({
    parentCategoryId,
    languageId
  }: {
    parentCategoryId?: number | null
    languageId: string
  }): Promise<GetAllCategoriesResType> {
    const categories = await this.prismaService.category.findMany({
      where: {
        deletedAt: null,
        parentCategoryId: parentCategoryId ?? null
      },
      include: {
        categoryTranslations: {
          where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId }
        }
      },
      orderBy: {
        createdAt: 'desc'
      }
    })

    return {
      data: categories,
      message: this.i18n.t('category.category.success.GET_SUCCESS')
    }
  }

  findById({ id, languageId }: { id: number; languageId: string }): Promise<CategoryIncludeTranslationType | null> {
    return this.prismaService.category.findUnique({
      where: {
        id,
        deletedAt: null
      },
      include: {
        categoryTranslations: {
          where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId }
        }
      }
    })
  }

  create({
    createdById,
    data
  }: {
    createdById: number | null
    data: CreateCategoryBodyType
  }): Promise<CategoryIncludeTranslationType> {
    return this.prismaService.category.create({
      data: {
        ...data,
        createdById
      },
      include: {
        categoryTranslations: {
          where: { deletedAt: null }
        }
      }
    })
  }

  async update({
    id,
    updatedById,
    data
  }: {
    id: number
    updatedById: number
    data: UpdateCategoryBodyType
  }): Promise<CategoryIncludeTranslationType> {
    return this.prismaService.category.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        ...data,
        updatedById
      },
      include: {
        categoryTranslations: {
          where: { deletedAt: null }
        }
      }
    })
  }

  delete(
    {
      id,
      deletedById
    }: {
      id: number
      deletedById: number
    },
    isHard?: boolean
  ): Promise<CategoryType> {
    return isHard
      ? this.prismaService.category.delete({
          where: {
            id
          }
        })
      : this.prismaService.category.update({
          where: {
            id,
            deletedAt: null
          },
          data: {
            deletedAt: new Date(),
            deletedById
          }
        })
  }
}
