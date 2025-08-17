import { Injectable } from '@nestjs/common'
import {
  GetCategoryTranslationDetailResType,
  CreateCategoryTranslationBodyType,
  CategoryTranslationType,
  UpdateCategoryTranslationBodyType
} from 'src/routes/category/category-translation/category-translation.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class CategoryTranslationRepo {
  constructor(private prismaService: PrismaService) {}

  findById(id: string): Promise<GetCategoryTranslationDetailResType | null> {
    return this.prismaService.categoryTranslation
      .findUnique({
        where: {
          id,
          deletedAt: null
        }
      })
      .then((result) => (result ? { data: result } : null))
  }

  create({
    createdById,
    data
  }: {
    createdById: string | null
    data: CreateCategoryTranslationBodyType
  }): Promise<CategoryTranslationType> {
    return this.prismaService.categoryTranslation.create({
      data: {
        ...data,
        createdById
      }
    })
  }

  async update({
    id,
    updatedById,
    data
  }: {
    id: string
    updatedById: string
    data: UpdateCategoryTranslationBodyType
  }): Promise<CategoryTranslationType> {
    return this.prismaService.categoryTranslation.update({
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

  delete(
    {
      id,
      deletedById
    }: {
      id: string
      deletedById: string
    },
    isHard?: boolean
  ): Promise<CategoryTranslationType> {
    return isHard
      ? this.prismaService.categoryTranslation.delete({
          where: {
            id
          }
        })
      : this.prismaService.categoryTranslation.update({
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
