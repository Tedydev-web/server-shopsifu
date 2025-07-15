import { Injectable } from '@nestjs/common'
import {
  GetBrandTranslationDetailResType,
  CreateBrandTranslationBodyType,
  BrandTranslationType,
  UpdateBrandTranslationBodyType
} from 'src/routes/brand/brand-translation/brand-translation.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class BrandTranslationRepo {
  constructor(private prismaService: PrismaService) {}

  findById(id: number): Promise<GetBrandTranslationDetailResType | null> {
    return this.prismaService.brandTranslation.findUnique({
      where: {
        id,
        deletedAt: null
      }
    })
  }

  create({
    createdById,
    data
  }: {
    createdById: number | null
    data: CreateBrandTranslationBodyType
  }): Promise<BrandTranslationType> {
    return this.prismaService.brandTranslation.create({
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
    id: number
    updatedById: number
    data: UpdateBrandTranslationBodyType
  }): Promise<BrandTranslationType> {
    return this.prismaService.brandTranslation.update({
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
      id: number
      deletedById: number
    },
    isHard?: boolean
  ): Promise<BrandTranslationType> {
    return isHard
      ? this.prismaService.brandTranslation.delete({
          where: {
            id
          }
        })
      : this.prismaService.brandTranslation.update({
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
