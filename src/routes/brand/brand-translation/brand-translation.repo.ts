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

  findById(id: string): Promise<GetBrandTranslationDetailResType | null> {
    return this.prismaService.brandTranslation
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
    id: string
    updatedById: string
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
      id: string
      deletedById: string
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
