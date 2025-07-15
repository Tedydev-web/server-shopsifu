import { Injectable } from '@nestjs/common'
import {
  GetProductTranslationDetailResType,
  CreateProductTranslationBodyType,
  UpdateProductTranslationBodyType
} from 'src/routes/product/product-translation/product-translation.model'
import { ProductTranslationType } from 'src/shared/models/shared-product-translation.model'
import { PrismaService } from 'src/shared/services/prisma.service'

@Injectable()
export class ProductTranslationRepo {
  constructor(private prismaService: PrismaService) {}

  findById(id: number): Promise<GetProductTranslationDetailResType | null> {
    return this.prismaService.productTranslation.findUnique({
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
    data: CreateProductTranslationBodyType
  }): Promise<ProductTranslationType> {
    return this.prismaService.productTranslation.create({
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
    data: UpdateProductTranslationBodyType
  }): Promise<ProductTranslationType> {
    return this.prismaService.productTranslation.update({
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
  ): Promise<ProductTranslationType> {
    return isHard
      ? this.prismaService.productTranslation.delete({
          where: {
            id
          }
        })
      : this.prismaService.productTranslation.update({
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
