import { Injectable } from '@nestjs/common'
import {
  CreateBrandBodyType,
  GetBrandsResType,
  UpdateBrandBodyType,
  BrandType,
  BrandIncludeTranslationType
} from 'src/routes/brand/brand.model'
import { ALL_LANGUAGE_CODE } from 'src/shared/constants/other.constant'
import { PaginationQueryType } from 'src/shared/models/request.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaginatedResult, paginate } from 'src/shared/utils/pagination.util'

@Injectable()
export class BrandRepo {
  constructor(private prismaService: PrismaService) {}

  async list(
    pagination: PaginationQueryType,
    languageId: string
  ): Promise<PaginatedResult<BrandIncludeTranslationType>> {
    return paginate<BrandIncludeTranslationType>(this.prismaService.brand, pagination, {
      where: {
        deletedAt: null
      },
      include: {
        brandTranslations: {
          where: languageId === ALL_LANGUAGE_CODE ? { deletedAt: null } : { deletedAt: null, languageId }
        }
      },
      orderBy: {
        createdAt: 'desc'
      }
    })
  }

  findById(id: number, languageId: string): Promise<BrandIncludeTranslationType | null> {
    return this.prismaService.brand.findUnique({
      where: {
        id,
        deletedAt: null
      },
      include: {
        brandTranslations: {
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
    data: CreateBrandBodyType
  }): Promise<BrandIncludeTranslationType> {
    return this.prismaService.brand.create({
      data: {
        ...data,
        createdById
      },
      include: {
        brandTranslations: {
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
    data: UpdateBrandBodyType
  }): Promise<BrandIncludeTranslationType> {
    return this.prismaService.brand.update({
      where: {
        id,
        deletedAt: null
      },
      data: {
        ...data,
        updatedById
      },
      include: {
        brandTranslations: {
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
  ): Promise<BrandType> {
    return isHard
      ? this.prismaService.brand.delete({
          where: {
            id
          }
        })
      : this.prismaService.brand.update({
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
