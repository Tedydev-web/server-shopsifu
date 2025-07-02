import { Injectable } from '@nestjs/common'
import {
  CreateBrandBodyType,
  GetBrandsResType,
  UpdateBrandBodyType,
  BrandType,
  BrandIncludeTranslationType,
  BrandPaginationQueryType,
} from 'src/routes/brand/brand.model'
import { PrismaService } from 'src/shared/services/prisma.service'
import { PaginationService, PaginatedResult } from 'src/shared/services/pagination.service'

@Injectable()
export class BrandRepo {
  constructor(
    private prismaService: PrismaService,
    private paginationService: PaginationService,
  ) {}

  async list(
    pagination: BrandPaginationQueryType,
    languageId?: string,
  ): Promise<PaginatedResult<BrandIncludeTranslationType>> {
    const include = {
      brandTranslations: {
        where: languageId ? { deletedAt: null, languageId } : { deletedAt: null },
      },
    }

    return this.paginationService.paginate(
      'brand',
      pagination,
      { deletedAt: null },
      {
        include,
        searchableFields: ['id', 'name'],
        orderBy: [{ createdAt: 'desc' }],
      },
    )
  }

  findById(id: number, languageId?: string): Promise<BrandIncludeTranslationType | null> {
    return this.prismaService.brand.findUnique({
      where: {
        id,
        deletedAt: null,
      },
      include: {
        brandTranslations: {
          where: languageId ? { deletedAt: null, languageId } : { deletedAt: null },
        },
      },
    })
  }

  create({
    createdById,
    data,
  }: {
    createdById: number | null
    data: CreateBrandBodyType
  }): Promise<BrandIncludeTranslationType> {
    return this.prismaService.brand.create({
      data: {
        ...data,
        createdById,
      },
      include: {
        brandTranslations: {
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
    data: UpdateBrandBodyType
  }): Promise<BrandIncludeTranslationType> {
    return this.prismaService.brand.update({
      where: {
        id,
        deletedAt: null,
      },
      data: {
        ...data,
        updatedById,
      },
      include: {
        brandTranslations: {
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
  ): Promise<BrandType> {
    return isHard
      ? this.prismaService.brand.delete({
          where: {
            id,
          },
        })
      : this.prismaService.brand.update({
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
