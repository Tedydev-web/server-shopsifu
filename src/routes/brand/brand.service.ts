import { Injectable } from '@nestjs/common'
import { BrandRepo } from 'src/routes/brand/brand.repo'
import { CreateBrandBodyType, UpdateBrandBodyType } from 'src/routes/brand/brand.model'
import { NotFoundRecordException } from 'src/shared/error'
import { isNotFoundPrismaError } from 'src/shared/helpers'
import { PaginationQueryType } from 'src/shared/models/pagination.model'
import { I18nContext } from 'nestjs-i18n'
import { PaginationService } from 'src/shared/services/pagination.service'
import { OrderBy, SortBy } from 'src/shared/constants/other.constant'

@Injectable()
export class BrandService {
  constructor(
    private brandRepo: BrandRepo,
    private paginationService: PaginationService,
  ) {}

  async list(props: { pagination: PaginationQueryType; filters: any }) {
    const languageId = I18nContext.current()?.lang as string

    // Xây dựng where clause từ filters
    const where = this.buildWhereClause(props.filters)

    // Xây dựng orderBy từ pagination và filters
    const orderBy = this.buildOrderBy(props.pagination, props.filters)

    return this.paginationService.paginate('brand', props.pagination, {
      where,
      include: {
        brandTranslations: {
          where: languageId === 'all' ? { deletedAt: null } : { deletedAt: null, languageId },
        },
      },
      orderBy,
      defaultSortField: 'createdAt',
    })
  }

  private buildWhereClause(filters: any) {
    const where: any = { deletedAt: null }

    // Hỗ trợ cả 'search' và 'name' param
    if (filters.search) {
      const searchTerm = filters.search
      where.name = {
        contains: searchTerm,
        mode: 'insensitive',
      }
    }

    // Filter theo createdById (cho admin/seller)
    if (filters.createdById) {
      where.createdById = Number(filters.createdById)
    }

    return where
  }

  private buildOrderBy(pagination: PaginationQueryType, filters: any) {
    const { sortBy = SortBy.CreatedAt, sortOrder = OrderBy.Desc } = filters

    if (sortBy === SortBy.Name) {
      return [{ name: sortOrder }]
    }

    return [{ createdAt: sortOrder }]
  }

  async findById(id: number) {
    const brand = await this.brandRepo.findById(id, I18nContext.current()?.lang as string)
    if (!brand) {
      throw NotFoundRecordException
    }
    return brand
  }

  create({ data, createdById }: { data: CreateBrandBodyType; createdById: number }) {
    return this.brandRepo.create({
      createdById,
      data,
    })
  }

  async update({ id, data, updatedById }: { id: number; data: UpdateBrandBodyType; updatedById: number }) {
    try {
      const brand = await this.brandRepo.update({
        id,
        updatedById,
        data,
      })
      return brand
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }

  async delete({ id, deletedById }: { id: number; deletedById: number }) {
    try {
      await this.brandRepo.delete({
        id,
        deletedById,
      })
      return {
        message: 'Delete successfully',
      }
    } catch (error) {
      if (isNotFoundPrismaError(error)) {
        throw NotFoundRecordException
      }
      throw error
    }
  }
}
