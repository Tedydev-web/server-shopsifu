import { Injectable } from '@nestjs/common'
import { BrandRepo } from 'src/routes/brand/brand.repo'
import { CreateBrandBodyType, UpdateBrandBodyType, BrandPaginationQueryType } from 'src/routes/brand/brand.model'
import { I18nContext } from 'nestjs-i18n'

@Injectable()
export class BrandService {
  constructor(private brandRepo: BrandRepo) {}

  list(query: BrandPaginationQueryType) {
    return this.brandRepo.list(query, I18nContext.current()?.lang as string)
  }

  findById(id: number) {
    return this.brandRepo.findById(id, I18nContext.current()?.lang as string)
  }

  create({ data, createdById }: { data: CreateBrandBodyType; createdById: number }) {
    return this.brandRepo.create({
      createdById,
      data,
    })
  }

  update({ id, data, updatedById }: { id: number; data: UpdateBrandBodyType; updatedById: number }) {
    return this.brandRepo.update({
      id,
      updatedById,
      data,
    })
  }

  delete({ id, deletedById }: { id: number; deletedById: number }) {
    return this.brandRepo.delete({
      id,
      deletedById,
    })
  }
}
