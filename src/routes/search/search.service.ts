import { Injectable } from '@nestjs/common'
import { SearchRepo } from './search.repo'
import { SearchProductsQueryType, SearchProductsResType } from './search.model'
import { I18nService } from 'nestjs-i18n'

@Injectable()
export class SearchService {
  constructor(
    private readonly searchRepo: SearchRepo,
    private readonly i18n: I18nService
  ) {}

  /**
   * Tìm kiếm sản phẩm
   */
  async searchProducts(query: SearchProductsQueryType): Promise<SearchProductsResType> {
    const result = await this.searchRepo.searchProducts(query)

    return {
      message: 'Search completed successfully',
      data: result.data,
      metadata: result.metadata
    }
  }
}
