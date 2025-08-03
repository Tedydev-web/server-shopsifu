import { Controller, Get, Query } from '@nestjs/common'
import { SkipThrottle } from '@nestjs/throttler'
import { ZodSerializerDto } from 'nestjs-zod'
import { SearchProductsQueryDTO, SearchProductsResDTO } from './search.dto'
import { SearchService } from './search.service'
import { IsPublic } from 'src/shared/decorators/auth.decorator'

@SkipThrottle()
@Controller('search')
@IsPublic()
export class SearchController {
  constructor(private readonly searchService: SearchService) {}

  @Get('products')
  @ZodSerializerDto(SearchProductsResDTO)
  searchProducts(@Query() query: SearchProductsQueryDTO) {
    return this.searchService.searchProducts(query as any)
  }
}
