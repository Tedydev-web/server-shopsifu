import { Controller, Get, Param, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { GetProductDetailResDTO, GetProductParamsDTO, GetProductsResDTO } from 'src/routes/product/product.dto'
import { ProductService } from 'src/routes/product/product.service'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { Pagination } from 'src/shared/decorators/pagination.decorator'
import { PaginationQueryDTO } from 'src/shared/dtos/pagination.dto'

@Controller('products')
@IsPublic()
export class ProductController {
  constructor(private readonly productService: ProductService) {}

  @Get()
  @ZodSerializerDto(GetProductsResDTO)
  list(@Pagination() pagination: PaginationQueryDTO, @Query() query: any) {
    return this.productService.list({
      pagination,
      filters: query,
    })
  }

  @Get(':productId')
  @ZodSerializerDto(GetProductDetailResDTO)
  findById(@Param() params: GetProductParamsDTO) {
    return this.productService.getDetail({
      productId: params.productId,
    })
  }
}
