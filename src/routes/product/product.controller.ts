import { Controller, Get, Header, Param, Query } from '@nestjs/common'
import { SkipThrottle } from '@nestjs/throttler'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  GetProductDetailResDTO,
  GetProductParamsDTO,
  GetProductsQueryDTO,
  GetProductsResDTO
} from 'src/routes/product/product.dto'
import { ProductService } from 'src/routes/product/product.service'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { Cacheable } from 'src/shared/decorators/cacheable.decorator'
import { RedisService } from 'src/shared/services/redis.service'

@SkipThrottle()
@Controller('products')
@IsPublic()
export class ProductController {
  constructor(
    private readonly productService: ProductService,
    private readonly redisService: RedisService
  ) {}

  @Get()
  @ZodSerializerDto(GetProductsResDTO)
  @Header('Cache-Control', 'public, max-age=1800, s-maxage=3600, stale-while-revalidate=7200')
  @Header('Vary', 'Accept-Language, Accept-Encoding')
  @Header('X-Cache-Strategy', 'redis+cdn+browser+homepage-optimized')
  list(@Query() query: GetProductsQueryDTO) {
    return this.productService.list({
      query
    } as any)
  }

  @SkipThrottle({ default: false })
  @Get(':productId')
  @ZodSerializerDto(GetProductDetailResDTO)
  @Header('Cache-Control', 'public, max-age=3600, s-maxage=3600, stale-while-revalidate=7200')
  @Header('Vary', 'Accept-Language')
  @Header('X-Cache-Strategy', 'redis+cdn+browser+long-term')
  findById(@Param() params: GetProductParamsDTO) {
    return this.productService.getDetail({
      productId: params.productId
    })
  }
}
