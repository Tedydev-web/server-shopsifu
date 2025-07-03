import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateProductBodyDTO,
  GetProductDetailResDTO,
  GetProductParamsDTO,
  GetProductsQueryDTO,
  GetProductsResDTO,
  ProductDTO,
  UpdateProductBodyDTO,
} from 'src/routes/product/product.dto'
import { ProductService } from 'src/routes/product/product.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { IsPublic } from 'src/shared/decorators/auth.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'

@Controller('products')
export class ProductController {
  constructor(private readonly productService: ProductService) {}

  @Get()
  @IsPublic()
  @ZodSerializerDto(GetProductsResDTO)
  list(@Query() query: GetProductsQueryDTO) {
    return this.productService.list(query)
  }

  @Get(':productId')
  @IsPublic()
  @ZodSerializerDto(GetProductDetailResDTO)
  findById(@Param() params: GetProductParamsDTO) {
    return this.productService.findById(params.productId)
  }

  @Post()
  @ZodSerializerDto(GetProductDetailResDTO)
  create(@Body() body: CreateProductBodyDTO, @ActiveUser('userId') userId: number) {
    return this.productService.create({
      data: body,
      createdById: userId,
    })
  }

  @Put(':productId')
  @ZodSerializerDto(ProductDTO)
  update(
    @Body() body: UpdateProductBodyDTO,
    @Param() params: GetProductParamsDTO,
    @ActiveUser('userId') userId: number,
  ) {
    return this.productService.update({
      data: body,
      id: params.productId,
      updatedById: userId,
    })
  }

  @Delete(':productId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetProductParamsDTO, @ActiveUser('userId') userId: number) {
    return this.productService.delete({
      id: params.productId,
      deletedById: userId,
    })
  }
}
