import { Body, Controller, Delete, Get, Param, Post, Put, Query } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import { ManageProductService } from 'src/routes/product/manage-product/manage-product.service'
import {
  CreateProductBodyDTO,
  GetManageProductsQueryDTO,
  GetProductDetailResDTO,
  GetProductParamsDTO,
  GetProductsResDTO,
  UpdateProductBodyDTO,
  UpdateProductResDTO
} from 'src/routes/product/product.dto'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('manage-product/products')
export class ManageProductController {
  constructor(private readonly manageProductService: ManageProductService) {}

  @Get()
  @ZodSerializerDto(GetProductsResDTO)
  list(@Query() query: GetManageProductsQueryDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageProductService.list({ query, user })
  }

  @Get(':productId')
  @ZodSerializerDto(GetProductDetailResDTO)
  findById(@Param() params: GetProductParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageProductService.getDetail({ productId: params.productId, user })
  }

  @Post()
  @ZodSerializerDto(GetProductDetailResDTO)
  create(@Body() body: CreateProductBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageProductService.create({ data: body, user })
  }

  @Put(':productId')
  @ZodSerializerDto(UpdateProductResDTO)
  update(
    @Body() body: UpdateProductBodyDTO,
    @Param() params: GetProductParamsDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.manageProductService.update({ data: body, productId: params.productId, user })
  }

  @Delete(':productId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetProductParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.manageProductService.delete({ productId: params.productId, user })
  }
}
