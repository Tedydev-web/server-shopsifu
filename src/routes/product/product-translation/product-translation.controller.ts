import { Body, Controller, Delete, Get, Param, Post, Put } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateProductTranslationBodyDTO,
  GetProductTranslationDetailResDTO,
  GetProductTranslationParamsDTO,
  UpdateProductTranslationBodyDTO
} from 'src/routes/product/product-translation/product-translation.dto'
import { ProductTranslationService } from 'src/routes/product/product-translation/product-translation.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('product-translations')
export class ProductTranslationController {
  constructor(private readonly productTranslationService: ProductTranslationService) {}

  @Get(':productTranslationId')
  @ZodSerializerDto(GetProductTranslationDetailResDTO)
  findById(@Param() params: GetProductTranslationParamsDTO) {
    return this.productTranslationService.findById(params.productTranslationId)
  }

  @Post()
  @ZodSerializerDto(GetProductTranslationDetailResDTO)
  create(@Body() body: CreateProductTranslationBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.productTranslationService.create({ data: body, user } as any)
  }

  @Put(':productTranslationId')
  @ZodSerializerDto(GetProductTranslationDetailResDTO)
  update(
    @Body() body: UpdateProductTranslationBodyDTO,
    @Param() params: GetProductTranslationParamsDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.productTranslationService.update({ data: body, id: params.productTranslationId, user } as any)
  }

  @Delete(':productTranslationId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetProductTranslationParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.productTranslationService.delete({ id: params.productTranslationId, user })
  }
}
