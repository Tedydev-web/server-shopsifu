import { Body, Controller, Delete, Get, Param, Post, Put } from '@nestjs/common'
import { ZodSerializerDto } from 'nestjs-zod'
import {
  CreateCategoryTranslationBodyDTO,
  GetCategoryTranslationDetailResDTO,
  GetCategoryTranslationParamsDTO,
  UpdateCategoryTranslationBodyDTO
} from 'src/routes/category/category-translation/category-translation.dto'
import { CategoryTranslationService } from 'src/routes/category/category-translation/category-translation.service'
import { ActiveUser } from 'src/shared/decorators/active-user.decorator'
import { MessageResDTO } from 'src/shared/dtos/response.dto'
import { AccessTokenPayload } from 'src/shared/types/jwt.type'

@Controller('category-translations')
export class CategoryTranslationController {
  constructor(private readonly categoryTranslationService: CategoryTranslationService) {}

  @Get(':categoryTranslationId')
  @ZodSerializerDto(GetCategoryTranslationDetailResDTO)
  findById(@Param() params: GetCategoryTranslationParamsDTO) {
    return this.categoryTranslationService.findById(params.categoryTranslationId)
  }

  @Post()
  @ZodSerializerDto(GetCategoryTranslationDetailResDTO)
  create(@Body() body: CreateCategoryTranslationBodyDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.categoryTranslationService.create({ data: body, user } as any)
  }

  @Put(':categoryTranslationId')
  @ZodSerializerDto(GetCategoryTranslationDetailResDTO)
  update(
    @Body() body: UpdateCategoryTranslationBodyDTO,
    @Param() params: GetCategoryTranslationParamsDTO,
    @ActiveUser() user: AccessTokenPayload
  ) {
    return this.categoryTranslationService.update({ data: body, id: params.categoryTranslationId, user } as any)
  }

  @Delete(':categoryTranslationId')
  @ZodSerializerDto(MessageResDTO)
  delete(@Param() params: GetCategoryTranslationParamsDTO, @ActiveUser() user: AccessTokenPayload) {
    return this.categoryTranslationService.delete({ id: params.categoryTranslationId, user })
  }
}
